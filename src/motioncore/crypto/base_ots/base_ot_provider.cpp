// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko, Lennart Braun
// Cryptography and Privacy Engineering Group (ENCRYPTO)
// TU Darmstadt, Germany
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "base/configuration.h"
#include "base/register.h"
#include "base_ot_provider.h"
#include "communication/context.h"
#include "crypto/base_ots/ot_hl17.h"
#include "data_storage/base_ot_data.h"
#include "data_storage/data_storage.h"
#include "utility/logger.h"

namespace MOTION {

BaseOTProvider::BaseOTProvider(Configuration &config, Logger &logger, Register &_register)
    : config_(config), logger_(logger), register_(_register), finished_(false) {}

void BaseOTProvider::ComputeBaseOTs() {
  if constexpr (MOTION_DEBUG) {
    logger_.LogDebug("Start computing base OTs");
  }

  std::vector<std::future<void>> task_futures;
  std::vector<std::unique_ptr<OT_HL17>> base_ots;
  std::vector<std::shared_ptr<DataStorage>> data_storages;

  task_futures.reserve(2 * (config_.GetNumOfParties() - 1));
  base_ots.reserve(config_.GetNumOfParties());
  data_storages.reserve(config_.GetNumOfParties());

  for (auto i = 0ull; i < config_.GetNumOfParties(); ++i) {
    if (i == config_.GetMyId()) {
      data_storages.push_back(nullptr);
      base_ots.emplace_back(nullptr);
      continue;
    }

    auto send_function = [this, i](flatbuffers::FlatBufferBuilder &&message) {
      register_.Send(i, std::move(message));
    };
    auto data_storage = config_.GetContexts().at(i)->GetDataStorage();
    data_storages.push_back(data_storage);
    base_ots.emplace_back(std::make_unique<OT_HL17>(send_function, data_storage));

    if (!data_storage->GetBaseOTsData()->GetReceiverData().is_ready_) {
      task_futures.emplace_back(std::async(std::launch::async, [&base_ots, &data_storages, i] {
        auto choices = ENCRYPTO::BitVector<>::Random(128);
        auto chosen_messages = base_ots[i]->recv(choices);  // sender base ots
        auto &receiver_data = data_storages[i]->GetBaseOTsData()->GetReceiverData();
        receiver_data.c_ = std::move(choices);
        for (std::size_t i = 0; i < chosen_messages.size(); ++i) {
          auto b = receiver_data.messages_c_.at(i).begin();
          std::copy(chosen_messages.at(i).begin(), chosen_messages.at(i).begin() + 16, b);
        }
        std::scoped_lock lock(receiver_data.is_ready_condition_->GetMutex());
        receiver_data.is_ready_ = true;
      }));
    }

    if (!data_storage->GetBaseOTsData()->GetSenderData().is_ready_) {
      task_futures.emplace_back(std::async(std::launch::async, [&base_ots, &data_storages, i] {
        auto both_messages = base_ots[i]->send(128);  // receiver base ots
        auto &sender_data = data_storages[i]->GetBaseOTsData()->GetSenderData();
        for (std::size_t i = 0; i < both_messages.size(); ++i) {
          auto b = sender_data.messages_0_.at(i).begin();
          std::copy(both_messages.at(i).first.begin(), both_messages.at(i).first.begin() + 16, b);
        }
        for (std::size_t i = 0; i < both_messages.size(); ++i) {
          auto b = sender_data.messages_1_.at(i).begin();
          std::copy(both_messages.at(i).second.begin(), both_messages.at(i).second.begin() + 16, b);
        }
        std::scoped_lock lock(sender_data.is_ready_condition_->GetMutex());
        sender_data.is_ready_ = true;
      }));
    }
  }

  std::for_each(task_futures.begin(), task_futures.end(), [](auto &f) { f.get(); });
  finished_ = true;

  if constexpr (MOTION_DEBUG) {
    logger_.LogDebug("Finished computing base OTs");
  }
}

void BaseOTProvider::ImportBaseOTs(std::size_t party_id, const ReceiverMsgs &msgs) {
  auto &rcv_data =
      config_.GetContexts().at(party_id)->GetDataStorage()->GetBaseOTsData()->GetReceiverData();
  if (rcv_data.is_ready_)
    throw std::runtime_error(
        fmt::format("Found previously computed receiver base OTs for Party#{}", party_id));

  rcv_data.c_ = msgs.c_;
  rcv_data.messages_c_ = msgs.messages_c_;

  {
    std::scoped_lock lock(rcv_data.is_ready_condition_->GetMutex());
    rcv_data.is_ready_ = true;
  }
  rcv_data.is_ready_condition_->NotifyAll();
}

void BaseOTProvider::ImportBaseOTs(std::size_t party_id, const SenderMsgs &msgs) {
  auto &snd_data =
      config_.GetContexts().at(party_id)->GetDataStorage()->GetBaseOTsData()->GetSenderData();
  if (snd_data.is_ready_)
    throw std::runtime_error(
        fmt::format("Found previously computed sender base OTs for Party#{}", party_id));

  snd_data.messages_0_ = msgs.messages_0_;
  snd_data.messages_1_ = msgs.messages_1_;

  {
    std::scoped_lock lock(snd_data.is_ready_condition_->GetMutex());
    snd_data.is_ready_ = true;
  }
  snd_data.is_ready_condition_->NotifyAll();
}

std::pair<ReceiverMsgs, SenderMsgs> BaseOTProvider::ExportBaseOTs(std::size_t party_id) {
  if (party_id == config_.GetMyId())
    throw std::runtime_error("Base OTs export is only possible for other parties");

  auto &base_ot_data = config_.GetContexts().at(party_id)->GetDataStorage()->GetBaseOTsData();
  auto &rcv_data = base_ot_data->GetReceiverData();
  auto &snd_data = base_ot_data->GetSenderData();

  if (!rcv_data.is_ready_)
    throw std::runtime_error(
        fmt::format("Trying to export non-existing receiver base OTs for Party#{}", party_id));

  if (!snd_data.is_ready_)
    throw std::runtime_error(
        fmt::format("Trying to export non-existing sender base OTs for Party#{}", party_id));

  std::pair<ReceiverMsgs, SenderMsgs> base_ots;

  std::get<0>(base_ots).c_ = rcv_data.c_;
  std::get<0>(base_ots).messages_c_ = rcv_data.messages_c_;

  std::get<1>(base_ots).messages_0_ = snd_data.messages_0_;
  std::get<1>(base_ots).messages_1_ = snd_data.messages_1_;

  return base_ots;
}

}  // namespace MOTION
