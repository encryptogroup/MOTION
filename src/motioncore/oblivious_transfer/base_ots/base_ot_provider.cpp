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

#include "base_ot_provider.h"
#include "ot_hl17.h"

#include "base/configuration.h"
#include "base/register.h"
#include "communication/communication_layer.h"
#include "communication/fbs_headers/message_generated.h"
#include "communication/message_manager.h"
#include "data_storage/base_ot_data.h"
#include "utility/fiber_condition.h"
#include "utility/logger.h"

namespace encrypto::motion {

// Implementation of BaseOtProvider: -------------------------------------------

BaseOtProvider::BaseOtProvider(communication::CommunicationLayer& communication_layer)
    : communication_layer_(communication_layer),
      number_of_parties_(communication_layer_.GetNumberOfParties()),
      my_id_(communication_layer_.GetMyId()),
      data_(number_of_parties_),
      logger_(communication_layer_.GetLogger()) {
  number_of_ots_.resize(number_of_parties_ - 1, 0);
}

BaseOtProvider::~BaseOtProvider() {}

void BaseOtProvider::PreSetup() {
  for (std::size_t party_id = 0; party_id < number_of_parties_; ++party_id) {
    if (party_id == my_id_) continue;
    std::size_t remapped_party_id{party_id > my_id_ ? party_id - 1 : party_id};
    data_[party_id].receiver_futures.reserve(number_of_ots_[remapped_party_id]);
    data_[party_id].sender_futures.reserve(number_of_ots_[remapped_party_id]);
    for (std::size_t i = 0; i < number_of_ots_[remapped_party_id]; ++i) {
      data_[party_id].receiver_futures.emplace_back(
          communication_layer_.GetMessageManager().RegisterReceive(
              party_id, communication::MessageType::kBaseROtMessageReceiver, i));
      data_[party_id].sender_futures.emplace_back(
          communication_layer_.GetMessageManager().RegisterReceive(
              party_id, communication::MessageType::kBaseROtMessageSender, i));
    }
  }
}

bool BaseOtProvider::HasWork() {
  for (auto n : number_of_ots_) {
    if (n != 0) return true;
  }
  return false;
}

std::vector<std::size_t> BaseOtProvider::Request(std::size_t number_of_ots) {
  std::vector<std::size_t> offsets(number_of_parties_, 0);

  for (std::size_t party_id = 0; party_id < number_of_parties_; ++party_id) {
    if (party_id == my_id_) {
      continue;
    }
    std::size_t remapped_party_id{party_id > my_id_ ? party_id - 1 : party_id};
    number_of_ots_.at(remapped_party_id) += number_of_ots;
    offsets.at(party_id) = data_.at(party_id).total_number_ots;
    data_.at(party_id).Add(number_of_ots);
  }
  return offsets;
}

std::size_t BaseOtProvider::Request(std::size_t number_of_ots, std::size_t party_id) {
  assert(party_id < number_of_parties_);
  std::size_t remapped_party_id{party_id > my_id_ ? party_id - 1 : party_id};
  number_of_ots_.at(remapped_party_id) += number_of_ots;
  auto offset = data_.at(party_id).total_number_ots;
  data_.at(party_id).Add(number_of_ots);
  return offset;
}

void BaseOtProvider::ComputeBaseOts() {
  if constexpr (kDebug) {
    if (logger_) {
      logger_->LogDebug("Start computing base OTs");
    }
  }

  std::vector<std::future<void>> task_futures;
  std::vector<std::unique_ptr<OtHL17>> base_ots;

  task_futures.reserve(2 * (number_of_parties_ - 1));
  base_ots.reserve(number_of_parties_);

  for (auto i = 0ull; i < number_of_parties_; ++i) {
    if (i == my_id_) {
      base_ots.emplace_back(nullptr);
      continue;
    }

    auto send_function = [this, i](flatbuffers::FlatBufferBuilder&& message) {
      communication_layer_.SendMessage(i, message.Release());
    };

    auto& base_ots_data = data_.at(i);
    base_ots.emplace_back(std::make_unique<OtHL17>(send_function, base_ots_data));
    std::size_t remapped_party_id{i > my_id_ ? i - 1 : i};

    task_futures.emplace_back(
        std::async(std::launch::async, [this, &base_ots, i, remapped_party_id] {
          auto choices = BitVector<>::SecureRandom(number_of_ots_.at(remapped_party_id));
          auto chosen_messages = base_ots[i]->Receive(choices);  // sender base ots
          auto& receiver_data = data_[i].GetReceiverData();
          receiver_data.c = std::move(choices);
          for (std::size_t i = 0; i < chosen_messages.size(); ++i) {
            auto b = receiver_data.messages_c.at(i).begin();
            std::copy(chosen_messages.at(i).begin(), chosen_messages.at(i).begin() + 16, b);
          }
        }));

    task_futures.emplace_back(std::async(std::launch::async, [this, &base_ots, i,
                                                              remapped_party_id] {
      auto both_messages =
          base_ots[i]->Send(number_of_ots_.at(remapped_party_id));  // receiver base ots
      auto& sender_data = data_[i].GetSenderData();
      for (std::size_t i = 0; i < both_messages.size(); ++i) {
        auto b = sender_data.messages_0.at(i).begin();
        std::copy(both_messages.at(i).first.begin(), both_messages.at(i).first.begin() + 16, b);
      }
      for (std::size_t i = 0; i < both_messages.size(); ++i) {
        auto b = sender_data.messages_1.at(i).begin();
        std::copy(both_messages.at(i).second.begin(), both_messages.at(i).second.begin() + 16, b);
      }
    }));
  }

  std::for_each(task_futures.begin(), task_futures.end(), [](auto& f) { f.get(); });
  SetOnlineIsReady();

  if constexpr (kDebug) {
    if (logger_) {
      logger_->LogDebug("Finished computing base OTs");
    }
  }
}

void BaseOtProvider::ImportBaseOts([[maybe_unused]] std::size_t party_id,
                                   [[maybe_unused]] const ReceiverMessage& messages) {
  // TODO
  throw std::runtime_error("Not completely implemented yet"); /*
   auto& receiver_data = data_.at(party_id).GetReceiverData();
   if (receiver_data.is_ready)
     throw std::runtime_error(
         fmt::format("Found previously computed receiver base OTs for Party#{}", party_id));

   receiver_data.c = messages.c;
   receiver_data.messages_c = messages.messages_c;

   {
     std::scoped_lock lock(receiver_data.is_ready_condition->GetMutex());
     receiver_data.is_ready = true;
   }
   receiver_data.is_ready_condition->NotifyAll();*/
}

void BaseOtProvider::ImportBaseOts([[maybe_unused]] std::size_t party_id,
                                   [[maybe_unused]] const SenderMessage& messages) {
  // TODO
  throw std::runtime_error("Not completely implemented yet"); /*
   auto& sender_data = data_.at(party_id).GetSenderData();
   if (sender_data.is_ready)
     throw std::runtime_error(
         fmt::format("Found previously computed sender base OTs for Party#{}", party_id));

   sender_data.messages_0 = messages.messages_0;
   sender_data.messages_1 = messages.messages_1;

   {
     std::scoped_lock lock(sender_data.is_ready_condition->GetMutex());
     sender_data.is_ready = true;
   }
   sender_data.is_ready_condition->NotifyAll();*/
}

std::pair<ReceiverMessage, SenderMessage> BaseOtProvider::ExportBaseOts(
    [[maybe_unused]] std::size_t party_id) {
  // TODO
  throw std::runtime_error("Not completely implemented yet"); /*
   if (party_id == my_id_)
     throw std::runtime_error("Base OTs export is only possible for other parties");

   auto& base_ot_data = data_.at(party_id);
   auto& receiver_data = base_ot_data.GetReceiverData();
   auto& sender_data = base_ot_data.GetSenderData();

   if (!receiver_data.is_ready)
     throw std::runtime_error(
         fmt::format("Trying to export non-existing receiver base OTs for Party#{}", party_id));

   if (!sender_data.is_ready)
     throw std::runtime_error(
         fmt::format("Trying to export non-existing sender base OTs for Party#{}", party_id));

   std::pair<ReceiverMessage, SenderMessage> base_ots;

   std::get<0>(base_ots).c = receiver_data.c;
   std::get<0>(base_ots).messages_c = receiver_data.messages_c;

   std::get<1>(base_ots).messages_0 = sender_data.messages_0;
   std::get<1>(base_ots).messages_1 = sender_data.messages_1;

   return base_ots;*/
}

}  // namespace encrypto::motion
