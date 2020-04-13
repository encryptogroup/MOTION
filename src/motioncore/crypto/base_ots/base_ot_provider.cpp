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
#include "communication/communication_layer.h"
#include "communication/fbs_headers/base_ot_generated.h"
#include "communication/fbs_headers/message_generated.h"
#include "communication/message_handler.h"
#include "crypto/base_ots/ot_hl17.h"
#include "data_storage/base_ot_data.h"
#include "utility/fiber_condition.h"
#include "utility/logger.h"

namespace MOTION {

// Handler for messages of type BaseROTMessageSender, BaseROTMessageReceiver
class BaseOTMessageHandler : public Communication::MessageHandler {
 public:
  // Create a handler object for a given party
  BaseOTMessageHandler(std::size_t party_id, std::shared_ptr<Logger> logger,
                       BaseOTsData &base_ots_data)
      : party_id_(party_id), logger_(logger), base_ots_data_(base_ots_data) {}

  // Method which is called on received messages.
  void received_message(std::size_t, std::vector<std::uint8_t> &&message) override;

  BaseOTsData &GetBaseOTsData() { return base_ots_data_; };

 private:
  std::size_t party_id_;
  std::shared_ptr<Logger> logger_;
  BaseOTsData &base_ots_data_;
};

void BaseOTMessageHandler::received_message(std::size_t, std::vector<std::uint8_t> &&raw_message) {
  assert(!raw_message.empty());
  auto message = Communication::GetMessage(raw_message.data());
  auto base_ot_message = Communication::GetBaseROTMessage(message->payload()->data());
  auto base_ot_id = base_ot_message->base_ot_id();
  if (message->message_type() == Communication::MessageType::BaseROTMessageReceiver) {
    base_ots_data_.MessageReceived(base_ot_message->buffer()->data(), BaseOTsDataType::HL17_R,
                                   base_ot_id);
  } else if (message->message_type() == Communication::MessageType::BaseROTMessageSender) {
    base_ots_data_.MessageReceived(base_ot_message->buffer()->data(), BaseOTsDataType::HL17_S,
                                   base_ot_id);
  } else {
    throw std::logic_error("BaseOTMessageHandler registered for wrong MessageType");
  }
}

// Implementation of BaseOTProvider: -------------------------------------------

BaseOTProvider::BaseOTProvider(Communication::CommunicationLayer &communication_layer,
                               std::shared_ptr<Logger> logger)
    : communication_layer_(communication_layer),
      num_parties_(communication_layer.get_num_parties()),
      my_id_(communication_layer.get_my_id()),
      data_(num_parties_),
      logger_(logger),
      finished_(false) {
  communication_layer_.register_message_handler(
      [this, &logger](auto party_id) {
        return std::make_shared<BaseOTMessageHandler>(party_id, logger, data_.at(party_id));
      },
      {Communication::MessageType::BaseROTMessageSender,
       Communication::MessageType::BaseROTMessageReceiver});
}

BaseOTProvider::~BaseOTProvider() {
  communication_layer_.deregister_message_handler(
      {Communication::MessageType::BaseROTMessageSender,
       Communication::MessageType::BaseROTMessageReceiver});
}

void BaseOTProvider::ComputeBaseOTs() {
  if constexpr (MOTION_DEBUG) {
    if (logger_) {
      logger_->LogDebug("Start computing base OTs");
    }
  }

  std::vector<std::future<void>> task_futures;
  std::vector<std::unique_ptr<OT_HL17>> base_ots;

  task_futures.reserve(2 * (num_parties_ - 1));
  base_ots.reserve(num_parties_);

  for (auto i = 0ull; i < num_parties_; ++i) {
    if (i == my_id_) {
      base_ots.emplace_back(nullptr);
      continue;
    }

    auto send_function = [this, i](flatbuffers::FlatBufferBuilder &&message) {
      communication_layer_.send_message(i, std::move(message));
    };

    auto &base_ots_data = data_.at(i);
    base_ots.emplace_back(std::make_unique<OT_HL17>(send_function, base_ots_data));

    if (!base_ots_data.GetReceiverData().is_ready_) {
      task_futures.emplace_back(std::async(std::launch::async, [this, &base_ots, i] {
        auto choices = ENCRYPTO::BitVector<>::Random(128);
        auto chosen_messages = base_ots[i]->recv(choices);  // sender base ots
        auto &receiver_data = data_[i].GetReceiverData();
        receiver_data.c_ = std::move(choices);
        for (std::size_t i = 0; i < chosen_messages.size(); ++i) {
          auto b = receiver_data.messages_c_.at(i).begin();
          std::copy(chosen_messages.at(i).begin(), chosen_messages.at(i).begin() + 16, b);
        }
        std::scoped_lock lock(receiver_data.is_ready_condition_->GetMutex());
        receiver_data.is_ready_ = true;
      }));
    }

    if (!base_ots_data.GetSenderData().is_ready_) {
      task_futures.emplace_back(std::async(std::launch::async, [this, &base_ots, i] {
        auto both_messages = base_ots[i]->send(128);  // receiver base ots
        auto &sender_data = data_[i].GetSenderData();
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
    if (logger_) {
      logger_->LogDebug("Finished computing base OTs");
    }
  }
}

void BaseOTProvider::ImportBaseOTs(std::size_t party_id, const ReceiverMsgs &msgs) {
  auto &rcv_data = data_.at(party_id).GetReceiverData();
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
  auto &snd_data = data_.at(party_id).GetSenderData();
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
  if (party_id == my_id_)
    throw std::runtime_error("Base OTs export is only possible for other parties");

  auto &base_ot_data = data_.at(party_id);
  auto &rcv_data = base_ot_data.GetReceiverData();
  auto &snd_data = base_ot_data.GetSenderData();

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
