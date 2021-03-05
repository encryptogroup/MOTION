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
#include "communication/fbs_headers/base_ot_generated.h"
#include "communication/fbs_headers/message_generated.h"
#include "communication/message_handler.h"
#include "data_storage/base_ot_data.h"
#include "utility/fiber_condition.h"
#include "utility/logger.h"

namespace encrypto::motion {

// Handler for messages of type BaseROTMessageSender, BaseROTMessageReceiver
class BaseOtMessageHandler : public communication::MessageHandler {
 public:
  // Create a handler object for a given party
  BaseOtMessageHandler(std::shared_ptr<Logger> logger, BaseOtData& base_ots_data)
      : logger_(logger), base_ots_data_(base_ots_data) {}

  // Method which is called on received messages.
  void ReceivedMessage(std::size_t, std::vector<std::uint8_t>&& message) override;

  BaseOtData& GetBaseOtsData() { return base_ots_data_; };

 private:
  std::shared_ptr<Logger> logger_;
  BaseOtData& base_ots_data_;
};

void BaseOtMessageHandler::ReceivedMessage(std::size_t, std::vector<std::uint8_t>&& raw_message) {
  assert(!raw_message.empty());
  auto message = communication::GetMessage(raw_message.data());
  auto base_ot_message = communication::GetBaseROtMessage(message->payload()->data());
  auto base_ot_id = base_ot_message->base_ot_id();
  if (message->message_type() == communication::MessageType::kBaseROtMessageReceiver) {
    base_ots_data_.MessageReceived(base_ot_message->buffer()->data(), BaseOtDataType::kHL17R,
                                   base_ot_id);
  } else if (message->message_type() == communication::MessageType::kBaseROtMessageSender) {
    base_ots_data_.MessageReceived(base_ot_message->buffer()->data(), BaseOtDataType::kHL17S,
                                   base_ot_id);
  } else {
    throw std::logic_error("BaseOtMessageHandler registered for wrong MessageType");
  }
}

// Implementation of BaseOtProvider: -------------------------------------------

BaseOtProvider::BaseOtProvider(communication::CommunicationLayer& communication_layer,
                               std::shared_ptr<Logger> logger)
    : communication_layer_(communication_layer),
      number_of_parties_(communication_layer.GetNumberOfParties()),
      my_id_(communication_layer.GetMyId()),
      data_(number_of_parties_),
      logger_(logger),
      finished_(false) {
  communication_layer_.RegisterMessageHandler(
      [this, &logger](auto party_id) {
        return std::make_shared<BaseOtMessageHandler>(logger, data_.at(party_id));
      },
      {communication::MessageType::kBaseROtMessageSender,
       communication::MessageType::kBaseROtMessageReceiver});
}

BaseOtProvider::~BaseOtProvider() {
  communication_layer_.DeregisterMessageHandler(
      {communication::MessageType::kBaseROtMessageSender,
       communication::MessageType::kBaseROtMessageReceiver});
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
      communication_layer_.SendMessage(i, std::move(message));
    };

    auto& base_ots_data = data_.at(i);
    base_ots.emplace_back(std::make_unique<OtHL17>(send_function, base_ots_data));

    if (!base_ots_data.GetReceiverData().is_ready) {
      task_futures.emplace_back(std::async(std::launch::async, [this, &base_ots, i] {
        auto choices = BitVector<>::SecureRandom(128);
        auto chosen_messages = base_ots[i]->Receive(choices);  // sender base ots
        auto& receiver_data = data_[i].GetReceiverData();
        receiver_data.c = std::move(choices);
        for (std::size_t i = 0; i < chosen_messages.size(); ++i) {
          auto b = receiver_data.messages_c.at(i).begin();
          std::copy(chosen_messages.at(i).begin(), chosen_messages.at(i).begin() + 16, b);
        }
        std::scoped_lock lock(receiver_data.is_ready_condition->GetMutex());
        receiver_data.is_ready = true;
      }));
    }

    if (!base_ots_data.GetSenderData().is_ready) {
      task_futures.emplace_back(std::async(std::launch::async, [this, &base_ots, i] {
        auto both_messages = base_ots[i]->Send(128);  // receiver base ots
        auto& sender_data = data_[i].GetSenderData();
        for (std::size_t i = 0; i < both_messages.size(); ++i) {
          auto b = sender_data.messages_0.at(i).begin();
          std::copy(both_messages.at(i).first.begin(), both_messages.at(i).first.begin() + 16, b);
        }
        for (std::size_t i = 0; i < both_messages.size(); ++i) {
          auto b = sender_data.messages_1.at(i).begin();
          std::copy(both_messages.at(i).second.begin(), both_messages.at(i).second.begin() + 16, b);
        }
        std::scoped_lock lock(sender_data.is_ready_condition->GetMutex());
        sender_data.is_ready = true;
      }));
    }
  }

  std::for_each(task_futures.begin(), task_futures.end(), [](auto& f) { f.get(); });
  finished_ = true;

  if constexpr (kDebug) {
    if (logger_) {
      logger_->LogDebug("Finished computing base OTs");
    }
  }
}

void BaseOtProvider::ImportBaseOts(std::size_t party_id, const ReceiverMessage& messages) {
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
  receiver_data.is_ready_condition->NotifyAll();
}

void BaseOtProvider::ImportBaseOts(std::size_t party_id, const SenderMessage& messages) {
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
  sender_data.is_ready_condition->NotifyAll();
}

std::pair<ReceiverMessage, SenderMessage> BaseOtProvider::ExportBaseOts(std::size_t party_id) {
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

  return base_ots;
}

}  // namespace encrypto::motion
