// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko
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

#include "data_storage.h"

#include <iostream>
#include <mutex>

#include "utility/condition.h"
#include "utility/logger.h"

namespace ABYN {

BaseOTsReceiverData::BaseOTsReceiverData() {
  received_S_.Resize(128, true);
  for (auto i = 0; i < 128; ++i) {
    received_S_condition_.emplace_back(
        std::make_unique<ENCRYPTO::Condition>([this, i]() { return received_S_.Get(i); }));
  }
  S_.resize(128);

  is_ready_condition_ = std::make_unique<ENCRYPTO::Condition>([this]() { return is_ready_; });
}

BaseOTsSenderData::BaseOTsSenderData() {
  received_R_.Resize(128, true);
  for (auto i = 0; i < 128; ++i) {
    received_R_condition_.emplace_back(
        std::make_unique<ENCRYPTO::Condition>([this, i]() { return received_R_.Get(i); }));
  }
  R_.resize(128);

  is_ready_condition_ = std::make_unique<ENCRYPTO::Condition>([this]() { return is_ready_; });
}

DataStorage::DataStorage(std::size_t id) : id_(id) {
  rcv_hello_msg_cond =
      std::make_shared<ENCRYPTO::Condition>([this]() { return !received_hello_message_.empty(); });
  snt_hello_msg_cond =
      std::make_shared<ENCRYPTO::Condition>([this]() { return !sent_hello_message_.empty(); });

  base_ots_receiver_data_ = std::make_unique<BaseOTsReceiverData>();
  base_ots_sender_data_ = std::make_unique<BaseOTsSenderData>();
}

void DataStorage::SetReceivedOutputMessage(std::vector<std::uint8_t> &&output_message) {
  assert(!output_message.empty());
  auto message = Communication::GetMessage(output_message.data());
  auto output_message_ptr = Communication::GetOutputMessage(message->payload()->data());
  std::shared_ptr<ENCRYPTO::Condition> cond;

  auto gate_id = output_message_ptr->gate_id();
  {
    // prevents inserting new elements while searching while GetOutputMessage() is called
    std::scoped_lock lock(output_message_mutex_);
    if (output_message_conditions_.find(gate_id) == output_message_conditions_.end()) {
      cond = std::make_shared<ENCRYPTO::Condition>([this, gate_id]() {
        return received_output_messages_.find(gate_id) != received_output_messages_.end();
      });
      // don't need to check anything
      output_message_conditions_.emplace(gate_id, cond);
    } else {
      cond = output_message_conditions_.find(gate_id)->second;
    }

    {
      std::scoped_lock lock_cond(cond->GetMutex());
      auto ret = received_output_messages_.emplace(gate_id, std::move(output_message));
      if (!ret.second) {
        logger_->LogError(
            fmt::format("Failed to insert new output message from Party#{} for "
                        "gate#{}, found another buffer on its place",
                        id_, gate_id));
      }
      logger_->LogDebug(
          fmt::format("Received an output message from Party#{} for gate#{}", id_, gate_id));
    }
  }
  cond->NotifyAll();
}  // namespace ABYN

const Communication::OutputMessage *DataStorage::GetOutputMessage(const std::size_t gate_id) {
  std::unordered_map<std::size_t, std::vector<std::uint8_t>>::iterator iterator, end;
  std::shared_ptr<ENCRYPTO::Condition> cond;
  {
    // prevent SetReceivedOutputMessage() to insert new elements while searching
    std::scoped_lock lock(output_message_mutex_);
    // create condition if there is no
    if (output_message_conditions_.find(gate_id) == output_message_conditions_.end()) {
      output_message_conditions_.emplace(
          gate_id, std::make_shared<ENCRYPTO::Condition>([this, gate_id]() {
            return received_output_messages_.find(gate_id) != received_output_messages_.end();
          }));
    }
  }
  {
    std::scoped_lock lock(output_message_mutex_);
    cond = output_message_conditions_.find(gate_id)->second;
  }
  while (!(*cond)()) {
    cond->WaitFor(std::chrono::milliseconds(1));
  }
  std::scoped_lock lock(output_message_mutex_);
  auto iter = received_output_messages_.find(gate_id);
  assert(iter != received_output_messages_.end());
  auto output_message = Communication::GetMessage(iter->second.data());
  assert(output_message != nullptr);
  return Communication::GetOutputMessage(output_message->payload()->data());
}

void DataStorage::SetReceivedHelloMessage(std::vector<std::uint8_t> &&hello_message) {
  {
    std::scoped_lock<std::mutex> lock(rcv_hello_msg_cond->GetMutex());
    received_hello_message_ = std::move(hello_message);
  }
  rcv_hello_msg_cond->NotifyAll();
}

const Communication::HelloMessage *DataStorage::GetReceivedHelloMessage() {
  if (received_hello_message_.empty()) {
    return nullptr;
  }
  auto hello_message = Communication::GetMessage(received_hello_message_.data());
  assert(hello_message != nullptr);
  return Communication::GetHelloMessage(hello_message->payload()->data());
}

void DataStorage::SetSentHelloMessage(const std::uint8_t *message, std::size_t size) {
  {
    std::scoped_lock<std::mutex> lock(snt_hello_msg_cond->GetMutex());
    std::vector<std::uint8_t> buf(message, message + size);
    SetSentHelloMessage(std::move(buf));
  }
  snt_hello_msg_cond->NotifyAll();
}

const Communication::HelloMessage *DataStorage::GetSentHelloMessage() {
  if (sent_hello_message_.empty()) {
    return nullptr;
  }
  auto hm = Communication::GetMessage(sent_hello_message_.data());
  assert(hm != nullptr);
  return Communication::GetHelloMessage(hm->payload()->data());
}

void DataStorage::Reset() {
  Clear();
  output_message_conditions_.clear();
}

void DataStorage::Clear() { received_output_messages_.clear(); }

bool DataStorage::SetSyncState(bool state) {
  if (!sync_condition_) {
    sync_condition_ =
        std::make_shared<ENCRYPTO::Condition>([this]() { return sync_message_received_; });
  }
  {
    std::scoped_lock lock(sync_condition_->GetMutex());
    std::swap(sync_message_received_, state);
  }
  sync_condition_->NotifyAll();
  return state;
}

std::shared_ptr<ENCRYPTO::Condition> &DataStorage::GetSyncCondition() {
  if (!sync_condition_) {
    sync_condition_ =
        std::make_shared<ENCRYPTO::Condition>([this]() { return sync_message_received_; });
  }
  return sync_condition_;
}

void DataStorage::BaseOTsReceived(const std::uint8_t *message, BaseOTsDataType type,
                                  std::size_t ot_id) {
  switch (type) {
    case BaseOTsDataType::HL17_R: {
      {
        std::scoped_lock lock(base_ots_sender_data_->received_R_condition_.at(ot_id)->GetMutex());
        std::copy(message, message + base_ots_sender_data_->R_.at(ot_id).size(),
                  reinterpret_cast<std::uint8_t *>(base_ots_sender_data_->R_.at(ot_id).data()));
        base_ots_sender_data_->received_R_.Set(true, ot_id);
      }
      base_ots_sender_data_->received_R_condition_.at(ot_id)->NotifyOne();
      break;
    }
    case BaseOTsDataType::HL17_S: {
      {
        std::scoped_lock lock(base_ots_receiver_data_->received_S_condition_.at(ot_id)->GetMutex());
        std::copy(message, message + base_ots_receiver_data_->S_.at(ot_id).size(),
                  reinterpret_cast<std::uint8_t *>(base_ots_receiver_data_->S_.at(ot_id).begin()));
        base_ots_receiver_data_->received_S_.Set(true, ot_id);
      }
      base_ots_receiver_data_->received_S_condition_.at(ot_id)->NotifyOne();
      break;
    }
    default: {
      throw std::runtime_error(
          fmt::format("DataStorage::BaseOTsReceived: unknown data type {}; data_type must be <{}",
                      type, BaseOTsDataType::BaseOTs_invalid_data_type));
    }
  }
}
}