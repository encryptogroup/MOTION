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
#include <thread>

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
  // Initialize forward-declared structs and their conditions conditions
  rcv_hello_msg_cond =
      std::make_shared<ENCRYPTO::Condition>([this]() { return !received_hello_message_.empty(); });
  snt_hello_msg_cond =
      std::make_shared<ENCRYPTO::Condition>([this]() { return !sent_hello_message_.empty(); });

  base_ots_receiver_data_ = std::make_unique<BaseOTsReceiverData>();
  base_ots_receiver_data_->is_ready_condition_ = std::make_unique<ENCRYPTO::Condition>(
      [this]() { return base_ots_receiver_data_->is_ready_; });
  base_ots_sender_data_ = std::make_unique<BaseOTsSenderData>();
  base_ots_sender_data_->is_ready_condition_ =
      std::make_unique<ENCRYPTO::Condition>([this]() { return base_ots_sender_data_->is_ready_; });

  ot_extension_sender_data_ = std::make_unique<OTExtensionSenderData>();
  ot_extension_receiver_data_ = std::make_unique<OTExtensionReceiverData>();

  ot_extension_sender_data_->received_u_condition_ =
      std::make_unique<ENCRYPTO::Condition>([this]() {
        return ot_extension_sender_data_->num_u_received_ == ot_extension_sender_data_->u_.size();
      });

  ot_extension_sender_data_->setup_finished_condition_ = std::make_unique<ENCRYPTO::Condition>(
      [this]() { return ot_extension_sender_data_->setup_finished_; });

  ot_extension_receiver_data_->setup_finished_condition_ = std::make_unique<ENCRYPTO::Condition>(
      [this]() { return ot_extension_receiver_data_->setup_finished_; });
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

void DataStorage::BaseOTsReceived(const std::uint8_t *message, const BaseOTsDataType type,
                                  const std::size_t ot_id) {
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

void DataStorage::OTExtensionReceived(const std::uint8_t *message, const OTExtensionDataType type,
                                      const std::size_t i) {
  switch (type) {
    case OTExtensionDataType::rcv_masks: {
      {
        while (ot_extension_sender_data_->bit_size_ == 0) {
          std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
        std::scoped_lock lock(ot_extension_sender_data_->received_u_condition_->GetMutex());
        ot_extension_sender_data_->u_.at(i) =
            ENCRYPTO::AlignedBitVector(message, ot_extension_sender_data_->bit_size_);
        ot_extension_sender_data_->num_u_received_++;
        ot_extension_sender_data_->received_u_ids_.push(i);
      }

      ot_extension_sender_data_->received_u_condition_->NotifyAll();
      break;
    }
    case OTExtensionDataType::rcv_corrections: {
      auto cond = ot_extension_sender_data_->received_correction_offsets_cond_.find(i);
      if (cond == ot_extension_sender_data_->received_correction_offsets_cond_.end()) {
        throw std::runtime_error(fmt::format(
            "Could not find Condition for OT#{} OTExtensionDataType::rcv_corrections", i));
      }
      {
        std::scoped_lock lock(cond->second->GetMutex(),
                              ot_extension_sender_data_->corrections_mutex_);
        auto num_ots = ot_extension_sender_data_->num_ots_in_batch_.find(i);
        if (num_ots == ot_extension_sender_data_->num_ots_in_batch_.end()) {
          throw std::runtime_error(fmt::format(
              "Could not find num_ots for OT#{} OTExtensionDataType::rcv_corrections", i));
        }
        ENCRYPTO::BitVector<> local_corrections(message, num_ots->second);
        ot_extension_sender_data_->corrections_.Copy(i, i + num_ots->second, local_corrections);
        ot_extension_sender_data_->received_correction_offsets_.insert(i);
      }
      cond->second->NotifyAll();
      break;
    }
    case OTExtensionDataType::snd_messages: {
      {
        ABYN::Helpers::WaitFor(*ot_extension_receiver_data_->setup_finished_condition_);

        auto it_c = ot_extension_receiver_data_->output_conditions_.find(i);
        if (it_c == ot_extension_receiver_data_->output_conditions_.end()) {
          throw std::runtime_error(fmt::format(
              "Could not find Condition for OT#{} OTExtensionDataType::snd_messages", i));
        }

        const auto bitlen = ot_extension_receiver_data_->bitlengths_.at(i);
        const auto bs_it = ot_extension_receiver_data_->num_ots_in_batch_.find(i);
        if (bs_it == ot_extension_receiver_data_->num_ots_in_batch_.end()) {
          throw std::runtime_error(fmt::format(
              "Could not find batch size for OT#{} OTExtensionDataType::snd_messages", i));
        }

        const auto batch_size = bs_it->second;
        while (ot_extension_receiver_data_->num_messages_.find(i) ==
               ot_extension_receiver_data_->num_messages_.end()) {
          std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
        const auto n = ot_extension_receiver_data_->num_messages_.at(i);

        ENCRYPTO::BitVector<> message_bv(message, batch_size * bitlen * n);

        while (ot_extension_receiver_data_->real_choices_cond_.find(i) ==
               ot_extension_receiver_data_->real_choices_cond_.end()) {
          std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
        ABYN::Helpers::WaitFor(*ot_extension_receiver_data_->real_choices_cond_.at(i));

        for (auto j = 0ull; j < batch_size; ++j) {
          if (n == 2) {
            if (ot_extension_receiver_data_->random_choices_->Get(i + j)) {
              ot_extension_receiver_data_->outputs_.at(i + j) ^=
                  message_bv.Subset((2 * j + 1) * bitlen, (2 * j + 2) * bitlen);
            } else {
              ot_extension_receiver_data_->outputs_.at(i + j) ^=
                  message_bv.Subset(2 * j * bitlen, (2 * j + 1) * bitlen);
            }
          } else if (n == 1) {
            if (ot_extension_receiver_data_->real_choices_->Get(i + j)) {
              ot_extension_receiver_data_->outputs_.at(i + j) ^=
                  message_bv.Subset(j * bitlen, (j + 1) * bitlen);
            }
          } else {
            throw std::runtime_error("Not inmplemented yet");
          }
        }

        {
          std::scoped_lock lock(it_c->second->GetMutex());
          ot_extension_receiver_data_->received_outputs_.emplace(i, true);
        }
        it_c->second->NotifyAll();
      }
      break;
    }
    default: {
      throw std::runtime_error(fmt::format(
          "DataStorage::OTExtensionDataType: unknown data type {}; data_type must be <{}", type,
          OTExtensionDataType::OTExtension_invalid_data_type));
    }
  }
}
}