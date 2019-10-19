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

#include "data_storage.h"

#include <mutex>
#include <thread>

#include "utility/condition.h"
#include "utility/constants.h"
#include "utility/logger.h"

namespace MOTION {

BaseOTsReceiverData::BaseOTsReceiverData() : received_S_(128, false) {
  for (auto i = 0; i < 128; ++i) {
    received_S_condition_.emplace_back(
        std::make_unique<ENCRYPTO::Condition>([this, i]() { return received_S_.at(i); }));
  }
  S_.resize(128);

  is_ready_condition_ =
      std::make_unique<ENCRYPTO::Condition>([this]() { return is_ready_.load(); });
}

BaseOTsSenderData::BaseOTsSenderData() : received_R_(128, false) {
  for (auto i = 0; i < 128; ++i) {
    received_R_condition_.emplace_back(
        std::make_unique<ENCRYPTO::Condition>([this, i]() { return received_R_.at(i); }));
  }
  R_.resize(128);

  is_ready_condition_ =
      std::make_unique<ENCRYPTO::Condition>([this]() { return is_ready_.load(); });
}

DataStorage::DataStorage(std::size_t id) : id_(id) {
  // Initialize forward-declared structs and their conditions conditions
  rcv_hello_msg_cond_ =
      std::make_shared<ENCRYPTO::Condition>([this]() { return !received_hello_message_.empty(); });
  snt_hello_msg_cond_ =
      std::make_shared<ENCRYPTO::Condition>([this]() { return !sent_hello_message_.empty(); });

  base_ots_receiver_data_ = std::make_unique<BaseOTsReceiverData>();
  base_ots_receiver_data_->is_ready_condition_ = std::make_unique<ENCRYPTO::Condition>(
      [this]() { return base_ots_receiver_data_->is_ready_.load(); });
  base_ots_sender_data_ = std::make_unique<BaseOTsSenderData>();
  base_ots_sender_data_->is_ready_condition_ = std::make_unique<ENCRYPTO::Condition>(
      [this]() { return base_ots_sender_data_->is_ready_.load(); });

  ot_extension_sender_data_ = std::make_unique<OTExtensionSenderData>();
  ot_extension_receiver_data_ = std::make_unique<OTExtensionReceiverData>();

  ot_extension_sender_data_->received_u_condition_ =
      std::make_unique<ENCRYPTO::Condition>([this]() {
        return ot_extension_sender_data_->num_u_received_ == ot_extension_sender_data_->u_.size();
      });

  ot_extension_sender_data_->setup_finished_cond_ = std::make_unique<ENCRYPTO::Condition>(
      [this]() { return ot_extension_sender_data_->setup_finished_.load(); });

  ot_extension_receiver_data_->setup_finished_cond_ = std::make_unique<ENCRYPTO::Condition>(
      [this]() { return ot_extension_receiver_data_->setup_finished_.load(); });

  bmr_data_ = std::make_unique<BMRData>();

  sync_cond_ = std::make_shared<ENCRYPTO::Condition>(
      [this]() { return sync_state_received_ >= sync_state_actual_; });
}

boost::fibers::future<std::vector<std::uint8_t>> DataStorage::RegisterForOutputMessage(std::size_t gate_id) {
  boost::fibers::promise<std::vector<std::uint8_t>> promise;
  auto future = promise.get_future();
  std::unique_lock<std::mutex> lock(output_message_promises_mutex_);
  auto [_, success] = output_message_promises_.insert({gate_id, std::move(promise)});
  lock.unlock();
  if (!success) {
    logger_->LogError(
        fmt::format("Tried to register twice for OutputMessage with gate#{}", gate_id));
    return boost::fibers::future<std::vector<std::uint8_t>>();  // XXX: maybe throw an exception here
  }
  if constexpr (MOTION_VERBOSE_DEBUG) {
    logger_->LogDebug(
        fmt::format("Registered for OutputMessage from Party#{} for gate#{}", gate_id, id_));
  }
  return future;
}

void DataStorage::SetReceivedOutputMessage(std::vector<std::uint8_t> &&output_message) {
  assert(!output_message.empty());
  auto message = Communication::GetMessage(output_message.data());
  auto output_message_ptr = Communication::GetOutputMessage(message->payload()->data());
  auto gate_id = output_message_ptr->gate_id();

  // find promise
  std::unique_lock<std::mutex> lock(output_message_promises_mutex_);
  auto it = output_message_promises_.find(gate_id);
  if (it == output_message_promises_.end()) {
    // no promise found -> drop message
    logger_->LogError(fmt::format(
        "Received unexpected OutputMessage from Party#{} for gate#{}, dropping", id_, gate_id));
    return;
  }
  auto promise = std::move(it->second);
  output_message_promises_.erase(it);
  lock.unlock();
  // put the received message into the promise
  try {
    promise.set_value(std::move(output_message));
  } catch (std::future_error &e) {
    // there might be already a value in the promise
    logger_->LogError(
        fmt::format("Error while processing OutputMessage from Party#{} for gate#{}, dropping: {}",
                    id_, gate_id, e.what()));
    return;
  }

  logger_->LogDebug(
      fmt::format("Received an OutputMessage from Party#{} for gate#{}", id_, gate_id));
}

void DataStorage::SetReceivedHelloMessage(std::vector<std::uint8_t> &&hello_message) {
  {
    std::scoped_lock<std::mutex> lock(rcv_hello_msg_cond_->GetMutex());
    received_hello_message_ = std::move(hello_message);
  }
  rcv_hello_msg_cond_->NotifyAll();
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
    std::scoped_lock<std::mutex> lock(snt_hello_msg_cond_->GetMutex());
    std::vector<std::uint8_t> buf(message, message + size);
    SetSentHelloMessage(std::move(buf));
  }
  snt_hello_msg_cond_->NotifyAll();
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
  output_message_promises_.clear();
}

void DataStorage::Clear() {
  for (auto &e : bmr_data_->input_public_values_) {
    e.second.second = decltype(e.second.second)();
  }
  for (auto &e : bmr_data_->input_public_keys_) {
    e.second.second = decltype(e.second.second)();
  }
}

void DataStorage::SetReceivedSyncState(const std::size_t state) {
  {
    std::scoped_lock lock(sync_cond_->GetMutex());
    if (state > sync_state_received_) {
      sync_state_received_ = state;
    }
  }
  sync_cond_->NotifyAll();
}

std::size_t DataStorage::IncrementMySyncState() {
  {
    std::scoped_lock lock(sync_cond_->GetMutex());
    ++sync_state_actual_;
  }
  sync_cond_->NotifyAll();
  return sync_state_actual_;
}

std::shared_ptr<ENCRYPTO::Condition> &DataStorage::GetSyncCondition() { return sync_cond_; }

void DataStorage::BaseOTsReceived(const std::uint8_t *message, const BaseOTsDataType type,
                                  const std::size_t ot_id) {
  switch (type) {
    case BaseOTsDataType::HL17_R: {
      {
        std::scoped_lock lock(base_ots_sender_data_->received_R_condition_.at(ot_id)->GetMutex());
        std::copy(message, message + base_ots_sender_data_->R_.at(ot_id).size(),
                  reinterpret_cast<std::uint8_t *>(base_ots_sender_data_->R_.at(ot_id).data()));
        base_ots_sender_data_->received_R_.at(ot_id) = true;
      }
      base_ots_sender_data_->received_R_condition_.at(ot_id)->NotifyOne();
      break;
    }
    case BaseOTsDataType::HL17_S: {
      {
        std::scoped_lock lock(base_ots_receiver_data_->received_S_condition_.at(ot_id)->GetMutex());
        std::copy(message, message + base_ots_receiver_data_->S_.at(ot_id).size(),
                  reinterpret_cast<std::uint8_t *>(base_ots_receiver_data_->S_.at(ot_id).begin()));
        base_ots_receiver_data_->received_S_.at(ot_id) = true;
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
        ot_extension_sender_data_->received_correction_offsets_.emplace(i);
      }
      cond->second->NotifyAll();
      break;
    }
    case OTExtensionDataType::snd_messages: {
      {
        MOTION::Helpers::WaitFor(*ot_extension_receiver_data_->setup_finished_cond_);

        auto it_c = ot_extension_receiver_data_->output_conds_.find(i);
        if (it_c == ot_extension_receiver_data_->output_conds_.end()) {
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
        MOTION::Helpers::WaitFor(*ot_extension_receiver_data_->real_choices_cond_.at(i));

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
              if (ot_extension_receiver_data_->xor_correlation_.find(i) !=
                  ot_extension_receiver_data_->xor_correlation_.end()) {
                ot_extension_receiver_data_->outputs_.at(i + j) ^=
                    message_bv.Subset(j * bitlen, (j + 1) * bitlen);
              } else {
                auto msg = message_bv.Subset(j * bitlen, (j + 1) * bitlen);
                auto out = ot_extension_receiver_data_->outputs_.at(i + j).GetMutableData().data();
                switch (bitlen) {
                  case 8u: {
                    *reinterpret_cast<uint8_t *>(out) =
                        *reinterpret_cast<const uint8_t *>(msg.GetData().data()) -
                        *reinterpret_cast<const uint8_t *>(out);
                    break;
                  }
                  case 16u: {
                    *reinterpret_cast<uint16_t *>(out) =
                        *reinterpret_cast<const uint16_t *>(msg.GetData().data()) -
                        *reinterpret_cast<const uint16_t *>(out);
                    break;
                  }
                  case 32u: {
                    *reinterpret_cast<uint32_t *>(out) =
                        *reinterpret_cast<const uint32_t *>(msg.GetData().data()) -
                        *reinterpret_cast<const uint32_t *>(out);
                    break;
                  }
                  case 64u: {
                    *reinterpret_cast<uint64_t *>(out) =
                        *reinterpret_cast<const uint64_t *>(msg.GetData().data()) -
                        *reinterpret_cast<const uint64_t *>(out);
                    break;
                  }
                  default:
                    throw std::runtime_error(
                        fmt::format("Unsupported bitlen={} for additive correlation. Allowed are "
                                    "bitlengths: 8, 16, 32, 64.",
                                    bitlen));
                }
              }
            }
          } else {
            throw std::runtime_error("Not inmplemented yet");
          }
        }

        {
          std::scoped_lock lock(it_c->second->GetMutex(),
                                ot_extension_receiver_data_->received_outputs_mutex_);
          ot_extension_receiver_data_->received_outputs_.emplace(i);
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

void DataStorage::BMRMessageReceived(const std::uint8_t *message, const BMRDataType type,
                                     const std::size_t i) {
  switch (type) {
    case BMRDataType::input_step_0: {
      assert(bmr_data_->input_public_values_.find(i) != bmr_data_->input_public_values_.end());
      std::size_t bitlen = bmr_data_->input_public_values_.at(i).first;
      bmr_data_->input_public_values_.at(i).second.set_value(
          std::make_unique<ENCRYPTO::BitVector<>>(message, bitlen));
      break;
    }
    case BMRDataType::input_step_1: {
      assert(bmr_data_->input_public_keys_.find(i) != bmr_data_->input_public_keys_.end());
      std::size_t bitlen = bmr_data_->input_public_keys_.at(i).first;
      assert(bitlen % 128 == 0);
      bmr_data_->input_public_keys_.at(i).second.set_value(
          std::make_unique<ENCRYPTO::BitVector<>>(message, bitlen));
      break;
    }
    case BMRDataType::and_gate: {
      assert(bmr_data_->garbled_rows_.find(i) != bmr_data_->garbled_rows_.end());
      std::size_t bitlen = bmr_data_->garbled_rows_.at(i).first;
      assert(bitlen % 128 == 0);
      bmr_data_->garbled_rows_.at(i).second.set_value(
          std::make_unique<ENCRYPTO::BitVector<>>(message, bitlen));
      break;
    }
    default:
      throw std::runtime_error("Unknown BMR message type");
  }
}
}  // namespace MOTION
