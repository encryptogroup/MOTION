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

#include "communication/fbs_headers/hello_message_generated.h"
#include "communication/fbs_headers/message_generated.h"
#include "communication/fbs_headers/output_message_generated.h"
#include "data_storage/base_ot_data.h"
#include "data_storage/bmr_data.h"
#include "data_storage/ot_extension_data.h"
#include "data_storage/shared_bits_data.h"
#include "utility/condition.h"
#include "utility/constants.h"
#include "utility/fiber_condition.h"
#include "utility/logger.h"

namespace MOTION {

DataStorage::DataStorage(std::size_t id) : id_(id) {
  // Initialize forward-declared structs and their conditions conditions
  rcv_hello_msg_cond_ =
      std::make_shared<ENCRYPTO::Condition>([this]() { return !received_hello_message_.empty(); });
  snt_hello_msg_cond_ =
      std::make_shared<ENCRYPTO::Condition>([this]() { return !sent_hello_message_.empty(); });

  base_ots_data_ = std::make_unique<BaseOTsData>();
  ot_extension_data_ = std::make_unique<OTExtensionData>();
  bmr_data_ = std::make_unique<BMRData>();
  shared_bits_data_ = std::make_unique<SharedBitsData>();

  sync_cond_ = std::make_shared<ENCRYPTO::Condition>(
      [this]() { return sync_state_received_ >= sync_state_actual_; });
}

ENCRYPTO::ReusableFiberFuture<std::vector<std::uint8_t>> DataStorage::RegisterForOutputMessage(
    std::size_t gate_id) {
  ENCRYPTO::ReusableFiberPromise<std::vector<std::uint8_t>> promise;
  auto future = promise.get_future();
  std::unique_lock<std::mutex> lock(output_message_promises_mutex_);
  auto [_, success] = output_message_promises_.insert({gate_id, std::move(promise)});
  lock.unlock();
  if (!success) {
    logger_->LogError(
        fmt::format("Tried to register twice for OutputMessage with gate#{}", gate_id));
    return {};  // XXX: maybe throw an exception here
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
  auto it = output_message_promises_.find(gate_id);
  if (it == output_message_promises_.end()) {
    // no promise found -> drop message
    logger_->LogError(fmt::format(
        "Received unexpected OutputMessage from Party#{} for gate#{}, dropping", id_, gate_id));
    return;
  }
  auto &promise = it->second;
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
  assert(received_hello_message_.empty());
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
  bmr_data_->Reset();
}

void DataStorage::Clear() { }

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

}  // namespace MOTION
