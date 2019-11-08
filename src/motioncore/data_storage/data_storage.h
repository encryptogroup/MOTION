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

#pragma once

#include <boost/fiber/future.hpp>
#include <mutex>

#include "utility/bit_vector.h"
#include "utility/reusable_future.h"
#include "utility/typedefs.h"

namespace ENCRYPTO {
class Condition;
using ConditionPtr = std::shared_ptr<Condition>;

class BitMatrix;
}  // namespace ENCRYPTO

namespace MOTION {

namespace Communication {
struct HelloMessage;
}

class Logger;
using LoggerPtr = std::shared_ptr<Logger>;

struct BaseOTsData;
struct BMRData;
struct OTExtensionData;
struct SharedBitsData;

class DataStorage {
 public:
  DataStorage(std::size_t id);

  ~DataStorage() = default;

  void SetLogger(const LoggerPtr &logger) { logger_ = logger; }

  const auto &GetLogger() { return logger_; }

  ENCRYPTO::ReusableFiberFuture<std::vector<std::uint8_t>> RegisterForOutputMessage(
      std::size_t gate_id);

  void SetReceivedOutputMessage(std::vector<std::uint8_t> &&output_message);

  void SetReceivedHelloMessage(std::vector<std::uint8_t> &&hello_message);

  const Communication::HelloMessage *GetReceivedHelloMessage();

  ENCRYPTO::ConditionPtr &GetReceivedHelloMessageCondition() { return rcv_hello_msg_cond_; }

  void SetSentHelloMessage(std::vector<std::uint8_t> &&hello_message) {
    sent_hello_message_ = std::move(hello_message);
  }

  void SetSentHelloMessage(const std::uint8_t *message, std::size_t size);

  const Communication::HelloMessage *GetSentHelloMessage();

  ENCRYPTO::ConditionPtr &GetSentHelloMessageCondition() { return snt_hello_msg_cond_; }

  void Reset();

  void Clear();

  void SetReceivedSyncState(const size_t state);

  std::size_t IncrementMySyncState();

  ENCRYPTO::ConditionPtr &GetSyncCondition();

  auto &GetBaseOTsData() { return base_ots_data_; }

  auto &GetOTExtensionData() { return ot_extension_data_; }

  auto &GetBMRData() { return bmr_data_; }

  auto &GetSharedBitsData() { return *shared_bits_data_; }

  void SetFixedKeyAESKey(const ENCRYPTO::AlignedBitVector &key) { fixed_key_aes_key_ = key; }
  const auto &GetFixedKeyAESKey() { return fixed_key_aes_key_; }

  auto GetID() { return id_; }

 private:
  std::vector<std::uint8_t> received_hello_message_, sent_hello_message_;
  ENCRYPTO::ConditionPtr rcv_hello_msg_cond_, snt_hello_msg_cond_, sync_cond_;

  ENCRYPTO::AlignedBitVector fixed_key_aes_key_;

  std::size_t sync_state_received_{0}, sync_state_actual_{0};

  // gate_id -> promise<buffer>
  std::unordered_map<std::size_t, ENCRYPTO::ReusableFiberPromise<std::vector<std::uint8_t>>>
      output_message_promises_;
  std::mutex output_message_promises_mutex_;

  std::unique_ptr<BaseOTsData> base_ots_data_;

  std::unique_ptr<OTExtensionData> ot_extension_data_;

  std::unique_ptr<BMRData> bmr_data_;

  std::unique_ptr<SharedBitsData> shared_bits_data_;

  LoggerPtr logger_;
  std::int64_t id_{-1};
  std::mutex output_message_mutex_;
};
}  // namespace MOTION
