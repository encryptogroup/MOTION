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

#include <mutex>
#include <queue>
#include <unordered_set>

#include <fmt/format.h>

#include "communication/fbs_headers/hello_message_generated.h"
#include "communication/fbs_headers/message_generated.h"
#include "communication/fbs_headers/output_message_generated.h"

#include "utility/bit_vector.h"
#include "utility/typedefs.h"

namespace ENCRYPTO {
class Condition;
using ConditionPtr = std::shared_ptr<Condition>;

class BitMatrix;
}  // namespace ENCRYPTO

namespace ABYN {

class Logger;
using LoggerPtr = std::shared_ptr<Logger>;

struct BaseOTsReceiverData {
  BaseOTsReceiverData();
  ~BaseOTsReceiverData() = default;

  ENCRYPTO::BitVector<> c_;  /// choice bits
  std::array<std::array<std::byte, 16>, 128> messages_c_;

  std::vector<std::array<std::byte, 32>> S_;
  ENCRYPTO::BitVector<> received_S_;
  std::vector<std::unique_ptr<ENCRYPTO::Condition>> received_S_condition_;

  bool is_ready_ = false;
  std::unique_ptr<ENCRYPTO::Condition> is_ready_condition_;
};

struct BaseOTsSenderData {
  BaseOTsSenderData();
  ~BaseOTsSenderData() = default;

  std::array<std::array<std::byte, 16>, 128> messages_0_;
  std::array<std::array<std::byte, 16>, 128> messages_1_;

  std::vector<std::array<std::byte, 32>> R_;
  ENCRYPTO::BitVector<> received_R_;
  std::vector<std::unique_ptr<ENCRYPTO::Condition>> received_R_condition_;

  bool is_ready_ = false;
  std::unique_ptr<ENCRYPTO::Condition> is_ready_condition_;
};

enum BaseOTsDataType : uint { HL17_R = 0, HL17_S = 1, BaseOTs_invalid_data_type = 3 };

class DataStorage {
 public:
  DataStorage(std::size_t id);

  ~DataStorage() = default;

  void SetLogger(const LoggerPtr &logger) { logger_ = logger; }

  void SetReceivedOutputMessage(std::vector<std::uint8_t> &&output_message);

  const Communication::OutputMessage *GetOutputMessage(const std::size_t gate_id);

  void SetReceivedHelloMessage(std::vector<std::uint8_t> &&hello_message);

  const Communication::HelloMessage *GetReceivedHelloMessage();

  ENCRYPTO::ConditionPtr &GetReceivedHelloMessageCondition() { return rcv_hello_msg_cond; }

  void SetSentHelloMessage(std::vector<std::uint8_t> &&hello_message) {
    sent_hello_message_ = std::move(hello_message);
  }

  void SetSentHelloMessage(const std::uint8_t *message, std::size_t size);

  const Communication::HelloMessage *GetSentHelloMessage();

  ENCRYPTO::ConditionPtr &GetSentHelloMessageCondition() { return snt_hello_msg_cond; }

  void Reset();

  void Clear();

  bool SetSyncState(bool state);

  ENCRYPTO::ConditionPtr &GetSyncCondition();

  void BaseOTsReceived(const std::uint8_t *message, BaseOTsDataType type, std::size_t ot_id = 0);

  auto &GetBaseOTsReceiverData() { return base_ots_receiver_data_; }
  auto &GetBaseOTsSenderData() { return base_ots_sender_data_; }

 private:
  std::vector<std::uint8_t> received_hello_message_, sent_hello_message_;
  ENCRYPTO::ConditionPtr rcv_hello_msg_cond, snt_hello_msg_cond, sync_condition_;

  bool sync_message_received_ = false;

  // id, buffer
  std::unordered_map<std::size_t, std::vector<std::uint8_t>> received_output_messages_;
  // id, condition
  std::unordered_map<std::size_t, ENCRYPTO::ConditionPtr> output_message_conditions_;

  std::unique_ptr<BaseOTsReceiverData> base_ots_receiver_data_;
  std::unique_ptr<BaseOTsSenderData> base_ots_sender_data_;

  LoggerPtr logger_;
  std::int64_t id_ = -1;
  std::mutex output_message_mutex_;
};
}  // namespace ABYN
