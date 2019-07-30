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

#include "utility/typedefs.h"

namespace ENCRYPTO {
class Condition;
}

namespace ABYN {

class Logger;
using LoggerPtr = std::shared_ptr<Logger>;

class DataStorage {
 public:
  DataStorage(std::size_t id);

  ~DataStorage() = default;

  void SetLogger(const LoggerPtr &logger) { logger_ = logger; }

  void SetReceivedOutputMessage(std::vector<std::uint8_t> &&output_message);

  const Communication::OutputMessage *GetOutputMessage(const std::size_t gate_id);

  void SetReceivedHelloMessage(std::vector<std::uint8_t> &&hello_message);

  const Communication::HelloMessage *GetReceivedHelloMessage();

  std::shared_ptr<ENCRYPTO::Condition> &GetReceivedHelloMessageCondition() {
    return rcv_hello_msg_cond;
  }

  void SetSentHelloMessage(std::vector<std::uint8_t> &&hello_message) {
    sent_hello_message_ = std::move(hello_message);
  }

  void SetSentHelloMessage(const std::uint8_t *message, std::size_t size);

  const Communication::HelloMessage *GetSentHelloMessage();

  std::shared_ptr<ENCRYPTO::Condition> &GetSentHelloMessageCondition() {
    return snt_hello_msg_cond;
  }

  void Reset();

  void Clear();

  bool SetSyncState(bool state);

  std::shared_ptr<ENCRYPTO::Condition> &GetSyncCondition();

 private:
  std::vector<std::uint8_t> received_hello_message_, sent_hello_message_;
  std::shared_ptr<ENCRYPTO::Condition> rcv_hello_msg_cond, snt_hello_msg_cond, sync_condition_;

  bool sync_message_received_ = false;

  // id, buffer
  std::unordered_map<std::size_t, std::vector<std::uint8_t>> received_output_messages_;
  // id, condition
  std::unordered_map<std::size_t, std::shared_ptr<ENCRYPTO::Condition>> output_message_conditions_;

  LoggerPtr logger_;
  std::int64_t id_ = -1;
  std::mutex output_message_mutex_;
};
}  // namespace ABYN
