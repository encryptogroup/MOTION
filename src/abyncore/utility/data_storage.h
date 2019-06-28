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

  void SetLogger(const ABYN::LoggerPtr &logger) { logger_ = logger; }

  void SetReceivedOutputMessage(std::vector<std::uint8_t> &&output_message);

  const ABYN::Communication::OutputMessage *GetOutputMessage(const std::size_t gate_id);

  const ABYN::Communication::OutputMessage *GetOutputMessageCondition(const std::size_t gate_id);

  void SetReceivedHelloMessage(std::vector<std::uint8_t> &&hello_message);

  const ABYN::Communication::HelloMessage *GetReceivedHelloMessage();

  std::shared_ptr<ENCRYPTO::Condition> &GetReceivedHelloMessageCondition() {
    return rcv_hello_msg_cond;
  }

  void SetSentHelloMessage(std::vector<std::uint8_t> &&hello_message) {
    sent_hello_message_ = std::move(hello_message);
  }

  void SetSentHelloMessage(const std::uint8_t *message, std::size_t size);

  const ABYN::Communication::HelloMessage *GetSentHelloMessage();

  std::shared_ptr<ENCRYPTO::Condition> &GetSentHelloMessageCondition() {
    return snt_hello_msg_cond;
  }

 private:
  std::vector<std::uint8_t> received_hello_message_, sent_hello_message_;
  std::shared_ptr<ENCRYPTO::Condition> rcv_hello_msg_cond, snt_hello_msg_cond;

  // id, buffer
  std::unordered_map<std::size_t, std::vector<std::uint8_t>>
      received_output_messages_;
  // id, condition
  std::unordered_map<std::size_t, std::shared_ptr<ENCRYPTO::Condition>> output_message_conditions_;

  ABYN::LoggerPtr logger_;
  std::int64_t id_ = -1;
  std::mutex output_message_mutex_;
};
}  // namespace ABYN
