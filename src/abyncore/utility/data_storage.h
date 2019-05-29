#pragma once

#include <mutex>
#include <queue>
#include <unordered_set>

#include <fmt/format.h>

#include "communication/fbs_headers/hello_message_generated.h"
#include "communication/fbs_headers/message_generated.h"
#include "communication/fbs_headers/output_message_generated.h"

#include "utility/logger.h"
#include "utility/typedefs.h"

namespace ABYN {
class DataStorage {
 public:
  DataStorage(std::size_t id) : id_(id) {}

  ~DataStorage() = default;

  void SetLogger(const ABYN::LoggerPtr &logger) { logger_ = logger; }

  void SetReceivedOutputMessage(std::vector<std::uint8_t> &&output_message);

  const ABYN::Communication::OutputMessage *GetOutputMessage(const std::size_t gate_id);

  void SetReceivedHelloMessage(std::vector<std::uint8_t> &&hello_message) {
    received_hello_message_ = std::move(hello_message);
  }

  const ABYN::Communication::HelloMessage *GetReceivedHelloMessage();

  void SetSentHelloMessage(std::vector<std::uint8_t> &&hello_message) {
    sent_hello_message_ = std::move(hello_message);
  }

  void SetSentHelloMessage(const std::uint8_t *message, std::size_t size);

  const ABYN::Communication::HelloMessage *GetSentHelloMessage();

 private:
  std::vector<std::uint8_t> received_hello_message_, sent_hello_message_;
  std::unordered_map<std::size_t, std::vector<std::uint8_t>>
      received_output_messages_;  // id, buffer
  ABYN::LoggerPtr logger_;
  std::int64_t id_ = -1;
  std::mutex output_message_mutex_;
};
}  // namespace ABYN
