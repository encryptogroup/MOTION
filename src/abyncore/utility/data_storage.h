#ifndef DATASTORAGE_H
#define DATASTORAGE_H

#include <queue>
#include <unordered_set>
#include <mutex>

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

  ~DataStorage() {}

  void SetLogger(const ABYN::LoggerPtr &logger) { logger_ = logger; }

  void SetReceivedOutputMessage(std::vector<u8> &&output_message);

  const ABYN::Communication::OutputMessage *GetOutputMessage(const std::size_t gate_id);

  void SetReceivedHelloMessage(std::vector<u8> &&hello_message) {
    received_hello_message_ = std::move(hello_message);
  }

  const ABYN::Communication::HelloMessage *GetReceivedHelloMessage();

  void SetSentHelloMessage(std::vector<u8> &&hello_message) {
    sent_hello_message_ = std::move(hello_message);
  }

  void SetSentHelloMessage(const u8 *message, std::size_t size);

  const ABYN::Communication::HelloMessage *GetSentHelloMessage();

 private:
  std::vector<u8> received_hello_message_, sent_hello_message_;
  std::unordered_map<std::size_t, std::vector<u8>> received_output_messages_;  // id, buffer
  ABYN::LoggerPtr logger_;
  std::int64_t id_ = -1;
  std::mutex output_message_mutex_;
};
}  // namespace ABYN

#endif  // DATASTORAGE_H
