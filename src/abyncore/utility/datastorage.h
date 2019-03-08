#ifndef DATASTORAGE_H
#define DATASTORAGE_H

#include <queue>
#include <unordered_set>

#include <fmt/format.h>

#include "communication/fbs_headers/message_generated.h"
#include "communication/fbs_headers/hello_message_generated.h"
#include "communication/fbs_headers/output_message_generated.h"

#include "utility/typedefs.h"
#include "utility/logger.h"

namespace ABYN {
  class DataStorage {
  public:
    DataStorage(ssize_t id) : id_(id) {}

    ~DataStorage() {}

    void SetLogger(const ABYN::LoggerPtr &logger) { logger_ = logger; }

    void SetReceivedOutputMessage(std::vector<u8> &&output_message) {
      const auto output_message_ptr = ABYN::Communication::GetOutputMessage(output_message.data());
      auto gate_id = output_message_ptr->gate_id();

      auto ret = received_output_messages_.insert({gate_id, std::move(output_message)});
      if (!ret.second) {
        logger_->LogError(fmt::format(
            "Failed to insert new output message from Party#{} for gate#{}, found another buffer on its place",
            id_, gate_id));
      }
      logger_->LogDebug(fmt::format("Received an output message from Party#{} for gate#{}", id_, gate_id));
    }

    const ABYN::Communication::OutputMessage *GetOutputMessage(size_t gate_id) {
      auto message = received_output_messages_.find(gate_id);
      if (message == received_output_messages_.end()) { return nullptr; }
      auto output_message = ABYN::Communication::GetMessage(message->second.data());
      assert(output_message != nullptr);
      return ABYN::Communication::GetOutputMessage(output_message->payload()->data());
    }

    void SetReceivedHelloMessage(std::vector<u8> &&hello_message) {
      received_hello_message_ = std::move(hello_message);
    }

    const ABYN::Communication::HelloMessage *GetReceivedHelloMessage() {
      if (received_hello_message_.empty()) { return nullptr; }
      auto hello_message = ABYN::Communication::GetMessage(received_hello_message_.data());
      assert(hello_message != nullptr);
      return ABYN::Communication::GetHelloMessage(hello_message->payload()->data());
    }

    void SetSentHelloMessage(std::vector<u8> &&hello_message) { sent_hello_message_ = std::move(hello_message); }

    void SetSentHelloMessage(const u8 *message, size_t size) {
      std::vector<u8> buf(message, message + size);
      SetSentHelloMessage(std::move(buf));
    }

    const ABYN::Communication::HelloMessage *GetSentHelloMessage() {
      if (sent_hello_message_.empty()) { return nullptr; }
      auto hm = ABYN::Communication::GetMessage(sent_hello_message_.data());
      assert(hm != nullptr);
      return ABYN::Communication::GetHelloMessage(hm->payload()->data());
    }

  private:
    std::vector<u8> received_hello_message_, sent_hello_message_;
    std::unordered_map<size_t, std::vector<u8>> received_output_messages_; // id, buffer
    ABYN::LoggerPtr logger_;
    ssize_t id_ = -1;
  };
}

#endif //DATASTORAGE_H
