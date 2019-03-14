#include "data_storage.h"

namespace ABYN {

  void DataStorage::SetReceivedOutputMessage(std::vector<u8> &&output_message) {
    auto message = ABYN::Communication::GetMessage(output_message.data());
    auto output_message_ptr = ABYN::Communication::GetOutputMessage(message->payload()->data());

    auto gate_id = output_message_ptr->gate_id();

    auto ret = received_output_messages_.insert({gate_id, std::move(output_message)});
    if (!ret.second) {
      logger_->LogError(fmt::format(
          "Failed to insert new output message from Party#{} for gate#{}, found another buffer on its place",
          id_, gate_id));
    }
    logger_->LogDebug(fmt::format("Received an output message from Party#{} for gate#{}", id_, gate_id));
  }

  const ABYN::Communication::OutputMessage *DataStorage::GetOutputMessage(size_t gate_id) {
    auto message = received_output_messages_.find(gate_id);
    if (message == received_output_messages_.end()) { return nullptr; }
    auto output_message = ABYN::Communication::GetMessage(message->second.data());
    assert(output_message != nullptr);
    return ABYN::Communication::GetOutputMessage(output_message->payload()->data());
  }

  const ABYN::Communication::HelloMessage *DataStorage::GetReceivedHelloMessage() {
    if (received_hello_message_.empty()) { return nullptr; }
    auto hello_message = ABYN::Communication::GetMessage(received_hello_message_.data());
    assert(hello_message != nullptr);
    return ABYN::Communication::GetHelloMessage(hello_message->payload()->data());
  }

  void DataStorage::SetSentHelloMessage(const u8 *message, size_t size) {
    std::vector<u8> buf(message, message + size);
    SetSentHelloMessage(std::move(buf));
  }

  const ABYN::Communication::HelloMessage *DataStorage::GetSentHelloMessage() {
    if (sent_hello_message_.empty()) { return nullptr; }
    auto hm = ABYN::Communication::GetMessage(sent_hello_message_.data());
    assert(hm != nullptr);
    return ABYN::Communication::GetHelloMessage(hm->payload()->data());
  }

}