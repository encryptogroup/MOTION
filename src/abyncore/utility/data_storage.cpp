#include "data_storage.h"

#include <mutex>

#include "utility/condition.h"
#include "utility/logger.h"

namespace ABYN {

DataStorage::DataStorage(std::size_t id) : id_(id) {
  rcv_hello_msg_cond =
      std::make_shared<ENCRYPTO::Condition>([this]() { return !received_hello_message_.empty(); });
  snt_hello_msg_cond =
      std::make_shared<ENCRYPTO::Condition>([this]() { return !sent_hello_message_.empty(); });
};

void DataStorage::SetReceivedOutputMessage(std::vector<std::uint8_t> &&output_message) {
  auto message = Communication::GetMessage(output_message.data());
  auto output_message_ptr = Communication::GetOutputMessage(message->payload()->data());

  auto gate_id = output_message_ptr->gate_id();

  // prevents inserting new elements while searching while GetOutputMessage() is called
  std::scoped_lock lock(output_message_mutex_);

  if (output_message_conditions_.find(gate_id) == output_message_conditions_.end()) {
    // don't need to check anything
    output_message_conditions_.emplace(
        gate_id, std::make_shared<ENCRYPTO::Condition>([]() { return true; }));
  }
  {
    std::scoped_lock lock_cond(output_message_conditions_.find(gate_id)->second->GetMutex());

    auto ret = received_output_messages_.emplace(gate_id, std::move(output_message));
    if (!ret.second) {
      logger_->LogError(
          fmt::format("Failed to insert new output message from Party#{} for "
                      "gate#{}, found another buffer on its place",
                      id_, gate_id));
    }
    logger_->LogDebug(
        fmt::format("Received an output message from Party#{} for gate#{}", id_, gate_id));
  }

  output_message_conditions_.find(gate_id)->second->NotifyAll();
}

const Communication::OutputMessage *DataStorage::GetOutputMessage(const std::size_t gate_id) {
  std::unordered_map<std::size_t, std::vector<std::uint8_t>>::iterator iterator, end;
  {
    // prevent SetReceivedOutputMessage() to insert new elements while searching
    std::scoped_lock lock(output_message_mutex_);

    // create condition if there is no
    if (output_message_conditions_.find(gate_id) == output_message_conditions_.end()) {
      output_message_conditions_.emplace(
          gate_id, std::make_shared<ENCRYPTO::Condition>([this, gate_id]() {
            return received_output_messages_.find(gate_id) != received_output_messages_.end();
          }));
    }

    // try to find the output message
    iterator = received_output_messages_.find(gate_id);
    end = received_output_messages_.end();
  }

  while (iterator == end) {
    // blocking wait if the is no message yet
    output_message_conditions_.find(gate_id)->second->WaitFor(std::chrono::milliseconds(1));
    std::scoped_lock lock(output_message_mutex_);
    // try to find it again, if we were notified through the Condition class
    iterator = received_output_messages_.find(gate_id);
    end = received_output_messages_.end();
  }
  auto output_message = Communication::GetMessage(iterator->second.data());
  assert(output_message != nullptr);

  return Communication::GetOutputMessage(output_message->payload()->data());
}

void DataStorage::SetReceivedHelloMessage(std::vector<std::uint8_t> &&hello_message) {
  {
    std::scoped_lock<std::mutex> lock(rcv_hello_msg_cond->GetMutex());
    received_hello_message_ = std::move(hello_message);
  }
  rcv_hello_msg_cond->NotifyAll();
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
    std::scoped_lock<std::mutex> lock(snt_hello_msg_cond->GetMutex());
    std::vector<std::uint8_t> buf(message, message + size);
    SetSentHelloMessage(std::move(buf));
  }
  snt_hello_msg_cond->NotifyAll();
}

const ABYN::Communication::HelloMessage *DataStorage::GetSentHelloMessage() {
  if (sent_hello_message_.empty()) {
    return nullptr;
  }
  auto hm = ABYN::Communication::GetMessage(sent_hello_message_.data());
  assert(hm != nullptr);
  return ABYN::Communication::GetHelloMessage(hm->payload()->data());
}

void DataStorage::Reset() { received_output_messages_.clear(); }

void DataStorage::Clear() { received_output_messages_.clear(); }

}