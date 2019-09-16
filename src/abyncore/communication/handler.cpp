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

#include "handler.h"

#include <algorithm>

#include "fmt/format.h"

#include "context.h"
#include "crypto/sharing_randomness_generator.h"
#include "message.h"
#include "utility/condition.h"
#include "utility/constants.h"
#include "utility/data_storage.h"
#include "utility/locked_queue.h"
#include "utility/logger.h"

namespace ABYN::Communication {
// use explicit conversion function to prevent implementation-dependent
// conversion issues on different architectures
std::vector<std::uint8_t> u32tou8(std::uint32_t v) {
  std::vector<std::uint8_t> result(sizeof(std::uint32_t));
  for (auto i = 0u; i < result.size(); ++i) {
    result[i] = (v >> i * 8) & 0xFF;
  }
  return result;
}

// use explicit conversion function to prevent implementation-dependent
// conversion issues on different architectures
std::uint32_t u8tou32(std::vector<std::uint8_t> &v) {
  std::uint32_t result = 0;
  for (auto i = 0u; i < sizeof(std::uint32_t); ++i) {
    result += (v[i] << i * 8);
  }
  return result;
}

Handler::Handler(ContextPtr &context, const LoggerPtr &logger)
    : context_(context),
      logger_(logger),
      lqueue_receive_(std::make_unique<ENCRYPTO::LockedQueue<std::vector<std::uint8_t>>>()),
      lqueue_send_(std::make_unique<ENCRYPTO::LockedQueue<std::vector<std::uint8_t>>>()) {
  handler_info_ =
      fmt::format("Party#{} handler with end ip {}, local port {}, remote port {}",
                  context->GetId(), context->GetIp(), context->GetSocket()->local_endpoint().port(),
                  context->GetSocket()->remote_endpoint().port());

  sender_thread_ = std::thread([&]() { ActAsSender(); });

  receiver_thread_ = std::thread([&]() { ActAsReceiver(); });
}

Handler::~Handler() {
  continue_communication_ = false;
  if (sender_thread_.joinable()) {
    sender_thread_.join();
  }
  if (receiver_thread_.joinable()) {
    receiver_thread_.join();
  }
  logger_->LogInfo(
      fmt::format("{}: {}B sent {}B received", handler_info_, bytes_sent_, bytes_received_));
}

void Handler::SendMessage(flatbuffers::FlatBufferBuilder &&message) {
  auto message_detached = message.Release();
  auto message_raw_pointer = message_detached.data();
  if (GetMessage(message_raw_pointer)->message_type() == MessageType_HelloMessage) {
    auto shared_ptr_context = context_.lock();
    assert(shared_ptr_context);
    shared_ptr_context->GetDataStorage()->SetSentHelloMessage(message_raw_pointer,
                                                              message_detached.size());
  }
  std::vector<std::uint8_t> buffer(message_raw_pointer,
                                   message_raw_pointer + message_detached.size());

  logger_->LogTrace(fmt::format("{}: Have put a {}-byte message to send queue", handler_info_,
                                message_detached.size()));
  lqueue_send_->enqueue(std::move(buffer));
}

const BoostSocketPtr Handler::GetSocket() {
  if (auto shared_ptr_context = context_.lock()) {
    return shared_ptr_context->GetSocket();
  } else {
    return nullptr;
  }
}

void Handler::TerminateCommunication() {
  auto message = BuildMessage(MessageType_TerminationMessage, nullptr);
  std::vector<std::uint8_t> buffer(message.GetBufferPointer(),
                                   message.GetBufferPointer() + message.GetSize());
  lqueue_send_->enqueue(std::move(buffer));

  logger_->LogTrace(
      fmt::format("{}: Put a termination message message to send queue", handler_info_));

  SentTerminationMessage();
}

void Handler::WaitForConnectionEnd() {
  while (continue_communication_) {
    if (lqueue_send_->empty() && lqueue_receive_->empty() && received_termination_message_ &&
        sent_termination_message_) {
      continue_communication_ = false;
      logger_->LogInfo(fmt::format("{}: terminated.", handler_info_));
    } else {
      std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
  }
}

void Handler::ActAsSender() {
  while (ContinueCommunication()) {
    auto tmp_queue = lqueue_send_->batch_dequeue(std::chrono::milliseconds(1));

    while (!tmp_queue.empty()) {
      auto &message = tmp_queue.front();

      if constexpr (ABYN_VERBOSE_DEBUG) {
        std::string s;
        for (auto i = 0u; i < message.size(); ++i) {
          s.append(fmt::format("{0:#x} ", message.at(i)));
        }
        logger_->LogTrace(fmt::format("{}: Written to the socket, size {}, message: {}", GetInfo(),
                                      message.size(), s));
      }

      if (message.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw(std::runtime_error(fmt::format("Max message size is {} B but tried to send {} B",
                                             std::numeric_limits<std::uint32_t>::max(),
                                             message.size())));
      }

      auto message_size = u32tou8(message.size());
      message.insert(message.begin(), message_size.begin(), message_size.end());
      boost::system::error_code ec;
      auto boost_socket = GetSocket();
      assert(boost_socket);
      assert(boost_socket->is_open());
      boost_socket->wait(boost::asio::ip::tcp::socket::wait_write, ec);
      if (ec) {
        throw(std::runtime_error(fmt::format("Error while writing to socket: {}", ec.message())));
      }
      boost::asio::write(*boost_socket.get(), boost::asio::buffer(message),
                         boost::asio::transfer_exactly(message.size()), ec);
      if (ec) {
        throw(std::runtime_error(fmt::format("Error while writing to socket: {}", ec.message())));
      }
      bytes_sent_ += message.size() + sizeof(uint32_t);
      tmp_queue.pop();
    }
  }
}

void Handler::ActAsReceiver() {
  //#pragma omp parallel
  //#pragma omp single
  {
    // separate task for receiving data and putting it to the queue
    //#pragma omp task
    std::thread thread_rcv([this]() {
      while (ContinueCommunication()) {
        if (GetSocket()->available() == 0) {
          std::this_thread::sleep_for(std::chrono::microseconds(100));
          continue;
        }

        std::uint32_t size = ParseHeader();
        static_assert(sizeof(size) == MESSAGE_SIZE_BYTELEN);  // check consistency of the byte
                                                              // length of the message size type
        if (size == 0) {
          continue;
        }

        std::vector<std::uint8_t> message_buffer = ParseBody(size);

        auto message = GetMessage(message_buffer.data());

        if constexpr (ABYN_DEBUG) {
          flatbuffers::Verifier verifier(message_buffer.data(), message_buffer.size());
          assert(message->Verify(verifier));
        }

        bytes_received_ += size + sizeof(uint32_t);

        if (message->message_type() == MessageType_TerminationMessage) {
          ReceivedTerminationMessage();
          if constexpr (ABYN_VERBOSE_DEBUG) {
            GetLogger()->LogTrace(
                fmt::format("{}: Got a termination message from the socket", GetInfo()));
          }
          break;
        }

        if constexpr (ABYN_VERBOSE_DEBUG) {
          std::string s;
          for (auto i = 0u; i < message_buffer.size(); ++i) {
            s.append(fmt::format("{0:#x} ", message_buffer.at(i)));
          }
          GetLogger()->LogTrace(
              fmt::format("{}: Read message body of size {}, message: {}", GetInfo(), size, s));
        }

        lqueue_receive_->enqueue(std::move(message_buffer));
        GetSocket()->non_blocking(false);
      }
    });
    // separate thread for parsing received messages
    // TODO: consider >= 4GB messages.
    //#pragma omp task
    std::thread thread_parse([this]() {
      while (ContinueCommunication() || !lqueue_receive_->empty()) {
        auto items = lqueue_receive_->batch_dequeue(std::chrono::milliseconds(1));
        while (!items.empty()) {
          auto &item = items.front();
          auto shared_ptr_context = context_.lock();
          assert(shared_ptr_context);
          shared_ptr_context->ParseMessage(std::move(item));
          items.pop();
        }
      }
    });
    thread_rcv.join();
    thread_parse.join();
  }
}  // namespace ABYN::Communication

std::uint32_t Handler::ParseHeader() {
  boost::system::error_code ec;
  std::vector<std::uint8_t> message_size_buffer(MESSAGE_SIZE_BYTELEN);
  // get the size of the next message
  boost::asio::read(*GetSocket().get(), boost::asio::buffer(message_size_buffer),
                    boost::asio::transfer_exactly(message_size_buffer.size()), ec);

  std::uint32_t size = u8tou32(message_size_buffer);

  if (size > 0) {
    std::string s;
    for (auto i = 0u; i < 4; ++i) {
      s.append(fmt::format("{0:#x} ", reinterpret_cast<std::uint8_t *>(&size)[i]));
    };
    GetLogger()->LogTrace(
        fmt::format("{}: Got a new message from the socket and have read the "
                    "header (size: {}), header: {}",
                    GetInfo(), size, s));
  } else if (size == 0 ||
             (ec == boost::asio::error::would_block || ec == boost::asio::error::eof)) {
    return 0;
  } else if (ec) {
    throw(std::runtime_error(fmt::format("Error while reading from socket: {}", ec.message())));
  }
  return size;
}

std::vector<std::uint8_t> Handler::ParseBody(std::uint32_t size) {
  boost::system::error_code ec;
  GetSocket()->non_blocking(false);
  std::vector<std::uint8_t> message_buffer(size);
  // get the message
  boost::asio::read(*GetSocket().get(), boost::asio::buffer(message_buffer),
                    boost::asio::transfer_exactly(message_buffer.size()), ec);
  if (ec) {
    throw(std::runtime_error(fmt::format("Error while reading from socket: {}", ec.message())));
  }
  return message_buffer;
}

bool Handler::VerifyHelloMessage() {
  bool result = true;
  auto shared_ptr_context = context_.lock();
  assert(shared_ptr_context);
  auto data_storage = shared_ptr_context->GetDataStorage();
  auto *my_hm = data_storage->GetSentHelloMessage();
  while (my_hm == nullptr) {
    data_storage->GetSentHelloMessageCondition()->WaitFor(std::chrono::microseconds(200));
    my_hm = data_storage->GetSentHelloMessage();
  }

  auto their_hm = data_storage->GetReceivedHelloMessage();
  while (their_hm == nullptr) {
    data_storage->GetReceivedHelloMessageCondition()->WaitFor(std::chrono::microseconds(200));
    their_hm = data_storage->GetReceivedHelloMessage();
  }

  if (shared_ptr_context) {
    if (my_hm->ABYN_version() != their_hm->ABYN_version()) {
      logger_->LogError(fmt::format("{}: Different {} versions: mine is {}, theirs is {}",
                                    handler_info_, FRAMEWORK_NAME, ABYN_VERSION,
                                    their_hm->ABYN_version()));
      result = false;
    }
    if (my_hm->num_of_parties() != their_hm->num_of_parties()) {
      logger_->LogError(
          fmt::format("{}: different total number of parties: mine is {}, theirs is {}",
                      handler_info_, my_hm->num_of_parties(), their_hm->num_of_parties()));
      result = false;
    }
    if (their_hm->destination_id() != my_hm->source_id()) {
      logger_->LogError(fmt::format("{}: wrong destination id: mine is #{}, but received #{}",
                                    handler_info_, my_hm->source_id(), their_hm->destination_id()));
      result = false;
    }
    if (my_hm->destination_id() != their_hm->source_id()) {
      logger_->LogError(fmt::format("{}: wrong source id: my info is #{}, but received #{}",
                                    handler_info_, my_hm->destination_id(), their_hm->source_id()));
      result = false;
    }
    if (my_hm->online_after_setup() != my_hm->online_after_setup()) {
      logger_->LogError(
          fmt::format("{}: different \"online after setup\" setting: my info "
                      "is #{}, but received #{}",
                      handler_info_, my_hm->online_after_setup(), their_hm->online_after_setup()));
      result = false;
    }
    if (my_hm->input_sharing_seed() == nullptr || my_hm->input_sharing_seed()->size() == 0) {
      logger_->LogInfo(fmt::format("{}: received no AES seeds", handler_info_));
    } else {
      logger_->LogInfo(fmt::format("{}: received an AES seed", handler_info_));
    }
  }
  return result;
}

void Handler::Reset() {
  auto shared_ptr_context = context_.lock();
  assert(shared_ptr_context);
  shared_ptr_context->GetDataStorage()->Reset();
  shared_ptr_context->GetMyRandomnessGenerator()->ResetBitPool();
  shared_ptr_context->GetTheirRandomnessGenerator()->ResetBitPool();
}

void Handler::Clear() {
  auto shared_ptr_context = context_.lock();
  assert(shared_ptr_context);
  shared_ptr_context->GetDataStorage()->Clear();
  shared_ptr_context->GetMyRandomnessGenerator()->ClearBitPool();
  shared_ptr_context->GetTheirRandomnessGenerator()->ClearBitPool();
}

void Handler::Sync() {
  auto context = context_.lock();
  assert(context);
  std::uint64_t new_state = context->GetDataStorage()->IncrementMySyncState();
  std::vector<std::uint8_t> v(8);
  *(reinterpret_cast<std::uint64_t *>(v.data())) = new_state;
  auto message = BuildMessage(MessageType_SynchronizationMessage, &v);
  std::vector<std::uint8_t> buffer(message.GetBufferPointer(),
                                   message.GetBufferPointer() + message.GetSize());
  lqueue_send_->enqueue(std::move(buffer));

  auto sync_condition = context->GetDataStorage()->GetSyncCondition();
  Helpers::WaitFor(*sync_condition);
}

}  // namespace ABYN::Communication
