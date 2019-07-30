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

#include "context.h"

#include <flatbuffers/flatbuffers.h>
#include <fmt/format.h>
#include <chrono>
#include <cstdlib>

#include "crypto/aes_randomness_generator.h"
#include "utility/constants.h"
#include "utility/data_storage.h"
#include "utility/helpers.h"
#include "utility/logger.h"
#include "utility/random.h"
#include "utility/typedefs.h"

namespace ABYN::Communication {

Context::Context(std::string ip, std::uint16_t port, Role role, std::size_t id)
    : data_storage_(std::make_shared<DataStorage>(id)),
      ip_(ip.c_str()),
      port_(port),
      role_(role),
      id_(id),
      is_connected_(false) {
  if (IsInvalidIp(ip.data())) {
    throw(std::runtime_error(fmt::format("{} is invalid IP address", ip)));
  }
}

Context::Context(const char *ip, std::uint16_t port, Role role, std::size_t id)
    : Context(std::string(ip), port, role, id) {}

Context::Context(int socket, Role role, std::size_t id)
    : data_storage_(std::make_shared<DataStorage>(id)),
      role_(role),
      id_(id),
      party_socket_(socket),
      is_connected_(true) {
  boost_party_socket_->assign(boost::asio::ip::tcp::v4(), socket);
}

Context::Context(Role role, std::size_t id, BoostSocketPtr &boost_socket)
    : data_storage_(std::make_shared<DataStorage>(id)),
      role_(role),
      id_(id),
      boost_party_socket_(boost_socket),
      is_connected_(true) {
  party_socket_ = boost_party_socket_->native_handle();
}

// close the socket
Context::~Context() {
  if (is_connected_ || boost_party_socket_->is_open()) {
    boost_party_socket_->shutdown(boost::asio::ip::tcp::socket::shutdown_both);
    boost_party_socket_->close();
  }
}

void Context::InitializeMyRandomnessGenerator() {
  std::vector<std::uint8_t> master_seed(
      RandomVector(Crypto::AESRandomnessGenerator::MASTER_SEED_BYTE_LENGTH));
  my_randomness_generator_ = std::make_unique<Crypto::AESRandomnessGenerator>(id_);
  my_randomness_generator_->Initialize(master_seed.data());
}

void Context::InitializeTheirRandomnessGenerator(std::vector<std::uint8_t> &seed) {
  their_randomness_generator_ = std::make_unique<Crypto::AESRandomnessGenerator>(id_);
  their_randomness_generator_->Initialize(seed.data());
}

void Context::SetLogger(const LoggerPtr &logger) {
  logger_ = logger;
  data_storage_->SetLogger(logger);
}

std::string Context::Connect() {
  if (is_connected_) {
    return std::move(fmt::format("Already connected to {}:{}\n", ip_, port_));
  } else if (role_ == Role::Client) {
    InitializeSocketClient();
  } else {
    InitializeSocketServer();
  };

  is_connected_ = true;

  return std::move(fmt::format("Successfully connected to {}:{}\n", ip_, port_));
}

void Context::ParseMessage(std::vector<std::uint8_t> &&raw_message) {
  auto message = GetMessage(raw_message.data());
  flatbuffers::Verifier verifier(raw_message.data(), raw_message.size());
  if (VerifyMessageBuffer(verifier) != true) {
    throw(std::runtime_error(
        fmt::format("Parsed a corrupt message from id#{} {}:{}", id_, ip_, port_)));
  }

  auto message_type = message->message_type();

  switch (message_type) {
    case MessageType_HelloMessage: {
      auto seed_vector = GetHelloMessage(message->payload()->data())->input_sharing_seed();
      if (seed_vector != nullptr && seed_vector->size() > 0) {
        const std::uint8_t *seed = seed_vector->data();
        auto seed_len = Crypto::AESRandomnessGenerator::MASTER_SEED_BYTE_LENGTH;
        std::vector<std::uint8_t> seed_v(seed, seed + seed_len);
        InitializeTheirRandomnessGenerator(seed_v);
        logger_->LogTrace(
            fmt::format("Initialized the randomness generator from Party#{} with Seed: {}", id_,
                        Helpers::Print::Hex(their_randomness_generator_->GetSeed())));
        logger_->LogInfo(
            fmt::format("Received a randomness seed in hello message from Party#{}", id_));
      }
      data_storage_->SetReceivedHelloMessage(std::move(raw_message));
    } break;
    case MessageType_OutputMessage: {
      data_storage_->SetReceivedOutputMessage(std::move(raw_message));
    } break;
    case MessageType_TerminationMessage: {
      //
    } break;
    case MessageType_SynchronizationMessage: {
      data_storage_->SetSyncState(true);
    } break;
    default:
      throw(std::runtime_error("Didn't recognize the message type"));
  }
}

bool Context::IsInvalidIp(const char *ip) {
  struct sockaddr_in sa;
  auto result = inet_pton(AF_INET, ip, &sa.sin_addr);
  if (result == -1) {
    throw(std::runtime_error(std::string("Address family not supported: ") + ip));
  }

  return result == 0;
}

void Context::InitializeSocketServer() {
  boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::tcp::v4(), port_);
  boost::asio::ip::tcp::acceptor acceptor(*io_service_.get(), endpoint,
                                          boost::asio::ip::tcp::acceptor::reuse_address(true));
  boost::system::error_code error;
  acceptor.accept(*boost_party_socket_.get(), error);
  io_service_->run();
  party_socket_ = boost_party_socket_->native_handle();
  if (error) {
    throw(std::runtime_error(error.message()));
  }
  is_connected_ = true;
}

void Context::InitializeSocketClient() {
  boost::asio::ip::tcp::resolver resolver(*io_service_.get());
  boost::asio::ip::tcp::resolver::query query(ip_, std::to_string(port_));
  boost::system::error_code error;
  do {
    if (error) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    } else {
      is_connected_ = true;
    }
    boost::asio::connect(*boost_party_socket_.get(), resolver.resolve(query), error);

  } while (error);
  party_socket_ = boost_party_socket_->native_handle();
}
}