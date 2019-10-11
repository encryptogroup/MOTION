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

#include <sys/socket.h>
#include <iostream>
#include <memory>
#include <string>

#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "utility/constants.h"
#include "utility/typedefs.h"

namespace MOTION {

namespace Crypto {

class SharingRandomnessGenerator;

}

class DataStorage;

class Logger;
using LoggerPtr = std::shared_ptr<Logger>;

using IoServicePtr = std::shared_ptr<boost::asio::io_service>;
using BoostSocketPtr = std::shared_ptr<boost::asio::ip::tcp::socket>;

namespace Communication {
/// Peer-related communication context
class Context {
 public:
  Context() = delete;

  Context(const Context &) = delete;

  Context(const std::string ip, std::uint16_t port, Role role, std::size_t id);

  Context(const char *ip, std::uint16_t port, Role role, std::size_t id);

  Context(int socket, Role role, std::size_t id);

  Context(Role role, std::size_t id, BoostSocketPtr &boost_socket);

  ~Context();

  void InitializeMyRandomnessGenerator();

  void InitializeTheirRandomnessGenerator(const std::vector<std::uint8_t> &seed);

  void SetLogger(const LoggerPtr &logger);

  const std::string &GetIp() { return ip_; }

  std::uint16_t GetPort() { return port_; }

  std::int64_t GetId() { return id_; }

  bool IsConnected() { return is_connected_ && party_socket_ >= 0; }

  std::string Connect();

  const BoostSocketPtr &GetSocket() { return boost_party_socket_; }

  void ParseMessage(std::vector<std::uint8_t> &&raw_message);

  std::shared_ptr<DataStorage> &GetDataStorage() { return data_storage_; }

  const std::unique_ptr<Crypto::SharingRandomnessGenerator> &GetMyRandomnessGenerator() {
    return my_randomness_generator_;
  }

  const std::unique_ptr<Crypto::SharingRandomnessGenerator> &GetTheirRandomnessGenerator() {
    return their_randomness_generator_;
  }

  void WaitForBaseOTs();

 private:
  std::shared_ptr<DataStorage> data_storage_;

  std::string ip_;
  std::uint16_t port_ = 0;
  Role role_ = Role::InvalidRole;
  std::int64_t id_ = -1;

  int party_socket_ = -2;

  IoServicePtr io_service_{new boost::asio::io_service()};
  BoostSocketPtr boost_party_socket_{new boost::asio::ip::tcp::socket{*io_service_.get()}};

  LoggerPtr logger_;

  std::unique_ptr<Crypto::SharingRandomnessGenerator> my_randomness_generator_,
      their_randomness_generator_;

  bool is_connected_ = false;

  bool IsInvalidIp(const char *ip);

  void InitializeSocketServer();

  void InitializeSocketClient();
};

using ContextPtr = std::shared_ptr<Context>;
}  // namespace Communication
}  // namespace MOTION