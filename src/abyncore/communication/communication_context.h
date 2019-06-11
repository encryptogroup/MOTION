#pragma once

#include <sys/socket.h>
#include <iostream>
#include <memory>
#include <string>

#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "crypto/aes_randomness_generator.h"
#include "utility/constants.h"
#include "utility/data_storage.h"
#include "utility/typedefs.h"

namespace ABYN {

class DataStorage;

class Logger;
using LoggerPtr = std::shared_ptr<Logger>;

using IoServicePtr = std::shared_ptr<boost::asio::io_service>;
using BoostSocketPtr = std::shared_ptr<boost::asio::ip::tcp::socket>;

/// Peer-related communication context
class CommunicationContext {
 public:
  CommunicationContext(const std::string ip, std::uint16_t port, Role role, std::size_t id);

  CommunicationContext(const char *ip, std::uint16_t port, Role role, std::size_t id);

  CommunicationContext(int socket, Role role, std::size_t id);

  CommunicationContext(Role role, std::size_t id, BoostSocketPtr &boost_socket);

  ~CommunicationContext();

  void InitializeMyRandomnessGenerator();

  void InitializeTheirRandomnessGenerator(std::vector<std::uint8_t> &key,
                                          std::vector<std::uint8_t> &iv);

  void SetLogger(const LoggerPtr &logger);

  const std::string &GetIp() { return ip_; }

  std::uint16_t GetPort() { return port_; }

  std::int64_t GetId() { return id_; }

  bool IsConnected() { return is_connected_ && party_socket_ >= 0; }

  std::string Connect();

  const BoostSocketPtr &GetSocket() { return boost_party_socket_; }

  void ParseMessage(std::vector<std::uint8_t> &&raw_message);

  DataStorage &GetDataStorage() { return data_storage_; }

  const std::unique_ptr<Crypto::AESRandomnessGenerator> &GetMyRandomnessGenerator() {
    return my_randomness_generator_;
  }

  const std::unique_ptr<Crypto::AESRandomnessGenerator> &GetTheirRandomnessGenerator() {
    return their_randomness_generator_;
  }

 private:
  DataStorage data_storage_;

  std::string ip_;
  std::uint16_t port_ = 0;
  Role role_ = Role::InvalidRole;
  std::int64_t id_ = -1;

  int party_socket_ = -2;

  IoServicePtr io_service_{new boost::asio::io_service()};
  BoostSocketPtr boost_party_socket_{new boost::asio::ip::tcp::socket{*io_service_.get()}};

  LoggerPtr logger_;

  std::unique_ptr<Crypto::AESRandomnessGenerator> my_randomness_generator_,
      their_randomness_generator_;

  bool is_connected_ = false;

  bool IsInvalidIp(const char *ip);

  void InitializeSocketServer();

  void InitializeSocketClient();

  CommunicationContext() = delete;
};

using CommunicationContextPtr = std::shared_ptr<CommunicationContext>;

}  // namespace ABYN