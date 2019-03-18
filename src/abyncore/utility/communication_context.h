#ifndef PARTY_H
#define PARTY_H

#include <memory>
#include <string>
#include <iostream>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio.hpp>
#include <flatbuffers/flatbuffers.h>
#include <fmt/format.h>

#include "utility/typedefs.h"
#include "utility/data_storage.h"
#include "utility/logger.h"
#include "utility/constants.h"

#include "crypto/aes_randomness_generator.h"

namespace ABYN {

  using IoServicePtr = std::shared_ptr<boost::asio::io_service>;
  using BoostSocketPtr = std::shared_ptr<boost::asio::ip::tcp::socket>;

  ///Peer-related communication context
  class CommunicationContext {

  public:

    CommunicationContext(const std::string ip, u16 port, ABYN::Role role, std::size_t id);

    CommunicationContext(const char *ip, u16 port, ABYN::Role role, std::size_t id) :
        CommunicationContext(std::string(ip), port, role, id) {}

    CommunicationContext(int socket, ABYN::Role role, std::size_t id) :
        data_storage_(id), role_(role), id_(id), party_socket_(socket), is_connected_(true) {
      boost_party_socket_->assign(boost::asio::ip::tcp::v4(), socket);
    }

    CommunicationContext(ABYN::Role role, std::size_t id, BoostSocketPtr &boost_socket) :
        data_storage_(id), role_(role), id_(id), boost_party_socket_(boost_socket), is_connected_(true) {
      party_socket_ = boost_party_socket_->native_handle();
    }

    // close the socket
    ~CommunicationContext() {
      if (is_connected_ || boost_party_socket_->is_open()) {
        boost_party_socket_->shutdown(boost::asio::ip::tcp::socket::shutdown_both);
        boost_party_socket_->close();
      }
    }

    void InitializeMyRandomnessGenerator();

    void InitializeTheirRandomnessGenerator(std::vector<u8> &key, std::vector<u8> &iv);

    void SetLogger(const ABYN::LoggerPtr &logger) {
      logger_ = logger;
      data_storage_.SetLogger(logger);
    }

    const std::string &GetIp() { return ip_; }

    u16 GetPort() { return port_; }

    std::int64_t GetId() { return id_; }

    bool IsConnected() { return is_connected_ && party_socket_ >= 0; }

    std::string Connect();

    const BoostSocketPtr &GetSocket() { return boost_party_socket_; }

    void ParseMessage(std::vector<u8> &&raw_message);

    DataStorage &GetDataStorage() { return data_storage_; }

    const std::unique_ptr<ABYN::Crypto::AESRandomnessGenerator> &GetMyRandomnessGenerator() {
      return my_randomness_generator_;
    }

    const std::unique_ptr<ABYN::Crypto::AESRandomnessGenerator> &GetTheirRandomnessGenerator() {
      return their_randomness_generator_;
    }

  private:

    DataStorage data_storage_;

    std::string ip_;
    u16 port_ = 0;
    ABYN::Role role_ = ABYN::Role::InvalidRole;
    std::int64_t id_ = -1;

    int party_socket_ = -2;

    IoServicePtr io_service_{new boost::asio::io_service()};
    BoostSocketPtr boost_party_socket_{new boost::asio::ip::tcp::socket{*io_service_.get()}};

    ABYN::LoggerPtr logger_;

    std::unique_ptr<ABYN::Crypto::AESRandomnessGenerator> my_randomness_generator_, their_randomness_generator_;

    bool is_connected_ = false;

    bool IsInvalidIp(const char *ip);

    void InitializeSocketServer();

    void InitializeSocketClient();

    CommunicationContext() = delete;

  };

  using CommunicationContextPtr = std::shared_ptr<CommunicationContext>;

}

#endif //PARTY_H
