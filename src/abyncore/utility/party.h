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
#include "utility/datastorage.h"
#include "utility/logger.h"

namespace ABYN {

  using IoServicePtr = std::shared_ptr<boost::asio::io_service>;
  using BoostSocketPtr = std::shared_ptr<boost::asio::ip::tcp::socket>;

  class Party {

  public:

    Party(const std::string ip, u16 port, ABYN::Role role, size_t id);

    Party(const char *ip, u16 port, ABYN::Role role, size_t id) :
        Party(std::string(ip), port, role, id) {}

    Party(int socket, ABYN::Role role, size_t id) :
        role_(role), id_(id), party_socket_(socket), is_connected_(true) {
      boost_party_socket_->assign(boost::asio::ip::tcp::v4(), socket);
    }

    Party(ABYN::Role role, size_t id, BoostSocketPtr &boost_socket) :
        role_(role), id_(id), boost_party_socket_(boost_socket), is_connected_(true) {
      party_socket_ = boost_party_socket_->native_handle();
    }

    // close the socket
    ~Party() {
      if (is_connected_ || boost_party_socket_->is_open()) {
        boost_party_socket_->shutdown(boost::asio::ip::tcp::socket::shutdown_both);
        boost_party_socket_->close();
      }
    }

    void SetLogger(const ABYN::LoggerPtr &logger) { logger_ = logger; }

    const std::string &GetIp() { return ip_; }

    u16 GetPort() { return port_; }

    ssize_t GetId() { return id_; }

    bool IsConnected() { return is_connected_ && party_socket_ >= 0; }

    std::string Connect();

    const BoostSocketPtr &GetSocket() { return boost_party_socket_; }

    void ParseMessage(std::vector<u8> &&raw_message);

  private:

    DataStorage data_storage_;

    std::string ip_;
    u16 port_ = 0;
    ABYN::Role role_ = ABYN::Role::InvalidRole;
    ssize_t id_ = -1;

    int party_socket_ = -2, opt_ = 1;

    IoServicePtr io_service_{new boost::asio::io_service()};
    BoostSocketPtr boost_party_socket_{new boost::asio::ip::tcp::socket{*io_service_.get()}};

    ABYN::LoggerPtr logger_;

    bool is_connected_ = false;

    bool IsInvalidIp(const char *ip);

    void InitializeSocketServer();

    void InitializeSocketClient();

    Party() = delete;

  };

  using PartyPtr = std::shared_ptr<Party>;

}

#endif //PARTY_H
