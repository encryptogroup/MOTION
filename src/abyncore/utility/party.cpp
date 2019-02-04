#include "party.h"

#include <chrono>
#include <cstdlib>
#include <fmt/format.h>

#include "utility/typedefs.h"
#include "utility/constants.h"

namespace ABYN {

  Party::Party(std::string ip, u16 port, ABYN::Role role, size_t id) :
      ip_(ip.c_str()), port_(port), role_(role), id_(id), is_connected_(false) {
    if (IsInvalidIp(ip.data())) {
      throw (std::runtime_error(fmt::format("{} is invalid IP address", ip)));
    }
  };

  std::string Party::Connect() {
    if (is_connected_)
      return std::move(fmt::format("Already connected to {}:{}\n", this->ip_, this->port_));

    if (role_ == ABYN::Role::Client) {
      InitializeSocketClient();
    } else {
      InitializeSocketServer();
    };

    is_connected_ = true;

    return std::move(fmt::format("Successfully connected to {}:{}\n", this->ip_, this->port_));
  };

  bool Party::IsInvalidIp(const char *ip) {
    struct sockaddr_in sa;
    auto result = inet_pton(AF_INET, ip, &sa.sin_addr);
    if (result == -1) {
      throw (std::runtime_error(std::string("Address family not supported: ") + ip));
    }

    return result == 0;
  }

  void Party::InitializeSocketServer() {
    boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::tcp::v4(), port_);
    boost::asio::ip::tcp::acceptor acceptor{*io_service_.get(), endpoint};
    acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
    boost::system::error_code error;
    acceptor.accept(*boost_party_socket_.get(), error);
    io_service_->run();
    party_socket_ = boost_party_socket_->native_handle();
    if(error){
      throw(std::runtime_error(error.message()));
    }
    is_connected_ = true;
  };

  void Party::InitializeSocketClient() {
    boost::asio::ip::tcp::resolver resolver(*io_service_.get());
    boost::asio::ip::tcp::resolver::query query(ip_, std::to_string(port_));
    boost::system::error_code error;
    do {
      if (error) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }else{
        is_connected_ = true;
      }
      boost::asio::connect(*boost_party_socket_.get(), resolver.resolve(query), error);

    } while (error);
    party_socket_ = boost_party_socket_->native_handle();
  };
}