#include "party.h"

#include <chrono>
#include <cstdlib>
#include <fmt/format.h>

#include "utility/typedefs.h"
#include "utility/constants.h"

namespace ABYN {

  bool Party::IsInvalidIp(const char *ip) {
    struct sockaddr_in sa;
    auto result = inet_pton(AF_INET, ip, &sa.sin_addr);
    if (result == -1) {
      throw (std::runtime_error(std::string("Address family not supported: ") + ip));
    }

    return result == 0;
  }

  void Party::InitializeSocketServer() {
    std::string role_str;
    if (role_ == ABYN::Role::Server) {
      role_str = std::move(std::string(" acting as server"));
    } else {
      role_str = std::move(std::string(" acting as client"));
    }

    auto info = std::move(fmt::format("{}:{} {}", ip_, port_, role_str));

    party_socket_ = socket(AF_INET, SOCK_STREAM, 0);

    if (party_socket_ < 0) {
      throw (std::runtime_error("Socket creation error for " + info));
    }

    if (setsockopt(party_socket_, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                   &opt_, sizeof(opt_))) {
      throw (std::runtime_error("Could not setsockopt() for " + info));
    }

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    inet_pton(AF_INET, ip_.data(), &address.sin_addr);
    address.sin_port = htons(port_);
    auto addrlen = sizeof(address);

    if (bind(party_socket_, (struct sockaddr *) &address, sizeof(address)) < 0) {
      throw (std::runtime_error(std::string("Could not bind() the socket for ") + info));
    }

    if (listen(party_socket_, 100) < 0) {
      throw (std::runtime_error(std::string("Could not listen() for ") + info));
    }


    int temp_socket;
    if ((temp_socket = accept(party_socket_, (struct sockaddr *) &address,
                              (socklen_t *) &addrlen)) < 0) {
      throw (std::runtime_error(std::string("Could not accept() ") + info));
    }

    shutdown(party_socket_, 2);
    party_socket_ = temp_socket;

    is_connected_ = true;
  };

  void Party::InitializeSocketClient() {

    std::string role_str;
    if (role_ == ABYN::Role::Server) {
      role_str = std::string(" acting as server");
    } else {
      role_str = std::string(" acting as client");
    }

    std::string info(std::string(ip_) + std::string(":") +
                     std::to_string(port_) + role_str);

    party_socket_ = socket(AF_INET, SOCK_STREAM, 0);

    if (party_socket_ < 0) {
      throw (std::runtime_error("Socket creation error for " + info));
    }

    fd_set myset;
    struct timeval tv;

    long arg = fcntl(party_socket_, F_GETFL, NULL);
    arg |= O_NONBLOCK;
    fcntl(party_socket_, F_SETFL, arg);

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port_);
    inet_pton(AF_INET, ip_.data(), &serv_addr.sin_addr);

    auto timeout = 0;
    while (1) {
      int res = connect(party_socket_, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
      if (res < 0) {
        if (res == EINPROGRESS) {
          tv.tv_sec = 15;
          tv.tv_usec = 0;
          FD_ZERO(&myset);
          FD_SET(party_socket_, &myset);
          if (select(party_socket_ + 1, NULL, &myset, NULL, &tv) > 0) {
            socklen_t lon = sizeof(int);
            int valopt;
            getsockopt(party_socket_, SOL_SOCKET, SO_ERROR, (void *) (&valopt), &lon);
            if (valopt) {
              throw (std::runtime_error(
                  fmt::format("{} error at connect() for {}", strerror(valopt), info)));
            }
            break;
          } else {
            throw (std::runtime_error("Connection timeout for " + info));
          }

        } else if (timeout < MAXIMUM_CONNECTION_TIMEOUT) {
          std::this_thread::sleep_until(std::chrono::system_clock::now() + std::chrono::seconds(1));
          timeout++;
          continue;
        } else {
          throw (std::runtime_error("Error at connect() for " + info));
        }
      } else {
        break;
      }
    }

    arg = fcntl(party_socket_, F_GETFL, NULL);
    arg &= (~O_NONBLOCK);
    fcntl(party_socket_, F_SETFL, arg);

    is_connected_ = true;
  };
}