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

namespace ABYN {

    using namespace boost::asio;
    using IoServicePtr = std::shared_ptr<io_service>;
    using BoostSocketPtr = std::shared_ptr<ip::tcp::socket>;

    class Party {

    public:

        Party(std::string_view &&ip, u16 port, ABYN::Role role, size_t id) :
                ip_(std::move(ip)), port_(port), role_(role), id_(id), is_connected_(false) {
            if (IsInvalidIp(ip.data())) {
                throw (std::runtime_error(fmt::format("{} is invalid IP address", ip)));
            }
        };

        Party(const std::string &ip, u16 port, ABYN::Role role, size_t id) :
                Party(std::move(std::string_view(ip.c_str())), port, role, id) {};

        Party(const char *ip, u16 port, ABYN::Role role, size_t id) :
                Party(std::move(std::string_view(ip)), port, role, id) {};

        Party(int socket, ABYN::Role role, size_t id) :
                role_(role), id_(id), party_socket_(socket), is_connected_(true) {
            boost_party_socket_->assign(boost::asio::ip::tcp::v4(), socket);
        };

        // close the socket
        ~Party() { if (is_connected_) shutdown(party_socket_, 2); };

        std::string_view &GetIp() { return ip_; };

        u16 GetPort() { return port_; };

        bool IsConnected() { return is_connected_ && party_socket_ >= 0; };

        std::string Connect() {
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

    private:

        std::string_view ip_;
        u16 port_ = 0;
        ABYN::Role role_ = ABYN::Role::InvalidRole;
        ssize_t id_ = -1;

        int party_socket_ = -2, opt_ = 1;
        bool is_connected_ = false;

        IoServicePtr io_service_{new boost::asio::io_service()};
        BoostSocketPtr boost_party_socket_{new ip::tcp::socket{*io_service_.get()}};


        bool IsInvalidIp(const char *ip);

        void InitializeSocketServer();

        void InitializeSocketClient();

        Party() = delete;

    };

}

#endif //PARTY_H
