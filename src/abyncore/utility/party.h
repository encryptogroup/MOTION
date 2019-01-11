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

#include "typedefs.h"

namespace ABYN {

    using namespace boost::asio;
    using IoServicePtr = std::shared_ptr<io_service>;
    using BoostSocketPtr = std::shared_ptr<ip::tcp::socket>;

    class Party {
    private:
        ABYN::Role role;
        std::string_view ip;
        u16 port;
        int party_socket = -2, opt = 1;
        ssize_t id = -1;

        IoServicePtr io_service{new boost::asio::io_service()};
        BoostSocketPtr boost_party_socket{new ip::tcp::socket{*io_service.get()}};

        bool is_connected = false;

        bool IsInvalidIp(const char *ip);

        void InitializeSocketServer();

        void InitializeSocketClient();

    protected:
        Party() {};
    public:

        Party(const std::string &ip, u16 port, ABYN::Role role, const size_t id) {
            if (IsInvalidIp(ip.c_str())) {
                throw (std::runtime_error(ip + " is invalid IP address"));
            }

            this->ip = std::string_view(ip);
            this->port = port;
            this->role = role;

            if (role == ABYN::Role::Client) {
                InitializeSocketClient();
            } else {
                InitializeSocketServer();
            }

            this->id = id;
        };

        Party(int socket, const size_t id) {
            this->party_socket = socket;
            this->role = role;
            boost_party_socket->assign(boost::asio::ip::tcp::v4(), socket);
            this->id = id;
        };

        // close the socket
        ~Party() { shutdown(party_socket, 2); };

        std::string_view &GetIp() { return ip; };

        u16 GetPort() { return port; };

        bool IsConnected() { return is_connected; };
    };

}

#endif //PARTY_H
