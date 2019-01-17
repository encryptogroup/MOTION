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

        Party(std::string_view && ip, u16 port, ABYN::Role role, size_t id) {
            if (IsInvalidIp(ip.data())) {
                throw (std::runtime_error(fmt::format("{} is invalid IP address", ip)));
            }
            this->ip = std::move(ip);
            this->port = port;
            this->role = role;
            this->id = id;
            is_connected = false;

            //TODO: move to the logger as soon as it is implemented
            std::cout << fmt::format("Party constructor for {}:{}\n", this->ip, this->port);
        };

        Party(std::string_view & ip, u16 port, ABYN::Role role, size_t id){
            Party(std::move(ip), port, role, id);
        }

        Party(int socket, size_t id) {
            this->party_socket = socket;
            this->role = role;
            boost_party_socket->assign(boost::asio::ip::tcp::v4(), socket);
            this->id = id;
            is_connected = true;
        };

        // close the socket
        ~Party() { if (is_connected) shutdown(party_socket, 2); };

        std::string_view &GetIp() { return ip; };

        u16 GetPort() { return port; };

        bool IsConnected() { return is_connected && party_socket >= 0; };

        void Connect() {
            if (is_connected)
                return;

            if (role == ABYN::Role::Client) {
                InitializeSocketClient();
            } else {
                InitializeSocketServer();
            };

            is_connected = true;

            //TODO: move to the logger as soon as it is implemented
            std::cout << fmt::format("Connected {}:{}\n", this->ip, this->port);
        };
    };

}

#endif //PARTY_H
