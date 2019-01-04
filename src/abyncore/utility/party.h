#ifndef PARTY_H
#define PARTY_H

#include <string>
#include <iostream>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <boost/asio.hpp>

#include "typedefs.h"

namespace ABYN {

    class Party {
    private:
        ABYN::Role role;
        std::string_view ip;
        u16 port;
        int party_socket = -2, opt = 1;

        bool IsInvalidIp(const char *ip);

        void InitializeSocketServer();

        void InitializeSocketClient();

    protected:
        Party() {};
    public:
        Party(const std::string &ip, const u16 &port, const ABYN::Role &role) {
            if (IsInvalidIp(ip.c_str())) {
                throw (ip + " is invalid IP address");
            }

            this->ip = std::string_view(ip);
            this->port = port;
            this->role = role;

            if (role == ABYN::Role::Client) {
                InitializeSocketClient();
            } else {
                InitializeSocketServer();
            }
        };

        Party(int socket) {
            this->party_socket = socket;
            this->role = role;
        };

        // close the socket
        ~Party() { shutdown(party_socket, 2); };

        std::string_view &GetIp() { return ip; };

        u16 GetPort() { return port; };
    };

}

#endif //PARTY_H
