#ifndef PARTY_H
#define PARTY_H

#include <string>
#include <arpa/inet.h>
#include <iostream>

#include "typedefs.h"

namespace ABYN {

    class Party {
    private:
        std::string ip;
        u16 port;

        bool isInvalidIp(const char *ip) {
            struct sockaddr_in sa;
            auto result = inet_pton(AF_INET, ip, &(sa.sin_addr));
            if (result == -1) {
                throw (std::string("Address family not supported: ") + ip);
            }

            return result == 0;
        }

    protected:
        Party() {};
    public:
        Party(const std::string &ip, const u16 &port) {
            if (isInvalidIp(ip.c_str())) {
                throw (ip + " is invalid IP address");
            }

            this->ip = std::string(ip);
            this->port = port;
        };

        ~Party() {};

        const std::string_view GetIp(){return ip;};
        const u16 GetPort(){return port;};
    };

}

#endif //PARTY_H
