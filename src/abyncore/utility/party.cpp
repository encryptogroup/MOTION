#include "party.h"

namespace ABYN
{

    void Party::InitializeSocketServer() {
        std::string role_str;
        if(role == ABYN::Role::Server){
            role_str = std::string(" acting as server");
        }
        else{
            role_str = std::string(" acting as client");
        }

        std::string info(std::string(ip) + std::string(":") +
                         std::to_string(port) + role_str);

        party_socket = socket(AF_INET, SOCK_STREAM, 0);

        if(party_socket < 0)
        {
            throw("Socket creation error for " + info);
        }

        if (setsockopt(party_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                       &opt, sizeof(opt)))
        {
            throw("Could not setsockopt() for " + info);
        }

        struct sockaddr_in address;
        address.sin_family = AF_INET;
        inet_pton(AF_INET, ip.data(), &address.sin_addr);
        address.sin_port = htons(port);
        auto addrlen = sizeof(address);

        if (bind(party_socket, (struct sockaddr *) &address, sizeof(address)) < 0) {
            throw (std::string("Could not bind() the socket for ") + info);
        }

        if (listen(party_socket, 100) < 0) {
            throw (std::string("Could not listen() for ") + info);
        }


        int temp_socket;
        if ((temp_socket = accept(party_socket, (struct sockaddr *)&address,
                                  (socklen_t*)&addrlen))<0)
        {
            throw (std::string("Could not accept() ") + info);
        }

        shutdown(party_socket, 2);
        party_socket = temp_socket;
    };

    void Party::InitializeSocketClient() {
        std::string role_str;
        if(role == ABYN::Role::Server){
            role_str = std::string(" acting as server");
        }
        else{
            role_str = std::string(" acting as client");
        }

        std::string info(std::string(ip) + std::string(":") +
                         std::to_string(port) + role_str);

        party_socket = socket(AF_INET, SOCK_STREAM, 0);

        if(party_socket < 0)
        {
            throw("Socket creation error for " + info);
        }

        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);
        inet_pton(AF_INET, ip.data(), &serv_addr.sin_addr);

        if (connect(party_socket, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            throw("connect() error for " + info);
        }
    };

}