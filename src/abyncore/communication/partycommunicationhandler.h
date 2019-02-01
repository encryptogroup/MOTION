#ifndef PARTYCOMMUNICATIONHANDLER_H
#define PARTYCOMMUNICATIONHANDLER_H

#include <deque>

#include "utility/party.h"
#include "message_generated.h"

namespace ABYN::Communication {
  class PartyCommunicationHandler {

  public:
    PartyCommunicationHandler(ABYN::PartyPtr &party) : party_(party) {
      sender_thread_ = std::thread([&]() {
        PartyCommunicationHandler::ActAsSerder(party->GetSocket(), deque_send_, continue_communication_);
      });
      receiver_thread_ = std::thread([&]() {
        PartyCommunicationHandler::ActAsReceiver(party->GetSocket(), deque_receive_, continue_communication_);
      });
    };

    virtual ~PartyCommunicationHandler() {
      continue_communication_ = false;
      if (sender_thread_.joinable()) sender_thread_.join();
      if (receiver_thread_.joinable()) receiver_thread_.join();
    };

  private:
    ABYN::PartyPtr party_;

    PartyCommunicationHandler() = delete;

    std::mutex mutex_;

    std::thread sender_thread_, receiver_thread_;
    std::deque<Message> deque_send_, deque_receive_;

    bool continue_communication_ = true;

    static void ActAsSerder(const BoostSocketPtr &socket, std::deque<Message> &deque_send,
                            const bool &continue_communication);

    static void ActAsReceiver(const BoostSocketPtr &socket, std::deque<Message> &deque_receive,
                              const bool &continue_communication);
  };

  using PartyCommunicationHandlerPtr = std::shared_ptr<PartyCommunicationHandler>;
}

#endif //PARTYCOMMUNICATIONHANDLER_H
