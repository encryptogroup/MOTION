#ifndef PARTYCOMMUNICATIONHANDLER_H
#define PARTYCOMMUNICATIONHANDLER_H

#include <queue>

#include "utility/party.h"
#include "message_generated.h"

namespace ABYN::Communication {
  class PartyCommunicationHandler {

  public:
    PartyCommunicationHandler(ABYN::PartyPtr &party);

    virtual ~PartyCommunicationHandler();

    void SendMessage(flatbuffers::FlatBufferBuilder & message);

  private:
    ABYN::PartyPtr party_;

    PartyCommunicationHandler() = delete;

    std::mutex queue_receive_mutex_, queue_send_mutex_;

    std::thread sender_thread_, receiver_thread_;
    std::queue<std::vector<u8>> queue_send_, queue_receive_;

    bool continue_communication_ = true;

    static void ActAsSender(const BoostSocketPtr &socket, std::queue<std::vector<u8>> &queue_send,
                            const bool &continue_communication, std::mutex &deque_send_mutex);

    static void ActAsReceiver(const BoostSocketPtr &socket, std::queue<std::vector<u8>> &queue_receive,
                              const bool &continue_communication, std::mutex &deque_receive_mutex);
  };

  using PartyCommunicationHandlerPtr = std::shared_ptr<PartyCommunicationHandler>;
}

#endif //PARTYCOMMUNICATIONHANDLER_H
