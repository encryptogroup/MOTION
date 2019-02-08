#ifndef PARTYCOMMUNICATIONHANDLER_H
#define PARTYCOMMUNICATIONHANDLER_H

#include <queue>

#include "utility/party.h"
#include "utility/logger.h"
#include "message_generated.h"

namespace ABYN::Communication {
  class PartyCommunicationHandler {

  public:
    PartyCommunicationHandler(ABYN::PartyPtr &party, ABYN::LoggerPtr & logger);

    virtual ~PartyCommunicationHandler();

    void SendMessage(flatbuffers::FlatBufferBuilder &message);

    const BoostSocketPtr GetSocket(){return party_->GetSocket();};

    bool ContinueCommunication() { return continue_communication_; };

    std::queue<std::vector<u8>> &GetSendQueue() { return queue_send_; };

    std::queue<std::vector<u8>> &GetReceiveQueue() { return queue_receive_; };

    std::mutex &GetSendMutex() { return queue_send_mutex_; };

    std::mutex &GetReceiveMutex() { return queue_receive_mutex_; };

    ABYN::LoggerPtr & GetLogger() {return logger_;}

  private:
    ABYN::PartyPtr party_;
    ABYN::LoggerPtr logger_;

    PartyCommunicationHandler() = delete;

    std::mutex queue_receive_mutex_, queue_send_mutex_;

    std::thread sender_thread_, receiver_thread_;
    std::queue<std::vector<u8>> queue_send_, queue_receive_;

    bool continue_communication_ = true;

    static void ActAsSender(PartyCommunicationHandler * communication_handler);

    static void ActAsReceiver(PartyCommunicationHandler * communication_handler);
  };

  using PartyCommunicationHandlerPtr = std::shared_ptr<PartyCommunicationHandler>;
}

#endif //PARTYCOMMUNICATIONHANDLER_H
