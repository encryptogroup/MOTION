#ifndef PARTYCOMMUNICATIONHANDLER_H
#define PARTYCOMMUNICATIONHANDLER_H

#include <queue>

#include "utility/communication_context.h"
#include "utility/logger.h"
#include "fbs_headers/message_generated.h"

namespace ABYN::Communication {
  class CommunicationHandler {

  public:
    CommunicationHandler(ABYN::CommunicationContextPtr &party, const ABYN::LoggerPtr &logger);

    virtual ~CommunicationHandler();

    void SendMessage(flatbuffers::FlatBufferBuilder &message);

    const BoostSocketPtr GetSocket() { return party_->GetSocket(); }

    bool ContinueCommunication() { return continue_communication_; }

    void TerminateCommunication();

    void WaitForConnectionEnd();

    std::queue<std::vector<u8>> &GetSendQueue() { return queue_send_; }

    std::queue<std::vector<u8>> &GetReceiveQueue() { return queue_receive_; }

    std::mutex &GetSendMutex() { return queue_send_mutex_; }

    std::mutex &GetReceiveMutex() { return queue_receive_mutex_; }

    ABYN::LoggerPtr &GetLogger() { return logger_; }

    const std::string &GetInfo() { return handler_info_; }

    bool VerifyHelloMessage();

  private:
    ABYN::CommunicationContextPtr party_;
    ABYN::LoggerPtr logger_;

    std::string handler_info_;

    CommunicationHandler() = delete;

    std::mutex queue_receive_mutex_, queue_send_mutex_;

    std::thread sender_thread_, receiver_thread_;
    std::queue<std::vector<u8>> queue_send_, queue_receive_;


    bool continue_communication_ = true;

    bool received_termination_message_ = false, sent_termination_message_ = false;

    void ReceivedTerminationMessage() { received_termination_message_ = true; }

    void SentTerminationMessage() { sent_termination_message_ = true; }

    static void ActAsSender(CommunicationHandler *handler);

    static void ActAsReceiver(CommunicationHandler *handler);

    static u32 ParseHeader(CommunicationHandler *handler);

    static std::vector<u8> ParseBody(CommunicationHandler *handler, u32 size);
  };

  using CommunicationHandlerPtr = std::shared_ptr<CommunicationHandler>;
}

#endif //PARTYCOMMUNICATIONHANDLER_H
