#ifndef PARTYCOMMUNICATIONHANDLER_H
#define PARTYCOMMUNICATIONHANDLER_H

#include <queue>

#include "utility/party.h"
#include "utility/logger.h"
#include "message_generated.h"

namespace ABYN::Communication {
  class PartyCommunicationHandler {

  public:
    PartyCommunicationHandler(ABYN::PartyPtr &party, ABYN::LoggerPtr &logger);

    virtual ~PartyCommunicationHandler();

    void SendMessage(flatbuffers::FlatBufferBuilder &message);

    const BoostSocketPtr GetSocket() { return party_->GetSocket(); }

    bool ContinueCommunication() { return continue_communication_; }

    void TerminateCommunication();

    void WaitForConnectionEnd() {
      while (continue_communication_) {
        if (queue_send_.empty() && queue_receive_.empty() &&
            received_termination_message_ && sent_termination_message_) {
          continue_communication_ = false;
          logger_->LogInfo(fmt::format("{}: terminated.", handler_info_));
        } else {
          std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
      };
    }

    std::queue<std::vector<u8>> &GetSendQueue() { return queue_send_; }

    std::queue<std::vector<u8>> &GetReceiveQueue() { return queue_receive_; }

    std::mutex &GetSendMutex() { return queue_send_mutex_; }

    std::mutex &GetReceiveMutex() { return queue_receive_mutex_; }

    ABYN::LoggerPtr &GetLogger() { return logger_; }

    const std::string &GetInfo() { return handler_info_; }

    bool VerifyHelloMessage();

  private:
    ABYN::PartyPtr party_;
    ABYN::LoggerPtr logger_;

    std::string handler_info_;

    PartyCommunicationHandler() = delete;

    std::mutex queue_receive_mutex_, queue_send_mutex_;

    std::thread sender_thread_, receiver_thread_;
    std::queue<std::vector<u8>> queue_send_, queue_receive_;



    bool continue_communication_ = true;

    bool received_termination_message_ = false, sent_termination_message_ = false;

    void ReceivedTerminationMessage() { received_termination_message_ = true; }

    void SentTerminationMessage() { sent_termination_message_ = true; }

    static void ActAsSender(PartyCommunicationHandler *handler);

    static void ActAsReceiver(PartyCommunicationHandler *handler);

    static u32 ParseHeader(PartyCommunicationHandler *handler);

    static std::vector<u8> ParseBody(PartyCommunicationHandler *handler, u32 size);
  };

  using PartyCommunicationHandlerPtr = std::shared_ptr<PartyCommunicationHandler>;
}

#endif //PARTYCOMMUNICATIONHANDLER_H
