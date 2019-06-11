#pragma once

#include <queue>

#include "communication_context.h"
#include "fbs_headers/message_generated.h"
#include "utility/logger.h"

namespace ABYN::Communication {
class CommunicationHandler {
 public:
  CommunicationHandler() = delete;

  CommunicationHandler(ABYN::CommunicationContextPtr &party, const ABYN::LoggerPtr &logger);

  virtual ~CommunicationHandler();

  void SendMessage(flatbuffers::FlatBufferBuilder &message);

  const BoostSocketPtr GetSocket() {
    if (auto shared_ptr_party = party_.lock()) {
      return shared_ptr_party->GetSocket();
    } else {
      return nullptr;
    }
  }

  bool ContinueCommunication() { return continue_communication_; }

  void TerminateCommunication();

  void WaitForConnectionEnd();

  std::queue<std::vector<std::uint8_t>> &GetSendQueue() { return queue_send_; }

  std::queue<std::vector<std::uint8_t>> &GetReceiveQueue() { return queue_receive_; }

  std::mutex &GetSendMutex() { return queue_send_mutex_; }

  std::mutex &GetReceiveMutex() { return queue_receive_mutex_; }

  ABYN::LoggerPtr &GetLogger() { return logger_; }

  const std::string &GetInfo() { return handler_info_; }

  bool VerifyHelloMessage();

 private:
  std::weak_ptr<ABYN::CommunicationContext> party_;
  ABYN::LoggerPtr logger_;

  std::string handler_info_;

  std::mutex queue_receive_mutex_, queue_send_mutex_;

  std::thread sender_thread_, receiver_thread_;

  std::queue<std::vector<std::uint8_t>> queue_send_, queue_receive_;
  bool continue_communication_ = true;

  bool received_termination_message_ = false, sent_termination_message_ = false;

  void ReceivedTerminationMessage() { received_termination_message_ = true; }

  void SentTerminationMessage() { sent_termination_message_ = true; }

  void ActAsSender();

  void ActAsReceiver();

  std::uint32_t ParseHeader();

  std::vector<std::uint8_t> ParseBody(std::uint32_t size);
};

using CommunicationHandlerPtr = std::shared_ptr<CommunicationHandler>;
}  // namespace ABYN::Communication
