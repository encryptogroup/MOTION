#pragma once

#include <queue>

#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "flatbuffers/flatbuffers.h"

namespace ABYN {
class Logger;
using LoggerPtr = std::shared_ptr<Logger>;

using IoServicePtr = std::shared_ptr<boost::asio::io_service>;
using BoostSocketPtr = std::shared_ptr<boost::asio::ip::tcp::socket>;

namespace Communication {
class Context;
using ContextPtr = std::shared_ptr<Context>;

class Handler {
 public:
  Handler() = delete;

  Handler(ContextPtr &party, const LoggerPtr &logger);

  virtual ~Handler();

  void SendMessage(flatbuffers::FlatBufferBuilder &message);

  const BoostSocketPtr GetSocket();

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
  std::weak_ptr<Context> party_;
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

using HandlerPtr = std::shared_ptr<Handler>;
}  // namespace Communication
}