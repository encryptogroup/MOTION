#include "partycommunicationhandler.h"

#include <algorithm>

#include "utility/constants.h"
#include "utility/logger.h"


namespace ABYN::Communication {
  //use explicit conversion function to prevent implementation-dependent conversion issues on different architectures
  std::vector<u8> u32tou8(u32 v) {
    std::vector<u8> result(sizeof(u32));
    for (auto i = 0u; i < result.size(); ++i) {
      result[i] = (v >> i * 8) & 0xFF;
    }
    return std::move(result);
  }

  //use explicit conversion function to prevent implementation-dependent conversion issues on different architectures
  u32 u8tou32(std::vector<u8> &v) {
    u32 result = 0;
    for (auto i = 0u; i < sizeof(u32); ++i) {
      result += (v[i] << i * 8);
    }
    return result;
  }

  PartyCommunicationHandler::PartyCommunicationHandler(ABYN::PartyPtr &party, ABYN::LoggerPtr &logger) :
      party_(party), logger_(logger) {

    handler_info_ = fmt::format("Party#{} handler with end ip {}, local port {}, remote port {}",
                                party->GetId(),
                                party->GetIp(),
                                party->GetSocket()->local_endpoint().port(),
                                party->GetSocket()->remote_endpoint().port());

    sender_thread_ = std::thread([&]() {
      PartyCommunicationHandler::ActAsSender(this);
    });

    receiver_thread_ = std::thread([&]() {
      PartyCommunicationHandler::ActAsReceiver(this);
    });
  }

  PartyCommunicationHandler::~PartyCommunicationHandler() {
    continue_communication_ = false;
    if (sender_thread_.joinable()) { sender_thread_.join(); };
    if (receiver_thread_.joinable()) { receiver_thread_.join(); };
  }

  void PartyCommunicationHandler::SendMessage(flatbuffers::FlatBufferBuilder &message) {
    u32 message_size = message.GetSize();
    std::vector<u8> buffer = std::move(u32tou8(message_size));
    buffer.insert(buffer.end(), message.GetBufferPointer(), message.GetBufferPointer() + message_size);
    {
      std::scoped_lock lock(queue_send_mutex_);
      queue_send_.push(std::move(buffer));
    }

    logger_->LogTrace(fmt::format("{}: Have put a {}-byte message to send queue", handler_info_, message_size));
  }

  void PartyCommunicationHandler::TerminateCommunication() {
    std::vector<u8> buffer = std::move(u32tou8(TERMINATION_MESSAGE));
    {
      std::scoped_lock lock(queue_send_mutex_);
      queue_send_.push(std::move(buffer));
    }

    logger_->LogTrace(fmt::format("{}: Put a termination message message to send queue", handler_info_));
  }

  void PartyCommunicationHandler::ActAsSender(PartyCommunicationHandler *handler) {
    while (handler->ContinueCommunication()) {
      if (!handler->GetSendQueue().empty()) {
        auto &message = handler->GetSendQueue().front();
        std::vector<u8> message_size_buffer(message.data(), message.data() + sizeof(u32));
        auto message_size = u8tou32(message_size_buffer);
        std::string s;
        for (auto i = 0u; i < message.size(); ++i) {
          s.append(fmt::format("{0:#x} ", message.at(i)));
        };

        if (message_size == TERMINATION_MESSAGE) { handler->SentTerminationMessage(); }
        auto message_info = message_size == TERMINATION_MESSAGE ?
                            fmt::format("termination packet") :
                            fmt::format("size: {}", message_size);
        handler->logger_->LogTrace(fmt::format("{}: Written to the socket,  {}, message: {}",
                                               handler->GetInfo(), message_info, s));

        boost::system::error_code ec;
        boost::asio::write(*handler->GetSocket().get(), boost::asio::buffer(message),
                           boost::asio::transfer_exactly(message.size()), ec);
        if (ec) {
          throw (std::runtime_error(fmt::format("Error while writing to socket: {}", ec.message())));
        }
        {
          std::scoped_lock lock(handler->GetSendMutex());
          handler->GetSendQueue().pop();
        }

      } else {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }
    }
  }

  void PartyCommunicationHandler::ActAsReceiver(PartyCommunicationHandler *handler) {
#pragma omp parallel
#pragma omp single
    {
#pragma omp task
      while (handler->ContinueCommunication()) {
        boost::system::error_code ec;

        if (handler->GetSocket()->available() == 0) {
          std::this_thread::sleep_for(std::chrono::milliseconds(1));
          continue;
        }


        u32 size = PartyCommunicationHandler::ParseHeader(handler);
        static_assert(
            sizeof(size) == MESSAGE_SIZE_BYTELEN); // check consistency of the bytelen of the message size type
        if (size == 0) { continue; }
        else if (size == TERMINATION_MESSAGE) { break; };

        std::vector<u8> message_buffer = PartyCommunicationHandler::ParseBody(handler, size);

        {
          std::scoped_lock lock(handler->GetReceiveMutex());
          handler->GetReceiveQueue().push(std::move(message_buffer));
        }
        handler->GetSocket()->non_blocking(true);

        std::string s;
        for (auto i = 0u; i < message_buffer.size(); ++i) {
          s.append(fmt::format("{0:#x} ", message_buffer.at(i)));
        }
        handler->GetLogger()->LogTrace(fmt::format("{}: Read message body of size {}, message: {}",
                                                   handler->GetInfo(), size, s));
      }
#pragma omp task
      while (handler->ContinueCommunication() || !handler->GetReceiveQueue().empty()) {
        //TODO: implement
        if (!handler->GetReceiveQueue().empty()) {
          handler->party_->ParseMessage(std::move(handler->GetReceiveQueue().front()));
          {
            std::scoped_lock(handler->GetReceiveMutex());
            handler->GetReceiveQueue().pop();
          }
        } else {
          std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
      }
    }
  }

  u32 PartyCommunicationHandler::ParseHeader(PartyCommunicationHandler *handler) {
    boost::system::error_code ec;
    std::vector<u8> message_size_buffer(MESSAGE_SIZE_BYTELEN);
    //get the size of the next message
    boost::asio::read(*handler->GetSocket().get(), boost::asio::buffer(message_size_buffer),
                      boost::asio::transfer_exactly(message_size_buffer.size()), ec);

    u32 size = u8tou32(message_size_buffer);

    if (size > 0) {
      if (size == TERMINATION_MESSAGE) {
        handler->ReceivedTerminationMessage();
        handler->GetLogger()->LogTrace(
            fmt::format("{}: Got a termination message from the socket", handler->GetInfo()));
      } else {
        std::string s;
        for (auto i = 0u; i < 4; ++i) {
          s.append(fmt::format("{0:#x} ", reinterpret_cast<u8 *>(&size)[i]));
        };
        handler->GetLogger()->LogTrace(
            fmt::format("{}: Got a new message from the socket and have read the header (size: {}), header: {}",
                        handler->GetInfo(), size, s));
      }
    } else if (size == 0 || (ec == boost::asio::error::would_block || ec == boost::asio::error::eof)) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
      return 0;
    } else if (ec) {
      throw (std::runtime_error(fmt::format("Error while reading from socket: {}", ec.message())));
    }

    return size;
  }


  std::vector<u8> PartyCommunicationHandler::ParseBody(PartyCommunicationHandler *handler, u32 size) {
    boost::system::error_code ec;
    handler->GetSocket()->non_blocking(false);
    std::vector<u8> message_buffer(size);
    //get the message
    boost::asio::read(*(handler->GetSocket().get()), boost::asio::buffer(message_buffer),
                      boost::asio::transfer_exactly(message_buffer.size()), ec);
    if (ec) {
      throw (std::runtime_error(fmt::format("Error while reading from socket: {}", ec.message())));
    }
    return std::move(message_buffer);
  }

  bool PartyCommunicationHandler::VerifyHelloMessage(){

  }
}


