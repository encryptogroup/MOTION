#include "partycommunicationhandler.h"

#include "utility/constants.h"
#include "utility/logger.h"


namespace ABYN::Communication {

  PartyCommunicationHandler::PartyCommunicationHandler(ABYN::PartyPtr &party, ABYN::LoggerPtr & logger) :
  party_(party), logger_(logger){

    sender_thread_ = std::thread([&]() {
      PartyCommunicationHandler::ActAsSender(this);
    });

    receiver_thread_ = std::thread([&]() {
      PartyCommunicationHandler::ActAsReceiver(this);
    });
  };

  PartyCommunicationHandler::~PartyCommunicationHandler() {
    continue_communication_ = false;
    if (sender_thread_.joinable()) { sender_thread_.join(); };
    if (receiver_thread_.joinable()) { receiver_thread_.join(); };
  };

  void PartyCommunicationHandler::SendMessage(flatbuffers::FlatBufferBuilder &message) {
    u32 message_size = message.GetSize();
    std::cout << fmt::format("Constructed a {}-byte message", message_size);
    u8 *message_size_bytes = reinterpret_cast<u8 *>(&message_size);
    std::vector<u8> buffer(message_size_bytes, message_size_bytes + message_size);
    buffer.reserve(message_size + MESSAGE_SIZE_BYTELEN);
    buffer.insert(buffer.end(), message.GetBufferPointer(), message.GetBufferPointer() + message_size);
    {
      std::scoped_lock lock(queue_send_mutex_);
      queue_send_.push(std::move(buffer));
    }
  }

  void PartyCommunicationHandler::ActAsSender(PartyCommunicationHandler *party) {
    while (party->ContinueCommunication()) {
      if (!party->GetSendQueue().empty()) {
        auto &message = party->GetSendQueue().front();
        std::cout << fmt::format("Written to the socket, size: {}\n", *(reinterpret_cast<u32 *>(message.data())));
        boost::system::error_code ec;
        boost::asio::write(*party->GetSocket().get(), boost::asio::buffer(message), ec);
        if (ec) {
          throw (std::runtime_error(fmt::format("Error while writing to socket: {}", ec.message())));
        }
        {
          std::scoped_lock lock(party->GetSendMutex());
          party->GetSendQueue().pop();
        }

      } else {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }
    }
  }

  void PartyCommunicationHandler::ActAsReceiver(PartyCommunicationHandler *party) {
    while (party->ContinueCommunication()) {
      party->GetSocket()->non_blocking(true);
      boost::system::error_code ec;
      u32 size = 0;
      static_assert(sizeof(size) == MESSAGE_SIZE_BYTELEN); // check consistency of the bytelen of the message size type

      //get the size of the next message
      party->GetSocket()->receive(boost::asio::buffer(&size, sizeof(size)), 0, ec);
      if (ec == boost::asio::error::would_block || ec == boost::asio::error::eof) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        continue;
      } else if (ec) {
        throw (std::runtime_error(fmt::format("Error while reading from socket: {}", ec.message())));
      }

      party->GetLogger()->LogTrace(fmt::format("Got a new message from the socket and have read the header"));

      party->GetSocket()->non_blocking(false);
      std::vector<u8> message_buffer(size);
      //get the message
      boost::asio::read(*(party->GetSocket().get()), boost::asio::buffer(message_buffer), ec);
      if (ec) {
        throw (std::runtime_error(fmt::format("Error while reading from socket: {}", ec.message())));
      }

      {
        std::scoped_lock lock(party->GetReceiveMutex());
        party->GetReceiveQueue().push(std::move(message_buffer));
      }
      party->GetSocket()->non_blocking(true);

      party->GetLogger()->LogTrace(fmt::format("Have read message body of size {}", size));
    }
  }

}