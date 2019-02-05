#include <utility/constants.h>
#include "partycommunicationhandler.h"

namespace ABYN::Communication {

  PartyCommunicationHandler::PartyCommunicationHandler(ABYN::PartyPtr &party) : party_(party) {
    sender_thread_ = std::thread([&]() {
      PartyCommunicationHandler::ActAsSender(party->GetSocket(), queue_send_, continue_communication_,
                                             queue_send_mutex_);
    });
    receiver_thread_ = std::thread([&]() {
      PartyCommunicationHandler::ActAsReceiver(party->GetSocket(), queue_receive_, continue_communication_,
                                               queue_receive_mutex_);
    });
  };

  PartyCommunicationHandler::~PartyCommunicationHandler() {
    continue_communication_ = false;
    if (sender_thread_.joinable()) { sender_thread_.join(); };
    if (receiver_thread_.joinable()) { receiver_thread_.join(); };
  };

  void PartyCommunicationHandler::SendMessage(flatbuffers::FlatBufferBuilder &message) {
    u32 message_size = message.GetSize();
    u8 *message_size_bytes = reinterpret_cast<u8 *>(&message_size);
    std::vector<u8> buffer(message_size_bytes, message_size_bytes + message_size);
    buffer.reserve(message_size + MESSAGE_SIZE_BYTELEN);
    buffer.insert(buffer.end(), message.GetBufferPointer(), message.GetBufferPointer() + message_size);
    {
      std::scoped_lock lock(queue_send_mutex_);
      queue_send_.push(std::move(buffer));
    }
  }

  void PartyCommunicationHandler::ActAsSender(const BoostSocketPtr &socket, std::queue<std::vector<u8>> &queue_send,
                                              const bool &continue_communication, std::mutex &queue_send_mutex) {
    while (continue_communication) {
      if (!queue_send.empty()) {
        auto &message = queue_send.front();
        boost::system::error_code ec;
        boost::asio::write(*socket.get(), boost::asio::buffer(message), ec);
        if (ec) {
          throw (std::runtime_error(fmt::format("Error while writing to socket: {}", ec.message())));
        }
        {
          std::scoped_lock lock(queue_send_mutex);
          queue_send.pop();
        }
      } else {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }
    }
  }

  void
  PartyCommunicationHandler::ActAsReceiver(const BoostSocketPtr &socket, std::queue<std::vector<u8>> &queue_receive,
                                           const bool &continue_communication, std::mutex &queue_send_mutex) {
    socket->non_blocking(true);
    while (continue_communication) {
      boost::system::error_code ec;
      u32 size = 0;
      static_assert(sizeof(size) == MESSAGE_SIZE_BYTELEN); // check consistency of the bytelen of the message size type

      //get the size of the next message
      socket->receive(boost::asio::buffer(&size, sizeof(size)), 0, ec);
      if (ec == boost::asio::error::would_block || ec == boost::asio::error::eof) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        continue;
      } else if (ec){
        throw (std::runtime_error(fmt::format("Error while reading from socket: {}", ec.message())));
      }

      socket->non_blocking(false);
      std::vector<u8> message_buffer(size);
      //get the message
      boost::asio::read(*socket.get(), boost::asio::buffer(message_buffer), ec);
      if (ec) {
        throw (std::runtime_error(fmt::format("Error while reading from socket: {}", ec.message())));
      }

      {
        std::scoped_lock lock(queue_send_mutex);
        queue_receive.push(std::move(message_buffer));
      }
      socket->non_blocking(true);
    }
  }

}