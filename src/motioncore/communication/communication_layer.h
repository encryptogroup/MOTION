// MIT License
//
// Copyright (c) 2020 Lennart Braun
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#pragma once

#include <atomic>
#include <cstddef>
#include <functional>
#include <memory>
#include <vector>

#include "fbs_headers/message_generated.h"
#include "transport.h"

namespace MOTION {

class Logger;

namespace Communication {

class MessageHandler;

// Central interface for all communication related functionality
//
// Allows to send messages to other parties and to register handlers for
// specific message types.
class CommunicationLayer {
 public:
  CommunicationLayer(std::size_t my_id, std::vector<std::unique_ptr<Transport>>&& transports);
  CommunicationLayer(std::size_t my_id, std::vector<std::unique_ptr<Transport>>&& transports,
                     std::shared_ptr<Logger> logger);
  ~CommunicationLayer();

  std::size_t get_num_parties() const { return num_parties_; }
  std::size_t get_my_id() const { return my_id_; }

  // Start communication
  void start();
  void sync();

  // Send a message to a specified party
  void send_message(std::size_t party_id, std::vector<std::uint8_t>&& message);
  void send_message(std::size_t party_id, const std::vector<std::uint8_t>& message);
  void send_message(std::size_t party_id, std::shared_ptr<const std::vector<std::uint8_t>> message);
  void send_message(std::size_t party_id, flatbuffers::FlatBufferBuilder&& message_builder);

  // Send a message to all other parties
  void broadcast_message(std::vector<std::uint8_t>&& message);
  void broadcast_message(const std::vector<std::uint8_t>& message);
  void broadcast_message(std::shared_ptr<const std::vector<std::uint8_t>> message);
  void broadcast_message(flatbuffers::FlatBufferBuilder&& message_builder);

  // Factory function for creating message handlers
  using message_handler_f = std::function<std::shared_ptr<MessageHandler>(std::size_t party_id)>;
  // Register message handlers for given types
  void register_message_handler(message_handler_f, const std::vector<MessageType>& message_types);
  // Deregister any message handler registered for the given types
  void deregister_message_handler(const std::vector<MessageType>& message_types);
  // Return the message handler registered for the given type.
  // Throws if no handler was registered for this type.
  MessageHandler& get_message_handler(std::size_t party_id, MessageType type);

  // Register handler to be called if no matchin handler is installed.
  void register_fallback_message_handler(message_handler_f);
  MessageHandler& get_fallback_message_handler(std::size_t party_id);

  // shutdown the communication layer
  void shutdown();

  void set_logger(std::shared_ptr<Logger> logger);

 private:
  struct CommunicationLayerImpl;

  std::size_t my_id_;
  std::size_t num_parties_;
  std::unique_ptr<CommunicationLayerImpl> impl_;
  bool is_started_;
  bool is_shutdown_;
  std::shared_ptr<Logger> logger_;
};

// Create a set of communication layers connected by dummy transports
std::vector<std::unique_ptr<CommunicationLayer>> make_dummy_communication_layers(
    std::size_t num_parties);

// Create a set of communication layers connected by local TCP connections
std::vector<std::unique_ptr<CommunicationLayer>> make_local_tcp_communication_layers(
    std::size_t num_parties, bool ipv6 = true);

}  // namespace Communication
}  // namespace MOTION
