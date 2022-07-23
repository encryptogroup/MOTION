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
#include <span>
#include <vector>

// Undefine Windows macros that collide with function names in MOTION.
#ifdef SendMessage
#undef SendMessage
#endif

#ifdef GetMessage
#undef GetMessage
#endif

#include "fbs_headers/message_generated.h"
#include "transport.h"
#include "utility/reusable_future.h"

namespace encrypto::motion {

class Logger;

}  // namespace encrypto::motion

namespace encrypto::motion::communication {

class MessageManager;
struct TransportStatistics;

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

  CommunicationLayer() = delete;
  CommunicationLayer(const CommunicationLayer&) = delete;

  std::size_t GetNumberOfParties() const { return number_of_parties_; }
  std::size_t GetMyId() const { return my_id_; }

  // Start communication
  void Start();
  void Synchronize();

  // Send a message to a specified party
  void SendMessage(std::size_t party_id, flatbuffers::DetachedBuffer&& message);

  // Send a message to all other parties
  void BroadcastMessage(flatbuffers::DetachedBuffer&& message);

  // shutdown the communication layer
  void Shutdown();

  std::vector<TransportStatistics> GetTransportStatistics() const noexcept;

  auto GetLogger() { return logger_; }

  void SetLogger(std::shared_ptr<Logger> logger);

  MessageManager& GetMessageManager() { return *message_manager_; }

 private:
  struct CommunicationLayerImplementation;

  std::size_t my_id_;
  std::size_t number_of_parties_;
  std::unique_ptr<CommunicationLayerImplementation> implementation_;
  bool is_started_;
  bool is_shutdown_;
  std::shared_ptr<Logger> logger_;
  std::shared_ptr<MessageManager> message_manager_;

  std::size_t sync_state_{0};
};

// Create a set of communication layers connected by dummy transports
std::vector<std::unique_ptr<CommunicationLayer>> MakeDummyCommunicationLayers(
    std::size_t number_of_parties);

// Create a set of communication layers connected by local TCP connections
std::vector<std::unique_ptr<CommunicationLayer>> MakeLocalTcpCommunicationLayers(
    std::size_t number_of_parties, bool ipv6 = true);

}  // namespace encrypto::motion::communication
