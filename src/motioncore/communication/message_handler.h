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

#include <cstddef>
#include <cstdint>
#include <vector>

#include "utility/synchronized_queue.h"

namespace encrypto::motion::communication {

// Abstract interface for handling received messages
//
// An instance of MessageHandler can be registered with the CommunicationLayer
// for a given set of message types.  Clients can either register a different
// handler object for each party or use the same for all parties.
class MessageHandler {
 public:
  // virtual destructor to enable inheritance
  virtual ~MessageHandler() = default;

  // Method which is called with received messages of the type the handler is
  // registered for and the id of the sending party.
  //
  // This method may be called concurrently with different values of party_id.
  // The client is responsible for the necessary synchronization.
  virtual void ReceivedMessage(std::size_t party_id, std::vector<std::uint8_t>&& message) = 0;
};

// Example message handler which puts received messages into a queue
class QueueHandler : public MessageHandler {
 public:
  void ReceivedMessage(std::size_t, std::vector<std::uint8_t>&& message) override {
    messages_.enqueue(std::move(message));
  };

  SynchronizedQueue<std::vector<std::uint8_t>>& GetQueue() { return messages_; };

 private:
  SynchronizedQueue<std::vector<std::uint8_t>> messages_;
};

}  // namespace encrypto::motion::communication
