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

#include "transport.h"
#include "utility/synchronized_queue.h"

namespace MOTION::Communication {

class DummyTransport : public Transport {
 public:
  // move constructor
  DummyTransport(DummyTransport&& other);

  // create a pair of dummy transports which are connected to each other
  static std::pair<std::unique_ptr<DummyTransport>, std::unique_ptr<DummyTransport>>
  make_transport_pair();

  // send a message
  void send_message(std::vector<std::uint8_t>&& message);
  void send_message(const std::vector<std::uint8_t>& message);

  // check if a new message is available
  bool available() const;

  // receive message, possibly blocking
  std::optional<std::vector<std::uint8_t>> receive_message();

  // shutdown the outgoing part of the transport to signal end of communication
  void shutdown_send();

  // shutdown this transport
  void shutdown();

 private:
  using message_queue_t = ENCRYPTO::SynchronizedQueue<std::vector<std::uint8_t>>;
  DummyTransport(std::shared_ptr<message_queue_t> send_queue,
                 std::shared_ptr<message_queue_t> receive_queue) noexcept;

  std::shared_ptr<message_queue_t> send_queue_;
  std::shared_ptr<message_queue_t> receive_queue_;
};

}  // namespace MOTION::Communication
