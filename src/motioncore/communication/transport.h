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
#include <optional>
#include <stdexcept>
#include <span>
#include <vector>
#include <cstdint>

namespace encrypto::motion::communication {

struct TransportStatistics {
  std::size_t number_of_messages_sent = 0;
  std::size_t number_of_messages_received = 0;
  std::size_t number_of_bytes_sent = 0;
  std::size_t number_of_bytes_received = 0;
};

// underlying transport between two parties
// e.g. a TCP/QUIC/.. connection, or a pair of local queues
class Transport {
 public:
  // default constructor
  Transport() = default;
  // move constructor
  Transport(Transport&& other) = default;
  // virtual destructor
  virtual ~Transport() = default;

  // send a message
  virtual void SendMessage(std::span<const std::uint8_t> message) = 0;

  // check if a new message is available
  virtual bool Available() const = 0;

  // receive message, possibly blocking
  virtual std::optional<std::vector<std::uint8_t>> ReceiveMessage() = 0;

  // shutdown the outgoing part of the transport to signal end of communication
  virtual void ShutdownSend() = 0;

  // shutdown this transport
  virtual void Shutdown() = 0;

  const TransportStatistics& GetStatistics() const;
  void ResetStatistics();

 protected:
  TransportStatistics statistics_;
};

}  // namespace encrypto::motion::communication
