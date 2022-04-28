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

#include <map>
#include <memory>
#include <string_view>
#include <vector>

#include "transport.h"

namespace encrypto::motion::communication {

namespace detail {

struct TcpTransportImplementation;

}  // namespace detail

class TcpTransport : public Transport {
 public:
  TcpTransport(std::unique_ptr<detail::TcpTransportImplementation> implementation);
  TcpTransport(TcpTransport&& other);

  // Destructor needs to be defined in implementation due to pimpl
  ~TcpTransport();

  void SendMessage(std::span<const std::uint8_t> message) override;

  bool Available() const override;
  std::optional<std::vector<std::uint8_t>> ReceiveMessage() override;
  void ShutdownSend() override;
  void Shutdown() override;

 private:
  bool is_connected_;
  std::unique_ptr<detail::TcpTransportImplementation> implementation_;
};

using TcpConnectionConfiguration = std::pair<std::string, std::uint16_t>;
using TcpPartiesConfiguration = std::vector<TcpConnectionConfiguration>;

// Helper class to establish point-to-point TCP connections among a set of
// parties.  Given the ID of the local party and a collection of host and port
// for all parties, connections are created as follows: This party tries to
// connect to all parties with smaller IDs, and it accepts connections from the
// parties with larger IDs.
class TcpSetupHelper {
 public:
  TcpSetupHelper(std::size_t my_id, const TcpPartiesConfiguration& parties_configuration);

  // Destructor needs to be defined in implementation due to pimpl
  ~TcpSetupHelper();

  // Try to establish connections as described above.
  // Throws a std::runtime_error if something goes wrong.
  std::vector<std::unique_ptr<Transport>> SetupConnections();

 private:
  struct TcpSetupImplementation;

  std::size_t my_id_;
  std::size_t number_of_parties_;
  const TcpPartiesConfiguration parties_configuration_;
  std::unique_ptr<TcpSetupImplementation> implementation_;
};

}  // namespace encrypto::motion::communication
