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

namespace MOTION::Communication {

namespace detail {
struct TCPTransportImpl;
}

class TCPTransport : public Transport {
 public:
  TCPTransport(std::unique_ptr<detail::TCPTransportImpl> impl);
  TCPTransport(TCPTransport&& other);

  // Destructor needs to be defined in implementation due to pimpl
  ~TCPTransport();

  void send_message(std::vector<std::uint8_t>&& message);
  void send_message(const std::vector<std::uint8_t>& message);

  bool available() const;
  std::optional<std::vector<std::uint8_t>> receive_message();
  void shutdown_send();
  void shutdown();

 private:
  bool is_connected_;
  std::unique_ptr<detail::TCPTransportImpl> impl_;
};

using tcp_connection_config = std::pair<std::string, std::uint16_t>;
using tcp_parties_config = std::vector<tcp_connection_config>;

// Helper class to establish point-to-point TCP connections among a set of
// parties.  Given the ID of the local party and a collection of host and port
// for all parties, connections are created as follows: This party tries to
// connect to all parties with smaller IDs, and it accepts connections from the
// parties with larger IDs.
class TCPSetupHelper {
 public:
  TCPSetupHelper(std::size_t my_id, const tcp_parties_config& parties_config);

  // Destructor needs to be defined in implementation due to pimpl
  ~TCPSetupHelper();

  // Try to establish connections as described above.
  // Throws a std::runtime_error if something goes wrong.
  std::vector<std::unique_ptr<Transport>> setup_connections();

 private:
  struct TCPSetupImpl;

  std::size_t my_id_;
  std::size_t num_parties_;
  bool connections_open = false;
  const tcp_parties_config parties_config_;
  std::unique_ptr<TCPSetupImpl> impl_;
};

}  // namespace MOTION::Communication
