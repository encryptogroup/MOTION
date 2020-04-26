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

#include "tcp_transport.h"

#include <chrono>
#include <future>
#include <shared_mutex>

#include <boost/asio/connect.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/system/error_code.hpp>
#include <fmt/format.h>

using boost::asio::ip::tcp;

namespace MOTION::Communication {

namespace detail {

struct TCPTransportImpl {
  TCPTransportImpl(std::shared_ptr<boost::asio::io_context> io_context, tcp::socket&& socket)
      : io_context_(io_context), socket_(std::move(socket)) {}
  std::shared_ptr<boost::asio::io_context> io_context_;
  boost::asio::ip::tcp::socket socket_;
  std::shared_mutex socket_mutex_;
};

}  // namespace detail

TCPTransport::TCPTransport(std::unique_ptr<detail::TCPTransportImpl> impl)
    : is_connected_(true), impl_(std::move(impl)) {}

TCPTransport::TCPTransport(TCPTransport&& other)
    : is_connected_(other.is_connected_), impl_(std::move(other.impl_)) {}

TCPTransport::~TCPTransport() = default;

bool TCPTransport::available() const {
  std::scoped_lock lock(impl_->socket_mutex_);
  auto result = impl_->socket_.available();
  return result > 0;
}

void TCPTransport::shutdown_send() {
  std::scoped_lock lock(impl_->socket_mutex_);
  boost::system::error_code ec;
  impl_->socket_.shutdown(tcp::socket::shutdown_send, ec);
}

void TCPTransport::shutdown() {
  std::scoped_lock lock(impl_->socket_mutex_);
  boost::system::error_code ec;
  impl_->socket_.shutdown(tcp::socket::shutdown_both, ec);
  impl_->socket_.close(ec);
}

void TCPTransport::send_message(std::vector<std::uint8_t>&& message) { send_message(message); }

static void u32tou8(std::uint32_t v, std::uint8_t* result) {
  for (auto i = 0u; i < sizeof(std::uint32_t); ++i) {
    result[i] = (v >> i * 8) & 0xFF;
  }
}

void TCPTransport::send_message(const std::vector<std::uint8_t>& message) {
  if (message.size() > std::numeric_limits<std::uint32_t>::max()) {
    throw std::runtime_error(fmt::format("Max message size is {} B but tried to send {} B",
                                         std::numeric_limits<std::uint32_t>::max(),
                                         message.size()));
  }
  std::array<std::uint8_t, sizeof(std::uint32_t)> message_size;
  u32tou8(message.size(), message_size.data());

  std::array<boost::asio::const_buffer, 2> buffers = {boost::asio::buffer(message_size),
                                                      boost::asio::buffer(message)};

  boost::system::error_code ec;
  std::shared_lock lock(impl_->socket_mutex_);
  boost::asio::write(impl_->socket_, buffers, boost::asio::transfer_all(), ec);
  if (ec) {
    throw std::runtime_error(fmt::format("Error while writing to socket: {}", ec.message()));
  }
  statistics_.num_bytes_sent += message.size() + sizeof(uint32_t);
  statistics_.num_messages_sent += 1;
}

static std::uint32_t u8tou32(std::array<std::uint8_t, sizeof(std::uint32_t)>& v) {
  std::uint32_t result = 0;
  for (auto i = 0u; i < sizeof(std::uint32_t); ++i) {
    result += (v[i] << i * 8);
  }
  return result;
}

std::optional<std::vector<std::uint8_t>> TCPTransport::receive_message() {
  std::array<std::uint8_t, sizeof(std::uint32_t)> message_size_buffer;
  boost::system::error_code ec;
  std::shared_lock lock(impl_->socket_mutex_);
  impl_->socket_.wait(tcp::socket::wait_read, ec);
  if (ec) {
    throw std::runtime_error(
        fmt::format("Error while wait read on socket: {} ({})", ec.message(), ec.value()));
  }
  boost::asio::read(impl_->socket_, boost::asio::buffer(message_size_buffer),
                    boost::asio::transfer_exactly(message_size_buffer.size()), ec);
  if (ec) {
    if (ec.value() == boost::asio::error::misc_errors::eof) {
      // connection has been closed
      return std::nullopt;
    }
    throw std::runtime_error(fmt::format("Error while reading message size from socket: {} ({})",
                                         ec.message(), ec.value()));
  }
  std::uint32_t message_size = u8tou32(message_size_buffer);
  std::vector<std::uint8_t> message_buffer(message_size);
  boost::asio::read(impl_->socket_, boost::asio::buffer(message_buffer),
                    boost::asio::transfer_exactly(message_buffer.size()), ec);
  if (ec) {
    throw std::runtime_error(
        fmt::format("Error while reading message size socket: {} ({})", ec.message(), ec.value()));
  }
  statistics_.num_bytes_received += message_size + sizeof(uint32_t);
  statistics_.num_messages_received += 1;
  return message_buffer;
}

using namespace std::chrono_literals;

struct TCPSetupHelper::TCPSetupImpl {
  [[nodiscard]] std::map<std::size_t, tcp::socket> accept_task();
  [[nodiscard]] tcp::socket connect_task(std::size_t other_id, std::string host,
                                         std::uint16_t port);

  std::size_t my_id_;
  std::size_t num_parties_;
  int num_connect_retries_ = 10;
  decltype(1s) retry_delay_ = 3s;
  boost::asio::ip::address bind_address_;
  std::uint16_t bind_port_;
  std::shared_ptr<boost::asio::io_context> io_context_;
  std::map<std::size_t, tcp::socket> sockets_;
};

TCPSetupHelper::TCPSetupHelper(std::size_t my_id, const tcp_parties_config& parties_config)
    : my_id_(my_id),
      num_parties_(parties_config.size()),
      parties_config_(parties_config),
      impl_(std::make_unique<TCPSetupImpl>()) {
  // check arguments
  if (num_parties_ <= 1) {
    throw std::invalid_argument("specified number of parties: parties_config.size() <= 1");
  }
  if (my_id_ >= num_parties_) {
    throw std::invalid_argument("specified invalid party id: my_id >= parties_config.size()");
  }
  boost::system::error_code ec;
  auto my_config = parties_config_[my_id_];
  impl_->my_id_ = my_id_;
  impl_->num_parties_ = num_parties_;
  impl_->bind_port_ = std::get<1>(my_config);
  impl_->bind_address_ = boost::asio::ip::make_address(std::get<0>(my_config), ec);
  if (ec) {
    throw std::invalid_argument(fmt::format("bind address ({}) is no IP address: {}",
                                            std::get<0>(my_config), ec.message()));
  }
  impl_->io_context_ = std::make_shared<boost::asio::io_context>();
}

TCPSetupHelper::~TCPSetupHelper() = default;

std::vector<std::unique_ptr<Transport>> TCPSetupHelper::setup_connections() {
  auto accept_fut = std::async(std::launch::async, [this] { return impl_->accept_task(); });
  std::vector<std::future<tcp::socket>> futs;
  for (std::size_t party_id = 0; party_id < my_id_; ++party_id) {
    auto party_config = parties_config_.at(party_id);
    futs.emplace_back(std::async(std::launch::async, [this, party_id, party_config] {
      return impl_->connect_task(party_id, std::get<0>(party_config), std::get<1>(party_config));
    }));
  }
  try {
    impl_->sockets_ = accept_fut.get();
    for (std::size_t party_id = 0; party_id < my_id_; ++party_id) {
      impl_->sockets_.emplace(party_id, futs.at(party_id).get());
    }
  } catch (std::runtime_error& e) {
    // an error happened => close all other sockets
    std::for_each(std::begin(impl_->sockets_), std::end(impl_->sockets_), [](auto& it) {
      auto& socket = it.second;
      if (socket.is_open()) {
        boost::system::error_code ec;
        socket.shutdown(tcp::socket::shutdown_type::shutdown_both, ec);
        socket.close(ec);
        // socket is closed even if error occures
      }
    });
    throw;
  }

  std::vector<std::unique_ptr<Transport>> result(num_parties_);
  std::for_each(std::begin(impl_->sockets_), std::end(impl_->sockets_), [this, &result](auto& it) {
    auto transport_impl =
        std::make_unique<detail::TCPTransportImpl>(impl_->io_context_, std::move(it.second));
    result.at(it.first) = std::make_unique<TCPTransport>(std::move(transport_impl));
  });
  return result;
}

std::map<std::size_t, tcp::socket> TCPSetupHelper::TCPSetupImpl::accept_task() {
  if (my_id_ == num_parties_ - 1) {
    return {};
  }
  std::map<std::size_t, tcp::socket> sockets;
  std::size_t num_accepted = 0;
  std::size_t expected_connections = num_parties_ - my_id_ - 1;
  boost::system::error_code ec;
  tcp::acceptor acceptor(*io_context_, tcp::endpoint(bind_address_, bind_port_),
                         /* reuse_addr = */ true);
  acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
  if (ec) {
    throw std::runtime_error(fmt::format("error occurred on listen: {}\n", ec.message()));
  }
  while (num_accepted < expected_connections) {
    tcp::socket socket(*io_context_);
    acceptor.accept(socket, ec);
    if (ec) {
      throw std::runtime_error(fmt::format("error occurred on accept: {}\n", ec.message()));
    }
    std::size_t other_id;
    // receive other id
    {
      std::uint64_t received_id;
      boost::asio::read(socket, boost::asio::mutable_buffer(&received_id, sizeof(received_id)), ec);
      if (ec) {
        socket.close();
        continue;
      }
      other_id = static_cast<std::size_t>(received_id);
    }
    // validate received id
    if (other_id <= my_id_ || other_id >= num_parties_) {
      // invalid_id
      socket.close();
      continue;
    }
    // check if we are already connected to this party
    if (auto it = sockets.find(static_cast<std::size_t>(other_id)); it != sockets.end()) {
      socket.close();
      continue;
    }
    // send my party id
    {
      std::uint64_t my_id = static_cast<std::uint64_t>(my_id_);
      boost::asio::write(socket, boost::asio::const_buffer(&my_id, sizeof(my_id)), ec);
      if (ec) {
        socket.close();
        continue;
      }
    }
    // success
    sockets.emplace(std::make_pair(other_id, std::move(socket)));
    ++num_accepted;
  }
  return sockets;
}

tcp::socket TCPSetupHelper::TCPSetupImpl::connect_task(std::size_t other_id, std::string host,
                                                       std::uint16_t port) {
  boost::system::error_code ec;
  tcp::socket socket(*io_context_);
  tcp::resolver resolver(*io_context_);
  auto endpoints = resolver.resolve(host, std::to_string(port), ec);
  if (ec) {
    throw std::runtime_error(fmt::format("cannot resolve {}:{}, {}\n", host, port, ec.message()));
  }
  int connect_retry_i = 0;
  for (; connect_retry_i < num_connect_retries_; ++connect_retry_i) {
    boost::asio::connect(socket, endpoints, ec);
    if (ec) {
      std::this_thread::sleep_for(retry_delay_);
      continue;
    }

    // send my id to the peer
    {
      std::uint64_t own_id = static_cast<std::uint64_t>(my_id_);
      boost::asio::write(socket, boost::asio::const_buffer(&own_id, sizeof(own_id)), ec);
      if (ec) {
        socket.close();
        continue;
      }
    }

    // receive id of the peer
    {
      std::uint64_t received_id;
      boost::asio::read(socket, boost::asio::mutable_buffer(&received_id, sizeof(received_id)), ec);
      if (ec) {
        socket.close();
        continue;
      }
      if (static_cast<std::size_t>(received_id) != other_id) {
        throw std::runtime_error(fmt::format("received unexpected party id {} of peer {}:{}\n",
                                             received_id, host, port));
      }
    }
    // success
    break;
  }
  if (connect_retry_i == num_connect_retries_) {
    throw std::runtime_error(fmt::format(
        "too many errors while trying to connect to party {} at {}:{}, last error message: {}",
        other_id, host, port, ec.message()));
  }
  return socket;
}

}  // namespace MOTION::Communication
