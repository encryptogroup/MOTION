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

#include <gtest/gtest.h>

#include <future>

#include "communication/tcp_transport.h"

class TCPTransportTest : public testing::TestWithParam<std::string> {};

TEST_P(TCPTransportTest, dummy) {
  auto localhost = GetParam();
  auto transport_alice_fut = std::async(std::launch::async, [localhost] {
    MOTION::Communication::TCPSetupHelper helper(0, {{localhost, 13337}, {localhost, 13338}});
    auto transports = helper.setup_connections();
    return std::move(transports.at(1));
  });
  auto transport_bob_fut = std::async(std::launch::async, [localhost] {
    MOTION::Communication::TCPSetupHelper helper(1, {{localhost, 13337}, {localhost, 13338}});
    auto transports = helper.setup_connections();
    return std::move(transports.at(0));
  });
  auto transport_alice = transport_alice_fut.get();
  auto transport_bob = transport_bob_fut.get();

  const std::vector<std::uint8_t> message = {0xde, 0xad, 0xbe, 0xef};

  EXPECT_FALSE(transport_bob->available());
  transport_alice->send_message(message);
  EXPECT_TRUE(transport_bob->available());
  auto received_message = transport_bob->receive_message();
  EXPECT_FALSE(transport_bob->available());

  EXPECT_EQ(received_message, message);
}

INSTANTIATE_TEST_SUITE_P(TCPTransportSuite, TCPTransportTest, testing::Values("127.0.0.1", "::1"),
                         [](auto& info) { return info.param == "::1" ? "ipv6" : "ipv4"; });
