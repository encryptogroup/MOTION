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

#include "communication/dummy_transport.h"

using namespace encrypto::motion::communication;

TEST(DummyTransport, Dummy) {
  auto [transport_alice, transport_bob] = DummyTransport::MakeTransportPair();

  const std::vector<std::uint8_t> message = {0xde, 0xad, 0xbe, 0xef};

  EXPECT_FALSE(transport_bob->Available());
  transport_alice->SendMessage(message);
  EXPECT_TRUE(transport_bob->Available());
  auto ReceivedMessage = transport_bob->ReceiveMessage();
  EXPECT_FALSE(transport_bob->Available());

  EXPECT_EQ(ReceivedMessage, message);
}
