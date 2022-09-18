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

#include <flatbuffers/flatbuffers.h>
#include <gtest/gtest.h>
#include <boost/log/trivial.hpp>

#include "communication/communication_layer.h"
#include "communication/message.h"
#include "communication/message_manager.h"
#include "utility/logger.h"

namespace {

namespace comm = encrypto::motion::communication;

TEST(CommunicationLayer, Dummy) {
  std::size_t number_of_parties = 3;
  auto communication_layers = comm::MakeDummyCommunicationLayers(3);
  auto& communication_layer_alice = communication_layers.at(0);
  auto& communication_layer_bob = communication_layers.at(1);
  auto& communication_layer_charlie = communication_layers.at(2);

  std::for_each(std::begin(communication_layers), std::end(communication_layers),
                [](auto& cl) { cl->Start(); });

  const std::vector<std::uint8_t> message = {0xde, 0xad, 0xbe, 0xef};

  auto message_future_b1{communication_layer_bob->GetMessageManager().RegisterReceive(
      0, comm::MessageType::kOutputMessage, 0)};

  auto message_future_b2{communication_layer_bob->GetMessageManager().RegisterReceive(
      0, comm::MessageType::kOutputMessage, 1)};
  auto message_future_c2{communication_layer_charlie->GetMessageManager().RegisterReceive(
      0, comm::MessageType::kOutputMessage, 1)};

  {
    communication_layer_alice->SendMessage(
        1, comm::BuildMessage(comm::MessageType::kOutputMessage, 0, message).Release());
    auto received_message = message_future_b1.get();
    auto lhs = comm::GetMessage(received_message.data())->payload();
    for (std::size_t i = 0; i < message.size(); ++i) EXPECT_EQ(lhs->Get(i), message[i]);
  }
  // sync#1
  {
    std::vector<std::future<void>> futures;
    for (auto& cl : communication_layers) {
      futures.emplace_back(std::async(std::launch::async, [&cl] { cl->Synchronize(); }));
    }
    std::for_each(std::begin(futures), std::end(futures), [](auto& f) { f.get(); });
  }

  {
    communication_layer_alice->BroadcastMessage(
        comm::BuildMessage(comm::MessageType::kOutputMessage, 1, message).Release());
    auto received_message_1 = message_future_b2.get();
    auto lhs1 = comm::GetMessage(received_message_1.data())->payload();
    for (std::size_t i = 0; i < message.size(); ++i) EXPECT_EQ(lhs1->Get(i), message[i]);
    auto received_message_2 = message_future_c2.get();
    auto lhs2 = comm::GetMessage(received_message_2.data())->payload();
    for (std::size_t i = 0; i < message.size(); ++i) EXPECT_EQ(lhs2->Get(i), message[i]);
  }

  // a few more syncs to check that it works
  for (std::size_t i = 0; i < 10u; ++i) {
    std::vector<std::future<void>> futures;
    for (auto& cl : communication_layers) {
      futures.emplace_back(std::async(std::launch::async, [&cl] { cl->Synchronize(); }));
    }
    std::for_each(std::begin(futures), std::end(futures), [](auto& f) { f.get(); });
  }

  // shutdown all commmunication layers
  std::vector<std::future<void>> futures;
  for (auto& cl : communication_layers) {
    futures.emplace_back(std::async(std::launch::async, [&cl] { cl->Shutdown(); }));
  }
  std::for_each(std::begin(futures), std::end(futures), [](auto& f) { f.get(); });
}

class CommunicationLayerTest : public testing::TestWithParam<bool> {};

TEST_P(CommunicationLayerTest, Tcp) {
  std::size_t number_of_parties = 3;
  auto communication_layers =
      encrypto::motion::communication::MakeLocalTcpCommunicationLayers(3, GetParam());
  auto& communication_layer_alice = communication_layers.at(0);
  auto& communication_layer_bob = communication_layers.at(1);
  auto& communication_layer_charlie = communication_layers.at(2);

  std::for_each(std::begin(communication_layers), std::end(communication_layers),
                [](auto& cl) { cl->Start(); });

  const std::vector<std::uint8_t> message = {0xde, 0xad, 0xbe, 0xef};

  auto message_future_b1{communication_layer_bob->GetMessageManager().RegisterReceive(
      0, comm::MessageType::kOutputMessage, 0)};

  auto message_future_b2{communication_layer_bob->GetMessageManager().RegisterReceive(
      0, comm::MessageType::kOutputMessage, 1)};
  auto message_future_c2{communication_layer_charlie->GetMessageManager().RegisterReceive(
      0, comm::MessageType::kOutputMessage, 1)};
  {
    communication_layer_alice->SendMessage(
        1, comm::BuildMessage(comm::MessageType::kOutputMessage, 0, message).Release());
    auto received_message = message_future_b1.get();
    auto lhs = comm::GetMessage(received_message.data())->payload();
    for (std::size_t i = 0; i < message.size(); ++i) EXPECT_EQ(lhs->Get(i), message[i]);
  }

  {
    std::vector<std::future<void>> futures;
    for (auto& cl : communication_layers) {
      futures.emplace_back(std::async(std::launch::async, [&cl] { cl->Synchronize(); }));
    }
    std::for_each(std::begin(futures), std::end(futures), [](auto& f) { f.get(); });
  }

  {
    communication_layer_alice->BroadcastMessage(
        comm::BuildMessage(comm::MessageType::kOutputMessage, 1, message).Release());
    auto received_message_1 = message_future_b2.get();
    auto lhs_1 = comm::GetMessage(received_message_1.data())->payload();
    for (std::size_t i = 0; i < message.size(); ++i) EXPECT_EQ(lhs_1->Get(i), message[i]);
    auto received_message_2 = message_future_c2.get();
    auto lhs_2 = comm::GetMessage(received_message_2.data())->payload();
    for (std::size_t i = 0; i < message.size(); ++i) EXPECT_EQ(lhs_2->Get(i), message[i]);
  }

  // shutdown all commmunication layers
  std::vector<std::future<void>> futures;
  for (auto& cl : communication_layers) {
    futures.emplace_back(std::async(std::launch::async, [&cl] { cl->Shutdown(); }));
  }
  std::for_each(std::begin(futures), std::end(futures), [](auto& f) { f.get(); });
}

INSTANTIATE_TEST_SUITE_P(CommunicationLayerTcpTests, CommunicationLayerTest, testing::Bool(),
                         [](auto& info) { return info.param ? "ipv6" : "ipv4"; });
}  // namespace