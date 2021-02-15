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
#include <boost/log/trivial.hpp>

#include "communication/communication_layer.h"
#include "communication/message_handler.h"
#include "utility/logger.h"

TEST(CommunicationLayer, Dummy) {
  std::size_t number_of_parties = 3;
  auto communication_layers = encrypto::motion::communication::MakeDummyCommunicationLayers(3);
  auto& communication_layer_alice = communication_layers.at(0);
  auto& communication_layer_bob = communication_layers.at(1);
  auto& communication_layer_charlie = communication_layers.at(2);

  auto log_alice =
      std::make_shared<encrypto::motion::Logger>(0, boost::log::trivial::severity_level::trace);
  auto log_bob =
      std::make_shared<encrypto::motion::Logger>(1, boost::log::trivial::severity_level::trace);
  auto log_charlie =
      std::make_shared<encrypto::motion::Logger>(2, boost::log::trivial::severity_level::trace);
  communication_layer_alice->SetLogger(log_alice);
  communication_layer_bob->SetLogger(log_bob);
  communication_layer_charlie->SetLogger(log_charlie);

  communication_layer_bob->RegisterFallbackMessageHandler([](auto party_id) {
    return std::make_shared<encrypto::motion::communication::QueueHandler>();
  });
  communication_layer_charlie->RegisterFallbackMessageHandler([](auto party_id) {
    return std::make_shared<encrypto::motion::communication::QueueHandler>();
  });
  auto& queue_handler_bob = dynamic_cast<encrypto::motion::communication::QueueHandler&>(
      communication_layer_bob->GetFallbackMessageHandler(0));
  auto& queue_handler_charlie = dynamic_cast<encrypto::motion::communication::QueueHandler&>(
      communication_layer_charlie->GetFallbackMessageHandler(0));

  std::for_each(std::begin(communication_layers), std::end(communication_layers),
                [](auto& cl) { cl->Start(); });

  const std::vector<std::uint8_t> message = {0xde, 0xad, 0xbe, 0xef};

  {
    communication_layer_alice->SendMessage(1, message);
    auto ReceivedMessage = queue_handler_bob.GetQueue().dequeue();
    EXPECT_EQ(ReceivedMessage, message);
  }

  {
    std::vector<std::future<void>> futures;
    for (auto& cl : communication_layers) {
      futures.emplace_back(std::async(std::launch::async, [&cl] { cl->Synchronize(); }));
    }
    std::for_each(std::begin(futures), std::end(futures), [](auto& f) { f.get(); });
  }

  {
    communication_layer_alice->BroadcastMessage(message);
    auto received_message_bob = queue_handler_bob.GetQueue().dequeue();
    EXPECT_EQ(received_message_bob, message);
    auto received_message_charlie = queue_handler_charlie.GetQueue().dequeue();
    EXPECT_EQ(received_message_charlie, message);
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

  auto log_alice =
      std::make_shared<encrypto::motion::Logger>(0, boost::log::trivial::severity_level::trace);
  auto log_bob =
      std::make_shared<encrypto::motion::Logger>(1, boost::log::trivial::severity_level::trace);
  auto log_charlie =
      std::make_shared<encrypto::motion::Logger>(2, boost::log::trivial::severity_level::trace);
  communication_layer_alice->SetLogger(log_alice);
  communication_layer_bob->SetLogger(log_bob);
  communication_layer_charlie->SetLogger(log_charlie);

  communication_layer_bob->RegisterFallbackMessageHandler([](auto party_id) {
    return std::make_shared<encrypto::motion::communication::QueueHandler>();
  });
  communication_layer_charlie->RegisterFallbackMessageHandler([](auto party_id) {
    return std::make_shared<encrypto::motion::communication::QueueHandler>();
  });
  auto& queue_handler_bob = dynamic_cast<encrypto::motion::communication::QueueHandler&>(
      communication_layer_bob->GetFallbackMessageHandler(0));
  auto& queue_handler_charlie = dynamic_cast<encrypto::motion::communication::QueueHandler&>(
      communication_layer_charlie->GetFallbackMessageHandler(0));

  std::for_each(std::begin(communication_layers), std::end(communication_layers),
                [](auto& cl) { cl->Start(); });

  const std::vector<std::uint8_t> message = {0xde, 0xad, 0xbe, 0xef};

  {
    communication_layer_alice->SendMessage(1, message);
    auto ReceivedMessage = queue_handler_bob.GetQueue().dequeue();
    EXPECT_EQ(ReceivedMessage, message);
  }

  {
    std::vector<std::future<void>> futures;
    for (auto& cl : communication_layers) {
      futures.emplace_back(std::async(std::launch::async, [&cl] { cl->Synchronize(); }));
    }
    std::for_each(std::begin(futures), std::end(futures), [](auto& f) { f.get(); });
  }

  {
    communication_layer_alice->BroadcastMessage(message);
    auto received_message_bob = queue_handler_bob.GetQueue().dequeue();
    EXPECT_EQ(received_message_bob, message);
    auto received_message_charlie = queue_handler_charlie.GetQueue().dequeue();
    EXPECT_EQ(received_message_charlie, message);
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
