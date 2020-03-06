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
  std::size_t num_parties = 3;
  auto comm_layers = MOTION::Communication::make_dummy_communication_layers(3);
  auto& cl_alice = comm_layers.at(0);
  auto& cl_bob = comm_layers.at(1);
  auto& cl_charlie = comm_layers.at(2);

  auto log_alice = std::make_shared<MOTION::Logger>(0, boost::log::trivial::severity_level::trace);
  auto log_bob = std::make_shared<MOTION::Logger>(1, boost::log::trivial::severity_level::trace);
  auto log_charlie =
      std::make_shared<MOTION::Logger>(2, boost::log::trivial::severity_level::trace);
  cl_alice->set_logger(log_alice);
  cl_bob->set_logger(log_bob);
  cl_charlie->set_logger(log_charlie);

  cl_bob->register_fallback_message_handler(
      [](auto party_id) { return std::make_shared<MOTION::Communication::QueueHandler>(); });
  cl_charlie->register_fallback_message_handler(
      [](auto party_id) { return std::make_shared<MOTION::Communication::QueueHandler>(); });
  auto& qh_bob =
      dynamic_cast<MOTION::Communication::QueueHandler&>(cl_bob->get_fallback_message_handler(0));
  auto& qh_charlie = dynamic_cast<MOTION::Communication::QueueHandler&>(
      cl_charlie->get_fallback_message_handler(0));

  std::for_each(std::begin(comm_layers), std::end(comm_layers), [](auto& cl) { cl->start(); });

  const std::vector<std::uint8_t> message = {0xde, 0xad, 0xbe, 0xef};

  {
    cl_alice->send_message(1, message);
    auto received_message = qh_bob.get_queue().dequeue();
    EXPECT_EQ(received_message, message);
  }

  {
    std::vector<std::future<void>> futs;
    for (auto& cl : comm_layers) {
      futs.emplace_back(std::async(std::launch::async, [&cl] { cl->sync(); }));
    }
    std::for_each(std::begin(futs), std::end(futs), [](auto& f) { f.get(); });
  }

  {
    cl_alice->broadcast_message(message);
    auto received_message_bob = qh_bob.get_queue().dequeue();
    EXPECT_EQ(received_message_bob, message);
    auto received_message_charlie = qh_charlie.get_queue().dequeue();
    EXPECT_EQ(received_message_charlie, message);
  }

  // shutdown all commmunication layers
  std::vector<std::future<void>> futs;
  for (auto& cl : comm_layers) {
    futs.emplace_back(std::async(std::launch::async, [&cl] { cl->shutdown(); }));
  }
  std::for_each(std::begin(futs), std::end(futs), [](auto& f) { f.get(); });
}

class CommunicationLayerTCP : public testing::TestWithParam<bool> {};

TEST_P(CommunicationLayerTCP, TCP) {
  std::size_t num_parties = 3;
  auto comm_layers = MOTION::Communication::make_local_tcp_communication_layers(3, GetParam());
  auto& cl_alice = comm_layers.at(0);
  auto& cl_bob = comm_layers.at(1);
  auto& cl_charlie = comm_layers.at(2);

  auto log_alice = std::make_shared<MOTION::Logger>(0, boost::log::trivial::severity_level::trace);
  auto log_bob = std::make_shared<MOTION::Logger>(1, boost::log::trivial::severity_level::trace);
  auto log_charlie =
      std::make_shared<MOTION::Logger>(2, boost::log::trivial::severity_level::trace);
  cl_alice->set_logger(log_alice);
  cl_bob->set_logger(log_bob);
  cl_charlie->set_logger(log_charlie);

  cl_bob->register_fallback_message_handler(
      [](auto party_id) { return std::make_shared<MOTION::Communication::QueueHandler>(); });
  cl_charlie->register_fallback_message_handler(
      [](auto party_id) { return std::make_shared<MOTION::Communication::QueueHandler>(); });
  auto& qh_bob =
      dynamic_cast<MOTION::Communication::QueueHandler&>(cl_bob->get_fallback_message_handler(0));
  auto& qh_charlie = dynamic_cast<MOTION::Communication::QueueHandler&>(
      cl_charlie->get_fallback_message_handler(0));

  std::for_each(std::begin(comm_layers), std::end(comm_layers), [](auto& cl) { cl->start(); });

  const std::vector<std::uint8_t> message = {0xde, 0xad, 0xbe, 0xef};

  {
    cl_alice->send_message(1, message);
    auto received_message = qh_bob.get_queue().dequeue();
    EXPECT_EQ(received_message, message);
  }

  {
    std::vector<std::future<void>> futs;
    for (auto& cl : comm_layers) {
      futs.emplace_back(std::async(std::launch::async, [&cl] { cl->sync(); }));
    }
    std::for_each(std::begin(futs), std::end(futs), [](auto& f) { f.get(); });
  }

  {
    cl_alice->broadcast_message(message);
    auto received_message_bob = qh_bob.get_queue().dequeue();
    EXPECT_EQ(received_message_bob, message);
    auto received_message_charlie = qh_charlie.get_queue().dequeue();
    EXPECT_EQ(received_message_charlie, message);
  }

  // shutdown all commmunication layers
  std::vector<std::future<void>> futs;
  for (auto& cl : comm_layers) {
    futs.emplace_back(std::async(std::launch::async, [&cl] { cl->shutdown(); }));
  }
  std::for_each(std::begin(futs), std::end(futs), [](auto& f) { f.get(); });
}

INSTANTIATE_TEST_SUITE_P(CommunicationLayerTCPTests, CommunicationLayerTCP, testing::Bool(),
                         [](auto& info) { return info.param ? "ipv6" : "ipv4"; });
