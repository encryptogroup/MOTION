// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko, Lennart Braun
// Cryptography and Privacy Engineering Group (ENCRYPTO)
// TU Darmstadt, Germany
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

#include <fmt/format.h>
#include <gtest/gtest.h>
#include "base/party.h"
#include "communication/context.h"
#include "test_constants.h"

using namespace MOTION;

// Check that MOTIONParty throws an exception when using an incorrect IP address
TEST(Party, Allocation_IncorrectIPMustThrow) {
  std::srand(std::time(nullptr));
  const std::string_view incorrect_symbols("*-+;:,/?'[]_=abcdefghijklmnopqrstuvwxyz");

  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    auto r_u8 = []() { return std::to_string((std::uint8_t)std::rand()); };
    auto rand_invalid_ip = [r_u8, incorrect_symbols]() {
      std::string result = fmt::format("{}.{}.{}.{}", r_u8(), r_u8(), r_u8(), r_u8());
      result.at(std::rand() % result.size()) =
          incorrect_symbols.at(std::rand() % incorrect_symbols.size());
      return result;
    };
    auto must_throw_function = [rand_invalid_ip]() {
      Communication::Context(rand_invalid_ip(), std::rand(), MOTION::Role::Client, 0);
    };
    ASSERT_ANY_THROW(must_throw_function());
  }
}

TEST(Party, NetworkConnection_OpenMP) {
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    bool all_connected = false;
    // use std::threads, since omp (and pragmas in general) cannot be used in macros :(
    try {
      std::vector<PartyPtr> motion_parties(0);
#pragma omp parallel num_threads(5) default(shared)
      {
#pragma omp single
        {
// Party #0
#pragma omp task
          {
            std::vector<Communication::ContextPtr> parties;
            parties.emplace_back(std::make_shared<Communication::Context>("127.0.0.1", PORT_OFFSET,
                                                                          MOTION::Role::Server, 1));
            parties.emplace_back(std::make_shared<Communication::Context>(
                "127.0.0.1", PORT_OFFSET + 1, MOTION::Role::Server, 2));
            parties.emplace_back(std::make_shared<Communication::Context>(
                "127.0.0.1", PORT_OFFSET + 2, MOTION::Role::Server, 3));
            auto motion = std::move(PartyPtr(new Party{parties, 0}));
            motion->Connect();
#pragma omp critical
            { motion_parties.push_back(std::move(motion)); }
          }
// Party #1
#pragma omp task
          {
            std::string ip = "127.0.0.1";
            std::vector<Communication::ContextPtr> parties;
            parties.emplace_back(
                std::make_shared<Communication::Context>(ip, PORT_OFFSET, MOTION::Role::Client, 0));
            parties.emplace_back(std::make_shared<Communication::Context>(
                "127.0.0.1", PORT_OFFSET + 3, MOTION::Role::Server, 2));
            parties.emplace_back(std::make_shared<Communication::Context>(
                "127.0.0.1", PORT_OFFSET + 4, MOTION::Role::Server, 3));
            auto motion = std::move(PartyPtr(new Party{parties, 1}));
            motion->Connect();
#pragma omp critical
            { motion_parties.push_back(std::move(motion)); }
          }

// Party #2
#pragma omp task
          {
            std::string ip = "127.0.0.1";
            std::uint16_t port = PORT_OFFSET + 1;
            auto motion = std::move(PartyPtr(new Party{
                {std::make_shared<Communication::Context>(ip, port, MOTION::Role::Client, 0),
                 std::make_shared<Communication::Context>(ip, PORT_OFFSET + 3, MOTION::Role::Client,
                                                          1),
                 std::make_shared<Communication::Context>("127.0.0.1", PORT_OFFSET + 5,
                                                          MOTION::Role::Server, 3)},
                2}));
            motion->Connect();
#pragma omp critical
            { motion_parties.push_back(std::move(motion)); }
          }

// Party #3
#pragma omp task
          {
            auto motion = std::move(
                PartyPtr(new Party{{std::make_shared<Communication::Context>(
                                        "127.0.0.1", PORT_OFFSET + 2, MOTION::Role::Client, 0),
                                    std::make_shared<Communication::Context>(
                                        "127.0.0.1", PORT_OFFSET + 4, MOTION::Role::Client, 1),
                                    std::make_shared<Communication::Context>(
                                        "127.0.0.1", PORT_OFFSET + 5, MOTION::Role::Client, 2)},
                                   3}));
            motion->Connect();
#pragma omp critical
            { motion_parties.push_back(std::move(motion)); }
          }
        }
      }

      all_connected = true;
      for (auto &motionparty : motion_parties) {
        for (auto &party : motionparty->GetConfiguration()->GetContexts()) {
          if (party.get()) {
            all_connected &= party->IsConnected();
          }
        }
      }

      for (auto i = 0u; i < motion_parties.size(); ++i) {
        motion_parties.at(i)->Run(2);
        motion_parties.at(i)->Finish();
      }
    } catch (std::exception &e) {
      std::cerr << e.what() << std::endl;
      all_connected = false;
    }

    ASSERT_TRUE(all_connected);
  }
}

TEST(Party, NetworkConnection_ManualThreads) {
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    bool all_connected = false;
    std::vector<PartyPtr> motion_parties(0);
    try {
      std::vector<std::future<PartyPtr>> futures(0);

      // Party #0
      futures.push_back(std::async(std::launch::async, []() {
        std::vector<Communication::ContextPtr> parties;
        parties.emplace_back(std::make_shared<Communication::Context>("127.0.0.1", PORT_OFFSET,
                                                                      MOTION::Role::Server, 1));
        parties.emplace_back(std::make_shared<Communication::Context>("127.0.0.1", PORT_OFFSET + 1,
                                                                      MOTION::Role::Server, 2));
        parties.emplace_back(std::make_shared<Communication::Context>("127.0.0.1", PORT_OFFSET + 2,
                                                                      MOTION::Role::Server, 3));
        auto motion = std::move(std::make_unique<Party>(parties, 0));
        motion->Connect();
        return std::move(motion);
      }));

      // Party #1
      futures.push_back(std::async(std::launch::async, []() {
        std::string ip = "127.0.0.1";
        std::vector<Communication::ContextPtr> parties;
        parties.emplace_back(
            std::make_shared<Communication::Context>(ip, PORT_OFFSET, MOTION::Role::Client, 0));
        parties.emplace_back(std::make_shared<Communication::Context>("127.0.0.1", PORT_OFFSET + 3,
                                                                      MOTION::Role::Server, 2));
        parties.emplace_back(std::make_shared<Communication::Context>("127.0.0.1", PORT_OFFSET + 4,
                                                                      MOTION::Role::Server, 3));
        auto motion = std::move(PartyPtr(new Party{parties, 1}));
        motion->Connect();
        return std::move(motion);
      }));

      // Party #2
      futures.push_back(std::async(std::launch::async, []() {
        std::string ip = "127.0.0.1";
        std::uint16_t port = PORT_OFFSET + 1;
        auto motion = std::move(PartyPtr(new Party{
            {std::make_shared<Communication::Context>(ip, port, MOTION::Role::Client, 0),
             std::make_shared<Communication::Context>(ip, PORT_OFFSET + 3, MOTION::Role::Client, 1),
             std::make_shared<Communication::Context>("127.0.0.1", PORT_OFFSET + 5,
                                                      MOTION::Role::Server, 3)},
            2}));
        motion->Connect();
        return std::move(motion);
      }));

      // Party #3
      futures.push_back(std::async(std::launch::async, []() {
        auto motion = std::move(
            PartyPtr(new Party{{std::make_shared<Communication::Context>(
                                    "127.0.0.1", PORT_OFFSET + 2, MOTION::Role::Client, 0),
                                std::make_shared<Communication::Context>(
                                    "127.0.0.1", PORT_OFFSET + 4, MOTION::Role::Client, 1),
                                std::make_shared<Communication::Context>(
                                    "127.0.0.1", PORT_OFFSET + 5, MOTION::Role::Client, 2)},
                               3}));
        motion->Connect();
        return std::move(motion);
      }));

      for (auto &f : futures) motion_parties.push_back(f.get());

      all_connected = true;
      for (auto &motionparty : motion_parties) {
        for (auto &party : motionparty->GetConfiguration()->GetContexts()) {
          if (party.get()) {
            all_connected &= party->IsConnected();
          }
        }
      }

      for (auto i = 0u; i < motion_parties.size(); ++i) {
        motion_parties.at(i)->Run(2);
        motion_parties.at(i)->Finish();
      }
    } catch (std::exception &e) {
      std::cerr << e.what() << std::endl;
      all_connected = false;
    }

    ASSERT_TRUE(all_connected);
  }
}

TEST(Party, NetworkConnection_LocalPartiesFromStaticFunction_2_3_4_5_10_parties) {
  for (auto i = 0u; i < TEST_ITERATIONS; ++i) {
    bool all_connected = false;
    for (auto num_parties : num_parties_list) {
      try {
        std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : motion_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
        }
        all_connected = true;
        for (auto &motionparty : motion_parties) {
          for (auto &party : motionparty->GetConfiguration()->GetContexts()) {
            if (party.get()) {
              all_connected &= party->IsConnected();
            }
          }
        }
        for (auto i = 0u; i < motion_parties.size(); ++i) {
          motion_parties.at(i)->Finish();
        }
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
        all_connected = false;
      }
    }
    ASSERT_TRUE(all_connected);
  }
}
