// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko
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

#include <algorithm>
#include <functional>
#include <future>
#include <random>
#include <vector>

#include <fmt/format.h>
#include <gtest/gtest.h>

#include "base/party.h"
#include "crypto/multiplication_triple/mt_provider.h"
#include "share/share_wrapper.h"
#include "utility/typedefs.h"
#include "wire/bmr_wire.h"
#include "wire/boolean_gmw_wire.h"

#include "test_constants.h"

constexpr auto num_parties_list = {2u, 3u, 4u, 5u, 10u};

namespace {
using namespace MOTION;

template <typename T>
inline T Rand() {
  std::random_device rd("/dev/urandom");
  std::uniform_int_distribution<T> dist(0, std::numeric_limits<T>::max());
  return dist(rd);
}

template <typename T>
inline std::vector<T> RandomVector(std::size_t size) {
  std::vector<T> v(size);
  std::generate(v.begin(), v.end(), Rand<T>);
  return v;
}

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

TEST(ArithmeticGMW, InputOutput_1_1K_SIMD_2_3_4_5_10_parties) {
  constexpr auto AGMW = MOTION::MPCProtocol::ArithmeticGMW;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_var) {
    for (auto num_parties : num_parties_list) {
      std::size_t input_owner = std::rand() % num_parties, output_owner = std::rand() % num_parties;
      using T = decltype(template_var);
      T global_input_1 = Rand<T>();
      std::vector<T> global_input_1K = RandomVector<T>(1000);
      try {
        std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : motion_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
          p->GetConfiguration()->SetOnlineAfterSetup(std::random_device{}() % 2 == 1);
        }
#pragma omp parallel num_threads(motion_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(motion_parties.size())
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          T input_1 = 0u;
          std::vector<T> input_1K(global_input_1K.size(), 0u);
          if (party_id == input_owner) {
            input_1 = global_input_1;
            input_1K = global_input_1K;
          }

          MOTION::Shares::ShareWrapper s_in_1 =
              motion_parties.at(party_id)->IN<AGMW>(input_1, input_owner);
          MOTION::Shares::ShareWrapper s_in_1K =
              motion_parties.at(party_id)->IN<AGMW>(input_1K, input_owner);

          auto s_out_1 = s_in_1.Out(output_owner);
          auto s_out_1K = s_in_1K.Out(output_owner);

          motion_parties.at(party_id)->Run(2);

          if (party_id == output_owner) {
            auto wire_1 = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(
                s_out_1->GetWires().at(0));
            auto wire_1K = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(
                s_out_1K->GetWires().at(0));

            assert(wire_1);
            assert(wire_1K);
            EXPECT_EQ(wire_1->GetValues().at(0), global_input_1);
            EXPECT_TRUE(Helpers::Compare::Vectors(wire_1K->GetValues(), global_input_1K));
          }
          motion_parties.at(party_id)->Finish();
        }
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    // lambdas don't support templates, but only auto types. So, let's try to trick them.
    template_test(static_cast<std::uint8_t>(0));
    template_test(static_cast<std::uint16_t>(0));
    template_test(static_cast<std::uint32_t>(0));
    template_test(static_cast<std::uint64_t>(0));
  }
}

TEST(ArithmeticGMW, Addition_1_1K_SIMD_2_3_4_5_10_parties) {
  constexpr auto AGMW = MOTION::MPCProtocol::ArithmeticGMW;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_var) {
    using T = decltype(template_var);
    const std::vector<T> _zero_v_1K(1000, 0);
    for (auto num_parties : num_parties_list) {
      std::size_t output_owner = std::rand() % num_parties;
      std::vector<T> in_1 = RandomVector<T>(num_parties);
      std::vector<std::vector<T>> in_1K(num_parties);
      for (auto &v : in_1K) {
        v = RandomVector<T>(1000);
      }
      try {
        std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : motion_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
          p->GetConfiguration()->SetOnlineAfterSetup(std::random_device{}() % 2 == 1);
        }
#pragma omp parallel num_threads(motion_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(motion_parties.size())
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          std::vector<MOTION::Shares::ShareWrapper> s_in_1, s_in_1K;
          for (auto j = 0u; j < num_parties; ++j) {
            // If my input - real input, otherwise a dummy 0 (-vector).
            // Should not make any difference, just for consistency...
            const T my_in_1 = party_id == j ? in_1.at(j) : 0;
            const std::vector<T> &my_in_1K = party_id == j ? in_1K.at(j) : _zero_v_1K;

            s_in_1.push_back(motion_parties.at(party_id)->IN<AGMW>(my_in_1, j));
            s_in_1K.push_back(motion_parties.at(party_id)->IN<AGMW>(my_in_1K, j));
          }

          auto s_add_1 = s_in_1.at(0) + s_in_1.at(1);
          auto s_add_1K = s_in_1K.at(0) + s_in_1K.at(1);

          for (auto j = 2u; j < num_parties; ++j) {
            s_add_1 += s_in_1.at(j);
            s_add_1K += s_in_1K.at(j);
          }

          auto s_out_1 = s_add_1.Out(output_owner);
          auto s_out_1K = s_add_1K.Out(output_owner);

          auto s_out_1_all = s_add_1.Out();
          auto s_out_1K_all = s_add_1K.Out();

          motion_parties.at(party_id)->Run(2);

          if (party_id == output_owner) {
            auto wire_1 = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(
                s_out_1->GetWires().at(0));
            auto wire_1K = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(
                s_out_1K->GetWires().at(0));

            T circuit_result_1 = wire_1->GetValues().at(0);
            T expected_result_1 = Helpers::SumReduction(in_1);
            EXPECT_EQ(circuit_result_1, expected_result_1);

            const std::vector<T> &circuit_result_1K = wire_1K->GetValues();
            const std::vector<T> expected_result_1K = std::move(Helpers::RowSumReduction(in_1K));
            for (auto i = 0u; i < circuit_result_1K.size(); ++i) {
              EXPECT_EQ(circuit_result_1K.at(i), expected_result_1K.at(i));
            }
          }

          {
            auto wire_1 = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(
                s_out_1_all->GetWires().at(0));
            auto wire_1K = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(
                s_out_1K_all->GetWires().at(0));

            T circuit_result_1 = wire_1->GetValues().at(0);
            T expected_result_1 = Helpers::SumReduction(in_1);
            EXPECT_EQ(circuit_result_1, expected_result_1);

            const std::vector<T> &circuit_result_1K = wire_1K->GetValues();
            const std::vector<T> expected_result_1K = std::move(Helpers::RowSumReduction(in_1K));
            for (auto i = 0u; i < circuit_result_1K.size(); ++i) {
              EXPECT_EQ(circuit_result_1K.at(i), expected_result_1K.at(i));
            }
          }
          motion_parties.at(party_id)->Finish();
        }
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    // lambdas don't support templates, but only auto types. So, let's try to trick them.
    template_test(static_cast<std::uint8_t>(0));
    template_test(static_cast<std::uint16_t>(0));
    template_test(static_cast<std::uint32_t>(0));
    template_test(static_cast<std::uint64_t>(0));
  }
}

TEST(ArithmeticGMW, Multiplication_1_100_SIMD_2_3_parties) {
  constexpr auto AGMW = MOTION::MPCProtocol::ArithmeticGMW;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_var) {
    using T = decltype(template_var);
    const std::vector<T> _zero_v_100(100, 0);
    for (auto num_parties : {2u, 3u}) {
      std::size_t output_owner = std::rand() % num_parties;
      std::vector<T> in_1 = RandomVector<T>(num_parties);
      std::vector<std::vector<T>> in_100(num_parties);
      for (auto &v : in_100) {
        v = RandomVector<T>(100);
      }
      try {
        std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : motion_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
          p->GetConfiguration()->SetOnlineAfterSetup(std::random_device{}() % 2 == 1);
        }
#pragma omp parallel num_threads(motion_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(motion_parties.size())
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          std::vector<MOTION::Shares::ShareWrapper> s_in_1, s_in_100;
          for (auto j = 0u; j < num_parties; ++j) {
            // If my input - real input, otherwise a dummy 0 (-vector).
            // Should not make any difference, just for consistency...
            const T my_in_1 = party_id == j ? in_1.at(j) : 0;
            const std::vector<T> &my_in_100 = party_id == j ? in_100.at(j) : _zero_v_100;

            s_in_1.push_back(motion_parties.at(party_id)->IN<AGMW>(my_in_1, j));
            s_in_100.push_back(motion_parties.at(party_id)->IN<AGMW>(my_in_100, j));
          }

          auto s_mul_1 = s_in_1.at(0) * s_in_1.at(1);
          auto s_mul_100 = s_in_100.at(0) * s_in_100.at(1);

          for (auto j = 2u; j < num_parties; ++j) {
            s_mul_1 *= s_in_1.at(j);
            s_mul_100 *= s_in_100.at(j);
          }

          auto s_out_1 = s_mul_1.Out(output_owner);
          auto s_out_1K = s_mul_100.Out(output_owner);

          auto s_out_1_all = s_mul_1.Out();
          auto s_out_100_all = s_mul_100.Out();

          motion_parties.at(party_id)->Run();

          if (party_id == output_owner) {
            auto wire_1 = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(
                s_out_1->GetWires().at(0));
            auto wire_100 = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(
                s_out_1K->GetWires().at(0));

            T circuit_result_1 = wire_1->GetValues().at(0);
            T expected_result_1 = Helpers::RowMulReduction(in_1);
            EXPECT_EQ(circuit_result_1, expected_result_1);

            const std::vector<T> &circuit_result_100 = wire_100->GetValues();
            const std::vector<T> expected_result_100 = std::move(Helpers::RowMulReduction(in_100));
            for (auto i = 0u; i < circuit_result_100.size(); ++i) {
              EXPECT_EQ(circuit_result_100.at(i), expected_result_100.at(i));
            }
          }
          motion_parties.at(party_id)->Finish();
        }
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    // lambdas don't support templates, but only auto types. So, let's try to trick them.
    template_test(static_cast<std::uint8_t>(0));
    template_test(static_cast<std::uint16_t>(0));
    template_test(static_cast<std::uint32_t>(0));
    template_test(static_cast<std::uint64_t>(0));
  }
}

TEST(BooleanGMW, InputOutput_1_1K_SIMD_2_3_4_5_10_parties) {
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    constexpr auto BGMW = MOTION::MPCProtocol::BooleanGMW;
    std::srand(std::time(nullptr));
    for (auto num_parties : num_parties_list) {
      const std::size_t input_owner = std::rand() % num_parties,
                        output_owner = std::rand() % num_parties;
      const auto global_input_1 = (std::rand() % 2) == 1;
      const auto global_input_1K = ENCRYPTO::BitVector<>::Random(1000);
      try {
        std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : motion_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
          p->GetConfiguration()->SetOnlineAfterSetup(i % 2 == 1);
        }
#pragma omp parallel num_threads(motion_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(motion_parties.size())
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          bool input_1 = false;
          ENCRYPTO::BitVector<> input_1K(global_input_1K.GetSize(), false);
          if (party_id == input_owner) {
            input_1 = global_input_1;
            input_1K = global_input_1K;
          }

          MOTION::Shares::ShareWrapper s_in_1 =
              motion_parties.at(party_id)->IN<BGMW>(input_1, input_owner);
          MOTION::Shares::ShareWrapper s_in_1K =
              motion_parties.at(party_id)->IN<BGMW>(input_1K, input_owner);

          auto s_out_1 = s_in_1.Out(output_owner);
          auto s_out_1K = s_in_1K.Out(output_owner);

          motion_parties.at(party_id)->Run(2);

          if (party_id == output_owner) {
            auto wire_1 =
                std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out_1->GetWires().at(0));
            auto wire_1K =
                std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out_1K->GetWires().at(0));

            assert(wire_1);
            assert(wire_1K);

            EXPECT_EQ(wire_1->GetValues().Get(0), global_input_1);
            EXPECT_EQ(wire_1K->GetValues(), global_input_1K);
          }
          motion_parties.at(party_id).reset();
        }
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
      }
    }
  }
}

TEST(BooleanGMW, INV_1K_SIMD_2_3_4_5_10_parties) {
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    constexpr auto BGMW = MOTION::MPCProtocol::BooleanGMW;
    std::srand(std::time(nullptr));
    for (auto num_parties : num_parties_list) {
      const std::size_t input_owner = std::rand() % num_parties,
                        output_owner = std::rand() % num_parties;
      const auto global_input_1K = ENCRYPTO::BitVector<>::Random(1000);
      try {
        std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : motion_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
          p->GetConfiguration()->SetOnlineAfterSetup(i % 2 == 1);
        }
#pragma omp parallel num_threads(motion_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(motion_parties.size())
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          ENCRYPTO::BitVector<> input_1K(global_input_1K.GetSize(), false);
          if (party_id == input_owner) {
            input_1K = global_input_1K;
          }

          MOTION::Shares::ShareWrapper s_in_1K =
              motion_parties.at(party_id)->IN<BGMW>(input_1K, input_owner);

          s_in_1K = ~s_in_1K;

          auto s_out_1K = s_in_1K.Out(output_owner);

          motion_parties.at(party_id)->Run();

          if (party_id == output_owner) {
            auto wire_1K =
                std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out_1K->GetWires().at(0));

            assert(wire_1K);

            EXPECT_EQ(wire_1K->GetValues(), ~global_input_1K);
          }
          motion_parties.at(party_id).reset();
        }
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
      }
    }
  }
}

TEST(BooleanGMW, XOR_64_bit_200_SIMD_2_3_4_5_10_parties) {
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    constexpr auto BGMW = MOTION::MPCProtocol::BooleanGMW;
    std::srand(std::time(nullptr));
    for (auto num_parties : num_parties_list) {
      const std::size_t output_owner = std::rand() % num_parties;
      std::vector<std::vector<ENCRYPTO::BitVector<>>> global_input_200_64_bit(num_parties);
      for (auto &bv_v : global_input_200_64_bit) {
        bv_v.resize(64);
        for (auto &bv : bv_v) {
          bv = ENCRYPTO::BitVector<>::Random(200);
        }
      }
      std::vector<ENCRYPTO::BitVector<>> dummy_input_200_64_bit(64,
                                                                ENCRYPTO::BitVector<>(200, false));

      try {
        std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : motion_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
          p->GetConfiguration()->SetOnlineAfterSetup(i % 2 == 1);
        }
#pragma omp parallel num_threads(motion_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(motion_parties.size())
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          std::vector<MOTION::Shares::ShareWrapper> s_in;

          for (auto j = 0ull; j < num_parties; ++j) {
            if (j == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
              s_in.push_back(
                  motion_parties.at(party_id)->IN<BGMW>(global_input_200_64_bit.at(j), j));
            } else {
              s_in.push_back(motion_parties.at(party_id)->IN<BGMW>(dummy_input_200_64_bit, j));
            }
          }

          auto s_xor = s_in.at(0) ^ s_in.at(1);

          for (auto j = 2ull; j < num_parties; ++j) {
            s_xor = s_xor ^ s_in.at(j);
          }

          auto s_out = s_xor.Out(output_owner);

          motion_parties.at(party_id)->Run(2);

          if (party_id == output_owner) {
            for (auto j = 0ull; j < global_input_200_64_bit.size(); ++j) {
              auto wire_200_64_bit_single =
                  std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out->GetWires().at(j));
              assert(wire_200_64_bit_single);

              std::vector<ENCRYPTO::BitVector<>> global_input_200_64_bit_single;
              for (auto k = 0ull; k < num_parties; ++k) {
                global_input_200_64_bit_single.push_back(global_input_200_64_bit.at(k).at(j));
              }

              EXPECT_EQ(wire_200_64_bit_single->GetValues(),
                        ENCRYPTO::BitVector<>::XORBitVectors(global_input_200_64_bit_single));
            }
          }

          motion_parties.at(party_id)->Finish();
        }
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
      }
    }
  }
}

TEST(BooleanGMW, AND_1_bit_1_1K_SIMD_2_3_parties) {
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    constexpr auto BGMW = MOTION::MPCProtocol::BooleanGMW;
    std::srand(std::time(nullptr));
    for (auto num_parties : {2u, 3u}) {
      const std::size_t output_owner = std::rand() % num_parties;
      std::vector<bool> global_input_1(num_parties);
      for (auto j = 0ull; j < global_input_1.size(); ++j) {
        global_input_1.at(j) = (std::rand() % 2) == 1;
      }
      std::vector<ENCRYPTO::BitVector<>> global_input_1K(num_parties);

      for (auto j = 0ull; j < global_input_1K.size(); ++j) {
        global_input_1K.at(j) = ENCRYPTO::BitVector<>::Random(1000);
      }
      bool dummy_input_1 = false;
      ENCRYPTO::BitVector<> dummy_input_1K(1000, false);
      try {
        std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : motion_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
          p->GetConfiguration()->SetOnlineAfterSetup(i % 2 == 1);
        }

        auto f = [&](std::size_t party_id) {
          std::vector<MOTION::Shares::ShareWrapper> s_in_1, s_in_1K;

          for (auto j = 0ull; j < num_parties; ++j) {
            if (j == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
              s_in_1.push_back(motion_parties.at(party_id)->IN<BGMW>(
                  static_cast<bool>(global_input_1.at(j)), j));
              s_in_1K.push_back(motion_parties.at(party_id)->IN<BGMW>(global_input_1K.at(j), j));
            } else {
              s_in_1.push_back(motion_parties.at(party_id)->IN<BGMW>(dummy_input_1, j));
              s_in_1K.push_back(motion_parties.at(party_id)->IN<BGMW>(dummy_input_1K, j));
            }
          }

          auto s_and_1 = s_in_1.at(0) & s_in_1.at(1);
          auto s_and_1K = s_in_1K.at(0) & s_in_1K.at(1);

          for (auto j = 2ull; j < num_parties; ++j) {
            s_and_1 = s_and_1 & s_in_1.at(j);
            s_and_1K = s_and_1K & s_in_1K.at(j);
          }

          auto s_out_1 = s_and_1.Out(output_owner);
          auto s_out_1K = s_and_1K.Out(output_owner);

          auto s_out_1_all = s_and_1.Out();
          auto s_out_1K_all = s_and_1K.Out();

          motion_parties.at(party_id)->Run();

          if (party_id == output_owner) {
            auto wire_1 =
                std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out_1->GetWires().at(0));
            auto wire_1K =
                std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out_1K->GetWires().at(0));

            assert(wire_1);
            assert(wire_1K);

            EXPECT_EQ(wire_1->GetValues().Get(0),
                      ENCRYPTO::BitVector<>::ANDReduceBitVector(global_input_1));
            EXPECT_EQ(wire_1K->GetValues(), ENCRYPTO::BitVector<>::ANDBitVectors(global_input_1K));
          }

          {
            auto wire_1 =
                std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out_1_all->GetWires().at(0));
            auto wire_1K =
                std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out_1K_all->GetWires().at(0));

            assert(wire_1);
            assert(wire_1K);

            EXPECT_EQ(wire_1->GetValues().Get(0),
                      ENCRYPTO::BitVector<>::ANDReduceBitVector(global_input_1));
            EXPECT_EQ(wire_1K->GetValues(), ENCRYPTO::BitVector<>::ANDBitVectors(global_input_1K));
          }
        };

#pragma omp parallel for num_threads(motion_parties.size() + 1)
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          f(party_id);
          // check multiplication triples
          if (party_id == 0) {
            ENCRYPTO::BitVector<> a, b, c;
            a = motion_parties.at(0)->GetBackend()->GetMTProvider()->GetBinaryAll().a;
            b = motion_parties.at(0)->GetBackend()->GetMTProvider()->GetBinaryAll().b;
            c = motion_parties.at(0)->GetBackend()->GetMTProvider()->GetBinaryAll().c;

            for (auto j = 1ull; j < motion_parties.size(); ++j) {
              a ^= motion_parties.at(j)->GetBackend()->GetMTProvider()->GetBinaryAll().a;
              b ^= motion_parties.at(j)->GetBackend()->GetMTProvider()->GetBinaryAll().b;
              c ^= motion_parties.at(j)->GetBackend()->GetMTProvider()->GetBinaryAll().c;
            }
            EXPECT_EQ(c, a & b);
          }
          motion_parties.at(party_id)->Finish();
        }
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
      }
    }
  }
}

TEST(BooleanGMW, AND_64_bit_10_SIMD_2_3_parties) {
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    constexpr auto BGMW = MOTION::MPCProtocol::BooleanGMW;
    std::srand(std::time(nullptr));
    for (auto num_parties : {2u, 3u}) {
      const std::size_t output_owner = std::rand() % num_parties;
      std::vector<std::vector<ENCRYPTO::BitVector<>>> global_input_10_64_bit(num_parties);
      for (auto &bv_v : global_input_10_64_bit) {
        bv_v.resize(64);
        for (auto &bv : bv_v) {
          bv = ENCRYPTO::BitVector<>::Random(10);
        }
      }
      std::vector<ENCRYPTO::BitVector<>> dummy_input_10_64_bit(64,
                                                               ENCRYPTO::BitVector<>(10, false));

      try {
        std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : motion_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
          p->GetConfiguration()->SetOnlineAfterSetup(i % 2 == 1);
        }
#pragma omp parallel for num_threads(motion_parties.size() + 1)
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          std::vector<MOTION::Shares::ShareWrapper> s_in;

          for (auto j = 0ull; j < num_parties; ++j) {
            if (j == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
              s_in.push_back(
                  motion_parties.at(party_id)->IN<BGMW>(global_input_10_64_bit.at(j), j));
            } else {
              s_in.push_back(motion_parties.at(party_id)->IN<BGMW>(dummy_input_10_64_bit, j));
            }
          }

          auto s_and = s_in.at(0) & s_in.at(1);

          for (auto j = 2ull; j < num_parties; ++j) {
            s_and = s_and & s_in.at(j);
          }

          auto s_out = s_and.Out(output_owner);

          motion_parties.at(party_id)->Run();

          if (party_id == output_owner) {
            for (auto j = 0ull; j < global_input_10_64_bit.size(); ++j) {
              auto wire_single =
                  std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out->GetWires().at(j));
              assert(wire_single);

              std::vector<ENCRYPTO::BitVector<>> global_input_single;
              for (auto k = 0ull; k < num_parties; ++k) {
                global_input_single.push_back(global_input_10_64_bit.at(k).at(j));
              }

              EXPECT_EQ(wire_single->GetValues(),
                        ENCRYPTO::BitVector<>::ANDBitVectors(global_input_single));
            }
          }

          motion_parties.at(party_id)->Finish();
        }
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
      }
    }
  }
}

}  // namespace
