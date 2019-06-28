#include <algorithm>
#include <functional>
#include <future>
#include <random>
#include <vector>

#include <fmt/format.h>
#include <gtest/gtest.h>
#include <omp.h>

#include "base/party.h"
#include "gate/gate.h"
#include "utility/bit_vector.h"
#include "utility/typedefs.h"
#include "wire/boolean_gmw_wire.h"

#include "test_constants.h"

constexpr auto num_parties_list = {3u, 4u, 5u, 10u};
constexpr auto PORT_OFFSET = 7777u;
constexpr auto DETAILED_LOGGING_ENABLED = false;

namespace {
using namespace ABYN;

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

// Check that ABYNParty throws an exception when using an incorrect IP address
TEST(ABYNPartyAllocation, IncorrectIPMustThrow) {
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
      Communication::Context(rand_invalid_ip(), std::rand(), ABYN::Role::Client, 0);
    };
    ASSERT_ANY_THROW(must_throw_function());
  }
}

TEST(ABYNParty, NetworkConnection_OpenMP) {
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    bool all_connected = false;
    // use std::threads, since omp (and pragmas in general) cannot be used in macros :(
    try {
      std::vector<PartyPtr> abyn_parties(0);
#pragma omp parallel num_threads(5) default(shared)
      {
#pragma omp single
        {
// Party #0
#pragma omp task
          {
            std::vector<Communication::ContextPtr> parties;
            parties.emplace_back(std::make_shared<Communication::Context>("127.0.0.1", PORT_OFFSET,
                                                                          ABYN::Role::Server, 1));
            parties.emplace_back(std::make_shared<Communication::Context>(
                "127.0.0.1", PORT_OFFSET + 1, ABYN::Role::Server, 2));
            parties.emplace_back(std::make_shared<Communication::Context>(
                "127.0.0.1", PORT_OFFSET + 2, ABYN::Role::Server, 3));
            auto abyn = std::move(PartyPtr(new Party{parties, 0}));
            abyn->Connect();
#pragma omp critical
            { abyn_parties.push_back(std::move(abyn)); }
          }
// Party #1
#pragma omp task
          {
            std::string ip = "127.0.0.1";
            std::vector<Communication::ContextPtr> parties;
            parties.emplace_back(
                std::make_shared<Communication::Context>(ip, PORT_OFFSET, ABYN::Role::Client, 0));
            parties.emplace_back(std::make_shared<Communication::Context>(
                "127.0.0.1", PORT_OFFSET + 3, ABYN::Role::Server, 2));
            parties.emplace_back(std::make_shared<Communication::Context>(
                "127.0.0.1", PORT_OFFSET + 4, ABYN::Role::Server, 3));
            auto abyn = std::move(PartyPtr(new Party{parties, 1}));
            abyn->Connect();
#pragma omp critical
            { abyn_parties.push_back(std::move(abyn)); }
          }

// Party #2
#pragma omp task
          {
            std::string ip = "127.0.0.1";
            std::uint16_t port = PORT_OFFSET + 1;
            auto abyn = std::move(PartyPtr(new Party{
                {std::make_shared<Communication::Context>(ip, port, ABYN::Role::Client, 0),
                 std::make_shared<Communication::Context>(ip, PORT_OFFSET + 3, ABYN::Role::Client,
                                                          1),
                 std::make_shared<Communication::Context>("127.0.0.1", PORT_OFFSET + 5,
                                                          ABYN::Role::Server, 3)},
                2}));
            abyn->Connect();
#pragma omp critical
            { abyn_parties.push_back(std::move(abyn)); }
          }

// Party #3
#pragma omp task
          {
            auto abyn = std::move(
                PartyPtr(new Party{{std::make_shared<Communication::Context>(
                                        "127.0.0.1", PORT_OFFSET + 2, ABYN::Role::Client, 0),
                                    std::make_shared<Communication::Context>(
                                        "127.0.0.1", PORT_OFFSET + 4, ABYN::Role::Client, 1),
                                    std::make_shared<Communication::Context>(
                                        "127.0.0.1", PORT_OFFSET + 5, ABYN::Role::Client, 2)},
                                   3}));
            abyn->Connect();
#pragma omp critical
            { abyn_parties.push_back(std::move(abyn)); }
          }
        }
      }

      all_connected = true;
      for (auto &abynparty : abyn_parties) {
        for (auto &party : abynparty->GetConfiguration()->GetParties()) {
          if (party.get()) {
            all_connected &= party->IsConnected();
          }
        }
      }

      for (auto i = 0u; i < abyn_parties.size(); ++i) {
        abyn_parties.at(i)->Run();
      }
    } catch (std::exception &e) {
      std::cerr << e.what() << std::endl;
      all_connected = false;
    }

    ASSERT_TRUE(all_connected);
  }
}

TEST(ABYNParty, NetworkConnection_ManualThreads) {
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    bool all_connected = false;
    try {
      std::vector<PartyPtr> abyn_parties(0);
      std::vector<std::future<PartyPtr>> futures(0);

      // Party #0
      futures.push_back(std::async(std::launch::async, []() {
        std::vector<Communication::ContextPtr> parties;
        parties.emplace_back(std::make_shared<Communication::Context>("127.0.0.1", PORT_OFFSET,
                                                                      ABYN::Role::Server, 1));
        parties.emplace_back(std::make_shared<Communication::Context>("127.0.0.1", PORT_OFFSET + 1,
                                                                      ABYN::Role::Server, 2));
        parties.emplace_back(std::make_shared<Communication::Context>("127.0.0.1", PORT_OFFSET + 2,
                                                                      ABYN::Role::Server, 3));
        auto abyn = std::move(PartyPtr(new Party{parties, 0}));
        abyn->Connect();
        return std::move(abyn);
      }));

      // Party #1
      futures.push_back(std::async(std::launch::async, []() {
        std::string ip = "127.0.0.1";
        std::vector<Communication::ContextPtr> parties;
        parties.emplace_back(
            std::make_shared<Communication::Context>(ip, PORT_OFFSET, ABYN::Role::Client, 0));
        parties.emplace_back(std::make_shared<Communication::Context>("127.0.0.1", PORT_OFFSET + 3,
                                                                      ABYN::Role::Server, 2));
        parties.emplace_back(std::make_shared<Communication::Context>("127.0.0.1", PORT_OFFSET + 4,
                                                                      ABYN::Role::Server, 3));
        auto abyn = std::move(PartyPtr(new Party{parties, 1}));
        abyn->Connect();
        return std::move(abyn);
      }));

      // Party #2
      futures.push_back(std::async(std::launch::async, []() {
        std::string ip = "127.0.0.1";
        std::uint16_t port = PORT_OFFSET + 1;
        auto abyn = std::move(PartyPtr(new Party{
            {std::make_shared<Communication::Context>(ip, port, ABYN::Role::Client, 0),
             std::make_shared<Communication::Context>(ip, PORT_OFFSET + 3, ABYN::Role::Client, 1),
             std::make_shared<Communication::Context>("127.0.0.1", PORT_OFFSET + 5,
                                                      ABYN::Role::Server, 3)},
            2}));
        abyn->Connect();
        return std::move(abyn);
      }));

      // Party #3
      futures.push_back(std::async(std::launch::async, []() {
        auto abyn =
            std::move(PartyPtr(new Party{{std::make_shared<Communication::Context>(
                                              "127.0.0.1", PORT_OFFSET + 2, ABYN::Role::Client, 0),
                                          std::make_shared<Communication::Context>(
                                              "127.0.0.1", PORT_OFFSET + 4, ABYN::Role::Client, 1),
                                          std::make_shared<Communication::Context>(
                                              "127.0.0.1", PORT_OFFSET + 5, ABYN::Role::Client, 2)},
                                         3}));
        abyn->Connect();
        return std::move(abyn);
      }));

      for (auto &f : futures) abyn_parties.push_back(f.get());

      all_connected = true;
      for (auto &abynparty : abyn_parties) {
        for (auto &party : abynparty->GetConfiguration()->GetParties()) {
          if (party.get()) {
            all_connected &= party->IsConnected();
          }
        }
      }

      for (auto i = 0u; i < abyn_parties.size(); ++i) {
        abyn_parties.at(i)->Run();
      }
    } catch (std::exception &e) {
      std::cerr << e.what() << std::endl;
      all_connected = false;
    }

    ASSERT_TRUE(all_connected);
  }
}

TEST(ABYNParty, NetworkConnection_LocalPartiesFromStaticFunction_3_4_5_10_parties) {
  for (auto i = 0u; i < TEST_ITERATIONS; ++i) {
    bool all_connected = false;
    for (auto num_parties : num_parties_list) {
      try {
        std::vector<PartyPtr> abyn_parties(
            std::move(Party::GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : abyn_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
        }
        all_connected = true;
        for (auto &abynparty : abyn_parties) {
          for (auto &party : abynparty->GetConfiguration()->GetParties()) {
            if (party.get()) {
              all_connected &= party->IsConnected();
            }
          }
        }
        for (auto i = 0u; i < abyn_parties.size(); ++i) {
          abyn_parties.at(i)->Run();
        }
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
        all_connected = false;
      }
    }
    ASSERT_TRUE(all_connected);
  }
}

TEST(ABYNArithmeticGMW_3_4_5_10_parties, InputOutput_SIMD_1_1K_10K) {
  const auto AGMW = ABYN::Protocol::ArithmeticGMW;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_var) {
    for (auto num_parties : num_parties_list) {
      std::size_t input_owner = std::rand() % num_parties, output_owner = std::rand() % num_parties;
      using T = decltype(template_var);
      T global_input_1 = Rand<T>();
      std::vector<T> global_input_1K = RandomVector<T>(1000),
                     global_input_10K = RandomVector<T>(10000);
      try {
        std::vector<PartyPtr> abyn_parties(
            std::move(Party::GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : abyn_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
          p->GetConfiguration()->SetOnlineAfterSetup(std::random_device{}() % 2 == 1);
        }
#pragma omp parallel num_threads(abyn_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(abyn_parties.size())
        for (auto party_id = 0u; party_id < abyn_parties.size(); ++party_id) {
          T input_1 = 0u;
          std::vector<T> input_1K(global_input_1K.size(), 0u);
          std::vector<T> input_10K(global_input_10K.size(), 0u);
          if (party_id == input_owner) {
            input_1 = global_input_1;
            input_1K = global_input_1K;
            input_10K = global_input_10K;
          }

          auto input_share_1 = abyn_parties.at(party_id)->IN<AGMW>(input_1, input_owner);
          auto input_share_1K = abyn_parties.at(party_id)->IN<AGMW>(input_1K, input_owner);
          auto input_share_10K = abyn_parties.at(party_id)->IN<AGMW>(input_10K, input_owner);

          auto output_share_1 = abyn_parties.at(party_id)->OUT(input_share_1, output_owner);
          auto output_share_1K = abyn_parties.at(party_id)->OUT(input_share_1K, output_owner);
          auto output_share_10K = abyn_parties.at(party_id)->OUT(input_share_10K, output_owner);

          abyn_parties.at(party_id)->Run();

          if (party_id == output_owner) {
            auto wire_1 = std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(
                output_share_1->GetWires().at(0));
            auto wire_1K = std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(
                output_share_1K->GetWires().at(0));
            auto wire_10K = std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(
                output_share_10K->GetWires().at(0));

            assert(wire_1);
            assert(wire_1K);
            assert(wire_10K);

            EXPECT_EQ(wire_1->GetValuesOnWire().at(0), global_input_1);
            EXPECT_TRUE(Helpers::Compare::Vectors(wire_1K->GetValuesOnWire(), global_input_1K));
            EXPECT_TRUE(Helpers::Compare::Vectors(wire_10K->GetValuesOnWire(), global_input_10K));
          }
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

TEST(ABYNArithmeticGMW_3_4_5_10_parties, Addition_SIMD_1_1K_10K) {
  const auto AGMW = ABYN::Protocol::ArithmeticGMW;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_var) {
    using T = decltype(template_var);
    const std::vector<T> _zero_v_1K(1000, 0), _zero_v_10K(10000, 0);
    for (auto num_parties : num_parties_list) {
      std::size_t output_owner = std::rand() % num_parties;
      std::vector<T> in_1 = RandomVector<T>(num_parties);
      std::vector<std::vector<T>> in_1K(num_parties), in_10K(num_parties);
      for (auto &v : in_1K) {
        v = RandomVector<T>(1000);
      }
      for (auto &v : in_10K) {
        v = RandomVector<T>(10000);
      }
      try {
        std::vector<PartyPtr> abyn_parties(
            std::move(Party::GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : abyn_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
          p->GetConfiguration()->SetOnlineAfterSetup(std::random_device{}() % 2 == 1);
        }
#pragma omp parallel num_threads(abyn_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(abyn_parties.size())
        for (auto party_id = 0u; party_id < abyn_parties.size(); ++party_id) {
          std::vector<ABYN::Shares::SharePtr> s_in_1, s_in_1K, s_in_10K;
          for (auto j = 0u; j < num_parties; ++j) {
            // If my input - real input, otherwise a dummy 0 (-vector).
            // Should not make any difference, just for consistency...
            const T my_in_1 = party_id == j ? in_1.at(j) : 0;
            const std::vector<T> &my_in_1K = party_id == j ? in_1K.at(j) : _zero_v_1K;
            const std::vector<T> &my_in_10K = party_id == j ? in_10K.at(j) : _zero_v_10K;

            s_in_1.push_back(abyn_parties.at(party_id)->IN<AGMW>(my_in_1, j));
            s_in_1K.push_back(abyn_parties.at(party_id)->IN<AGMW>(my_in_1K, j));
            s_in_10K.push_back(abyn_parties.at(party_id)->IN<AGMW>(my_in_10K, j));
          }

          auto s_add_1 = abyn_parties.at(party_id)->ADD(s_in_1.at(0), s_in_1.at(1));
          auto s_add_1K = abyn_parties.at(party_id)->ADD(s_in_1K.at(0), s_in_1K.at(1));
          auto s_add_10K = abyn_parties.at(party_id)->ADD(s_in_10K.at(0), s_in_10K.at(1));

          for (auto j = 2u; j < num_parties; ++j) {
            s_add_1 = abyn_parties.at(party_id)->ADD(s_add_1, s_in_1.at(j));
            s_add_1K = abyn_parties.at(party_id)->ADD(s_add_1K, s_in_1K.at(j));
            s_add_10K = abyn_parties.at(party_id)->ADD(s_add_10K, s_in_10K.at(j));
          }

          auto s_out_1 = abyn_parties.at(party_id)->OUT(s_add_1, output_owner);
          auto s_out_1K = abyn_parties.at(party_id)->OUT(s_add_1K, output_owner);
          auto s_out_10K = abyn_parties.at(party_id)->OUT(s_add_10K, output_owner);

          abyn_parties.at(party_id)->Run();

          if (party_id == output_owner) {
            auto wire_1 = std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(
                s_out_1->GetWires().at(0));
            auto wire_1K = std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(
                s_out_1K->GetWires().at(0));
            auto wire_10K = std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(
                s_out_10K->GetWires().at(0));

            T circuit_result_1 = wire_1->GetValuesOnWire().at(0);
            T expected_result_1 = Helpers::SumReduction(in_1);
            EXPECT_EQ(circuit_result_1, expected_result_1);

            const std::vector<T> &circuit_result_1K = wire_1K->GetValuesOnWire();
            const std::vector<T> expected_result_1K = std::move(Helpers::RowSumReduction(in_1K));
            for (auto i = 0u; i < circuit_result_1K.size(); ++i) {
              EXPECT_EQ(circuit_result_1K.at(i), expected_result_1K.at(i));
            }

            const std::vector<T> &circuit_result_10K = wire_10K->GetValuesOnWire();
            const std::vector<T> expected_result_10K = std::move(Helpers::RowSumReduction(in_10K));
            for (auto i = 0u; i < circuit_result_10K.size(); ++i) {
              EXPECT_EQ(circuit_result_10K.at(i), expected_result_10K.at(i));
            }
          }
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

TEST(ABYNBooleanGMW_3_4_5_10_parties, InputOutput_SIMD_1_1K_10K) {
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    const auto BGMW = ABYN::Protocol::BooleanGMW;
    std::srand(std::time(nullptr));
    for (auto num_parties : num_parties_list) {
      const std::size_t input_owner = std::rand() % num_parties,
                        output_owner = std::rand() % num_parties;
      const auto global_input_1 = (std::rand() % 2) == 1;
      const auto global_input_1K = ENCRYPTO::BitVector::Random(1000),
                 global_input_10K = ENCRYPTO::BitVector::Random(10000);
      try {
        std::vector<PartyPtr> abyn_parties(
            std::move(Party::GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : abyn_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
          p->GetConfiguration()->SetOnlineAfterSetup(i % 2 == 1);
        }
#pragma omp parallel num_threads(abyn_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(abyn_parties.size())
        for (auto party_id = 0u; party_id < abyn_parties.size(); ++party_id) {
          bool input_1 = false;
          ENCRYPTO::BitVector input_1K(global_input_1K.GetSize(), false);
          ENCRYPTO::BitVector input_10K(global_input_10K.GetSize(), false);
          if (party_id == input_owner) {
            input_1 = global_input_1;
            input_1K = global_input_1K;
            input_10K = global_input_10K;
          }

          auto input_share_1 = abyn_parties.at(party_id)->IN<BGMW>(input_1, input_owner);
          auto input_share_1K = abyn_parties.at(party_id)->IN<BGMW>(input_1K, input_owner);
          auto input_share_10K = abyn_parties.at(party_id)->IN<BGMW>(input_10K, input_owner);

          auto output_share_1 = abyn_parties.at(party_id)->OUT(input_share_1, output_owner);
          auto output_share_1K = abyn_parties.at(party_id)->OUT(input_share_1K, output_owner);
          auto output_share_10K = abyn_parties.at(party_id)->OUT(input_share_10K, output_owner);

          abyn_parties.at(party_id)->Run();

          if (party_id == output_owner) {
            auto wire_1 =
                std::dynamic_pointer_cast<ABYN::Wires::GMWWire>(output_share_1->GetWires().at(0));
            auto wire_1K =
                std::dynamic_pointer_cast<ABYN::Wires::GMWWire>(output_share_1K->GetWires().at(0));
            auto wire_10K =
                std::dynamic_pointer_cast<ABYN::Wires::GMWWire>(output_share_10K->GetWires().at(0));

            assert(wire_1);
            assert(wire_1K);
            assert(wire_10K);

            EXPECT_EQ(wire_1->GetValuesOnWire().Get(0), global_input_1);
            EXPECT_EQ(wire_1K->GetValuesOnWire(), global_input_1K);
            EXPECT_EQ(wire_10K->GetValuesOnWire(), global_input_10K);
          }
        }
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
      }
    }
  }
}

TEST(ABYNBooleanGMW_3_4_5_10_parties, XOR_1_bit_SIMD_1_1K_10K) {
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    const auto BGMW = ABYN::Protocol::BooleanGMW;
    std::srand(std::time(nullptr));
    for (auto num_parties : num_parties_list) {
      const std::size_t output_owner = std::rand() % num_parties;
      std::vector<bool> global_input_1(num_parties);
      for (auto j = 0ull; j < global_input_1.size(); ++j) {
        global_input_1.at(j) = (std::rand() % 2) == 1;
      }
      std::vector<ENCRYPTO::BitVector> global_input_1K(num_parties), global_input_10K(num_parties);

      for (auto j = 0ull; j < global_input_1K.size(); ++j) {
        global_input_1K.at(j) = ENCRYPTO::BitVector::Random(1000);
        global_input_10K.at(j) = ENCRYPTO::BitVector::Random(10000);
      }
      bool dummy_input_1 = false;
      ENCRYPTO::BitVector dummy_input_1K(1000, false);
      ENCRYPTO::BitVector dummy_input_10K(10000, false);
      try {
        std::vector<PartyPtr> abyn_parties(
            std::move(Party::GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : abyn_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
          p->GetConfiguration()->SetOnlineAfterSetup(i % 2 == 1);
        }
#pragma omp parallel num_threads(abyn_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(abyn_parties.size())
        for (auto party_id = 0u; party_id < abyn_parties.size(); ++party_id) {
          std::vector<Shares::SharePtr> input_share_1, input_share_1K, input_share_10K;

          for (auto j = 0ull; j < num_parties; ++j) {
            if (j == abyn_parties.at(party_id)->GetConfiguration()->GetMyId()) {
              input_share_1.push_back(
                  abyn_parties.at(party_id)->IN<BGMW>(static_cast<bool>(global_input_1.at(j)), j));
              input_share_1K.push_back(
                  abyn_parties.at(party_id)->IN<BGMW>(global_input_1K.at(j), j));
              input_share_10K.push_back(
                  abyn_parties.at(party_id)->IN<BGMW>(global_input_10K.at(j), j));
            } else {
              input_share_1.push_back(abyn_parties.at(party_id)->IN<BGMW>(dummy_input_1, j));
              input_share_1K.push_back(abyn_parties.at(party_id)->IN<BGMW>(dummy_input_1K, j));
              input_share_10K.push_back(abyn_parties.at(party_id)->IN<BGMW>(dummy_input_10K, j));
            }
          }

          auto xor_1 = abyn_parties.at(party_id)->XOR(input_share_1.at(0), input_share_1.at(1));
          auto xor_1K = abyn_parties.at(party_id)->XOR(input_share_1K.at(0), input_share_1K.at(1));
          auto xor_10K =
              abyn_parties.at(party_id)->XOR(input_share_10K.at(0), input_share_10K.at(1));

          for (auto j = 2ull; j < num_parties; ++j) {
            xor_1 = abyn_parties.at(party_id)->XOR(xor_1, input_share_1.at(j));
            xor_1K = abyn_parties.at(party_id)->XOR(xor_1K, input_share_1K.at(j));
            xor_10K = abyn_parties.at(party_id)->XOR(xor_10K, input_share_10K.at(j));
          }

          auto output_share_1 = abyn_parties.at(party_id)->OUT(xor_1, output_owner);
          auto output_share_1K = abyn_parties.at(party_id)->OUT(xor_1K, output_owner);
          auto output_share_10K = abyn_parties.at(party_id)->OUT(xor_10K, output_owner);

          abyn_parties.at(party_id)->Run();

          if (party_id == output_owner) {
            auto wire_1 =
                std::dynamic_pointer_cast<ABYN::Wires::GMWWire>(output_share_1->GetWires().at(0));
            auto wire_1K =
                std::dynamic_pointer_cast<ABYN::Wires::GMWWire>(output_share_1K->GetWires().at(0));
            auto wire_10K =
                std::dynamic_pointer_cast<ABYN::Wires::GMWWire>(output_share_10K->GetWires().at(0));

            assert(wire_1);
            assert(wire_1K);
            assert(wire_10K);

            EXPECT_EQ(wire_1->GetValuesOnWire().Get(0),
                      Helpers::XORReduceBitVector(global_input_1));
            EXPECT_EQ(wire_1K->GetValuesOnWire(), Helpers::XORBitVectors(global_input_1K));
            EXPECT_EQ(wire_10K->GetValuesOnWire(), Helpers::XORBitVectors(global_input_10K));
          }
        }
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
      }
    }
  }
}

TEST(ABYNBooleanGMW_3_4_5_10_parties, XOR_64_bit_SIMD_1K) {
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    const auto BGMW = ABYN::Protocol::BooleanGMW;
    std::srand(std::time(nullptr));
    for (auto num_parties : num_parties_list) {
      const std::size_t output_owner = std::rand() % num_parties;
      std::vector<std::vector<ENCRYPTO::BitVector>> global_input_1K_64_bit(num_parties);
      for (auto &bv_v : global_input_1K_64_bit) {
        bv_v.resize(64);
        for (auto &bv : bv_v) {
          bv = ENCRYPTO::BitVector::Random(1000);
        }
      }
      std::vector<ENCRYPTO::BitVector> dummy_input_1K_64_bit(64, ENCRYPTO::BitVector(1000, false));

      try {
        std::vector<PartyPtr> abyn_parties(
            std::move(Party::GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : abyn_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
          p->GetConfiguration()->SetOnlineAfterSetup(i % 2 == 1);
        }
#pragma omp parallel num_threads(abyn_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(abyn_parties.size())
        for (auto party_id = 0u; party_id < abyn_parties.size(); ++party_id) {
          std::vector<Shares::SharePtr> input_share_1K_64_bit;

          for (auto j = 0ull; j < num_parties; ++j) {
            if (j == abyn_parties.at(party_id)->GetConfiguration()->GetMyId()) {
              input_share_1K_64_bit.push_back(
                  abyn_parties.at(party_id)->IN<BGMW>(global_input_1K_64_bit.at(j), j));
            } else {
              input_share_1K_64_bit.push_back(
                  abyn_parties.at(party_id)->IN<BGMW>(dummy_input_1K_64_bit, j));
            }
          }

          auto xor_1K_64_bit = abyn_parties.at(party_id)->XOR(input_share_1K_64_bit.at(0),
                                                              input_share_1K_64_bit.at(1));

          for (auto j = 2ull; j < num_parties; ++j) {
            xor_1K_64_bit =
                abyn_parties.at(party_id)->XOR(xor_1K_64_bit, input_share_1K_64_bit.at(j));
          }

          auto output_share_1K_64_bit = abyn_parties.at(party_id)->OUT(xor_1K_64_bit, output_owner);

          abyn_parties.at(party_id)->Run();

          if (party_id == output_owner) {
            for (auto j = 0ull; j < global_input_1K_64_bit.size(); ++j) {
              auto wire_1K_64_bit_single = std::dynamic_pointer_cast<ABYN::Wires::GMWWire>(
                  output_share_1K_64_bit->GetWires().at(j));
              assert(wire_1K_64_bit_single);

              std::vector<ENCRYPTO::BitVector> global_input_1K_64_bit_single;
              for (auto k = 0ull; k < num_parties; ++k) {
                global_input_1K_64_bit_single.push_back(global_input_1K_64_bit.at(k).at(j));
              }

              EXPECT_EQ(wire_1K_64_bit_single->GetValuesOnWire(),
                        Helpers::XORBitVectors(global_input_1K_64_bit_single));
            }
          }
        }
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
      }
    }
  }
}
}  // namespace