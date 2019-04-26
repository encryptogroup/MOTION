#ifndef TEST_CPP
#define TEST_CPP

#include <gtest/gtest.h>
#include <algorithm>
#include <functional>
#include <future>
#include <vector>

#include <fmt/format.h>
#include <omp.h>

#include "abynparty/party.h"
#include "gate/gate.h"
#include "utility/typedefs.h"

namespace {

const auto num_parties_list = {3u, 4u, 5u, 10u};

using namespace ABYN;

const auto PORT_OFFSET = 7777u;
const auto TEST_ITERATIONS = 3;  // increase if needed
const auto LOGGING_ENABLED = false;

template <typename T>
inline T Rand() {
  if (typeid(T) == typeid(u64)) {
    u64 r = std::rand();
    r <<= 32;
    return r + std::rand();
  } else
    return std::rand();
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

  for (auto i = 0; i < TEST_ITERATIONS; ++i) {
    auto r_u8 = []() { return std::to_string((u8)std::rand()); };
    auto rand_invalid_ip = [r_u8, incorrect_symbols]() {
      std::string result = fmt::format("{}.{}.{}.{}", r_u8(), r_u8(), r_u8(), r_u8());
      result.at(std::rand() % result.size()) =
          incorrect_symbols.at(std::rand() % incorrect_symbols.size());
      return result;
    };
    auto must_throw_function = [rand_invalid_ip]() {
      CommunicationContext(rand_invalid_ip(), std::rand(), ABYN::Role::Client, 0);
    };
    ASSERT_ANY_THROW(must_throw_function());
  }
}

TEST(ABYNPartyTest, NetworkConnection_OpenMP) {
  for (auto i = 0; i < TEST_ITERATIONS; ++i) {
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
            std::vector<CommunicationContextPtr> parties;
            parties.emplace_back(std::make_shared<CommunicationContext>("127.0.0.1", PORT_OFFSET,
                                                                        ABYN::Role::Server, 1));
            parties.emplace_back(std::make_shared<CommunicationContext>(
                "127.0.0.1", PORT_OFFSET + 1, ABYN::Role::Server, 2));
            parties.emplace_back(std::make_shared<CommunicationContext>(
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
            std::vector<CommunicationContextPtr> parties;
            parties.emplace_back(
                std::make_shared<CommunicationContext>(ip, PORT_OFFSET, ABYN::Role::Client, 0));
            parties.emplace_back(std::make_shared<CommunicationContext>(
                "127.0.0.1", PORT_OFFSET + 3, ABYN::Role::Server, 2));
            parties.emplace_back(std::make_shared<CommunicationContext>(
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
            u16 port = PORT_OFFSET + 1;
            auto abyn = std::move(PartyPtr(new Party{
                {std::make_shared<CommunicationContext>(ip, port, ABYN::Role::Client, 0),
                 std::make_shared<CommunicationContext>(ip, PORT_OFFSET + 3, ABYN::Role::Client, 1),
                 std::make_shared<CommunicationContext>("127.0.0.1", PORT_OFFSET + 5,
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
                PartyPtr(new Party{{std::make_shared<CommunicationContext>(
                                        "127.0.0.1", PORT_OFFSET + 2, ABYN::Role::Client, 0),
                                    std::make_shared<CommunicationContext>(
                                        "127.0.0.1", PORT_OFFSET + 4, ABYN::Role::Client, 1),
                                    std::make_shared<CommunicationContext>(
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

TEST(ABYNPartyTest, NetworkConnection_ManualThreads) {
  for (auto i = 0; i < TEST_ITERATIONS; ++i) {
    bool all_connected = false;
    try {
      std::vector<PartyPtr> abyn_parties(0);
      std::vector<std::future<PartyPtr>> futures(0);

      // Party #0
      futures.push_back(std::async(std::launch::async, []() {
        std::vector<CommunicationContextPtr> parties;
        parties.emplace_back(std::make_shared<CommunicationContext>("127.0.0.1", PORT_OFFSET,
                                                                    ABYN::Role::Server, 1));
        parties.emplace_back(std::make_shared<CommunicationContext>("127.0.0.1", PORT_OFFSET + 1,
                                                                    ABYN::Role::Server, 2));
        parties.emplace_back(std::make_shared<CommunicationContext>("127.0.0.1", PORT_OFFSET + 2,
                                                                    ABYN::Role::Server, 3));
        auto abyn = std::move(PartyPtr(new Party{parties, 0}));
        abyn->Connect();
        return std::move(abyn);
      }));

      // Party #1
      futures.push_back(std::async(std::launch::async, []() {
        std::string ip = "127.0.0.1";
        std::vector<CommunicationContextPtr> parties;
        parties.emplace_back(
            std::make_shared<CommunicationContext>(ip, PORT_OFFSET, ABYN::Role::Client, 0));
        parties.emplace_back(std::make_shared<CommunicationContext>("127.0.0.1", PORT_OFFSET + 3,
                                                                    ABYN::Role::Server, 2));
        parties.emplace_back(std::make_shared<CommunicationContext>("127.0.0.1", PORT_OFFSET + 4,
                                                                    ABYN::Role::Server, 3));
        auto abyn = std::move(PartyPtr(new Party{parties, 1}));
        abyn->Connect();
        return std::move(abyn);
      }));

      // Party #2
      futures.push_back(std::async(std::launch::async, []() {
        std::string ip = "127.0.0.1";
        u16 port = PORT_OFFSET + 1;
        auto abyn = std::move(PartyPtr(new Party{
            {std::make_shared<CommunicationContext>(ip, port, ABYN::Role::Client, 0),
             std::make_shared<CommunicationContext>(ip, PORT_OFFSET + 3, ABYN::Role::Client, 1),
             std::make_shared<CommunicationContext>("127.0.0.1", PORT_OFFSET + 5,
                                                    ABYN::Role::Server, 3)},
            2}));
        abyn->Connect();
        return std::move(abyn);
      }));

      // Party #3
      futures.push_back(std::async(std::launch::async, []() {
        auto abyn =
            std::move(PartyPtr(new Party{{std::make_shared<CommunicationContext>(
                                              "127.0.0.1", PORT_OFFSET + 2, ABYN::Role::Client, 0),
                                          std::make_shared<CommunicationContext>(
                                              "127.0.0.1", PORT_OFFSET + 4, ABYN::Role::Client, 1),
                                          std::make_shared<CommunicationContext>(
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

TEST(ABYNPartyTest, NetworkConnection_LocalPartiesFromStaticFunction_3_4_5_10_parties) {
  for (auto i = 0u; i < TEST_ITERATIONS; ++i) {
    bool all_connected = false;
    for (auto num_parties : num_parties_list) {
      try {
        std::vector<PartyPtr> abyn_parties(
            std::move(Party::GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : abyn_parties) {
          p->GetLogger()->Logging(LOGGING_ENABLED);
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

TEST(ABYNArithmeticTest, InputOutput_SIMD_1_1K_10K) {
  const auto AGMW = ABYN::Protocol::ArithmeticGMW;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_var) {
      for (auto num_parties : num_parties_list) {
        std::size_t input_owner = std::rand() % num_parties,
                    output_owner = std::rand() % num_parties;
        using T = decltype(template_var);
        T global_input_1 = Rand<T>();
        std::vector<T> global_input_1K = RandomVector<T>(1000),
                       global_input_10K = RandomVector<T>(10000);
        try {
          std::vector<PartyPtr> abyn_parties(
              std::move(Party::GetNLocalParties(num_parties, PORT_OFFSET)));
          for (auto &p : abyn_parties) {
            p->GetLogger()->Logging(LOGGING_ENABLED);
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

            auto input_share_1 = abyn_parties.at(party_id)->IN<AGMW, T>(input_owner, input_1);
            auto input_share_1K = abyn_parties.at(party_id)->IN<AGMW, T>(input_owner, input_1K);
            auto input_share_10K = abyn_parties.at(party_id)->IN<AGMW, T>(input_owner, input_10K);

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
  for (auto i = 0; i < TEST_ITERATIONS; ++i) {
    // lambdas don't support templates, but only auto types. So, lets try to trick them.
    template_test(static_cast<u8>(0));
    template_test(static_cast<u16>(0));
    template_test(static_cast<u32>(0));
    template_test(static_cast<u64>(0));
  }
}

TEST(ABYNArithmeticTest, Addition_SIMD_1_1K_10K) {
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
          p->GetLogger()->Logging(LOGGING_ENABLED);
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

            s_in_1.push_back(abyn_parties.at(party_id)->IN<AGMW, T>(j, my_in_1));
            s_in_1K.push_back(abyn_parties.at(party_id)->IN<AGMW, T>(j, my_in_1K));
            s_in_10K.push_back(abyn_parties.at(party_id)->IN<AGMW, T>(j, my_in_10K));
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
  for (auto i = 0; i < TEST_ITERATIONS; ++i) {
    // lambdas don't support templates, but only auto types. So, lets try to trick them.
    template_test(static_cast<u8>(0));
    template_test(static_cast<u16>(0));
    template_test(static_cast<u32>(0));
    template_test(static_cast<u64>(0));
  }
}
}  // namespace

[[maybe_unused]] int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

#endif