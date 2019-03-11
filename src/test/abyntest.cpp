#ifndef TEST_CPP
#define TEST_CPP

#include <gtest/gtest.h>
#include <vector>
#include <algorithm>
#include <future>
#include <functional>
#include <fmt/format.h>
#include <omp.h>

#include "gate/gate.h"
#include "abynparty/abynparty.h"
#include "utility/typedefs.h"


namespace {

  using namespace ABYN;
  using namespace ABYN::Arithmetic;

  const auto TEST_ITERATIONS = 1; //increase if needed

  // A dummy first-try test
  // Test that arithmetic input gates work correctly
  // TODO: modify after implementing input gates properly
  TEST(ABYNPartyTest, NetworkConnection_OpenMP) {
    for (auto i = 0; i < TEST_ITERATIONS; ++i) {
      bool all_connected = false;
      //use std::threads, since omp (and pragmas in general) cannot be used in macros :(
      try {
        std::vector<ABYNPartyPtr> abyn_parties(0);
        std::vector<std::future<ABYNPartyPtr>> futures(0);

#pragma omp parallel num_threads(5) default(shared)
        {

#pragma omp single
          {
            //Party #0
#pragma omp task
            {
              std::vector<PartyPtr> parties;
              parties.emplace_back(std::make_shared<Party>("127.0.0.1", 7773, ABYN::Role::Server, 1));
              parties.emplace_back(std::make_shared<Party>("127.0.0.1", 7774, ABYN::Role::Server, 2));
              parties.emplace_back(std::make_shared<Party>("127.0.0.1", 7775, ABYN::Role::Server, 3));
              auto abyn = std::move(ABYNPartyPtr(new ABYNParty{parties, 0}));
              abyn->Connect();
#pragma omp critical
              {
                abyn_parties.push_back(std::move(abyn));
              }
            }

            //Party #1
#pragma omp task
            {
              std::string ip = "127.0.0.1";
              std::vector<PartyPtr> parties;
              parties.emplace_back(std::make_shared<Party>(ip, 7773, ABYN::Role::Client, 0));
              parties.emplace_back(std::make_shared<Party>("127.0.0.1", 7776, ABYN::Role::Server, 2));
              parties.emplace_back(std::make_shared<Party>("127.0.0.1", 7777, ABYN::Role::Server, 3));
              auto abyn = std::move(ABYNPartyPtr(new ABYNParty{parties, 1}));
              abyn->Connect();
#pragma omp critical
              {
                abyn_parties.push_back(std::move(abyn));
              }
            }

            //Party #2
#pragma omp task
            {
              std::string ip = "127.0.0.1";
              u16 port = 7774;
              auto abyn = std::move(ABYNPartyPtr(
                  new ABYNParty{{std::make_shared<Party>(ip, port, ABYN::Role::Client, 0),
                                 std::make_shared<Party>(ip, 7776, ABYN::Role::Client, 1),
                                 std::make_shared<Party>("127.0.0.1", 7778, ABYN::Role::Server, 3)},
                                2}));
              abyn->Connect();
#pragma omp critical
              {
                abyn_parties.push_back(std::move(abyn));
              }
            }

            //Party #3
#pragma omp task
            {
              auto abyn = std::move(ABYNPartyPtr(
                  new ABYNParty{
                      {std::make_shared<Party>("127.0.0.1", 7775, ABYN::Role::Client, 0),
                       std::make_shared<Party>("127.0.0.1", 7777, ABYN::Role::Client, 1),
                       std::make_shared<Party>("127.0.0.1", 7778, ABYN::Role::Client, 2)},
                      3}));
              abyn->Connect();
#pragma omp critical
              {
                abyn_parties.push_back(std::move(abyn));
              }
            }
          }
        }

        all_connected = true;
        for (auto &abynparty : abyn_parties) {
          for (auto &party: abynparty->GetConfiguration()->GetParties()) {
            if (party.get()) { all_connected &= party->IsConnected(); }
          }
        }

        for (auto i = 0u; i < abyn_parties.size(); ++i) {
          abyn_parties.at(i)->Run();
        }
      }
      catch (std::exception &e) {
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
        std::vector<ABYNPartyPtr> abyn_parties(0);
        std::vector<std::future<ABYNPartyPtr>> futures(0);

        //Party #0
        futures.push_back(std::async(std::launch::async,
                                     []() {
                                       std::vector<PartyPtr> parties;
                                       parties.emplace_back(
                                           std::make_shared<Party>("127.0.0.1", 7773, ABYN::Role::Server, 1));
                                       parties.emplace_back(
                                           std::make_shared<Party>("127.0.0.1", 7774, ABYN::Role::Server, 2));
                                       parties.emplace_back(
                                           std::make_shared<Party>("127.0.0.1", 7775, ABYN::Role::Server, 3));
                                       auto abyn = std::move(ABYNPartyPtr(new ABYNParty{parties, 0}));
                                       abyn->Connect();
                                       return std::move(abyn);
                                     }));

        //Party #1
        futures.push_back(std::async(std::launch::async,
                                     []() {
                                       std::string ip = "127.0.0.1";
                                       std::vector<PartyPtr> parties;
                                       parties.emplace_back(std::make_shared<Party>(ip, 7773, ABYN::Role::Client, 0));
                                       parties.emplace_back(
                                           std::make_shared<Party>("127.0.0.1", 7776, ABYN::Role::Server, 2));
                                       parties.emplace_back(
                                           std::make_shared<Party>("127.0.0.1", 7777, ABYN::Role::Server, 3));
                                       auto abyn = std::move(ABYNPartyPtr(new ABYNParty{parties, 1}));
                                       abyn->Connect();
                                       return std::move(abyn);
                                     }));

        //Party #2
        futures.push_back(std::async(std::launch::async,
                                     []() {
                                       std::string ip = "127.0.0.1";
                                       u16 port = 7774;
                                       auto abyn = std::move(ABYNPartyPtr(
                                           new ABYNParty{{std::make_shared<Party>(ip, port, ABYN::Role::Client, 0),
                                                          std::make_shared<Party>(ip, 7776, ABYN::Role::Client, 1),
                                                          std::make_shared<Party>("127.0.0.1", 7778, ABYN::Role::Server,
                                                                                  3)},
                                                         2}));
                                       abyn->Connect();
                                       return std::move(abyn);
                                     }));

        //Party #3
        futures.push_back(std::async(std::launch::async,
                                     []() {
                                       auto abyn = std::move(ABYNPartyPtr(
                                           new ABYNParty{
                                               {std::make_shared<Party>("127.0.0.1", 7775, ABYN::Role::Client, 0),
                                                std::make_shared<Party>("127.0.0.1", 7777, ABYN::Role::Client, 1),
                                                std::make_shared<Party>("127.0.0.1", 7778, ABYN::Role::Client, 2)},
                                               3}));
                                       abyn->Connect();
                                       return std::move(abyn);
                                     }));

        for (auto &f : futures)
          abyn_parties.push_back(f.get());

        all_connected = true;
        for (auto &abynparty : abyn_parties) {
          for (auto &party: abynparty->GetConfiguration()->GetParties()) {
            if (party.get()) { all_connected &= party->IsConnected(); }
          }
        }

        for (auto i = 0u; i < abyn_parties.size(); ++i) {
          abyn_parties.at(i)->Run();
        }
      }
      catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
        all_connected = false;
      }

      ASSERT_TRUE(all_connected);
    }
  }

  TEST(ABYNPartyTest, NetworkConnection_LocalPartiesFromStaticFunction_3_10) {
    for (auto i = 0u; i < TEST_ITERATIONS; ++i) {
      bool all_connected = false;
      for (auto num_parties = 3u; num_parties < 10u; ++num_parties) {
        try {
          std::vector<ABYNPartyPtr> abyn_parties(std::move(ABYNParty::GetNLocalConnectedParties(num_parties, 7777)));
          all_connected = true;
          for (auto &abynparty : abyn_parties) {
            for (auto &party: abynparty->GetConfiguration()->GetParties()) {
              if (party.get()) { all_connected &= party->IsConnected(); }
            }
          }
          for (auto i = 0u; i < abyn_parties.size(); ++i) {
            abyn_parties.at(i)->Run();
          }
        }
        catch (std::exception &e) {
          std::cerr << e.what() << std::endl;
          all_connected = false;
        }
      }
      ASSERT_TRUE(all_connected);
    }
  }


  TEST(ABYNSharingTest, ArithmeticInputOutput_SIMD1) {
    srand(time(NULL));
    auto template_test = [](auto template_var) {
      for (auto i = 0u; i < TEST_ITERATIONS; ++i) {
        bool success = true;
        for (auto num_parties = 3u; num_parties < 10u; ++num_parties) {
          decltype(template_var) input_owner = rand() % num_parties,
          output_owner = rand() % num_parties,
          global_input = rand();
          try {
            std::vector<ABYNPartyPtr> abyn_parties(std::move(ABYNParty::GetNLocalConnectedParties(num_parties, 7777)));
#pragma omp parallel num_threads(abyn_parties.size() + 1) default(shared)
            {
#pragma omp single
              {
#pragma omp taskloop num_tasks(abyn_parties.size())
                for (auto party_id = 0u; party_id < abyn_parties.size(); ++party_id) {
                  decltype(template_var) input = 0u;
                  if (party_id == input_owner) {
                    input = global_input;
                  }
                  auto input_share =
                      abyn_parties.at(party_id)->ShareArithmeticInput<decltype(template_var)>(input_owner, input);
                  auto output_gate =
                      std::make_shared<Gates::Arithmetic::ArithmeticOutputGate<decltype(template_var)>>(
                          input_share, output_owner);
                  auto output_share = std::dynamic_pointer_cast<ArithmeticShare<decltype(template_var)>>(
                      output_gate->GetOutputShare());

                  abyn_parties.at(party_id)->Run();

                  if (party_id == output_owner) {
                    auto wire = std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<decltype(template_var)>>(
                        output_share->GetWires().at(0));
                    success &= wire->GetValuesOnWire().at(0) == global_input;
                  }
                }
              }
            }
          }
          catch (std::exception &e) {
            std::cerr << e.what() << std::endl;
            success = false;
          }

        }
        ASSERT_TRUE(success);
      }
    };
    //lambdas don't support templates, but only auto types. So, lets try to trick it.
    template_test(static_cast<u8>(0));
    template_test(static_cast<u16>(0));
    template_test(static_cast<u32>(0));
    template_test(static_cast<u64>(0));
  }

  TEST(ABYNSharingTest, ArithmeticInputOutput_SIMD10to100) {
    srand(time(NULL));
    for (auto i = 0u; i < TEST_ITERATIONS; ++i) {
      bool success = true;
      for (auto num_parties = 3u; num_parties < 10u; ++num_parties) {
        size_t input_owner = rand() % num_parties, output_owner = rand() % num_parties, global_input = rand();
        try {
          std::vector<ABYNPartyPtr> abyn_parties(std::move(ABYNParty::GetNLocalConnectedParties(num_parties, 7777)));
#pragma omp parallel num_threads(abyn_parties.size() + 1) default(shared)
          {
#pragma omp single
            {
#pragma omp taskloop num_tasks(abyn_parties.size())
              for (auto party_id = 0u; party_id < abyn_parties.size(); ++party_id) {
                auto input = 0u;
                if (party_id == input_owner) {
                  input = global_input;
                }
                auto input_share = abyn_parties.at(party_id)->ShareArithmeticInput<u32>(input_owner, input);
                auto output_gate =
                    std::make_shared<Gates::Arithmetic::ArithmeticOutputGate<u32>>(input_share, output_owner);
                auto output_share = std::dynamic_pointer_cast<ArithmeticShare<u32>>(output_gate->GetOutputShare());

                abyn_parties.at(party_id)->Run();

                if (party_id == output_owner) {
                  auto wire = std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<u32>>(
                      output_share->GetWires().at(0));
                  success &= wire->GetValuesOnWire().at(0) == global_input;
                }
              }
            }
          }
        }
        catch (std::exception &e) {
          std::cerr << e.what() << std::endl;
          success = false;
        }

      }
      ASSERT_TRUE(success);
    }
  }


/*
    TEST(ArithmeticSharingTest, InputGateUnsigned16) {
        for (auto i = 0; i < TEST_ITERATIONS; ++i) {
            u16 value = rand();
            auto p = ArithmeticInputGate(value);
            p.Evaluate();
            auto s = p.GetOutputShare();
            auto sa = std::dynamic_pointer_cast<ArithmeticShare<decltype(value)>>(s);
            auto test_value = sa->GetValue();
            ASSERT_EQ(value, test_value);
        }
    }

    TEST(ArithmeticSharingTest, InputGateUnsigned32) {
        for (auto i = 0; i < TEST_ITERATIONS; ++i) {
            u32 value = rand();
            auto p = ArithmeticInputGate(value);
            p.Evaluate();
            auto s = p.GetOutputShare();
            auto sa = std::dynamic_pointer_cast<ArithmeticShare<decltype(value)>>(s);
            auto test_value = sa->GetValue();
            ASSERT_EQ(value, test_value);
        }
    }

    TEST(ArithmeticSharingTest, InputGateUnsigned64) {
        for (auto i = 0; i < TEST_ITERATIONS; ++i) {
            u64 value = rand();
            auto p = ArithmeticInputGate(value);
            p.Evaluate();
            auto s = p.GetOutputShare();
            auto sa = std::dynamic_pointer_cast<ArithmeticShare<decltype(value)>>(s);
            auto test_value = sa->GetValue();
            ASSERT_EQ(value, test_value);
        }
    }

    // Test that IPs and ports are set correctly after ABYNParty initialization
    TEST(ABYNPartyAllocation, CorrectnessOfIPsAndPorts) {
        const std::string d(".");

        for (auto i = 0; i < TEST_ITERATIONS; ++i) {
            const auto number_of_parties = 5;

            std::vector<u8> check_ports;
            std::vector<std::string> check_ips;

            auto r_u8 = []() {
                return std::to_string((u8) rand());
            };

            auto rand_valid_ip = [r_u8, d]() {
                return std::string(r_u8() + d + r_u8() + d + r_u8() + d + r_u8());
            };

            for (auto party_i = 0; party_i < number_of_parties; ++party_i) {
                check_ips.push_back(rand_valid_ip());
                check_ports.push_back(rand());
            }

            auto p3 = std::shared_ptr<ABYNParty>(
                    new ABYNParty{
                            Party(check_ips[0], check_ports[0], ABYN::Role::Client),
                            Party(check_ips[1], check_ports[1], ABYN::Role::Client),
                            Party(check_ips[2], check_ports[2], ABYN::Role::Client)});

            auto p4 = std::shared_ptr<ABYNParty>(
                    new ABYNParty{
                            Party(check_ips[0], check_ports[0], ABYN::Role::Client),
                            Party(check_ips[1], check_ports[1], ABYN::Role::Client),
                            Party(check_ips[2], check_ports[2], ABYN::Role::Client),
                            Party(check_ips[3], check_ports[3], ABYN::Role::Client)});

            auto p5 = std::shared_ptr<ABYNParty>(
                    new ABYNParty{
                            Party(check_ips[0], check_ports[0], ABYN::Role::Client),
                            Party(check_ips[1], check_ports[1], ABYN::Role::Client),
                            Party(check_ips[2], check_ports[2], ABYN::Role::Client),
                            Party(check_ips[3], check_ports[3], ABYN::Role::Client),
                            Party(check_ips[4], check_ports[4], ABYN::Role::Client)});

            std::vector<std::shared_ptr<ABYNParty >> p345{p3, p4, p5}, p45{p4, p5};

            for (auto j = 0; j < number_of_parties; ++j) {
                if (j < 3) {
                    for (auto &p : p345) {
                        //string.compare(s1, s2) = 0 if s1 equals s2
                        ASSERT_EQ(p->GetConfiguration()->GetParty(j).GetIp().compare(check_ips[j]), 0);
                        ASSERT_EQ(p->GetConfiguration()->GetParty(j).GetPort(), check_ports[j]);
                    }
                } else if (j < 4) {
                    for (auto &p : p45) {
                        ASSERT_EQ(p->GetConfiguration()->GetParty(j).GetIp().compare(check_ips[j]), 0);
                        ASSERT_EQ(p->GetConfiguration()->GetParty(j).GetPort(), check_ports[j]);
                    }
                } else {
                    ASSERT_EQ(p5->GetConfiguration()->GetParty(j).GetIp().compare(check_ips[j]), 0);
                    ASSERT_EQ(p5->GetConfiguration()->GetParty(j).GetPort(), check_ports[j]);
                }

            }
        }
    }
*/

// Check that ABYNParty throws an exception when using an incorrect IP address
  TEST(ABYNPartyAllocation, IncorrectIPMustThrow) {
    srand(time(NULL));
    const std::string_view incorrect_symbols("*-+;:,/?'[]_=abcdefghijklmnopqrstuvwxyz");

    for (auto i = 0; i < TEST_ITERATIONS; ++i) {
      auto r_u8 = []() { return std::to_string((u8) rand()); };
      auto rand_invalid_ip = [r_u8, incorrect_symbols]() {
        std::string result = fmt::format("{}.{}.{}.{}", r_u8(), r_u8(), r_u8(), r_u8());
        result.at(rand() % result.size()) = incorrect_symbols.at(rand() % incorrect_symbols.size());
        return result;
      };
      auto must_throw_function = [rand_invalid_ip]() { Party(rand_invalid_ip(), rand(), ABYN::Role::Client, 0); };
      ASSERT_ANY_THROW(must_throw_function());
    }
  }
}

#endif