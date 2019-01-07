#ifndef TEST_CPP
#define TEST_CPP

#include <gtest/gtest.h>
#include <vector>
#include <algorithm>
#include <future>
#include <functional>
#include <fmt/format.h>

#include "gate/gate.h"
#include "abynparty/abynparty.h"


namespace {

    using namespace ABYN;
    using namespace ABYN::Arithmetic;

    const auto TEST_ITERATIONS = 10;

    // A dummy first-try test
    // Test that arithmetic input gates work correctly
    // TODO: modify after implementing input gates properly
    TEST(ABYNPartyTest, NetworkConnection) {
        for (auto i = 0; i < 2; ++i) {
            bool all_connected = false;
            try {
                std::vector<ABYNPartyPtr> abyn_parties(0);
                std::vector<std::future<ABYNPartyPtr>> futures(0);


                futures.push_back(std::async(std::launch::async,
                                             []() {
                                                 std::vector<Party> parties;
                                                 parties.emplace_back("127.0.0.1", 7773, ABYN::Role::Server, 1);
                                                 parties.emplace_back("127.0.0.1", 7774, ABYN::Role::Server, 2);
                                                 parties.emplace_back("127.0.0.1", 7775, ABYN::Role::Server, 3);
                                                 return ABYNPartyPtr(new ABYNParty{parties, 0});
                                             }));

                futures.push_back(std::async(std::launch::async,
                                             []() {
                                                 std::vector<Party> parties;
                                                 parties.emplace_back("127.0.0.1", 7773, ABYN::Role::Client, 0);
                                                 parties.emplace_back("127.0.0.1", 7776, ABYN::Role::Server, 2);
                                                 parties.emplace_back("127.0.0.1", 7777, ABYN::Role::Server, 3);
                                                 return ABYNPartyPtr(new ABYNParty{parties, 1});
                                             }));

                futures.push_back(std::async(std::launch::async,
                                             []() {
                                                 std::vector<Party> parties;
                                                 parties.emplace_back("127.0.0.1", 7774, ABYN::Role::Client, 0);
                                                 parties.emplace_back("127.0.0.1", 7776, ABYN::Role::Client, 1);
                                                 parties.emplace_back("127.0.0.1", 7778, ABYN::Role::Server, 3);
                                                 return ABYNPartyPtr(new ABYNParty{parties, 2});
                                             }));

                futures.push_back(std::async(std::launch::async,
                                             []() {
                                                 std::vector<Party> parties;
                                                 parties.emplace_back("127.0.0.1", 7775, ABYN::Role::Client, 0);
                                                 parties.emplace_back("127.0.0.1", 7777, ABYN::Role::Client, 1);
                                                 parties.emplace_back("127.0.0.1", 7778, ABYN::Role::Client, 2);
                                                 return ABYNPartyPtr(new ABYNParty{parties, 3});
                                             }));

                for (auto &f : futures)
                    abyn_parties.push_back(f.get());

                all_connected = abyn_parties.at(0)->GetConfiguration()->GetParty(0).IsConnected();
                for (auto &abynparty : abyn_parties) {
                    for (auto &party: abynparty->GetConfiguration()->GetParties()) {
                        all_connected &= party.IsConnected();
                    }
                }
            }
            catch (std::exception &e) {
                std::cerr << e.what() << std::endl;
                all_connected = false;
            }

            ASSERT_TRUE(all_connected);
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