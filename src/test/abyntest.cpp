#ifndef TEST_CPP
#define TEST_CPP

#include "gate/gate.h"
#include "abynparty/abynparty.h"

#include <gtest/gtest.h>

namespace {

    using namespace ABYN;
    using namespace ABYN::Arithmetic;

    TEST(ArithmeticSharingTest, InputGateUnsigned8) {
        for (auto i = 0; i < 100; ++i) {
            u8 value = rand();
            auto p = ArithmeticInputGate(value);
            p.Evaluate();
            auto s = p.GetOutputShare();
            auto sa = std::dynamic_pointer_cast<ArithmeticShare<decltype(value)>>(s);
            auto test_value = sa->GetValue();
            ASSERT_EQ(value, test_value);
        }
    }

    TEST(ArithmeticSharingTest, InputGateUnsigned16) {
        for (auto i = 0; i < 100; ++i) {
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
        for (auto i = 0; i < 100; ++i) {
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
        for (auto i = 0; i < 100; ++i) {
            u64 value = rand();
            auto p = ArithmeticInputGate(value);
            p.Evaluate();
            auto s = p.GetOutputShare();
            auto sa = std::dynamic_pointer_cast<ArithmeticShare<decltype(value)>>(s);
            auto test_value = sa->GetValue();
            ASSERT_EQ(value, test_value);
        }
    }

    TEST(ABYNPartyAllocation, CorrectnessOfIPsAndPorts) {
        const std::string d(".");

        for (auto i = 0; i < 10; ++i) {
            const auto number_of_parties = 5;

            std::vector < u8 > check_ports;
            std::vector < std::string > check_ips;

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

            auto p3 = std::shared_ptr < ABYNParty > (
                    new ABYNParty{
                            Party(check_ips[0], check_ports[0]),
                            Party(check_ips[1], check_ports[1]),
                            Party(check_ips[2], check_ports[2])});

            auto p4 = std::shared_ptr < ABYNParty > (
                    new ABYNParty{
                            Party(check_ips[0], check_ports[0]),
                            Party(check_ips[1], check_ports[1]),
                            Party(check_ips[2], check_ports[2]),
                            Party(check_ips[3], check_ports[3])});

            auto p5 = std::shared_ptr < ABYNParty > (
                    new ABYNParty{
                            Party(check_ips[0], check_ports[0]),
                            Party(check_ips[1], check_ports[1]),
                            Party(check_ips[2], check_ports[2]),
                            Party(check_ips[3], check_ports[3]),
                            Party(check_ips[4], check_ports[4])});

            std::vector < std::shared_ptr < ABYNParty >> p345{p3, p4, p5}, p45{p4, p5};

            for (auto j = 0; j < number_of_parties; ++j) {
                if (j < 3) {
                    for (auto &p : p345) {
                        //string.compare(s1, s2) = 0 if s1 equals s2
                        ASSERT_EQ(p->getConfiguration()->GetParties()[j].GetIp().compare(check_ips[j]), 0);
                        ASSERT_EQ(p->getConfiguration()->GetParties()[j].GetPort(), check_ports[j]);
                    }
                } else if (j < 4) {
                    for (auto &p : p45) {
                        ASSERT_EQ(p->getConfiguration()->GetParties()[j].GetIp().compare(check_ips[j]), 0);
                        ASSERT_EQ(p->getConfiguration()->GetParties()[j].GetPort(), check_ports[j]);
                    }
                } else {
                    ASSERT_EQ(p5->getConfiguration()->GetParties()[j].GetIp().compare(check_ips[j]), 0);
                    ASSERT_EQ(p5->getConfiguration()->GetParties()[j].GetPort(), check_ports[j]);
                }

            }
        }
    }

    TEST(ABYNPartyAllocation, IncorrectIPMustThrow) {
        const std::string_view incorrect_symbols("*-+;:,/?'[]_=abcdefghijklmnopqrstuvwxyz");
        const std::string d(".");

        for (auto i = 0; i < 10; ++i) {
            auto r_u8 = []() {
                return std::to_string((u8) rand());
            };

            auto rand_invalid_ip = [r_u8, incorrect_symbols, d]() {
                std::string result(r_u8() + d + r_u8() + d + r_u8() + d + r_u8());
                result.at(rand() % result.size()) = incorrect_symbols.at(rand() % incorrect_symbols.size());
                return result;
            };

            auto must_throw_function = [r_u8, rand_invalid_ip]() { Party(rand_invalid_ip(), rand()); };
            ASSERT_ANY_THROW(must_throw_function());
        }
    }


    int main(int argc, char **argv) {
        testing::InitGoogleTest(&argc, argv);
        return RUN_ALL_TESTS();
    }
}

#endif