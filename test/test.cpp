#ifndef TEST_CPP
#define TEST_CPP

#include "gate.h"
#include "share.h"
#include <gtest/gtest.h>

#include <iostream>
#include <memory>


using namespace ABYN::Gates::Interfaces;
using namespace ABYN::Gates::Arithmetic;
using namespace ABYN::Shares;

namespace {

    TEST(ArithmeticSharingTest, unsigned8) {
        for (auto i = 0; i < 1000; ++i) {
            u8 value = rand();
            auto p = ArithmeticInputGate(value);
            p.Evaluate();
            auto s = p.GetOutputShare();
            auto sa = std::dynamic_pointer_cast<ArithmeticShare<decltype(value)>>(s);
            auto test_value = sa->GetValue();
            ASSERT_EQ(value, test_value);
        }
    }

    TEST(ArithmeticSharingTest, unsigned16) {
        for (auto i = 0; i < 1000; ++i) {
            u16 value = rand();
            auto p = ArithmeticInputGate(value);
            p.Evaluate();
            auto s = p.GetOutputShare();
            auto sa = std::dynamic_pointer_cast<ArithmeticShare<decltype(value)>>(s);
            auto test_value = sa->GetValue();
            ASSERT_EQ(value, test_value);
        }
    }

    TEST(ArithmeticSharingTest, unsigned32) {
        for (auto i = 0; i < 1000; ++i) {
            u32 value = rand();
            auto p = ArithmeticInputGate(value);
            p.Evaluate();
            auto s = p.GetOutputShare();
            auto sa = std::dynamic_pointer_cast<ArithmeticShare<decltype(value)>>(s);
            auto test_value = sa->GetValue();
            ASSERT_EQ(value, test_value);
        }
    }

    TEST(ArithmeticSharingTest, unsigned64) {
        for (auto i = 0; i < 1000; ++i) {
            u64 value = rand();
            auto p = ArithmeticInputGate(value);
            p.Evaluate();
            auto s = p.GetOutputShare();
            auto sa = std::dynamic_pointer_cast<ArithmeticShare<decltype(value)>>(s);
            auto test_value = sa->GetValue();
            ASSERT_EQ(value, test_value);
        }
    }

    int main(int argc, char **argv) {
        testing::InitGoogleTest(&argc, argv);
        return RUN_ALL_TESTS();
    }
}

#endif