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

#include <fstream>
#include <random>

#include <gtest/gtest.h>

#include "algorithm/algorithm_description.h"
#include "base/party.h"
#include "secure_type/secure_unsigned_integer.h"
#include "share/share_wrapper.h"
#include "utility/config.h"
#include "wire/bmr_wire.h"
#include "wire/boolean_gmw_wire.h"

#include "test_constants.h"

namespace {
TEST(AlgorithmDescription, FromBristolFormat__int_add8_size) {
  const auto int_add8 = ENCRYPTO::AlgorithmDescription::FromBristol(
      std::string(MOTION::MOTION_ROOT_DIR) + "/circuits/int/int_add8_size.bristol");
  EXPECT_EQ(int_add8.n_gates_, 34);
  EXPECT_EQ(int_add8.gates_.size(), 34);
  EXPECT_EQ(int_add8.n_output_wires_, 8);
  EXPECT_EQ(int_add8.n_input_wires_parent_a_, 8);
  ASSERT_NO_THROW([&int_add8]() { EXPECT_EQ(*int_add8.n_input_wires_parent_b_, 8); });
  EXPECT_EQ(int_add8.n_wires_, 50);

  const auto &gate0 = int_add8.gates_.at(0);
  EXPECT_EQ(gate0.parent_a_, 0);
  ASSERT_NO_THROW([&gate0]() { EXPECT_EQ(*gate0.parent_b_, 8); });
  EXPECT_EQ(gate0.output_wire_, 42);
  EXPECT_EQ(gate0.type_, ENCRYPTO::PrimitiveOperationType::XOR);
  EXPECT_EQ(gate0.selection_bit_.has_value(), false);

  const auto &gate1 = int_add8.gates_.at(1);
  EXPECT_EQ(gate1.parent_a_, 0);
  ASSERT_NO_THROW([&gate1]() { EXPECT_EQ(*gate1.parent_b_, 8); });
  EXPECT_EQ(gate1.output_wire_, 16);
  EXPECT_EQ(gate1.type_, ENCRYPTO::PrimitiveOperationType::AND);
  EXPECT_EQ(gate1.selection_bit_.has_value(), false);

  const auto &gate32 = int_add8.gates_.at(32);
  EXPECT_EQ(gate32.parent_a_, 15);
  ASSERT_NO_THROW([&gate32]() { EXPECT_EQ(*gate32.parent_b_, 40); });
  EXPECT_EQ(gate32.output_wire_, 41);
  EXPECT_EQ(gate32.type_, ENCRYPTO::PrimitiveOperationType::XOR);
  EXPECT_EQ(gate32.selection_bit_.has_value(), false);

  const auto &gate33 = int_add8.gates_.at(33);
  EXPECT_EQ(gate33.parent_a_, 7);
  ASSERT_NO_THROW([&gate33]() { EXPECT_EQ(*gate33.parent_b_, 41); });
  EXPECT_EQ(gate33.output_wire_, 49);
  EXPECT_EQ(gate33.type_, ENCRYPTO::PrimitiveOperationType::XOR);
  EXPECT_EQ(gate33.selection_bit_.has_value(), false);
}

// TODO: rewrite as generic tests
template <typename T>
class SecureUintTest : public ::testing::Test {
  void TestSingle() {
    using namespace MOTION;
    constexpr auto GMW = MOTION::MPCProtocol::BooleanGMW;
    std::mt19937 g(0);
    std::uniform_int_distribution<T> dist(0, std::numeric_limits<T>::max());
    auto r = std::bind(dist, g);
    const std::vector<T> raw_global_input = {r(), r()};
    constexpr auto n_wires{sizeof(T) * 8};
    constexpr std::size_t n_simd{1};
    std::vector<std::vector<ENCRYPTO::BitVector<>>> global_input{
        ENCRYPTO::ToInput(raw_global_input.at(0)), ENCRYPTO::ToInput(raw_global_input.at(1))};
    std::vector<ENCRYPTO::BitVector<>> dummy_input(n_wires, ENCRYPTO::BitVector<>(n_simd, false));

    std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(2, PORT_OFFSET)));
    for (auto &p : motion_parties) {
      p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
      p->GetConfiguration()->SetOnlineAfterSetup(true);
    }
    std::vector<std::thread> t;
    for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
      t.emplace_back(
          [party_id, &motion_parties, n_wires, &global_input, &dummy_input, &raw_global_input]() {
            const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
            MOTION::SecureUnsignedInteger s_0 = party_0 ? motion_parties.at(party_id)->IN<GMW>(
                                                              global_input.at(0), 0)
                                                        : motion_parties.at(party_id)->IN<GMW>(
                                                              dummy_input, 0),
                                          s_1 = party_0 ? motion_parties.at(party_id)->IN<GMW>(
                                                              dummy_input, 1)
                                                        : motion_parties.at(party_id)->IN<GMW>(
                                                              global_input.at(1), 1);
            EXPECT_EQ(s_0.Get()->GetBitLength(), n_wires);

            const auto s_result = Add(s_0, s_1);
            auto s_out = s_result.Out();

            motion_parties.at(party_id)->Run();

            const T sum_check = raw_global_input.at(0) + raw_global_input.at(1);
            std::vector<ENCRYPTO::BitVector<>> out;
            for (auto i = 0ull; i < n_wires; ++i) {
              auto wire_single =
                  std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out->GetWires().at(i));
              assert(wire_single);
              out.emplace_back(wire_single->GetValues());
            }
            T sum = ENCRYPTO::ToOutput<T>(out);
            EXPECT_EQ(sum, sum_check);
            motion_parties.at(party_id)->Finish();
          });
    }
    for (auto &tt : t)
      if (tt.joinable()) tt.join();
  };

  void TestSIMD() {
    using namespace MOTION;
    constexpr auto GMW = MOTION::MPCProtocol::BooleanGMW;
    std::mt19937 g(0);
    std::uniform_int_distribution<T> dist(0, std::numeric_limits<T>::max());
    auto r = std::bind(dist, g);
    const std::vector<T> raw_global_input = {r(), r()};
    constexpr auto n_wires{sizeof(T) * 8};
    constexpr std::size_t n_simd{1};
    std::vector<std::vector<ENCRYPTO::BitVector<>>> global_input{
        ENCRYPTO::ToInput(raw_global_input.at(0)), ENCRYPTO::ToInput(raw_global_input.at(1))};
    std::vector<ENCRYPTO::BitVector<>> dummy_input(n_wires, ENCRYPTO::BitVector<>(n_simd, false));

    std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(2, PORT_OFFSET)));
    for (auto &p : motion_parties) {
      p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
      p->GetConfiguration()->SetOnlineAfterSetup(true);
    }
    std::vector<std::thread> t;
    for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
      t.emplace_back(
          [party_id, &motion_parties, n_wires, &global_input, &dummy_input, &raw_global_input]() {
            const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
            MOTION::SecureUnsignedInteger s_0 = party_0 ? motion_parties.at(party_id)->IN<GMW>(
                                                              global_input.at(0), 0)
                                                        : motion_parties.at(party_id)->IN<GMW>(
                                                              dummy_input, 0),
                                          s_1 = party_0 ? motion_parties.at(party_id)->IN<GMW>(
                                                              dummy_input, 1)
                                                        : motion_parties.at(party_id)->IN<GMW>(
                                                              global_input.at(1), 1);
            EXPECT_EQ(s_0.Get()->GetBitLength(), n_wires);

            const auto s_result = Add(s_0, s_1);
            auto s_out = s_result.Out();

            motion_parties.at(party_id)->Run();

            const T sum_check = raw_global_input.at(0) + raw_global_input.at(1);
            std::vector<ENCRYPTO::BitVector<>> out;
            for (auto i = 0ull; i < n_wires; ++i) {
              auto wire_single =
                  std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out->GetWires().at(i));
              assert(wire_single);
              out.emplace_back(wire_single->GetValues());
            }
            T sum = ENCRYPTO::ToOutput<T>(out);
            EXPECT_EQ(sum, sum_check);
            motion_parties.at(party_id)->Finish();
          });
    }
    for (auto &tt : t)
      if (tt.joinable()) tt.join();
  };

  static MOTION::Shares::ShareWrapper Add(const MOTION::SecureUnsignedInteger &a,
                                          const MOTION::SecureUnsignedInteger &b) {
    return (a + b).Get();
  }

  static MOTION::Shares::ShareWrapper Sub(const MOTION::SecureUnsignedInteger &a,
                                          const MOTION::SecureUnsignedInteger &b) {
    return (a - b).Get();
  }

  static MOTION::Shares::ShareWrapper Mul(const MOTION::SecureUnsignedInteger &a,
                                          const MOTION::SecureUnsignedInteger &b) {
    return (a * b).Get();
  }

  static MOTION::Shares::ShareWrapper Div(const MOTION::SecureUnsignedInteger &a,
                                          const MOTION::SecureUnsignedInteger &b) {
    return (a / b).Get();
  }

  static MOTION::Shares::ShareWrapper Gt(const MOTION::SecureUnsignedInteger &a,
                                         const MOTION::SecureUnsignedInteger &b) {
    return a > b;
  }

  static MOTION::Shares::ShareWrapper Eq(const MOTION::SecureUnsignedInteger &a,
                                         const MOTION::SecureUnsignedInteger &b) {
    return a == b;
  }
};

using all_uints = ::testing::Types<std::uint8_t, std::uint16_t, std::uint32_t, std::uint64_t>;
TYPED_TEST_SUITE(SecureUintTest, all_uints);

TYPED_TEST(SecureUintTest, AdditionInBMR) {
  using T = TypeParam;
  using namespace MOTION;
  constexpr auto BMR = MOTION::MPCProtocol::BMR;
  std::mt19937 g(0);
  std::uniform_int_distribution<T> dist(0, std::numeric_limits<T>::max());
  auto r = std::bind(dist, g);
  const std::vector<T> raw_global_input = {r(), r()};
  const std::vector<std::vector<T>> raw_global_input_simd(2, std::vector<T>{r(), r(), r()});
  constexpr auto n_wires{sizeof(T) * 8};
  constexpr std::size_t n_simd{1};
  std::vector<std::vector<ENCRYPTO::BitVector<>>> global_input{
      ENCRYPTO::ToInput(raw_global_input.at(0)), ENCRYPTO::ToInput(raw_global_input.at(1))};
  std::vector<std::vector<ENCRYPTO::BitVector<>>> global_input_simd{
      ENCRYPTO::ToInput(raw_global_input_simd.at(0)),
      ENCRYPTO::ToInput(raw_global_input_simd.at(1))};
  std::vector<ENCRYPTO::BitVector<>> dummy_input(n_wires, ENCRYPTO::BitVector<>(1, false)),
      dummy_input_simd(n_wires, ENCRYPTO::BitVector<>(3, false));

  std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(2, PORT_OFFSET)));
  for (auto &p : motion_parties) {
    p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
    p->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> t;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    t.emplace_back([party_id, &motion_parties, n_wires, &global_input, &global_input_simd,
                    &dummy_input, &dummy_input_simd, &raw_global_input, &raw_global_input_simd]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      MOTION::SecureUnsignedInteger s_0 = party_0 ? motion_parties.at(party_id)->IN<BMR>(
                                                        global_input.at(0), 0)
                                                  : motion_parties.at(party_id)->IN<BMR>(
                                                        dummy_input, 0),
                                    s_1 = party_0
                                              ? motion_parties.at(party_id)->IN<BMR>(dummy_input, 1)
                                              : motion_parties.at(party_id)->IN<BMR>(
                                                    global_input.at(1), 1);
      MOTION::SecureUnsignedInteger s_0_simd = party_0 ? motion_parties.at(party_id)->IN<BMR>(
                                                             global_input_simd.at(0), 0)
                                                       : motion_parties.at(party_id)->IN<BMR>(
                                                             dummy_input_simd, 0),
                                    s_1_simd = party_0 ? motion_parties.at(party_id)->IN<BMR>(
                                                             dummy_input_simd, 1)
                                                       : motion_parties.at(party_id)->IN<BMR>(
                                                             global_input_simd.at(1), 1);
      EXPECT_EQ(s_0.Get()->GetBitLength(), n_wires);

      const auto s_add = s_0 + s_1;
      const auto s_add_simd = s_0_simd + s_1_simd;

      auto s_out = s_add.Get().Out();
      auto s_out_simd = s_add_simd.Get().Out();

      motion_parties.at(party_id)->Run();

      const T sum_check = raw_global_input.at(0) + raw_global_input.at(1);
      const auto sum_check_simd =
          MOTION::Helpers::AddVectors(raw_global_input_simd.at(0), raw_global_input_simd.at(1));
      std::vector<ENCRYPTO::BitVector<>> out, out_simd;
      for (auto i = 0ull; i < n_wires; ++i) {
        auto wire_single =
            std::dynamic_pointer_cast<MOTION::Wires::BMRWire>(s_out->GetWires().at(i));
        assert(wire_single);
        out.emplace_back(wire_single->GetPublicValues());
        auto wire_single_simd =
            std::dynamic_pointer_cast<MOTION::Wires::BMRWire>(s_out_simd->GetWires().at(i));
        assert(wire_single_simd);
        out_simd.emplace_back(wire_single_simd->GetPublicValues());
      }
      const T sum = ENCRYPTO::ToOutput<T>(out);
      const auto sum_simd = ENCRYPTO::ToVectorOutput<T>(out_simd);

      EXPECT_EQ(sum, sum_check);
      EXPECT_EQ(sum_simd, sum_check_simd);
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto &tt : t)
    if (tt.joinable()) tt.join();
}

TYPED_TEST(SecureUintTest, AdditionInGMW) {
  using T = TypeParam;
  using namespace MOTION;
  constexpr auto GMW = MOTION::MPCProtocol::BooleanGMW;
  std::mt19937 g(0);
  std::uniform_int_distribution<T> dist(0, std::numeric_limits<T>::max());
  auto r = std::bind(dist, g);
  const std::vector<T> raw_global_input = {r(), r()};
  constexpr auto n_wires{sizeof(T) * 8};
  constexpr std::size_t n_simd{1};
  std::vector<std::vector<ENCRYPTO::BitVector<>>> global_input{
      ENCRYPTO::ToInput(raw_global_input.at(0)), ENCRYPTO::ToInput(raw_global_input.at(1))};
  std::vector<ENCRYPTO::BitVector<>> dummy_input(n_wires, ENCRYPTO::BitVector<>(n_simd, false));

  std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(2, PORT_OFFSET)));
  for (auto &p : motion_parties) {
    p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
    p->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> t;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    t.emplace_back([party_id, &motion_parties, n_wires, &global_input, &dummy_input,
                    &raw_global_input]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      MOTION::SecureUnsignedInteger s_0 = party_0 ? motion_parties.at(party_id)->IN<GMW>(
                                                        global_input.at(0), 0)
                                                  : motion_parties.at(party_id)->IN<GMW>(
                                                        dummy_input, 0),
                                    s_1 = party_0
                                              ? motion_parties.at(party_id)->IN<GMW>(dummy_input, 1)
                                              : motion_parties.at(party_id)->IN<GMW>(
                                                    global_input.at(1), 1);
      EXPECT_EQ(s_0.Get()->GetBitLength(), n_wires);

      const auto s_add = s_0 + s_1;
      auto s_out = s_add.Get().Out();

      motion_parties.at(party_id)->Run();

      const T sum_check = raw_global_input.at(0) + raw_global_input.at(1);
      std::vector<ENCRYPTO::BitVector<>> out;
      for (auto i = 0ull; i < n_wires; ++i) {
        auto wire_single =
            std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out->GetWires().at(i));
        assert(wire_single);
        out.emplace_back(wire_single->GetValues());
      }
      T sum = ENCRYPTO::ToOutput<T>(out);
      EXPECT_EQ(sum, sum_check);
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto &tt : t)
    if (tt.joinable()) tt.join();
}

TYPED_TEST(SecureUintTest, SubtractionInBMR) {
  using T = TypeParam;
  using namespace MOTION;
  constexpr auto BMR = MOTION::MPCProtocol::BMR;
  std::mt19937 g(0);
  std::uniform_int_distribution<T> dist(0, std::numeric_limits<T>::max());
  auto r = std::bind(dist, g);
  const std::vector<T> raw_global_input = {r(), r()};
  constexpr auto n_wires{sizeof(T) * 8};
  constexpr std::size_t n_simd{1};
  std::vector<std::vector<ENCRYPTO::BitVector<>>> global_input{
      ENCRYPTO::ToInput(raw_global_input.at(0)), ENCRYPTO::ToInput(raw_global_input.at(1))};
  std::vector<ENCRYPTO::BitVector<>> dummy_input(n_wires, ENCRYPTO::BitVector<>(n_simd, false));

  std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(2, PORT_OFFSET)));
  for (auto &p : motion_parties) {
    p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
    p->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> t;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    t.emplace_back([party_id, &motion_parties, n_wires, &global_input, &dummy_input,
                    &raw_global_input]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      MOTION::SecureUnsignedInteger s_0 = party_0 ? motion_parties.at(party_id)->IN<BMR>(
                                                        global_input.at(0), 0)
                                                  : motion_parties.at(party_id)->IN<BMR>(
                                                        dummy_input, 0),
                                    s_1 = party_0
                                              ? motion_parties.at(party_id)->IN<BMR>(dummy_input, 1)
                                              : motion_parties.at(party_id)->IN<BMR>(
                                                    global_input.at(1), 1);
      EXPECT_EQ(s_0.Get()->GetBitLength(), n_wires);

      const auto s_sub = s_0 - s_1;
      auto s_out = s_sub.Get().Out();

      motion_parties.at(party_id)->Run();

      const T sum_check = raw_global_input.at(0) - raw_global_input.at(1);
      std::vector<ENCRYPTO::BitVector<>> out;
      for (auto i = 0ull; i < n_wires; ++i) {
        auto wire_single =
            std::dynamic_pointer_cast<MOTION::Wires::BMRWire>(s_out->GetWires().at(i));
        assert(wire_single);
        out.emplace_back(wire_single->GetPublicValues());
      }
      T sum = ENCRYPTO::ToOutput<T>(out);
      EXPECT_EQ(sum, sum_check);
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto &tt : t)
    if (tt.joinable()) tt.join();
}

TYPED_TEST(SecureUintTest, SubtractionInGMW) {
  using T = TypeParam;
  using namespace MOTION;
  constexpr auto GMW = MOTION::MPCProtocol::BooleanGMW;
  std::mt19937 g(0);
  std::uniform_int_distribution<T> dist(0, std::numeric_limits<T>::max());
  auto r = std::bind(dist, g);
  const std::vector<T> raw_global_input = {r(), r()};
  constexpr auto n_wires{sizeof(T) * 8};
  constexpr std::size_t n_simd{1};
  std::vector<std::vector<ENCRYPTO::BitVector<>>> global_input{
      ENCRYPTO::ToInput(raw_global_input.at(0)), ENCRYPTO::ToInput(raw_global_input.at(1))};
  std::vector<ENCRYPTO::BitVector<>> dummy_input(n_wires, ENCRYPTO::BitVector<>(n_simd, false));

  std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(2, PORT_OFFSET)));
  for (auto &p : motion_parties) {
    p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
    p->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> t;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    t.emplace_back([party_id, &motion_parties, n_wires, &global_input, &dummy_input,
                    &raw_global_input]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      MOTION::SecureUnsignedInteger s_0 = party_0 ? motion_parties.at(party_id)->IN<GMW>(
                                                        global_input.at(0), 0)
                                                  : motion_parties.at(party_id)->IN<GMW>(
                                                        dummy_input, 0),
                                    s_1 = party_0
                                              ? motion_parties.at(party_id)->IN<GMW>(dummy_input, 1)
                                              : motion_parties.at(party_id)->IN<GMW>(
                                                    global_input.at(1), 1);
      EXPECT_EQ(s_0.Get()->GetBitLength(), n_wires);

      const auto s_sub = s_0 - s_1;
      auto s_out = s_sub.Get().Out();

      motion_parties.at(party_id)->Run();

      const T sum_check = raw_global_input.at(0) - raw_global_input.at(1);
      std::vector<ENCRYPTO::BitVector<>> out;
      for (auto i = 0ull; i < n_wires; ++i) {
        auto wire_single =
            std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out->GetWires().at(i));
        assert(wire_single);
        out.emplace_back(wire_single->GetValues());
      }
      T sum = ENCRYPTO::ToOutput<T>(out);
      EXPECT_EQ(sum, sum_check);
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto &tt : t)
    if (tt.joinable()) tt.join();
}

// FIXME: fails for >32 bits due to operating system restriction for maximum number of threads
// enable when replaced with co-routines
TYPED_TEST(SecureUintTest, DISABLED_MultiplicationInBMR) {
  using T = TypeParam;
  using namespace MOTION;
  constexpr auto BMR = MOTION::MPCProtocol::BMR;
  std::mt19937 g(0);
  std::uniform_int_distribution<T> dist(0, std::numeric_limits<T>::max());
  auto r = std::bind(dist, g);
  const std::vector<T> raw_global_input = {r(), r()};
  constexpr auto n_wires{sizeof(T) * 8};
  constexpr std::size_t n_simd{1};
  std::vector<std::vector<ENCRYPTO::BitVector<>>> global_input{
      ENCRYPTO::ToInput(raw_global_input.at(0)), ENCRYPTO::ToInput(raw_global_input.at(1))};
  std::vector<ENCRYPTO::BitVector<>> dummy_input(n_wires, ENCRYPTO::BitVector<>(n_simd, false));

  std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(2, PORT_OFFSET)));
  for (auto &p : motion_parties) {
    p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
    p->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> t;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    t.emplace_back([party_id, &motion_parties, n_wires, &global_input, &dummy_input,
                    &raw_global_input]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      MOTION::SecureUnsignedInteger s_0 = party_0 ? motion_parties.at(party_id)->IN<BMR>(
                                                        global_input.at(0), 0)
                                                  : motion_parties.at(party_id)->IN<BMR>(
                                                        dummy_input, 0),
                                    s_1 = party_0
                                              ? motion_parties.at(party_id)->IN<BMR>(dummy_input, 1)
                                              : motion_parties.at(party_id)->IN<BMR>(
                                                    global_input.at(1), 1);
      EXPECT_EQ(s_0.Get()->GetBitLength(), n_wires);

      const auto s_mul = s_0 * s_1;
      auto s_out = s_mul.Get().Out();

      motion_parties.at(party_id)->Run();

      const T sum_check = raw_global_input.at(0) * raw_global_input.at(1);
      std::vector<ENCRYPTO::BitVector<>> out;
      for (auto i = 0ull; i < n_wires; ++i) {
        auto wire_single =
            std::dynamic_pointer_cast<MOTION::Wires::BMRWire>(s_out->GetWires().at(i));
        assert(wire_single);
        out.emplace_back(wire_single->GetPublicValues());
      }
      T sum = ENCRYPTO::ToOutput<T>(out);
      EXPECT_EQ(sum, sum_check);
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto &tt : t)
    if (tt.joinable()) tt.join();
}

TYPED_TEST(SecureUintTest, DISABLED_MultiplicationInGMW) {
  using T = TypeParam;
  using namespace MOTION;
  constexpr auto GMW = MOTION::MPCProtocol::BooleanGMW;
  std::mt19937 g(0);
  std::uniform_int_distribution<T> dist(0, std::numeric_limits<T>::max());
  auto r = std::bind(dist, g);
  const std::vector<T> raw_global_input = {r(), r()};
  constexpr auto n_wires{sizeof(T) * 8};
  constexpr std::size_t n_simd{1};
  std::vector<std::vector<ENCRYPTO::BitVector<>>> global_input{
      ENCRYPTO::ToInput(raw_global_input.at(0)), ENCRYPTO::ToInput(raw_global_input.at(1))};
  std::vector<ENCRYPTO::BitVector<>> dummy_input(n_wires, ENCRYPTO::BitVector<>(n_simd, false));

  std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(2, PORT_OFFSET)));
  for (auto &p : motion_parties) {
    p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
    p->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> t;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    t.emplace_back([party_id, &motion_parties, n_wires, &global_input, &dummy_input,
                    &raw_global_input]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      MOTION::SecureUnsignedInteger s_0 = party_0 ? motion_parties.at(party_id)->IN<GMW>(
                                                        global_input.at(0), 0)
                                                  : motion_parties.at(party_id)->IN<GMW>(
                                                        dummy_input, 0),
                                    s_1 = party_0
                                              ? motion_parties.at(party_id)->IN<GMW>(dummy_input, 1)
                                              : motion_parties.at(party_id)->IN<GMW>(
                                                    global_input.at(1), 1);
      EXPECT_EQ(s_0.Get()->GetBitLength(), n_wires);

      const auto s_mul = s_0 * s_1;
      auto s_out = s_mul.Get().Out();

      motion_parties.at(party_id)->Run();

      const T sum_check = raw_global_input.at(0) * raw_global_input.at(1);
      std::vector<ENCRYPTO::BitVector<>> out;
      for (auto i = 0ull; i < n_wires; ++i) {
        auto wire_single =
            std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out->GetWires().at(i));
        assert(wire_single);
        out.emplace_back(wire_single->GetValues());
      }
      T sum = ENCRYPTO::ToOutput<T>(out);
      EXPECT_EQ(sum, sum_check);
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto &tt : t)
    if (tt.joinable()) tt.join();
}

// FIXME: fails for >32 bits due to operating system restriction for maximum number of threads
// enable when replaced with co-routines
TYPED_TEST(SecureUintTest, DISABLED_DivisionInBMR) {
  using T = TypeParam;
  using namespace MOTION;
  constexpr auto BMR = MOTION::MPCProtocol::BMR;
  std::mt19937 g(0);
  std::uniform_int_distribution<T> dist(0, std::numeric_limits<T>::max());
  auto r = std::bind(dist, g);
  const std::vector<T> raw_global_input = {r(), r()};
  constexpr auto n_wires{sizeof(T) * 8};
  constexpr std::size_t n_simd{1};
  std::vector<std::vector<ENCRYPTO::BitVector<>>> global_input{
      ENCRYPTO::ToInput(raw_global_input.at(0)), ENCRYPTO::ToInput(raw_global_input.at(1))};
  std::vector<ENCRYPTO::BitVector<>> dummy_input(n_wires, ENCRYPTO::BitVector<>(n_simd, false));

  std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(2, PORT_OFFSET)));
  for (auto &p : motion_parties) {
    p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
    p->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> t;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    t.emplace_back([party_id, &motion_parties, n_wires, &global_input, &dummy_input,
                    &raw_global_input]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      MOTION::SecureUnsignedInteger s_0 = party_0 ? motion_parties.at(party_id)->IN<BMR>(
                                                        global_input.at(0), 0)
                                                  : motion_parties.at(party_id)->IN<BMR>(
                                                        dummy_input, 0),
                                    s_1 = party_0
                                              ? motion_parties.at(party_id)->IN<BMR>(dummy_input, 1)
                                              : motion_parties.at(party_id)->IN<BMR>(
                                                    global_input.at(1), 1);
      EXPECT_EQ(s_0.Get()->GetBitLength(), n_wires);

      const auto s_div = s_0 / s_1;
      auto s_out = s_div.Get().Out();

      motion_parties.at(party_id)->Run();

      const T result_check = raw_global_input.at(0) / raw_global_input.at(1);
      std::vector<ENCRYPTO::BitVector<>> out;
      for (auto i = 0ull; i < n_wires; ++i) {
        auto wire_single =
            std::dynamic_pointer_cast<MOTION::Wires::BMRWire>(s_out->GetWires().at(i));
        assert(wire_single);
        out.emplace_back(wire_single->GetPublicValues());
      }
      T result = ENCRYPTO::ToOutput<T>(out);
      EXPECT_EQ(result, result_check);
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto &tt : t)
    if (tt.joinable()) tt.join();
}

TYPED_TEST(SecureUintTest, DISABLED_DivisionInGMW) {
  using T = TypeParam;
  using namespace MOTION;
  constexpr auto GMW = MOTION::MPCProtocol::BooleanGMW;
  std::mt19937 g(0);
  std::uniform_int_distribution<T> dist(0, std::numeric_limits<T>::max());
  auto r = std::bind(dist, g);
  const std::vector<T> raw_global_input = {r(), r()};
  constexpr auto n_wires{sizeof(T) * 8};
  constexpr std::size_t n_simd{1};
  std::vector<std::vector<ENCRYPTO::BitVector<>>> global_input{
      ENCRYPTO::ToInput(raw_global_input.at(0)), ENCRYPTO::ToInput(raw_global_input.at(1))};
  std::vector<ENCRYPTO::BitVector<>> dummy_input(n_wires, ENCRYPTO::BitVector<>(n_simd, false));

  std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(2, PORT_OFFSET)));
  for (auto &p : motion_parties) {
    p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
    p->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> t;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    t.emplace_back([party_id, &motion_parties, n_wires, &global_input, &dummy_input,
                    &raw_global_input]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      MOTION::SecureUnsignedInteger s_0 = party_0 ? motion_parties.at(party_id)->IN<GMW>(
                                                        global_input.at(0), 0)
                                                  : motion_parties.at(party_id)->IN<GMW>(
                                                        dummy_input, 0),
                                    s_1 = party_0
                                              ? motion_parties.at(party_id)->IN<GMW>(dummy_input, 1)
                                              : motion_parties.at(party_id)->IN<GMW>(
                                                    global_input.at(1), 1);
      EXPECT_EQ(s_0.Get()->GetBitLength(), n_wires);
      EXPECT_EQ(s_1.Get()->GetBitLength(), n_wires);

      const auto s_add = s_0 / s_1;
      auto s_out = s_add.Get().Out();

      motion_parties.at(party_id)->Run();

      const T sum_check = raw_global_input.at(0) / raw_global_input.at(1);
      std::vector<ENCRYPTO::BitVector<>> out;
      for (auto i = 0ull; i < n_wires; ++i) {
        auto wire_single =
            std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out->GetWires().at(i));
        assert(wire_single);
        out.emplace_back(wire_single->GetValues());
      }
      T sum = ENCRYPTO::ToOutput<T>(out);
      EXPECT_EQ(sum, sum_check);
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto &tt : t)
    if (tt.joinable()) tt.join();
}

TYPED_TEST(SecureUintTest, EqualityInBMR) {
  using T = TypeParam;
  using namespace MOTION;
  constexpr auto BMR = MOTION::MPCProtocol::BMR;
  std::mt19937 g(0);
  std::uniform_int_distribution<T> dist(0, std::numeric_limits<T>::max());
  auto r = std::bind(dist, g);
  const std::vector<T> raw_global_input = {r(), r()};
  constexpr auto n_wires{sizeof(T) * 8};
  constexpr std::size_t n_simd{1};
  std::vector<std::vector<ENCRYPTO::BitVector<>>> global_input{
      ENCRYPTO::ToInput(raw_global_input.at(0)), ENCRYPTO::ToInput(raw_global_input.at(1))};
  std::vector<ENCRYPTO::BitVector<>> dummy_input(n_wires, ENCRYPTO::BitVector<>(n_simd, false));

  std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(2, PORT_OFFSET)));
  for (auto &p : motion_parties) {
    p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
    p->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> t;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    t.emplace_back([party_id, &motion_parties, n_wires, &global_input, &dummy_input,
                    &raw_global_input]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      MOTION::SecureUnsignedInteger s_0 = party_0 ? motion_parties.at(party_id)->IN<BMR>(
                                                        global_input.at(0), 0)
                                                  : motion_parties.at(party_id)->IN<BMR>(
                                                        dummy_input, 0),
                                    s_1 = party_0
                                              ? motion_parties.at(party_id)->IN<BMR>(dummy_input, 1)
                                              : motion_parties.at(party_id)->IN<BMR>(
                                                    global_input.at(1), 1);
      EXPECT_EQ(s_0.Get()->GetBitLength(), n_wires);

      const auto s_eq = s_0 == s_1;
      auto s_out = s_eq.Out();
      assert(s_out->GetBitLength() == 1);

      motion_parties.at(party_id)->Run();

      std::vector<ENCRYPTO::BitVector<>> out;
      auto wire_single = std::dynamic_pointer_cast<MOTION::Wires::BMRWire>(s_out->GetWires().at(0));
      assert(wire_single);
      const bool result_check = raw_global_input.at(0) == raw_global_input.at(1);
      const bool result = wire_single->GetPublicValues()[0];
      EXPECT_EQ(result, result_check);

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto &tt : t)
    if (tt.joinable()) tt.join();
}

TYPED_TEST(SecureUintTest, EqualityInGMW) {
  using T = TypeParam;
  using namespace MOTION;
  constexpr auto GMW = MOTION::MPCProtocol::BooleanGMW;
  std::mt19937 g(0);
  std::uniform_int_distribution<T> dist(0, std::numeric_limits<T>::max());
  auto r = std::bind(dist, g);
  const std::vector<T> raw_global_input = {r(), r()};
  constexpr auto n_wires{sizeof(T) * 8};
  constexpr std::size_t n_simd{1};
  std::vector<std::vector<ENCRYPTO::BitVector<>>> global_input{
      ENCRYPTO::ToInput(raw_global_input.at(0)), ENCRYPTO::ToInput(raw_global_input.at(1))};
  std::vector<ENCRYPTO::BitVector<>> dummy_input(n_wires, ENCRYPTO::BitVector<>(n_simd, false));

  std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(2, PORT_OFFSET)));
  for (auto &p : motion_parties) {
    p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
    p->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> t;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    t.emplace_back([party_id, &motion_parties, n_wires, &global_input, &dummy_input,
                    &raw_global_input]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      MOTION::SecureUnsignedInteger s_0 = party_0 ? motion_parties.at(party_id)->IN<GMW>(
                                                        global_input.at(0), 0)
                                                  : motion_parties.at(party_id)->IN<GMW>(
                                                        dummy_input, 0),
                                    s_1 = party_0
                                              ? motion_parties.at(party_id)->IN<GMW>(dummy_input, 1)
                                              : motion_parties.at(party_id)->IN<GMW>(
                                                    global_input.at(1), 1);
      EXPECT_EQ(s_0.Get()->GetBitLength(), n_wires);

      const auto s_eq = s_0 == s_1;
      auto s_out = s_eq.Out();
      assert(s_out->GetBitLength() == 1);

      motion_parties.at(party_id)->Run();

      std::vector<ENCRYPTO::BitVector<>> out;
      auto wire_single = std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out->GetWires().at(0));
      assert(wire_single);
      const bool result_check = raw_global_input.at(0) == raw_global_input.at(1);
      const bool result = wire_single->GetValues()[0];
      EXPECT_EQ(result, result_check);

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto &tt : t)
    if (tt.joinable()) tt.join();
}

TYPED_TEST(SecureUintTest, GreaterThanInGMW) {
  using T = TypeParam;
  using namespace MOTION;
  constexpr auto GMW = MOTION::MPCProtocol::BooleanGMW;
  std::mt19937 g(0);
  std::uniform_int_distribution<T> dist(0, std::numeric_limits<T>::max());
  auto r = std::bind(dist, g);
  const std::vector<T> raw_global_input = {r(), r()};
  constexpr auto n_wires{sizeof(T) * 8};
  constexpr std::size_t n_simd{1};
  std::vector<std::vector<ENCRYPTO::BitVector<>>> global_input{
      ENCRYPTO::ToInput(raw_global_input.at(0)), ENCRYPTO::ToInput(raw_global_input.at(1))};
  std::vector<ENCRYPTO::BitVector<>> dummy_input(n_wires, ENCRYPTO::BitVector<>(n_simd, false));

  std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(2, PORT_OFFSET)));
  for (auto &p : motion_parties) {
    p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
    p->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> t;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    t.emplace_back([party_id, &motion_parties, n_wires, &global_input, &dummy_input,
                    &raw_global_input]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      MOTION::SecureUnsignedInteger s_0 = party_0 ? motion_parties.at(party_id)->IN<GMW>(
                                                        global_input.at(0), 0)
                                                  : motion_parties.at(party_id)->IN<GMW>(
                                                        dummy_input, 0),
                                    s_1 = party_0
                                              ? motion_parties.at(party_id)->IN<GMW>(dummy_input, 1)
                                              : motion_parties.at(party_id)->IN<GMW>(
                                                    global_input.at(1), 1);
      EXPECT_EQ(s_0.Get()->GetBitLength(), n_wires);
      EXPECT_EQ(s_1.Get()->GetBitLength(), n_wires);

      const auto s_gt = s_0 > s_1;
      auto s_out = s_gt.Out();
      assert(s_out->GetBitLength() == 1);

      motion_parties.at(party_id)->Run();

      std::vector<ENCRYPTO::BitVector<>> out;
      auto wire_single = std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out->GetWires().at(0));
      assert(wire_single);
      const bool result_check = raw_global_input.at(0) > raw_global_input.at(1);
      const bool result = wire_single->GetValues()[0];
      EXPECT_EQ(result, result_check);

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto &tt : t)
    if (tt.joinable()) tt.join();
}

TYPED_TEST(SecureUintTest, GreaterThanInBMR) {
  using T = TypeParam;
  using namespace MOTION;
  constexpr auto GMW = MOTION::MPCProtocol::BooleanGMW;
  std::mt19937 g(0);
  std::uniform_int_distribution<T> dist(0, std::numeric_limits<T>::max());
  auto r = std::bind(dist, g);
  const std::vector<T> raw_global_input = {r(), r()};
  constexpr auto n_wires{sizeof(T) * 8};
  constexpr std::size_t n_simd{1};
  std::vector<std::vector<ENCRYPTO::BitVector<>>> global_input{
      ENCRYPTO::ToInput(raw_global_input.at(0)), ENCRYPTO::ToInput(raw_global_input.at(1))};
  std::vector<ENCRYPTO::BitVector<>> dummy_input(n_wires, ENCRYPTO::BitVector<>(n_simd, false));

  std::vector<PartyPtr> motion_parties(std::move(GetNLocalParties(2, PORT_OFFSET)));
  for (auto &p : motion_parties) {
    p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
    p->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> t;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    t.emplace_back([party_id, &motion_parties, n_wires, &global_input, &dummy_input,
                    &raw_global_input]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      MOTION::SecureUnsignedInteger s_0 = party_0 ? motion_parties.at(party_id)->IN<GMW>(
                                                        global_input.at(0), 0)
                                                  : motion_parties.at(party_id)->IN<GMW>(
                                                        dummy_input, 0),
                                    s_1 = party_0
                                              ? motion_parties.at(party_id)->IN<GMW>(dummy_input, 1)
                                              : motion_parties.at(party_id)->IN<GMW>(
                                                    global_input.at(1), 1);
      EXPECT_EQ(s_0.Get()->GetBitLength(), n_wires);
      EXPECT_EQ(s_1.Get()->GetBitLength(), n_wires);

      const auto s_gt = s_0 > s_1;
      auto s_out = s_gt.Out();

      motion_parties.at(party_id)->Run();

      std::vector<ENCRYPTO::BitVector<>> out;
      auto wire_single = std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(s_out->GetWires().at(0));
      assert(wire_single);
      const bool result_check = raw_global_input.at(0) > raw_global_input.at(1);
      const bool result = wire_single->GetValues()[0];
      EXPECT_EQ(result, result_check);

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto &tt : t)
    if (tt.joinable()) tt.join();
}

}  // namespace
