// MIT License
//
// Copyright (c) 2021 Oleksandr Tkachenko, Arianne Roselina Prananto
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

#include <gtest/gtest.h>
#include <algorithm>
#include <fstream>
#include <limits>
#include <random>
#include <type_traits>

#include "algorithm/algorithm_description.h"
#include "base/party.h"
#include "protocols/bmr/bmr_wire.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/share_wrapper.h"
#include "secure_type/secure_unsigned_integer.h"
#include "utility/config.h"
#include "utility/helpers.h"

#include "test_constants.h"

using namespace encrypto::motion;

namespace {
TEST(AlgorithmDescription, FromBristolFormatIntAdd8Size) {
  const auto int_add8 = encrypto::motion::AlgorithmDescription::FromBristol(
      std::string(encrypto::motion::kRootDir) + "/circuits/int/int_add8_size.bristol");
  EXPECT_EQ(int_add8.number_of_gates, 34);
  EXPECT_EQ(int_add8.gates.size(), 34);
  EXPECT_EQ(int_add8.number_of_output_wires, 8);
  EXPECT_EQ(int_add8.number_of_input_wires_parent_a, 8);
  ASSERT_NO_THROW([&int_add8]() { EXPECT_EQ(*int_add8.number_of_input_wires_parent_b, 8); }());
  EXPECT_EQ(int_add8.number_of_wires, 50);

  const auto& gate0 = int_add8.gates.at(0);
  EXPECT_EQ(gate0.parent_a, 0);
  ASSERT_NO_THROW([&gate0]() { EXPECT_EQ(*gate0.parent_b, 8); }());
  EXPECT_EQ(gate0.output_wire, 42);
  EXPECT_TRUE(gate0.type == encrypto::motion::PrimitiveOperationType::kXor);
  EXPECT_EQ(gate0.selection_bit.has_value(), false);

  const auto& gate1 = int_add8.gates.at(1);
  EXPECT_EQ(gate1.parent_a, 0);
  ASSERT_NO_THROW([&gate1]() { EXPECT_EQ(*gate1.parent_b, 8); }());
  EXPECT_EQ(gate1.output_wire, 16);
  EXPECT_TRUE(gate1.type == encrypto::motion::PrimitiveOperationType::kAnd);
  EXPECT_EQ(gate1.selection_bit.has_value(), false);

  const auto& gate32 = int_add8.gates.at(32);
  EXPECT_EQ(gate32.parent_a, 15);
  ASSERT_NO_THROW([&gate32]() { EXPECT_EQ(*gate32.parent_b, 40); }());
  EXPECT_EQ(gate32.output_wire, 41);
  EXPECT_TRUE(gate32.type == encrypto::motion::PrimitiveOperationType::kXor);
  EXPECT_EQ(gate32.selection_bit.has_value(), false);

  const auto& gate33 = int_add8.gates.at(33);
  EXPECT_EQ(gate33.parent_a, 7);
  ASSERT_NO_THROW([&gate33]() { EXPECT_EQ(*gate33.parent_b, 41); }());
  EXPECT_EQ(gate33.output_wire, 49);
  EXPECT_TRUE(gate33.type == encrypto::motion::PrimitiveOperationType::kXor);
  EXPECT_EQ(gate33.selection_bit.has_value(), false);
}

// TODO: rewrite as generic tests
template <typename T>
class SecureUintTest : public ::testing::Test {
  void TestSingle() {
    constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
    std::mt19937 mersenne_twister(sizeof(T));
    std::uniform_int_distribution<T> distribution(0, std::numeric_limits<T>::max());
    auto random = std::bind(distribution, mersenne_twister);
    const std::vector<T> raw_global_input = {random(), random()};
    constexpr auto kNumberOfWires{sizeof(T) * 8};
    constexpr std::size_t kNumberOfSimd{1};
    std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
        encrypto::motion::ToInput(raw_global_input.at(0)),
        encrypto::motion::ToInput(raw_global_input.at(1))};
    std::vector<encrypto::motion::BitVector<>> dummy_input(
        kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

    std::vector<PartyPointer> motion_parties(
        std::move(MakeLocallyConnectedParties(2, kPortOffset)));
    for (auto& party : motion_parties) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      party->GetConfiguration()->SetOnlineAfterSetup(true);
    }
    std::vector<std::thread> threads;
    for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
      threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                            &raw_global_input]() {
        const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
        encrypto::motion::SecureUnsignedInteger
            share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                              : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
            share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                              : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
        EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

        const auto share_result = Add(share_0, share_1);
        auto share_output = share_result.Out();

        motion_parties.at(party_id)->Run();

        const T sum_check = raw_global_input.at(0) + raw_global_input.at(1);
        std::vector<encrypto::motion::BitVector<>> output;
        for (auto i = 0ull; i < kNumberOfWires; ++i) {
          auto wire_single = std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
              share_output->GetWires().at(i));
          assert(wire_single);
          output.emplace_back(wire_single->GetValues());
        }
        T sum = encrypto::motion::ToOutput<T>(output);
        EXPECT_EQ(sum, sum_check);
        motion_parties.at(party_id)->Finish();
      });
    }
    for (auto& t : threads)
      if (t.joinable()) t.join();
  };

  void TestSimd() {
    constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
    std::mt19937 mersenne_twister(sizeof(T));
    std::uniform_int_distribution<T> distribution(0, std::numeric_limits<T>::max());
    auto random = std::bind(distribution, mersenne_twister);
    const std::vector<T> raw_global_input = {random(), random()};
    constexpr auto kNumberOfWires{sizeof(T) * 8};
    constexpr std::size_t kNumberOfSimd{1};
    std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
        encrypto::motion::ToInput(raw_global_input.at(0)),
        encrypto::motion::ToInput(raw_global_input.at(1))};
    std::vector<encrypto::motion::BitVector<>> dummy_input(
        kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

    std::vector<PartyPointer> motion_parties(
        std::move(MakeLocallyConnectedParties(2, kPortOffset)));
    for (auto& party : motion_parties) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      party->GetConfiguration()->SetOnlineAfterSetup(true);
    }
    std::vector<std::thread> threads;
    for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
      threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                            &raw_global_input]() {
        const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
        encrypto::motion::SecureUnsignedInteger
            share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                              : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
            share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                              : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
        EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

        const auto share_result = Add(share_0, share_1);
        auto share_output = share_result.Out();

        motion_parties.at(party_id)->Run();

        const T sum_check = raw_global_input.at(0) + raw_global_input.at(1);
        std::vector<encrypto::motion::BitVector<>> output;
        for (auto i = 0ull; i < kNumberOfWires; ++i) {
          auto wire_single = std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
              share_output->GetWires().at(i));
          assert(wire_single);
          output.emplace_back(wire_single->GetValues());
        }
        T sum = encrypto::motion::ToOutput<T>(output);
        EXPECT_EQ(sum, sum_check);
        motion_parties.at(party_id)->Finish();
      });
    }
    for (auto& t : threads)
      if (t.joinable()) t.join();
  };

  static encrypto::motion::ShareWrapper Add(const encrypto::motion::SecureUnsignedInteger& a,
                                            const encrypto::motion::SecureUnsignedInteger& b) {
    return (a + b).Get();
  }

  static encrypto::motion::ShareWrapper Sub(const encrypto::motion::SecureUnsignedInteger& a,
                                            const encrypto::motion::SecureUnsignedInteger& b) {
    return (a - b).Get();
  }

  static encrypto::motion::ShareWrapper Mul(const encrypto::motion::SecureUnsignedInteger& a,
                                            const encrypto::motion::SecureUnsignedInteger& b) {
    return (a * b).Get();
  }

  static encrypto::motion::ShareWrapper Div(const encrypto::motion::SecureUnsignedInteger& a,
                                            const encrypto::motion::SecureUnsignedInteger& b) {
    return (a / b).Get();
  }

  static encrypto::motion::ShareWrapper Gt(const encrypto::motion::SecureUnsignedInteger& a,
                                           const encrypto::motion::SecureUnsignedInteger& b) {
    return a > b;
  }

  static encrypto::motion::ShareWrapper Eq(const encrypto::motion::SecureUnsignedInteger& a,
                                           const encrypto::motion::SecureUnsignedInteger& b) {
    return a == b;
  }
};

using all_uints = ::testing::Types<std::uint8_t, std::uint16_t, std::uint32_t, std::uint64_t>;
TYPED_TEST_SUITE(SecureUintTest, all_uints);

TYPED_TEST(SecureUintTest, AdditionInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  std::mt19937 mersenne_twister(sizeof(T));
  std::uniform_int_distribution<T> distribution(0, std::numeric_limits<T>::max());
  auto random = std::bind(distribution, mersenne_twister);
  const std::vector<T> raw_global_input = {random(), random()};
  const std::vector<std::vector<T>> raw_global_input_simd(
      2, std::vector<T>{random(), random(), random()});
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input.at(0)),
      encrypto::motion::ToInput(raw_global_input.at(1))};
  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input_simd{
      encrypto::motion::ToInput(raw_global_input_simd.at(0)),
      encrypto::motion::ToInput(raw_global_input_simd.at(1))};
  std::vector<encrypto::motion::BitVector<>> dummy_input(kNumberOfWires,
                                                         encrypto::motion::BitVector<>(1, false)),
      dummy_input_simd(kNumberOfWires, encrypto::motion::BitVector<>(3, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input,
                          &global_input_simd, &dummy_input, &dummy_input_simd, &raw_global_input,
                          &raw_global_input_simd]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      encrypto::motion::SecureUnsignedInteger
          share_0_simd = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input_simd.at(0), 0)
                                 : motion_parties.at(party_id)->In<kBmr>(dummy_input_simd, 0),
          share_1_simd = party_0
                             ? motion_parties.at(party_id)->In<kBmr>(dummy_input_simd, 1)
                             : motion_parties.at(party_id)->In<kBmr>(global_input_simd.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_addition = share_0 + share_1;
      const auto share_addition_simd = share_0_simd + share_1_simd;

      auto share_output = share_addition.Get().Out();
      auto share_output_simd = share_addition_simd.Get().Out();

      motion_parties.at(party_id)->Run();

      const T result_check = raw_global_input.at(0) + raw_global_input.at(1);
      const auto result_check_simd =
          encrypto::motion::AddVectors<T>(raw_global_input_simd.at(0), raw_global_input_simd.at(1));
      std::vector<encrypto::motion::BitVector<>> output, output_simd;
      for (auto i = 0ull; i < kNumberOfWires; ++i) {
        auto wire_single = std::dynamic_pointer_cast<encrypto::motion::proto::bmr::Wire>(
            share_output->GetWires().at(i));
        assert(wire_single);
        output.emplace_back(wire_single->GetPublicValues());
        auto wire_single_simd = std::dynamic_pointer_cast<encrypto::motion::proto::bmr::Wire>(
            share_output_simd->GetWires().at(i));
        assert(wire_single_simd);
        output_simd.emplace_back(wire_single_simd->GetPublicValues());
      }
      const T result = encrypto::motion::ToOutput<T>(output);
      const auto result_simd = encrypto::motion::ToVectorOutput<T>(output_simd);

      EXPECT_EQ(result, result_check);
      EXPECT_EQ(result_simd, result_check_simd);
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest, AdditionInGmw) {
  using T = TypeParam;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  std::mt19937 mersenne_twister(sizeof(T));
  std::uniform_int_distribution<T> distribution(0, std::numeric_limits<T>::max());
  auto random = std::bind(distribution, mersenne_twister);
  const std::vector<T> raw_global_input = {random(), random()};
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input.at(0)),
      encrypto::motion::ToInput(raw_global_input.at(1))};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_addition = share_0 + share_1;
      auto share_output = share_addition.Get().Out();

      motion_parties.at(party_id)->Run();

      const T result_check = raw_global_input.at(0) + raw_global_input.at(1);
      std::vector<encrypto::motion::BitVector<>> output;
      for (auto i = 0ull; i < kNumberOfWires; ++i) {
        auto wire_single = std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
            share_output->GetWires().at(i));
        assert(wire_single);
        output.emplace_back(wire_single->GetValues());
      }
      T result = encrypto::motion::ToOutput<T>(output);
      EXPECT_EQ(result, result_check);
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest, AdditionInGarbledCircuit) {
  using T = TypeParam;
  constexpr auto kGc = encrypto::motion::MpcProtocol::kGarbledCircuit;
  std::mt19937 mersenne_twister(sizeof(T));
  std::uniform_int_distribution<T> distribution(0, std::numeric_limits<T>::max());
  auto random = std::bind(distribution, mersenne_twister);
  const std::vector<T> raw_global_input = {random(), random()};
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input.at(0)),
      encrypto::motion::ToInput(raw_global_input.at(1))};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kGc>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kGc>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kGc>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kGc>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_addition = share_0 + share_1;
      auto share_output = share_addition.Out();

      motion_parties.at(party_id)->Run();

      const T result_check = raw_global_input.at(0) + raw_global_input.at(1);
      T result = share_output.As<T>();
      EXPECT_EQ(result, result_check);
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest, SubtractionInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  std::mt19937 mersenne_twister(sizeof(T));
  std::uniform_int_distribution<T> distribution(0, std::numeric_limits<T>::max());
  auto random = std::bind(distribution, mersenne_twister);
  const std::vector<T> raw_global_input = {random(), random()};
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input.at(0)),
      encrypto::motion::ToInput(raw_global_input.at(1))};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_sub = share_0 - share_1;
      auto share_output = share_sub.Get().Out();

      motion_parties.at(party_id)->Run();

      const T result_check = raw_global_input.at(0) - raw_global_input.at(1);
      std::vector<encrypto::motion::BitVector<>> output;
      for (auto i = 0ull; i < kNumberOfWires; ++i) {
        auto wire_single = std::dynamic_pointer_cast<encrypto::motion::proto::bmr::Wire>(
            share_output->GetWires().at(i));
        assert(wire_single);
        output.emplace_back(wire_single->GetPublicValues());
      }
      T result = encrypto::motion::ToOutput<T>(output);
      EXPECT_EQ(result, result_check);
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest, SubtractionInGmw) {
  using T = TypeParam;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  std::mt19937 mersenne_twister(sizeof(T));
  std::uniform_int_distribution<T> distribution(0, std::numeric_limits<T>::max());
  auto random = std::bind(distribution, mersenne_twister);
  const std::vector<T> raw_global_input = {random(), random()};
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input.at(0)),
      encrypto::motion::ToInput(raw_global_input.at(1))};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_sub = share_0 - share_1;
      auto share_output = share_sub.Get().Out();

      motion_parties.at(party_id)->Run();

      const T result_check = raw_global_input.at(0) - raw_global_input.at(1);
      std::vector<encrypto::motion::BitVector<>> output;
      for (auto i = 0ull; i < kNumberOfWires; ++i) {
        auto wire_single = std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
            share_output->GetWires().at(i));
        assert(wire_single);
        output.emplace_back(wire_single->GetValues());
      }
      T result = encrypto::motion::ToOutput<T>(output);
      EXPECT_EQ(result, result_check);
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest, SubtractionInGarbledCircuit) {
  using T = TypeParam;
  constexpr auto kGc = encrypto::motion::MpcProtocol::kGarbledCircuit;
  std::mt19937 mersenne_twister(sizeof(T));
  std::uniform_int_distribution<T> distribution(0, std::numeric_limits<T>::max());
  auto random = std::bind(distribution, mersenne_twister);
  const std::vector<T> raw_global_input = {random(), random()};
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input.at(0)),
      encrypto::motion::ToInput(raw_global_input.at(1))};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kGc>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kGc>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kGc>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kGc>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_sub = share_0 - share_1;
      auto share_output = share_sub.Out();

      motion_parties.at(party_id)->Run();

      const T result_check = raw_global_input.at(0) - raw_global_input.at(1);
      T result = share_output.As<T>();
      EXPECT_EQ(result, result_check);
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest, MultiplicationInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  std::mt19937 mersenne_twister(sizeof(T));
  std::uniform_int_distribution<T> distribution(0, std::numeric_limits<T>::max());
  auto random = std::bind(distribution, mersenne_twister);
  const std::vector<T> raw_global_input = {random(), random()};
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input.at(0)),
      encrypto::motion::ToInput(raw_global_input.at(1))};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_multiplication = share_0 * share_1;
      auto share_output = share_multiplication.Get().Out();

      motion_parties.at(party_id)->Run();

      const T result_check = raw_global_input.at(0) * raw_global_input.at(1);
      std::vector<encrypto::motion::BitVector<>> output;
      for (auto i = 0ull; i < kNumberOfWires; ++i) {
        auto wire_single = std::dynamic_pointer_cast<encrypto::motion::proto::bmr::Wire>(
            share_output->GetWires().at(i));
        assert(wire_single);
        output.emplace_back(wire_single->GetPublicValues());
      }
      T result = encrypto::motion::ToOutput<T>(output);
      EXPECT_EQ(result, result_check);
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest, MultiplicationInGmw) {
  using T = TypeParam;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  std::mt19937 mersenne_twister(sizeof(T));
  // HyCC operates on signed integers, so the max number is not 2^{l}-1, but 2^{l-1}-1
  // let's make the divisor smaller than dividend to get something else than 0/1 from the result
  std::uniform_int_distribution<T> distribution_dividend(std::numeric_limits<T>::max() / 8,
                                                         std::numeric_limits<T>::max() / 2);
  std::uniform_int_distribution<T> distribution_divisor(1, std::numeric_limits<T>::max() / 10);
  auto random_dividend = std::bind(distribution_dividend, mersenne_twister);
  auto random_divisor = std::bind(distribution_divisor, mersenne_twister);
  const std::vector<T> raw_global_input = {random_dividend(), random_divisor()};
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input.at(0)),
      encrypto::motion::ToInput(raw_global_input.at(1))};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_multiplication = share_0 * share_1;
      auto share_output = share_multiplication.Get().Out();

      motion_parties.at(party_id)->Run();

      const T result_check = raw_global_input.at(0) * raw_global_input.at(1);
      std::vector<encrypto::motion::BitVector<>> output;
      for (auto i = 0ull; i < kNumberOfWires; ++i) {
        auto wire_single = std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
            share_output->GetWires().at(i));
        assert(wire_single);
        output.emplace_back(wire_single->GetValues());
      }
      T result = encrypto::motion::ToOutput<T>(output);
      EXPECT_EQ(result, result_check);
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest, MultiplicationInGarbledCircuit) {
  using T = TypeParam;
  constexpr auto kGc = encrypto::motion::MpcProtocol::kGarbledCircuit;
  std::mt19937 mersenne_twister(sizeof(T));
  std::uniform_int_distribution<T> distribution(0, std::numeric_limits<T>::max());
  auto random = std::bind(distribution, mersenne_twister);
  const std::vector<T> raw_global_input = {random(), random()};
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input.at(0)),
      encrypto::motion::ToInput(raw_global_input.at(1))};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kGc>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kGc>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kGc>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kGc>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_addition = share_0 * share_1;
      auto share_output = share_addition.Out();

      motion_parties.at(party_id)->Run();

      const T result_check = raw_global_input.at(0) * raw_global_input.at(1);
      T result = share_output.As<T>();
      EXPECT_EQ(result, result_check);
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest, DivisionInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  std::mt19937 mersenne_twister(sizeof(T));
  // HyCC operates on signed integers, so the max number is not 2^{l}-1, but 2^{l-1}-1
  // let's make the divisor smaller than dividend to get something else than 0/1 from the result
  std::uniform_int_distribution<T> distribution_dividend(std::numeric_limits<T>::max() / 8,
                                                         std::numeric_limits<T>::max() / 2);
  std::uniform_int_distribution<T> distribution_divisor(1, std::numeric_limits<T>::max() / 10);
  auto random_dividend = std::bind(distribution_dividend, mersenne_twister);
  auto random_divisor = std::bind(distribution_divisor, mersenne_twister);
  const std::vector<T> raw_global_input = {random_dividend(), random_divisor()};
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input.at(0)),
      encrypto::motion::ToInput(raw_global_input.at(1))};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_division = share_0 / share_1;
      auto share_output = share_division.Get().Out();

      motion_parties.at(party_id)->Run();

      const T result_check = raw_global_input.at(0) / raw_global_input.at(1);
      std::vector<encrypto::motion::BitVector<>> output;
      for (auto i = 0ull; i < kNumberOfWires; ++i) {
        auto wire_single = std::dynamic_pointer_cast<encrypto::motion::proto::bmr::Wire>(
            share_output->GetWires().at(i));
        assert(wire_single);
        output.emplace_back(wire_single->GetPublicValues());
      }
      T result = encrypto::motion::ToOutput<T>(output);
      EXPECT_EQ(result, result_check);
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest, DivisionInGmw) {
  using T = TypeParam;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  std::mt19937 mersenne_twister(sizeof(T));
  // HyCC operates on signed integers, so the max number is not 2^{l}-1, but 2^{l-1}-1
  // let's make the divisor smaller than dividend to get something else than 0/1 from the result
  std::uniform_int_distribution<T> distribution_dividend(std::numeric_limits<T>::max() / 8,
                                                         std::numeric_limits<T>::max() / 2);
  std::uniform_int_distribution<T> distribution_divisor(1, std::numeric_limits<T>::max() / 10);
  auto random_dividend = std::bind(distribution_dividend, mersenne_twister);
  auto random_divisor = std::bind(distribution_divisor, mersenne_twister);

  const std::vector<T> raw_global_input = {random_dividend(), random_divisor()};
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input.at(0)),
      encrypto::motion::ToInput(raw_global_input.at(1))};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);
      EXPECT_EQ(share_1.Get()->GetBitLength(), kNumberOfWires);

      const auto share_division = share_0 / share_1;
      auto share_output = share_division.Get().Out();

      motion_parties.at(party_id)->Run();

      const T result_check = raw_global_input.at(0) / raw_global_input.at(1);
      std::vector<encrypto::motion::BitVector<>> output;
      for (auto i = 0ull; i < kNumberOfWires; ++i) {
        auto wire_single = std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
            share_output->GetWires().at(i));
        assert(wire_single);
        output.emplace_back(wire_single->GetValues());
      }
      T result = encrypto::motion::ToOutput<T>(output);
      EXPECT_EQ(result, result_check);
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest, DivisionInGarbledCircuit) {
  using T = TypeParam;
  constexpr auto kGc = encrypto::motion::MpcProtocol::kGarbledCircuit;
  std::mt19937 mersenne_twister(sizeof(T));
  // HyCC operates on signed integers, so the max number is not 2^{l}-1, but 2^{l-1}-1
  // let's make the divisor smaller than dividend to get something else than 0/1 from the result
  std::uniform_int_distribution<T> distribution_dividend(std::numeric_limits<T>::max() / 8,
                                                         std::numeric_limits<T>::max() / 2);
  std::uniform_int_distribution<T> distribution_divisor(1, std::numeric_limits<T>::max() / 10);
  auto random_dividend = std::bind(distribution_dividend, mersenne_twister);
  auto random_divisor = std::bind(distribution_divisor, mersenne_twister);

  const std::vector<T> raw_global_input = {random_dividend(), random_divisor()};
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input.at(0)),
      encrypto::motion::ToInput(raw_global_input.at(1))};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kGc>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kGc>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kGc>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kGc>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);
      EXPECT_EQ(share_1.Get()->GetBitLength(), kNumberOfWires);

      const auto share_division = share_0 / share_1;
      auto share_output = share_division.Out();

      motion_parties.at(party_id)->Run();

      const T result_check = raw_global_input.at(0) / raw_global_input.at(1);
      T result = share_output.As<T>();
      EXPECT_EQ(result, result_check);
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest, EqualityInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  std::mt19937 mersenne_twister(sizeof(T));
  std::uniform_int_distribution<T> distribution(0, std::numeric_limits<T>::max());
  auto random = std::bind(distribution, mersenne_twister);
  const std::vector<T> raw_global_input = {random(), random()};
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input.at(0)),
      encrypto::motion::ToInput(raw_global_input.at(1))};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_equal = share_0 == share_1;
      auto share_output = share_equal.Out();
      assert(share_output->GetBitLength() == 1);

      motion_parties.at(party_id)->Run();

      std::vector<encrypto::motion::BitVector<>> output;
      auto wire_single = std::dynamic_pointer_cast<encrypto::motion::proto::bmr::Wire>(
          share_output->GetWires().at(0));
      assert(wire_single);
      const bool result_check = raw_global_input.at(0) == raw_global_input.at(1);
      const bool result = wire_single->GetPublicValues()[0];
      EXPECT_EQ(result, result_check);

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest, EqualityInGmw) {
  using T = TypeParam;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  std::mt19937 mersenne_twister(sizeof(T));
  std::uniform_int_distribution<T> distribution(0, std::numeric_limits<T>::max());
  auto random = std::bind(distribution, mersenne_twister);
  const std::vector<T> raw_global_input = {random(), random()};
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input.at(0)),
      encrypto::motion::ToInput(raw_global_input.at(1))};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_equal = share_0 == share_1;
      auto share_output = share_equal.Out();
      assert(share_output->GetBitLength() == 1);

      motion_parties.at(party_id)->Run();

      std::vector<encrypto::motion::BitVector<>> output;
      auto wire_single = std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
          share_output->GetWires().at(0));
      assert(wire_single);
      const bool result_check = raw_global_input.at(0) == raw_global_input.at(1);
      const bool result = wire_single->GetValues()[0];
      EXPECT_EQ(result, result_check);

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest, EqualityInGarbledCircuit) {
  using T = TypeParam;
  constexpr auto kGc = encrypto::motion::MpcProtocol::kGarbledCircuit;
  std::mt19937 mersenne_twister(sizeof(T));
  std::uniform_int_distribution<T> distribution(0, std::numeric_limits<T>::max());
  auto random = std::bind(distribution, mersenne_twister);
  const std::vector<T> raw_global_input = {random(), random()};
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input.at(0)),
      encrypto::motion::ToInput(raw_global_input.at(1))};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kGc>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kGc>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kGc>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kGc>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_equal = share_0 == share_1;
      auto share_output = share_equal.Out();
      assert(share_output->GetBitLength() == 1);

      motion_parties.at(party_id)->Run();

      const bool result_check = raw_global_input.at(0) == raw_global_input.at(1);
      const bool result = share_output.As<bool>();
      EXPECT_EQ(result, result_check);

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest, GreaterThanInGmw) {
  using T = TypeParam;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  std::mt19937 mersenne_twister(sizeof(T));
  std::uniform_int_distribution<T> distribution(0, std::numeric_limits<T>::max() / 2);
  auto random = std::bind(distribution, mersenne_twister);
  const std::vector<T> raw_global_input = {random(), random()};
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input.at(0)),
      encrypto::motion::ToInput(raw_global_input.at(1))};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);
      EXPECT_EQ(share_1.Get()->GetBitLength(), kNumberOfWires);

      const auto share_greater = share_0 > share_1;
      auto share_output = share_greater.Out();
      assert(share_output->GetBitLength() == 1);

      motion_parties.at(party_id)->Run();

      std::vector<encrypto::motion::BitVector<>> output;
      auto wire_single = std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(
          share_output->GetWires().at(0));
      assert(wire_single);
      const bool result_check = raw_global_input.at(0) > raw_global_input.at(1);
      const bool result = wire_single->GetValues()[0];
      EXPECT_EQ(result, result_check);

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest, GreaterThanInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  std::mt19937 mersenne_twister(sizeof(T));
  std::uniform_int_distribution<T> distribution(0, std::numeric_limits<T>::max() / 2);
  auto random = std::bind(distribution, mersenne_twister);
  const std::vector<T> raw_global_input = {random(), random()};
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input.at(0)),
      encrypto::motion::ToInput(raw_global_input.at(1))};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);
      EXPECT_EQ(share_1.Get()->GetBitLength(), kNumberOfWires);

      const auto share_greater = share_0 > share_1;
      auto share_output = share_greater.Out();

      motion_parties.at(party_id)->Run();

      std::vector<encrypto::motion::BitVector<>> output;
      auto wire_single = std::dynamic_pointer_cast<encrypto::motion::proto::bmr::Wire>(
          share_output->GetWires().at(0));
      assert(wire_single);
      const bool result_check = raw_global_input.at(0) > raw_global_input.at(1);
      const bool result = wire_single->GetPublicValues()[0];
      EXPECT_EQ(result, result_check);

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest, GreaterThanInGarbledCircuit) {
  using T = TypeParam;
  constexpr auto kGc = encrypto::motion::MpcProtocol::kGarbledCircuit;
  std::mt19937 mersenne_twister(sizeof(T));
  std::uniform_int_distribution<T> distribution(0, std::numeric_limits<T>::max() / 2);
  auto random = std::bind(distribution, mersenne_twister);
  const std::vector<T> raw_global_input = {random(), random()};
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input.at(0)),
      encrypto::motion::ToInput(raw_global_input.at(1))};
  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
                          &raw_global_input]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 = party_0 ? motion_parties.at(party_id)->In<kGc>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kGc>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kGc>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kGc>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);
      EXPECT_EQ(share_1.Get()->GetBitLength(), kNumberOfWires);

      const auto share_greater = share_0 > share_1;
      auto share_output = share_greater.Out();

      motion_parties.at(party_id)->Run();

      const bool result_check = raw_global_input.at(0) > raw_global_input.at(1);
      const bool result = share_output.As<bool>();
      EXPECT_EQ(result, result_check);

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest, AsUintInArithmeticGmw) {
  using T = TypeParam;
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  std::mt19937 mersenne_twister(sizeof(T));
  std::uniform_int_distribution<T> distribution(0, std::numeric_limits<T>::max());
  auto random = std::bind(distribution, mersenne_twister);
  const T input = random(), dummy_input = random();

  std::vector<PartyPointer> parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }

  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < parties.size(); ++party_id) {
    threads.emplace_back([party_id, &parties, input, dummy_input]() {
      const bool party_0 = parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger share =
          party_0 ? parties.at(party_id)->In<kArithmeticGmw>(input, 0)
                  : parties.at(party_id)->In<kArithmeticGmw>(dummy_input, 0);
      auto share_output = share.Out();

      parties.at(party_id)->Run();
      const T result = share_output.As<T>();

      EXPECT_EQ(result, input);
      parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest, AsUintVectorInArithmeticGmw) {
  using T = TypeParam;
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  std::mt19937 mersenne_twister(sizeof(T));
  std::uniform_int_distribution<T> distribution(0, std::numeric_limits<T>::max());
  auto random = std::bind(distribution, mersenne_twister);
  const auto input_size = 10;
  std::vector<T> input(input_size), dummy_input(input_size);
  for (std::size_t size = 0; size < input_size; size++) {
    input.emplace_back(random());
    dummy_input.emplace_back(random());
  }

  std::vector<PartyPointer> parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }

  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < parties.size(); ++party_id) {
    threads.emplace_back([party_id, &parties, input, dummy_input]() {
      const bool party_0 = parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger share =
          party_0 ? parties.at(party_id)->In<kArithmeticGmw>(input, 0)
                  : parties.at(party_id)->In<kArithmeticGmw>(dummy_input, 0);
      auto share_output = share.Out();

      parties.at(party_id)->Run();
      const std::vector<T> result = share_output.As<std::vector<T>>();

      EXPECT_EQ(result.size(), input.size());
      for (std::size_t i = 0; i < result.size(); i++) EXPECT_EQ(result.at(i), input.at(i));
      parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest, AsUintInBooleanGmw) {
  using T = TypeParam;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  std::mt19937 mersenne_twister(sizeof(T));
  std::uniform_int_distribution<T> distribution(0, std::numeric_limits<T>::max());
  auto random = std::bind(distribution, mersenne_twister);
  const T input = random(), dummy_input = random();

  std::vector<PartyPointer> parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }

  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < parties.size(); ++party_id) {
    threads.emplace_back([party_id, &parties, input, dummy_input]() {
      const bool party_0 = parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger share =
          party_0
              ? parties.at(party_id)->In<kBooleanGmw>(encrypto::motion::ToInput(input), 0)
              : parties.at(party_id)->In<kBooleanGmw>(encrypto::motion::ToInput(dummy_input), 0);
      auto share_output = share.Out();

      parties.at(party_id)->Run();
      const T result = share_output.As<T>();

      EXPECT_EQ(result, input);
      parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest, AsUintInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  std::mt19937 mersenne_twister(sizeof(T));
  std::uniform_int_distribution<T> distribution(0, std::numeric_limits<T>::max());
  auto random = std::bind(distribution, mersenne_twister);
  const T input = random(), dummy_input = random();

  std::vector<PartyPointer> parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }

  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < parties.size(); ++party_id) {
    threads.emplace_back([party_id, &parties, input, dummy_input]() {
      const bool party_0 = parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger share =
          party_0 ? parties.at(party_id)->In<kBmr>(encrypto::motion::ToInput(input), 0)
                  : parties.at(party_id)->In<kBmr>(encrypto::motion::ToInput(dummy_input), 0);
      auto share_output = share.Out();

      parties.at(party_id)->Run();
      const T result = share_output.As<T>();

      EXPECT_EQ(result, input);
      parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest, AsUintInGarbledCircuit) {
  using T = TypeParam;
  constexpr auto kGc = encrypto::motion::MpcProtocol::kGarbledCircuit;
  std::mt19937 mersenne_twister(sizeof(T));
  std::uniform_int_distribution<T> distribution(0, std::numeric_limits<T>::max());
  auto random = std::bind(distribution, mersenne_twister);
  const T input = random(), dummy_input = random();

  std::vector<PartyPointer> parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }

  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < parties.size(); ++party_id) {
    threads.emplace_back([party_id, &parties, input, dummy_input]() {
      const bool party_0 = parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger share =
          party_0 ? parties.at(party_id)->In<kGc>(encrypto::motion::ToInput(input), 0)
                  : parties.at(party_id)->In<kGc>(encrypto::motion::ToInput(dummy_input), 0);
      auto share_output = share.Out();

      parties.at(party_id)->Run();
      const T result = share_output.As<T>();

      EXPECT_EQ(result, input);
      parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

template <typename T>
struct PartySharedInTest : public testing::Test {};

TYPED_TEST_SUITE(PartySharedInTest, all_uints);

TYPED_TEST(PartySharedInTest, SharedInArithmeticGmw) {
  using T = TypeParam;
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  std::mt19937 mersenne_twister(sizeof(T));
  std::uniform_int_distribution<T> distribution(0, std::numeric_limits<T>::max());
  auto random = std::bind(distribution, mersenne_twister);
  auto test_number_of_parties = std::vector<std::size_t>{2, 4, 6};

  for (auto number_of_parties : test_number_of_parties) {
    std::vector<T> input;
    T subtract = 0;

    const T expected = random();
    for (std::size_t i = 0; i < number_of_parties - 1; i++) {
      input.push_back(random());
      subtract += input.at(i);
    }
    input.push_back(static_cast<T>(expected - subtract));

    std::vector<PartyPointer> parties(
        std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
    for (auto& party : parties) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      party->GetConfiguration()->SetOnlineAfterSetup(true);
    }

    std::vector<std::thread> threads;
    for (auto party_id = 0u; party_id < number_of_parties; ++party_id) {
      threads.emplace_back([party_id, expected, &parties, &input]() {
        const auto my_id = parties.at(party_id)->GetConfiguration()->GetMyId();
        encrypto::motion::SecureUnsignedInteger share =
            parties.at(my_id)->SharedIn<kArithmeticGmw>(input.at(my_id));
        auto share_output = share.Out();

        parties.at(my_id)->Run();
        const T result = share_output.As<T>();

        EXPECT_EQ(result, expected);
        parties.at(my_id)->Finish();
      });
    }
    for (auto& t : threads)
      if (t.joinable()) t.join();
  }
}

TYPED_TEST(PartySharedInTest, SharedInVectorArithmeticGmw) {
  using T = TypeParam;
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  std::mt19937 mersenne_twister(sizeof(T));
  std::uniform_int_distribution<T> distribution(0, std::numeric_limits<T>::max());
  auto random = std::bind(distribution, mersenne_twister);
  const auto input_size = 10;
  auto test_number_of_parties = std::vector<std::size_t>{2, 4, 6};

  for (auto number_of_parties : test_number_of_parties) {
    std::vector<std::vector<T>> input;
    std::vector<T> expected(input_size, random()), subtract(input_size);

    for (std::size_t i = 0; i < number_of_parties - 1; i++) {
      std::vector<T> each_input(input_size, random());
      input.push_back(each_input);
      for (std::size_t j = 0; j < input_size; j++) {
        subtract.at(j) += each_input.at(j);
      }
    }

    std::vector<T> party_input;
    for (std::size_t i = 0; i < input_size; i++) {
      party_input.push_back(static_cast<T>(expected.at(i) - subtract.at(i)));
    }
    input.push_back(party_input);

    std::vector<PartyPointer> parties(
        std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
    for (auto& party : parties) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      party->GetConfiguration()->SetOnlineAfterSetup(true);
    }

    std::vector<std::thread> threads;
    for (auto party_id = 0u; party_id < parties.size(); ++party_id) {
      threads.emplace_back([party_id, expected, &parties, &input]() {
        const auto my_id = parties.at(party_id)->GetConfiguration()->GetMyId();
        encrypto::motion::SecureUnsignedInteger share =
            parties.at(my_id)->SharedIn<kArithmeticGmw>(input.at(my_id));
        auto share_output = share.Out();

        parties.at(my_id)->Run();
        const std::vector<T> result = share_output.As<std::vector<T>>();

        EXPECT_EQ(result.size(), expected.size());
        for (std::size_t i = 0; i < result.size(); i++) EXPECT_EQ(result.at(i), expected.at(i));
        parties.at(my_id)->Finish();
      });
    }
    for (auto& t : threads)
      if (t.joinable()) t.join();
  }
}

TYPED_TEST(PartySharedInTest, SharedInBooleanGmw) {
  using T = TypeParam;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  std::mt19937 mersenne_twister(sizeof(T));
  std::uniform_int_distribution<T> distribution(0, std::numeric_limits<T>::max());
  auto random = std::bind(distribution, mersenne_twister);
  auto test_number_of_parties = std::vector<std::size_t>{2, 4, 6};

  for (auto number_of_parties : test_number_of_parties) {
    std::vector<T> input;
    T subtract = 0;

    const T expected = random();
    for (std::size_t i = 0; i < number_of_parties - 1; i++) {
      input.push_back(random());
      subtract ^= input.at(i);
    }
    input.push_back(static_cast<T>(expected ^ subtract));

    std::vector<PartyPointer> parties(
        std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
    for (auto& party : parties) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      party->GetConfiguration()->SetOnlineAfterSetup(true);
    }

    std::vector<std::thread> threads;
    for (auto party_id = 0u; party_id < parties.size(); ++party_id) {
      threads.emplace_back([party_id, expected, &parties, &input]() {
        const auto my_id = parties.at(party_id)->GetConfiguration()->GetMyId();
        encrypto::motion::SecureUnsignedInteger share =
            parties.at(party_id)->SharedIn<kBooleanGmw>(encrypto::motion::ToInput(input.at(my_id)));
        auto share_output = share.Out();

        parties.at(my_id)->Run();
        const T result = share_output.As<T>();

        EXPECT_EQ(result, expected);
        parties.at(my_id)->Finish();
      });
    }
    for (auto& t : threads)
      if (t.joinable()) t.join();
  }
}

}  // namespace
