// MIT License
//
// Copyright (c) 2022 Liang Zhao
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
#include "protocols/bmr/bmr_wire.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/share_wrapper.h"
#include "secure_type/secure_unsigned_integer.h"
#include "test_constants.h"
#include "test_helpers.h"
#include "utility/config.h"

using namespace encrypto::motion;

namespace {
TEST(AlgorithmDescription, FromBristolFormatIntAdd8Size) {
  const auto uint_add8 = encrypto::motion::AlgorithmDescription::FromBristol(
      std::string(encrypto::motion::kRootDir) +
      "/circuits/unsigned_integer/uint8_add_size.bristol");
  EXPECT_EQ(uint_add8.number_of_gates, 34);
  EXPECT_EQ(uint_add8.gates.size(), 34);
  EXPECT_EQ(uint_add8.number_of_output_wires, 8);
  EXPECT_EQ(uint_add8.number_of_input_wires_parent_a, 8);
  ASSERT_NO_THROW([&uint_add8]() { EXPECT_EQ(*uint_add8.number_of_input_wires_parent_b, 8); }());
  EXPECT_EQ(uint_add8.number_of_wires, 50);

  const auto& gate0 = uint_add8.gates.at(0);
  EXPECT_EQ(gate0.parent_a, 0);
  ASSERT_NO_THROW([&gate0]() { EXPECT_EQ(*gate0.parent_b, 8); }());
  EXPECT_EQ(gate0.output_wire, 42);
  // EXPECT_EQ(gate0.type, encrypto::motion::PrimitiveOperationType::kXor); // compile errors
  EXPECT_EQ((gate0.type == encrypto::motion::PrimitiveOperationType::kXor), 1);

  EXPECT_EQ(gate0.selection_bit.has_value(), false);

  const auto& gate1 = uint_add8.gates.at(1);
  EXPECT_EQ(gate1.parent_a, 0);
  ASSERT_NO_THROW([&gate1]() { EXPECT_EQ(*gate1.parent_b, 8); }());
  EXPECT_EQ(gate1.output_wire, 16);
  // EXPECT_EQ(gate1.type, encrypto::motion::PrimitiveOperationType::kAnd); // compile errors
  EXPECT_EQ((gate1.type == encrypto::motion::PrimitiveOperationType::kAnd), 1);
  EXPECT_EQ(gate1.selection_bit.has_value(), false);

  const auto& gate32 = uint_add8.gates.at(32);
  EXPECT_EQ(gate32.parent_a, 15);
  ASSERT_NO_THROW([&gate32]() { EXPECT_EQ(*gate32.parent_b, 40); }());
  EXPECT_EQ(gate32.output_wire, 41);
  // EXPECT_EQ(gate32.type, encrypto::motion::PrimitiveOperationType::kXor); // compile errors
  EXPECT_EQ((gate32.type == encrypto::motion::PrimitiveOperationType::kXor), 1);
  EXPECT_EQ(gate32.selection_bit.has_value(), false);

  const auto& gate33 = uint_add8.gates.at(33);
  EXPECT_EQ(gate33.parent_a, 7);
  ASSERT_NO_THROW([&gate33]() { EXPECT_EQ(*gate33.parent_b, 41); }());
  EXPECT_EQ(gate33.output_wire, 49);
  // EXPECT_EQ(gate33.type, encrypto::motion::PrimitiveOperationType::kXor); // compile errors
  EXPECT_EQ((gate33.type == encrypto::motion::PrimitiveOperationType::kXor), 1);
  EXPECT_EQ(gate33.selection_bit.has_value(), false);
}
template <typename T>
class SecureUintTest_8_16_32_64_gc : public ::testing::Test {};

template <typename T>
class SecureUintTest_8_16_32_64_128_gc : public ::testing::Test {};

template <typename T>
class SecureUintTest_32_64_gc : public ::testing::Test {};

using uint_32_64 = ::testing::Types<std::uint32_t, std::uint64_t>;
using uint_8_16_32_64 = ::testing::Types<std::uint8_t, std::uint16_t, std::uint32_t, std::uint64_t>;

using uint_8_16_32_64_128 =
    ::testing::Types<std::uint8_t, std::uint16_t, std::uint32_t, std::uint64_t, __uint128_t>;

TYPED_TEST_SUITE(SecureUintTest_32_64_gc, uint_32_64);

TYPED_TEST_SUITE(SecureUintTest_8_16_32_64_128_gc, uint_8_16_32_64_128);

TYPED_TEST(SecureUintTest_8_16_32_64_128_gc, AdditionSIMDInGC) {
  using T = TypeParam;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;

  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = 0;
  T max = T(1) << (sizeof(T) * 8 - 1);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  const std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
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
                          &raw_global_input_1, &raw_global_input_2]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 =
              party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                      : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0
                        ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                        : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 + share_1;
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const T expect_result = raw_global_input_1.at(i) + raw_global_input_2.at(i);
        std::vector<T> result = share_output.AsVector<T>();

        EXPECT_EQ(result[i], expect_result);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest_8_16_32_64_128_gc, AdditionConstantSIMDInGC) {
  using T = TypeParam;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;

  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = 0;
  T max = T(1) << (sizeof(T) * 8 - 1);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  const std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
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
                          &raw_global_input_1, &raw_global_input_2]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 =
              party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                      : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0
                        ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                        : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      encrypto::motion::SecureUnsignedInteger share_result = share_0 + raw_global_input_2.at(0);
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const T expect_result = raw_global_input_1.at(i) + raw_global_input_2.at(0);
        std::vector<T> result = share_output.AsVector<T>();

        EXPECT_EQ(result[i], expect_result);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest_8_16_32_64_128_gc, SubtractionSIMDInGC) {
  using T = TypeParam;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;

  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = 0;
  T max = T(1) << (sizeof(T) * 8 - 1);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  const std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
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
                          &raw_global_input_1, &raw_global_input_2]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 =
              party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                      : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0
                        ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                        : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 - share_1;
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const T expect_result = raw_global_input_1.at(i) - raw_global_input_2.at(i);
        std::vector<T> result = share_output.AsVector<T>();

        EXPECT_EQ(result[i], expect_result);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest_8_16_32_64_128_gc, MultiplicationSIMDInGC) {
  using T = TypeParam;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;

  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
  std::srand(time(nullptr));

  T min = 0;
  T max = T(1) << (sizeof(T) * 8 - 1);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  const std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
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
                          &raw_global_input_1, &raw_global_input_2]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 =
              party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                      : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0
                        ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                        : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 * share_1;
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const T expect_result = raw_global_input_1.at(i) * raw_global_input_2.at(i);
        std::vector<T> result = share_output.AsVector<T>();

        EXPECT_EQ(result[i], expect_result);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest_8_16_32_64_128_gc, DivisionSIMDInGC) {
  using T = TypeParam;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;

  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
  std::srand(time(nullptr));

  T min = 1;
  T max = T(1) << (sizeof(T) * 8 - 1);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  const std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
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
                          &raw_global_input_1, &raw_global_input_2]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 =
              party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                      : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0
                        ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                        : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 / share_1;
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const T expect_result = raw_global_input_1.at(i) / raw_global_input_2.at(i);
        std::vector<T> result = share_output.AsVector<T>();

        EXPECT_EQ(result[i], expect_result);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest_8_16_32_64_128_gc, LessThanSIMDInGC) {
  using T = TypeParam;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;

  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = 0;
  T max = T(1) << (sizeof(T) * 8 - 1);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  const std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
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
                          &raw_global_input_1, &raw_global_input_2]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 =
              party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                      : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0
                        ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                        : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 < share_1;
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const bool expect_result = raw_global_input_1.at(i) < raw_global_input_2.at(i);
        BitVector<> result = share_output.As<BitVector<>>();

        EXPECT_EQ(result[i], expect_result);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest_8_16_32_64_128_gc, GreaterThanSIMDInGC) {
  using T = TypeParam;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;

  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = 0;
  T max = T(1) << (sizeof(T) * 8 - 1);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  const std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
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
                          &raw_global_input_1, &raw_global_input_2]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 =
              party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                      : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0
                        ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                        : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 > share_1;
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const bool expect_result = raw_global_input_1.at(i) > raw_global_input_2.at(i);
        BitVector<> result = share_output.As<BitVector<>>();

        EXPECT_EQ(result[i], expect_result);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest_8_16_32_64_128_gc, EqualitySIMDInGC) {
  using T = TypeParam;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;

  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = 0;
  T max = T(1) << (sizeof(T) * 8 - 1);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  const std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
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
                          &raw_global_input_1, &raw_global_input_2]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 =
              party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                      : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0
                        ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                        : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 == share_1;
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const bool expect_result = raw_global_input_1.at(i) == raw_global_input_2.at(i);
        BitVector<> result = share_output.As<BitVector<>>();

        EXPECT_EQ(result[i], expect_result);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest_8_16_32_64_128_gc, MulBooleanBitSIMDInGC) {
  using T = TypeParam;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;

  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = 0;
  T max = T(1) << (sizeof(T) * 8 - 1);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  std::vector<bool> raw_global_input_2 = RandomBoolVector(kNumberOfSimd);
  std::vector<bool> raw_global_input_3 = RandomBoolVector(kNumberOfSimd);

  BitVector<> boolean_bit = BitVector(raw_global_input_2);
  BitVector<> dummy_boolean_bit = boolean_bit ^ boolean_bit;

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1)};
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
                          &raw_global_input_1, &boolean_bit, &dummy_boolean_bit]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      // encrypto::motion::SecureUnsignedInteger
      //     share_0 =
      //         party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
      //                 : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
      //     share_1 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_boolean_bit, 1)
      //                       : motion_parties.at(party_id)->In<kGarbledCircuit>(boolean_bit, 1);

      // only for debugging
      encrypto::motion::SecureUnsignedInteger
          share_0 =
              party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                      : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(boolean_bit, 1)
                            : motion_parties.at(party_id)->In<kGarbledCircuit>(boolean_bit, 1);

      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.MulBooleanBit(share_1.Get());
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const T expect_result = raw_global_input_1.at(i) * (boolean_bit[i]);
        std::vector<T> result = share_output.AsVector<T>();

        EXPECT_EQ(result[i], expect_result);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest_8_16_32_64_128_gc, IsZeroSIMDInGC) {
  using T = TypeParam;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;

  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = 0;
  T max = T(1) << (sizeof(T) * 8 - 1);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  const std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
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
                          &raw_global_input_1, &raw_global_input_2]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 =
              party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                      : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0
                        ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                        : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.IsZero();
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const bool expect_result = raw_global_input_1.at(i) == 0;
        BitVector<> result = share_output.As<BitVector<>>();

        EXPECT_EQ(result[i], expect_result);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest_8_16_32_64_128_gc, GESIMDInGC) {
  using T = TypeParam;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;

  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = 0;
  T max = T(1) << (sizeof(T) * 8 - 1);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  const std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
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
                          &raw_global_input_1, &raw_global_input_2]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 =
              party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                      : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0
                        ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                        : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.GE(share_1);
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const bool expect_result = raw_global_input_1.at(i) >= raw_global_input_2.at(i);
        BitVector<> result = share_output.As<BitVector<>>();

        EXPECT_EQ(result[i], expect_result);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest_8_16_32_64_128_gc, LESIMDInGC) {
  using T = TypeParam;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;

  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = 0;
  T max = T(1) << (sizeof(T) * 8 - 1);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  const std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
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
                          &raw_global_input_1, &raw_global_input_2]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 =
              party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                      : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0
                        ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                        : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.LE(share_1);
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const bool expect_result = raw_global_input_1.at(i) <= raw_global_input_2.at(i);
        BitVector<> result = share_output.As<BitVector<>>();

        EXPECT_EQ(result[i], expect_result);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest_8_16_32_64_128_gc, ObliviousModSIMDInGC) {
  using T = TypeParam;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = 0;
  T max = T(1) << (sizeof(T) * 8 - 1);
  std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(T(1), max, kNumberOfSimd);

  // // only for debugging
  // raw_global_input_2[0]=1000;

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
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
                          &raw_global_input_1, &raw_global_input_2]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 =
              party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                      : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0
                        ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                        : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Mod(share_1);
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const T expect_result = raw_global_input_1.at(i) % raw_global_input_2.at(i);
        std::vector<T> result = share_output.AsVector<T>();

        EXPECT_EQ(result[i], expect_result);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest_8_16_32_64_128_gc, ModSIMDInGC) {
  using T = TypeParam;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;

  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = 0;
  T max = T(1) << (sizeof(T) * 8 - 1);

  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  const std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(T(1), max, kNumberOfSimd);
  std::size_t m = raw_global_input_2[0];

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
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
                          &raw_global_input_1, &raw_global_input_2, &m]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 =
              party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                      : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0
                        ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                        : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      encrypto::motion::SecureUnsignedInteger share_result = share_0.Mod(raw_global_input_2.at(0));
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const T expect_result = raw_global_input_1.at(i) % raw_global_input_2.at(0);
        std::vector<T> result = share_output.AsVector<T>();
        EXPECT_EQ(result[i], expect_result);
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest_8_16_32_64_128_gc, NegSIMDInGC) {
  using T = TypeParam;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;

  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = 0;
  T max = T(1) << (sizeof(T) * 8 - 1);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  const std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  std::size_t m = raw_global_input_2[0];

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
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
                          &raw_global_input_1, &m]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 =
              party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                      : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0
                        ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                        : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Neg();
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const T expect_result = -raw_global_input_1[i];
        std::vector<T> result = share_output.AsVector<T>();

        EXPECT_EQ(result[i], expect_result);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest_8_16_32_64_128_gc, NegConditionSIMDInGC) {
  using T = TypeParam;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;

  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = 0;
  T max = T(1) << (sizeof(T) * 8 - 3);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  // std::vector<bool> raw_global_input_2 = RandomBoolVector(kNumberOfSimd);

  BitVector<> boolean_bit = encrypto::motion::BitVector<>::SecureRandom(kNumberOfSimd);
  BitVector<> dummy_boolean_bit = boolean_bit ^ boolean_bit;

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1)};
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
                          &raw_global_input_1, &boolean_bit, &dummy_boolean_bit]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureSignedInteger share_0 =
          party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                  : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0);
      encrypto::motion::ShareWrapper share_1 =
          party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_boolean_bit, 1)
                  : motion_parties.at(party_id)->In<kGarbledCircuit>(boolean_bit, 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Neg(share_1);
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const T expect_result = (1 - 2 * boolean_bit[i]) * (raw_global_input_1.at(i));
        std::vector<T> result = share_output.AsVector<T>();

        EXPECT_EQ((result[i]), expect_result);
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest_32_64_gc, Int2FLSIMDInGC) {
  using T = TypeParam;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;

  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  T min = 0;
  T max = T(1) << (sizeof(T) * 8 - 1);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  const std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
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
                          &raw_global_input_1, &raw_global_input_2]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 =
              party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                      : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0
                        ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                        : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result_32 = share_0.Int2FL(32);
      const auto share_result_64 = share_0.Int2FL(64);
      auto share_output_32 = share_result_32.Out();
      auto share_output_64 = share_result_64.Out();

      // std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      // std::cout << "party finish" << std::endl;

      std::vector<float> result_32 = share_output_32.AsFloatingPointVector<float>();
      std::vector<double> result_64 = share_output_64.AsFloatingPointVector<double>();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const float expect_result_32 = float(raw_global_input_1.at(i));
        const double expect_result_64 = double(raw_global_input_1.at(i));

        EXPECT_EQ(result_32[i], expect_result_32);
        EXPECT_EQ(result_64[i], expect_result_64);
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureUintTest_32_64_gc, Int2FxSIMDInGC) {
  using T = std::uint64_t;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;

  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};
  std::srand(time(nullptr));

  std::size_t fixed_point_fraction_part_bit_length = 16;

  T min = 0;
  T max = T(1) << (sizeof(T) * 8 - 1 - fixed_point_fraction_part_bit_length);
  const std::vector<T> raw_global_input_1 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);
  const std::vector<T> raw_global_input_2 = RandomRangeIntegerVector<T>(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput(raw_global_input_1), encrypto::motion::ToInput(raw_global_input_2)};
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
                          &raw_global_input_1, &raw_global_input_2,
                          &fixed_point_fraction_part_bit_length]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureUnsignedInteger
          share_0 =
              party_0 ? motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(0), 0)
                      : motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 0),
          share_1 = party_0
                        ? motion_parties.at(party_id)->In<kGarbledCircuit>(dummy_input, 1)
                        : motion_parties.at(party_id)->In<kGarbledCircuit>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Int2Fx(fixed_point_fraction_part_bit_length);
      auto share_output = share_result.Out();

      // std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      // std::cout << "party finish" << std::endl;

      std::vector<double> result = share_output.AsFixedPointVector<std::uint64_t, std::int64_t>();

      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        const double expect_result = double(raw_global_input_1.at(i));
        EXPECT_EQ(result[i], expect_result);
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

// remove later
// template <typename T>
// struct PartySharedInGCTest : public testing::Test {};

// TYPED_TEST_SUITE(PartySharedInGCTest, uint_8_16_32_64_128);

// TYPED_TEST(PartySharedInGCTest, PublicInGC) {
//   using T = TypeParam;
//   constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
//   std::mt19937 mersenne_twister(sizeof(T));
//   std::uniform_int_distribution<T> distribution(0, std::numeric_limits<T>::max());
//   auto random = std::bind(distribution, mersenne_twister);
//   auto test_number_of_parties = std::vector<std::size_t>{2, 4, 6};

//   std::size_t num_of_simd = 10;

//   for (auto number_of_parties : test_number_of_parties) {
//     std::vector<T> input;

//     const std::vector<T> expected = ::RandomVector<T>(num_of_simd);
//     input = expected;

//     std::vector<PartyPointer> parties(
//         std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
//     for (auto& party : parties) {
//       party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
//       party->GetConfiguration()->SetOnlineAfterSetup(true);
//     }

//     std::vector<std::thread> threads;
//     for (auto party_id = 0u; party_id < parties.size(); ++party_id) {
//       threads.emplace_back([party_id, expected, &parties, &input, &num_of_simd]() {
//         const auto my_id = parties.at(party_id)->GetConfiguration()->GetMyId();
//         encrypto::motion::SecureUnsignedInteger share =
//             parties.at(party_id)->PublicIn<kGarbledCircuit>(encrypto::motion::ToInput(input));
//         auto share_output = share.Out();

//         parties.at(my_id)->Run();
//         const std::vector<T> result = share_output.As<std::vector<T>>();
//         EXPECT_EQ(result, expected);

//         parties.at(my_id)->Finish();
//       });
//     }
//     for (auto& t : threads)
//       if (t.joinable()) t.join();
//   }
// }

}  // namespace
