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
#include "test_helpers.h"
#include "utility/config.h"

#include "test_constants.h"

using namespace encrypto::motion;

namespace {
TEST(AlgorithmDescription, FromBristolFormatIntAdd8Size) {
  const auto uint_add8 = encrypto::motion::AlgorithmDescription::FromBristol(
      std::string(encrypto::motion::kRootDir) +
      "/circuits/unsigned_integer_HyCC/uint8_add_size.bristol");
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
class SecureUintTest_8_16_32_64_bmr : public ::testing::Test {};

template <typename T>
class SecureUintTest_8_16_32_64_128_bmr : public ::testing::Test {};

template <typename T>
class SecureUintTest_32_64_bmr : public ::testing::Test {};

using uint_32_64 = ::testing::Types<std::uint32_t, std::uint64_t>;
using uint_8_16_32_64 = ::testing::Types<std::uint8_t, std::uint16_t, std::uint32_t, std::uint64_t>;

using uint_8_16_32_64_128 =
    ::testing::Types<std::uint8_t, std::uint16_t, std::uint32_t, std::uint64_t, __uint128_t>;

TYPED_TEST_SUITE(SecureUintTest_32_64_bmr, uint_32_64);

TYPED_TEST_SUITE(SecureUintTest_8_16_32_64_128_bmr, uint_8_16_32_64_128);

TYPED_TEST(SecureUintTest_8_16_32_64_128_bmr, AdditionSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;

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
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
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

TYPED_TEST(SecureUintTest_8_16_32_64_128_bmr, AdditionConstantSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;

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
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
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

TYPED_TEST(SecureUintTest_8_16_32_64_128_bmr, SubtractionSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;

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
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
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

TYPED_TEST(SecureUintTest_8_16_32_64_128_bmr, MultiplicationSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;

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
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
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

TYPED_TEST(SecureUintTest_8_16_32_64_128_bmr, DivisionSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;

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
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
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

TYPED_TEST(SecureUintTest_8_16_32_64_128_bmr, LessThanSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;

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
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
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

TYPED_TEST(SecureUintTest_8_16_32_64_128_bmr, GreaterThanSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;

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
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
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

TYPED_TEST(SecureUintTest_8_16_32_64_128_bmr, EqualitySIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;

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
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
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

TYPED_TEST(SecureUintTest_8_16_32_64_128_bmr, IsZeroSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;

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
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
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

TYPED_TEST(SecureUintTest_8_16_32_64_128_bmr, ObliviousModSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
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
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
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

TYPED_TEST(SecureUintTest_8_16_32_64_128_bmr, ModSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;

  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
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
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
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

TYPED_TEST(SecureUintTest_8_16_32_64_128_bmr, GESIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;

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
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
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

TYPED_TEST(SecureUintTest_8_16_32_64_128_bmr, LESIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;

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
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
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


}  // namespace
