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
#include "secure_type/secure_fixed_point_circuit_CBMC.h"
#include "utility/MOTION_dp_mechanism_helper/fixed_point_operation.h"
#include "utility/config.h"

#include "test_constants.h"
#include "test_helpers.h"

using namespace encrypto::motion;

namespace {
TEST(AlgorithmDescription, FromBristolFormatFixedPointAdd64) {
  const auto fx_add64 = encrypto::motion::AlgorithmDescription::FromBristol(
      std::string(encrypto::motion::kRootDir) +
      "/circuits/fixed_point_CBMC_k64_f16/fix64_add_depth.bristol");
  EXPECT_EQ(fx_add64.number_of_gates, 701);
  EXPECT_EQ(fx_add64.gates.size(), 701);

  EXPECT_EQ(fx_add64.number_of_output_wires, 64);
  EXPECT_EQ(fx_add64.number_of_input_wires_parent_a, 64);
  ASSERT_NO_THROW([&fx_add64]() { EXPECT_EQ(*fx_add64.number_of_input_wires_parent_b, 64); }());
  EXPECT_EQ(fx_add64.number_of_wires, 829);

  const auto& gate0 = fx_add64.gates.at(0);
  EXPECT_EQ(gate0.parent_a, 0);
  ASSERT_NO_THROW([&gate0]() { EXPECT_EQ(*gate0.parent_b, 64); }());
  EXPECT_EQ(gate0.output_wire, 765);
  // EXPECT_EQ(gate0.type, encrypto::motion::PrimitiveOperationType::kXor); // compile error
  EXPECT_EQ((gate0.type == encrypto::motion::PrimitiveOperationType::kXor), 1);
  EXPECT_EQ(gate0.selection_bit.has_value(), false);

  const auto& gate2 = fx_add64.gates.at(2);
  EXPECT_EQ(gate2.parent_a, 0);
  ASSERT_NO_THROW([&gate2]() { EXPECT_EQ(*gate2.parent_b, 64); }());
  EXPECT_EQ(gate2.output_wire, 129);
  // EXPECT_EQ(gate2.type, encrypto::motion::PrimitiveOperationType::kAnd); // compile error
  EXPECT_EQ((gate2.type == encrypto::motion::PrimitiveOperationType::kAnd), 1);
  EXPECT_EQ(gate2.selection_bit.has_value(), false);

  const auto& gate698 = fx_add64.gates.at(698);
  EXPECT_EQ(gate698.parent_a, 396);
  ASSERT_NO_THROW([&gate698]() { EXPECT_EQ(*gate698.parent_b, 762); }());
  EXPECT_EQ(gate698.output_wire, 763);
  // EXPECT_EQ(gate698.type, encrypto::motion::PrimitiveOperationType::kAnd); // compile error
  EXPECT_EQ((gate698.type == encrypto::motion::PrimitiveOperationType::kAnd), 1);
  EXPECT_EQ(gate698.selection_bit.has_value(), false);

  const auto& gate700 = fx_add64.gates.at(700);
  EXPECT_EQ(gate700.parent_a, 746);
  ASSERT_NO_THROW([&gate700]() { EXPECT_EQ(*gate700.parent_b, 764); }());
  EXPECT_EQ(gate700.output_wire, 828);
  // EXPECT_EQ(gate700.type, encrypto::motion::PrimitiveOperationType::kXor); // compile error
  EXPECT_EQ((gate700.type == encrypto::motion::PrimitiveOperationType::kXor), 1);
  EXPECT_EQ(gate700.selection_bit.has_value(), false);
}

template <typename T>
class SecureFixedPointCircuitCBMCBgmwTest : public ::testing::Test {};
//
using all_fixed_point = ::testing::Types<std::uint64_t>;
TYPED_TEST_SUITE(SecureFixedPointCircuitCBMCBgmwTest, all_fixed_point);

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, AddInGmw) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;

  std::vector<T> raw_global_input = ::RandomVector<T>(2);
  T fixed_point_mask = T(1) << (sizeof(T) * 8 - 2);
  raw_global_input[0] = raw_global_input[0] % fixed_point_mask;
  raw_global_input[1] = raw_global_input[1] % fixed_point_mask;

  // adjust the sign of fixed-point numbers
  bool v1_sign = std::rand() % 2;
  bool v2_sign = std::rand() % 2;
  raw_global_input.at(0) = raw_global_input.at(0) * (1 - 2 * v1_sign);
  raw_global_input.at(1) = raw_global_input.at(1) * (1 - 2 * v2_sign);

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 + share_1;
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      const double expect_result = FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) +
                                   FixedPointToDouble<T, T_int>(raw_global_input.at(1), k, f);
      double result_T;

      result_T = share_output.AsFixedPoint<T, T_int>();
      double abs_error = 0.02;
      EXPECT_NEAR(result_T, expect_result, abs_error);  // error: 0.015625

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, AddSIMDInGmw) {
  using T = std::uint64_t;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  using A = std::allocator<T>;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
  T fixed_point_mask = T(1) << (sizeof(T) * 8 - 2);

  for (std::size_t i = 0; i < kNumberOfSimd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
  }

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 + share_1;
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<double> result_T;
        result_T = share_output.AsFixedPointVector<T, T_int>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          double result_check_i = FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f) +
                                  FixedPointToDouble<T, T_int>(raw_global_input_2[i], k, f);
          double abs_error = 0.02;
          EXPECT_NEAR(result_T[i], result_check_i, abs_error);  // error: 0.015625
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, NegSIMDInGmw) {
  using T = std::uint64_t;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  using A = std::allocator<T>;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
  T fixed_point_mask = T(1) << (sizeof(T) * 8 - 2);

  for (std::size_t i = 0; i < kNumberOfSimd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
  }

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Neg();
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<double> result_T;
        result_T = share_output.AsFixedPointVector<T, T_int>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          double result_check_i = -FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f);
          double abs_error = 0.02;
          EXPECT_NEAR(result_T[i], result_check_i, abs_error);  // error: 0.015625
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}
TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, AbsSIMDInGmw) {
  using T = std::uint64_t;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  using A = std::allocator<T>;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
  T fixed_point_mask = T(1) << (sizeof(T) * 8 - 2);

  for (std::size_t i = 0; i < kNumberOfSimd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
  }

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Abs();
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<double> result_T;
        result_T = share_output.AsFixedPointVector<T, T_int>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          double result_check_i =
              std::abs(FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f));
          double abs_error = 0.02;
          EXPECT_NEAR(result_T[i], result_check_i, abs_error);  // error: 0.015625
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, AddConstantSIMDInGmw) {
  using T = std::uint64_t;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  using A = std::allocator<T>;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
  T fixed_point_mask = T(1) << (sizeof(T) * 8 - 2);

  for (std::size_t i = 0; i < kNumberOfSimd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);

    raw_global_input_2[i] = raw_global_input_2[0];
  }

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      const auto share_result =
          share_0 + double(FixedPointToDouble<T, T_int>(raw_global_input_2[0], k, f));
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<double> result_T;
        result_T = share_output.AsFixedPointVector<T, T_int>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          double result_check_i = FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f) +
                                  FixedPointToDouble<T, T_int>(raw_global_input_2[0], k, f);
          double abs_error = 0.02;
          EXPECT_NEAR(result_T[i], result_check_i, abs_error);  // error: 0.015625
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, SubInGmw) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;

  std::vector<T> raw_global_input = ::RandomVector<T>(2);
  T fixed_point_mask = T(1) << (sizeof(T) * 8 - 2);
  raw_global_input[0] = raw_global_input[0] % fixed_point_mask;
  raw_global_input[1] = raw_global_input[1] % fixed_point_mask;

  // adjust the sign
  bool v1_sign = std::rand() % 2;
  bool v2_sign = std::rand() % 2;
  raw_global_input.at(0) = raw_global_input.at(0) * (1 - 2 * v1_sign);
  raw_global_input.at(1) = raw_global_input.at(1) * (1 - 2 * v2_sign);

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 - share_1;
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      const double expect_result = FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) -
                                   FixedPointToDouble<T, T_int>(raw_global_input.at(1), k, f);

      double result_T;

      result_T = share_output.AsFixedPoint<T, T_int>();

      double abs_error = 0.02;
      EXPECT_NEAR(result_T, expect_result, abs_error);  // error: 0.015625

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, SubSIMDInGmw) {
  using T = std::uint64_t;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  using A = std::allocator<T>;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
  T fixed_point_mask = T(1) << (sizeof(T) * 8 - 2);

  for (std::size_t i = 0; i < kNumberOfSimd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
  }

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 - share_1;
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<double> result_T;
        result_T = share_output.AsFixedPointVector<T, T_int>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          double result_check_i = FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f) -
                                  FixedPointToDouble<T, T_int>(raw_global_input_2[i], k, f);
          double abs_error = 0.02;
          EXPECT_NEAR(result_T[i], result_check_i, abs_error);  // error: 0.015625
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, MulInGmw) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;

  std::vector<T> raw_global_input = ::RandomVector<T>(2);
  T fixed_point_mask = T(1) << ((sizeof(T) * 8 - 2) / 2);
  raw_global_input[0] = raw_global_input[0] % fixed_point_mask;
  raw_global_input[1] = raw_global_input[1] % fixed_point_mask;

  // adjust the sign
  bool v1_sign = std::rand() % 2;
  bool v2_sign = std::rand() % 2;
  raw_global_input.at(0) = raw_global_input.at(0) * (1 - 2 * v1_sign);
  raw_global_input.at(1) = raw_global_input.at(1) * (1 - 2 * v2_sign);

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 * share_1;
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      const double expect_result = FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) *
                                   FixedPointToDouble<T, T_int>(raw_global_input.at(1), k, f);

      double result_T;

      result_T = share_output.AsFixedPoint<T, T_int>();

      double abs_error = 0.02;
      EXPECT_NEAR(result_T, expect_result, abs_error);  // error: 0.015625

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, MulSIMDInGmw) {
  using T = std::uint64_t;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  using A = std::allocator<T>;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
  T fixed_point_mask = T(1) << ((sizeof(T) * 8 - 2)) / 2;

  for (std::size_t i = 0; i < kNumberOfSimd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
  }

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 * share_1;
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<double> result_T;
        result_T = share_output.AsFixedPointVector<T, T_int>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          double result_check_i = FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f) *
                                  FixedPointToDouble<T, T_int>(raw_global_input_2[i], k, f);
          double abs_error = 0.02;
          EXPECT_NEAR(result_T[i], result_check_i, abs_error);  // error: 0.015625
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, MulConstantSIMDInGmw) {
  using T = std::uint64_t;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  using A = std::allocator<T>;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
  T fixed_point_mask = T(1) << ((sizeof(T) * 8 - 2) / 2);

  for (std::size_t i = 0; i < kNumberOfSimd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);

    raw_global_input_2[i] = raw_global_input_2[0];
  }

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      const auto share_result =
          share_0 * double(FixedPointToDouble<T, T_int>(raw_global_input_2[0], k, f));
      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<double> result_T;
        result_T = share_output.AsFixedPointVector<T, T_int>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          double result_check_i = FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f) *
                                  FixedPointToDouble<T, T_int>(raw_global_input_2[0], k, f);
          double abs_error = 0.02;
          EXPECT_NEAR(result_T[i], result_check_i, abs_error);  // error: 0.015625
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, SqrSIMDInGmw) {
  using T = std::uint64_t;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  using A = std::allocator<T>;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
  T fixed_point_mask = T(1) << ((sizeof(T) * 8 - 2)) / 2;

  for (std::size_t i = 0; i < kNumberOfSimd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
  }

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Sqr();
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<double> result_T;
        result_T = share_output.AsFixedPointVector<T, T_int>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          double result_check_i = FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f) *
                                  FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f);
          double abs_error = 0.02;
          EXPECT_NEAR(result_T[i], result_check_i, abs_error);  // error: 0.015625
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, DivInGmw) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;

  std::vector<T> raw_global_input = ::RandomVector<T>(2);
  T fixed_point_mask = T(1) << ((sizeof(T) * 8 - 2) / 2);
  raw_global_input[0] = raw_global_input[0] % fixed_point_mask;
  raw_global_input[1] = raw_global_input[1] % fixed_point_mask;

  // adjust the sign
  bool v1_sign = std::rand() % 2;
  bool v2_sign = std::rand() % 2;
  raw_global_input.at(0) = raw_global_input.at(0) * (1 - 2 * v1_sign);
  raw_global_input.at(1) = raw_global_input.at(1) * (1 - 2 * v2_sign);

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 / share_1;
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      const double expect_result = FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) /
                                   FixedPointToDouble<T, T_int>(raw_global_input.at(1), k, f);

      double result_T;

      result_T = share_output.AsFixedPoint<T, T_int>();

      double abs_error = 0.02;
      EXPECT_NEAR(result_T, expect_result, abs_error);  // error: 0.015625

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, DivSIMDInGmw) {
  using T = std::uint64_t;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  using A = std::allocator<T>;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
  T fixed_point_mask = T(1) << ((sizeof(T) * 8 - 2)) / 2;

  for (std::size_t i = 0; i < kNumberOfSimd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
  }

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 / share_1;
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<double> result_T;
        result_T = share_output.AsFixedPointVector<T, T_int>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          double result_check_i = FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f) /
                                  FixedPointToDouble<T, T_int>(raw_global_input_2[i], k, f);
          double abs_error = 0.02;
          EXPECT_NEAR(result_T[i], result_check_i, abs_error);  // error: 0.015625
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, LessThanInGmw) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;

  std::vector<T> raw_global_input = ::RandomVector<T>(2);
  T fixed_point_mask = T(1) << ((sizeof(T) * 8 - 2));

  raw_global_input[0] = raw_global_input[0] % fixed_point_mask;
  raw_global_input[1] = raw_global_input[1] % fixed_point_mask;

  // adjust the sign
  bool v1_sign = std::rand() % 2;
  bool v2_sign = std::rand() % 2;
  raw_global_input.at(0) = raw_global_input.at(0) * (1 - 2 * v1_sign);
  raw_global_input.at(1) = raw_global_input.at(1) * (1 - 2 * v2_sign);

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 < share_1;
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      const bool expect_result = FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) <
                                 FixedPointToDouble<T, T_int>(raw_global_input.at(1), k, f);

      bool result_T;

      result_T = share_output.As<bool>();

      EXPECT_EQ(result_T, expect_result);

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, LessThanSIMDInGmw) {
  using T = std::uint64_t;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  using A = std::allocator<T>;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
  T fixed_point_mask = T(1) << ((sizeof(T) * 8 - 2));

  for (std::size_t i = 0; i < kNumberOfSimd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
  }

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 < share_1;
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        BitVector<> result_T;
        result_T = share_output.As<BitVector<>>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          bool result_check_i = FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f) <
                                FixedPointToDouble<T, T_int>(raw_global_input_2[i], k, f);
          EXPECT_EQ(result_T[i], result_check_i);
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, GreaterThanInGmw) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;

  std::vector<T> raw_global_input = ::RandomVector<T>(2);
  T fixed_point_mask = T(1) << ((sizeof(T) * 8 - 2));

  raw_global_input[0] = raw_global_input[0] % fixed_point_mask;
  raw_global_input[1] = raw_global_input[1] % fixed_point_mask;

  // adjust the sign
  bool v1_sign = std::rand() % 2;
  bool v2_sign = std::rand() % 2;
  raw_global_input.at(0) = raw_global_input.at(0) * (1 - 2 * v1_sign);
  raw_global_input.at(1) = raw_global_input.at(1) * (1 - 2 * v2_sign);

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 > share_1;
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      const bool expect_result = FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) >
                                 FixedPointToDouble<T, T_int>(raw_global_input.at(1), k, f);

      bool result_T;

      result_T = share_output.As<bool>();

      EXPECT_EQ(result_T, expect_result);

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, GreaterThanSIMDInGmw) {
  using T = std::uint64_t;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  using A = std::allocator<T>;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
  T fixed_point_mask = T(1) << ((sizeof(T) * 8 - 2));

  for (std::size_t i = 0; i < kNumberOfSimd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
  }

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 > share_1;
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        BitVector<> result_T;
        result_T = share_output.As<BitVector<>>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          bool result_check_i = FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f) >
                                FixedPointToDouble<T, T_int>(raw_global_input_2[i], k, f);
          EXPECT_EQ(result_T[i], result_check_i);
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, EqualityInGmw) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;

  std::vector<T> raw_global_input = ::RandomVector<T>(2);
  T fixed_point_mask = T(1) << ((sizeof(T) * 8 - 2));

  raw_global_input[0] = raw_global_input[0] % fixed_point_mask;
  raw_global_input[1] = raw_global_input[1] % fixed_point_mask;

  // adjust the sign
  bool v1_sign = std::rand() % 2;
  bool v2_sign = std::rand() % 2;
  raw_global_input.at(0) = raw_global_input.at(0) * (1 - 2 * v1_sign);
  raw_global_input.at(1) = raw_global_input.at(1) * (1 - 2 * v2_sign);

  std::size_t edge_case = std::rand() % 5;
  if (edge_case == 0) {
    raw_global_input.at(0) = raw_global_input.at(1);
  } else if (edge_case == 1) {
    raw_global_input.at(0) = 0;
  } else if (edge_case == 2) {
    raw_global_input.at(1) = 0;
  } else if (edge_case == 3) {
    raw_global_input.at(0) = 0;
    raw_global_input.at(1) = 0;
  }

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 == share_1;
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      const bool expect_result = FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) ==
                                 FixedPointToDouble<T, T_int>(raw_global_input.at(1), k, f);

      bool result_T;

      result_T = share_output.As<bool>();

      EXPECT_EQ(result_T, expect_result);

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, EqualitySIMDInGmw) {
  using T = std::uint64_t;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  using A = std::allocator<T>;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
  T fixed_point_mask = T(1) << ((sizeof(T) * 8 - 2));

  for (std::size_t i = 0; i < kNumberOfSimd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
  }

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 == share_1;
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        BitVector<> result_T;
        result_T = share_output.As<BitVector<>>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          bool result_check_i = FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f) ==
                                FixedPointToDouble<T, T_int>(raw_global_input_2[i], k, f);
          EXPECT_EQ(result_T[i], result_check_i);
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, MulBooleanGmwBitSIMDInGmw) {
  using T = std::uint64_t;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  using A = std::allocator<T>;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
  T fixed_point_mask = T(1) << (sizeof(T) * 8 - 2);

  for (std::size_t i = 0; i < kNumberOfSimd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
  }

  BitVector<> boolean_gmw_bits = BitVector<>::SecureRandom(kNumberOfSimd);

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
                          &raw_global_input_1, &raw_global_input_2, &boolean_gmw_bits]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFixedPointCircuitCBMC share_0 =
          party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                  : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0);
      encrypto::motion::ShareWrapper share_1 =
          party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(boolean_gmw_bits, 1)
                  : motion_parties.at(party_id)->In<kBooleanGmw>(boolean_gmw_bits, 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.MulBooleanGmwBit(share_1);
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<double> result_T;
        result_T = share_output.AsFixedPointVector<T, T_int>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          double result_check_i =
              FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f) * boolean_gmw_bits[i];
          double abs_error = 0.02;
          EXPECT_NEAR(result_T[i], result_check_i, abs_error);  // error: 0.015625
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, EqualZeroInGmw) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;

  std::vector<T> raw_global_input = ::RandomVector<T>(2);
  T fixed_point_mask = T(1) << ((sizeof(T) * 8 - 2));

  raw_global_input[0] = raw_global_input[0] % fixed_point_mask;
  raw_global_input[1] = raw_global_input[1] % fixed_point_mask;

  // adjust the sign
  bool v1_sign = std::rand() % 2;
  bool v2_sign = std::rand() % 2;
  raw_global_input.at(0) = raw_global_input.at(0) * (1 - 2 * v1_sign);
  raw_global_input.at(1) = raw_global_input.at(1) * (1 - 2 * v2_sign);

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.EQZ();
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      const bool expect_result = FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) == 0;

      bool result_T;

      result_T = share_output.As<bool>();

      EXPECT_EQ(result_T, expect_result);

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, EqualZeroSIMDInGmw) {
  using T = std::uint64_t;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  using A = std::allocator<T>;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
  T fixed_point_mask = T(1) << ((sizeof(T) * 8 - 2));

  for (std::size_t i = 0; i < kNumberOfSimd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
  }

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.EQZ();
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        BitVector<> result_T;
        result_T = share_output.As<BitVector<>>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          bool result_check_i = FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f) == 0;
          EXPECT_EQ(result_T[i], result_check_i);
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, LessThanZeroInGmw) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;

  std::vector<T> raw_global_input = ::RandomVector<T>(2);
  T fixed_point_mask = T(1) << ((sizeof(T) * 8 - 2));

  raw_global_input[0] = raw_global_input[0] % fixed_point_mask;
  raw_global_input[1] = raw_global_input[1] % fixed_point_mask;

  // adjust the sign
  bool v1_sign = std::rand() % 2;
  bool v2_sign = std::rand() % 2;
  raw_global_input.at(0) = raw_global_input.at(0) * (1 - 2 * v1_sign);
  raw_global_input.at(1) = raw_global_input.at(1) * (1 - 2 * v2_sign);

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.LTZ();
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      const bool expect_result = FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) < 0;

      bool result_T;

      result_T = share_output.As<bool>();

      EXPECT_EQ(result_T, expect_result);

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, LessThanZeroSIMDInGmw) {
  using T = std::uint64_t;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  using A = std::allocator<T>;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
  T fixed_point_mask = T(1) << ((sizeof(T) * 8 - 2));

  for (std::size_t i = 0; i < kNumberOfSimd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
  }

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.LTZ();
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        BitVector<> result_T;
        result_T = share_output.As<BitVector<>>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          bool result_check_i = FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f) < 0;
          EXPECT_EQ(result_T[i], result_check_i);
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, CeilInGmw) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;

  std::vector<T> raw_global_input = ::RandomVector<T>(2);
  T fixed_point_mask = T(1) << (sizeof(T) * 8 - 4);
  raw_global_input[0] = raw_global_input[0] % fixed_point_mask;
  raw_global_input[1] = raw_global_input[1] % fixed_point_mask;

  // adjust the sign
  bool v1_sign = std::rand() % 2;
  bool v2_sign = std::rand() % 2;
  raw_global_input.at(0) = raw_global_input.at(0) * (1 - 2 * v1_sign);
  raw_global_input.at(1) = raw_global_input.at(1) * (1 - 2 * v2_sign);

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Ceil();
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      const double expect_result = ceil(FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f));

      double result_T;

      result_T = share_output.AsFixedPoint<T, T_int>();

      double abs_error = 0.02;
      EXPECT_NEAR(result_T, expect_result, abs_error);  // error: 0.015625

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, CeilSIMDInGmw) {
  using T = std::uint64_t;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  using A = std::allocator<T>;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
  T fixed_point_mask = T(1) << (sizeof(T) * 8 - 4);

  for (std::size_t i = 0; i < kNumberOfSimd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
  }

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Ceil();
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<double> result_T;
        result_T = share_output.AsFixedPointVector<T, T_int>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          double expect_result = ceil(FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f));
          double raw_global_input_1_double =
              FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f);

          // ! this test may fail caused by the C++ double division behaviour (auto rounded
          // result
          // during division), but the ceil protocol is correct (manually verify the result)
          // std::cout << "raw_global_input_1: " << raw_global_input_1[i] << std::endl;
          // std::cout << "T_int(raw_global_input_1): " << T_int(raw_global_input_1[i]) <<
          // std::endl; std::cout << "raw_global_input_1_double: " << std::setprecision(20)
          //           << raw_global_input_1_double << std::endl;
          // std::cout << "result_double_i: " << std::setprecision(20) << result_T[i] << std::endl;
          // std::cout << "expect_result: " << std::setprecision(20) << expect_result << std::endl;
          // std::cout << std::endl;

          double abs_error = 0.02;
          EXPECT_NEAR(result_T[i], expect_result, abs_error);  // error: 0.015625
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, FloorInGmw) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;

  std::vector<T> raw_global_input = ::RandomVector<T>(2);
  T fixed_point_mask = T(1) << (sizeof(T) * 8 - 4);
  raw_global_input[0] = raw_global_input[0] % fixed_point_mask;
  raw_global_input[1] = raw_global_input[1] % fixed_point_mask;

  // adjust the sign
  bool v1_sign = std::rand() % 2;
  bool v2_sign = std::rand() % 2;
  raw_global_input.at(0) = raw_global_input.at(0) * (1 - 2 * v1_sign);
  raw_global_input.at(1) = raw_global_input.at(1) * (1 - 2 * v2_sign);

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Floor();
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      const double expect_result =
          floor(FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f));

      double result_T;

      result_T = share_output.AsFixedPoint<T, T_int>();

      double abs_error = 0.02;
      EXPECT_NEAR(result_T, expect_result, abs_error);  // error: 0.015625

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, FloorSIMDInGmw) {
  using T = std::uint64_t;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  using A = std::allocator<T>;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
  T fixed_point_mask = T(1) << (sizeof(T) * 8 - 4);

  for (std::size_t i = 0; i < kNumberOfSimd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
  }

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Floor();
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<double> result_T;
        result_T = share_output.AsFixedPointVector<T, T_int>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          double expect_result = floor(FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f));
          double raw_global_input_1_double =
              FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f);

          // ! this test may fail caused by the C++ double division behaviour (auto rounded
          // result
          // during division), but the ceil protocol is correct (manually verify the result)
          // std::cout << "raw_global_input_1: " << raw_global_input_1[i] << std::endl;
          // std::cout << "T_int(raw_global_input_1): " << T_int(raw_global_input_1[i]) <<
          // std::endl; std::cout << "raw_global_input_1_double: " << std::setprecision(20)
          //           << raw_global_input_1_double << std::endl;
          // std::cout << "result_double_i: " << std::setprecision(20) << result_T[i] << std::endl;
          // std::cout << "expect_result: " << std::setprecision(20) << expect_result << std::endl;
          // std::cout << std::endl;

          double abs_error = 0.02;
          EXPECT_NEAR(result_T[i], expect_result, abs_error);  // error: 0.015625
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, Fx2IntInGmw) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;

  std::srand(std::time(0));
  std::vector<T> raw_global_input = ::RandomVector<T>(2);
  T fixed_point_mask = T(1) << (sizeof(T) * 8 - 2);

  raw_global_input[0] = raw_global_input[0] % fixed_point_mask;
  raw_global_input[1] = raw_global_input[1] % fixed_point_mask;

  // adjust the sign
  bool v1_sign = std::rand() % 2;
  bool v2_sign = std::rand() % 2;
  raw_global_input.at(0) = raw_global_input.at(0) * (1 - 2 * v1_sign);
  raw_global_input.at(1) = raw_global_input.at(1) * (1 - 2 * v2_sign);

  // edge case
  std::size_t edge_case = std::rand() % 8;
  switch (edge_case) {
    case 0:
      raw_global_input[0] = 50000;
      break;
    case 1:
      raw_global_input[0] = -50000;
      break;
    case 2:
      raw_global_input[0] = 30000;
      break;
    case 3:
      raw_global_input[0] = -30000;
      break;
    case 4:
      raw_global_input[0] = -50000;
      break;
    case 5:
      raw_global_input[0] = -80000;
      break;
    case 6:
      raw_global_input[0] = -80000;
      break;
    default:
      // code block
      break;
  }

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Fx2Int(sizeof(T) * 8);
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      const T expect_result = round(FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f));

      T result_T;

      result_T = share_output.As<T>();
      EXPECT_EQ(T_int(result_T), expect_result);

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, Fx2IntSIMDInGmw) {
  using T = std::uint64_t;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  using A = std::allocator<T>;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
  T fixed_point_mask = T(1) << (sizeof(T) * 8 - 2);

  for (std::size_t i = 0; i < kNumberOfSimd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
  }

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Fx2Int(sizeof(T) * 8);
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<T> result_T;
        result_T = share_output.AsVector<T>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          double result_check_i = round(FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f));

          // only for debug
          // ! this test may fail caused by the C++ double division behaviour (auto rounded
          // result
          // during division), but the protocol is correct
          // std::cout << "raw_global_input_1: " << (raw_global_input_1[i]) << std::endl;
          // std::cout << "T_int(raw_global_input_1): " << T_int(raw_global_input_1[i]) <<
          // std::endl; std::cout << "result_double_i: " << result_T[i] << std::endl; std::cout <<
          // "result_check_i: " << std::setprecision(20) << result_check_i << std::endl;

          double abs_error = 0.2;
          EXPECT_NEAR(T_int(result_T[i]), T_int(result_check_i), abs_error);  // error: 0.015625
          // std::cout << std::endl;
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, Fx2FLInGmw) {
  using T = TypeParam;
  using T_int = get_int_type_t<T>;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  std::srand(std::time(nullptr));
  std::vector<T> raw_global_input = ::RandomVector<T>(2);
  T fixed_point_mask = T(1) << (sizeof(T) * 8 - 2);

  raw_global_input[0] = raw_global_input[0] % fixed_point_mask;
  raw_global_input[1] = raw_global_input[1] % fixed_point_mask;

  // edge case
  std::size_t edge_case = std::rand() % 8;
  switch (edge_case) {
    case 0:
      raw_global_input[0] = 50000;
      break;
    case 1:
      raw_global_input[0] = -50000;
      break;
    case 2:
      raw_global_input[0] = 30000;
      break;
    case 3:
      raw_global_input[0] = -30000;
      break;
    case 4:
      raw_global_input[0] = -50000;
      break;
    case 5:
      raw_global_input[0] = -80000;
      break;
    case 6:
      raw_global_input[0] = -80000;
      break;
    default:
      break;
  }

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result_32 = share_0.Fx2FL(32);
      const auto share_result_64 = share_0.Fx2FL(64);
      auto share_output_32 = share_result_32.Out();
      auto share_output_64 = share_result_64.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;
      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();

      const double expect_result = FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f);
      // std::cout << "raw_global_input.at(0): " << T_int(raw_global_input.at(0)) << std::endl;
      // std::cout << "raw_global_input.at(0)_double: "
      //           << FixedPointToDouble<T, T_int>(raw_global_input.at(0), k, f) << std::endl;
      // std::cout << "expect_result: " << expect_result << std::endl;

      double result_T_32;
      double result_T_64;

      result_T_32 = share_output_32.AsFloatingPoint<float>();
      result_T_64 = share_output_64.AsFloatingPoint<double>();
      // std::cout << "result_T_32: " << result_T_32 << std::endl;
      // std::cout << "result_T_64: " << result_T_64 << std::endl;
      // double abs_error = 0.01;
      // EXPECT_NEAR(result_T_32, expect_result, abs_error);
      // EXPECT_NEAR(result_T_32, expect_result, abs_error);

      // float/double cannot represent all 64-bit integers,
      // therefore, the result is inaccurate
      EXPECT_GE((expect_result), std::nextafter(result_T_32, -INFINITY));
      EXPECT_LE((expect_result), std::nextafter(result_T_32, +INFINITY));

      double abs_error = 0.2;
      EXPECT_NEAR((result_T_64), expect_result, abs_error);
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, Fx2FLSIMDInGmw) {
  using T = std::uint64_t;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  using A = std::allocator<T>;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1000};

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
  T fixed_point_mask = T(1) << (sizeof(T) * 8 - 2);

  for (std::size_t i = 0; i < kNumberOfSimd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    // adjust the sign
    bool v1_sign = std::rand() % 2;
    bool v2_sign = std::rand() % 2;
    raw_global_input_1[i] = raw_global_input_1[i] * (1 - 2 * v1_sign);
    raw_global_input_2[i] = raw_global_input_2[i] * (1 - 2 * v2_sign);
  }

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result_32 = share_0.Fx2FL(32);
      const auto share_result_64 = share_0.Fx2FL(64);
      encrypto::motion::SecureFloatingPointCircuitABY share_output_32 = share_result_32.Out();
      encrypto::motion::SecureFloatingPointCircuitABY share_output_64 = share_result_64.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      std::vector<float> result_T_32;
      std::vector<double> result_T_64;
      result_T_32 = share_output_32.AsFloatingPointVector<float>();
      result_T_64 = share_output_64.AsFloatingPointVector<double>();
      if (party_0) {
        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          double expect_result = (FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f));

          double abs_error = 0.2;

          // float/double cannot represent all 64-bit integers,
          // therefore, the result is inaccurate
          EXPECT_GE((expect_result), std::nextafter(result_T_32[i], -INFINITY));
          EXPECT_LE((expect_result), std::nextafter(result_T_32[i], +INFINITY));

          EXPECT_NEAR((result_T_64[i]), expect_result, abs_error);
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, Sqrt_P0132SIMDInGmw) {
  using T = std::uint64_t;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  using A = std::allocator<T>;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
  T fixed_point_mask = T(1) << ((sizeof(T) * 8 - 2));

  for (std::size_t i = 0; i < kNumberOfSimd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;
  }

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Sqrt_P0132();
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<double> result_T;
        result_T = share_output.AsFixedPointVector<T, T_int>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          double expect_result = sqrt(FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f));
          double abs_error = 0.001;
          EXPECT_LT(std::abs((expect_result - result_T[i]) / result_T[i]), abs_error);
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, Log2_P2508SIMDInGmw) {
  using T = std::uint64_t;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  using A = std::allocator<T>;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
  T fixed_point_mask = T(1) << ((sizeof(T) * 8 - 2));

  for (std::size_t i = 0; i < kNumberOfSimd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;
  }

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Log2_P2508();
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<double> result_T;
        result_T = share_output.AsFixedPointVector<T, T_int>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          double expect_result =
              std::log2(FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f));
          double abs_error = 0.001;
          EXPECT_LT(std::abs((expect_result - result_T[i]) / result_T[i]), abs_error);
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, LnSIMDInGmw) {
  using T = std::uint64_t;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  using A = std::allocator<T>;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
  T fixed_point_mask = T(1) << ((sizeof(T) * 8 - 2));

  for (std::size_t i = 0; i < kNumberOfSimd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;
  }

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Ln();
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<double> result_T;
        result_T = share_output.AsFixedPointVector<T, T_int>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          double expect_result =
              std::log(FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f));
          double abs_error = 0.001;
          EXPECT_LT(std::abs((expect_result - result_T[i]) / result_T[i]), abs_error);
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, Exp2_P1045_PSIMDInGmw) {
  using T = std::uint64_t;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  using A = std::allocator<T>;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
  T fixed_point_mask = T(1) << ((20));

  for (std::size_t i = 0; i < kNumberOfSimd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;
  }

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Exp2_P1045();
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<double> result_T;
        result_T = share_output.AsFixedPointVector<T, T_int>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          double expect_result =
              std::exp2(FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f));
          double abs_error = 0.001;
          EXPECT_LT(std::abs((expect_result - result_T[i]) / result_T[i]), abs_error);
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, Exp_SIMDInGmw) {
  using T = std::uint64_t;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  using A = std::allocator<T>;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
  T fixed_point_mask = T(1) << ((20));

  for (std::size_t i = 0; i < kNumberOfSimd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;
  }

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Exp();
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<double> result_T;
        result_T = share_output.AsFixedPointVector<T, T_int>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          double expect_result =
              std::exp(FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f));

          double abs_error = 0.001;
          EXPECT_LT(std::abs((expect_result - result_T[i]) / result_T[i]), abs_error);
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, Exp2_P1045_Neg_0_1_SIMDInGmw) {
  using T = std::uint64_t;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  using A = std::allocator<T>;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
  T fixed_point_mask = T(1) << ((16));

  for (std::size_t i = 0; i < kNumberOfSimd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;

    raw_global_input_1[i] = -raw_global_input_1[i];
  }

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Exp2_P1045_Neg_0_1();
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<double> result_T;
        result_T = share_output.AsFixedPointVector<T, T_int>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          double expect_result =
              std::exp2(FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f));

          double abs_error = 0.01;
          EXPECT_LT(std::abs((expect_result - result_T[i]) / result_T[i]), abs_error);
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, Sin_P3307_0_1_SIMDInGmw) {
  using T = std::uint64_t;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  using A = std::allocator<T>;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};

  std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
  std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
  T fixed_point_mask = T(1) << ((16));

  for (std::size_t i = 0; i < kNumberOfSimd; i++) {
    raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
    raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;
  }

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
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Sin_P3307_0_1();
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<double> result_T;
        result_T = share_output.AsFixedPointVector<T, T_int>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          double expect_result =
              sin(FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f) * 0.5 * M_PI);
          double abs_error = 0.01;
          EXPECT_LT(std::abs((expect_result - result_T[i]) / result_T[i]), abs_error);
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, Sin_P3307_0_4_SIMDInGmw) {
  using T = std::uint64_t;
  using T_int = get_int_type_t<T>;
  std::srand(std::time(nullptr));
  using A = std::allocator<T>;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};

  std::size_t fixed_point_fraction_bit_size = 16;

  std::vector<double> raw_global_input_1 = rand_range_double_vector(0, 4, kNumberOfSimd);

  std::vector<encrypto::motion::BitVector<>> dummy_input(
      kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

  std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2, kPortOffset)));
  for (auto& party : motion_parties) {
    party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    party->GetConfiguration()->SetOnlineAfterSetup(true);
  }
  std::vector<std::thread> threads;
  for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
    threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &dummy_input,
                          &raw_global_input_1, fixed_point_fraction_bit_size]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFixedPointCircuitCBMC
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(
                                  FixedPointToInput<T, T_int>(raw_global_input_1,
                                                              fixed_point_fraction_bit_size),
                                  0)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBooleanGmw>(
                                  FixedPointToInput<T, T_int>(raw_global_input_1,
                                                              fixed_point_fraction_bit_size),
                                  1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Sin_P3307_0_4();
      auto share_output = share_result.Out();

      std::size_t k = share_0.k_;
      std::size_t f = share_0.f_;

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<double> result_T;
        result_T = share_output.AsFixedPointVector<T, T_int>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          double expect_result = sin(raw_global_input_1[i] * M_PI / 2.0);
          double abs_error = 0.01;
          EXPECT_LT(std::abs((expect_result - result_T[i]) / result_T[i]), abs_error);
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

// TODO: generate cos circuit and test
// TYPED_TEST(SecureFixedPointCircuitCBMCBgmwTest, Cos_P3508_SIMDInGmw) {
//   using T = std::uint64_t;
//   using T_int = get_int_type_t<T>;
//   std::srand(std::time(nullptr));
//   using A = std::allocator<T>;
//   constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
//   constexpr auto kNumberOfWires{sizeof(T) * 8};
//   constexpr std::size_t kNumberOfSimd{10};

//   std::vector<T> raw_global_input_1 = ::RandomVector<T>(kNumberOfSimd);
//   std::vector<T> raw_global_input_2 = ::RandomVector<T>(kNumberOfSimd);
//   T fixed_point_mask = T(1) << ((16));

//   for (std::size_t i = 0; i < kNumberOfSimd; i++) {
//     raw_global_input_1[i] = raw_global_input_1[i] % fixed_point_mask;
//     raw_global_input_2[i] = raw_global_input_2[i] % fixed_point_mask;
//   }

//   std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
//       encrypto::motion::ToInput(raw_global_input_1),
//       encrypto::motion::ToInput(raw_global_input_2)};

//   std::vector<encrypto::motion::BitVector<>> dummy_input(
//       kNumberOfWires, encrypto::motion::BitVector<>(kNumberOfSimd, false));

//   std::vector<PartyPointer> motion_parties(std::move(MakeLocallyConnectedParties(2,
//   kPortOffset))); for (auto& party : motion_parties) {
//     party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
//     party->GetConfiguration()->SetOnlineAfterSetup(true);
//   }
//   std::vector<std::thread> threads;
//   for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
//     threads.emplace_back([party_id, &motion_parties, kNumberOfWires, &global_input, &dummy_input,
//                           &raw_global_input_1, &raw_global_input_2]() {
//       const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
//       encrypto::motion::SecureFixedPointCircuitCBMC
//           share_0 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(0), 0)
//                             : motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 0),
//           share_1 = party_0 ? motion_parties.at(party_id)->In<kBooleanGmw>(dummy_input, 1)
//                             : motion_parties.at(party_id)->In<kBooleanGmw>(global_input.at(1),
//                             1);
//       EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

//       const auto share_result = (share_0 * double(M_PI / 2)).Cos_P3508();
//       auto share_output = share_result.Out();

//       std::size_t k = share_0.k_;
//       std::size_t f = share_0.f_;

//       motion_parties.at(party_id)->Run();
//       motion_parties.at(party_id)->Finish();
//       if (party_0) {
//         std::vector<double> result_T;
//         result_T = share_output.AsFixedPointVector<T, T_int>();

//         for (std::size_t i = 0; i < kNumberOfSimd; i++) {
//           double expect_result =
//               cos(FixedPointToDouble<T, T_int>(raw_global_input_1[i], k, f) * 0.5 * M_PI);

//           double abs_error = 0.01;
//           EXPECT_LT(std::abs((expect_result - result_T[i]) / result_T[i]), abs_error);
//         }
//       }
//     });
//   }
//   for (auto& t : threads)
//     if (t.joinable()) t.join();
// }

}  // namespace
