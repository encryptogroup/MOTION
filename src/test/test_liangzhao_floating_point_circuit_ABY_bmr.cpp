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
#include "secure_type/secure_floating_point_circuit_ABY.h"
#include "utility/config.h"

#include "test_constants.h"
#include "test_helpers.h"

using namespace encrypto::motion;

namespace {

template <typename T>
class SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr : public ::testing::Test {};
using all_floating_point = ::testing::Types<float, double>;
TYPED_TEST_SUITE(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, all_floating_point);

template <typename T>
class SecureFloatingPointCircuitABYTest_with_CBMC_GC_circuit_bmr : public ::testing::Test {};
TYPED_TEST_SUITE(SecureFloatingPointCircuitABYTest_with_CBMC_GC_circuit_bmr, all_floating_point);

// test passed
TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, AdditionInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::srand(time(nullptr));

  T min = -(std::numeric_limits<T>::max() / 10);
  T max = std::numeric_limits<T>::max() / 10;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, 2);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(0)),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(1))};

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
                          &raw_global_input_1]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_addition = share_0 + share_1;
      auto share_output = share_addition.Out();

      motion_parties.at(party_id)->Run();
      const T expect_result = raw_global_input_1.at(0) + raw_global_input_1.at(1);

      T result_T;

      if (std::is_same<T, float>::value) {
        result_T = share_output.AsFloatingPoint<float>();
        EXPECT_FLOAT_EQ(result_T, expect_result);
      } else if (std::is_same<T, double>::value) {
        result_T = share_output.AsFloatingPoint<double>();
        EXPECT_DOUBLE_EQ(result_T, expect_result);
      }

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

// test passed
TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, AdditionSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{100};
  std::srand(time(nullptr));

  T min = -(std::numeric_limits<T>::max() / 10);
  T max = std::numeric_limits<T>::max() / 10;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);
  std::vector<T> raw_global_input_2 = RandomRangeVector(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_2)};

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
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 + share_1;
      // const auto share_result = share_0 + share_0;
      const auto expect_result =
          encrypto::motion::AddVectors<T>(raw_global_input_1, raw_global_input_2);

      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();

      if (party_0) {
        std::vector<T> result_T;

        result_T = share_output.AsFloatingPointVector<T>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          if (std::is_same<T, float>::value) {
            EXPECT_FLOAT_EQ(result_T[i], expect_result[i]);
          } else if (std::is_same<T, double>::value) {
            EXPECT_DOUBLE_EQ(result_T[i], expect_result[i]);
          }
        }
      }
      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

// test passed
TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, AdditionConstantSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
  std::srand(time(nullptr));

  T min = -(std::numeric_limits<T>::max() / 10);
  T max = std::numeric_limits<T>::max() / 10;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);
  std::vector<T> raw_global_input_2 = RandomRangeVector(min, max, kNumberOfSimd);

  T constant_value = raw_global_input_2[0];
  for (std::size_t i = 1; i < kNumberOfSimd; i++) {
    raw_global_input_2[i] = constant_value;
  }

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_2)};

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
                          &raw_global_input_1, &raw_global_input_2, &constant_value]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      encrypto::motion::SecureFloatingPointCircuitABY share_result = share_0 + constant_value;
      const auto expect_result =
          encrypto::motion::AddVectors<T>(raw_global_input_1, raw_global_input_2);

      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<T> result_T;

        result_T = share_output.AsFloatingPointVector<T>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          if (std::is_same<T, float>::value) {
            EXPECT_FLOAT_EQ(result_T[i], expect_result[i]);
          } else if (std::is_same<T, double>::value) {
            EXPECT_DOUBLE_EQ(result_T[i], expect_result[i]);
          }
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

// test passed
TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, SubtractionInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::srand(time(nullptr));

  T min = -(std::numeric_limits<T>::max() / 2);
  T max = std::numeric_limits<T>::max() / 2;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, 2);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(0)),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(1))};
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
                          &raw_global_input_1]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_sub = share_0 - share_1;
      auto share_output = share_sub.Out();

      motion_parties.at(party_id)->Run();

      const T expect_result = raw_global_input_1.at(0) - raw_global_input_1.at(1);

      std::uint32_t result_uint32t;
      std::uint64_t result_uint64t;
      T result_T;

      if (std::is_same<T, float>::value) {
        result_T = share_output.AsFloatingPoint<float>();
        EXPECT_FLOAT_EQ(result_T, expect_result);
      } else if (std::is_same<T, double>::value) {
        result_T = share_output.AsFloatingPoint<double>();
        EXPECT_DOUBLE_EQ(result_T, expect_result);
      }

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

// test passed
TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, SubtractionSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
  std::srand(time(nullptr));

  T min = -(std::numeric_limits<T>::max() / 10);
  T max = std::numeric_limits<T>::max() / 10;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);
  std::vector<T> raw_global_input_2 = RandomRangeVector(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_2)};

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
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 - share_1;
      const auto expect_result =
          encrypto::motion::SubVectors<T>(raw_global_input_1, raw_global_input_2);

      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<T> result_T;

        result_T = share_output.AsFloatingPointVector<T>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          if (std::is_same<T, float>::value) {
            EXPECT_FLOAT_EQ(result_T[i], expect_result[i]);
          } else if (std::is_same<T, double>::value) {
            EXPECT_DOUBLE_EQ(result_T[i], expect_result[i]);
          }
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

// test passed
TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, MultiplicationInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  std::mt19937 mersenne_twister(sizeof(T));
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::srand(time(nullptr));

  T min = sqrt(std::numeric_limits<T>::max());
  T max = sqrt(std::numeric_limits<T>::max());

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, 2);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(0)),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(1))};
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
                          &raw_global_input_1]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_multiplication = share_0 * share_1;
      auto share_output = share_multiplication.Out();

      motion_parties.at(party_id)->Run();

      const T expect_result = raw_global_input_1.at(0) * raw_global_input_1.at(1);
      T result_T;

      if (std::is_same<T, float>::value) {
        result_T = share_output.AsFloatingPoint<float>();
        EXPECT_FLOAT_EQ(result_T, expect_result);
      } else if (std::is_same<T, double>::value) {
        result_T = share_output.AsFloatingPoint<double>();
        EXPECT_DOUBLE_EQ(result_T, expect_result);
      }

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

// test passed
TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, MultiplicationSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
  std::srand(time(nullptr));

  T min = sqrt(std::numeric_limits<T>::max());
  T max = sqrt(std::numeric_limits<T>::max());

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);
  std::vector<T> raw_global_input_2 = RandomRangeVector(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_2)};

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
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 * share_1;
      const auto expect_result =
          encrypto::motion::MultiplyVectors<T>(raw_global_input_1, raw_global_input_2);

      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<T> result_T;

        result_T = share_output.AsFloatingPointVector<T>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          if (std::is_same<T, float>::value) {
            EXPECT_FLOAT_EQ(result_T[i], expect_result[i]);
          } else if (std::is_same<T, double>::value) {
            EXPECT_DOUBLE_EQ(result_T[i], expect_result[i]);
          }
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

// test passed
TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, DivisionInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  std::mt19937 mersenne_twister(sizeof(T));
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::srand(time(nullptr));

  T min = -(std::numeric_limits<T>::max() / 2);
  T max = std::numeric_limits<T>::max() / 2;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, 2);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(0)),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(1))};
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
                          &raw_global_input_1]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);
      EXPECT_EQ(share_1.Get()->GetBitLength(), kNumberOfWires);

      const auto share_division = share_0 / share_1;
      auto share_output = share_division.Out();

      motion_parties.at(party_id)->Run();

      const T expect_result = raw_global_input_1.at(0) / raw_global_input_1.at(1);
      T result_T;

      if (std::is_same<T, float>::value) {
        result_T = share_output.AsFloatingPoint<float>();
        // std::cout << "result_float: " << result_T << std::endl;
        EXPECT_FLOAT_EQ(result_T, expect_result);
      } else if (std::is_same<T, double>::value) {
        result_T = share_output.AsFloatingPoint<double>();
        // std::cout << "result_float: " << result_T << std::endl;
        EXPECT_DOUBLE_EQ(result_T, expect_result);
      }

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

// test passed
TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, DivisionSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
  std::srand(time(nullptr));

  T min = -(std::numeric_limits<T>::max() / 2);
  T max = std::numeric_limits<T>::max() / 2;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);
  std::vector<T> raw_global_input_2 = RandomRangeVector(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_2)};

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
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 / share_1;
      const auto expect_result =
          encrypto::motion::RestrictDivVectors<T>(raw_global_input_1, raw_global_input_2);

      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<T> result_T;

        result_T = share_output.AsFloatingPointVector<T>();

        double relative_error = 0.001;
        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          if (std::is_same<T, float>::value) {
            EXPECT_LT(std::abs(result_T[i] / expect_result[i] - 1), relative_error);
          } else if (std::is_same<T, double>::value) {
            EXPECT_LT(std::abs(result_T[i] / expect_result[i] - 1), relative_error);
          }
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

// test passed
TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, Exp2InBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::srand(time(nullptr));

  T min = -log2(std::numeric_limits<T>::max());
  T max = log(std::numeric_limits<T>::max());

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, 2);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(0)),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(1))};
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
                          &raw_global_input_1]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);
      EXPECT_EQ(share_1.Get()->GetBitLength(), kNumberOfWires);

      const auto share_exp2 = share_0.Exp2();
      auto share_output = share_exp2.Out();

      motion_parties.at(party_id)->Run();

      const T expect_result = exp2(raw_global_input_1.at(0));
      T result_T;

      double relative_error = 0.001;

      if (std::is_same<T, float>::value) {
        result_T = share_output.AsFloatingPoint<float>();
        if (result_T != 0) {
          EXPECT_LT(std::abs((result_T - std::exp2(raw_global_input_1[0])) /
                             std::exp2(raw_global_input_1[0])),
                    relative_error);
        } else {
          EXPECT_NEAR(result_T, std::exp2(raw_global_input_1[0]), relative_error);
        }
      } else if (std::is_same<T, double>::value) {
        result_T = share_output.AsFloatingPoint<double>();
        if (result_T != 0) {
          EXPECT_LT(std::abs((result_T - std::exp2(raw_global_input_1[0])) /
                             std::exp2(raw_global_input_1[0])),
                    relative_error);
        } else {
          EXPECT_NEAR(result_T, std::exp2(raw_global_input_1[0]), relative_error);
        }
      }

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

// test passed
TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, Exp2SIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
  std::srand(time(nullptr));

  T min = -log2(std::numeric_limits<T>::max());
  T max = log2(std::exp2(20));

  int edge_case = std::rand() % 4;
  switch (edge_case) {
    case 0:
      max = 0;
      break;
    case 1:
      max = 1;
      break;
  }

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);
  std::vector<T> raw_global_input_2 = RandomRangeVector(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_2)};

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
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Exp2();

      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<T> result_T;

        result_T = share_output.AsFloatingPointVector<T>();
        double relative_error = 0.0001;

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          if (std::is_same<T, float>::value) {
            if (result_T[i] != 0) {
              EXPECT_LT(std::abs((result_T[i] - std::exp2(raw_global_input_1[i])) /
                                 std::exp2(raw_global_input_1[i])),
                        relative_error);
            } else {
              EXPECT_NEAR(result_T[i], std::exp2(raw_global_input_1[i]), relative_error);
            }
          } else if (std::is_same<T, double>::value) {
            if (result_T[i] != 0) {
              EXPECT_LT(std::abs((result_T[i] - std::exp2(raw_global_input_1[i])) /
                                 std::exp2(raw_global_input_1[i])),
                        relative_error);
            } else {
              EXPECT_NEAR(result_T[i], std::exp2(raw_global_input_1[i]), relative_error);
            }
          }
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

// test passed
// ! this accuracy of the circuit should be further improved
TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, ExpInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::srand(time(nullptr));

  T min = -log(std::numeric_limits<T>::max());
  T max = log(std::numeric_limits<T>::max());

  int edge_case = std::rand() % 4;
  switch (edge_case) {
    case 0:
      max = 0;
      break;
    case 1:
      max = 1;
      break;
  }

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, 2);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(0)),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(1))};
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
                          &raw_global_input_1]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);
      EXPECT_EQ(share_1.Get()->GetBitLength(), kNumberOfWires);

      const auto share_exp = share_0.Exp();
      auto share_output = share_exp.Out();

      // std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      // std::cout << "party finish" << std::endl;

      T result_T;

      if (std::is_same<T, float>::value) {
        result_T = share_output.AsFloatingPoint<float>();
        // EXPECT_FLOAT_EQ(result_T, std::exp(raw_global_input_1[0]));

        double abs_error = 0.0001;
        EXPECT_LT(std::abs((result_T - std::exp(raw_global_input_1[0])) / result_T), abs_error);

      } else if (std::is_same<T, double>::value) {
        result_T = share_output.AsFloatingPoint<double>();
        // EXPECT_DOUBLE_EQ(result_T, std::exp2(raw_global_input_1.at(0) *
        // log2(std::numbers::e)));

        double abs_error = 0.0001;
        EXPECT_LT(std::abs((result_T - std::exp2(raw_global_input_1[0] * log2(std::numbers::e))) /
                           result_T),
                  abs_error);
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

// test passed
// ! this accuracy of the circuit should be further improved
TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, ExpSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
  std::srand(time(nullptr));

  T min = -log(std::numeric_limits<T>::max());
  T max = log(std::numeric_limits<T>::max());  // max cause large errors
  std::cout << "max: " << max << std::endl;

  // // only for debugging
  // max = 30;  // the circuit need to be improved for accuracy

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);

  // edge case testing
  int edge_case = std::rand() % 6;
  switch (edge_case) {
    case 0: {
      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        raw_global_input_1[i] = 0;
      }
      break;
    }
    case 1: {
      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        raw_global_input_1[i] = 1;
      }
      break;
    }
  }

  // only for debugging
  std::cout << "raw_global_input_1: " << std::endl;
  for (std::size_t i = 0; i < kNumberOfSimd; i++) {
    std::cout << raw_global_input_1[i] << std::endl;
  }

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1)};

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
                          &raw_global_input_1]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY share_0 =
          party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                  : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_addition = share_0.Exp();

      auto share_output = share_addition.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<T> result_T;

        result_T = share_output.AsFloatingPointVector<T>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          if (std::is_same<T, float>::value) {
            // EXPECT_FLOAT_EQ(result_T[i], std::exp(raw_global_input_1[i]));

            double abs_error = 0.0001;
            EXPECT_LT(
                std::abs((result_T[i] - std::exp2(raw_global_input_1[i] * log2(std::numbers::e))) /
                         result_T[i]),
                abs_error);
          } else {
            // EXPECT_DOUBLE_EQ(result_T[i], std::exp2(raw_global_input_1[i] *
            // log2(std::numbers::e)));

            double abs_error = 0.0001;
            EXPECT_LT(
                std::abs((result_T[i] - std::exp2(raw_global_input_1[i] * log2(std::numbers::e))) /
                         result_T[i]),
                abs_error);
          }
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

// ! this test may fail because the circuit is diferent from double arithmetic
TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, Log2InBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::srand(time(nullptr));

  T min = 0;
  T max = (std::numeric_limits<T>::max());

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, 2);

  int edge_case = std::rand() % 6;
  switch (edge_case) {
    case 0:
      raw_global_input_1[0] = 0;
      break;
    case 1:
      raw_global_input_1[0] = 1;
      break;
  }

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(0)),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(1))};
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
                          &raw_global_input_1]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);
      EXPECT_EQ(share_1.Get()->GetBitLength(), kNumberOfWires);

      const auto share_exp2 = share_0.Log2();
      auto share_output = share_exp2.Out();

      motion_parties.at(party_id)->Run();

      const T expect_result = log2(raw_global_input_1.at(0));
      T result_T;

      if (std::is_same<T, float>::value) {
        result_T = share_output.AsFloatingPoint<float>();
        std::cout << "result_float: " << result_T << std::endl;
        EXPECT_FLOAT_EQ(result_T, expect_result);
      } else if (std::is_same<T, double>::value) {
        result_T = share_output.AsFloatingPoint<double>();
        std::cout << "result_float: " << result_T << std::endl;
        EXPECT_DOUBLE_EQ(result_T, expect_result);
      }

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

// ! this test may fail because the circuit is diferent from double arithmetic
TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, Log2SIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
  std::srand(time(nullptr));

  T min = 0;
  T max = (std::numeric_limits<T>::max());

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);
  std::vector<T> raw_global_input_2 = RandomRangeVector(min, max, kNumberOfSimd);

  // edge case testing
  int edge_case = std::rand() % 6;
  switch (edge_case) {
    case 0: {
      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        raw_global_input_1[i] = 0.001;
      }
      break;
    }
    case 1: {
      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        raw_global_input_1[i] = 1;
      }
      break;
    }
  }

  // only for debugging
  std::cout << "raw_global_input_1[i]: " << std::endl;
  for (std::size_t i = 0; i < kNumberOfSimd; i++) {
    std::cout << raw_global_input_1[i] << std::endl;
  }

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_2)};

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
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Log2();

      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<T> result_T;

        result_T = share_output.AsFloatingPointVector<T>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          if (std::is_same<T, float>::value) {
            EXPECT_NEAR(result_T[i], std::log2(raw_global_input_1[i]), 0.1);
          } else if (std::is_same<T, double>::value) {
            EXPECT_NEAR(result_T[i], std::log2(raw_global_input_1[i]), 0.1);
          }
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, LnInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::srand(time(nullptr));

  T min = 0;
  T max = (std::numeric_limits<T>::max());

  int edge_case = std::rand() % 8;
  switch (edge_case) {
    case 0:
      max = 0;
      break;
    case 1:
      max = 1;
      break;
    case 2:
      min = 1;
      max = 1;
      break;
  }

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, 2);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(0)),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(1))};
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
                          &raw_global_input_1]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);
      EXPECT_EQ(share_1.Get()->GetBitLength(), kNumberOfWires);

      const auto share_exp2 = share_0.Ln();
      auto share_output = share_exp2.Out();

      motion_parties.at(party_id)->Run();

      const T expect_result = log(raw_global_input_1.at(0));
      T result_T;

      if (std::is_same<T, float>::value) {
        result_T = share_output.AsFloatingPoint<float>();
        std::cout << "result_float: " << result_T << std::endl;
        EXPECT_FLOAT_EQ(result_T, expect_result);
      } else if (std::is_same<T, double>::value) {
        result_T = share_output.AsFloatingPoint<double>();
        std::cout << "result_float: " << result_T << std::endl;
        EXPECT_DOUBLE_EQ(result_T, expect_result);
      }

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, LnSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
  std::srand(time(nullptr));

  T min = 0;
  T max = (std::numeric_limits<T>::max());

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);
  std::vector<T> raw_global_input_2 = RandomRangeVector(min, max, kNumberOfSimd);

  // edge case testing
  int edge_case = std::rand() % 6;
  switch (edge_case) {
    case 0: {
      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        raw_global_input_1[i] = 0.001;
      }
      break;
    }
    case 1: {
      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        raw_global_input_1[i] = 1;
      }
      break;
    }
  }

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_2)};

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
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Ln();

      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<T> result_T;

        result_T = share_output.AsFloatingPointVector<T>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          if (std::is_same<T, float>::value) {
            EXPECT_FLOAT_EQ(result_T[i], std::log(raw_global_input_1[i]));
          } else if (std::is_same<T, double>::value) {
            EXPECT_DOUBLE_EQ(result_T[i], std::log(raw_global_input_1[i]));
          }
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, SqrtInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::srand(time(nullptr));

  T min = 0;
  T max = (std::numeric_limits<T>::max());

  int edge_case = std::rand() % 4;
  switch (edge_case) {
    case 0:
      max = 0;
      break;
    case 1:
      max = 1;
      break;
  }

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, 2);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(0)),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(1))};
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
                          &raw_global_input_1]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);
      EXPECT_EQ(share_1.Get()->GetBitLength(), kNumberOfWires);

      const auto share_exp2 = share_0.Sqrt();
      auto share_output = share_exp2.Out();

      motion_parties.at(party_id)->Run();

      const T expect_result = sqrt(raw_global_input_1.at(0));
      T result_T;

      if (std::is_same<T, float>::value) {
        result_T = share_output.AsFloatingPoint<float>();
        // std::cout << "result_float: " << result_T << std::endl;
        EXPECT_FLOAT_EQ(result_T, expect_result);
      } else if (std::is_same<T, double>::value) {
        result_T = share_output.AsFloatingPoint<double>();
        // std::cout << "result_float: " << result_T << std::endl;
        EXPECT_DOUBLE_EQ(result_T, expect_result);
      }

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, SqrtSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
  std::srand(time(nullptr));

  T min = 0;
  T max = (std::numeric_limits<T>::max());

  int edge_case = std::rand() % 4;
  switch (edge_case) {
    case 0:
      max = 0;
      break;
    case 1:
      max = 1;
      break;
  }

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);
  std::vector<T> raw_global_input_2 = RandomRangeVector(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_2)};

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
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Sqrt();

      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<T> result_T;

        result_T = share_output.AsFloatingPointVector<T>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          if (std::is_same<T, float>::value) {
            EXPECT_FLOAT_EQ(result_T[i], sqrt(raw_global_input_1[i]));
          } else if (std::is_same<T, double>::value) {
            EXPECT_DOUBLE_EQ(result_T[i], sqrt(raw_global_input_1[i]));
          }
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, SqrInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::srand(time(nullptr));

  T min = -(sqrt(std::numeric_limits<T>::max()));
  T max = (sqrt(std::numeric_limits<T>::max()));

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, 2);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(0)),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(1))};
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
                          &raw_global_input_1]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);
      EXPECT_EQ(share_1.Get()->GetBitLength(), kNumberOfWires);

      const auto share_exp2 = share_0.Sqr();
      auto share_output = share_exp2.Out();

      motion_parties.at(party_id)->Run();

      const T expect_result = raw_global_input_1.at(0) * raw_global_input_1.at(0);
      T result_T;

      if (std::is_same<T, float>::value) {
        result_T = share_output.AsFloatingPoint<float>();
        // std::cout << "result_float: " << result_T << std::endl;
        EXPECT_FLOAT_EQ(result_T, expect_result);
      } else if (std::is_same<T, double>::value) {
        result_T = share_output.AsFloatingPoint<double>();
        // std::cout << "result_float: " << result_T << std::endl;
        EXPECT_DOUBLE_EQ(result_T, expect_result);
      }

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, SqrSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
  std::srand(time(nullptr));

  T min = -(sqrt(std::numeric_limits<T>::max()));
  T max = (sqrt(std::numeric_limits<T>::max()));

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);
  std::vector<T> raw_global_input_2 = RandomRangeVector(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_2)};

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
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Sqr();

      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<T> result_T;

        result_T = share_output.AsFloatingPointVector<T>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          if (std::is_same<T, float>::value) {
            EXPECT_FLOAT_EQ(result_T[i], (raw_global_input_1[i]) * (raw_global_input_1[i]));
          } else if (std::is_same<T, double>::value) {
            EXPECT_DOUBLE_EQ(result_T[i], (raw_global_input_1[i]) * (raw_global_input_1[i]));
          }
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, EqualityInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::srand(time(nullptr));

  T min = -(std::numeric_limits<T>::max() / 2);
  T max = std::numeric_limits<T>::max() / 2;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, 2);

  if (std::rand() % 2 == 0) {
    raw_global_input_1[0] = raw_global_input_1[1];
  }

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(0)),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(1))};
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
                          &raw_global_input_1]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_equal = share_0 == share_1;
      auto share_output = share_equal.Out();
      assert(share_output->GetBitLength() == 1);

      motion_parties.at(party_id)->Run();

      bool result = share_output.As<bool>();
      const bool expect_result = raw_global_input_1.at(0) == raw_global_input_1.at(1);
      EXPECT_EQ(result, expect_result);

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, EqualitySIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
  std::srand(time(nullptr));

  T min = -(sqrt(std::numeric_limits<T>::max()));
  T max = (sqrt(std::numeric_limits<T>::max()));

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);
  std::vector<T> raw_global_input_2 = RandomRangeVector(min, max, kNumberOfSimd);

  if (std::rand() % 2 == 0) {
    raw_global_input_2 = raw_global_input_1;
  }

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_2)};

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
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 == share_1;

      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        BitVector<> result_T;

        result_T = share_output.As<BitVector<>>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          if (std::is_same<T, float>::value) {
            EXPECT_FLOAT_EQ(result_T[i], (raw_global_input_1[i]) == (raw_global_input_2[i]));
          } else if (std::is_same<T, double>::value) {
            EXPECT_DOUBLE_EQ(result_T[i], (raw_global_input_1[i]) == (raw_global_input_2[i]));
          }
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, GreaterThanInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::srand(time(nullptr));

  T min = -(std::numeric_limits<T>::max());
  T max = std::numeric_limits<T>::max();

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, 2);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(0)),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(1))};
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
                          &raw_global_input_1]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);
      EXPECT_EQ(share_1.Get()->GetBitLength(), kNumberOfWires);

      const auto share_greater = share_0 > share_1;
      auto share_output = share_greater.Out();
      assert(share_output->GetBitLength() == 1);

      motion_parties.at(party_id)->Run();

      const bool expect_result = raw_global_input_1.at(0) > raw_global_input_1.at(1);
      const bool result = share_output.As<bool>();
      EXPECT_EQ(result, expect_result);

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, GreaterThanSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
  std::srand(time(nullptr));

  T min = -(sqrt(std::numeric_limits<T>::max()));
  T max = (sqrt(std::numeric_limits<T>::max()));

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);
  std::vector<T> raw_global_input_2 = RandomRangeVector(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_2)};

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
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 > share_1;

      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        BitVector<> result_T;

        result_T = share_output.As<BitVector<>>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          if (std::is_same<T, float>::value) {
            EXPECT_FLOAT_EQ(result_T[i], (raw_global_input_1[i]) > (raw_global_input_2[i]));
          } else if (std::is_same<T, double>::value) {
            EXPECT_DOUBLE_EQ(result_T[i], (raw_global_input_1[i]) > (raw_global_input_2[i]));
          }
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, LessThanInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::srand(time(nullptr));

  T min = -(std::numeric_limits<T>::max());
  T max = std::numeric_limits<T>::max();

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, 2);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(0)),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(1))};
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
                          &raw_global_input_1]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);
      EXPECT_EQ(share_1.Get()->GetBitLength(), kNumberOfWires);

      const auto share_greater = share_0 < share_1;
      auto share_output = share_greater.Out();
      assert(share_output->GetBitLength() == 1);

      motion_parties.at(party_id)->Run();

      const bool expect_result = raw_global_input_1.at(0) < raw_global_input_1.at(1);
      const bool result = share_output.As<bool>();
      EXPECT_EQ(result, expect_result);

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, LessThanSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
  std::srand(time(nullptr));

  T min = -(sqrt(std::numeric_limits<T>::max()));
  T max = (sqrt(std::numeric_limits<T>::max()));

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);
  std::vector<T> raw_global_input_2 = RandomRangeVector(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_2)};

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
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0 < share_1;

      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        BitVector<> result_T;

        result_T = share_output.As<BitVector<>>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          if (std::is_same<T, float>::value) {
            EXPECT_FLOAT_EQ(result_T[i], (raw_global_input_1[i]) < (raw_global_input_2[i]));
          } else if (std::is_same<T, double>::value) {
            EXPECT_DOUBLE_EQ(result_T[i], (raw_global_input_1[i]) < (raw_global_input_2[i]));
          }
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, IsZeroInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::srand(time(nullptr));

  T min = -(std::numeric_limits<T>::max() / 10);
  T max = std::numeric_limits<T>::max() / 10;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, 2);

  if (std::rand() % 2 == 0) {
    raw_global_input_1[0] = 0;
  }

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(0)),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(1))};
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
                          &raw_global_input_1]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);
      EXPECT_EQ(share_1.Get()->GetBitLength(), kNumberOfWires);

      const auto share_greater = share_0.IsZero();
      auto share_output = share_greater.Out();
      assert(share_output->GetBitLength() == 1);

      motion_parties.at(party_id)->Run();

      const bool expect_result = raw_global_input_1.at(0) == 0;
      const bool result = share_output.As<bool>();

      EXPECT_EQ(result, expect_result);

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, IsZeroSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
  std::srand(time(nullptr));

  T min = -(sqrt(std::numeric_limits<T>::max()));
  T max = (sqrt(std::numeric_limits<T>::max()));

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);
  std::vector<T> raw_global_input_2 = RandomRangeVector(min, max, kNumberOfSimd);

  int edge_case = std::rand() % 6;
  switch (edge_case) {
    case 0: {
      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        raw_global_input_1[i] = 0;
      }
      break;
    }
    case 1: {
      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        raw_global_input_1[i] = -raw_global_input_1[i];
      }
      break;
    }
  }

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_2)};

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
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.IsZero();

      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        BitVector<> result_T;

        result_T = share_output.As<BitVector<>>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          if (std::is_same<T, float>::value) {
            EXPECT_FLOAT_EQ(result_T[i], (raw_global_input_1[i]) == (0));
          } else if (std::is_same<T, double>::value) {
            EXPECT_DOUBLE_EQ(result_T[i], (raw_global_input_1[i]) == (0));
          }
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, IsNegInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::srand(time(nullptr));

  T min = -(std::numeric_limits<T>::max() / 10);
  T max = std::numeric_limits<T>::max() / 10;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, 2);

  int edge_case = std::rand() % 6;
  switch (edge_case) {
    case 0: {
      raw_global_input_1[0] = 0;
      break;
    }
    case 1: {
      raw_global_input_1[0] = -raw_global_input_1[0];
      break;
    }
  }

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(0)),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(1))};
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
                          &raw_global_input_1]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);
      EXPECT_EQ(share_1.Get()->GetBitLength(), kNumberOfWires);

      const auto share_greater = share_0.IsNeg();
      auto share_output = share_greater.Out();
      assert(share_output->GetBitLength() == 1);

      motion_parties.at(party_id)->Run();

      const bool expect_result = raw_global_input_1.at(0) < 0;
      const bool result = share_output.As<bool>();

      EXPECT_EQ(result, expect_result);

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, IsNegSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
  std::srand(time(nullptr));

  T min = -(sqrt(std::numeric_limits<T>::max()));
  T max = (sqrt(std::numeric_limits<T>::max()));

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);
  std::vector<T> raw_global_input_2 = RandomRangeVector(min, max, kNumberOfSimd);

  int edge_case = std::rand() % 6;
  switch (edge_case) {
    case 0: {
      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        raw_global_input_1[i] = 0;
      }
      break;
    }
    case 1: {
      for (std::size_t i = 0; i < kNumberOfSimd; i++) {
        raw_global_input_1[i] = -raw_global_input_1[i];
      }
      break;
    }
  }

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_2)};

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
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.IsNeg();

      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        BitVector<> result_T;

        result_T = share_output.As<BitVector<>>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          if (std::is_same<T, float>::value) {
            EXPECT_FLOAT_EQ(result_T[i], (raw_global_input_1[i]) < (0));
          } else if (std::is_same<T, double>::value) {
            EXPECT_DOUBLE_EQ(result_T[i], (raw_global_input_1[i]) < (0));
          }
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, MulBooleanBitSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
  std::srand(time(nullptr));

  // T min = -(std::numeric_limits<T>::max() / 10);
  // T max = std::numeric_limits<T>::max() / 10;
  T min = -100;
  T max = 100;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);
  std::vector<bool> raw_global_input_2 = RandomBoolVector(kNumberOfSimd);

  // // only for debugging
  // for (std::size_t i = 0; i < kNumberOfSimd; i++) {
  //   raw_global_input_1[i] = 0.15;
  // }

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1)};

  BitVector<> boolean_bit = BitVector(raw_global_input_2);
  BitVector<> dummy_boolean_input = boolean_bit ^ boolean_bit;

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
                          &raw_global_input_1, &boolean_bit, &dummy_boolean_input]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY share_0 =
          party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                  : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0);

      encrypto::motion::ShareWrapper share_1 =
          party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_boolean_input, 1)
                  : motion_parties.at(party_id)->In<kBmr>(boolean_bit, 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.MulBooleanBit(share_1);

      auto share_output = share_result.Out();

      // std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      // std::cout << "party finish" << std::endl;
      if (party_0) {
        std::vector<T> result_T;
        result_T = share_output.AsFloatingPointVector<T>();
        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          EXPECT_EQ(result_T[i], (raw_global_input_1[i]) * (boolean_bit[i]));
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

// test passed
TYPED_TEST(SecureFloatingPointCircuitABYTest_with_CBMC_GC_circuit_bmr, CeilInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::srand(time(nullptr));

  T min = -std::exp2(25);
  T max = -min;
  // T min = -10000;
  // T max = -min;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, 2);

  // only for debugging
  // raw_global_input_1[0] = 1200.2;  // error
  // raw_global_input_1[0] = 4541486.6; // error

  int edge_case = std::rand() % 10;
  switch (edge_case) {
    case 0: {
      raw_global_input_1[0] = 0;
      break;
    }
    case 1: {
      raw_global_input_1[0] = -raw_global_input_1[0];
      break;
    }
    case 2: {
      raw_global_input_1[0] = 1200.2;
      break;
    }
    case 3: {
      raw_global_input_1[0] = 4541486.6;
      break;
    }
    case 4: {
      raw_global_input_1[0] = -4.2334;
      break;
    }
    case 5: {
      raw_global_input_1[0] = -4.8334;
      break;
    }
  }

  std::cout << "raw_global_input_1" << raw_global_input_1[0] << std::endl;

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(0)),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(1))};
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
                          &raw_global_input_1]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);
      EXPECT_EQ(share_1.Get()->GetBitLength(), kNumberOfWires);

      const auto share_floating_point_floor = share_0.Ceil();
      auto share_output = share_floating_point_floor.Out();

      // std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      // std::cout << "party finish" << std::endl;

      if (std::is_same<T, float>::value) {
        float result_T = share_output.AsFloatingPoint<float>();
        std::uint32_t result_uint32_t = share_output.As<std::uint32_t>();
        const float expect_result = ceil(raw_global_input_1.at(0));
        // std::cout << "raw_global_input_1: " << setprecision(20) << raw_global_input_1[0] <<
        // std::endl; std::cout << "result_float: " << setprecision(20) << result_T <<
        // std::endl; std::cout << "result_uint32_t: " << setprecision(20) << result_uint32_t
        // << std::endl; std::cout << "expect_result: " << setprecision(20) << expect_result
        // << std::endl;
        EXPECT_EQ(result_T, expect_result);
      } else if (std::is_same<T, double>::value) {
        double result_T = share_output.AsFloatingPoint<double>();
        const double expect_result = ceil(raw_global_input_1.at(0));
        // std::cout << "raw_global_input_1: " << setprecision(20) << raw_global_input_1[0] <<
        // std::endl; std::cout << "result_float: " << setprecision(20) << result_T <<
        // std::endl; std::cout << "expect_result: " << setprecision(20) << expect_result <<
        // std::endl;
        EXPECT_EQ(result_T, expect_result);
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

// test passed
TYPED_TEST(SecureFloatingPointCircuitABYTest_with_CBMC_GC_circuit_bmr, CeilSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
  std::srand(time(nullptr));

  T min = -(std::numeric_limits<T>::max() / 10);
  T max = std::numeric_limits<T>::max() / 10;
  // T min = -1000;
  // T max = 1000;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);
  // std::vector<T> raw_global_input_2 = RandomRangeVector(min, max, kNumberOfSimd);
  //  const std::vector<T> raw_global_input_1 (kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1)};

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
                          &raw_global_input_1]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY share_0 =
          party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                  : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_addition = share_0.Ceil();
      // const auto expect_result =
      //     encrypto::motion::AddVectors(raw_global_input_1, raw_global_input_2);

      auto share_output = share_addition.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<TypeParam> result_T;

        result_T = share_output.AsFloatingPointVector<TypeParam>();
        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          if (std::is_same<T, float>::value) {
            EXPECT_FLOAT_EQ(result_T[i], ceil(raw_global_input_1[i]));
          } else {
            EXPECT_DOUBLE_EQ(result_T[i], ceil(raw_global_input_1[i]));
          }
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

// test passed
TYPED_TEST(SecureFloatingPointCircuitABYTest_with_CBMC_GC_circuit_bmr, FloorInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::srand(time(nullptr));

  T min = -std::exp2(25);
  T max = -min;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, 2);
  // raw_global_input_1[0] = -4.2334;

  int edge_case = std::rand() % 10;
  switch (edge_case) {
    case 0: {
      raw_global_input_1[0] = 0;
      break;
    }
    case 1: {
      raw_global_input_1[0] = -raw_global_input_1[0];
      break;
    }
    case 2: {
      raw_global_input_1[0] = 1200.2;
      break;
    }
    case 3: {
      raw_global_input_1[0] = 4541486.6;
      break;
    }
    case 4: {
      raw_global_input_1[0] = -4.2334;
      break;
    }
    case 5: {
      raw_global_input_1[0] = -4.8334;
      break;
    }
  }

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(0)),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(1))};
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
                          &raw_global_input_1]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);
      EXPECT_EQ(share_1.Get()->GetBitLength(), kNumberOfWires);

      const auto share_floating_point_floor = share_0.Floor();
      auto share_output = share_floating_point_floor.Out();

      // std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      // std::cout << "party finish" << std::endl;

      if (std::is_same<T, float>::value) {
        float result_T = share_output.AsFloatingPoint<float>();
        const float expect_result = floor(raw_global_input_1.at(0));
        // std::cout << "raw_global_input_1: " << setprecision(20) << raw_global_input_1[0]
        //           << std::endl;
        // std::cout << "result_float: " << setprecision(20) << result_T << std::endl;
        // std::cout << "expect_result: " << setprecision(20) << expect_result << std::endl;
        EXPECT_EQ(result_T, expect_result);
      } else if (std::is_same<T, double>::value) {
        double result_T = share_output.AsFloatingPoint<double>();
        const double expect_result = floor(raw_global_input_1.at(0));
        // std::cout << "raw_global_input_1: " << setprecision(20) << raw_global_input_1[0]
        //           << std::endl;
        // std::cout << "result_float: " << setprecision(20) << result_T << std::endl;
        // std::cout << "expect_result: " << setprecision(20) << expect_result << std::endl;
        EXPECT_EQ(result_T, expect_result);
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

// test passed
TYPED_TEST(SecureFloatingPointCircuitABYTest_with_CBMC_GC_circuit_bmr, FloorSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
  std::srand(time(nullptr));

  T min = -(std::numeric_limits<T>::max() / 10);
  T max = std::numeric_limits<T>::max() / 10;
  // T min = -1000;
  // T max = 1000;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);
  // std::vector<T> raw_global_input_2 = RandomRangeVector(min, max, kNumberOfSimd);
  //  const std::vector<T> raw_global_input_1 (kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1)};

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
                          &raw_global_input_1]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY share_0 =
          party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                  : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_addition = share_0.Floor();
      // const auto expect_result =
      //     encrypto::motion::AddVectors(raw_global_input_1, raw_global_input_2);

      auto share_output = share_addition.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<TypeParam> result_T;

        result_T = share_output.AsFloatingPointVector<TypeParam>();
        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          if (std::is_same<T, float>::value) {
            EXPECT_FLOAT_EQ(result_T[i], floor(raw_global_input_1[i]));
          } else {
            EXPECT_DOUBLE_EQ(result_T[i], floor(raw_global_input_1[i]));
          }
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

// test passed
TYPED_TEST(SecureFloatingPointCircuitABYTest_with_CBMC_GC_circuit_bmr, FL2IntInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::srand(time(nullptr));

  T min = -INT32_MAX;
  T max = INT32_MAX;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, 2);
  // std::cout << "raw_global_input_1[0]" << raw_global_input_1[0] << std::endl;

  // edge case testing
  int edge_case = std::rand() % 12;
  switch (edge_case) {
    case 0: {
      raw_global_input_1[0] = 0.1;
      break;
    }
    case 1: {
      raw_global_input_1[0] = -0.1;
      break;
    }
    case 2: {
      raw_global_input_1[0] = 0.91;
      break;
    }
    case 3: {
      raw_global_input_1[0] = -0.91;
      break;
    }
    case 4: {
      raw_global_input_1[0] = 2.91;
      break;
    }
    case 5: {
      raw_global_input_1[0] = -2.91;
      break;
    }
    case 6: {
      raw_global_input_1[0] = 2.11;
      break;
    }
    case 7: {
      raw_global_input_1[0] = -2.11;
      break;
    }
  }

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(0)),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(1))};
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
                          &raw_global_input_1]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);
      EXPECT_EQ(share_1.Get()->GetBitLength(), kNumberOfWires);

      const auto share_floating_point_to_integer_32 = share_0.FL2Int(32);
      auto share_floating_point_to_integer_32_output = share_floating_point_to_integer_32.Out();

      const auto share_floating_point_to_integer_64 = share_0.FL2Int(64);
      auto share_floating_point_to_integer_64_output = share_floating_point_to_integer_64.Out();

      // std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      // std::cout << "party finish" << std::endl;

      if (std::is_same<T, float>::value) {
        std::int32_t result_T_32 = share_floating_point_to_integer_32_output.As<std::uint32_t>();
        std::int64_t result_T_64 = share_floating_point_to_integer_64_output.As<std::uint64_t>();
        const std::int32_t expect_result_32 = round(raw_global_input_1.at(0));
        const std::int64_t expect_result_64 = round(raw_global_input_1.at(0));
        EXPECT_NEAR(result_T_32, expect_result_32, 1);
        EXPECT_NEAR(result_T_64, expect_result_64, 1);

      } else if (std::is_same<T, double>::value) {
        std::int32_t result_T_32 = share_floating_point_to_integer_32_output.As<std::uint32_t>();
        std::int64_t result_T_64 = share_floating_point_to_integer_64_output.As<std::uint64_t>();
        const std::int32_t expect_result_32 = round(raw_global_input_1.at(0));
        const std::int64_t expect_result_64 = round(raw_global_input_1.at(0));
        EXPECT_NEAR(result_T_32, expect_result_32, 1);
        EXPECT_NEAR(result_T_64, expect_result_64, 1);
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

// test passed
TYPED_TEST(SecureFloatingPointCircuitABYTest_with_CBMC_GC_circuit_bmr, FL2IntSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
  std::srand(time(nullptr));

  T min = -std::exp2(20);
  T max = -min;
  // T min = -1000;
  // T max = 1000;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);
  // std::vector<T> raw_global_input_2 = RandomRangeVector(min, max, kNumberOfSimd);
  //  const std::vector<T> raw_global_input_1 (kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1)};

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
                          &raw_global_input_1]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY share_0 =
          party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                  : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result_32 = share_0.FL2Int(32);
      const auto share_result_64 = share_0.FL2Int(64);

      auto share_output_32 = share_result_32.Out();
      auto share_output_64 = share_result_64.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          if (std::is_same<T, float>::value) {
            std::vector<std::uint32_t> result_T_32 = share_output_32.AsVector<std::uint32_t>();
            EXPECT_NEAR(std::int32_t(result_T_32[i]), round(raw_global_input_1[i]), 1);
            std::vector<std::uint64_t> result_T_64 = share_output_64.AsVector<std::uint64_t>();
            EXPECT_NEAR(std::int64_t(result_T_64[i]), round(raw_global_input_1[i]), 1);
          } else {
            std::vector<std::uint32_t> result_T_32 = share_output_32.AsVector<std::uint32_t>();
            EXPECT_NEAR(std::int32_t(result_T_32[i]), round(raw_global_input_1[i]), 1);
            std::vector<std::uint64_t> result_T_64 = share_output_64.AsVector<std::uint64_t>();
            EXPECT_NEAR(std::int64_t(result_T_64[i]), round(raw_global_input_1[i]), 1);
          }
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

// test passed
TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, MulPow2mInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::srand(time(nullptr));

  T min = -1000;
  T max = 1000;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, 2);
  std::int64_t m = 10;

  // edge case test
  int test_case = std::rand() % 6;
  switch (test_case) {
    case 0:
      raw_global_input_1.at(0) = 3;
      m = 0;
      break;
    case 1:
      raw_global_input_1.at(0) = -3;
      m = 1;
      break;
    case 2:
      raw_global_input_1.at(0) = 0;
      m = 10;
      break;
    case 3:
      raw_global_input_1.at(0) = 3;
      m = -10;
      break;
    case 4:
      raw_global_input_1.at(0) = 0;
      m = -10;
      break;
  }

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(0)),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(1))};
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
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);
      EXPECT_EQ(share_1.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.MulPow2m(m);
      auto share_output = share_result.Out();

      // std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();

      const T expect_result = raw_global_input_1.at(0) * pow(2, m);
      if (std::is_same<T, float>::value) {
        T result_T = share_output.AsFloatingPoint<T>();
        EXPECT_FLOAT_EQ((result_T), (raw_global_input_1[0]) * pow(2, m));
      } else {
        T result_T = share_output.AsFloatingPoint<T>();
        EXPECT_DOUBLE_EQ((result_T), (raw_global_input_1[0]) * pow(2, m));
      }

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

// test passed
TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, MulPow2SIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
  std::srand(time(nullptr));

  T min = -100000;
  T max = 100000;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);
  // std::vector<T> raw_global_input_2 = RandomRangeVector(min, max, kNumberOfSimd);
  //  const std::vector<T> raw_global_input_1 (kNumberOfSimd);
  std::int64_t m = std::rand() % 100;

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1)};

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
      encrypto::motion::SecureFloatingPointCircuitABY share_0 =
          party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                  : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.MulPow2m(m);

      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          if (std::is_same<T, float>::value) {
            std::vector<T> result_T = share_output.AsFloatingPointVector<T>();
            EXPECT_FLOAT_EQ((result_T[i]), (raw_global_input_1[i]) * pow(2, m));
          } else {
            std::vector<T> result_T = share_output.AsFloatingPointVector<T>();
            EXPECT_DOUBLE_EQ((result_T[i]), (raw_global_input_1[i]) * pow(2, m));
          }
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

// test passed
TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, DivPow2mInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::srand(time(nullptr));

  T min = -1000;
  T max = 1000;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, 2);
  std::int64_t m = 10;

  // edge case test
  std::size_t test_case = std::rand() % 6;
  switch (test_case) {
    case 0:
      raw_global_input_1.at(0) = 3;
      m = 0;
      break;
    case 1:
      raw_global_input_1.at(0) = -3;
      m = 1;
      break;
    case 2:
      raw_global_input_1.at(0) = 0;
      m = 10;
      break;
    case 3:
      raw_global_input_1.at(0) = 3;
      m = -10;
      break;
    case 4:
      raw_global_input_1.at(0) = 0;
      m = -10;
      break;
  }

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(0)),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(1))};
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
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);
      EXPECT_EQ(share_1.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.DivPow2m(m);
      auto share_output = share_result.Out();

      // std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();

      const T expect_result = raw_global_input_1.at(0) / pow(2, m);

      if (std::is_same<T, float>::value) {
        T result_T = share_output.AsFloatingPoint<T>();
        EXPECT_FLOAT_EQ((result_T), (raw_global_input_1[0]) / pow(2, m));
      } else {
        T result_T = share_output.AsFloatingPoint<T>();
        EXPECT_DOUBLE_EQ((result_T), (raw_global_input_1[0]) / pow(2, m));
      }

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

// test passed
TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, DivPow2SIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
  std::srand(time(nullptr));

  T min = -100000;
  T max = 100000;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);
  // std::vector<T> raw_global_input_2 = RandomRangeVector(min, max, kNumberOfSimd);
  //  const std::vector<T> raw_global_input_1 (kNumberOfSimd);
  std::int64_t m = std::rand() % 100;

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1)};

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
      encrypto::motion::SecureFloatingPointCircuitABY share_0 =
          party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                  : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.DivPow2m(m);

      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          if (std::is_same<T, float>::value) {
            std::vector<T> result_T = share_output.AsFloatingPointVector<T>();
            EXPECT_FLOAT_EQ((result_T[i]), (raw_global_input_1[i]) / pow(2, m));
          } else {
            std::vector<T> result_T = share_output.AsFloatingPointVector<T>();
            EXPECT_DOUBLE_EQ((result_T[i]), (raw_global_input_1[i]) / pow(2, m));
          }
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

// test passed
TYPED_TEST(SecureFloatingPointCircuitABYTest_with_CBMC_GC_circuit_bmr, ClampBmInBmr) {
  using T = double;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::srand(time(nullptr));

  T min = -log2(std::numeric_limits<T>::max());
  T max = log2(std::numeric_limits<T>::max());

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, 2);
  double B;

  // test cases
  int test_case = std::rand() % 10;
  switch (test_case) {
    case 0:
      raw_global_input_1.at(0) = 3.1;
      B = 2.5;
      break;
    case 1:
      raw_global_input_1.at(0) = 3.7;
      B = 3.5;
      break;
    case 2:
      raw_global_input_1.at(0) = -3.1;
      B = 2.5;
      break;
    case 3:
      raw_global_input_1.at(0) = -3.9;
      B = 3.5;
      break;
  }

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(0))};
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
                          &raw_global_input_1, &B]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY share_x =
          party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                  : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0);
      // EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);
      // EXPECT_EQ(share_1.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_x.ClampB(B);
      auto share_output = share_result.Out();

      // std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();

      T expect_result = raw_global_input_1.at(0);
      if (raw_global_input_1.at(0) > B) {
        expect_result = B;
      } else if (raw_global_input_1.at(0) < -B) {
        expect_result = -B;
      }
      std::cout << "expect_result: " << expect_result << std::endl;

      T result_T;

      result_T = share_output.AsFloatingPoint<double>();
      std::cout << "result_float: " << result_T << std::endl;
      EXPECT_DOUBLE_EQ(result_T, expect_result);

      motion_parties.at(party_id)->Finish();
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFloatingPointCircuitABYTest_with_CBMC_GC_circuit_bmr, ClampBSIMDInBmr) {
  using T = double;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
  std::srand(time(nullptr));

  T min = -log2(std::numeric_limits<T>::max());
  T max = log2(std::numeric_limits<T>::max());

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);

  // guarantee B > 0
  double B = raw_global_input_1[0];
  if (B < 0) {
    B = -B;
  }

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1)};

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
                          &raw_global_input_1, &B]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY share_0 =
          party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                  : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      // std::cout << "000" << std::endl;
      const auto share_result = share_0.ClampB(B);

      auto share_output = share_result.Out();
      // std::cout << "xxx" << std::endl;

      // // std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      // std::cout << "party finished" << std::endl;

      if (party_0) {
        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          T expect_result = raw_global_input_1.at(i);
          if (raw_global_input_1.at(i) > B) {
            expect_result = B;
          } else if (raw_global_input_1.at(i) < -B) {
            expect_result = -B;
          }

          if (std::is_same<T, float>::value) {
            std::vector<T> result_T = share_output.AsFloatingPointVector<T>();
            EXPECT_FLOAT_EQ((result_T[i]), expect_result);
          } else {
            std::vector<T> result_T = share_output.AsFloatingPointVector<T>();
            EXPECT_DOUBLE_EQ((result_T[i]), expect_result);
          }
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFloatingPointCircuitABYTest_with_CBMC_GC_circuit_bmr,
           FLRoundToNearestIntegerInBmr) {
  using T = double;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::srand(time(nullptr));

  T min = -(INT64_MAX);
  T max = INT64_MAX;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, 2);

  // test casesz
  std::size_t test_case = std::rand() % 8;
  switch (test_case) {
    case 0:
      raw_global_input_1.at(0) = 3.2;
      break;
    case 1:
      raw_global_input_1.at(0) = 3.5;
      break;
    case 2:
      raw_global_input_1.at(0) = -2.1;
      break;
    case 3:
      raw_global_input_1.at(0) = -3.7;
      break;
    case 4:
      raw_global_input_1.at(0) = 0;
      break;
    case 5:
      raw_global_input_1.at(0) = 0.2;
      break;
    case 6:
      raw_global_input_1.at(0) = -0.2;
      break;
  }

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(0)),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(1))};
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
                          &raw_global_input_1]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);
      EXPECT_EQ(share_1.Get()->GetBitLength(), kNumberOfWires);

      const auto share_floating_point_to_integer = share_0.RoundToNearestInteger();
      auto share_output = share_floating_point_to_integer.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();

      double round_nearest_integer = share_output.AsFloatingPoint<double>();
      const double expect_result = round(raw_global_input_1.at(0));

      std::cout << "expect_result: " << expect_result << std::endl;
      std::cout << "raw_global_input_1[0]: " << raw_global_input_1[0] << std::endl;
      std::cout << "round_nearest_integer: " << round_nearest_integer << std::endl;

      EXPECT_EQ(expect_result, round_nearest_integer);
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFloatingPointCircuitABYTest_with_CBMC_GC_circuit_bmr,
           FLRoundToNearestIntegerSIMDInBmr) {
  using T = double;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
  std::srand(time(nullptr));

  T min = -(INT64_MAX);
  T max = INT64_MAX;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1)};

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
                          &raw_global_input_1]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY share_0 =
          party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                  : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      // std::cout << "000" << std::endl;
      const auto share_result = share_0.RoundToNearestInteger();

      auto share_output = share_result.Out();
      // std::cout << "xxx" << std::endl;

      // // std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      // std::cout << "party finished" << std::endl;

      if (party_0) {
        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          if (std::is_same<T, float>::value) {
            std::vector<T> result_T = share_output.AsFloatingPointVector<T>();
            EXPECT_FLOAT_EQ((result_T[i]), round(raw_global_input_1.at(i)));
          } else {
            std::vector<T> result_T = share_output.AsFloatingPointVector<T>();
            EXPECT_DOUBLE_EQ((result_T[i]), round(raw_global_input_1.at(i)));
          }
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, FLNegInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::srand(time(nullptr));

  T min = -(INT64_MAX);
  T max = INT64_MAX;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, 2);

  // test casesz
  std::size_t test_case = std::rand() % 8;
  switch (test_case) {
    case 0:
      raw_global_input_1.at(0) = 3.2;
      break;
    case 1:
      raw_global_input_1.at(0) = 3.5;
      break;
    case 2:
      raw_global_input_1.at(0) = -2.1;
      break;
    case 3:
      raw_global_input_1.at(0) = -3.5;
      break;
    case 4:
      raw_global_input_1.at(0) = 0;
      break;
    case 5:
      raw_global_input_1.at(0) = 0.2;
      break;
    case 6:
      raw_global_input_1.at(0) = -0.2;
      break;
  }

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(0)),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(1))};
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
                          &raw_global_input_1]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);
      EXPECT_EQ(share_1.Get()->GetBitLength(), kNumberOfWires);

      const auto share_floating_point_to_integer = share_0.Neg();
      auto share_output = share_floating_point_to_integer.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();

      double round_nearest_integer = share_output.AsFloatingPoint<T>();
      const double expect_result = -(raw_global_input_1.at(0));

      std::cout << "expect_result: " << expect_result << std::endl;
      std::cout << "raw_global_input_1[0]: " << raw_global_input_1[0] << std::endl;
      std::cout << "round_nearest_integer: " << round_nearest_integer << std::endl;

      EXPECT_EQ(expect_result, round_nearest_integer);
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, FLNegSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
  std::srand(time(nullptr));

  T min = -(std::numeric_limits<T>::max() / 10);
  T max = std::numeric_limits<T>::max() / 10;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);
  std::vector<T> raw_global_input_2 = RandomRangeVector(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_2)};

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
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Neg();
      const auto expect_result = encrypto::motion::MinusVectors<T>(raw_global_input_1);

      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<T> result_T;

        result_T = share_output.AsFloatingPointVector<T>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          if (std::is_same<T, float>::value) {
            EXPECT_FLOAT_EQ(result_T[i], expect_result[i]);
          } else if (std::is_same<T, double>::value) {
            EXPECT_DOUBLE_EQ(result_T[i], expect_result[i]);
          }
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, FLAbsInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::srand(time(nullptr));

  T min = -(INT64_MAX);
  T max = INT64_MAX;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, 2);

  // test casesz
  std::size_t test_case = std::rand() % 8;
  switch (test_case) {
    case 0:
      raw_global_input_1.at(0) = 3.2;
      break;
    case 1:
      raw_global_input_1.at(0) = 3.5;
      break;
    case 2:
      raw_global_input_1.at(0) = -2.1;
      break;
    case 3:
      raw_global_input_1.at(0) = -3.5;
      break;
    case 4:
      raw_global_input_1.at(0) = 0;
      break;
    case 5:
      raw_global_input_1.at(0) = 0.2;
      break;
    case 6:
      raw_global_input_1.at(0) = -0.2;
      break;
  }

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(0)),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(1))};
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
                          &raw_global_input_1]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);
      EXPECT_EQ(share_1.Get()->GetBitLength(), kNumberOfWires);

      const auto share_floating_point_to_integer = share_0.Abs();
      auto share_output = share_floating_point_to_integer.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();

      double abs_result = share_output.AsFloatingPoint<T>();
      const double expect_result = abs(raw_global_input_1.at(0));

      std::cout << "expect_result: " << expect_result << std::endl;
      std::cout << "raw_global_input_1[0]: " << raw_global_input_1[0] << std::endl;
      std::cout << "abs_result: " << abs_result << std::endl;

      EXPECT_EQ(expect_result, abs_result);
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, FLAbsSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
  std::srand(time(nullptr));

  T min = -(std::numeric_limits<T>::max() / 10);
  T max = std::numeric_limits<T>::max() / 10;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);
  std::vector<T> raw_global_input_2 = RandomRangeVector(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_2)};

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
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_result = share_0.Abs();
      const auto expect_result = encrypto::motion::AbsVectors(raw_global_input_1);

      auto share_output = share_result.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<T> result_T;

        result_T = share_output.AsFloatingPointVector<T>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          if (std::is_same<T, float>::value) {
            EXPECT_FLOAT_EQ(result_T[i], expect_result[i]);
          } else if (std::is_same<T, double>::value) {
            EXPECT_DOUBLE_EQ(result_T[i], expect_result[i]);
          }
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, FL2FxInBmr) {
  using T = double;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::srand(time(nullptr));

  T min = -(INT32_MAX);
  T max = INT32_MAX;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, 2);
  std::size_t fixed_point_fraction_bit_size = 16;

  // edge case test
  std::size_t test_case = std::rand() % 7;
  switch (test_case) {
    case 0:
      raw_global_input_1.at(0) = 3.2;
      break;
    case 1:
      raw_global_input_1.at(0) = 3.5;
      break;
    case 2:
      raw_global_input_1.at(0) = -2.1;
      break;
    case 3:
      raw_global_input_1.at(0) = -3.5;
      break;
    case 4:
      raw_global_input_1.at(0) = 0;
      break;
    case 5:
      raw_global_input_1.at(0) = 0.2;
      break;
    case 6:
      raw_global_input_1.at(0) = -0.2;
      break;
  }

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(0)),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1.at(1))};
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
                          &raw_global_input_1, fixed_point_fraction_bit_size]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);
      EXPECT_EQ(share_1.Get()->GetBitLength(), kNumberOfWires);

      encrypto::motion::SecureFixedPointCircuitCBMC share_floating_point_to_fixed_point =
          share_0.FL2Fx(fixed_point_fraction_bit_size);
      auto share_output = share_floating_point_to_fixed_point.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();

      if (std::is_same<T, float>::value) {
        double fixed_point_result = share_output.AsFixedPoint<std::uint64_t, std::int64_t>();
        double expect_result = (raw_global_input_1.at(0));
        EXPECT_NEAR(expect_result, fixed_point_result, 0.01);
      } else if (std::is_same<T, double>::value) {
        double fixed_point_result = share_output.AsFixedPoint<std::uint64_t, std::int64_t>();
        double expect_result = (raw_global_input_1.at(0));
        EXPECT_NEAR(expect_result, fixed_point_result, 0.01);
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, FL2FxSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{1};
  std::srand(time(nullptr));

  T min = -10000;
  T max = 10000;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);
  std::vector<T> raw_global_input_2 = RandomRangeVector(min, max, kNumberOfSimd);
  std::size_t fixed_point_fraction_bit_size = 16;
  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_2)};

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
                          &fixed_point_fraction_bit_size]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      encrypto::motion::SecureFixedPointCircuitCBMC share_floating_point_to_fixed_point =
          share_0.FL2Fx(fixed_point_fraction_bit_size);

      auto share_output = share_floating_point_to_fixed_point.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<T> result_T;

        std::vector<double> fixed_point_result =
            share_output.AsFixedPointVector<std::uint64_t, std::int64_t>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          EXPECT_NEAR(raw_global_input_1[i], fixed_point_result[i], 0.01);
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

// test passed
TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr,
           DoublePrecisionToSinglePrecisionSIMDInBmr) {
  using T = double;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
  std::srand(time(nullptr));

  // T min = -(std::numeric_limits<T>::max() / 10);
  // T max = std::numeric_limits<T>::max() / 10;
  T min = -100000;
  T max = 100000;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1)};

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
                          &raw_global_input_1]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_conversion = share_0.ConvertDoublePrecisionToSinglePrecision();

      auto share_output = share_conversion.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<float> result_T;

        result_T = share_output.AsFloatingPointVector<float>();
        // std::cout << "result_double_0: " << result_T[0] << std::endl;

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          // std::cout << "result_float_i: " << result_T[i] << std::endl;
          // std::cout << "expect_result[i]: " << expect_result[i] << std::endl;
          double abs_error = 0.01;
          EXPECT_NEAR(result_T[i], raw_global_input_1[i], abs_error);
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

// test passed
TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr,
           SinglePrecisionToDoublePrecisionSIMDInBmr) {
  using T = float;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{10};
  std::srand(time(nullptr));

  // T min = -(std::numeric_limits<T>::max() / 10);
  // T max = std::numeric_limits<T>::max() / 10;
  T min = -100000;
  T max = 100000;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1)};

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
                          &raw_global_input_1]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_conversion = share_0.ConvertSinglePrecisionToDoublePrecision();

      auto share_output = share_conversion.Out();

      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      if (party_0) {
        std::vector<double> result_T;

        result_T = share_output.AsFloatingPointVector<double>();

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          // std::cout << "raw_global_input_1.at(i): " << raw_global_input_1.at(i) <<
          // std::endl; std::cout << "result_float_i: " << result_T[i] << std::endl;
          double abs_error = 0.01;
          EXPECT_NEAR(result_T[i], raw_global_input_1[i], abs_error);
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, SinSIMDInBmr) {
  using T = double;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{500};
  std::srand(time(nullptr));

  // T min = -(std::numeric_limits<T>::max() / 10);
  // T max = std::numeric_limits<T>::max() / 10;
  T min = -100;
  T max = 100;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);

  // // only for debugging
  // for (std::size_t i = 0; i < kNumberOfSimd; i++) {
  //   raw_global_input_1[i] = 0.2515;
  // }

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1)};

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
                          &raw_global_input_1]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_conversion = share_0.Sin();

      auto share_output = share_conversion.Out();

      // // std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      // // std::cout << "party finish" << std::endl;
      if (party_0) {
        std::vector<T> result_T;

        result_T = share_output.AsFloatingPointVector<T>();
        // std::cout << "result_double_0: " << result_T[0] << std::endl;

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          // std::cout << "raw_global_input_1[i] : " << (raw_global_input_1[i]) << std::endl;
          // std::cout << "raw_global_input_1[i] * M_PI: " << (raw_global_input_1[i] * M_PI)
          // << std::endl; std::cout << "expect_result: " << sin(raw_global_input_1[i] * M_PI)
          // << std::endl; std::cout << "result_float_i: " << result_T[i] << std::endl;
          double abs_error = 0.01;
          EXPECT_NEAR(result_T[i], sin(raw_global_input_1[i] * M_PI), abs_error);
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

TYPED_TEST(SecureFloatingPointCircuitABYTest_with_ABY_circuit_bmr, CosSIMDInBmr) {
  using T = TypeParam;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kNumberOfWires{sizeof(T) * 8};
  constexpr std::size_t kNumberOfSimd{500};
  std::srand(time(nullptr));

  // T min = -(std::numeric_limits<T>::max() / 10);
  // T max = std::numeric_limits<T>::max() / 10;
  T min = -100;
  T max = 100;

  std::vector<T> raw_global_input_1 = RandomRangeVector(min, max, kNumberOfSimd);

  // // only for debugging
  // for (std::size_t i = 0; i < kNumberOfSimd; i++) {
  //   raw_global_input_1[i] = 0.15;
  // }

  std::vector<std::vector<encrypto::motion::BitVector<>>> global_input{
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1),
      encrypto::motion::ToInput<T, std::true_type>(raw_global_input_1)};

  // only for debugging
  // std::cout << "bitvector: ";
  // for (std::size_t i = 0; i < kNumberOfWires; i++) {
  //   std::cout << global_input[0][kNumberOfWires-1-i];
  // }

  std::cout << std::endl;

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
                          &raw_global_input_1]() {
      const bool party_0 = motion_parties.at(party_id)->GetConfiguration()->GetMyId() == 0;
      encrypto::motion::SecureFloatingPointCircuitABY
          share_0 = party_0 ? motion_parties.at(party_id)->In<kBmr>(global_input.at(0), 0)
                            : motion_parties.at(party_id)->In<kBmr>(dummy_input, 0),
          share_1 = party_0 ? motion_parties.at(party_id)->In<kBmr>(dummy_input, 1)
                            : motion_parties.at(party_id)->In<kBmr>(global_input.at(1), 1);
      EXPECT_EQ(share_0.Get()->GetBitLength(), kNumberOfWires);

      const auto share_conversion = share_0.Cos();

      auto share_output = share_conversion.Out();

      // std::cout << "party run" << std::endl;
      motion_parties.at(party_id)->Run();
      motion_parties.at(party_id)->Finish();
      // std::cout << "party finish" << std::endl;
      if (party_0) {
        std::vector<T> result_T;

        result_T = share_output.AsFloatingPointVector<T>();
        // std::cout << "result_double_0: " << result_T[0] << std::endl;

        for (std::size_t i = 0; i < kNumberOfSimd; i++) {
          // std::cout << "raw_global_input_1[i] : " << (raw_global_input_1[i]) << std::endl;
          // std::cout << "raw_global_input_1[i] * M_PI: " << (raw_global_input_1[i] * M_PI)
          // << std::endl; std::cout << "expect_result: " << cos(raw_global_input_1[i] * M_PI)
          // << std::endl; std::cout << "result_float_i: " << result_T[i] << std::endl;
          double abs_error = 0.01;
          EXPECT_NEAR(result_T[i], cos(raw_global_input_1[i] * M_PI), abs_error);
        }
      }
    });
  }
  for (auto& t : threads)
    if (t.joinable()) t.join();
}

}  // namespace
