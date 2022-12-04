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

#include <fstream>
#include <random>

#include <gtest/gtest.h>

#include "algorithm/algorithm_description.h"
#include "base/party.h"
#include "protocols/bmr/bmr_wire.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/share_wrapper.h"
#include "secure_dp_mechanism/secure_sampling_algorithm_naive.h"
#include "secure_dp_mechanism/secure_snapping_mechanism.h"
#include "secure_type/secure_unsigned_integer.h"
#include "test_helpers.h"
#include "utility/MOTION_dp_mechanism_helper/dp_mechanism_helper.h"
#include "utility/MOTION_dp_mechanism_helper/snapping_mechanism.h"
#include "utility/config.h"

#include "test_constants.h"

using namespace encrypto::motion;

namespace {

// test passed
TEST(BasicRandomNumberGeneration, GenerateRandomUnsignedIntegerPow2BGMW_20_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1) {
    using T = decltype(template_variable_1);

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      std::size_t num_of_simd = 20;
      std::size_t k = std::rand() % (sizeof(T) * 8);
      if (k == 0) {
        k = 1;
      }

      // only for debugging
      // k=1;
      // k=20;

      std::cout << "k: " << k << std::endl;
      print_u128_u("T(1)<<k: ", T(1) << k);

      try {
        std::vector<PartyPointer> motion_parties(
            std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
        for (auto& party : motion_parties) {
          party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
          party->GetConfiguration()->SetOnlineAfterSetup(std::mt19937{}() % 2 == 1);
        }
#pragma omp parallel num_threads(motion_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(motion_parties.size())
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          encrypto::motion::ShareWrapper share_random_unsigned_integer_0_m_vector;
          encrypto::motion::ShareWrapper share_x;

          for (std::size_t i = 0; i < num_of_simd; i++) {
            share_x =
                motion_parties.at(party_id)->In<kBooleanGmw>(ToInput<double, std::true_type>(0), 0);
          }

          SecureUnsignedInteger share_result =
              SecureSamplingAlgorithm_naive(share_x).GenerateRandomUnsignedIntegerPow2BGMW<T>(
                  k, num_of_simd);

          encrypto::motion::SecureUnsignedInteger share_result_out = share_result.Out();

          std::cout << "party run" << std::endl;
          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            std::vector<T> share_result_out_as = share_result_out.AsVector<T>();

            for (std::size_t i = 0; i < num_of_simd; i++) {
              // std::cout << "share_result_out_as[i]: " << share_result_out_as[i] << std::endl;
              print_u128_u("share_result_out_as[i]: ", share_result_out_as[i]);

              EXPECT_LT(share_result_out_as[i], T(1) << k);
              EXPECT_LE(0, share_result_out_as[i]);
            }
          }
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    template_test(static_cast<std::uint8_t>(0));
    template_test(static_cast<std::uint16_t>(0));
    template_test(static_cast<std::uint32_t>(0));
    template_test(static_cast<std::uint64_t>(0));
    template_test(static_cast<__uint128_t>(0));
  }
}

// test passed
TEST(BasicRandomNumberGeneration, GenerateRandomUnsignedIntegerBGMW_20_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1, auto template_variable_2) {
    using T = decltype(template_variable_1);
    using T_expand = decltype(template_variable_2);

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      std::size_t num_of_simd = 20;
      T m = std::rand();
      if (m == 0) {
        m = 1;
      }

      // only for debugging
      // m = 32;

      // std::cout << "m: " << m << std::endl;
      print_u128_u("m: ", m);

      try {
        std::vector<PartyPointer> motion_parties(
            std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
        for (auto& party : motion_parties) {
          party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
          party->GetConfiguration()->SetOnlineAfterSetup(std::mt19937{}() % 2 == 1);
        }
#pragma omp parallel num_threads(motion_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(motion_parties.size())
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          encrypto::motion::ShareWrapper share_random_unsigned_integer_0_m_vector;
          encrypto::motion::ShareWrapper share_x;

          for (std::size_t i = 0; i < num_of_simd; i++) {
            share_x =
                motion_parties.at(party_id)->In<kBooleanGmw>(ToInput<double, std::true_type>(0), 0);
          }

          SecureUnsignedInteger share_result =
              SecureSamplingAlgorithm_naive(share_x).GenerateRandomUnsignedIntegerBGMW<T, T_expand>(
                  m, num_of_simd);

          encrypto::motion::SecureUnsignedInteger share_result_out = share_result.Out();

          std::cout << "party run" << std::endl;
          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            std::vector<T> share_result_out_as = share_result_out.AsVector<T>();

            for (std::size_t i = 0; i < num_of_simd; i++) {
              // std::cout << "share_result_out_as[i]: " << share_result_out_as[i] << std::endl;
              print_u128_u("share_result_out_as[i]: ", share_result_out_as[i]);

              EXPECT_LT(share_result_out_as[i], m);
              EXPECT_LE(0, share_result_out_as[i]);
            }
          }
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    template_test(static_cast<std::uint8_t>(0), static_cast<std::uint16_t>(0));
    template_test(static_cast<std::uint16_t>(0), static_cast<std::uint32_t>(0));
    template_test(static_cast<std::uint32_t>(0), static_cast<std::uint64_t>(0));
    template_test(static_cast<std::uint64_t>(0), static_cast<__uint128_t>(0));
  }
}

// test passed
TEST(BasicRandomNumberGeneration, GenerateRandomUnsignedIntegerBMR_20_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1, auto template_variable_2) {
    using T = decltype(template_variable_1);
    using T_expand = decltype(template_variable_2);

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      std::size_t num_of_simd = 20;
      T m = std::rand();
      if (m == 0) {
        m = 1;
      }

      // only for debugging
      // m = 32;

      // std::cout << "m: " << m << std::endl;
      print_u128_u("m: ", m);

      try {
        std::vector<PartyPointer> motion_parties(
            std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
        for (auto& party : motion_parties) {
          party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
          party->GetConfiguration()->SetOnlineAfterSetup(std::mt19937{}() % 2 == 1);
        }
#pragma omp parallel num_threads(motion_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(motion_parties.size())
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          encrypto::motion::ShareWrapper share_random_unsigned_integer_0_m_vector;
          encrypto::motion::ShareWrapper share_x;

          for (std::size_t i = 0; i < num_of_simd; i++) {
            share_x = motion_parties.at(party_id)->In<kBmr>(ToInput<double, std::true_type>(0), 0);
          }

          SecureUnsignedInteger share_result =
              SecureSamplingAlgorithm_naive(share_x).GenerateRandomUnsignedIntegerBMR<T, T_expand>(
                  m, num_of_simd);

          encrypto::motion::SecureUnsignedInteger share_result_out = share_result.Out();

          std::cout << "party run" << std::endl;
          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            std::vector<T> share_result_out_as = share_result_out.AsVector<T>();

            for (std::size_t i = 0; i < num_of_simd; i++) {
              // std::cout << "share_result_out_as[i]: " << share_result_out_as[i] << std::endl;
              print_u128_u("share_result_out_as[i]: ", share_result_out_as[i]);

              EXPECT_LT(share_result_out_as[i], m);
              EXPECT_LE(0, share_result_out_as[i]);
            }
          }
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    template_test(static_cast<std::uint8_t>(0), static_cast<std::uint16_t>(0));
    template_test(static_cast<std::uint16_t>(0), static_cast<std::uint32_t>(0));
    template_test(static_cast<std::uint32_t>(0), static_cast<std::uint64_t>(0));
    template_test(static_cast<std::uint64_t>(0), static_cast<__uint128_t>(0));
  }
}

TEST(BasicRandomNumberGeneration, GenerateRandomUnsignedIntegerGC_20_Simd_2_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  auto template_test = [](auto template_variable_1, auto template_variable_2) {
    using T = decltype(template_variable_1);
    using T_expand = decltype(template_variable_2);

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      std::size_t num_of_simd = 20;
      T m = std::rand();
      if (m == 0) {
        m = 1;
      }

      // only for debugging
      // m = 32;

      // std::cout << "m: " << m << std::endl;
      print_u128_u("m: ", m);

      try {
        std::vector<PartyPointer> motion_parties(
            std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
        for (auto& party : motion_parties) {
          party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
          party->GetConfiguration()->SetOnlineAfterSetup(std::mt19937{}() % 2 == 1);
        }
#pragma omp parallel num_threads(motion_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(motion_parties.size())
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          encrypto::motion::ShareWrapper share_random_unsigned_integer_0_m_vector;
          encrypto::motion::ShareWrapper share_x;

          for (std::size_t i = 0; i < num_of_simd; i++) {
            share_x =
                motion_parties.at(party_id)->In<kBooleanGmw>(ToInput<double, std::true_type>(0), 0);
          }

          SecureUnsignedInteger share_result =
              SecureSamplingAlgorithm_naive(share_x).GenerateRandomUnsignedIntegerGC<T, T_expand>(
                  m, num_of_simd);

          encrypto::motion::SecureUnsignedInteger share_result_out = share_result.Out();

          std::cout << "party run" << std::endl;
          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            std::vector<T> share_result_out_as = share_result_out.AsVector<T>();

            for (std::size_t i = 0; i < num_of_simd; i++) {
              // std::cout << "share_result_out_as[i]: " << share_result_out_as[i] << std::endl;
              print_u128_u("share_result_out_as[i]: ", share_result_out_as[i]);

              EXPECT_LT(share_result_out_as[i], m);
              EXPECT_LE(0, share_result_out_as[i]);
            }
          }
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    template_test(static_cast<std::uint8_t>(0), static_cast<std::uint16_t>(0));
    template_test(static_cast<std::uint16_t>(0), static_cast<std::uint32_t>(0));
    template_test(static_cast<std::uint32_t>(0), static_cast<std::uint64_t>(0));
    template_test(static_cast<std::uint64_t>(0), static_cast<__uint128_t>(0));
  }
}

}  // namespace
