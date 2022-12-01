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
#include "secure_dp_mechanism/secure_snapping_mechanism.h"
#include "secure_type/secure_unsigned_integer.h"
#include "test_helpers.h"
#include "utility/MOTION_dp_mechanism_helper/discrete_gaussian_mechanism.h"
#include "utility/MOTION_dp_mechanism_helper/dp_mechanism_helper.h"
#include "utility/MOTION_dp_mechanism_helper/integer_scaling_mechanism.h"
#include "utility/MOTION_dp_mechanism_helper/snapping_mechanism.h"
#include "utility/config.h"
#include "secure_dp_mechanism/secure_sampling_algorithm_naive.h"

#include "test_constants.h"

using namespace encrypto::motion;

namespace {

// ? test passed
TEST(SecureSamplingAlgorithm_naive,
     FLSymmetricBinomialDistribution_constant_0_1_1_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1, auto template_variable_2,
                          auto template_variable_3) {
    using IntType = decltype(template_variable_1);
    using IntType_int = get_int_type_t<IntType>;
    using FLType = decltype(template_variable_3);
    using T = std::uint64_t;
    using T_int = std::int64_t;
    using A = std::allocator<IntType>;
    std::srand(std::time(nullptr));

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      std::size_t num_of_simd = 1;

      double sqrt_n;
      if (std::is_same_v<IntType, __uint128_t>) {
        sqrt_n = std::exp2(56);
      } else {
        sqrt_n = std::exp2(40);
      }

      std::cout << "sqrt_n: " << sqrt_n << std::endl;
      double m = floor(M_SQRT2 * sqrt_n + 1);
      std::cout << "m: " << m << std::endl;
      std::vector<double> sqrt_n_vector(num_of_simd, sqrt_n);
      std::vector<double> m_vector(num_of_simd, m);
      long double failure_probability_requirement = std::exp2(-20);

      std::vector<long double> optimize_symmetrical_binomial_distribution_iteration_result =
          optimize_symmetrical_binomial_distribution_iteration(sqrt_n,
                                                               failure_probability_requirement);

      std::size_t iterations = optimize_symmetrical_binomial_distribution_iteration_result[0];
      long double failure_probability =
          optimize_symmetrical_binomial_distribution_iteration_result[1];

      // only for debug
      iterations = 50;

      std::cout << "iterations: " << iterations << std::endl;
      std::cout << "failure_probability: " << failure_probability << std::endl;

      std::vector<T> signed_integer_geometric_sample_vector =
          RandomRangeIntegerVector<T>(0, 10, iterations * num_of_simd);

      std::vector<bool> random_bits_vector = RandomBoolVector(iterations * num_of_simd);

      std::vector<T> random_unsigned_integer_vector =
          RandomRangeIntegerVector<T>(0, m, iterations * num_of_simd);

      std::vector<double> random_floating_point_0_1_vector =
          RandomRangeVector<double>(0, 1, iterations * num_of_simd);

      std::vector<IntType> expect_result(num_of_simd);
      std::vector<bool> expect_result_success(num_of_simd);
      for (std::size_t i = 0; i < num_of_simd; i++) {
        std::cout << "SIMD: " << i << std::endl;

        std::vector<T> signed_integer_geometric_sample_subvector(
            signed_integer_geometric_sample_vector.begin() + i * iterations,
            signed_integer_geometric_sample_vector.begin() + (i + 1) * iterations);

        std::vector<bool> random_bits_subvector(random_bits_vector.begin() + i * iterations,
                                                random_bits_vector.begin() + (i + 1) * iterations);

        std::vector<T> random_unsigned_integer_subvector(
            random_unsigned_integer_vector.begin() + i * iterations,
            random_unsigned_integer_vector.begin() + (i + 1) * iterations);

        std::vector<double> random_floating_point_0_1_subvector(
            random_floating_point_0_1_vector.begin() + i * iterations,
            random_floating_point_0_1_vector.begin() + (i + 1) * iterations);

        // std::cout << "unsigned_integer_numerator_vector[i]: "
        //           << unsigned_integer_numerator_vector[i] << std::endl;
        // std::cout << "unsigned_integer_denominator_vector[i]: "
        //           << unsigned_integer_denominator_vector[i] << std::endl;

        // for (std::size_t i = 0; i < (iteration_1 + iteration_2); ++i) {
        //   std::cout << "random_floating_point_0_1_subvector[i]: "
        //             << random_floating_point_0_1_subvector[i] << std::endl;
        // }

        // for (std::size_t i = 0; i < (iteration_1); ++i) {
        //   std::cout << "random_unsigned_integer_subvector[i]: "
        //             << random_unsigned_integer_subvector[i] << std::endl;
        // }

        std::vector<IntType> result = symmetrical_binomial_distribution<IntType, IntType_int, A>(
            sqrt_n_vector[i], signed_integer_geometric_sample_subvector, random_bits_subvector,
            random_unsigned_integer_subvector, random_floating_point_0_1_subvector, iterations);
        expect_result[i] = result[0];
        expect_result_success[i] = result[1];
        std::cout << std::endl;
      }

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
          std::vector<encrypto::motion::ShareWrapper> share_signed_integer_geometric_sample_vector(
              iterations * num_of_simd);
          std::vector<encrypto::motion::ShareWrapper> share_random_bits_vector(iterations *
                                                                               num_of_simd);
          std::vector<encrypto::motion::ShareWrapper> share_random_unsigned_integer_vector(
              iterations * num_of_simd);
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point_0_1_vector(
              iterations * num_of_simd);

          for (std::size_t i = 0; i < iterations * num_of_simd; i++) {
            share_signed_integer_geometric_sample_vector[i] =
                motion_parties.at(party_id)->In<kBooleanGmw>(
                    ToInput<IntType>(IntType_int(T_int(signed_integer_geometric_sample_vector[i]))),
                    0);
            share_random_bits_vector[i] = motion_parties.at(party_id)->In<kBooleanGmw>(
                BitVector<>(1, random_bits_vector[i]), 0);
            share_random_unsigned_integer_vector[i] = motion_parties.at(party_id)->In<kBooleanGmw>(
                ToInput<IntType>(random_unsigned_integer_vector[i]), 0);
            share_random_floating_point_0_1_vector[i] =
                motion_parties.at(party_id)->In<kBooleanGmw>(
                    ToInput<double, std::true_type>(random_floating_point_0_1_vector[i]), 0);
          }

          std::vector<ShareWrapper> share_result =
              SecureSamplingAlgorithm_naive(share_random_floating_point_0_1_vector[0])
                  .FLSymmetricBinomialDistribution_BGMW<double, IntType>(
                      sqrt_n_vector,
                      encrypto::motion::ShareWrapper::Simdify(
                          share_signed_integer_geometric_sample_vector),
                      encrypto::motion::ShareWrapper::Simdify(share_random_bits_vector),
                      encrypto::motion::ShareWrapper::Simdify(share_random_unsigned_integer_vector),
                      encrypto::motion::ShareWrapper::Simdify(
                          share_random_floating_point_0_1_vector),
                      iterations);

          encrypto::motion::SecureUnsignedInteger share_result_0_out = share_result[0].Out();
          encrypto::motion::ShareWrapper share_result_1_out = share_result[1].Out();

          encrypto::motion::SecureFloatingPointCircuitABY share_result_2_out =
              share_result[2].Out();
          encrypto::motion::SecureUnsignedInteger share_result_3_out = share_result[3].Out();
          encrypto::motion::SecureFloatingPointCircuitABY share_result_4_out =
              share_result[4].Out();
          encrypto::motion::ShareWrapper share_result_5_out = share_result[5].Out();
          encrypto::motion::SecureFloatingPointCircuitABY share_result_6_out =
              share_result[6].Out();
          encrypto::motion::SecureFloatingPointCircuitABY share_result_7_out =
              share_result[7].Out();
          encrypto::motion::ShareWrapper share_result_8_out = share_result[8].Out();
          encrypto::motion::ShareWrapper share_result_9_out = share_result[9].Out();
          encrypto::motion::SecureFloatingPointCircuitABY share_result_10_out =
              share_result[10].Out();
          encrypto::motion::SecureFloatingPointCircuitABY share_result_11_out =
              share_result[11].Out();

          std::cout << "party run" << std::endl;
          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            std::vector<IntType> share_result_0_out_as = share_result_0_out.AsVector<IntType>();
            BitVector<> share_result_1_out_as = share_result_1_out.As<BitVector<>>();
            // std::cout << "share_result_0_out_as: " << share_result_0_out_as << std::endl;

            std::cout << std::endl;
            for (std::size_t i = 0; i < num_of_simd; ++i) {
              std::cout << "SIMD: " << i << std::endl;
              print_u128_u_neg("share_result_0_out_as[i]: ", (share_result_0_out_as[i]));
              if (share_result_1_out_as.Get(i)) {
                std::cout << "success" << std::endl;
              } else {
                std::cout << "fail" << std::endl;
              }

              std::cout << std::endl;
            };
            std::cout << "share_result_success_vector: " << share_result_1_out_as << std::endl;

            // only for debug
            for (std::size_t i = 0; i < iterations * num_of_simd; ++i) {
              std::cout << "floating_point_floating_point_p_i: "
                        << share_result_2_out.AsFloatingPointVector<double>()[i] << std::endl;
            };
            for (std::size_t i = 0; i < iterations * num_of_simd; ++i) {
              print_u128_u_neg("signed_integer_i: ", share_result_3_out.AsVector<IntType>()[i]);
            };
            for (std::size_t i = 0; i < iterations * num_of_simd; ++i) {
              std::cout << "floating_point_signed_i: "
                        << share_result_4_out.AsFloatingPointVector<double>()[i] << std::endl;
            };
            for (std::size_t i = 0; i < iterations * num_of_simd; ++i) {
              std::cout << "boolean_gmw_share_i_in_range_condition: "
                        << share_result_5_out.As<BitVector<>>()[i] << std::endl;
            };
            for (std::size_t i = 0; i < iterations * num_of_simd; ++i) {
              std::cout << "floating_point_pow2_s: "
                        << share_result_6_out.AsFloatingPointVector<double>()[i] << std::endl;
            };
            for (std::size_t i = 0; i < iterations * num_of_simd; ++i) {
              std::cout << "floating_point_p_i_mul_f: "
                        << share_result_7_out.AsFloatingPointVector<double>()[i] << std::endl;
            };
            for (std::size_t i = 0; i < iterations * num_of_simd; ++i) {
              std::cout << "boolean_gmw_share_choice: " << share_result_8_out.As<BitVector<>>()[i]
                        << std::endl;
            };
            for (std::size_t i = 0; i < iterations * num_of_simd; ++i) {
              std::cout << "boolean_gmw_share_Bernoulli_c: "
                        << share_result_9_out.As<BitVector<>>()[i] << std::endl;
            };
            for (std::size_t i = 0; i < iterations * num_of_simd; ++i) {
              std::cout << "random_floating_point_0_1_boolean_gmw_share: "
                        << share_result_10_out.AsFloatingPointVector<double>()[i] << std::endl;
            };
            for (std::size_t i = 0; i < iterations * num_of_simd; ++i) {
              std::cout << "signed_integer_s.Int2FL(FLType_size): "
                        << share_result_11_out.AsFloatingPointVector<double>()[i] << std::endl;
            };

            for (std::size_t i = 0; i < num_of_simd; i++) {
              print_u128_u_neg("expect_result[i]: ", expect_result[i]);
              print_u128_u_neg("share_result_0_out_as[i]: ", share_result_0_out_as[i]);

              EXPECT_EQ(expect_result[i], share_result_0_out_as[i]);
              EXPECT_EQ(expect_result_success[i], share_result_1_out_as.Get(i));
            }
            std::cout << std::endl;
          }
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    template_test(static_cast<std::uint64_t>(0), static_cast<std::int64_t>(0),
                  static_cast<double>(0));
    // template_test(static_cast<__uint128_t>(0), static_cast<__int128_t>(0), static_cast<double>(0));
  }
}

}  // namespace
