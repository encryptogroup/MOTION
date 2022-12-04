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
#include "utility/MOTION_dp_mechanism_helper/discrete_gaussian_mechanism.h"
#include "utility/MOTION_dp_mechanism_helper/dp_mechanism_helper.h"
#include "utility/MOTION_dp_mechanism_helper/integer_scaling_mechanism.h"
#include "utility/MOTION_dp_mechanism_helper/snapping_mechanism.h"
#include "utility/config.h"

#include "test_constants.h"

using namespace encrypto::motion;

namespace {

// test passed
TEST(SecureSamplingAlgorithm_naive, FLGeometricDistributionEXP_GC_2_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1, auto template_variable_2,
                          auto template_variable_3) {
    using T = decltype(template_variable_1);
    using T_int = decltype(template_variable_2);
    using FLType = decltype(template_variable_3);
    using A = std::allocator<T>;

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      // double scale = 0.8;
      // std::uint64_t numerator = decimalToFraction(1 / scale)[0];
      // std::uint64_t denominator = decimalToFraction(1 / scale)[1];

      // // only for debug
      // numerator = std::rand() % 10 + 1;
      // denominator = std::rand() % 300 + 1;

      std::size_t num_of_elements = 1;
      double min = 0;
      double max = 2;

      std::vector<double> scale_double_vector = rand_range_double_vector(min, max, num_of_elements);

      long double x_geo = scale_double_vector[0];

      std::cout << "x_geo: " << x_geo << std::endl;

      std::size_t num_of_simd = 10;

      // std::cout << "numerator: " << numerator << std::endl;
      // std::cout << "denominator: " << denominator << std::endl;

      GeometricDistributionEXPOptimizationStruct<T>
          optimize_geometric_distribution_EXP_iteration_result_struct =
              optimize_geometric_distribution_EXP_iteration<T>(x_geo, standard_failure_probability);

      std::size_t iteration_1 =
          optimize_geometric_distribution_EXP_iteration_result_struct.iteration_1;
      std::size_t iteration_2 =
          optimize_geometric_distribution_EXP_iteration_result_struct.iteration_2;
      std::size_t total_iteration =
          optimize_geometric_distribution_EXP_iteration_result_struct.minimum_total_iteration;
      long double total_failure_probability =
          optimize_geometric_distribution_EXP_iteration_result_struct
              .geometric_failure_probability_estimation;

      T numerator = optimize_geometric_distribution_EXP_iteration_result_struct.numerator;
      T denominator = optimize_geometric_distribution_EXP_iteration_result_struct.denominator;

      std::cout << "numerator: " << numerator << std::endl;
      std::cout << "denominator: " << denominator << std::endl;

      // if (denominator == 1) {
      //   iteration_1 = 0;
      // }

      std::cout << "iteration_1: " << iteration_1 << std::endl;
      std::cout << "iteration_2: " << iteration_2 << std::endl;
      std::cout << "total_iteration: " << total_iteration << std::endl;
      std::cout << "total_failure_probability: " << total_failure_probability << std::endl;

      // std::vector<double> random_floating_point_0_1_vector =
      //     RandomRangeVector<double>(0, 1, (iteration_1 + iteration_2) * num_of_simd);
      std::vector<double> random_floating_point_0_1_vector =
          rand_range_double_vector(0, 1, (iteration_1 + iteration_2) * num_of_simd);

      // for (std::size_t i = 0; i < random_floating_point_0_1_vector.size(); ++i) {
      //   std::cout << "random_floating_point_0_1_vector: " <<
      // random_floating_point_0_1_vector[i]
      //             << std::endl;
      // }

      std::vector<T> random_unsigned_integer_vector =
          rand_range_integer_vector<T>(0, denominator, num_of_simd * iteration_1);

      // for (std::size_t i = 0; i < random_unsigned_integer_vector.size(); ++i) {
      //   std::cout << "random_unsigned_integer_vector[i]: " <<
      // random_unsigned_integer_vector[i]
      //             << std::endl;
      // }

      std::vector<T> expect_result(num_of_simd);
      std::vector<bool> expect_result_success(num_of_simd);

      for (std::size_t i = 0; i < num_of_simd; i++) {
        std::cout << "SIMD: " << i << std::endl;

        std::vector<double> random_floating_point_0_1_subvector(
            random_floating_point_0_1_vector.begin() + i * iteration_1,
            random_floating_point_0_1_vector.begin() + (i + 1) * iteration_1);

        random_floating_point_0_1_subvector.insert(
            random_floating_point_0_1_subvector.end(),
            random_floating_point_0_1_vector.begin() + num_of_simd * iteration_1 + i * iteration_2,
            random_floating_point_0_1_vector.begin() + num_of_simd * iteration_1 +
                (i + 1) * iteration_2);

        std::vector<T> random_unsigned_integer_subvector(
            random_unsigned_integer_vector.begin() + i * iteration_1,
            random_unsigned_integer_vector.begin() + (i + 1) * iteration_1);

        if (denominator != 1) {
          std::vector<T> result = geometric_distribution_EXP<T, A>(
              numerator, denominator, random_floating_point_0_1_subvector,
              random_unsigned_integer_subvector, iteration_1, iteration_2);
          expect_result[i] = result[0];
          expect_result_success[i] = result[1];
          std::cout << "expect_result[i]: " << expect_result[i] << std::endl;
          std::cout << "expect_result_success[i]: " << expect_result_success[i] << std::endl;
          std::cout << std::endl;
        } else {
          std::vector<T> result = geometric_distribution_EXP<T, A>(
              numerator, random_floating_point_0_1_subvector, iteration_2);
          expect_result[i] = result[0];
          expect_result_success[i] = result[1];
          std::cout << "expect_result[i]: " << expect_result[i] << std::endl;
          std::cout << "expect_result_success[i]: " << expect_result_success[i] << std::endl;
          std::cout << std::endl;
        }
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
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point_0_1_vector(
              (iteration_1 + iteration_2) * num_of_simd);
          std::vector<encrypto::motion::ShareWrapper> share_random_unsigned_integer(num_of_simd *
                                                                                    iteration_1);
          for (std::size_t i = 0; i < num_of_simd * (iteration_1 + iteration_2); i++) {
            share_random_floating_point_0_1_vector[i] =
                motion_parties.at(party_id)->In<kGarbledCircuit>(
                    ToInput<FLType, std::true_type>(FLType(random_floating_point_0_1_vector[i])),
                    0);
          }

          for (std::size_t i = 0; i < num_of_simd * iteration_1; i++) {
            share_random_unsigned_integer[i] = motion_parties.at(party_id)->In<kGarbledCircuit>(
                ToInput<T>(random_unsigned_integer_vector[i]), 0);
          }

          std::vector<T> unsigned_integer_numerator_vector(num_of_simd, numerator);
          std::vector<T> unsigned_integer_denominator_vector(num_of_simd, denominator);

          std::vector<ShareWrapper> share_result;

          if (denominator != 1) {
            share_result =
                SecureSamplingAlgorithm_naive(share_random_floating_point_0_1_vector[0])
                    .FLGeometricDistributionEXP_GC<FLType, T, T_int, A>(
                        unsigned_integer_numerator_vector, unsigned_integer_denominator_vector,
                        encrypto::motion::ShareWrapper::Simdify(
                            share_random_floating_point_0_1_vector),
                        encrypto::motion::ShareWrapper::Simdify(share_random_unsigned_integer),
                        iteration_1, iteration_2);

          } else {
            share_result = SecureSamplingAlgorithm_naive(share_random_floating_point_0_1_vector[0])
                               .FLGeometricDistributionEXP_GC<FLType, T, T_int, A>(
                                   unsigned_integer_numerator_vector,
                                   encrypto::motion::ShareWrapper::Simdify(
                                       share_random_floating_point_0_1_vector),
                                   iteration_2);
          }

          encrypto::motion::SecureUnsignedInteger share_result_0_out = share_result[0].Out();
          encrypto::motion::ShareWrapper share_result_1_out = share_result[1].Out();

          // // only for debugging purposes
          encrypto::motion::SecureFloatingPointCircuitABY share_result_2_out;
          encrypto::motion::SecureFloatingPointCircuitABY share_result_3_out;
          encrypto::motion::SecureFloatingPointCircuitABY share_result_4_out;
          encrypto::motion::SecureFloatingPointCircuitABY share_result_5_out;
          encrypto::motion::SecureUnsignedInteger share_result_6_out;
          encrypto::motion::SecureUnsignedInteger share_result_7_out;
          encrypto::motion::SecureUnsignedInteger share_result_8_out;
          if (denominator != 1) {
            share_result_2_out = share_result[2].Out();
            share_result_3_out = share_result[3].Out();

            share_result_4_out = share_result[4].Out();
            share_result_5_out = share_result[5].Out();

            share_result_6_out = share_result[6].Out();
            share_result_7_out = share_result[7].Out();
            share_result_8_out = share_result[8].Out();
          }

          std::cout << "party run" << std::endl;
          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            std::vector<T> share_result_0_out_as = share_result_0_out.AsVector<T>();
            BitVector<> share_result_1_out_as = share_result_1_out.As<BitVector<>>();

            std::cout << std::endl;
            for (std::size_t i = 0; i < num_of_simd; ++i) {
              std::cout << "SIMD: " << i << std::endl;
              std::cout << "share_result_0_out_as[i]: " << share_result_0_out_as[i] << std::endl;
              if (share_result_1_out_as.Get(i)) {
                std::cout << "success" << std::endl;
              } else {
                std::cout << "fail" << std::endl;
              }

              std::cout << std::endl;
            };
            std::cout << "share_result_success_vector: " << share_result_1_out_as << std::endl;

            // // only for debugging purposes
            if (denominator != 1) {
              for (std::size_t i = 0; i < iteration_1; ++i) {
                std::cout << "floating_point_denominator_simdify: "
                          << share_result_2_out.AsFloatingPointVector<FLType>()[i] << std::endl;
              };

              for (std::size_t i = 0; i < iteration_1 * num_of_simd; ++i) {
                std::cout << "floating_point_random_unsigned_integer: "
                          << share_result_3_out.AsFloatingPointVector<FLType>()[i] << std::endl;
              };

              for (std::size_t i = 0; i < iteration_1 * num_of_simd; ++i) {
                std::cout << "floating_point_unsigned_integer_denominator_simdify: "
                          << share_result_4_out.AsFloatingPointVector<FLType>()[i] << std::endl;
              };
              for (std::size_t i = 0; i < iteration_1 * num_of_simd; ++i) {
                std::cout << "floating_point_random_unsigned_integer_div_denominator: "
                          << share_result_5_out.AsFloatingPointVector<FLType>()[i] << std::endl;
              };

              for (std::size_t i = 0; i < num_of_simd; ++i) {
                std::cout << "boolean_gmw_share_v: " << share_result_6_out.AsVector<T>()[i]
                          << std::endl;
              };
              for (std::size_t i = 0; i < num_of_simd; ++i) {
                std::cout << "boolean_gmw_share_u: " << share_result_7_out.AsVector<T>()[i]
                          << std::endl;
              };
              for (std::size_t i = 0; i < num_of_simd; ++i) {
                std::cout << "unsigned_integer_w: " << share_result_8_out.AsVector<T>()[i]
                          << std::endl;
              };
              std::cout << std::endl;
            }

            for (std::size_t i = 0; i < num_of_simd; i++) {
              EXPECT_EQ(expect_result[i], share_result_0_out_as[i]);
              EXPECT_EQ(expect_result_success[i], share_result_1_out_as.Get(i));
            }
          }
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    template_test(static_cast<std::uint64_t>(0), static_cast<std::int64_t>(0),
                  static_cast<float>(0));
    template_test(static_cast<std::uint64_t>(0), static_cast<std::int64_t>(0),
                  static_cast<double>(0));
  }
}



// test passed
TEST(SecureSamplingAlgorithm_naive, FLGeometricDistributionEXP_BGMW_2_3_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1, auto template_variable_2,
                          auto template_variable_3) {
    using T = decltype(template_variable_1);
    using T_int = decltype(template_variable_2);
    using FLType = decltype(template_variable_3);
    using A = std::allocator<T>;

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      // double scale = 0.8;
      // std::uint64_t numerator = decimalToFraction(1 / scale)[0];
      // std::uint64_t denominator = decimalToFraction(1 / scale)[1];

      // // only for debug
      // numerator = std::rand() % 10 + 1;
      // denominator = std::rand() % 300 + 1;

      std::size_t num_of_elements = 1;
      double min = 0;
      double max = 2;

      std::vector<double> scale_double_vector = rand_range_double_vector(min, max, num_of_elements);

      long double x_geo = scale_double_vector[0];

      std::cout << "x_geo: " << x_geo << std::endl;

      std::size_t num_of_simd = 10;

      // std::cout << "numerator: " << numerator << std::endl;
      // std::cout << "denominator: " << denominator << std::endl;

      GeometricDistributionEXPOptimizationStruct<T>
          optimize_geometric_distribution_EXP_iteration_result_struct =
              optimize_geometric_distribution_EXP_iteration<T>(x_geo, standard_failure_probability);

      std::size_t iteration_1 =
          optimize_geometric_distribution_EXP_iteration_result_struct.iteration_1;
      std::size_t iteration_2 =
          optimize_geometric_distribution_EXP_iteration_result_struct.iteration_2;
      std::size_t total_iteration =
          optimize_geometric_distribution_EXP_iteration_result_struct.minimum_total_iteration;
      long double total_failure_probability =
          optimize_geometric_distribution_EXP_iteration_result_struct
              .geometric_failure_probability_estimation;

      T numerator = optimize_geometric_distribution_EXP_iteration_result_struct.numerator;
      T denominator = optimize_geometric_distribution_EXP_iteration_result_struct.denominator;

      std::cout << "numerator: " << numerator << std::endl;
      std::cout << "denominator: " << denominator << std::endl;

      // if (denominator == 1) {
      //   iteration_1 = 0;
      // }

      std::cout << "iteration_1: " << iteration_1 << std::endl;
      std::cout << "iteration_2: " << iteration_2 << std::endl;
      std::cout << "total_iteration: " << total_iteration << std::endl;
      std::cout << "total_failure_probability: " << total_failure_probability << std::endl;

      // std::vector<double> random_floating_point_0_1_vector =
      //     RandomRangeVector<double>(0, 1, (iteration_1 + iteration_2) * num_of_simd);
      std::vector<double> random_floating_point_0_1_vector =
          rand_range_double_vector(0, 1, (iteration_1 + iteration_2) * num_of_simd);

      // for (std::size_t i = 0; i < random_floating_point_0_1_vector.size(); ++i) {
      //   std::cout << "random_floating_point_0_1_vector: " <<
      // random_floating_point_0_1_vector[i]
      //             << std::endl;
      // }

      std::vector<T> random_unsigned_integer_vector =
          rand_range_integer_vector<T>(0, denominator, num_of_simd * iteration_1);

      // for (std::size_t i = 0; i < random_unsigned_integer_vector.size(); ++i) {
      //   std::cout << "random_unsigned_integer_vector[i]: " <<
      // random_unsigned_integer_vector[i]
      //             << std::endl;
      // }

      std::vector<T> expect_result(num_of_simd);
      std::vector<bool> expect_result_success(num_of_simd);

      for (std::size_t i = 0; i < num_of_simd; i++) {
        std::cout << "SIMD: " << i << std::endl;

        std::vector<double> random_floating_point_0_1_subvector(
            random_floating_point_0_1_vector.begin() + i * iteration_1,
            random_floating_point_0_1_vector.begin() + (i + 1) * iteration_1);

        random_floating_point_0_1_subvector.insert(
            random_floating_point_0_1_subvector.end(),
            random_floating_point_0_1_vector.begin() + num_of_simd * iteration_1 + i * iteration_2,
            random_floating_point_0_1_vector.begin() + num_of_simd * iteration_1 +
                (i + 1) * iteration_2);

        std::vector<T> random_unsigned_integer_subvector(
            random_unsigned_integer_vector.begin() + i * iteration_1,
            random_unsigned_integer_vector.begin() + (i + 1) * iteration_1);

        if (denominator != 1) {
          std::vector<T> result = geometric_distribution_EXP<T, A>(
              numerator, denominator, random_floating_point_0_1_subvector,
              random_unsigned_integer_subvector, iteration_1, iteration_2);
          expect_result[i] = result[0];
          expect_result_success[i] = result[1];
          std::cout << "expect_result[i]: " << expect_result[i] << std::endl;
          std::cout << "expect_result_success[i]: " << expect_result_success[i] << std::endl;
          std::cout << std::endl;
        } else {
          std::vector<T> result = geometric_distribution_EXP<T, A>(
              numerator, random_floating_point_0_1_subvector, iteration_2);
          expect_result[i] = result[0];
          expect_result_success[i] = result[1];
          std::cout << "expect_result[i]: " << expect_result[i] << std::endl;
          std::cout << "expect_result_success[i]: " << expect_result_success[i] << std::endl;
          std::cout << std::endl;
        }
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
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point_0_1_vector(
              (iteration_1 + iteration_2) * num_of_simd);
          std::vector<encrypto::motion::ShareWrapper> share_random_unsigned_integer(num_of_simd *
                                                                                    iteration_1);
          for (std::size_t i = 0; i < num_of_simd * (iteration_1 + iteration_2); i++) {
            share_random_floating_point_0_1_vector[i] =
                motion_parties.at(party_id)->In<kBooleanGmw>(
                    ToInput<FLType, std::true_type>(FLType(random_floating_point_0_1_vector[i])),
                    0);
          }

          for (std::size_t i = 0; i < num_of_simd * iteration_1; i++) {
            share_random_unsigned_integer[i] = motion_parties.at(party_id)->In<kBooleanGmw>(
                ToInput<T>(random_unsigned_integer_vector[i]), 0);
          }

          std::vector<T> unsigned_integer_numerator_vector(num_of_simd, numerator);
          std::vector<T> unsigned_integer_denominator_vector(num_of_simd, denominator);

          std::vector<ShareWrapper> share_result;

          if (denominator != 1) {
            share_result =
                SecureSamplingAlgorithm_naive(share_random_floating_point_0_1_vector[0])
                    .FLGeometricDistributionEXP_BGMW<FLType, T, T_int, A>(
                        unsigned_integer_numerator_vector, unsigned_integer_denominator_vector,
                        encrypto::motion::ShareWrapper::Simdify(
                            share_random_floating_point_0_1_vector),
                        encrypto::motion::ShareWrapper::Simdify(share_random_unsigned_integer),
                        iteration_1, iteration_2);

          } else {
            share_result = SecureSamplingAlgorithm_naive(share_random_floating_point_0_1_vector[0])
                               .FLGeometricDistributionEXP_BGMW<FLType, T, T_int, A>(
                                   unsigned_integer_numerator_vector,
                                   encrypto::motion::ShareWrapper::Simdify(
                                       share_random_floating_point_0_1_vector),
                                   iteration_2);
          }

          encrypto::motion::SecureUnsignedInteger share_result_0_out = share_result[0].Out();
          encrypto::motion::ShareWrapper share_result_1_out = share_result[1].Out();

          // // only for debugging purposes
          encrypto::motion::SecureFloatingPointCircuitABY share_result_2_out;
          encrypto::motion::SecureFloatingPointCircuitABY share_result_3_out;
          encrypto::motion::SecureFloatingPointCircuitABY share_result_4_out;
          encrypto::motion::SecureFloatingPointCircuitABY share_result_5_out;
          encrypto::motion::SecureUnsignedInteger share_result_6_out;
          encrypto::motion::SecureUnsignedInteger share_result_7_out;
          encrypto::motion::SecureUnsignedInteger share_result_8_out;
          if (denominator != 1) {
            share_result_2_out = share_result[2].Out();
            share_result_3_out = share_result[3].Out();

            share_result_4_out = share_result[4].Out();
            share_result_5_out = share_result[5].Out();

            share_result_6_out = share_result[6].Out();
            share_result_7_out = share_result[7].Out();
            share_result_8_out = share_result[8].Out();
          }

          std::cout << "party run" << std::endl;
          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            std::vector<T> share_result_0_out_as = share_result_0_out.AsVector<T>();
            BitVector<> share_result_1_out_as = share_result_1_out.As<BitVector<>>();

            std::cout << std::endl;
            for (std::size_t i = 0; i < num_of_simd; ++i) {
              std::cout << "SIMD: " << i << std::endl;
              std::cout << "share_result_0_out_as[i]: " << share_result_0_out_as[i] << std::endl;
              if (share_result_1_out_as.Get(i)) {
                std::cout << "success" << std::endl;
              } else {
                std::cout << "fail" << std::endl;
              }

              std::cout << std::endl;
            };
            std::cout << "share_result_success_vector: " << share_result_1_out_as << std::endl;

            // // only for debugging purposes
            if (denominator != 1) {
              for (std::size_t i = 0; i < iteration_1; ++i) {
                std::cout << "floating_point_denominator_simdify: "
                          << share_result_2_out.AsFloatingPointVector<FLType>()[i] << std::endl;
              };

              for (std::size_t i = 0; i < iteration_1 * num_of_simd; ++i) {
                std::cout << "floating_point_random_unsigned_integer: "
                          << share_result_3_out.AsFloatingPointVector<FLType>()[i] << std::endl;
              };

              for (std::size_t i = 0; i < iteration_1 * num_of_simd; ++i) {
                std::cout << "floating_point_unsigned_integer_denominator_simdify: "
                          << share_result_4_out.AsFloatingPointVector<FLType>()[i] << std::endl;
              };
              for (std::size_t i = 0; i < iteration_1 * num_of_simd; ++i) {
                std::cout << "floating_point_random_unsigned_integer_div_denominator: "
                          << share_result_5_out.AsFloatingPointVector<FLType>()[i] << std::endl;
              };

              for (std::size_t i = 0; i < num_of_simd; ++i) {
                std::cout << "boolean_gmw_share_v: " << share_result_6_out.AsVector<T>()[i]
                          << std::endl;
              };
              for (std::size_t i = 0; i < num_of_simd; ++i) {
                std::cout << "boolean_gmw_share_u: " << share_result_7_out.AsVector<T>()[i]
                          << std::endl;
              };
              for (std::size_t i = 0; i < num_of_simd; ++i) {
                std::cout << "unsigned_integer_w: " << share_result_8_out.AsVector<T>()[i]
                          << std::endl;
              };
              std::cout << std::endl;
            }

            for (std::size_t i = 0; i < num_of_simd; i++) {
              EXPECT_EQ(expect_result[i], share_result_0_out_as[i]);
              EXPECT_EQ(expect_result_success[i], share_result_1_out_as.Get(i));
            }
          }
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    template_test(static_cast<std::uint64_t>(0), static_cast<std::int64_t>(0),
                  static_cast<float>(0));
    template_test(static_cast<std::uint64_t>(0), static_cast<std::int64_t>(0),
                  static_cast<double>(0));
  }
}






TEST(SecureSamplingAlgorithm_naive, FLGeometricDistributionEXP_BMR_2_3_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1, auto template_variable_2,
                          auto template_variable_3) {
    using T = decltype(template_variable_1);
    using T_int = decltype(template_variable_2);
    using FLType = decltype(template_variable_3);
    using A = std::allocator<T>;

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      // double scale = 0.8;
      // std::uint64_t numerator = decimalToFraction(1 / scale)[0];
      // std::uint64_t denominator = decimalToFraction(1 / scale)[1];

      // // only for debug
      // numerator = std::rand() % 10 + 1;
      // denominator = std::rand() % 300 + 1;

      std::size_t num_of_elements = 1;
      double min = 0;
      double max = 2;

      std::vector<double> scale_double_vector = rand_range_double_vector(min, max, num_of_elements);

      long double x_geo = scale_double_vector[0];

      std::cout << "x_geo: " << x_geo << std::endl;

      std::size_t num_of_simd = 10;

      // std::cout << "numerator: " << numerator << std::endl;
      // std::cout << "denominator: " << denominator << std::endl;

      GeometricDistributionEXPOptimizationStruct<T>
          optimize_geometric_distribution_EXP_iteration_result_struct =
              optimize_geometric_distribution_EXP_iteration<T>(x_geo, standard_failure_probability);

      std::size_t iteration_1 =
          optimize_geometric_distribution_EXP_iteration_result_struct.iteration_1;
      std::size_t iteration_2 =
          optimize_geometric_distribution_EXP_iteration_result_struct.iteration_2;
      std::size_t total_iteration =
          optimize_geometric_distribution_EXP_iteration_result_struct.minimum_total_iteration;
      long double total_failure_probability =
          optimize_geometric_distribution_EXP_iteration_result_struct
              .geometric_failure_probability_estimation;

      T numerator = optimize_geometric_distribution_EXP_iteration_result_struct.numerator;
      T denominator = optimize_geometric_distribution_EXP_iteration_result_struct.denominator;

      std::cout << "numerator: " << numerator << std::endl;
      std::cout << "denominator: " << denominator << std::endl;

      // if (denominator == 1) {
      //   iteration_1 = 0;
      // }

      std::cout << "iteration_1: " << iteration_1 << std::endl;
      std::cout << "iteration_2: " << iteration_2 << std::endl;
      std::cout << "total_iteration: " << total_iteration << std::endl;
      std::cout << "total_failure_probability: " << total_failure_probability << std::endl;

      // std::vector<double> random_floating_point_0_1_vector =
      //     RandomRangeVector<double>(0, 1, (iteration_1 + iteration_2) * num_of_simd);
      std::vector<double> random_floating_point_0_1_vector =
          rand_range_double_vector(0, 1, (iteration_1 + iteration_2) * num_of_simd);

      // for (std::size_t i = 0; i < random_floating_point_0_1_vector.size(); ++i) {
      //   std::cout << "random_floating_point_0_1_vector: " <<
      // random_floating_point_0_1_vector[i]
      //             << std::endl;
      // }

      std::vector<T> random_unsigned_integer_vector =
          rand_range_integer_vector<T>(0, denominator, num_of_simd * iteration_1);

      // for (std::size_t i = 0; i < random_unsigned_integer_vector.size(); ++i) {
      //   std::cout << "random_unsigned_integer_vector[i]: " <<
      // random_unsigned_integer_vector[i]
      //             << std::endl;
      // }

      std::vector<T> expect_result(num_of_simd);
      std::vector<bool> expect_result_success(num_of_simd);

      for (std::size_t i = 0; i < num_of_simd; i++) {
        std::cout << "SIMD: " << i << std::endl;

        std::vector<double> random_floating_point_0_1_subvector(
            random_floating_point_0_1_vector.begin() + i * iteration_1,
            random_floating_point_0_1_vector.begin() + (i + 1) * iteration_1);

        random_floating_point_0_1_subvector.insert(
            random_floating_point_0_1_subvector.end(),
            random_floating_point_0_1_vector.begin() + num_of_simd * iteration_1 + i * iteration_2,
            random_floating_point_0_1_vector.begin() + num_of_simd * iteration_1 +
                (i + 1) * iteration_2);

        std::vector<T> random_unsigned_integer_subvector(
            random_unsigned_integer_vector.begin() + i * iteration_1,
            random_unsigned_integer_vector.begin() + (i + 1) * iteration_1);

        if (denominator != 1) {
          std::vector<T> result = geometric_distribution_EXP<T, A>(
              numerator, denominator, random_floating_point_0_1_subvector,
              random_unsigned_integer_subvector, iteration_1, iteration_2);
          expect_result[i] = result[0];
          expect_result_success[i] = result[1];
          std::cout << "expect_result[i]: " << expect_result[i] << std::endl;
          std::cout << "expect_result_success[i]: " << expect_result_success[i] << std::endl;
          std::cout << std::endl;
        } else {
          std::vector<T> result = geometric_distribution_EXP<T, A>(
              numerator, random_floating_point_0_1_subvector, iteration_2);
          expect_result[i] = result[0];
          expect_result_success[i] = result[1];
          std::cout << "expect_result[i]: " << expect_result[i] << std::endl;
          std::cout << "expect_result_success[i]: " << expect_result_success[i] << std::endl;
          std::cout << std::endl;
        }
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
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point_0_1_vector(
              (iteration_1 + iteration_2) * num_of_simd);
          std::vector<encrypto::motion::ShareWrapper> share_random_unsigned_integer(num_of_simd *
                                                                                    iteration_1);
          for (std::size_t i = 0; i < num_of_simd * (iteration_1 + iteration_2); i++) {
            share_random_floating_point_0_1_vector[i] =
                motion_parties.at(party_id)->In<kBmr>(
                    ToInput<FLType, std::true_type>(FLType(random_floating_point_0_1_vector[i])),
                    0);
          }

          for (std::size_t i = 0; i < num_of_simd * iteration_1; i++) {
            share_random_unsigned_integer[i] = motion_parties.at(party_id)->In<kBmr>(
                ToInput<T>(random_unsigned_integer_vector[i]), 0);
          }

          std::vector<T> unsigned_integer_numerator_vector(num_of_simd, numerator);
          std::vector<T> unsigned_integer_denominator_vector(num_of_simd, denominator);

          std::vector<ShareWrapper> share_result;

          if (denominator != 1) {
            share_result =
                SecureSamplingAlgorithm_naive(share_random_floating_point_0_1_vector[0])
                    .FLGeometricDistributionEXP_BMR<FLType, T, T_int, A>(
                        unsigned_integer_numerator_vector, unsigned_integer_denominator_vector,
                        encrypto::motion::ShareWrapper::Simdify(
                            share_random_floating_point_0_1_vector),
                        encrypto::motion::ShareWrapper::Simdify(share_random_unsigned_integer),
                        iteration_1, iteration_2);

          } else {
            share_result = SecureSamplingAlgorithm_naive(share_random_floating_point_0_1_vector[0])
                               .FLGeometricDistributionEXP_BMR<FLType, T, T_int, A>(
                                   unsigned_integer_numerator_vector,
                                   encrypto::motion::ShareWrapper::Simdify(
                                       share_random_floating_point_0_1_vector),
                                   iteration_2);
          }

          encrypto::motion::SecureUnsignedInteger share_result_0_out = share_result[0].Out();
          encrypto::motion::ShareWrapper share_result_1_out = share_result[1].Out();

          // // only for debugging purposes
          encrypto::motion::SecureFloatingPointCircuitABY share_result_2_out;
          encrypto::motion::SecureFloatingPointCircuitABY share_result_3_out;
          encrypto::motion::SecureFloatingPointCircuitABY share_result_4_out;
          encrypto::motion::SecureFloatingPointCircuitABY share_result_5_out;
          encrypto::motion::SecureUnsignedInteger share_result_6_out;
          encrypto::motion::SecureUnsignedInteger share_result_7_out;
          encrypto::motion::SecureUnsignedInteger share_result_8_out;
          if (denominator != 1) {
            share_result_2_out = share_result[2].Out();
            share_result_3_out = share_result[3].Out();

            share_result_4_out = share_result[4].Out();
            share_result_5_out = share_result[5].Out();

            share_result_6_out = share_result[6].Out();
            share_result_7_out = share_result[7].Out();
            share_result_8_out = share_result[8].Out();
          }

          std::cout << "party run" << std::endl;
          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            std::vector<T> share_result_0_out_as = share_result_0_out.AsVector<T>();
            BitVector<> share_result_1_out_as = share_result_1_out.As<BitVector<>>();

            std::cout << std::endl;
            for (std::size_t i = 0; i < num_of_simd; ++i) {
              std::cout << "SIMD: " << i << std::endl;
              std::cout << "share_result_0_out_as[i]: " << share_result_0_out_as[i] << std::endl;
              if (share_result_1_out_as.Get(i)) {
                std::cout << "success" << std::endl;
              } else {
                std::cout << "fail" << std::endl;
              }

              std::cout << std::endl;
            };
            std::cout << "share_result_success_vector: " << share_result_1_out_as << std::endl;

            // // only for debugging purposes
            if (denominator != 1) {
              for (std::size_t i = 0; i < iteration_1; ++i) {
                std::cout << "floating_point_denominator_simdify: "
                          << share_result_2_out.AsFloatingPointVector<FLType>()[i] << std::endl;
              };

              for (std::size_t i = 0; i < iteration_1 * num_of_simd; ++i) {
                std::cout << "floating_point_random_unsigned_integer: "
                          << share_result_3_out.AsFloatingPointVector<FLType>()[i] << std::endl;
              };

              for (std::size_t i = 0; i < iteration_1 * num_of_simd; ++i) {
                std::cout << "floating_point_unsigned_integer_denominator_simdify: "
                          << share_result_4_out.AsFloatingPointVector<FLType>()[i] << std::endl;
              };
              for (std::size_t i = 0; i < iteration_1 * num_of_simd; ++i) {
                std::cout << "floating_point_random_unsigned_integer_div_denominator: "
                          << share_result_5_out.AsFloatingPointVector<FLType>()[i] << std::endl;
              };

              for (std::size_t i = 0; i < num_of_simd; ++i) {
                std::cout << "boolean_gmw_share_v: " << share_result_6_out.AsVector<T>()[i]
                          << std::endl;
              };
              for (std::size_t i = 0; i < num_of_simd; ++i) {
                std::cout << "boolean_gmw_share_u: " << share_result_7_out.AsVector<T>()[i]
                          << std::endl;
              };
              for (std::size_t i = 0; i < num_of_simd; ++i) {
                std::cout << "unsigned_integer_w: " << share_result_8_out.AsVector<T>()[i]
                          << std::endl;
              };
              std::cout << std::endl;
            }

            for (std::size_t i = 0; i < num_of_simd; i++) {
              EXPECT_EQ(expect_result[i], share_result_0_out_as[i]);
              EXPECT_EQ(expect_result_success[i], share_result_1_out_as.Get(i));
            }
          }
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    template_test(static_cast<std::uint64_t>(0), static_cast<std::int64_t>(0),
                  static_cast<float>(0));
    template_test(static_cast<std::uint64_t>(0), static_cast<std::int64_t>(0),
                  static_cast<double>(0));
  }
}








}  // namespace