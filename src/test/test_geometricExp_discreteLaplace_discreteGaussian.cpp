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
#include "secure_dp_mechanism/secure_dp_mechanism_helper.h"
#include "secure_type/secure_unsigned_integer.h"
#include "test_constants.h"
#include "test_helpers.h"
#include "utility/MOTION_dp_mechanism_helper/discrete_gaussian_mechanism.h"
#include "utility/MOTION_dp_mechanism_helper/dp_mechanism_helper.h"
#include "utility/MOTION_dp_mechanism_helper/integer_scaling_mechanism.h"
#include "utility/MOTION_dp_mechanism_helper/print_uint128_t.h"
#include "utility/MOTION_dp_mechanism_helper/snapping_mechanism.h"
#include "utility/config.h"

using namespace encrypto::motion;

namespace {

TEST(GeometricExp, FLGeometricDistributionEXP1_0_1_1_Simd_2_3_4_5_10_parties) {
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

      double scale = 0.8;
      std::uint64_t numerator = decimalToFraction(1 / scale)[0];
      std::uint64_t denominator = decimalToFraction(1 / scale)[1];

      // generate random numerator and denominator values
      numerator = std::rand() % 10 + 1;
      denominator = std::rand() % 300 + 1;

      std::size_t num_of_simd = 10;

      // std::cout << "numerator: " << numerator << std::endl;
      // std::cout << "denominator: " << denominator << std::endl;

      double required_fail_probability = std::exp2(-10);

      std::vector<long double> optimize_geometric_distribution_EXP_iteration_result_vector =
          optimize_geometric_distribution_EXP_iteration<T>(numerator, denominator,
                                                           required_fail_probability);

      std::size_t iteration_1 = optimize_geometric_distribution_EXP_iteration_result_vector[0];
      std::size_t iteration_2 = optimize_geometric_distribution_EXP_iteration_result_vector[1];
      std::size_t total_iteration = optimize_geometric_distribution_EXP_iteration_result_vector[2];
      long double total_fail_probability =
          optimize_geometric_distribution_EXP_iteration_result_vector[3];

      if (denominator == 1) {
        iteration_1 = 0;
      }

      // std::cout << "iteration_1: " << iteration_1 << std::endl;
      // std::cout << "iteration_2: " << iteration_2 << std::endl;
      // std::cout << "total_iteration: " << total_iteration << std::endl;
      // std::cout << "total_fail_probability: " << total_fail_probability << std::endl;

      std::vector<double> random_floating_point_0_1_vector =
          rand_range_double_vector(0, 1, (iteration_1 + iteration_2) * num_of_simd);

      std::vector<T> random_unsigned_integer_vector =
          rand_range_integer_vector<T>(0, denominator, num_of_simd * iteration_1);

      std::vector<T> expect_result(num_of_simd);
      std::vector<bool> expect_result_success(num_of_simd);

      for (std::size_t i = 0; i < num_of_simd; i++) {
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
        } else {
          std::vector<T> result = geometric_distribution_EXP<T, A>(
              numerator, random_floating_point_0_1_subvector, iteration_2);
          expect_result[i] = result[0];
          expect_result_success[i] = result[1];
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
                SecureDPMechanismHelper(share_random_floating_point_0_1_vector[0])
                    .FLGeometricDistributionEXP<FLType, T, T_int>(
                        unsigned_integer_numerator_vector, unsigned_integer_denominator_vector,
                        encrypto::motion::ShareWrapper::Simdify(
                            share_random_floating_point_0_1_vector),
                        encrypto::motion::ShareWrapper::Simdify(share_random_unsigned_integer),
                        iteration_1, iteration_2);
          } else {
            share_result = SecureDPMechanismHelper(share_random_floating_point_0_1_vector[0])
                               .FLGeometricDistributionEXP<FLType, T, T_int>(
                                   unsigned_integer_numerator_vector,
                                   encrypto::motion::ShareWrapper::Simdify(
                                       share_random_floating_point_0_1_vector),
                                   iteration_2);
          }

          encrypto::motion::SecureUnsignedInteger share_result_0_out = share_result[0].Out();
          encrypto::motion::ShareWrapper share_result_1_out = share_result[1].Out();

          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            std::vector<T> share_result_0_out_as = share_result_0_out.AsVector<T>();
            BitVector<> share_result_1_out_as = share_result_1_out.As<BitVector<>>();

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

TEST(DiscreteLaplace, FLDiscreteLaplaceDistributionEXP1_0_1_1_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  // std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1, auto template_variable_2,
                          auto template_variable_3) {
    using T = decltype(template_variable_1);
    using T_int = decltype(template_variable_2);
    using FLType = decltype(template_variable_3);
    using A = std::allocator<T>;
    std::srand(std::time(nullptr));

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      double scale = 0.25;
      std::uint64_t numerator = decimalToFraction(1 / scale)[0];
      std::uint64_t denominator = decimalToFraction(1 / scale)[1];

      // generate random numerator and denominator values
      numerator = std::rand() % 10 + 1;
      denominator = std::rand() % 300 + 1;

      std::size_t num_of_simd_dlap = 3;

      // std::cout << "numerator: " << numerator << std::endl;
      // std::cout << "denominator: " << denominator << std::endl;

      double required_fail_probability = std::exp2(-10);

      std::vector<long double> optimize_discrete_laplace_distribution_EXP_iteration_result_vector =
          optimize_discrete_laplace_distribution_EXP_iteration<T>(numerator, denominator,
                                                                  required_fail_probability);

      std::size_t iteration_1 =
          optimize_discrete_laplace_distribution_EXP_iteration_result_vector[0];
      std::size_t iteration_2 =
          optimize_discrete_laplace_distribution_EXP_iteration_result_vector[1];
      std::size_t iteration_3 =
          optimize_discrete_laplace_distribution_EXP_iteration_result_vector[2];
      std::size_t total_iteration =
          optimize_discrete_laplace_distribution_EXP_iteration_result_vector[3];
      std::size_t minimum_total_MPC_time =
          optimize_discrete_laplace_distribution_EXP_iteration_result_vector[4];
      long double geometric_fail_probability_estimation =
          optimize_discrete_laplace_distribution_EXP_iteration_result_vector[5];
      long double total_fail_probability =
          optimize_discrete_laplace_distribution_EXP_iteration_result_vector[6];

      if (denominator == 1) {
        iteration_1 = 0;
      }

      // std::cout << "iteration_1: " << iteration_1 << std::endl;
      // std::cout << "iteration_2: " << iteration_2 << std::endl;
      // std::cout << "iteration_3: " << iteration_3 << std::endl;
      // std::cout << "total_iteration: " << total_iteration << std::endl;
      // std::cout << "minimum_total_MPC_time: " << minimum_total_MPC_time << std::endl;
      // std::cout << "geometric_fail_probability_estimation: "
      //           << geometric_fail_probability_estimation << std::endl;
      // std::cout << "total_fail_probability: " << total_fail_probability << std::endl;

      std::size_t num_of_simd_geo = iteration_3;
      std::size_t num_of_simd_total = num_of_simd_dlap * num_of_simd_geo;

      std::vector<double> random_floating_point_0_1_vector =
          rand_range_double_vector(0, 1, (iteration_1 + iteration_2) * num_of_simd_total);

      std::vector<T> random_unsigned_integer_vector =
          rand_range_integer_vector<T>(0, denominator, iteration_1 * num_of_simd_total);

      std::vector<bool> bernoulli_sample_vector = rand_bool_vector(num_of_simd_total);

      std::vector<T> expect_result(num_of_simd_dlap);
      std::vector<bool> expect_result_success(num_of_simd_dlap);

      for (std::size_t i = 0; i < num_of_simd_dlap; i++) {
        std::vector<double> random_floating_point_0_1_subvector(
            random_floating_point_0_1_vector.begin() + i * iteration_1 * num_of_simd_geo,
            random_floating_point_0_1_vector.begin() + (i + 1) * iteration_1 * num_of_simd_geo);

        random_floating_point_0_1_subvector.insert(
            random_floating_point_0_1_subvector.end(),
            random_floating_point_0_1_vector.begin() +
                num_of_simd_dlap * iteration_1 * num_of_simd_geo +
                i * iteration_2 * num_of_simd_geo,
            random_floating_point_0_1_vector.begin() +
                num_of_simd_dlap * iteration_1 * num_of_simd_geo +
                (i + 1) * iteration_2 * num_of_simd_geo);

        std::vector<T> random_unsigned_integer_subvector(
            random_unsigned_integer_vector.begin() + i * iteration_1 * num_of_simd_geo,
            random_unsigned_integer_vector.begin() + (i + 1) * iteration_1 * num_of_simd_geo);

        std::vector<bool> bernoulli_sample_subvector(
            bernoulli_sample_vector.begin() + i * iteration_3,
            bernoulli_sample_vector.begin() + (i + 1) * iteration_3);

        if (denominator != 1) {
          std::vector<T> result = discrete_laplace_distribution_EXP<T, A>(
              numerator, denominator, random_floating_point_0_1_subvector,
              random_unsigned_integer_subvector, bernoulli_sample_subvector, iteration_1,
              iteration_2, iteration_3);
          expect_result[i] = result[0];
          expect_result_success[i] = result[1];
        } else {
          std::vector<T> result = discrete_laplace_distribution_EXP<T, A>(
              numerator, random_floating_point_0_1_subvector, bernoulli_sample_subvector,
              iteration_2, iteration_3);
          expect_result[i] = result[0];
          expect_result_success[i] = result[1];
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
              (iteration_1 + iteration_2) * num_of_simd_total);
          std::vector<encrypto::motion::ShareWrapper> share_random_unsigned_integer_vector(
              num_of_simd_total * iteration_1);
          std::vector<encrypto::motion::ShareWrapper> share_bernoulli_sample_vector(
              num_of_simd_total);

          for (std::size_t i = 0; i < num_of_simd_total * (iteration_1 + iteration_2); i++) {
            share_random_floating_point_0_1_vector[i] =
                motion_parties.at(party_id)->In<kBooleanGmw>(
                    ToInput<FLType, std::true_type>(FLType(random_floating_point_0_1_vector[i])),
                    0);
          }

          for (std::size_t i = 0; i < num_of_simd_total * iteration_1; i++) {
            share_random_unsigned_integer_vector[i] = motion_parties.at(party_id)->In<kBooleanGmw>(
                ToInput<T>(random_unsigned_integer_vector[i]), 0);
          }

          for (std::size_t i = 0; i < num_of_simd_total; i++) {
            share_bernoulli_sample_vector[i] = motion_parties.at(party_id)->In<kBooleanGmw>(
                BitVector<>(1, bernoulli_sample_vector[i]), 0);
          }

          std::vector<T> unsigned_integer_numerator_vector(num_of_simd_dlap, numerator);
          std::vector<T> unsigned_integer_denominator_vector(num_of_simd_dlap, denominator);

          std::vector<ShareWrapper> share_result;

          if (denominator != 1) {
            share_result =
                SecureDPMechanismHelper(share_random_floating_point_0_1_vector[0])
                    .FLDiscreteLaplaceDistribution<FLType, T, T_int>(
                        unsigned_integer_numerator_vector, unsigned_integer_denominator_vector,
                        encrypto::motion::ShareWrapper::Simdify(
                            share_random_floating_point_0_1_vector),
                        encrypto::motion::ShareWrapper::Simdify(
                            share_random_unsigned_integer_vector),
                        encrypto::motion::ShareWrapper::Simdify(share_bernoulli_sample_vector),
                        iteration_1, iteration_2, iteration_3);
          } else {
            share_result =
                SecureDPMechanismHelper(share_random_floating_point_0_1_vector[0])
                    .FLDiscreteLaplaceDistribution<FLType, T, T_int>(
                        unsigned_integer_numerator_vector,
                        encrypto::motion::ShareWrapper::Simdify(
                            share_random_floating_point_0_1_vector),
                        encrypto::motion::ShareWrapper::Simdify(share_bernoulli_sample_vector),
                        iteration_2, iteration_3);
          }

          encrypto::motion::SecureSignedInteger share_result_0_out = share_result[0].Out();
          encrypto::motion::ShareWrapper share_result_1_out = share_result[1].Out();

          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            std::vector<T> share_result_0_out_as = share_result_0_out.AsVector<T>();
            BitVector<> share_result_1_out_as = share_result_1_out.As<BitVector<>>();

            for (std::size_t i = 0; i < num_of_simd_dlap; i++) {
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

TEST(DiscreteGaussian, FLDiscreteGaussianDistributionEXP1_0_1_1_Simd_2_3_4_5_10_parties) {
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

      double sigma = 4;

      double min = 0;
      double max = 10;
      sigma = RandomRangeVector(min, max, 1)[0];
      if (sigma == 0) {
        sigma = 1;
      }

      double t = floor(sigma) + 1;
      std::size_t num_of_simd_dgau = 1;

      // std::cout << "sigma: " << sigma << std::endl;
      // std::cout << "t: " << t << std::endl;

      // the standard_fail_probability cause memory overflow
      long double fail_probability_requirement = std::exp2l(-10);

      std::vector<long double> optimize_discrete_gaussian_distribution_EXP_iteration_result_vector =
          optimize_discrete_gaussian_distribution_EXP_iteration<T, T_int>(
              sigma, fail_probability_requirement);

      std::size_t iteration_1 =
          optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[0];
      std::size_t iteration_2 =
          optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[1];
      std::size_t iteration_3 =
          optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[2];
      std::size_t iteration_4 =
          optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[3];
      std::size_t total_iteration =
          optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[4];
      long double total_fail_probability =
          optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[8];

      if (t == 1) {
        iteration_1 = 0;
      }

      // std::cout << "iteration_1: " << iteration_1 << std::endl;
      // std::cout << "iteration_2: " << iteration_2 << std::endl;
      // std::cout << "iteration_3: " << iteration_3 << std::endl;
      // std::cout << "iteration_4: " << iteration_4 << std::endl;
      // std::cout << "total_iteration: " << total_iteration << std::endl;
      // std::cout << "total_fail_probability: " << total_fail_probability << std::endl;

      std::size_t num_of_simd_geo = iteration_3;
      std::size_t num_of_simd_dlap = iteration_4;
      std::size_t num_of_simd_total = num_of_simd_dlap * num_of_simd_geo * num_of_simd_dgau;

      std::vector<double> constant_floating_point_sigma_vector(num_of_simd_dgau, sigma);

      std::vector<T> constant_unsigned_integer_t_vector =
          rand_range_integer_vector<T>(0, t, iteration_1 * num_of_simd_total);

      std::vector<double> random_floating_point_0_1_dlap_vector =
          rand_range_double_vector(0, 1, (iteration_1 + iteration_2) * num_of_simd_total);

      std::vector<T> random_unsigned_integer_dlap_vector =
          rand_range_integer_vector<T>(0, t, iteration_1 * num_of_simd_total);

      std::vector<bool> bernoulli_sample_dlap_vector = rand_bool_vector(num_of_simd_total);

      std::vector<double> random_floating_point_0_1_dgau_vector =
          rand_range_double_vector(0, 1, (iteration_4 * num_of_simd_dgau));

      std::vector<T> expect_result(num_of_simd_dlap);
      std::vector<bool> expect_result_success(num_of_simd_dlap);
      for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
        // std::cout << "SIMD: " << i << std::endl;

        std::vector<double> random_floating_point_0_1_dlap_subvector(
            random_floating_point_0_1_dlap_vector.begin() +
                i * iteration_1 * num_of_simd_geo * num_of_simd_dlap,
            random_floating_point_0_1_dlap_vector.begin() +
                (i + 1) * iteration_1 * num_of_simd_geo * num_of_simd_dlap);

        random_floating_point_0_1_dlap_subvector.insert(
            random_floating_point_0_1_dlap_subvector.end(),
            random_floating_point_0_1_dlap_vector.begin() +
                num_of_simd_dgau * iteration_1 * num_of_simd_geo * iteration_4 +
                i * iteration_2 * num_of_simd_geo * iteration_4,
            random_floating_point_0_1_dlap_vector.begin() +
                num_of_simd_dgau * iteration_1 * num_of_simd_geo * iteration_4 +
                (i + 1) * iteration_2 * num_of_simd_geo * iteration_4);

        std::vector<T> random_unsigned_integer_dlap_subvector(
            random_unsigned_integer_dlap_vector.begin() +
                i * iteration_1 * num_of_simd_geo * iteration_4,
            random_unsigned_integer_dlap_vector.begin() +
                (i + 1) * iteration_1 * num_of_simd_geo * iteration_4);

        std::vector<bool> bernoulli_sample_dlap_subvector(
            bernoulli_sample_dlap_vector.begin() + i * iteration_3 * iteration_4,
            bernoulli_sample_dlap_vector.begin() + (i + 1) * iteration_3 * iteration_4);

        std::vector<double> random_floating_point_0_1_dgau_subvector(
            random_floating_point_0_1_dgau_vector.begin() + i * iteration_4,
            random_floating_point_0_1_dgau_vector.begin() + (i + 1) * iteration_4);

        if (t != 1) {
          std::vector<T> result = discrete_gaussian_distribution_EXP<T, T_int, A>(
              constant_floating_point_sigma_vector[i], random_floating_point_0_1_dlap_subvector,
              random_unsigned_integer_dlap_subvector, bernoulli_sample_dlap_subvector,
              random_floating_point_0_1_dgau_subvector, iteration_1, iteration_2, iteration_3,
              iteration_4);
          expect_result[i] = result[0];
          expect_result_success[i] = result[1];

        } else {
          std::vector<T> result = discrete_gaussian_distribution_EXP<T, T_int, A>(
              constant_floating_point_sigma_vector[i], random_floating_point_0_1_dlap_subvector,
              bernoulli_sample_dlap_subvector, random_floating_point_0_1_dgau_subvector,
              iteration_2, iteration_3, iteration_4);
          expect_result[i] = result[0];
          expect_result_success[i] = result[1];
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
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point_0_1_dlap_vector(
              (iteration_1 + iteration_2) * num_of_simd_total);
          std::vector<encrypto::motion::ShareWrapper> share_random_unsigned_integer_dlap_vector(
              num_of_simd_total * iteration_1);
          std::vector<encrypto::motion::ShareWrapper> share_bernoulli_sample_dlap_vector(
              num_of_simd_total);
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point_0_1_dgau_vector(
              iteration_4 * num_of_simd_dgau);

          for (std::size_t i = 0; i < num_of_simd_total * (iteration_1 + iteration_2); i++) {
            share_random_floating_point_0_1_dlap_vector[i] =
                motion_parties.at(party_id)->In<kBooleanGmw>(
                    ToInput<FLType, std::true_type>(
                        FLType(random_floating_point_0_1_dlap_vector[i])),
                    0);
          }

          for (std::size_t i = 0; i < num_of_simd_total * iteration_1; i++) {
            share_random_unsigned_integer_dlap_vector[i] =
                motion_parties.at(party_id)->In<kBooleanGmw>(
                    ToInput<T>(random_unsigned_integer_dlap_vector[i]), 0);
          }

          for (std::size_t i = 0; i < num_of_simd_total; i++) {
            share_bernoulli_sample_dlap_vector[i] = motion_parties.at(party_id)->In<kBooleanGmw>(
                BitVector<>(1, bernoulli_sample_dlap_vector[i]), 0);
          }

          for (std::size_t i = 0; i < iteration_4 * num_of_simd_dgau; i++) {
            share_random_floating_point_0_1_dgau_vector[i] =
                motion_parties.at(party_id)->In<kBooleanGmw>(
                    ToInput<FLType, std::true_type>(
                        FLType(random_floating_point_0_1_dgau_vector[i])),
                    0);
          }

          std::vector<ShareWrapper> share_result;
          if (t != 1) {
            share_result =
                SecureDPMechanismHelper(share_random_floating_point_0_1_dlap_vector[0])
                    .FLDiscreteGaussianDistribution<FLType, T, T_int>(
                        constant_floating_point_sigma_vector,
                        encrypto::motion::ShareWrapper::Simdify(
                            share_random_floating_point_0_1_dlap_vector),
                        encrypto::motion::ShareWrapper::Simdify(
                            share_random_unsigned_integer_dlap_vector),
                        encrypto::motion::ShareWrapper::Simdify(share_bernoulli_sample_dlap_vector),
                        encrypto::motion::ShareWrapper::Simdify(
                            share_random_floating_point_0_1_dgau_vector),
                        iteration_1, iteration_2, iteration_3, iteration_4, 1);
          } else {
            share_result =
                SecureDPMechanismHelper(share_random_floating_point_0_1_dlap_vector[0])
                    .FLDiscreteGaussianDistribution<FLType, T, T_int>(
                        constant_floating_point_sigma_vector,
                        encrypto::motion::ShareWrapper::Simdify(
                            share_random_floating_point_0_1_dlap_vector),
                        encrypto::motion::ShareWrapper::Simdify(share_bernoulli_sample_dlap_vector),
                        encrypto::motion::ShareWrapper::Simdify(
                            share_random_floating_point_0_1_dgau_vector),
                        iteration_2, iteration_3, iteration_4);
          }

          encrypto::motion::SecureSignedInteger share_result_0_out = share_result[0].Out();
          encrypto::motion::ShareWrapper share_result_1_out = share_result[1].Out();

          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            std::vector<T> share_result_0_out_as = share_result_0_out.AsVector<T>();
            BitVector<> share_result_1_out_as = share_result_1_out.As<BitVector<>>();

            // std::cout << std::endl;

            for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
              EXPECT_EQ(expect_result[i], share_result_0_out_as[i]);
              EXPECT_EQ(expect_result_success[i], share_result_1_out_as.Get(i));
            }

            // std::cout << std::endl;
            // std::cout << std::endl;
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

// =================================================================

TEST(DiscreteLaplace, FxDiscreteLaplaceDistributionEXP1_0_1_1_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  // std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1) {
    using T = decltype(template_variable_1);
    using T_int = get_int_type_t<T>;
    using A = std::allocator<T>;
    std::size_t fixed_point_fraction_bit_size = 16;
    std::size_t fixed_point_bit_size = 64;
    std::srand(std::time(nullptr));

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      double scale = 2;
      std::uint64_t numerator = decimalToFraction(1 / scale)[0];
      std::uint64_t denominator = decimalToFraction(1 / scale)[1];

      numerator = std::rand() % 10 + 1;
      denominator = std::rand() % 300 + 1;

      std::size_t num_of_simd_dlap = 1;

      // std::cout << "numerator: " << numerator << std::endl;
      // std::cout << "denominator: " << denominator << std::endl;

      long double fail_probability_requirement = std::exp2l(-10);

      std::vector<long double> optimize_discrete_laplace_distribution_EXP_iteration_result_vector =
          optimize_discrete_laplace_distribution_EXP_iteration<T>(numerator, denominator,
                                                                  fail_probability_requirement);

      std::size_t iteration_1 =
          optimize_discrete_laplace_distribution_EXP_iteration_result_vector[0];
      std::size_t iteration_2 =
          optimize_discrete_laplace_distribution_EXP_iteration_result_vector[1];
      std::size_t iteration_3 =
          optimize_discrete_laplace_distribution_EXP_iteration_result_vector[2];
      std::size_t total_iteration =
          optimize_discrete_laplace_distribution_EXP_iteration_result_vector[3];
      long double total_fail_probability =
          optimize_discrete_laplace_distribution_EXP_iteration_result_vector[4];

      if (denominator == 1) {
        iteration_1 = 0;
      }

      // std::cout << "iteration_1: " << iteration_1 << std::endl;
      // std::cout << "iteration_2: " << iteration_2 << std::endl;
      // std::cout << "iteration_3: " << iteration_3 << std::endl;
      // std::cout << "total_iteration: " << total_iteration << std::endl;
      // std::cout << "total_fail_probability: " << total_fail_probability << std::endl;

      std::size_t num_of_simd_geo = iteration_3;
      std::size_t num_of_simd_total = num_of_simd_dlap * num_of_simd_geo;

      std::vector<double> random_floating_point_0_1_vector =
          rand_range_double_vector(0, 1, (iteration_1 + iteration_2) * num_of_simd_total);

      std::vector<T> random_unsigned_integer_vector =
          rand_range_integer_vector<T>(0, denominator, iteration_1 * num_of_simd_total);

      std::vector<bool> bernoulli_sample_vector = rand_bool_vector(num_of_simd_total);

      std::vector<T> expect_result(num_of_simd_dlap);
      std::vector<bool> expect_result_success(num_of_simd_dlap);

      for (std::size_t i = 0; i < num_of_simd_dlap; i++) {
        std::vector<double> random_floating_point_0_1_subvector(
            random_floating_point_0_1_vector.begin() + i * iteration_1 * num_of_simd_geo,
            random_floating_point_0_1_vector.begin() + (i + 1) * iteration_1 * num_of_simd_geo);

        random_floating_point_0_1_subvector.insert(
            random_floating_point_0_1_subvector.end(),
            random_floating_point_0_1_vector.begin() +
                num_of_simd_dlap * iteration_1 * num_of_simd_geo +
                i * iteration_2 * num_of_simd_geo,
            random_floating_point_0_1_vector.begin() +
                num_of_simd_dlap * iteration_1 * num_of_simd_geo +
                (i + 1) * iteration_2 * num_of_simd_geo);

        std::vector<T> random_unsigned_integer_subvector(
            random_unsigned_integer_vector.begin() + i * iteration_1 * num_of_simd_geo,
            random_unsigned_integer_vector.begin() + (i + 1) * iteration_1 * num_of_simd_geo);

        std::vector<bool> bernoulli_sample_subvector(
            bernoulli_sample_vector.begin() + i * iteration_3,
            bernoulli_sample_vector.begin() + (i + 1) * iteration_3);

        if (denominator != 1) {
          std::vector<T> result = discrete_laplace_distribution_EXP<T, A>(
              numerator, denominator, random_floating_point_0_1_subvector,
              random_unsigned_integer_subvector, bernoulli_sample_subvector, iteration_1,
              iteration_2, iteration_3);
          expect_result[i] = result[0];
          expect_result_success[i] = result[1];
        } else {
          std::vector<T> result = discrete_laplace_distribution_EXP<T, A>(
              numerator, random_floating_point_0_1_subvector, bernoulli_sample_subvector,
              iteration_2, iteration_3);
          expect_result[i] = result[0];
          expect_result_success[i] = result[1];
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
              (iteration_1 + iteration_2) * num_of_simd_total);
          std::vector<encrypto::motion::ShareWrapper> share_random_unsigned_integer_vector(
              num_of_simd_total * iteration_1);
          std::vector<encrypto::motion::ShareWrapper> share_bernoulli_sample_vector(
              num_of_simd_total);

          for (std::size_t i = 0; i < num_of_simd_total * (iteration_1 + iteration_2); i++) {
            share_random_floating_point_0_1_vector[i] =
                motion_parties.at(party_id)->In<kBooleanGmw>(
                    FixedPointToInput<T, T_int>(random_floating_point_0_1_vector[i],
                                                fixed_point_fraction_bit_size),
                    0);
          }

          for (std::size_t i = 0; i < num_of_simd_total * iteration_1; i++) {
            share_random_unsigned_integer_vector[i] = motion_parties.at(party_id)->In<kBooleanGmw>(
                ToInput<T>(random_unsigned_integer_vector[i]), 0);
          }

          for (std::size_t i = 0; i < num_of_simd_total; i++) {
            share_bernoulli_sample_vector[i] = motion_parties.at(party_id)->In<kBooleanGmw>(
                BitVector<>(1, bernoulli_sample_vector[i]), 0);
          }

          std::vector<T> unsigned_integer_numerator_vector(num_of_simd_dlap, numerator);
          std::vector<T> unsigned_integer_denominator_vector(num_of_simd_dlap, denominator);

          std::vector<ShareWrapper> share_result;

          if (denominator != 1) {
            share_result =
                SecureDPMechanismHelper(share_random_floating_point_0_1_vector[0])
                    .FxDiscreteLaplaceDistribution(
                        unsigned_integer_numerator_vector, unsigned_integer_denominator_vector,
                        encrypto::motion::ShareWrapper::Simdify(
                            share_random_floating_point_0_1_vector),
                        encrypto::motion::ShareWrapper::Simdify(
                            share_random_unsigned_integer_vector),
                        encrypto::motion::ShareWrapper::Simdify(share_bernoulli_sample_vector),
                        iteration_1, iteration_2, iteration_3, fixed_point_fraction_bit_size);
          } else {
            share_result =
                SecureDPMechanismHelper(share_random_floating_point_0_1_vector[0])
                    .FxDiscreteLaplaceDistribution(
                        unsigned_integer_numerator_vector,
                        encrypto::motion::ShareWrapper::Simdify(
                            share_random_floating_point_0_1_vector),
                        encrypto::motion::ShareWrapper::Simdify(share_bernoulli_sample_vector),
                        iteration_2, iteration_3, fixed_point_fraction_bit_size);
          }

          encrypto::motion::SecureSignedInteger share_result_0_out = share_result[0].Out();
          encrypto::motion::ShareWrapper share_result_1_out = share_result[1].Out();

          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            std::vector<T> share_result_0_out_as = share_result_0_out.AsVector<T>();
            BitVector<> share_result_1_out_as = share_result_1_out.As<BitVector<>>();

            for (std::size_t i = 0; i < num_of_simd_dlap; i++) {
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
    template_test(static_cast<std::uint64_t>(0));
  }
}

TEST(GeometricExp, FxGeometricDistributionEXP1_0_1_1_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1, auto template_variable_2,
                          auto template_variable_3) {
    using T = decltype(template_variable_1);
    using T_int = decltype(template_variable_2);
    using FxType = decltype(template_variable_3);
    using A = std::allocator<T>;
    std::size_t fixed_point_fraction_bit_size = 16;
    std::size_t fixed_point_bit_size = 64;
    std::srand(std::time(nullptr));

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      double scale = 1;
      std::uint64_t numerator = decimalToFraction(1 / scale)[0];
      std::uint64_t denominator = decimalToFraction(1 / scale)[1];

      numerator = std::rand() % 10 + 1;
      denominator = std::rand() % 300 + 1;

      std::size_t num_of_simd = 10;

      // std::cout << "numerator: " << numerator << std::endl;
      // std::cout << "denominator: " << denominator << std::endl;

      long double fail_probability_requirement = std::exp2l(-10);

      std::vector<long double> optimize_geometric_distribution_EXP_iteration_result_vector =
          optimize_geometric_distribution_EXP_iteration<T>(numerator, denominator,
                                                           fail_probability_requirement);

      std::size_t iteration_1 = optimize_geometric_distribution_EXP_iteration_result_vector[0];
      std::size_t iteration_2 = optimize_geometric_distribution_EXP_iteration_result_vector[1];
      std::size_t total_iteration = optimize_geometric_distribution_EXP_iteration_result_vector[2];
      long double total_fail_probability =
          optimize_geometric_distribution_EXP_iteration_result_vector[3];

      if (denominator == 1) {
        iteration_1 = 0;
      }

      // std::cout << "iteration_1: " << iteration_1 << std::endl;
      // std::cout << "iteration_2: " << iteration_2 << std::endl;
      // std::cout << "total_iteration: " << total_iteration << std::endl;
      // std::cout << "total_fail_probability: " << total_fail_probability << std::endl;

      std::vector<double> random_floating_point_0_1_vector =
          rand_range_double_vector(0, 1, (iteration_1 + iteration_2) * num_of_simd);

      std::vector<T> random_unsigned_integer_vector =
          rand_range_integer_vector<T>(0, denominator, num_of_simd * iteration_1);

      std::vector<T> expect_result(num_of_simd);
      std::vector<bool> expect_result_success(num_of_simd);

      for (std::size_t i = 0; i < num_of_simd; i++) {
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
        } else {
          std::vector<T> result = geometric_distribution_EXP<T, A>(
              numerator, random_floating_point_0_1_subvector, iteration_2);
          expect_result[i] = result[0];
          expect_result_success[i] = result[1];
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
                    FixedPointToInput<T, T_int>(random_floating_point_0_1_vector[i],
                                                fixed_point_fraction_bit_size),
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
                SecureDPMechanismHelper(share_random_floating_point_0_1_vector[0])
                    .FxGeometricDistributionEXP<FxType, T, T_int>(
                        unsigned_integer_numerator_vector, unsigned_integer_denominator_vector,
                        encrypto::motion::ShareWrapper::Simdify(
                            share_random_floating_point_0_1_vector),
                        encrypto::motion::ShareWrapper::Simdify(share_random_unsigned_integer),
                        iteration_1, iteration_2, fixed_point_fraction_bit_size);
          } else {
            share_result = SecureDPMechanismHelper(share_random_floating_point_0_1_vector[0])
                               .FxGeometricDistributionEXP<FxType, T, T_int>(
                                   unsigned_integer_numerator_vector,
                                   encrypto::motion::ShareWrapper::Simdify(
                                       share_random_floating_point_0_1_vector),
                                   iteration_2, fixed_point_fraction_bit_size);
          }

          encrypto::motion::SecureUnsignedInteger share_result_0_out = share_result[0].Out();
          encrypto::motion::ShareWrapper share_result_1_out = share_result[1].Out();

          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            std::vector<T> share_result_0_out_as = share_result_0_out.AsVector<T>();
            BitVector<> share_result_1_out_as = share_result_1_out.As<BitVector<>>();

            // std::cout << std::endl;
            // std::cout << std::endl;
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
                  static_cast<double>(0));
  }
}

TEST(DiscreteLaplace, FxDiscreteGaussianDistributionEXP1_0_1_1_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  // std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1) {
    using T = decltype(template_variable_1);
    using T_int = get_int_type_t<T>;
    using A = std::allocator<T>;
    std::size_t fixed_point_fraction_bit_size = 16;
    std::size_t fixed_point_bit_size = 64;
    std::srand(std::time(nullptr));

    // only for debug
    long double fail_probability_requirement = std::exp2l(-10);

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      double sigma = 4.5;

      double min = 0;
      double max = 10;
      sigma = RandomRangeVector(min, max, 1)[0];
      if (sigma == 0) {
        sigma = 1;
      }

      double t = floor(sigma) + 1;

      std::size_t num_of_simd_dgau = 1;

      std::vector<long double> optimize_discrete_gaussian_distribution_EXP_iteration_result_vector =
          optimize_discrete_gaussian_distribution_EXP_iteration<T, T_int>(
              sigma, fail_probability_requirement);

      std::size_t iteration_1 =
          optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[0];
      std::size_t iteration_2 =
          optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[1];
      std::size_t iteration_3 =
          optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[2];
      std::size_t iteration_4 =
          optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[3];
      std::size_t total_iteration =
          optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[4];
      long double total_fail_probability =
          optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[5];

      if (t == 1) {
        iteration_1 = 0;
      }

      // std::cout << "iteration_1: " << iteration_1 << std::endl;
      // std::cout << "iteration_2: " << iteration_2 << std::endl;
      // std::cout << "iteration_3: " << iteration_3 << std::endl;
      // std::cout << "iteration_4: " << iteration_4 << std::endl;
      // std::cout << "total_iteration: " << total_iteration << std::endl;
      // std::cout << "total_fail_probability: " << total_fail_probability << std::endl;

      std::size_t num_of_simd_geo = iteration_3;
      std::size_t num_of_simd_dlap = iteration_4;
      std::size_t num_of_simd_total = num_of_simd_dlap * num_of_simd_geo * num_of_simd_dgau;

      std::vector<double> constant_floating_point_sigma_vector(num_of_simd_dgau, sigma);

      std::vector<T> constant_unsigned_integer_t_vector =
          rand_range_integer_vector<T>(0, t, iteration_1 * num_of_simd_total);

      std::vector<double> random_floating_point_0_1_dlap_vector =
          rand_range_double_vector(0, 1, (iteration_1 + iteration_2) * num_of_simd_total);

      std::vector<T> random_unsigned_integer_dlap_vector =
          rand_range_integer_vector<T>(0, t, iteration_1 * num_of_simd_total);

      std::vector<bool> bernoulli_sample_dlap_vector = rand_bool_vector(num_of_simd_total);

      std::vector<double> random_floating_point_0_1_dgau_vector =
          rand_range_double_vector(0, 1, (iteration_4 * num_of_simd_dgau));

      std::vector<T> expect_result(num_of_simd_dgau);
      std::vector<bool> expect_result_success(num_of_simd_dgau);
      for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
        std::vector<double> random_floating_point_0_1_dlap_subvector(
            random_floating_point_0_1_dlap_vector.begin() +
                i * iteration_1 * num_of_simd_geo * num_of_simd_dlap,
            random_floating_point_0_1_dlap_vector.begin() +
                (i + 1) * iteration_1 * num_of_simd_geo * num_of_simd_dlap);

        random_floating_point_0_1_dlap_subvector.insert(
            random_floating_point_0_1_dlap_subvector.end(),
            random_floating_point_0_1_dlap_vector.begin() +
                num_of_simd_dgau * iteration_1 * num_of_simd_geo * iteration_4 +
                i * iteration_2 * num_of_simd_geo * iteration_4,
            random_floating_point_0_1_dlap_vector.begin() +
                num_of_simd_dgau * iteration_1 * num_of_simd_geo * iteration_4 +
                (i + 1) * iteration_2 * num_of_simd_geo * iteration_4);

        std::vector<T> random_unsigned_integer_dlap_subvector(
            random_unsigned_integer_dlap_vector.begin() +
                i * iteration_1 * num_of_simd_geo * iteration_4,
            random_unsigned_integer_dlap_vector.begin() +
                (i + 1) * iteration_1 * num_of_simd_geo * iteration_4);

        std::vector<bool> bernoulli_sample_dlap_subvector(
            bernoulli_sample_dlap_vector.begin() + i * iteration_3 * iteration_4,
            bernoulli_sample_dlap_vector.begin() + (i + 1) * iteration_3 * iteration_4);

        std::vector<double> random_floating_point_0_1_dgau_subvector(
            random_floating_point_0_1_dgau_vector.begin() + i * iteration_4,
            random_floating_point_0_1_dgau_vector.begin() + (i + 1) * iteration_4);

        if (t != 1) {
          std::vector<T> result = discrete_gaussian_distribution_EXP<T, T_int, A>(
              constant_floating_point_sigma_vector[i], random_floating_point_0_1_dlap_subvector,
              random_unsigned_integer_dlap_subvector, bernoulli_sample_dlap_subvector,
              random_floating_point_0_1_dgau_subvector, iteration_1, iteration_2, iteration_3,
              iteration_4);
          expect_result[i] = result[0];
          expect_result_success[i] = result[1];

        } else {
          std::vector<T> result = discrete_gaussian_distribution_EXP<T, T_int, A>(
              constant_floating_point_sigma_vector[i], random_floating_point_0_1_dlap_subvector,
              bernoulli_sample_dlap_subvector, random_floating_point_0_1_dgau_subvector,
              iteration_2, iteration_3, iteration_4);
          expect_result[i] = result[0];
          expect_result_success[i] = result[1];
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
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point_0_1_dlap_vector(
              (iteration_1 + iteration_2) * num_of_simd_total);
          std::vector<encrypto::motion::ShareWrapper> share_random_unsigned_integer_dlap_vector(
              num_of_simd_total * iteration_1);
          std::vector<encrypto::motion::ShareWrapper> share_bernoulli_sample_dlap_vector(
              num_of_simd_total);
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point_0_1_dgau_vector(
              iteration_4 * num_of_simd_dgau);

          for (std::size_t i = 0; i < num_of_simd_total * (iteration_1 + iteration_2); i++) {
            share_random_floating_point_0_1_dlap_vector[i] =
                motion_parties.at(party_id)->In<kBooleanGmw>(
                    FixedPointToInput<T, T_int>(random_floating_point_0_1_dlap_vector[i],
                                                fixed_point_fraction_bit_size),
                    0);
          }

          for (std::size_t i = 0; i < num_of_simd_total * iteration_1; i++) {
            share_random_unsigned_integer_dlap_vector[i] =
                motion_parties.at(party_id)->In<kBooleanGmw>(
                    ToInput<T>(random_unsigned_integer_dlap_vector[i]), 0);
          }

          for (std::size_t i = 0; i < num_of_simd_total; i++) {
            share_bernoulli_sample_dlap_vector[i] = motion_parties.at(party_id)->In<kBooleanGmw>(
                BitVector<>(1, bernoulli_sample_dlap_vector[i]), 0);
          }

          for (std::size_t i = 0; i < iteration_4 * num_of_simd_dgau; i++) {
            share_random_floating_point_0_1_dgau_vector[i] =
                motion_parties.at(party_id)->In<kBooleanGmw>(
                    FixedPointToInput<T, T_int>(random_floating_point_0_1_dgau_vector[i],
                                                fixed_point_fraction_bit_size),
                    0);
          }

          std::vector<ShareWrapper> share_result;
          if (t != 1) {
            share_result =
                SecureDPMechanismHelper(share_random_floating_point_0_1_dlap_vector[0])
                    .FxDiscreteGaussianDistribution(
                        constant_floating_point_sigma_vector,
                        encrypto::motion::ShareWrapper::Simdify(
                            share_random_floating_point_0_1_dlap_vector),
                        encrypto::motion::ShareWrapper::Simdify(
                            share_random_unsigned_integer_dlap_vector),
                        encrypto::motion::ShareWrapper::Simdify(share_bernoulli_sample_dlap_vector),
                        encrypto::motion::ShareWrapper::Simdify(
                            share_random_floating_point_0_1_dgau_vector),
                        iteration_1, iteration_2, iteration_3, iteration_4, 1,
                        fixed_point_fraction_bit_size);
          } else {
            share_result =
                SecureDPMechanismHelper(share_random_floating_point_0_1_dlap_vector[0])
                    .FxDiscreteGaussianDistribution(
                        constant_floating_point_sigma_vector,
                        encrypto::motion::ShareWrapper::Simdify(
                            share_random_floating_point_0_1_dlap_vector),
                        encrypto::motion::ShareWrapper::Simdify(share_bernoulli_sample_dlap_vector),
                        encrypto::motion::ShareWrapper::Simdify(
                            share_random_floating_point_0_1_dgau_vector),
                        iteration_2, iteration_3, iteration_4, fixed_point_fraction_bit_size);
          }

          encrypto::motion::SecureSignedInteger share_result_0_out = share_result[0].Out();
          encrypto::motion::ShareWrapper share_result_1_out = share_result[1].Out();

          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            std::vector<T> share_result_0_out_as = share_result_0_out.AsVector<T>();
            BitVector<> share_result_1_out_as = share_result_1_out.As<BitVector<>>();

            for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
              EXPECT_EQ(expect_result[i], share_result_0_out_as[i]);
              EXPECT_EQ(expect_result_success[i], share_result_1_out_as.Get(i));
            }

            // std::cout << std::endl;
            // std::cout << std::endl;
          }
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    template_test(static_cast<std::uint64_t>(0));
  }
}

TEST(IntegerScalingMechanism,
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

      // std::cout << "sqrt_n: " << sqrt_n << std::endl;
      double m = floor(M_SQRT2 * sqrt_n + 1);
      // std::cout << "m: " << m << std::endl;
      std::vector<double> sqrt_n_vector(num_of_simd, sqrt_n);
      std::vector<double> m_vector(num_of_simd, m);
      long double fail_probability_requirement = std::exp2(-10);

      std::vector<long double> optimize_symmetrical_binomial_distribution_iteration_result =
          optimize_symmetrical_binomial_distribution_iteration(sqrt_n,
                                                               fail_probability_requirement);

      std::size_t iterations = optimize_symmetrical_binomial_distribution_iteration_result[0];
      long double fail_probability = optimize_symmetrical_binomial_distribution_iteration_result[1];

      // std::cout << "iterations: " << iterations << std::endl;
      // std::cout << "fail_probability: " << fail_probability << std::endl;

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

        std::vector<IntType> result = symmetrical_binomial_distribution<IntType, IntType_int, A>(
            sqrt_n_vector[i], signed_integer_geometric_sample_subvector, random_bits_subvector,
            random_unsigned_integer_subvector, random_floating_point_0_1_subvector, iterations);
        expect_result[i] = result[0];
        expect_result_success[i] = result[1];
        // std::cout << std::endl;
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
              SecureDPMechanismHelper(share_random_floating_point_0_1_vector[0])
                  .FLSymmetricBinomialDistribution<double, IntType, IntType_int>(
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

          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            std::vector<IntType> share_result_0_out_as = share_result_0_out.AsVector<IntType>();
            BitVector<> share_result_1_out_as = share_result_1_out.As<BitVector<>>();

            for (std::size_t i = 0; i < num_of_simd; i++) {
              EXPECT_EQ(expect_result[i], share_result_0_out_as[i]);
              EXPECT_EQ(expect_result_success[i], share_result_1_out_as.Get(i));
            }
            // std::cout << std::endl;
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
    template_test(static_cast<__uint128_t>(0), static_cast<__int128_t>(0), static_cast<double>(0));
  }
}

}  // namespace
