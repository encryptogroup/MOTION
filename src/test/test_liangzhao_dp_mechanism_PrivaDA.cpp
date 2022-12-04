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
#include "secure_dp_mechanism/secure_discrete_gaussian_mechanism_CKS.h"
#include "secure_dp_mechanism/secure_dp_mechanism_PrivaDA.h"
// #include "secure_dp_mechanism/secure_gaussian_mechanism.h"
#include "secure_dp_mechanism/secure_dp_mechanism_PrivaDA.h"
#include "secure_dp_mechanism/secure_integer_scaling_gaussian_mechanism.h"
#include "secure_dp_mechanism/secure_integer_scaling_laplace_mechanism.h"
#include "secure_dp_mechanism/secure_sampling_algorithm_optimized.h"
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
// TODO: need intensive re-test, seems to fail once
TEST(SecureDPMechanismEKMPP, Laplace_DiscreteLaplace_Mechanism_GC_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  // std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1) {
    using T = decltype(template_variable_1);
    // using T_int = get_int_type_t<T>;
    using T_int = std::int64_t;
    using A = std::allocator<T>;
    std::srand(std::time(nullptr));

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      std::size_t num_of_simd_lap_dlap = 10;
      std::vector<T> fD_vector = rand_range_integer_vector<T>(0, 5, num_of_simd_lap_dlap);
      std::size_t fixed_point_fraction_bit_size = 16;

      // only for debugging
      // std::cout << "fD_vector: " << std::endl;
      // for (std::size_t i = 0; i < fD_vector.size(); ++i) {
      //   std::cout << fD_vector[i] << std::endl;
      // }

      std::vector<double> random_floating_point_0_1_rx_vector =
          rand_range_double_vector(0, 1, num_of_simd_lap_dlap);

      std::vector<double> random_floating_point_0_1_ry_vector =
          rand_range_double_vector(0, 1, num_of_simd_lap_dlap);

      // only for debugging
      // std::cout << "random_floating_point_0_1_rx_vector" << std::endl;
      // for (std::size_t i = 0; i < num_of_simd_lap_dlap; i++) {
      //   std::cout << random_floating_point_0_1_rx_vector[i] << std::endl;
      // }
      // std::cout << "random_floating_point_0_1_ry_vector" << std::endl;
      // for (std::size_t i = 0; i < num_of_simd_lap_dlap; i++) {
      //   std::cout << random_floating_point_0_1_ry_vector[i] << std::endl;
      // }

      double sensitivity = 1;
      double epsilon = 1.5;
      double lambda_lap = sensitivity / epsilon;
      double lambda_dlap = std::exp(-epsilon / sensitivity);

      std::vector<double> expect_lap_result(num_of_simd_lap_dlap);
      std::vector<double> expect_dlap_result(num_of_simd_lap_dlap);
      for (std::size_t i = 0; i < num_of_simd_lap_dlap; i++) {
        expect_lap_result[i] =
            laplace_distribution(lambda_lap, random_floating_point_0_1_rx_vector[i],
                                 random_floating_point_0_1_ry_vector[i]);
        expect_dlap_result[i] =
            discrete_laplace_distribution(lambda_dlap, random_floating_point_0_1_rx_vector[i],
                                          random_floating_point_0_1_ry_vector[i]);
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
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point32_0_1_rx_vector(
              num_of_simd_lap_dlap);
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point32_0_1_ry_vector(
              num_of_simd_lap_dlap);
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point64_0_1_rx_vector(
              num_of_simd_lap_dlap);
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point64_0_1_ry_vector(
              num_of_simd_lap_dlap);

          for (std::size_t i = 0; i < num_of_simd_lap_dlap; i++) {
            share_random_floating_point32_0_1_rx_vector[i] =
                motion_parties.at(party_id)->In<kGarbledCircuit>(
                    ToInput<float, std::true_type>(float(random_floating_point_0_1_rx_vector[i])),
                    0);
            share_random_floating_point32_0_1_ry_vector[i] =
                motion_parties.at(party_id)->In<kGarbledCircuit>(
                    ToInput<float, std::true_type>(float(random_floating_point_0_1_ry_vector[i])),
                    0);
            share_random_floating_point64_0_1_rx_vector[i] =
                motion_parties.at(party_id)->In<kGarbledCircuit>(
                    ToInput<double, std::true_type>(random_floating_point_0_1_rx_vector[i]), 0);
            share_random_floating_point64_0_1_ry_vector[i] =
                motion_parties.at(party_id)->In<kGarbledCircuit>(
                    ToInput<double, std::true_type>(random_floating_point_0_1_ry_vector[i]), 0);
          }

          encrypto::motion::ShareWrapper share_fD =
              motion_parties.at(party_id)->In<kGarbledCircuit>(ToInput<T>(fD_vector), 0);

          SecureDPMechanism_PrivaDA secure_laplace_discrete_laplace_mechanism =
              SecureDPMechanism_PrivaDA(share_fD);
          secure_laplace_discrete_laplace_mechanism.ParameterSetup(sensitivity, epsilon,
                                                                   num_of_simd_lap_dlap);

          SecureFloatingPointCircuitABY floating_point32_laplace_noise =
              secure_laplace_discrete_laplace_mechanism.FL32LaplaceNoiseGeneration(
                  ShareWrapper::Simdify(share_random_floating_point32_0_1_rx_vector),
                  ShareWrapper::Simdify(share_random_floating_point32_0_1_ry_vector));
          SecureFloatingPointCircuitABY floating_point64_laplace_noise =
              secure_laplace_discrete_laplace_mechanism.FL64LaplaceNoiseGeneration(
                  ShareWrapper::Simdify(share_random_floating_point64_0_1_rx_vector),
                  ShareWrapper::Simdify(share_random_floating_point64_0_1_ry_vector));

          SecureFloatingPointCircuitABY floating_point32_laplace_noise_out =
              floating_point32_laplace_noise.Out();
          SecureFloatingPointCircuitABY floating_point64_laplace_noise_out =
              floating_point64_laplace_noise.Out();

          SecureSignedInteger signed_integer_discrete_laplace_noise_fl32 =
              secure_laplace_discrete_laplace_mechanism.FL32DiscreteLaplaceNoiseGeneration(
                  ShareWrapper::Simdify(share_random_floating_point32_0_1_rx_vector),
                  ShareWrapper::Simdify(share_random_floating_point32_0_1_ry_vector));
          SecureSignedInteger signed_integer_discrete_laplace_noise_fl64 =
              secure_laplace_discrete_laplace_mechanism.FL64DiscreteLaplaceNoiseGeneration(
                  ShareWrapper::Simdify(share_random_floating_point64_0_1_rx_vector),
                  ShareWrapper::Simdify(share_random_floating_point64_0_1_ry_vector));

          SecureSignedInteger signed_integer_discrete_laplace_noise_fl32_out =
              signed_integer_discrete_laplace_noise_fl32.Out();
          SecureSignedInteger signed_integer_discrete_laplace_noise_fl64_out =
              signed_integer_discrete_laplace_noise_fl64.Out();

          std::cout << "party run" << std::endl;
          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();
          std::cout << "party finish" << std::endl;

          if (party_id == 0) {
            std::cout << "party_id: " << party_id << std::endl;
            std::vector<float> floating_point32_laplace_noise_out_as =
                floating_point32_laplace_noise_out.AsFloatingPointVector<float>();
            std::vector<double> floating_point64_laplace_noise_out_as =
                floating_point64_laplace_noise_out.AsFloatingPointVector<double>();

            std::vector<T> signed_integer_discrete_laplace_noise_fl32_out_as =
                signed_integer_discrete_laplace_noise_fl32_out.AsVector<T>();
            std::vector<T> signed_integer_discrete_laplace_noise_fl64_out_as =
                signed_integer_discrete_laplace_noise_fl64_out.AsVector<T>();

            for (std::size_t i = 0; i < num_of_simd_lap_dlap; ++i) {
              std::cout << "expect_lap_result[i]: " << expect_lap_result[i] << std::endl;
              std::cout << "floating_point32_laplace_noise_out_as[i]: "
                        << floating_point32_laplace_noise_out_as[i] << std::endl;
              std::cout << "floating_point64_laplace_noise_out_as[i]: "
                        << floating_point64_laplace_noise_out_as[i] << std::endl;

              double abs_error = 0.01;
              EXPECT_NEAR(expect_lap_result[i], floating_point32_laplace_noise_out_as[i],
                          abs_error);
              EXPECT_NEAR(expect_lap_result[i], floating_point64_laplace_noise_out_as[i],
                          abs_error);

              std::cout << "expect_dlap_result[i]: " << expect_dlap_result[i] << std::endl;
              std::cout << "signed_integer_discrete_laplace_noise_fl32_out_as[i]: "
                        << T_int(signed_integer_discrete_laplace_noise_fl32_out_as[i]) << std::endl;
              std::cout << "signed_integer_discrete_laplace_noise_fl64_out_as[i]: "
                        << T_int(signed_integer_discrete_laplace_noise_fl64_out_as[i]) << std::endl;
              EXPECT_EQ(expect_dlap_result[i],
                        T_int(signed_integer_discrete_laplace_noise_fl32_out_as[i]));
              EXPECT_EQ(expect_dlap_result[i],
                        T_int(signed_integer_discrete_laplace_noise_fl64_out_as[i]));
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

TEST(SecureDPMechanismEKMPP, Laplace_DiscreteLaplace_Mechanism_BGMW_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  // std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1) {
    using T = decltype(template_variable_1);
    // using T_int = get_int_type_t<T>;
    using T_int = std::int64_t;
    using A = std::allocator<T>;
    std::srand(std::time(nullptr));

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      std::size_t num_of_simd_lap_dlap = 10;
      std::vector<T> fD_vector = rand_range_integer_vector<T>(0, 5, num_of_simd_lap_dlap);
      std::size_t fixed_point_fraction_bit_size = 16;

      // only for debugging
      // std::cout << "fD_vector: " << std::endl;
      // for (std::size_t i = 0; i < fD_vector.size(); ++i) {
      //   std::cout << fD_vector[i] << std::endl;
      // }

      std::vector<double> random_floating_point_0_1_rx_vector =
          rand_range_double_vector(0, 1, num_of_simd_lap_dlap);

      std::vector<double> random_floating_point_0_1_ry_vector =
          rand_range_double_vector(0, 1, num_of_simd_lap_dlap);

      // only for debugging
      // std::cout << "random_floating_point_0_1_rx_vector" << std::endl;
      // for (std::size_t i = 0; i < num_of_simd_lap_dlap; i++) {
      //   std::cout << random_floating_point_0_1_rx_vector[i] << std::endl;
      // }
      // std::cout << "random_floating_point_0_1_ry_vector" << std::endl;
      // for (std::size_t i = 0; i < num_of_simd_lap_dlap; i++) {
      //   std::cout << random_floating_point_0_1_ry_vector[i] << std::endl;
      // }

      double sensitivity = 1;
      double epsilon = 1.5;
      double lambda_lap = sensitivity / epsilon;
      double lambda_dlap = std::exp(-epsilon / sensitivity);

      std::vector<double> expect_lap_result(num_of_simd_lap_dlap);
      std::vector<double> expect_dlap_result(num_of_simd_lap_dlap);
      for (std::size_t i = 0; i < num_of_simd_lap_dlap; i++) {
        expect_lap_result[i] =
            laplace_distribution(lambda_lap, random_floating_point_0_1_rx_vector[i],
                                 random_floating_point_0_1_ry_vector[i]);
        expect_dlap_result[i] =
            discrete_laplace_distribution(lambda_dlap, random_floating_point_0_1_rx_vector[i],
                                          random_floating_point_0_1_ry_vector[i]);
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
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point32_0_1_rx_vector(
              num_of_simd_lap_dlap);
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point32_0_1_ry_vector(
              num_of_simd_lap_dlap);
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point64_0_1_rx_vector(
              num_of_simd_lap_dlap);
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point64_0_1_ry_vector(
              num_of_simd_lap_dlap);

          for (std::size_t i = 0; i < num_of_simd_lap_dlap; i++) {
            share_random_floating_point32_0_1_rx_vector[i] =
                motion_parties.at(party_id)->In<kBooleanGmw>(
                    ToInput<float, std::true_type>(float(random_floating_point_0_1_rx_vector[i])),
                    0);
            share_random_floating_point32_0_1_ry_vector[i] =
                motion_parties.at(party_id)->In<kBooleanGmw>(
                    ToInput<float, std::true_type>(float(random_floating_point_0_1_ry_vector[i])),
                    0);
            share_random_floating_point64_0_1_rx_vector[i] =
                motion_parties.at(party_id)->In<kBooleanGmw>(
                    ToInput<double, std::true_type>(random_floating_point_0_1_rx_vector[i]), 0);
            share_random_floating_point64_0_1_ry_vector[i] =
                motion_parties.at(party_id)->In<kBooleanGmw>(
                    ToInput<double, std::true_type>(random_floating_point_0_1_ry_vector[i]), 0);
          }

          encrypto::motion::ShareWrapper share_fD =
              motion_parties.at(party_id)->In<kBooleanGmw>(ToInput<T>(fD_vector), 0);

          SecureDPMechanism_PrivaDA secure_laplace_discrete_laplace_mechanism =
              SecureDPMechanism_PrivaDA(share_fD);
          secure_laplace_discrete_laplace_mechanism.ParameterSetup(sensitivity, epsilon,
                                                                   num_of_simd_lap_dlap);

          SecureFloatingPointCircuitABY floating_point32_laplace_noise =
              secure_laplace_discrete_laplace_mechanism.FL32LaplaceNoiseGeneration(
                  ShareWrapper::Simdify(share_random_floating_point32_0_1_rx_vector),
                  ShareWrapper::Simdify(share_random_floating_point32_0_1_ry_vector));
          SecureFloatingPointCircuitABY floating_point64_laplace_noise =
              secure_laplace_discrete_laplace_mechanism.FL64LaplaceNoiseGeneration(
                  ShareWrapper::Simdify(share_random_floating_point64_0_1_rx_vector),
                  ShareWrapper::Simdify(share_random_floating_point64_0_1_ry_vector));

          SecureFloatingPointCircuitABY floating_point32_laplace_noise_out =
              floating_point32_laplace_noise.Out();
          SecureFloatingPointCircuitABY floating_point64_laplace_noise_out =
              floating_point64_laplace_noise.Out();

          SecureSignedInteger signed_integer_discrete_laplace_noise_fl32 =
              secure_laplace_discrete_laplace_mechanism.FL32DiscreteLaplaceNoiseGeneration(
                  ShareWrapper::Simdify(share_random_floating_point32_0_1_rx_vector),
                  ShareWrapper::Simdify(share_random_floating_point32_0_1_ry_vector));
          SecureSignedInteger signed_integer_discrete_laplace_noise_fl64 =
              secure_laplace_discrete_laplace_mechanism.FL64DiscreteLaplaceNoiseGeneration(
                  ShareWrapper::Simdify(share_random_floating_point64_0_1_rx_vector),
                  ShareWrapper::Simdify(share_random_floating_point64_0_1_ry_vector));

          SecureSignedInteger signed_integer_discrete_laplace_noise_fl32_out =
              signed_integer_discrete_laplace_noise_fl32.Out();
          SecureSignedInteger signed_integer_discrete_laplace_noise_fl64_out =
              signed_integer_discrete_laplace_noise_fl64.Out();

          std::cout << "party run" << std::endl;
          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();
          std::cout << "party finish" << std::endl;

          if (party_id == 0) {
            std::cout << "party_id: " << party_id << std::endl;
            std::vector<float> floating_point32_laplace_noise_out_as =
                floating_point32_laplace_noise_out.AsFloatingPointVector<float>();
            std::vector<double> floating_point64_laplace_noise_out_as =
                floating_point64_laplace_noise_out.AsFloatingPointVector<double>();

            std::vector<T> signed_integer_discrete_laplace_noise_fl32_out_as =
                signed_integer_discrete_laplace_noise_fl32_out.AsVector<T>();
            std::vector<T> signed_integer_discrete_laplace_noise_fl64_out_as =
                signed_integer_discrete_laplace_noise_fl64_out.AsVector<T>();

            for (std::size_t i = 0; i < num_of_simd_lap_dlap; ++i) {
              std::cout << "expect_lap_result[i]: " << expect_lap_result[i] << std::endl;
              std::cout << "floating_point32_laplace_noise_out_as[i]: "
                        << floating_point32_laplace_noise_out_as[i] << std::endl;
              std::cout << "floating_point64_laplace_noise_out_as[i]: "
                        << floating_point64_laplace_noise_out_as[i] << std::endl;

              double abs_error = 0.01;
              EXPECT_NEAR(expect_lap_result[i], floating_point32_laplace_noise_out_as[i],
                          abs_error);
              EXPECT_NEAR(expect_lap_result[i], floating_point64_laplace_noise_out_as[i],
                          abs_error);

              std::cout << "expect_dlap_result[i]: " << expect_dlap_result[i] << std::endl;
              std::cout << "signed_integer_discrete_laplace_noise_fl32_out_as[i]: "
                        << T_int(signed_integer_discrete_laplace_noise_fl32_out_as[i]) << std::endl;
              std::cout << "signed_integer_discrete_laplace_noise_fl64_out_as[i]: "
                        << T_int(signed_integer_discrete_laplace_noise_fl64_out_as[i]) << std::endl;
              EXPECT_EQ(expect_dlap_result[i],
                        T_int(signed_integer_discrete_laplace_noise_fl32_out_as[i]));
              EXPECT_EQ(expect_dlap_result[i],
                        T_int(signed_integer_discrete_laplace_noise_fl64_out_as[i]));
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

TEST(SecureDPMechanismEKMPP, Laplace_DiscreteLaplace_Mechanism_BMR_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  // std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1) {
    using T = decltype(template_variable_1);
    // using T_int = get_int_type_t<T>;
    using T_int = std::int64_t;
    using A = std::allocator<T>;
    std::srand(std::time(nullptr));

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      std::size_t num_of_simd_lap_dlap = 10;
      std::vector<T> fD_vector = rand_range_integer_vector<T>(0, 5, num_of_simd_lap_dlap);
      std::size_t fixed_point_fraction_bit_size = 16;

      // only for debugging
      // std::cout << "fD_vector: " << std::endl;
      // for (std::size_t i = 0; i < fD_vector.size(); ++i) {
      //   std::cout << fD_vector[i] << std::endl;
      // }

      std::vector<double> random_floating_point_0_1_rx_vector =
          rand_range_double_vector(0, 1, num_of_simd_lap_dlap);

      std::vector<double> random_floating_point_0_1_ry_vector =
          rand_range_double_vector(0, 1, num_of_simd_lap_dlap);

      // only for debugging
      // std::cout << "random_floating_point_0_1_rx_vector" << std::endl;
      // for (std::size_t i = 0; i < num_of_simd_lap_dlap; i++) {
      //   std::cout << random_floating_point_0_1_rx_vector[i] << std::endl;
      // }
      // std::cout << "random_floating_point_0_1_ry_vector" << std::endl;
      // for (std::size_t i = 0; i < num_of_simd_lap_dlap; i++) {
      //   std::cout << random_floating_point_0_1_ry_vector[i] << std::endl;
      // }

      double sensitivity = 1;
      double epsilon = 1.5;
      double lambda_lap = sensitivity / epsilon;
      double lambda_dlap = std::exp(-epsilon / sensitivity);

      std::vector<double> expect_lap_result(num_of_simd_lap_dlap);
      std::vector<double> expect_dlap_result(num_of_simd_lap_dlap);
      for (std::size_t i = 0; i < num_of_simd_lap_dlap; i++) {
        expect_lap_result[i] =
            laplace_distribution(lambda_lap, random_floating_point_0_1_rx_vector[i],
                                 random_floating_point_0_1_ry_vector[i]);
        expect_dlap_result[i] =
            discrete_laplace_distribution(lambda_dlap, random_floating_point_0_1_rx_vector[i],
                                          random_floating_point_0_1_ry_vector[i]);
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
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point32_0_1_rx_vector(
              num_of_simd_lap_dlap);
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point32_0_1_ry_vector(
              num_of_simd_lap_dlap);
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point64_0_1_rx_vector(
              num_of_simd_lap_dlap);
          std::vector<encrypto::motion::ShareWrapper> share_random_floating_point64_0_1_ry_vector(
              num_of_simd_lap_dlap);

          for (std::size_t i = 0; i < num_of_simd_lap_dlap; i++) {
            share_random_floating_point32_0_1_rx_vector[i] = motion_parties.at(party_id)->In<kBmr>(
                ToInput<float, std::true_type>(float(random_floating_point_0_1_rx_vector[i])), 0);
            share_random_floating_point32_0_1_ry_vector[i] = motion_parties.at(party_id)->In<kBmr>(
                ToInput<float, std::true_type>(float(random_floating_point_0_1_ry_vector[i])), 0);
            share_random_floating_point64_0_1_rx_vector[i] = motion_parties.at(party_id)->In<kBmr>(
                ToInput<double, std::true_type>(random_floating_point_0_1_rx_vector[i]), 0);
            share_random_floating_point64_0_1_ry_vector[i] = motion_parties.at(party_id)->In<kBmr>(
                ToInput<double, std::true_type>(random_floating_point_0_1_ry_vector[i]), 0);
          }

          encrypto::motion::ShareWrapper share_fD =
              motion_parties.at(party_id)->In<kBmr>(ToInput<T>(fD_vector), 0);

          SecureDPMechanism_PrivaDA secure_laplace_discrete_laplace_mechanism =
              SecureDPMechanism_PrivaDA(share_fD);
          secure_laplace_discrete_laplace_mechanism.ParameterSetup(sensitivity, epsilon,
                                                                   num_of_simd_lap_dlap);

          SecureFloatingPointCircuitABY floating_point32_laplace_noise =
              secure_laplace_discrete_laplace_mechanism.FL32LaplaceNoiseGeneration(
                  ShareWrapper::Simdify(share_random_floating_point32_0_1_rx_vector),
                  ShareWrapper::Simdify(share_random_floating_point32_0_1_ry_vector));
          SecureFloatingPointCircuitABY floating_point64_laplace_noise =
              secure_laplace_discrete_laplace_mechanism.FL64LaplaceNoiseGeneration(
                  ShareWrapper::Simdify(share_random_floating_point64_0_1_rx_vector),
                  ShareWrapper::Simdify(share_random_floating_point64_0_1_ry_vector));

          SecureFloatingPointCircuitABY floating_point32_laplace_noise_out =
              floating_point32_laplace_noise.Out();
          SecureFloatingPointCircuitABY floating_point64_laplace_noise_out =
              floating_point64_laplace_noise.Out();

          SecureSignedInteger signed_integer_discrete_laplace_noise_fl32 =
              secure_laplace_discrete_laplace_mechanism.FL32DiscreteLaplaceNoiseGeneration(
                  ShareWrapper::Simdify(share_random_floating_point32_0_1_rx_vector),
                  ShareWrapper::Simdify(share_random_floating_point32_0_1_ry_vector));
          SecureSignedInteger signed_integer_discrete_laplace_noise_fl64 =
              secure_laplace_discrete_laplace_mechanism.FL64DiscreteLaplaceNoiseGeneration(
                  ShareWrapper::Simdify(share_random_floating_point64_0_1_rx_vector),
                  ShareWrapper::Simdify(share_random_floating_point64_0_1_ry_vector));

          SecureSignedInteger signed_integer_discrete_laplace_noise_fl32_out =
              signed_integer_discrete_laplace_noise_fl32.Out();
          SecureSignedInteger signed_integer_discrete_laplace_noise_fl64_out =
              signed_integer_discrete_laplace_noise_fl64.Out();

          std::cout << "party run" << std::endl;
          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();
          std::cout << "party finish" << std::endl;

          if (party_id == 0) {
            std::cout << "party_id: " << party_id << std::endl;
            std::vector<float> floating_point32_laplace_noise_out_as =
                floating_point32_laplace_noise_out.AsFloatingPointVector<float>();
            std::vector<double> floating_point64_laplace_noise_out_as =
                floating_point64_laplace_noise_out.AsFloatingPointVector<double>();

            std::vector<T> signed_integer_discrete_laplace_noise_fl32_out_as =
                signed_integer_discrete_laplace_noise_fl32_out.AsVector<T>();
            std::vector<T> signed_integer_discrete_laplace_noise_fl64_out_as =
                signed_integer_discrete_laplace_noise_fl64_out.AsVector<T>();

            for (std::size_t i = 0; i < num_of_simd_lap_dlap; ++i) {
              std::cout << "expect_lap_result[i]: " << expect_lap_result[i] << std::endl;
              std::cout << "floating_point32_laplace_noise_out_as[i]: "
                        << floating_point32_laplace_noise_out_as[i] << std::endl;
              std::cout << "floating_point64_laplace_noise_out_as[i]: "
                        << floating_point64_laplace_noise_out_as[i] << std::endl;

              double abs_error = 0.01;
              EXPECT_NEAR(expect_lap_result[i], floating_point32_laplace_noise_out_as[i],
                          abs_error);
              EXPECT_NEAR(expect_lap_result[i], floating_point64_laplace_noise_out_as[i],
                          abs_error);

              std::cout << "expect_dlap_result[i]: " << expect_dlap_result[i] << std::endl;
              std::cout << "signed_integer_discrete_laplace_noise_fl32_out_as[i]: "
                        << T_int(signed_integer_discrete_laplace_noise_fl32_out_as[i]) << std::endl;
              std::cout << "signed_integer_discrete_laplace_noise_fl64_out_as[i]: "
                        << T_int(signed_integer_discrete_laplace_noise_fl64_out_as[i]) << std::endl;
              EXPECT_EQ(expect_dlap_result[i],
                        T_int(signed_integer_discrete_laplace_noise_fl32_out_as[i]));
              EXPECT_EQ(expect_dlap_result[i],
                        T_int(signed_integer_discrete_laplace_noise_fl64_out_as[i]));
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

// not check correctness of the calculation
// only check if implementation is correct
TEST(SecureDPMechanismEKMPP, LaplaceNoiseGeneration_BGMW_GC_BMR_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  // std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1) {
    using T = decltype(template_variable_1);
    using T_int = get_int_type_t<T>;
    using A = std::allocator<T>;
    std::srand(std::time(nullptr));

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      std::size_t num_of_simd_lap_dlap = 1;
      std::vector<T> fD_vector = rand_range_integer_vector<T>(0, 5, num_of_simd_lap_dlap);

      std::cout << "fD_vector: " << std::endl;
      for (std::size_t i = 0; i < fD_vector.size(); ++i) {
        std::cout << fD_vector[i] << std::endl;
      }

      double sensitivity = 1;
      double epsilon = 1.5;
      double lambda_lap = sensitivity / epsilon;
      double lambda_dlap = std::exp(-epsilon / sensitivity);

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
          encrypto::motion::ShareWrapper share_fD_bgmw =
              motion_parties.at(party_id)->In<kBooleanGmw>(ToInput<T>(fD_vector), 0);
          encrypto::motion::ShareWrapper share_fD_gc =
              motion_parties.at(party_id)->In<kGarbledCircuit>(ToInput<T>(fD_vector), 0);
          encrypto::motion::ShareWrapper share_fD_bmr =
              motion_parties.at(party_id)->In<kBmr>(ToInput<T>(fD_vector), 0);

          SecureDPMechanism_PrivaDA secure_dp_mechanism_PrivaDA_bgmw =
              SecureDPMechanism_PrivaDA(share_fD_bgmw);
          secure_dp_mechanism_PrivaDA_bgmw.ParameterSetup(sensitivity, epsilon,
                                                          num_of_simd_lap_dlap);
          SecureDPMechanism_PrivaDA secure_dp_mechanism_PrivaDA_gc =
              SecureDPMechanism_PrivaDA(share_fD_gc);
          secure_dp_mechanism_PrivaDA_gc.ParameterSetup(sensitivity, epsilon, num_of_simd_lap_dlap);

          SecureDPMechanism_PrivaDA secure_dp_mechanism_PrivaDA_bmr =
              SecureDPMechanism_PrivaDA(share_fD_bmr);
          secure_dp_mechanism_PrivaDA_bmr.ParameterSetup(sensitivity, epsilon,
                                                         num_of_simd_lap_dlap);

          SecureSignedInteger signed_integer_discrete_laplace_noise_bgmw =
              secure_dp_mechanism_PrivaDA_bgmw.FL32LaplaceNoiseGeneration();
          SecureSignedInteger signed_integer_discrete_laplace_noise_gc =
              secure_dp_mechanism_PrivaDA_gc.FL32LaplaceNoiseGeneration();
          SecureSignedInteger signed_integer_discrete_laplace_noise_bmr =
              secure_dp_mechanism_PrivaDA_bmr.FL32LaplaceNoiseGeneration();

          SecureSignedInteger signed_integer_noisy_fD_bgmw =
              secure_dp_mechanism_PrivaDA_bgmw.FL32LaplaceNoiseAddition();
          SecureSignedInteger signed_integer_noisy_fD_gc =
              secure_dp_mechanism_PrivaDA_gc.FL32LaplaceNoiseAddition();
          SecureSignedInteger signed_integer_noisy_fD_bmr =
              secure_dp_mechanism_PrivaDA_bmr.FL32LaplaceNoiseAddition();

          SecureSignedInteger signed_integer_discrete_laplace_noise_out_bgmw =
              signed_integer_discrete_laplace_noise_bgmw.Out();
          SecureSignedInteger signed_integer_noisy_fD_out_bgmw = signed_integer_noisy_fD_bgmw.Out();

          SecureSignedInteger signed_integer_discrete_laplace_noise_out_gc =
              signed_integer_discrete_laplace_noise_gc.Out();
          SecureSignedInteger signed_integer_noisy_fD_out_gc = signed_integer_noisy_fD_gc.Out();

          SecureSignedInteger signed_integer_discrete_laplace_noise_out_bmr =
              signed_integer_discrete_laplace_noise_bmr.Out();
          SecureSignedInteger signed_integer_noisy_fD_out_bmr = signed_integer_noisy_fD_bmr.Out();

          std::cout << "party run" << std::endl;
          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == 0) {
            std::cout << "party_id: " << party_id << std::endl;
            std::vector<T> share_result_0_out_as_bgmw =
                signed_integer_discrete_laplace_noise_out_bgmw.AsVector<T>();

            for (std::size_t i = 0; i < share_result_0_out_as_bgmw.size(); ++i) {
              std::cout << "share_result_0_out_as_bgmw[i]: " << T_int(share_result_0_out_as_bgmw[i])
                        << std::endl;
            }
            std::vector<T> signed_integer_noisy_fD_out_as_bgmw =
                signed_integer_noisy_fD_out_bgmw.AsVector<T>();

            for (std::size_t i = 0; i < signed_integer_noisy_fD_out_as_bgmw.size(); ++i) {
              std::cout << "signed_integer_noisy_fD_out_as_bgmw[i]: "
                        << T_int(signed_integer_noisy_fD_out_as_bgmw[i]) << std::endl;
            }

            std::vector<T> share_result_0_out_as_gc =
                signed_integer_discrete_laplace_noise_out_gc.AsVector<T>();

            for (std::size_t i = 0; i < share_result_0_out_as_gc.size(); ++i) {
              std::cout << "share_result_0_out_as_gc[i]: " << T_int(share_result_0_out_as_gc[i])
                        << std::endl;
            }
            std::vector<T> signed_integer_noisy_fD_out_as_gc =
                signed_integer_noisy_fD_out_gc.AsVector<T>();

            for (std::size_t i = 0; i < signed_integer_noisy_fD_out_as_gc.size(); ++i) {
              std::cout << "signed_integer_noisy_fD_out_as_gc[i]: "
                        << T_int(signed_integer_noisy_fD_out_as_gc[i]) << std::endl;
            }


            std::vector<T> share_result_0_out_as_bmr =
                signed_integer_discrete_laplace_noise_out_bmr.AsVector<T>();

            for (std::size_t i = 0; i < share_result_0_out_as_bmr.size(); ++i) {
              std::cout << "share_result_0_out_as_bmr[i]: " << T_int(share_result_0_out_as_bmr[i])
                        << std::endl;
            }
            std::vector<T> signed_integer_noisy_fD_out_as_bmr =
                signed_integer_noisy_fD_out_bmr.AsVector<T>();

            for (std::size_t i = 0; i < signed_integer_noisy_fD_out_as_bmr.size(); ++i) {
              std::cout << "signed_integer_noisy_fD_out_as_bmr[i]: "
                        << T_int(signed_integer_noisy_fD_out_as_bmr[i]) << std::endl;
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
// not check correctness of the calculation
// only check if implementation is correct
TEST(SecureDPMechanismEKMPP, DiscreteLaplaceNoiseGeneration_BGMW_GC_BMR_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBmr = encrypto::motion::MpcProtocol::kBmr;
  constexpr auto kGarbledCircuit = encrypto::motion::MpcProtocol::kGarbledCircuit;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  // std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1) {
    using T = decltype(template_variable_1);
    using T_int = get_int_type_t<T>;
    using A = std::allocator<T>;
    std::srand(std::time(nullptr));

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      std::size_t num_of_simd_lap_dlap = 1;
      std::vector<T> fD_vector = rand_range_integer_vector<T>(0, 5, num_of_simd_lap_dlap);

      std::cout << "fD_vector: " << std::endl;
      for (std::size_t i = 0; i < fD_vector.size(); ++i) {
        std::cout << fD_vector[i] << std::endl;
      }

      double sensitivity = 1;
      double epsilon = 1.5;
      double lambda_lap = sensitivity / epsilon;
      double lambda_dlap = std::exp(-epsilon / sensitivity);

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
          encrypto::motion::ShareWrapper share_fD_bgmw =
              motion_parties.at(party_id)->In<kBooleanGmw>(ToInput<T>(fD_vector), 0);
          encrypto::motion::ShareWrapper share_fD_gc =
              motion_parties.at(party_id)->In<kGarbledCircuit>(ToInput<T>(fD_vector), 0);
          encrypto::motion::ShareWrapper share_fD_bmr =
              motion_parties.at(party_id)->In<kBmr>(ToInput<T>(fD_vector), 0);

          SecureDPMechanism_PrivaDA secure_dp_mechanism_PrivaDA_bgmw =
              SecureDPMechanism_PrivaDA(share_fD_bgmw);
          secure_dp_mechanism_PrivaDA_bgmw.ParameterSetup(sensitivity, epsilon,
                                                          num_of_simd_lap_dlap);
          SecureDPMechanism_PrivaDA secure_dp_mechanism_PrivaDA_gc =
              SecureDPMechanism_PrivaDA(share_fD_gc);
          secure_dp_mechanism_PrivaDA_gc.ParameterSetup(sensitivity, epsilon, num_of_simd_lap_dlap);

          SecureDPMechanism_PrivaDA secure_dp_mechanism_PrivaDA_bmr =
              SecureDPMechanism_PrivaDA(share_fD_bmr);
          secure_dp_mechanism_PrivaDA_bmr.ParameterSetup(sensitivity, epsilon,
                                                         num_of_simd_lap_dlap);

          SecureSignedInteger signed_integer_discrete_laplace_noise_bgmw =
              secure_dp_mechanism_PrivaDA_bgmw.FL32DiscreteLaplaceNoiseGeneration();
          SecureSignedInteger signed_integer_discrete_laplace_noise_gc =
              secure_dp_mechanism_PrivaDA_gc.FL32DiscreteLaplaceNoiseGeneration();
          SecureSignedInteger signed_integer_discrete_laplace_noise_bmr =
              secure_dp_mechanism_PrivaDA_bmr.FL32DiscreteLaplaceNoiseGeneration();

          SecureSignedInteger signed_integer_noisy_fD_bgmw =
              secure_dp_mechanism_PrivaDA_bgmw.FL32DiscreteLaplaceNoiseAddition();
          SecureSignedInteger signed_integer_noisy_fD_gc =
              secure_dp_mechanism_PrivaDA_gc.FL32DiscreteLaplaceNoiseAddition();
          SecureSignedInteger signed_integer_noisy_fD_bmr =
              secure_dp_mechanism_PrivaDA_bmr.FL32DiscreteLaplaceNoiseAddition();

          SecureSignedInteger signed_integer_discrete_laplace_noise_out_bgmw =
              signed_integer_discrete_laplace_noise_bgmw.Out();
          SecureSignedInteger signed_integer_noisy_fD_out_bgmw = signed_integer_noisy_fD_bgmw.Out();

          SecureSignedInteger signed_integer_discrete_laplace_noise_out_gc =
              signed_integer_discrete_laplace_noise_gc.Out();
          SecureSignedInteger signed_integer_noisy_fD_out_gc = signed_integer_noisy_fD_gc.Out();

          SecureSignedInteger signed_integer_discrete_laplace_noise_out_bmr =
              signed_integer_discrete_laplace_noise_bmr.Out();
          SecureSignedInteger signed_integer_noisy_fD_out_bmr = signed_integer_noisy_fD_bmr.Out();

          std::cout << "party run" << std::endl;
          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == 0) {
            std::cout << "party_id: " << party_id << std::endl;
            std::vector<T> share_result_0_out_as_bgmw =
                signed_integer_discrete_laplace_noise_out_bgmw.AsVector<T>();

            for (std::size_t i = 0; i < share_result_0_out_as_bgmw.size(); ++i) {
              std::cout << "share_result_0_out_as_bgmw[i]: " << T_int(share_result_0_out_as_bgmw[i])
                        << std::endl;
            }
            std::vector<T> signed_integer_noisy_fD_out_as_bgmw =
                signed_integer_noisy_fD_out_bgmw.AsVector<T>();

            for (std::size_t i = 0; i < signed_integer_noisy_fD_out_as_bgmw.size(); ++i) {
              std::cout << "signed_integer_noisy_fD_out_as_bgmw[i]: "
                        << T_int(signed_integer_noisy_fD_out_as_bgmw[i]) << std::endl;
            }

            std::vector<T> share_result_0_out_as_gc =
                signed_integer_discrete_laplace_noise_out_gc.AsVector<T>();

            for (std::size_t i = 0; i < share_result_0_out_as_gc.size(); ++i) {
              std::cout << "share_result_0_out_as_gc[i]: " << T_int(share_result_0_out_as_gc[i])
                        << std::endl;
            }
            std::vector<T> signed_integer_noisy_fD_out_as_gc =
                signed_integer_noisy_fD_out_gc.AsVector<T>();

            for (std::size_t i = 0; i < signed_integer_noisy_fD_out_as_gc.size(); ++i) {
              std::cout << "signed_integer_noisy_fD_out_as_gc[i]: "
                        << T_int(signed_integer_noisy_fD_out_as_gc[i]) << std::endl;
            }


            std::vector<T> share_result_0_out_as_bmr =
                signed_integer_discrete_laplace_noise_out_bmr.AsVector<T>();

            for (std::size_t i = 0; i < share_result_0_out_as_bmr.size(); ++i) {
              std::cout << "share_result_0_out_as_bmr[i]: " << T_int(share_result_0_out_as_bmr[i])
                        << std::endl;
            }
            std::vector<T> signed_integer_noisy_fD_out_as_bmr =
                signed_integer_noisy_fD_out_bmr.AsVector<T>();

            for (std::size_t i = 0; i < signed_integer_noisy_fD_out_as_bmr.size(); ++i) {
              std::cout << "signed_integer_noisy_fD_out_as_bmr[i]: "
                        << T_int(signed_integer_noisy_fD_out_as_bmr[i]) << std::endl;
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

}  // namespace
