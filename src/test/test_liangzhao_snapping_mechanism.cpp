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
#include "utility/MOTION_dp_mechanism_helper/dp_mechanism_helper.h"
#include "utility/MOTION_dp_mechanism_helper/snapping_mechanism.h"
#include "utility/config.h"

#include "test_constants.h"

using namespace encrypto::motion;

namespace {

// interface test, not check for correctness
// TODO: add correctness test
TEST(SnappingMechanism, SecureSnappingMechanism_100_Simd_2_3_4_5_10_parties) {
  constexpr auto kArithmeticGmw = encrypto::motion::MpcProtocol::kArithmeticGmw;
  constexpr auto kArithmeticConstant = encrypto::motion::MpcProtocol::kArithmeticConstant;
  constexpr auto kBooleanGmw = encrypto::motion::MpcProtocol::kBooleanGmw;
  constexpr auto kBooleanConstant = encrypto::motion::MpcProtocol::kBooleanConstant;
  std::srand(std::time(nullptr));
  auto template_test = [](auto template_variable_1) {
    using T = decltype(template_variable_1);
    std::size_t num_of_simd = 100;

    std::size_t exponent_random_bits_length = 1022;
    std::size_t mantissa_random_bits_length = 52;
    std::size_t sign_random_bits_length = 1;

    double fD = 1.7;

    std::vector<double> fD_vector(num_of_simd, fD);

    double sensitivity = 1;
    double lambda = 0.01;
    double clamp_B = 1.9;

    for (auto number_of_parties : kNumberOfPartiesList) {
      std::size_t output_owner = 0;

      const std::vector<bool> exponent_random_bits_vector =
          RandomBoolVector(exponent_random_bits_length);
      const std::vector<bool> mantissa_random_bits_vector =
          RandomBoolVector(mantissa_random_bits_length);
      const std::vector<bool> sign_random_bits_vector = RandomBoolVector(sign_random_bits_length);

      const std::vector<double> floating_point_0_1_vector =
          RandomRangeVector<double>(0, 1, num_of_simd);

      // // only for debug
      // for (std::size_t i = 0; i < exponent_random_bits_length; i++) {
      //   exponent_random_bits_vector[i] = 0;
      // }
      // for (std::size_t i = 0; i < mantissa_random_bits_length; i++) {
      //   mantissa_random_bits_vector[i] = 0;
      // }

      //   std::cout << "exponent_random_bits_vector: ";
      //   for (std::size_t i = 0; i < exponent_random_bits_length; i++) {
      //     std::cout << exponent_random_bits_vector[i];
      //   }
      //   std::cout << std::endl;

      //   std::cout << "mantissa_random_bits_vector: ";
      //   for (std::size_t i = 0; i < mantissa_random_bits_length; i++) {
      //     std::cout << mantissa_random_bits_vector[i];
      //   }
      //   std::cout << std::endl;

      //   std::cout << "sign_random_bits_vector: ";
      //   for (std::size_t i = 0; i < sign_random_bits_length; i++) {
      //     std::cout << sign_random_bits_vector[i];
      //   }
      //   std::cout << std::endl;

      std::vector<BitVector<>> exponent_random_bits_bitvector_vector(exponent_random_bits_length);
      for (std::size_t i = 0; i < exponent_random_bits_length; i++) {
        exponent_random_bits_bitvector_vector[i] =
            BitVector<>(num_of_simd, exponent_random_bits_vector[i]);
      }

      std::vector<BitVector<>> mantissa_random_bits_bitvector_vector(mantissa_random_bits_length);
      for (std::size_t i = 0; i < mantissa_random_bits_length; i++) {
        mantissa_random_bits_bitvector_vector[i] =
            BitVector<>(num_of_simd, mantissa_random_bits_vector[i]);
      }

      std::vector<BitVector<>> sign_random_bits_bitvector_vector(sign_random_bits_length);
      for (std::size_t i = 0; i < sign_random_bits_length; i++) {
        sign_random_bits_bitvector_vector[i] = BitVector<>(num_of_simd, sign_random_bits_vector[i]);
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
          encrypto::motion::ShareWrapper share_input_exponent_random_bits;
          encrypto::motion::ShareWrapper share_input_mantissa_random_bits;
          encrypto::motion::ShareWrapper share_input_sign_random_bits;
          encrypto::motion::ShareWrapper share_input_fD;
          encrypto::motion::ShareWrapper share_floating_point_0_1_vector;

          share_input_exponent_random_bits = motion_parties.at(party_id)->In<kBooleanGmw>(
              exponent_random_bits_bitvector_vector, 0);
          share_input_mantissa_random_bits = motion_parties.at(party_id)->In<kBooleanGmw>(
              mantissa_random_bits_bitvector_vector, 0);
          share_input_sign_random_bits =
              motion_parties.at(party_id)->In<kBooleanGmw>(sign_random_bits_bitvector_vector, 0);
          share_input_fD = motion_parties.at(party_id)->In<kBooleanGmw>(
              ToInput<double, std::true_type>(fD_vector), 0);

          share_floating_point_0_1_vector = motion_parties.at(party_id)->In<kBooleanGmw>(
              ToInput<double, std::true_type>(floating_point_0_1_vector), 0);

          std::cout << "party in" << std::endl;

          SecureSnappingMechanism share_snapping_mechanism =
              SecureSnappingMechanism(share_input_fD);

          share_snapping_mechanism.ParameterSetup(sensitivity, lambda, clamp_B);

          SecureFloatingPointCircuitABY share_noise_naive =
              share_snapping_mechanism.NoiseGeneration_naive();
          SecureFloatingPointCircuitABY share_noise_optimized =
              share_snapping_mechanism.NoiseGeneration_optimized();

          SecureFloatingPointCircuitABY share_adding_noise_naive =
              share_snapping_mechanism.SnappingAndNoiseAddition_naive(
                  share_floating_point_0_1_vector);
          SecureFloatingPointCircuitABY share_adding_noise_optimized =
              share_snapping_mechanism.SnappingAndNoiseAddition_optimized(
                  share_floating_point_0_1_vector);

          SecureFloatingPointCircuitABY share_noise_naive_out = share_noise_naive.Out();
          SecureFloatingPointCircuitABY share_noise_optimized_out = share_noise_optimized.Out();

          SecureFloatingPointCircuitABY share_adding_noise_naive_out =
              share_adding_noise_naive.Out();
          SecureFloatingPointCircuitABY share_adding_noise_optimized_out =
              share_adding_noise_optimized.Out();

          std::cout << "party run" << std::endl;
          motion_parties.at(party_id)->Run();
          motion_parties.at(party_id)->Finish();

          if (party_id == output_owner) {
            // std::cout << "output_vector :";
            // for (std::size_t i = 0; i < output_vector.size(); i++) {
            //   std::cout << output_vector[i].As<bool>();
            // }
            // std::cout<<std::endl;

            // T share_noise_out_T = share_noise_out.As<T>();
            // std::cout << "share_noise_out_T: " << share_noise_out_T <<
            // std::endl;
            std::vector<double> share_noise_naive_out_double_vector =
                share_noise_naive_out.AsFloatingPointVector<double>();
            std::vector<double> share_noise_optimized_out_double_vector =
                share_noise_optimized_out.AsFloatingPointVector<double>();

            std::vector<double> share_adding_noise_naive_out_double_vector =
                share_adding_noise_naive_out.AsFloatingPointVector<double>();
            std::vector<double> share_adding_noise_optimized_out_double_vector =
                share_adding_noise_optimized_out.AsFloatingPointVector<double>();

            for (std::size_t i = 0; i < num_of_simd; i++) {
              std::cout << "share_noise_naive_out_double_vector[i]: "
                        << share_noise_naive_out_double_vector[i] << std::endl;
              std::cout << "share_noise_optimized_out_double_vector[i]: "
                        << share_noise_optimized_out_double_vector[i] << std::endl;
              std::cout << "share_adding_noise_naive_out_double_vector[i]: "
                        << share_adding_noise_naive_out_double_vector[i] << std::endl;
              std::cout << "share_adding_noise_optimized_out_double_vector[i]: "
                        << share_adding_noise_optimized_out_double_vector[i] << std::endl;
            }
          }
        }
      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  };
  for (auto i = 0ull; i < kTestIterations; ++i) {
    // lambdas don't support templates, but only auto types. So, let's try to trick them.
    template_test(static_cast<std::uint64_t>(0));
  }
}

}  // namespace
