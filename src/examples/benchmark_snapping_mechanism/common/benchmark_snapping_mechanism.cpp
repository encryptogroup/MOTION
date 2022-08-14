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

#include "benchmark_snapping_mechanism.h"

#include <openssl/rand.h>
#include <algorithm>
#include <limits>
#include <vector>
#include "algorithm/algorithm_description.h"
#include "protocols/share_wrapper.h"
#include "secure_dp_mechanism/secure_snapping_mechanism.h"
#include "secure_type/secure_fixed_point_circuit_CBMC.h"
#include "secure_type/secure_unsigned_integer.h"
#include "statistics/analysis.h"
#include "statistics/run_time_statistics.h"
#include "utility/config.h"
#include "secure_dp_mechanism/secure_dp_mechanism_helper.h"


namespace em = encrypto::motion;

em::RunTimeStatistics EvaluateProtocol(em::PartyPointer& party, std::size_t number_of_simd,
                                       std::size_t bit_size, em::MpcProtocol protocol,
                                       em::DPMechanismType operation_type) {
  em::SecureFloatingPointCircuitABY floating_point_boolean_gmw_share_ABY_0;
  em::SecureFloatingPointCircuitABY floating_point_boolean_gmw_share_ABY_1;


  std::size_t floating_point_mantissa_bit_size = 53;
  std::size_t floating_point_exponent_bit_size = 11;

  std::size_t fixed_point_bit_size = 64;
  std::size_t fixed_point_fraction_bit_size = 16;

  std::uint64_t m = 50;

  std::vector<double> vector_of_input = rand_range_double_vector(0, 1, number_of_simd);

  floating_point_boolean_gmw_share_ABY_0 =
      em::SecureFloatingPointCircuitABY(party->In<em::MpcProtocol::kBooleanGmw>(
          em::ToInput<double, std::true_type>(vector_of_input), 0));
  floating_point_boolean_gmw_share_ABY_1 =
      em::SecureFloatingPointCircuitABY(party->In<em::MpcProtocol::kBooleanGmw>(
          em::ToInput<double, std::true_type>(vector_of_input), 0));


  em::ShareWrapper boolean_gmw_share_random_bits_52 =
      em::SecureDPMechanismHelper(floating_point_boolean_gmw_share_ABY_0.Get()).GenerateRandomBooleanGmwBits(52, number_of_simd);
  em::ShareWrapper boolean_gmw_share_random_bits_1 =
      em::SecureDPMechanismHelper(floating_point_boolean_gmw_share_ABY_0.Get()).GenerateRandomBooleanGmwBits(1, number_of_simd);
  em::ShareWrapper boolean_gmw_share_random_bits_1022 =
      em::SecureDPMechanismHelper(floating_point_boolean_gmw_share_ABY_0.Get()).GenerateRandomBooleanGmwBits(1022,
                                                                                number_of_simd);
  em::ShareWrapper boolean_gmw_share_random_bits_23 =
      em::SecureDPMechanismHelper(floating_point_boolean_gmw_share_ABY_0.Get()).GenerateRandomBooleanGmwBits(23, number_of_simd);
  em::ShareWrapper boolean_gmw_share_random_bits_126 =
      em::SecureDPMechanismHelper(floating_point_boolean_gmw_share_ABY_0.Get()).GenerateRandomBooleanGmwBits(126,
                                                                                number_of_simd);
  em::ShareWrapper random_bits_of_length_fixed_point_fraction =
      em::SecureDPMechanismHelper(floating_point_boolean_gmw_share_ABY_0.Get()).GenerateRandomBooleanGmwBits(
          fixed_point_fraction_bit_size, number_of_simd);

  double sensitivity = 1;
  double lambda = 0.01;
  double clamp_B = 1.9;

  std::vector<double> fD_vector = rand_range_double_vector(0, 1, number_of_simd);
  em::ShareWrapper share_input_fD =
      party->In<em::MpcProtocol::kBooleanGmw>(em::ToInput<double, std::true_type>(fD_vector), 0);

  em::SecureSnappingMechanism secure_snapping_mechanism =
      em::SecureSnappingMechanism(share_input_fD);

  secure_snapping_mechanism.ParameterSetup(sensitivity, lambda, clamp_B);

  if (protocol == em::MpcProtocol::kBooleanGmw) {
    switch (operation_type) {
      case em::DPMechanismType::kGenerateRandomBooleanGmwBits: {
        em::SecureDPMechanismHelper(floating_point_boolean_gmw_share_ABY_0.Get()).GenerateRandomBooleanGmwBits(1022,
                                                                                  number_of_simd);
        break;
      }
      case em::DPMechanismType::kSimpleGeometricSampling: {
        em::SecureDPMechanismHelper(floating_point_boolean_gmw_share_ABY_0.Get()).SimpleGeometricSampling_1(
            boolean_gmw_share_random_bits_1022);
        break;
      }
      case em::DPMechanismType::kUniformFloatingPoint32_0_1: {
        em::SecureDPMechanismHelper(floating_point_boolean_gmw_share_ABY_0.Get()).UniformFloatingPoint32_0_1(
            boolean_gmw_share_random_bits_23, boolean_gmw_share_random_bits_126);
        break;
      }
      case em::DPMechanismType::kUniformFloatingPoint64_0_1: {
        em::SecureDPMechanismHelper(floating_point_boolean_gmw_share_ABY_0.Get()).UniformFloatingPoint64_0_1(
            boolean_gmw_share_random_bits_52, boolean_gmw_share_random_bits_1022);
        break;
      }
      case em::DPMechanismType::kUniformFixedPoint_0_1: {
        em::SecureDPMechanismHelper(floating_point_boolean_gmw_share_ABY_0.Get()).UniformFixedPoint_0_1(
            boolean_gmw_share_random_bits_52, fixed_point_bit_size);
        break;
      }
      case em::DPMechanismType::kUniformFixedPoint_0_1_Up: {
        em::SecureDPMechanismHelper(floating_point_boolean_gmw_share_ABY_0.Get()).UniformFixedPoint_0_1_Up(
            boolean_gmw_share_random_bits_52, fixed_point_bit_size);
        break;
      }
      case em::DPMechanismType::kRandomUnsignedInteger: {
        em::SecureDPMechanismHelper(floating_point_boolean_gmw_share_ABY_0.Get()).GenerateRandomUnsignedInteger<std::uint64_t>(
            m, number_of_simd);
        break;
      }
      case em::DPMechanismType::kSecureSnappingMechanism: {
        secure_snapping_mechanism.SnappingAndNoiseAddition(boolean_gmw_share_random_bits_52,
                                                           boolean_gmw_share_random_bits_1022,
                                                           boolean_gmw_share_random_bits_1);
        break;
      }
      default:
        throw std::invalid_argument("Unknown operation type");
    }
  }

  else {
    throw std::invalid_argument("Invalid MPC protocol");
  }

  party->Run();
  party->Finish();
  const auto& statistics = party->GetBackend()->GetRunTimeStatistics();
  return statistics.front();
}