// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko
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

#include "benchmark_liangzhao_dp_mechanism_PrivaDA.h"

#include <openssl/rand.h>
#include <algorithm>
#include <limits>
#include <vector>
#include "algorithm/algorithm_description.h"
#include "protocols/share_wrapper.h"
// #include "secure_dp_mechanism/secure_gaussian_mechanism.h"
#include "secure_dp_mechanism/secure_dp_mechanism_PrivaDA.h"
#include "secure_dp_mechanism/secure_snapping_mechanism.h"
#include "secure_type/secure_fixed_point_agmw_CS.h"
#include "secure_type/secure_fixed_point_circuit_CBMC.h"
#include "secure_type/secure_floating_point_circuit_ABY.h"
#include "secure_type/secure_unsigned_integer.h"
#include "statistics/analysis.h"
#include "statistics/run_time_statistics.h"
#include "utility/config.h"

// template <typename T>
// inline T Rand() {
//   unsigned char buf[sizeof(T)];
//   RAND_bytes(buf, sizeof(T));
//   return *reinterpret_cast<T*>(buf);
// }

// template <typename T>
// inline std::vector<T> RandomVector(std::size_t size) {
//   std::vector<T> v(size);
//   std::generate(v.begin(), v.end(), Rand<T>);
//   return v;
// }

namespace em = encrypto::motion;

em::RunTimeStatistics EvaluateProtocol(em::PartyPointer& party, std::size_t number_of_simd,
                                       std::size_t bit_size, em::MpcProtocol protocol,
                                       em::DPMechanismType operation_type) {
  // em::SecureFloatingPointCircuitABY floating_point_boolean_gmw_share_ABY_0;
  // em::SecureFloatingPointCircuitABY floating_point_boolean_gmw_share_ABY_1;

  // em::SecureFloatingPointAgmwABZS floating_point_agmw_ABZS_0;
  // em::SecureFloatingPointAgmwABZS floating_point_agmw_ABZS_1;

  // std::size_t floating_point_mantissa_bit_size = 53;
  // std::size_t floating_point_exponent_bit_size = 11;

  std::size_t fixed_point_bit_size = 64;
  std::size_t fixed_point_fraction_bit_size = 16;

  // std::vector<double> vector_of_input(number_of_simd, 0);

  // floating_point_boolean_gmw_share_ABY_0 =
  //     em::SecureFloatingPointCircuitABY(party->In<em::MpcProtocol::kBooleanGmw>(
  //         em::ToInput<double, std::true_type>(vector_of_input), 0));
  // floating_point_boolean_gmw_share_ABY_1 =
  //     em::SecureFloatingPointCircuitABY(party->In<em::MpcProtocol::kBooleanGmw>(
  //         em::ToInput<double, std::true_type>(vector_of_input), 0));

  // floating_point_agmw_ABZS_0 =
  //     em::SecureFloatingPointAgmwABZS(party->InFloatingPoint<em::MpcProtocol::kArithmeticGmw>(
  //         double(0), floating_point_mantissa_bit_size, floating_point_exponent_bit_size, 0));
  // floating_point_agmw_ABZS_1 =
  //     em::SecureFloatingPointAgmwABZS(party->InFloatingPoint<em::MpcProtocol::kArithmeticGmw>(
  //         double(0), floating_point_mantissa_bit_size, floating_point_exponent_bit_size, 0));

  // em::ShareWrapper boolean_gmw_share_random_bits_52 =
  //     floating_point_boolean_gmw_share_ABY_0.Get().GenerateRandomBooleanGmwBits(52,
  //     number_of_simd);
  // em::ShareWrapper boolean_gmw_share_random_bits_1 =
  //     floating_point_boolean_gmw_share_ABY_0.Get().GenerateRandomBooleanGmwBits(1,
  //     number_of_simd);
  // em::ShareWrapper boolean_gmw_share_random_bits_1022 =
  //     floating_point_boolean_gmw_share_ABY_0.Get().GenerateRandomBooleanGmwBits(1022,
  //                                                                               number_of_simd);
  // em::ShareWrapper random_bits_of_length_fixed_point_fraction =
  //     floating_point_boolean_gmw_share_ABY_0.Get().GenerateRandomBooleanGmwBits(
  //         fixed_point_fraction_bit_size, number_of_simd);

  // ================================================================
  double sensitivity_lap_dlap = 1;
  std::vector<float> fD_float_vector = rand_range_float_vector(0, 1, number_of_simd);
  std::vector<double> fD_double_vector = rand_range_double_vector(0, 1, number_of_simd);

  em::ShareWrapper share_input_fD_float;
  em::ShareWrapper share_input_fD_double;

  if (protocol == encrypto::motion::MpcProtocol::kBooleanGmw) {
    share_input_fD_float = party->In<em::MpcProtocol::kBooleanGmw>(
        em::ToInput<float, std::true_type>(fD_float_vector), 0);
    share_input_fD_double = party->In<em::MpcProtocol::kBooleanGmw>(
        em::ToInput<double, std::true_type>(fD_double_vector), 0);
  } else if (protocol == encrypto::motion::MpcProtocol::kGarbledCircuit) {
    share_input_fD_float = party->In<em::MpcProtocol::kGarbledCircuit>(
        em::ToInput<float, std::true_type>(fD_float_vector), 0);
    share_input_fD_double = party->In<em::MpcProtocol::kGarbledCircuit>(
        em::ToInput<double, std::true_type>(fD_double_vector), 0);
  } else if (protocol == encrypto::motion::MpcProtocol::kBmr) {
    share_input_fD_float =
        party->In<em::MpcProtocol::kBmr>(em::ToInput<float, std::true_type>(fD_float_vector), 0);
    share_input_fD_double =
        party->In<em::MpcProtocol::kBmr>(em::ToInput<double, std::true_type>(fD_double_vector), 0);
  } else {
    throw std::invalid_argument("Unknown operation type");
  }

  double epsilon = 0.01;
  double lambda_lap = sensitivity_lap_dlap / epsilon;
  double lambda_dlap = std::exp(-epsilon / sensitivity_lap_dlap);
  em::SecureDPMechanism_PrivaDA secure_dp_mechanism_PrivaDA_fl32 =
      em::SecureDPMechanism_PrivaDA(share_input_fD_float);
  secure_dp_mechanism_PrivaDA_fl32.ParameterSetup(sensitivity_lap_dlap, epsilon, number_of_simd,
                                                  fixed_point_bit_size,
                                                  fixed_point_fraction_bit_size);
  em::SecureDPMechanism_PrivaDA secure_dp_mechanism_PrivaDA_fl64 =
      em::SecureDPMechanism_PrivaDA(share_input_fD_double);
  secure_dp_mechanism_PrivaDA_fl64.ParameterSetup(sensitivity_lap_dlap, epsilon, number_of_simd,
                                                  fixed_point_bit_size,
                                                  fixed_point_fraction_bit_size);

  // ================================================================
  switch (operation_type) {
    case em::DPMechanismType::kDPMechanism_PrivaDA_FL32Laplace_noise_generation: {
      secure_dp_mechanism_PrivaDA_fl32.FL32LaplaceNoiseGeneration();
      break;
    }
    case em::DPMechanismType::kDPMechanism_PrivaDA_FL64Laplace_noise_generation: {
      secure_dp_mechanism_PrivaDA_fl64.FL64LaplaceNoiseGeneration();
      break;
    }
    case em::DPMechanismType::kDPMechanism_PrivaDA_FL32Laplace_perturbation: {
      em::SecureFloatingPointCircuitABY(share_input_fD_float) +
          em::SecureFloatingPointCircuitABY(share_input_fD_float);
      break;
    }
    case em::DPMechanismType::kDPMechanism_PrivaDA_FL64Laplace_perturbation: {
      em::SecureFloatingPointCircuitABY(share_input_fD_double) +
          em::SecureFloatingPointCircuitABY(share_input_fD_double);
      break;
    }

    default:
      throw std::invalid_argument("Unknown operation type");
  }

  party->Run();
  party->Finish();
  const auto& statistics = party->GetBackend()->GetRunTimeStatistics();
  return statistics.front();
}