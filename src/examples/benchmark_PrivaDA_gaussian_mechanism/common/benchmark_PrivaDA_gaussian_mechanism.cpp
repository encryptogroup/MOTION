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

#include "benchmark_PrivaDA_gaussian_mechanism.h"

#include <openssl/rand.h>
#include <algorithm>
#include <limits>
#include <vector>
#include "algorithm/algorithm_description.h"
#include "protocols/share_wrapper.h"
#include "secure_dp_mechanism/secure_PrivaDA_EKMPP.h"
#include "secure_dp_mechanism/secure_gaussian_mechanism.h"
#include "secure_dp_mechanism/secure_snapping_mechanism.h"
#include "secure_type/secure_fixed_point_circuit_CBMC.h"
#include "secure_type/secure_unsigned_integer.h"
#include "statistics/analysis.h"
#include "statistics/run_time_statistics.h"
#include "utility/config.h"

namespace em = encrypto::motion;

em::RunTimeStatistics EvaluateProtocol(em::PartyPointer& party, std::size_t number_of_simd,
                                       std::size_t bit_size, em::MpcProtocol protocol,
                                       em::DPMechanismType operation_type) {
  std::size_t floating_point_mantissa_bit_size = 53;
  std::size_t floating_point_exponent_bit_size = 11;

  std::size_t fixed_point_bit_size = 64;
  std::size_t fixed_point_fraction_bit_size = 16;

  // ================================================================
  double sensitivity_lap_dlap = 1;
  std::vector<float> fD_float_vector = rand_range_float_vector(0, 1, number_of_simd);
  std::vector<double> fD_double_vector = rand_range_double_vector(0, 1, number_of_simd);

  em::ShareWrapper share_input_fD_float = party->In<em::MpcProtocol::kBooleanGmw>(
      em::ToInput<float, std::true_type>(fD_float_vector), 0);
  em::ShareWrapper share_input_fD_double = party->In<em::MpcProtocol::kBooleanGmw>(
      em::ToInput<double, std::true_type>(fD_double_vector), 0);

  double epsilon = 0.01;
  double lambda_lap = sensitivity_lap_dlap / epsilon;
  double lambda_dlap = std::exp(-epsilon / sensitivity_lap_dlap);
  em::SecurePrivaDA secure_laplace_discrete_laplace_mechanism_fl32 =
      em::SecurePrivaDA(share_input_fD_float);
  secure_laplace_discrete_laplace_mechanism_fl32.ParameterSetup(
      sensitivity_lap_dlap, epsilon, number_of_simd, fixed_point_bit_size,
      fixed_point_fraction_bit_size);
  em::SecurePrivaDA secure_laplace_discrete_laplace_mechanism_fx_fl64 =
      em::SecurePrivaDA(share_input_fD_double);
  secure_laplace_discrete_laplace_mechanism_fx_fl64.ParameterSetup(
      sensitivity_lap_dlap, epsilon, number_of_simd, fixed_point_bit_size,
      fixed_point_fraction_bit_size);

  // ================================================================
  double sensitivity_gau = 1;
  double mu = 0;
  double sigma = 1;
  em::SecureGaussianMechanism secure_gaussian_mechanism_fl32 =
      em::SecureGaussianMechanism(share_input_fD_float);
  secure_gaussian_mechanism_fl32.ParameterSetup(sensitivity_gau, mu, sigma, number_of_simd,
                                                fixed_point_bit_size,
                                                fixed_point_fraction_bit_size);
  em::SecureGaussianMechanism secure_gaussian_mechanism_fx_fl64 =
      em::SecureGaussianMechanism(share_input_fD_double);
  secure_gaussian_mechanism_fx_fl64.ParameterSetup(sensitivity_gau, mu, sigma, number_of_simd,
                                                   fixed_point_bit_size,
                                                   fixed_point_fraction_bit_size);
  // ================================================================
  switch (operation_type) {
    case em::DPMechanismType::kSecurePrivaDA_EKMPP_FxLaplace_DP_insecure: {
      secure_laplace_discrete_laplace_mechanism_fx_fl64.FxLaplaceNoiseAddition();
      break;
    }
    case em::DPMechanismType::kSecurePrivaDA_EKMPP_FL32Laplace_DP_insecure: {
      secure_laplace_discrete_laplace_mechanism_fl32.FL32LaplaceNoiseAddition();
      break;
    }
    case em::DPMechanismType::kSecurePrivaDA_EKMPP_FL64Laplace_DP_insecure: {
      secure_laplace_discrete_laplace_mechanism_fx_fl64.FL64LaplaceNoiseAddition();
      break;
    }
    case em::DPMechanismType::kSecurePrivaDA_EKMPP_FxDiscreteLaplace: {
      secure_laplace_discrete_laplace_mechanism_fx_fl64.FxDiscreteLaplaceNoiseAddition();
      break;
    }
    case em::DPMechanismType::kSecurePrivaDA_EKMPP_FL32DiscreteLaplace: {
      secure_laplace_discrete_laplace_mechanism_fl32.FL32DiscreteLaplaceNoiseAddition();
      break;
    }
    case em::DPMechanismType::kSecurePrivaDA_EKMPP_FL64DiscreteLaplace: {
      secure_laplace_discrete_laplace_mechanism_fx_fl64.FL64DiscreteLaplaceNoiseAddition();
      break;
    }
    case em::DPMechanismType::kSecureGaussianMechanism_FxGaussian_DP_insecure: {
      secure_gaussian_mechanism_fx_fl64.FxGaussianNoiseAddition();
      break;
    }
    case em::DPMechanismType::kSecureGaussianMechanism_FL32Gaussian_DP_insecure: {
      secure_gaussian_mechanism_fl32.FL32GaussianNoiseAddition();
      break;
    }
    case em::DPMechanismType::kSecureGaussianMechanism_FL64Gaussian_DP_insecure: {
      secure_gaussian_mechanism_fx_fl64.FL64GaussianNoiseAddition();
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