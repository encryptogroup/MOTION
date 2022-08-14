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

#include "benchmark_integer_scaling_mechanism.h"

#include <openssl/rand.h>
#include <algorithm>
#include <limits>
#include <vector>
#include "algorithm/algorithm_description.h"
#include "protocols/share_wrapper.h"
#include "secure_dp_mechanism/secure_discrete_gaussian_mechanism_CKS.h"
#include "secure_dp_mechanism/secure_discrete_laplace_mechanism_CKS.h"
#include "secure_dp_mechanism/secure_integer_scaling_gaussian_mechanism.h"
#include "secure_dp_mechanism/secure_integer_scaling_laplace_mechanism.h"
#include "secure_dp_mechanism/secure_PrivaDA_EKMPP.h"
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

  double sensitivity = 1;

  std::vector<double> fD_vector = rand_range_double_vector(0, 1, number_of_simd);
  em::ShareWrapper share_input_fD =
      party->In<em::MpcProtocol::kBooleanGmw>(em::ToInput<double, std::true_type>(fD_vector), 0);

  em::SecureIntegerScalingLaplaceMechanism secure_integer_scaling_laplace_mechanism =
      em::SecureIntegerScalingLaplaceMechanism(share_input_fD);

  em::SecureIntegerScalingGaussianMechanism secure_integer_scaling_gaussian_mechanism =
      em::SecureIntegerScalingGaussianMechanism(share_input_fD);

  if (protocol == em::MpcProtocol::kBooleanGmw) {
    switch (operation_type) {
      case em::DPMechanismType::kSecureIntegerScalingLaplaceMechanism_FxLaplace: {
        // double epsilon = rand_range_double(0, 2);

        // only for debug
        double epsilon = 1.435;

        long double fail_probability = std::exp2l(-40);
        secure_integer_scaling_laplace_mechanism.ParameterSetup(
            sensitivity, epsilon, number_of_simd, fail_probability, fixed_point_bit_size,
            fixed_point_fraction_bit_size);
        secure_integer_scaling_laplace_mechanism.FxLaplaceNoiseAddition();
        break;
      }
      case em::DPMechanismType::kSecureIntegerScalingLaplaceMechanism_FL32Laplace: {
        // double epsilon = rand_range_double(0, 2);

        // only for debug
        double epsilon = 1.435;

        long double fail_probability = std::exp2l(-40);
        secure_integer_scaling_laplace_mechanism.ParameterSetup(
            sensitivity, epsilon, number_of_simd, fail_probability, fixed_point_bit_size,
            fixed_point_fraction_bit_size);
        secure_integer_scaling_laplace_mechanism.FL32LaplaceNoiseAddition();
        break;
      }

      case em::DPMechanismType::kSecureIntegerScalingLaplaceMechanism_FL64Laplace: {
        // double epsilon = rand_range_double(0, 2);

        // only for debug
        double epsilon = 1.435;

        long double fail_probability = std::exp2l(-40);
        secure_integer_scaling_laplace_mechanism.ParameterSetup(
            sensitivity, epsilon, number_of_simd, fail_probability, fixed_point_bit_size,
            fixed_point_fraction_bit_size);
        secure_integer_scaling_laplace_mechanism.FL64LaplaceNoiseAddition();
        break;
      }
      case em::DPMechanismType::kSecureIntegerScalingGaussianMechanism_FLGaussian: {
        long double fail_probability = std::exp2l(-40);
        double epsilon = 1.435;
        double delta = 0.001;

        secure_integer_scaling_gaussian_mechanism.ParameterSetup(sensitivity, epsilon, delta,
                                                                 number_of_simd, fail_probability);
        secure_integer_scaling_gaussian_mechanism.FLGaussianNoiseAddition();
        break;
      }
      default:
        throw std::invalid_argument("Unknown operation type");
    }
  }

  party->Run();
  party->Finish();
  const auto& statistics = party->GetBackend()->GetRunTimeStatistics();
  return statistics.front();
}