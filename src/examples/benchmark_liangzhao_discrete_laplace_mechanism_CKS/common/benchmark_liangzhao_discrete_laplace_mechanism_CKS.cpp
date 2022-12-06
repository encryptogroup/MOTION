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

#include "benchmark_liangzhao_discrete_laplace_mechanism_CKS.h"

#include <openssl/rand.h>
#include <algorithm>
#include <limits>
#include <vector>
#include "algorithm/algorithm_description.h"
#include "protocols/share_wrapper.h"
#include "secure_dp_mechanism/secure_discrete_gaussian_mechanism_CKS.h"
#include "secure_dp_mechanism/secure_discrete_laplace_mechanism_CKS.h"
#include "secure_dp_mechanism/secure_snapping_mechanism.h"
#include "secure_type/secure_fixed_point_agmw_CS.h"
#include "secure_type/secure_fixed_point_circuit_CBMC.h"
#include "secure_type/secure_unsigned_integer.h"
#include "statistics/analysis.h"
#include "statistics/run_time_statistics.h"
#include "utility/config.h"

namespace em = encrypto::motion;

em::RunTimeStatistics EvaluateProtocol(em::PartyPointer& party, std::size_t number_of_simd,
                                       std::size_t bit_size, em::MpcProtocol protocol,
                                       em::DPMechanismType operation_type,
                                       double failure_probability) {
  std::size_t floating_point_mantissa_bit_size = 53;
  std::size_t floating_point_exponent_bit_size = 11;

  std::size_t fixed_point_bit_size = 64;
  std::size_t fixed_point_fraction_bit_size = 16;

  double sensitivity = 1;
  // double scale = 0.01;
  // long double failure_probability = standard_failure_probability;

  std::vector<double> fD_vector = rand_range_double_vector(0, 1, number_of_simd);
  std::vector<std::uint64_t> dummy_noise_vector =
      rand_range_integer_vector<std::uint64_t>(0, 1, number_of_simd);

  em::ShareWrapper share_input_fD;
  em::ShareWrapper share_input_dummy_noise;

  if (protocol == encrypto::motion::MpcProtocol::kBooleanGmw) {
    share_input_fD =
        party->In<em::MpcProtocol::kBooleanGmw>(em::ToInput<double, std::true_type>(fD_vector), 0);
    share_input_dummy_noise =
        party->In<em::MpcProtocol::kBooleanGmw>(em::ToInput<std::uint64_t>(dummy_noise_vector), 0);
  } else if (protocol == encrypto::motion::MpcProtocol::kGarbledCircuit) {
    share_input_fD = party->In<em::MpcProtocol::kGarbledCircuit>(
        em::ToInput<double, std::true_type>(fD_vector), 0);
    share_input_dummy_noise = party->In<em::MpcProtocol::kGarbledCircuit>(
        em::ToInput<std::uint64_t>(dummy_noise_vector), 0);
  } else if (protocol == encrypto::motion::MpcProtocol::kBmr) {
    share_input_fD =
        party->In<em::MpcProtocol::kBmr>(em::ToInput<double, std::true_type>(fD_vector), 0);
    share_input_dummy_noise =
        party->In<em::MpcProtocol::kBmr>(em::ToInput<std::uint64_t>(dummy_noise_vector), 0);
  } else {
    throw std::invalid_argument("Unknown operation type");
  }

  em::SecureDiscreteLaplaceMechanismCKS secure_discrete_laplace_mechanism_CKS =
      em::SecureDiscreteLaplaceMechanismCKS(share_input_fD);

  // only for debug
  double scale = 0.135;

  std::cout<<"failure_probability: "<<failure_probability<<std::endl;

  secure_discrete_laplace_mechanism_CKS.ParameterSetup(sensitivity, scale, number_of_simd,
                                                       failure_probability, fixed_point_bit_size,
                                                       fixed_point_fraction_bit_size);

  // =================================================================

  switch (operation_type) {
    case em::DPMechanismType::
        kDiscreteLaplaceMechanismCKS_FL32DiscreteLaplace_noise_generation_naive: {
      secure_discrete_laplace_mechanism_CKS.FL32DiscreteLaplaceNoiseGeneration_naive();
      break;
    }
    case em::DPMechanismType::
        kDiscreteLaplaceMechanismCKS_FL32DiscreteLaplace_noise_generation_optimized: {
      secure_discrete_laplace_mechanism_CKS.FL32DiscreteLaplaceNoiseGeneration_optimized();
      break;
    }
    case em::DPMechanismType::kDiscreteLaplaceMechanismCKS_FL32DiscreteLaplace_perturbation: {
      em::SecureSignedInteger(share_input_fD) + em::SecureSignedInteger(share_input_dummy_noise);
      break;
    }
    case em::DPMechanismType::
        kDiscreteLaplaceMechanismCKS_FL64DiscreteLaplace_noise_generation_naive: {
      secure_discrete_laplace_mechanism_CKS.FL64DiscreteLaplaceNoiseGeneration_naive();
      break;
    }
    case em::DPMechanismType::
        kDiscreteLaplaceMechanismCKS_FL64DiscreteLaplace_noise_generation_optimized: {
      secure_discrete_laplace_mechanism_CKS.FL64DiscreteLaplaceNoiseGeneration_optimized();
      break;
    }
    case em::DPMechanismType::kDiscreteLaplaceMechanismCKS_FL64DiscreteLaplace_perturbation: {
      em::SecureSignedInteger(share_input_fD) + em::SecureSignedInteger(share_input_dummy_noise);
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