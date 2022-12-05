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

#pragma once

#include "protocols/share_wrapper.h"
#include "secure_dp_mechanism/secure_discrete_laplace_mechanism_CKS.h"
#include "secure_dp_mechanism/secure_dp_mechanism_PrivaDA.h"
#include "secure_type/secure_floating_point32_agmw_ABZS.h"
#include "secure_type/secure_floating_point64_agmw_ABZS.h"
#include "secure_type/secure_floating_point_circuit_ABY.h"

#include "secure_dp_mechanism/secure_sampling_algorithm_naive.h"
#include "secure_dp_mechanism/secure_sampling_algorithm_optimized.h"

namespace encrypto::motion {

class Logger;

class SecureFixedPointCircuitCBMC;
class SecureUnsignedInteger;
class SecureFloatingPointCircuitABY;
class SecureDiscreteLaplaceMechanismCKS;
class SecureDPMechanism_PrivaDA;

class SecureSamplingAlgorithm_naive;
class SecureSamplingAlgorithm_optimized;

// reference:
// https://github.com/google/differential-privacy/blob/main/common_docs/Secure_Noise_Generation.pdf
// https://github.com/google/differential-privacy/blob/main/go/noise/laplace_noise.go

class SecureIntegerScalingLaplaceMechanism {
 public:
  using T = std::uint64_t;
  using T_int = std::int64_t;

  SecureIntegerScalingLaplaceMechanism() = default;

  SecureIntegerScalingLaplaceMechanism(const SecureIntegerScalingLaplaceMechanism& other)
      : SecureIntegerScalingLaplaceMechanism(*other.fD_) {}

  SecureIntegerScalingLaplaceMechanism(SecureIntegerScalingLaplaceMechanism&& other)
      : SecureIntegerScalingLaplaceMechanism(std::move(*other.fD_)) {
    other.fD_->Get().reset();
  }

  SecureIntegerScalingLaplaceMechanism(const ShareWrapper& other)
      : SecureIntegerScalingLaplaceMechanism(*other) {}

  SecureIntegerScalingLaplaceMechanism(ShareWrapper&& other)
      : SecureIntegerScalingLaplaceMechanism(std::move(*other)) {
    other.Get().reset();
  }

  SecureIntegerScalingLaplaceMechanism(const SharePointer& other);

  SecureIntegerScalingLaplaceMechanism(SharePointer&& other);

  SecureIntegerScalingLaplaceMechanism& operator=(
      const SecureIntegerScalingLaplaceMechanism& other) {
    this->fD_ = other.fD_;
    this->logger_ = other.logger_;
    return *this;
  }

  SecureIntegerScalingLaplaceMechanism& operator=(SecureIntegerScalingLaplaceMechanism&& other) {
    this->fD_ = std::move(other.fD_);
    this->logger_ = std::move(other.logger_);
    return *this;
  }

  ShareWrapper& Get() { return *noisy_fD_; }
  const ShareWrapper& Get() const { return *noisy_fD_; }
  ShareWrapper& operator->() { return *noisy_fD_; }
  const ShareWrapper& operator->() const { return *noisy_fD_; }

  // void ParameterSetup(double sensitivity_l1, double epsilon,
  //                     long double failure_probability = standard_failure_probability);

  void ParameterSetup(double sensitivity_l1, double epsilon, std::size_t num_of_simd_lap,
                      long double failure_probability = standard_failure_probability,
                      std::size_t fixed_point_bit_size = 64,
                      std::size_t fixed_point_fraction_bit_size = 16);

  // =================================================================================================
  // 32-bit floating point version
  // SecureFloatingPointCircuitABY FL32LaplaceNoiseAddition();

  SecureFloatingPointCircuitABY FL32LaplaceNoiseGeneration_naive();
  SecureFloatingPointCircuitABY FL32LaplaceNoiseGeneration_optimized();

  // =================================================================================================
  // 64-bit floating point version
  // SecureFloatingPointCircuitABY FL64LaplaceNoiseAddition();

  SecureFloatingPointCircuitABY FL64LaplaceNoiseGeneration_naive();
  SecureFloatingPointCircuitABY FL64LaplaceNoiseGeneration_optimized();

  // =================================================================================================
 public:
  double sensitivity_l1_ = 1;

  double epsilon_;
  long double resolution_r_;
  std::int64_t log2_resolution_r_;
  long double delta_r_;

  // k in [10, 45]
  long double pow2_k_ = std::exp2l(15);
  // long double pow2_k_ = std::exp2l(40);

  double lambda_;

  // guarantee the iteration terminate and fail with probability security_parameter
  long double failure_probability_requirement_;

  // number of laplace noise to generate at the same time
  std::size_t num_of_simd_lap_;

  std::size_t fixed_point_bit_size_ = 64;
  std::size_t fixed_point_fraction_bit_size_ = 16;

  // =================================================================
  // sample from a discrete Laplace(t) distribution
  // Returns integer x with Pr[x] = exp(-abs(x)/scale)*(exp(1/scale)-1)/(exp(1/scale)+1)
  // assumes scale>=0
  // finally rescale it to floating point representation
  // based on paper (The Discrete Gaussian for Differential
  // Privacy)
  double scale_;

  // =================================================================
  // // use discrete laplace distribution based on paper (Differentially Private Data Aggregation
  // with
  // // Optimal Utility)
  // std::size_t iteration_EKMPP_;
  // double lambda_dlap_;
  // double epsilon_dlap_;

 private:
  // fD_ is 64-bit floating point number
  // !NOTE: fD_ must be first round to multiply of power of two before secret sharing
  std::shared_ptr<ShareWrapper> fD_{nullptr};
  std::shared_ptr<ShareWrapper> noisy_fD_{nullptr};
  std::shared_ptr<Logger> logger_{nullptr};
};
}  // namespace encrypto::motion