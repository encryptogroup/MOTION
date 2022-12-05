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
// #include "secure_type/secure_floating_point32_agmw_ABZS.h"
// #include "secure_type/secure_floating_point64_agmw_ABZS.h"
#include "secure_type/secure_floating_point_circuit_ABY.h"
#include "utility/MOTION_dp_mechanism_helper/discrete_gaussian_mechanism.h"
#include "utility/MOTION_dp_mechanism_helper/dp_mechanism_helper.h"

#include "secure_dp_mechanism/secure_sampling_algorithm_naive.h"
#include "secure_dp_mechanism/secure_sampling_algorithm_optimized.h"

namespace encrypto::motion {

class Logger;

class SecureFixedPointCircuitCBMC;
class SecureUnsignedInteger;
class SecureFloatingPointCircuitABY;

class SecureSamplingAlgorithm_naive;
class SecureSamplingAlgorithm_optimized;

// reference: The Discrete Gaussian for Differential Privacy
// DLap(x | scale) = exp(-abs(x)/scale)*(exp(1/scale)-1)/(exp(1/scale)+1)

class SecureDiscreteLaplaceMechanismCKS {
 public:
  using T = std::uint64_t;
  using T_int = std::int64_t;
  using T_expand = __uint128_t;

  SecureDiscreteLaplaceMechanismCKS() = default;

  SecureDiscreteLaplaceMechanismCKS(const SecureDiscreteLaplaceMechanismCKS& other)
      : SecureDiscreteLaplaceMechanismCKS(*other.fD_) {}

  SecureDiscreteLaplaceMechanismCKS(SecureDiscreteLaplaceMechanismCKS&& other)
      : SecureDiscreteLaplaceMechanismCKS(std::move(*other.fD_)) {
    other.fD_->Get().reset();
  }

  SecureDiscreteLaplaceMechanismCKS(const ShareWrapper& other)
      : SecureDiscreteLaplaceMechanismCKS(*other) {}

  SecureDiscreteLaplaceMechanismCKS(ShareWrapper&& other)
      : SecureDiscreteLaplaceMechanismCKS(std::move(*other)) {
    other.Get().reset();
  }

  SecureDiscreteLaplaceMechanismCKS(const SharePointer& other);

  SecureDiscreteLaplaceMechanismCKS(SharePointer&& other);

  SecureDiscreteLaplaceMechanismCKS& operator=(const SecureDiscreteLaplaceMechanismCKS& other) {
    this->fD_ = other.fD_;
    this->logger_ = other.logger_;
    return *this;
  }

  SecureDiscreteLaplaceMechanismCKS& operator=(SecureDiscreteLaplaceMechanismCKS&& other) {
    this->fD_ = std::move(other.fD_);
    this->logger_ = std::move(other.logger_);
    return *this;
  }

  ShareWrapper& Get() { return *noisy_fD_; }
  const ShareWrapper& Get() const { return *noisy_fD_; }
  ShareWrapper& operator->() { return *noisy_fD_; }
  const ShareWrapper& operator->() const { return *noisy_fD_; }

  // void ParameterSetup(double sensitivity_l1, double scale,
  //                     long double failure_probability = standard_failure_probability);

  void ParameterSetup(double sensitivity_l1, double scale, std::size_t num_of_simd_dlap,
                      long double failure_probability = standard_failure_probability,
                      std::size_t fixed_point_bit_size = 64,
                      std::size_t fixed_point_fraction_bit_size = 16);

  //============================================================================
  // 32-bit floating point version
  // SecureSignedInteger FL32DiscreteLaplaceNoiseAddition();

  // ! naive version
  SecureSignedInteger FL32DiscreteLaplaceNoiseGeneration_naive();

  SecureSignedInteger FL32DiscreteLaplaceNoiseGeneration_naive(
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
      const ShareWrapper& random_unsigned_integer_boolean_gmw_gc_bmr_share,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample);

  SecureSignedInteger FL32DiscreteLaplaceNoiseGeneration_naive(
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample);

  // ! optimized version
  SecureSignedInteger FL32DiscreteLaplaceNoiseGeneration_optimized();
  SecureSignedInteger FL32DiscreteLaplaceNoiseGeneration_optimized(
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
      const ShareWrapper& random_unsigned_integer_boolean_gmw_share,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample);
  SecureSignedInteger FL32DiscreteLaplaceNoiseGeneration_optimized(
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample);
  //============================================================================
  // 64-bit floating point version
  // SecureSignedInteger FL64DiscreteLaplaceNoiseAddition();

  // ! naive version
  SecureSignedInteger FL64DiscreteLaplaceNoiseGeneration_naive();
  SecureSignedInteger FL64DiscreteLaplaceNoiseGeneration_naive(
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
      const ShareWrapper& random_unsigned_integer_boolean_gmw_gc_bmr_share,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample);
  SecureSignedInteger FL64DiscreteLaplaceNoiseGeneration_naive(
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample);

  // ! optimized version
  SecureSignedInteger FL64DiscreteLaplaceNoiseGeneration_optimized();
  SecureSignedInteger FL64DiscreteLaplaceNoiseGeneration_optimized(
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
      const ShareWrapper& random_unsigned_integer_boolean_gmw_share,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample);
  SecureSignedInteger FL64DiscreteLaplaceNoiseGeneration_optimized(
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample);

  //============================================================================

 public:
  double sensitivity_l1_ = 1;
  double scale_;

  T numerator_;
  T denominator_;
  std::size_t log2_denominator_;
  T upscale_factor_ = 1;

  // iterations for geometric distribution sampling
  double iteration_1_;
  double iteration_2_;

  // iterations for discrete laplace distribution sampling
  double iteration_3_;

  double minimum_total_iteration_;
  double minimum_total_MPC_time_;
  long double geometric_failure_probability_estimation_;
  long double discrete_laplace_failure_probability_estimation_;

  // guarantee the iteration terminate and fail with probability security_parameter
  long double failure_probability_requirement_;

  std::size_t num_of_simd_geo_;

  // number of discrete laplace noist to generate at the same time
  std::size_t num_of_simd_dlap_;
  std::size_t num_of_simd_total_;

  std::size_t fixed_point_bit_size_ = 64;
  std::size_t fixed_point_fraction_bit_size_ = 16;

 private:
  // fD_ is a 64-bit signed integer
  std::shared_ptr<ShareWrapper> fD_{nullptr};
  std::shared_ptr<ShareWrapper> noisy_fD_{nullptr};
  std::shared_ptr<Logger> logger_{nullptr};
};
}  // namespace encrypto::motion