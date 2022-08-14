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
#include "secure_type/secure_floating_point_circuit_ABY.h"
#include "utility/MOTION_dp_mechanism_helper/dp_mechanism_helper.h"
#include "utility/MOTION_dp_mechanism_helper/integer_scaling_mechanism.h"

namespace encrypto::motion {

class Logger;

class SecureFixedPointCircuitCBMC;
class SecureUnsignedInteger;
class SecureFloatingPointCircuitABY;

class SecureIntegerScalingGaussianMechanism {
 public:
  using T = std::uint64_t;

  SecureIntegerScalingGaussianMechanism() = default;

  SecureIntegerScalingGaussianMechanism(const SecureIntegerScalingGaussianMechanism& other)
      : SecureIntegerScalingGaussianMechanism(*other.fD_) {}

  SecureIntegerScalingGaussianMechanism(SecureIntegerScalingGaussianMechanism&& other)
      : SecureIntegerScalingGaussianMechanism(std::move(*other.fD_)) {
    other.fD_->Get().reset();
  }

  SecureIntegerScalingGaussianMechanism(const ShareWrapper& other)
      : SecureIntegerScalingGaussianMechanism(*other) {}

  SecureIntegerScalingGaussianMechanism(ShareWrapper&& other)
      : SecureIntegerScalingGaussianMechanism(std::move(*other)) {
    other.Get().reset();
  }

  SecureIntegerScalingGaussianMechanism(const SharePointer& other);

  SecureIntegerScalingGaussianMechanism(SharePointer&& other);

  SecureIntegerScalingGaussianMechanism& operator=(
      const SecureIntegerScalingGaussianMechanism& other) {
    this->fD_ = other.fD_;
    this->logger_ = other.logger_;
    return *this;
  }

  SecureIntegerScalingGaussianMechanism& operator=(SecureIntegerScalingGaussianMechanism&& other) {
    this->fD_ = std::move(other.fD_);
    this->logger_ = std::move(other.logger_);
    return *this;
  }

  ShareWrapper& Get() { return *noisy_fD_; }
  const ShareWrapper& Get() const { return *noisy_fD_; }
  ShareWrapper& operator->() { return *noisy_fD_; }
  const ShareWrapper& operator->() const { return *noisy_fD_; }

  void ParameterSetup(double sensitivity_l1, double sigma, std::size_t num_of_simd_gau,
                      long double fail_probability = standard_fail_probability);

// satisfy (epsilon,delta)-DP
  void ParameterSetup(double sensitivity_l1, double epsilon, double delta,
                      std::size_t num_of_simd_gau,
                      long double fail_probability = standard_fail_probability);

  // ============================================================
  // 64-bit floating point, 64/128-bit unsigned integer
  SecureFloatingPointCircuitABY FLGaussianNoiseAddition();
  SecureFloatingPointCircuitABY FLGaussianNoiseGeneration();
  SecureFloatingPointCircuitABY FLGaussianNoiseGeneration(
      const ShareWrapper& unsigned_integer_boolean_gmw_share_geometric_sample,
      const ShareWrapper& boolean_gmw_share_random_bits,
      const ShareWrapper& random_unsigned_integer_boolean_gmw_share,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share);
  // ============================================================

 public:
  double sensitivity_l1_ = 1;
  double resolution_r_;
  std::int64_t log2_resolution_r_;
  double sigma_;

  long double sqrtN_;
  T m_;

  double epsilon_;
  double delta_;

  // change based on query type
  std::int64_t sensitivity_l0_ = 1;
  double sensitivity_lInf_ = 6;

  // guarantee the iteration terminate and fail with probability security_parameter
  long double fail_probability_requirement_;

  // number of gaussian noise to generate at the same time
  std::size_t num_of_simd_gau_;

  std::size_t iteration_;
  long double total_fail_probability_;

  long double binomial_bound_ = std::exp2l(57);

 private:
  // fD_ is 64-bit floating point number
  // !NOTE: fD_ must be first round to multiply of power of two before secret sharing
  std::shared_ptr<ShareWrapper> fD_{nullptr};
  std::shared_ptr<ShareWrapper> noisy_fD_{nullptr};
  std::shared_ptr<Logger> logger_{nullptr};
};
}  // namespace encrypto::motion