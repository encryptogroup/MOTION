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
#include "secure_type/secure_fixed_point_circuit_CBMC.h"
#include "secure_type/secure_floating_point_circuit_ABY.h"
#include "utility/MOTION_dp_mechanism_helper/discrete_gaussian_mechanism.h"
#include "utility/MOTION_dp_mechanism_helper/dp_mechanism_helper.h"

namespace encrypto::motion {

class Logger;

class SecureFixedPointCircuitCBMC;
class SecureUnsignedInteger;
class SecureFloatingPointCircuitABY;
class SecureGaussianMechanism;

// reference: CRYPTEN: Secure Multi-Party Computation Meets Machine Learning
// ! note: the Gaussian random variable sampling algorithm in this paper is not secure, only for
// benchmarking purposes
class SecureGaussianMechanism {
 public:
  // using T = std::uint64_t;

  SecureGaussianMechanism() = default;

  SecureGaussianMechanism(const SecureGaussianMechanism& other)
      : SecureGaussianMechanism(*other.fD_) {}

  SecureGaussianMechanism(SecureGaussianMechanism&& other)
      : SecureGaussianMechanism(std::move(*other.fD_)) {
    other.fD_->Get().reset();
  }

  SecureGaussianMechanism(const ShareWrapper& other) : SecureGaussianMechanism(*other) {}

  SecureGaussianMechanism(ShareWrapper&& other) : SecureGaussianMechanism(std::move(*other)) {
    other.Get().reset();
  }

  SecureGaussianMechanism(const SharePointer& other);

  SecureGaussianMechanism(SharePointer&& other);

  SecureGaussianMechanism& operator=(const SecureGaussianMechanism& other) {
    this->fD_ = other.fD_;
    this->logger_ = other.logger_;
    return *this;
  }

  SecureGaussianMechanism& operator=(SecureGaussianMechanism&& other) {
    this->fD_ = std::move(other.fD_);
    this->logger_ = std::move(other.logger_);
    return *this;
  }

  ShareWrapper& Get() { return *noisy_fD_; }
  const ShareWrapper& Get() const { return *noisy_fD_; }
  ShareWrapper& operator->() { return *noisy_fD_; }
  const ShareWrapper& operator->() const { return *noisy_fD_; }

  void ParameterSetup(double sensitivity_l1, double mu, double sigma, std::size_t num_of_simd_gauss,
                      std::size_t fixed_point_bit_size = 64,
                      std::size_t fixed_point_fraction_bit_size = 16);

  // ==============================================================
  // independent x1, x2 are sampled from Gauss(0,1),
  // x1 = sqrt(-2*ln(u1))*cos(2*pi*u2)
  // x2 = sqrt(-2*ln(u1))*sin(2*pi*u2)
  // y is sampled from Gauss(mu,sigma), y = sigma*x+mu,
  // ! as discussed in paper (Are We There Yet? Timing and Floating-Point Attacks on Differential
  // Privacy Systems), to (slightly) mitigate the attack in above paper, we discard x2 and only use
  // x1 as noise, however, this still suffer from above attacks
  // ==============================================================
  // 32-bit floating point version
  SecureFloatingPointCircuitABY FL32GaussianNoiseAddition();
  SecureFloatingPointCircuitABY FL32GaussianNoiseGeneration();
  SecureFloatingPointCircuitABY FL32GaussianNoiseGeneration(
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_u1,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_u2);
  //============================================================================
  // 64-bit floating point version
  SecureFloatingPointCircuitABY FL64GaussianNoiseAddition();
  SecureFloatingPointCircuitABY FL64GaussianNoiseGeneration();
  SecureFloatingPointCircuitABY FL64GaussianNoiseGeneration(
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_u1,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_u2);
  //============================================================================
  // fixed-point version
  SecureFixedPointCircuitCBMC FxGaussianNoiseAddition();
  SecureFixedPointCircuitCBMC FxGaussianNoiseGeneration();
  SecureFixedPointCircuitCBMC FxGaussianNoiseGeneration(
      const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_u1,
      const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_u2);
  //============================================================================

 public:
  double sensitivity_l1_ = 1;
  double epsilon_;
  double delta_;

  double mu_;
  double sigma_;

  // number of discrete Gaussian noise to generate at the same time
  std::size_t num_of_simd_gauss_;

  std::size_t fixed_point_bit_size_ = 64;
  std::size_t fixed_point_fraction_bit_size_ = 16;

 private:
  // fD_ can be 32-bit floating point numbers, 64-bit floating point numbers or fixed point numbers
  std::shared_ptr<ShareWrapper> fD_{nullptr};
  std::shared_ptr<ShareWrapper> noisy_fD_{nullptr};
  std::shared_ptr<Logger> logger_{nullptr};
};
}  // namespace encrypto::motion