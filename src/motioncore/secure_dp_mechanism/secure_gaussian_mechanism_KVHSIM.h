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
#include "secure_type/secure_floating_point32_agmw_ABZS.h"
#include "secure_type/secure_floating_point64_agmw_ABZS.h"
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

  // void ParameterSetup(double sensitivity_l1, double epsilon);

  // satisfy (epsilon, sigma)-DP
  void ParameterSetup(double sensitivity_l1, double epsilon, double delta,
                      std::size_t num_of_simd_gauss, std::size_t fixed_point_bit_size = 64,
                      std::size_t fixed_point_fraction_bit_size = 16);

  // ==============================================================
  // 32-bit floating point version
  SecureFloatingPointCircuitABY FL32GaussianNoiseAddition();

  SecureFloatingPointCircuitABY FL32GaussianNoiseGeneration();

  // sample from Gaussian distribution with PDF: Gau(x|mu,sigma) =
  // 1/(sigma*sqrt(2*pi))*e^(-0.5*((x-mu)/sigma)^2) ! Note that the generated Gaussian random
  // variable is not secure regarding differential privacy, it can be attacked by paper (On
  // Signiﬁcance of the Least Signiﬁcant Bits For Differential Privacy)
  SecureFloatingPointCircuitABY FL32GaussianNoiseGeneration(
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_u1,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_u2);

  //============================================================================
  // 64-bit floating point version
  SecureFloatingPointCircuitABY FL64GaussianNoiseAddition();

  SecureFloatingPointCircuitABY FL64GaussianNoiseGeneration();

  // sample from Gaussian distribution with PDF: Gau(x|mu,sigma) =
  // 1/(sigma*sqrt(2*pi))*e^(-0.5*((x-mu)/sigma)^2) ! Note that the generated Gaussian random
  // variable is not secure regarding differential privacy, it can be attacked by paper (On
  // Signiﬁcance of the Least Signiﬁcant Bits For Differential Privacy)
  SecureFloatingPointCircuitABY FL64GaussianNoiseGeneration(
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_u1,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_u2);

  //============================================================================
  // fixed-point version
  SecureFixedPointCircuitCBMC FxGaussianNoiseAddition();

  SecureFixedPointCircuitCBMC FxGaussianNoiseGeneration();

  // TODO: implement cos in fixed-point
  // sample from Gaussian distribution with PDF: Gau(x|mu,sigma) =
  // 1/(sigma*sqrt(2*pi))*e^(-0.5*((x-mu)/sigma)^2) ! Note that the generated Gaussian random
  // variable is not secure regarding DP can be attacked by (On Significance of the Least
  // Significant Bits For Differential Privacy)
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
 // fD_ is 32-bit floating point number, 64-bit floating point number or fixed point number
  std::shared_ptr<ShareWrapper> fD_{nullptr};
  std::shared_ptr<ShareWrapper> noisy_fD_{nullptr};
  std::shared_ptr<Logger> logger_{nullptr};
};
}  // namespace encrypto::motion