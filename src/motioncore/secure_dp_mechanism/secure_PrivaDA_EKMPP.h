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
#include "utility/MOTION_dp_mechanism_helper/discrete_gaussian_mechanism.h"
#include "utility/MOTION_dp_mechanism_helper/dp_mechanism_helper.h"

namespace encrypto::motion {

class Logger;

class SecureFixedPointCircuitCBMC;
class SecureUnsignedInteger;
class SecureFloatingPointCircuitABY;
class SecurePrivaDA;

// reference: Differentially Private Data Aggregation with Optimal Utility
// ! note: the Laplace random variable sampling algorithm in this paper is not secure, only for
// benchmarking purposes

class SecurePrivaDA {
 public:
  using T = std::uint64_t;
  using IntType = std::uint64_t;
  using IntType_int = std::int64_t;
  std::size_t IntType_size = sizeof(IntType) * 8;

  SecurePrivaDA() = default;

  SecurePrivaDA(const SecurePrivaDA& other) : SecurePrivaDA(*other.fD_) {}

  SecurePrivaDA(SecurePrivaDA&& other) : SecurePrivaDA(std::move(*other.fD_)) {
    other.fD_->Get().reset();
  }

  SecurePrivaDA(const ShareWrapper& other) : SecurePrivaDA(*other) {}

  SecurePrivaDA(ShareWrapper&& other) : SecurePrivaDA(std::move(*other)) { other.Get().reset(); }

  SecurePrivaDA(const SharePointer& other);

  SecurePrivaDA(SharePointer&& other);

  SecurePrivaDA& operator=(const SecurePrivaDA& other) {
    this->fD_ = other.fD_;
    this->logger_ = other.logger_;
    return *this;
  }

  SecurePrivaDA& operator=(SecurePrivaDA&& other) {
    this->fD_ = std::move(other.fD_);
    this->logger_ = std::move(other.logger_);
    return *this;
  }

  ShareWrapper& Get() { return *noisy_fD_; }
  const ShareWrapper& Get() const { return *noisy_fD_; }
  ShareWrapper& operator->() { return *noisy_fD_; }
  const ShareWrapper& operator->() const { return *noisy_fD_; }

  // satisfy epsilon-DP
  void ParameterSetup(double sensitivity_l1, double epsilon, std::size_t num_of_simd_lap_dlap,
                      std::size_t fixed_point_bit_size = 64,
                      std::size_t fixed_point_fraction_bit_size = 16);

  // ==============================================================
  // generate Laplace noise
  // sample from Laplace distribution with PDF: Lap(x|lambda) = 1/(2*lambda) * e^(-|x|/lambda)
  // ! Note that the generated Laplace random variable is not secure regarding differential privacy,
  // it can be attacked by paper (On Signiﬁcance of the Least Signiﬁcant Bits For Diﬀerential
  // Privacy)
  // ==============================================================
  // 32-bit floating point version
  SecureFloatingPointCircuitABY FL32LaplaceNoiseAddition();
  SecureFloatingPointCircuitABY FL32LaplaceNoiseGeneration();
  SecureFloatingPointCircuitABY FL32LaplaceNoiseGeneration(
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_rx,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_ry);

  //============================================================================
  // 64-bit floating point version
  SecureFloatingPointCircuitABY FL64LaplaceNoiseAddition();
  SecureFloatingPointCircuitABY FL64LaplaceNoiseGeneration();
  SecureFloatingPointCircuitABY FL64LaplaceNoiseGeneration(
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_rx,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_ry);

  //============================================================================
  // fixed-point version
  SecureFixedPointCircuitCBMC FxLaplaceNoiseAddition();
  SecureFixedPointCircuitCBMC FxLaplaceNoiseGeneration();
  SecureFixedPointCircuitCBMC FxLaplaceNoiseGeneration(
      const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_rx,
      const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_ry);

  //============================================================================
  // generate discrete Laplace noise
  // ! the security of the generated discrete Laplace noise is not proved
  // sample from discrete Laplace distribution with PDF: DLap(x|lambda) = (1-lambda)/(1+lambda) *
  // lambda^(|x|),
  // lambda = e^(-epsilon/l1_sensitivity) satisfy epsilon-DP
  //============================================================================
  // 32-bit floating point version
  SecureSignedInteger FL32DiscreteLaplaceNoiseAddition();
  SecureSignedInteger FL32DiscreteLaplaceNoiseGeneration();
  SecureSignedInteger FL32DiscreteLaplaceNoiseGeneration(
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_rx,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_ry);
  //============================================================================
  // 64-bit floating point version
  SecureSignedInteger FL64DiscreteLaplaceNoiseAddition();
  SecureSignedInteger FL64DiscreteLaplaceNoiseGeneration();
  SecureSignedInteger FL64DiscreteLaplaceNoiseGeneration(
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_rx,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_ry);
  //============================================================================
  // fixed-point version
  SecureSignedInteger FxDiscreteLaplaceNoiseAddition();
  SecureSignedInteger FxDiscreteLaplaceNoiseGeneration();
  SecureSignedInteger FxDiscreteLaplaceNoiseGeneration(
      const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_rx,
      const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_ry);
  //============================================================================

 public:
  double sensitivity_l1_ = 1;
  double epsilon_;

  double lambda_lap_;

  double lambda_dlap_;
  double alpha_dlap_;

  // number of noise to generate at the same time
  std::size_t num_of_simd_lap_;
  std::size_t num_of_simd_dlap_;

  std::size_t fixed_point_bit_size_ = 64;
  std::size_t fixed_point_fraction_bit_size_ = 16;

 private:
  // fD_ can be 32-bit floating point numbers, 64-bit floating point numbers or fixed point numbers
  std::shared_ptr<ShareWrapper> fD_{nullptr};
  std::shared_ptr<ShareWrapper> noisy_fD_{nullptr};
  std::shared_ptr<Logger> logger_{nullptr};
};
}  // namespace encrypto::motion