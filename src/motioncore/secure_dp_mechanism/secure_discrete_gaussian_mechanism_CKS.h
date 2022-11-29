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
#include "secure_dp_mechanism/secure_laplace_discrete_laplace_mechanism_EKMPP.h"
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
class SecureLaplaceDiscreteLaplaceMechanismEKMPP;

// we use fixed-point, 32-bit floating-point and 64-bit floating-point,
// reference: The Discrete Gaussian for Differential Privacy
class SecureDiscreteGaussianMechanismCKS {
 public:
  using T = std::uint64_t;
  using T_int = std::int64_t;
  SecureDiscreteGaussianMechanismCKS() = default;

  SecureDiscreteGaussianMechanismCKS(const SecureDiscreteGaussianMechanismCKS& other)
      : SecureDiscreteGaussianMechanismCKS(*other.fD_) {}

  SecureDiscreteGaussianMechanismCKS(SecureDiscreteGaussianMechanismCKS&& other)
      : SecureDiscreteGaussianMechanismCKS(std::move(*other.fD_)) {
    other.fD_->Get().reset();
  }

  SecureDiscreteGaussianMechanismCKS(const ShareWrapper& other)
      : SecureDiscreteGaussianMechanismCKS(*other) {}

  SecureDiscreteGaussianMechanismCKS(ShareWrapper&& other)
      : SecureDiscreteGaussianMechanismCKS(std::move(*other)) {
    other.Get().reset();
  }

  SecureDiscreteGaussianMechanismCKS(const SharePointer& other);

  SecureDiscreteGaussianMechanismCKS(SharePointer&& other);

  SecureDiscreteGaussianMechanismCKS& operator=(const SecureDiscreteGaussianMechanismCKS& other) {
    this->fD_ = other.fD_;
    this->logger_ = other.logger_;
    return *this;
  }

  SecureDiscreteGaussianMechanismCKS& operator=(SecureDiscreteGaussianMechanismCKS&& other) {
    this->fD_ = std::move(other.fD_);
    this->logger_ = std::move(other.logger_);
    return *this;
  }

  ShareWrapper& Get() { return *noisy_fD_; }
  const ShareWrapper& Get() const { return *noisy_fD_; }
  ShareWrapper& operator->() { return *noisy_fD_; }
  const ShareWrapper& operator->() const { return *noisy_fD_; }

  // void ParameterSetup(double sensitivity_l1, double sigma,
  //                     long double failure_probability = standard_failure_probability);

  void ParameterSetup(double sensitivity_l1, double sigma, std::size_t num_of_simd_dgau,
                      long double failure_probability = standard_failure_probability,
                      std::size_t fixed_point_bit_size = 64,
                      std::size_t fixed_point_fraction_bit_size = 16);

  // =================================================================
  // 32-bit floating-point version
  SecureSignedInteger FL32DiscreteGaussianNoiseAddition();

  SecureSignedInteger FL32DiscreteGaussianNoiseGeneration();

  SecureSignedInteger FL32DiscreteGaussianNoiseGeneration(
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
      const ShareWrapper& random_unsigned_integer_boolean_gmw_share_dlap,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau);

  SecureSignedInteger FL32DiscreteGaussianNoiseGeneration(
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau);

  // =================================================================
  // 64-bit floating-point version
  SecureSignedInteger FL64DiscreteGaussianNoiseAddition();

  SecureSignedInteger FL64DiscreteGaussianNoiseGeneration();

  SecureSignedInteger FL64DiscreteGaussianNoiseGeneration(
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
      const ShareWrapper& random_unsigned_integer_boolean_gmw_share_dlap,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau);

  SecureSignedInteger FL64DiscreteGaussianNoiseGeneration(
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau);

  // =================================================================
  // fixed-point version
  SecureSignedInteger FxDiscreteGaussianNoiseAddition();

  SecureSignedInteger FxDiscreteGaussianNoiseGeneration();

  SecureSignedInteger FxDiscreteGaussianNoiseGeneration(
      const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_dlap,
      const ShareWrapper& random_unsigned_integer_boolean_gmw_share_dlap,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
      const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_dgau);

  SecureSignedInteger FxDiscreteGaussianNoiseGeneration(
      const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_dlap,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
      const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_dgau);

  // =================================================================
  // void ParameterSetup_with_DiscreteLaplaceEKMPP(double sensitivity_l1, double sigma,
  //                                          std::size_t num_of_simd_dgau,
  //                                          long double failure_probability =
  //                                          standard_failure_probability, std::size_t
  //                                          fixed_point_bit_size = 64, std::size_t
  //                                          fixed_point_fraction_bit_size = 16);

  // SecureSignedInteger FLDiscreteGaussianNoiseAddition_with_DiscreteLaplaceEKMPP();

  // SecureSignedInteger FLDiscreteGaussianNoiseGeneration_with_DiscreteLaplaceEKMPP();

  // SecureSignedInteger FLDiscreteGaussianNoiseGeneration_with_DiscreteLaplaceEKMPP(
  //     const ShareWrapper& boolean_gmw_share_discrete_laplace_sample,
  //     const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau);

  // =================================================================

  //   SecureSignedInteger FxDiscreteGaussianNoiseAddition_with_DiscreteLaplaceEKMPP();

  //   SecureSignedInteger FxDiscreteGaussianNoiseGeneration_with_DiscreteLaplaceEKMPP();

  //   SecureSignedInteger FxDiscreteGaussianNoiseGeneration_with_DiscreteLaplaceEKMPP(
  //       const ShareWrapper& boolean_gmw_share_discrete_laplace_sample,
  //       const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau);

  // =================================================================
 public:
  double sensitivity_l1_ = 1;
  double sigma_;
  double t_;

  // =================================================================
  // use discrete laplace distribution based on paper (The Discrete Gaussian for Differential
  // Privacy)
  T upscale_factor_;

  // iterations for geometric distribution sampling
  double iteration_1_;
  double iteration_2_;
  T numerator_;
  T denominator_;
  std::size_t log2_denominator_;

  // iterations for discrete laplace distribution sampling
  double iteration_3_;

  // iterations for discrete gaussian distribution sampling
  double iteration_4_;

  double minimum_total_iteration_;
  double minimum_total_MPC_time_;
  long double geometric_failure_probability_estimation_;
  long double discrete_laplace_failure_probability_estimation_;
  long double discrete_gaussian_failure_probability_estimation_;

  // guarantee the iteration terminate and fail with probability security_parameter
  long double failure_probability_requirement_;

  std::size_t num_of_simd_geo_;
  std::size_t num_of_simd_dlap_;

  // number of discrete gaussian noise to generate at a batch
  std::size_t num_of_simd_dgau_;
  std::size_t num_of_simd_total_;

  // =================================================================
  // // use discrete laplace distribution based on paper (Differentially Private Data Aggregation
  // with
  // // Optimal Utility)
  // std::size_t iteration_EKMPP_;
  // double lambda_dlap_;
  // double epsilon_dlap_;
  // =================================================================

  std::size_t fixed_point_bit_size_ = 64;
  std::size_t fixed_point_fraction_bit_size_ = 16;

 private:
  // fD_ is 64-bit signed integer
  std::shared_ptr<ShareWrapper> fD_{nullptr};
  std::shared_ptr<ShareWrapper> noisy_fD_{nullptr};
  std::shared_ptr<Logger> logger_{nullptr};
};
}  // namespace encrypto::motion