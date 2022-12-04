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

#include "secure_dp_mechanism/secure_dp_mechanism_PrivaDA.h"
#include "base/backend.h"

namespace encrypto::motion {
SecureDPMechanism_PrivaDA::SecureDPMechanism_PrivaDA(
    const SharePointer& other)
    : fD_(std::make_unique<ShareWrapper>(other)),
      logger_(fD_.get()->Get()->GetRegister()->GetLogger()) {}

SecureDPMechanism_PrivaDA::SecureDPMechanism_PrivaDA(
    SharePointer&& other)
    : fD_(std::make_unique<ShareWrapper>(std::move(other))),
      logger_(fD_.get()->Get()->GetRegister()->GetLogger()) {}

// void SecureDPMechanism_PrivaDA::ParameterSetup(double sensitivity_l1, double
// epsilon) {
//   std::size_t num_of_simd_lap_dlap = fD_->Get()->GetNumberOfSimdValues();
//   ParameterSetup(sensitivity_l1, epsilon, num_of_simd_lap_dlap);
// }

void SecureDPMechanism_PrivaDA::ParameterSetup(
    double sensitivity_l1, double epsilon, std::size_t num_of_simd_lap_dlap,
    std::size_t fixed_point_bit_size, std::size_t fixed_point_fraction_bit_size) {
  assert(fD_->Get()->GetNumberOfSimdValues() == num_of_simd_lap_dlap);

  fixed_point_bit_size_ = fixed_point_bit_size;
  fixed_point_fraction_bit_size_ = fixed_point_fraction_bit_size;

  sensitivity_l1_ = sensitivity_l1;
  epsilon_ = epsilon;
  num_of_simd_lap_ = num_of_simd_lap_dlap;
  num_of_simd_dlap_ = num_of_simd_lap_dlap;

  lambda_lap_ = sensitivity_l1_ / epsilon_;
  lambda_dlap_ = std::exp(-epsilon_ / sensitivity_l1_);
  alpha_dlap_ = -sensitivity_l1_ / epsilon_;

  //   std::cout << "lambda_lap_: " << lambda_lap_ << std::endl;
  //   std::cout << "lambda_dlap_: " << lambda_dlap_ << std::endl;
  //   std::cout << "alpha_dlap_: " << alpha_dlap_ << std::endl;
}

//============================================================================
// 32-bit floating point version
SecureFloatingPointCircuitABY
SecureDPMechanism_PrivaDA::FL32LaplaceNoiseAddition() {
  SecureFloatingPointCircuitABY floating_point_noisy_fD =
      SecureFloatingPointCircuitABY(fD_->Get()) + FL32LaplaceNoiseGeneration();
  noisy_fD_ = std::make_unique<ShareWrapper>(floating_point_noisy_fD.Get().Get());
  return floating_point_noisy_fD;
}

SecureFloatingPointCircuitABY
SecureDPMechanism_PrivaDA::FL32LaplaceNoiseGeneration() {
  ShareWrapper random_bits_of_length_23_rx =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .GenerateRandomBooleanGmwBits(FLOATINGPOINT32_MANTISSA_BITS, num_of_simd_lap_);
  ShareWrapper random_bits_of_length_126_rx =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .GenerateRandomBooleanGmwBits(FLOATINGPOINT32_EXPONENT_BIAS - 1, num_of_simd_lap_);
  ShareWrapper random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .UniformFloatingPoint32_0_1(random_bits_of_length_23_rx, random_bits_of_length_126_rx);

  ShareWrapper random_bits_of_length_23_ry =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .GenerateRandomBooleanGmwBits(FLOATINGPOINT32_MANTISSA_BITS, num_of_simd_lap_);
  ShareWrapper random_bits_of_length_126_ry =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .GenerateRandomBooleanGmwBits(FLOATINGPOINT32_EXPONENT_BIAS - 1, num_of_simd_lap_);
  ShareWrapper random_floating_point_0_1_boolean_gmw_gc_bmr_share_ry =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .UniformFloatingPoint32_0_1(random_bits_of_length_23_ry, random_bits_of_length_126_ry);

  return SecureSamplingAlgorithm_optimized(fD_->Get())
      .FL32LaplaceNoiseGeneration(random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx,
                                  random_floating_point_0_1_boolean_gmw_gc_bmr_share_ry,
                                  lambda_lap_);
}

SecureFloatingPointCircuitABY
SecureDPMechanism_PrivaDA::FL32LaplaceNoiseGeneration(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_gc_bmr_share_ry) {
  return SecureSamplingAlgorithm_optimized(fD_->Get())
      .FL32LaplaceNoiseGeneration(random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx,
                                  random_floating_point_0_1_boolean_gmw_gc_bmr_share_ry,
                                  lambda_lap_);
}

//============================================================================
// 64-bit floating point version
SecureFloatingPointCircuitABY
SecureDPMechanism_PrivaDA::FL64LaplaceNoiseAddition() {
  SecureFloatingPointCircuitABY floating_point_noisy_fD =
      SecureFloatingPointCircuitABY(fD_->Get()) + FL64LaplaceNoiseGeneration();
  noisy_fD_ = std::make_unique<ShareWrapper>(floating_point_noisy_fD.Get().Get());
  return floating_point_noisy_fD;
}

SecureFloatingPointCircuitABY
SecureDPMechanism_PrivaDA::FL64LaplaceNoiseGeneration() {
  ShareWrapper random_bits_of_length_52_rx =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .GenerateRandomBooleanGmwBits(FLOATINGPOINT_MANTISSA_BITS, num_of_simd_lap_);
  ShareWrapper random_bits_of_length_1022_rx =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .GenerateRandomBooleanGmwBits(FLOATINGPOINT_EXPONENT_BIAS - 1, num_of_simd_lap_);
  ShareWrapper random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .UniformFloatingPoint64_0_1(random_bits_of_length_52_rx, random_bits_of_length_1022_rx);

  ShareWrapper random_bits_of_length_52_ry =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .GenerateRandomBooleanGmwBits(FLOATINGPOINT_MANTISSA_BITS, num_of_simd_lap_);
  ShareWrapper random_bits_of_length_1022_ry =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .GenerateRandomBooleanGmwBits(FLOATINGPOINT_EXPONENT_BIAS - 1, num_of_simd_lap_);
  ShareWrapper random_floating_point_0_1_boolean_gmw_gc_bmr_share_ry =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .UniformFloatingPoint64_0_1(random_bits_of_length_52_ry, random_bits_of_length_1022_ry);

  return SecureSamplingAlgorithm_optimized(fD_->Get())
      .FL64LaplaceNoiseGeneration(random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx,
                                  random_floating_point_0_1_boolean_gmw_gc_bmr_share_ry,
                                  lambda_lap_);
}

SecureFloatingPointCircuitABY
SecureDPMechanism_PrivaDA::FL64LaplaceNoiseGeneration(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_gc_bmr_share_ry) {
  return SecureSamplingAlgorithm_optimized(fD_->Get())
      .FL64LaplaceNoiseGeneration(random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx,
                                  random_floating_point_0_1_boolean_gmw_gc_bmr_share_ry,
                                  lambda_lap_);
}

//============================================================================
// 32-bit floating point version

SecureSignedInteger SecureDPMechanism_PrivaDA::FL32DiscreteLaplaceNoiseAddition() {
  SecureSignedInteger signed_integer_noisy_fD =
      SecureSignedInteger(fD_->Get()) + FL32DiscreteLaplaceNoiseGeneration();
  noisy_fD_ = std::make_unique<ShareWrapper>(signed_integer_noisy_fD.Get().Get());
  return signed_integer_noisy_fD;
}

SecureSignedInteger
SecureDPMechanism_PrivaDA::FL32DiscreteLaplaceNoiseGeneration() {
  ShareWrapper random_bits_of_length_23_rx =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .GenerateRandomBooleanGmwBits(23, num_of_simd_dlap_);
  ShareWrapper random_bits_of_length_126_rx =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .GenerateRandomBooleanGmwBits(126, num_of_simd_dlap_);
  ShareWrapper random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .UniformFloatingPoint32_0_1(random_bits_of_length_23_rx, random_bits_of_length_126_rx);

  ShareWrapper random_bits_of_length_23_ry =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .GenerateRandomBooleanGmwBits(23, num_of_simd_dlap_);
  ShareWrapper random_bits_of_length_126_ry =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .GenerateRandomBooleanGmwBits(126, num_of_simd_dlap_);
  ShareWrapper random_floating_point_0_1_boolean_gmw_gc_bmr_share_ry =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .UniformFloatingPoint32_0_1(random_bits_of_length_23_ry, random_bits_of_length_126_ry);

  return SecureSamplingAlgorithm_optimized(fD_->Get())
      .FL32DiscreteLaplaceNoiseGeneration<IntType>(
          random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx,
          random_floating_point_0_1_boolean_gmw_gc_bmr_share_ry, alpha_dlap_);
}

SecureSignedInteger SecureDPMechanism_PrivaDA::FL32DiscreteLaplaceNoiseGeneration(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_gc_bmr_share_ry) {
  return SecureSamplingAlgorithm_optimized(fD_->Get())
      .FL32DiscreteLaplaceNoiseGeneration<IntType>(
          random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx,
          random_floating_point_0_1_boolean_gmw_gc_bmr_share_ry, alpha_dlap_);
}

//============================================================================
// 64-bit floating point version
SecureSignedInteger SecureDPMechanism_PrivaDA::FL64DiscreteLaplaceNoiseAddition() {
  SecureSignedInteger signed_integer_noisy_fD =
      SecureSignedInteger(fD_->Get()) + FL64DiscreteLaplaceNoiseGeneration();
  noisy_fD_ = std::make_unique<ShareWrapper>(signed_integer_noisy_fD.Get().Get());
  return signed_integer_noisy_fD;
}

SecureSignedInteger
SecureDPMechanism_PrivaDA::FL64DiscreteLaplaceNoiseGeneration() {
  ShareWrapper random_bits_of_length_52_rx =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .GenerateRandomBooleanGmwBits(52, num_of_simd_dlap_);
  ShareWrapper random_bits_of_length_1022_rx =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .GenerateRandomBooleanGmwBits(1022, num_of_simd_dlap_);
  ShareWrapper random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .UniformFloatingPoint64_0_1(random_bits_of_length_52_rx, random_bits_of_length_1022_rx);

  ShareWrapper random_bits_of_length_52_ry =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .GenerateRandomBooleanGmwBits(52, num_of_simd_dlap_);
  ShareWrapper random_bits_of_length_1022_ry =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .GenerateRandomBooleanGmwBits(1022, num_of_simd_dlap_);
  ShareWrapper random_floating_point_0_1_boolean_gmw_gc_bmr_share_ry =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .UniformFloatingPoint64_0_1(random_bits_of_length_52_ry, random_bits_of_length_1022_ry);

  return SecureSamplingAlgorithm_optimized(fD_->Get())
      .FL64DiscreteLaplaceNoiseGeneration<IntType>(
          random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx,
          random_floating_point_0_1_boolean_gmw_gc_bmr_share_ry, alpha_dlap_);
}

SecureSignedInteger SecureDPMechanism_PrivaDA::FL64DiscreteLaplaceNoiseGeneration(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_gc_bmr_share_ry) {
  return SecureSamplingAlgorithm_optimized(fD_->Get())
      .FL64DiscreteLaplaceNoiseGeneration<IntType>(
          random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx,
          random_floating_point_0_1_boolean_gmw_gc_bmr_share_ry, alpha_dlap_);
}

}  // namespace encrypto::motion