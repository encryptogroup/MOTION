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

#include "secure_dp_mechanism/secure_discrete_gaussian_mechanism_CKS.h"
#include "secure_dp_mechanism/secure_dp_mechanism_helper.h"
#include "base/backend.h"

namespace encrypto::motion {

SecureDiscreteGaussianMechanismCKS::SecureDiscreteGaussianMechanismCKS(const SharePointer& other)
    : fD_(std::make_unique<ShareWrapper>(other)),
      logger_(fD_.get()->Get()->GetRegister()->GetLogger()) {}

SecureDiscreteGaussianMechanismCKS::SecureDiscreteGaussianMechanismCKS(SharePointer&& other)
    : fD_(std::make_unique<ShareWrapper>(std::move(other))),
      logger_(fD_.get()->Get()->GetRegister()->GetLogger()) {}

void SecureDiscreteGaussianMechanismCKS::ParameterSetup(double sensitivity_l1, double sigma,
                                                        std::size_t num_of_simd_dgau,
                                                        long double fail_probability,
                                                        std::size_t fixed_point_bit_size,
                                                        std::size_t fixed_point_fraction_bit_size) {
  //   std::cout << "SecureDiscreteGaussianMechanismCKS::ParameterSetup" << std::endl;
  //   std::cout << "sigma: " << sigma << std::endl;

  assert(fD_->Get()->GetNumberOfSimdValues() == num_of_simd_dgau);

  sensitivity_l1_ = sensitivity_l1;
  sigma_ = sigma;
  t_ = floorl(sigma_) + 1;

  fixed_point_bit_size_ = fixed_point_bit_size;
  fixed_point_fraction_bit_size_ = fixed_point_fraction_bit_size;

  fail_probability_requirement_ = fail_probability;

  num_of_simd_dgau_ = num_of_simd_dgau;

  // estimate the number of iterations required to satisfy the security parameter
  std::vector<long double> optimize_discrete_gaussian_distribution_EXP_iteration_result_vector =
      optimize_discrete_gaussian_distribution_EXP_iteration<T, T_int>(
          sigma_, fail_probability_requirement_);

  iteration_1_ = optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[0];
  iteration_2_ = optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[1];
  iteration_3_ = optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[2];
  iteration_4_ = optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[3];
  minimum_total_iteration_ = optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[4];
  minimum_total_MPC_time_ = optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[5];
  geometric_fail_probability_estimation_ =
      optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[6];
  discrete_laplace_fail_probability_estimation_ =
      optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[7];
  discrete_gaussian_fail_probability_estimation_ =
      optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[8];
  upscale_factor_ = optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[9];

  num_of_simd_geo_ = iteration_3_;
  num_of_simd_dlap_ = iteration_4_;
  num_of_simd_total_ = num_of_simd_geo_ * num_of_simd_dlap_ * num_of_simd_dgau_;

  //   std::cout << "discrete_gaussian_best_iteration_1: " << iteration_1_ << std::endl;
  //   std::cout << "discrete_gaussian_best_iteration_2: " << iteration_2_ << std::endl;
  //   std::cout << "discrete_gaussian_best_iteration_3: " << iteration_3_ << std::endl;
  //   std::cout << "discrete_gaussian_best_iteration_4: " << iteration_4_ << std::endl;
  //   std::cout << "minimum_total_iteration_: " << minimum_total_iteration_ << std::endl;
  //   std::cout << "minimum_total_MPC_time_: " << minimum_total_MPC_time_ << std::endl;
  //   std::cout << "geometric_fail_probability_estimation_: " <<
  //   geometric_fail_probability_estimation_
  //             << std::endl;
  //   std::cout << "discrete_laplace_fail_probability_estimation_: "
  //             << discrete_laplace_fail_probability_estimation_ << std::endl;
  //   std::cout << "discrete_laplace_fail_probability_estimation_: "
  //             << discrete_laplace_fail_probability_estimation_ << std::endl;
  //   std::cout << "upscale_factor_: " << upscale_factor_ << std::endl;

  //   std::cout << "num_of_simd_geo_: " << num_of_simd_geo_ << std::endl;
  //   std::cout << "num_of_simd_dlap_: " << num_of_simd_dlap_ << std::endl;
  //   std::cout << "num_of_simd_dgau_: " << num_of_simd_dgau_ << std::endl;
  //   std::cout << "num_of_simd_total_: " << num_of_simd_total_ << std::endl;
}

// =========================================================================
// 32-bit floating-point version
SecureSignedInteger SecureDiscreteGaussianMechanismCKS::FL32DiscreteGaussianNoiseAddition() {
  SecureSignedInteger signed_integer_noisy_fD =
      SecureSignedInteger(fD_->Get()) + FL32DiscreteGaussianNoiseGeneration();
  noisy_fD_ = std::make_unique<ShareWrapper>(signed_integer_noisy_fD.Get().Get());
  return signed_integer_noisy_fD;
}

SecureSignedInteger SecureDiscreteGaussianMechanismCKS::FL32DiscreteGaussianNoiseGeneration() {
  if (t_ != T(1)) {
    ShareWrapper random_bits_of_length_23_dlap =
        SecureDPMechanismHelper(*fD_).GenerateRandomBooleanGmwBits(
            FLOATINGPOINT32_MANTISSA_BITS, (iteration_1_ + iteration_2_) * num_of_simd_total_);
    ShareWrapper random_bits_of_length_126_dlap =
        SecureDPMechanismHelper(*fD_).GenerateRandomBooleanGmwBits(
            FLOATINGPOINT32_EXPONENT_BIAS - 1, (iteration_1_ + iteration_2_) * num_of_simd_total_);
    ShareWrapper random_floating_point_0_1_boolean_gmw_share_dlap =
        SecureDPMechanismHelper(*fD_).UniformFloatingPoint32_0_1(random_bits_of_length_23_dlap,
                                                                 random_bits_of_length_126_dlap);

    ShareWrapper random_unsigned_integer_boolean_gmw_share_dlap =
        SecureDPMechanismHelper(*fD_).GenerateRandomUnsignedInteger(
            T(t_), iteration_1_ * num_of_simd_total_);

    ShareWrapper boolean_gmw_share_bernoulli_sample_dlap =
        SecureDPMechanismHelper(*fD_).GenerateRandomBooleanGmwBits(1, num_of_simd_total_);

    ShareWrapper random_bits_of_length_23_dgau =
        SecureDPMechanismHelper(*fD_).GenerateRandomBooleanGmwBits(
            FLOATINGPOINT32_MANTISSA_BITS, (iteration_4_)*num_of_simd_dgau_);
    ShareWrapper random_bits_of_length_126_dgau =
        SecureDPMechanismHelper(*fD_).GenerateRandomBooleanGmwBits(
            FLOATINGPOINT32_EXPONENT_BIAS - 1, (iteration_4_)*num_of_simd_dgau_);
    ShareWrapper random_floating_point_0_1_boolean_gmw_share_dgau =
        SecureDPMechanismHelper(*fD_).UniformFloatingPoint32_0_1(random_bits_of_length_23_dgau,
                                                                 random_bits_of_length_126_dgau);

    SecureSignedInteger signed_integer_discrete_gaussian_noise =
        FL32DiscreteGaussianNoiseGeneration(random_floating_point_0_1_boolean_gmw_share_dlap,
                                            random_unsigned_integer_boolean_gmw_share_dlap,
                                            boolean_gmw_share_bernoulli_sample_dlap,
                                            random_floating_point_0_1_boolean_gmw_share_dgau);
    return signed_integer_discrete_gaussian_noise;

  } else {
    ShareWrapper random_bits_of_length_23_dlap =
        SecureDPMechanismHelper(*fD_).GenerateRandomBooleanGmwBits(
            FLOATINGPOINT32_MANTISSA_BITS, (iteration_2_)*num_of_simd_total_);
    ShareWrapper random_bits_of_length_126_dlap =
        SecureDPMechanismHelper(*fD_).GenerateRandomBooleanGmwBits(
            FLOATINGPOINT32_EXPONENT_BIAS - 1, (iteration_2_)*num_of_simd_total_);
    ShareWrapper random_floating_point_0_1_boolean_gmw_share_dlap =
        SecureDPMechanismHelper(*fD_).UniformFloatingPoint32_0_1(random_bits_of_length_23_dlap,
                                                                 random_bits_of_length_126_dlap);

    ShareWrapper boolean_gmw_share_bernoulli_sample_dlap =
        SecureDPMechanismHelper(*fD_).GenerateRandomBooleanGmwBits(1, num_of_simd_total_);

    ShareWrapper random_bits_of_length_23_dgau =
        SecureDPMechanismHelper(*fD_).GenerateRandomBooleanGmwBits(
            FLOATINGPOINT32_MANTISSA_BITS, (iteration_4_)*num_of_simd_dgau_);
    ShareWrapper random_bits_of_length_126_dgau =
        SecureDPMechanismHelper(*fD_).GenerateRandomBooleanGmwBits(
            FLOATINGPOINT32_EXPONENT_BIAS - 1, (iteration_4_)*num_of_simd_dgau_);
    ShareWrapper random_floating_point_0_1_boolean_gmw_share_dgau =
        SecureDPMechanismHelper(*fD_).UniformFloatingPoint32_0_1(random_bits_of_length_23_dgau,
                                                                 random_bits_of_length_126_dgau);

    SecureSignedInteger signed_integer_discrete_gaussian_noise =
        FL32DiscreteGaussianNoiseGeneration(random_floating_point_0_1_boolean_gmw_share_dlap,
                                            boolean_gmw_share_bernoulli_sample_dlap,
                                            random_floating_point_0_1_boolean_gmw_share_dgau);

    return signed_integer_discrete_gaussian_noise;
  }
}

SecureSignedInteger SecureDiscreteGaussianMechanismCKS::FL32DiscreteGaussianNoiseGeneration(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share_dlap,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau) {
  assert(t_ != 1);

  std::vector<double> sigma_vector(num_of_simd_dgau_, sigma_);

  std::vector<ShareWrapper> result_vector =
      SecureDPMechanismHelper(*fD_)
          .FLDiscreteGaussianDistribution<float, std::uint64_t, std::int64_t>(
              sigma_vector, random_floating_point_0_1_boolean_gmw_share_dlap,
              random_unsigned_integer_boolean_gmw_share_dlap,
              boolean_gmw_share_bernoulli_sample_dlap,
              random_floating_point_0_1_boolean_gmw_share_dgau, iteration_1_, iteration_2_,
              iteration_3_, iteration_4_, upscale_factor_);

  ShareWrapper signed_integer_boolean_gmw_share_discrete_gaussian_noise = result_vector[0];
  return SecureSignedInteger(signed_integer_boolean_gmw_share_discrete_gaussian_noise);
}

SecureSignedInteger SecureDiscreteGaussianMechanismCKS::FL32DiscreteGaussianNoiseGeneration(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau) {
  assert(t_ == 1);
  std::vector<double> sigma_vector(num_of_simd_dgau_, sigma_);

  std::vector<ShareWrapper> result_vector =
      SecureDPMechanismHelper(*fD_)
          .FLDiscreteGaussianDistribution<float, std::uint64_t, std::int64_t>(
              sigma_vector, random_floating_point_0_1_boolean_gmw_share_dlap,
              boolean_gmw_share_bernoulli_sample_dlap,
              random_floating_point_0_1_boolean_gmw_share_dgau, iteration_2_, iteration_3_,
              iteration_4_);

  ShareWrapper signed_integer_boolean_gmw_share_discrete_gaussian_noise = result_vector[0];

  return SecureSignedInteger(signed_integer_boolean_gmw_share_discrete_gaussian_noise);
}

// =================================================================
// 64-bit floating-point version
SecureSignedInteger SecureDiscreteGaussianMechanismCKS::FL64DiscreteGaussianNoiseAddition() {
  SecureSignedInteger signed_integer_noisy_fD =
      SecureSignedInteger(fD_->Get()) + FL64DiscreteGaussianNoiseGeneration();
  noisy_fD_ = std::make_unique<ShareWrapper>(signed_integer_noisy_fD.Get().Get());
  return signed_integer_noisy_fD;
}

SecureSignedInteger SecureDiscreteGaussianMechanismCKS::FL64DiscreteGaussianNoiseGeneration() {
  if (t_ != T(1)) {
    ShareWrapper random_bits_of_length_52_dlap =
        SecureDPMechanismHelper(*fD_).GenerateRandomBooleanGmwBits(
            FLOATINGPOINT_MANTISSA_BITS, (iteration_1_ + iteration_2_) * num_of_simd_total_);
    ShareWrapper random_bits_of_length_1022_dlap =
        SecureDPMechanismHelper(*fD_).GenerateRandomBooleanGmwBits(
            FLOATINGPOINT_EXPONENT_BIAS - 1, (iteration_1_ + iteration_2_) * num_of_simd_total_);
    ShareWrapper random_floating_point_0_1_boolean_gmw_share_dlap =
        SecureDPMechanismHelper(*fD_).UniformFloatingPoint64_0_1(random_bits_of_length_52_dlap,
                                                                 random_bits_of_length_1022_dlap);

    ShareWrapper random_unsigned_integer_boolean_gmw_share_dlap =
        SecureDPMechanismHelper(*fD_).GenerateRandomUnsignedInteger(
            T(t_), iteration_1_ * num_of_simd_total_);

    ShareWrapper boolean_gmw_share_bernoulli_sample_dlap =
        SecureDPMechanismHelper(*fD_).GenerateRandomBooleanGmwBits(1, num_of_simd_total_);

    ShareWrapper random_bits_of_length_52_dgau =
        SecureDPMechanismHelper(*fD_).GenerateRandomBooleanGmwBits(
            FLOATINGPOINT_MANTISSA_BITS, (iteration_4_)*num_of_simd_dgau_);
    ShareWrapper random_bits_of_length_1022_dgau =
        SecureDPMechanismHelper(*fD_).GenerateRandomBooleanGmwBits(
            FLOATINGPOINT_EXPONENT_BIAS - 1, (iteration_4_)*num_of_simd_dgau_);
    ShareWrapper random_floating_point_0_1_boolean_gmw_share_dgau =
        SecureDPMechanismHelper(*fD_).UniformFloatingPoint64_0_1(random_bits_of_length_52_dgau,
                                                                 random_bits_of_length_1022_dgau);

    SecureSignedInteger signed_integer_discrete_gaussian_noise =
        FL64DiscreteGaussianNoiseGeneration(random_floating_point_0_1_boolean_gmw_share_dlap,
                                            random_unsigned_integer_boolean_gmw_share_dlap,
                                            boolean_gmw_share_bernoulli_sample_dlap,
                                            random_floating_point_0_1_boolean_gmw_share_dgau);
    return signed_integer_discrete_gaussian_noise;

  } else {
    ShareWrapper random_bits_of_length_52_dlap =
        SecureDPMechanismHelper(*fD_).GenerateRandomBooleanGmwBits(
            FLOATINGPOINT_MANTISSA_BITS, (iteration_2_)*num_of_simd_total_);
    ShareWrapper random_bits_of_length_1022_dlap =
        SecureDPMechanismHelper(*fD_).GenerateRandomBooleanGmwBits(
            FLOATINGPOINT_EXPONENT_BIAS - 1, (iteration_2_)*num_of_simd_total_);
    ShareWrapper random_floating_point_0_1_boolean_gmw_share_dlap =
        SecureDPMechanismHelper(*fD_).UniformFloatingPoint64_0_1(random_bits_of_length_52_dlap,
                                                                 random_bits_of_length_1022_dlap);

    ShareWrapper boolean_gmw_share_bernoulli_sample_dlap =
        SecureDPMechanismHelper(*fD_).GenerateRandomBooleanGmwBits(1, num_of_simd_total_);

    ShareWrapper random_bits_of_length_52_dgau =
        SecureDPMechanismHelper(*fD_).GenerateRandomBooleanGmwBits(
            FLOATINGPOINT_MANTISSA_BITS, (iteration_4_)*num_of_simd_dgau_);
    ShareWrapper random_bits_of_length_1022_dgau =
        SecureDPMechanismHelper(*fD_).GenerateRandomBooleanGmwBits(
            FLOATINGPOINT_EXPONENT_BIAS - 1, (iteration_4_)*num_of_simd_dgau_);
    ShareWrapper random_floating_point_0_1_boolean_gmw_share_dgau =
        SecureDPMechanismHelper(*fD_).UniformFloatingPoint64_0_1(random_bits_of_length_52_dgau,
                                                                 random_bits_of_length_1022_dgau);

    SecureSignedInteger signed_integer_discrete_gaussian_noise =
        FL64DiscreteGaussianNoiseGeneration(random_floating_point_0_1_boolean_gmw_share_dlap,
                                            boolean_gmw_share_bernoulli_sample_dlap,
                                            random_floating_point_0_1_boolean_gmw_share_dgau);

    return signed_integer_discrete_gaussian_noise;
  }
}

SecureSignedInteger SecureDiscreteGaussianMechanismCKS::FL64DiscreteGaussianNoiseGeneration(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share_dlap,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau) {
  assert(t_ != 1);

  std::vector<double> sigma_vector(num_of_simd_dgau_, sigma_);

  std::vector<ShareWrapper> result_vector =
      SecureDPMechanismHelper(*fD_)
          .FLDiscreteGaussianDistribution<double, std::uint64_t, std::int64_t>(
              sigma_vector, random_floating_point_0_1_boolean_gmw_share_dlap,
              random_unsigned_integer_boolean_gmw_share_dlap,
              boolean_gmw_share_bernoulli_sample_dlap,
              random_floating_point_0_1_boolean_gmw_share_dgau, iteration_1_, iteration_2_,
              iteration_3_, iteration_4_, upscale_factor_);

  ShareWrapper signed_integer_boolean_gmw_share_discrete_gaussian_noise = result_vector[0];
  return SecureSignedInteger(signed_integer_boolean_gmw_share_discrete_gaussian_noise);
}

SecureSignedInteger SecureDiscreteGaussianMechanismCKS::FL64DiscreteGaussianNoiseGeneration(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau) {
  assert(t_ == 1);
  std::vector<double> sigma_vector(num_of_simd_dgau_, sigma_);

  std::vector<ShareWrapper> result_vector =
      SecureDPMechanismHelper(*fD_)
          .FLDiscreteGaussianDistribution<double, std::uint64_t, std::int64_t>(
              sigma_vector, random_floating_point_0_1_boolean_gmw_share_dlap,
              boolean_gmw_share_bernoulli_sample_dlap,
              random_floating_point_0_1_boolean_gmw_share_dgau, iteration_2_, iteration_3_,
              iteration_4_);

  ShareWrapper signed_integer_boolean_gmw_share_discrete_gaussian_noise = result_vector[0];

  return SecureSignedInteger(signed_integer_boolean_gmw_share_discrete_gaussian_noise);
}

// =========================================================================
// fixed-point version
SecureSignedInteger SecureDiscreteGaussianMechanismCKS::FxDiscreteGaussianNoiseAddition() {
  SecureSignedInteger signed_integer_noisy_fD =
      SecureSignedInteger(fD_->Get()) + FxDiscreteGaussianNoiseGeneration();
  noisy_fD_ = std::make_unique<ShareWrapper>(signed_integer_noisy_fD.Get().Get());
  return signed_integer_noisy_fD;
}

SecureSignedInteger SecureDiscreteGaussianMechanismCKS::FxDiscreteGaussianNoiseGeneration() {
  if (t_ != T(1)) {
    ShareWrapper random_bits_of_length_fixed_point_fraction_dlap =
        SecureDPMechanismHelper(*fD_).GenerateRandomBooleanGmwBits(
            fixed_point_fraction_bit_size_, (iteration_1_ + iteration_2_) * num_of_simd_total_);
    ShareWrapper random_fixed_point_0_1_boolean_gmw_share_dlap =
        SecureDPMechanismHelper(*fD_).UniformFixedPoint_0_1(
            random_bits_of_length_fixed_point_fraction_dlap, fixed_point_bit_size_);

    ShareWrapper random_unsigned_integer_boolean_gmw_share_dlap =
        SecureDPMechanismHelper(*fD_).GenerateRandomUnsignedInteger(
            T(t_), iteration_1_ * num_of_simd_total_);

    ShareWrapper boolean_gmw_share_bernoulli_sample_dlap =
        SecureDPMechanismHelper(*fD_).GenerateRandomBooleanGmwBits(1, num_of_simd_total_);

    ShareWrapper random_bits_of_length_fixed_point_fraction_dgau =
        SecureDPMechanismHelper(*fD_).GenerateRandomBooleanGmwBits(
            fixed_point_fraction_bit_size_, (iteration_4_)*num_of_simd_dgau_);
    ShareWrapper random_fixed_point_0_1_boolean_gmw_share_dgau =
        SecureDPMechanismHelper(*fD_).UniformFixedPoint_0_1(
            random_bits_of_length_fixed_point_fraction_dgau, fixed_point_bit_size_);

    SecureSignedInteger signed_integer_discrete_gaussian_noise = FxDiscreteGaussianNoiseGeneration(
        random_fixed_point_0_1_boolean_gmw_share_dlap,
        random_unsigned_integer_boolean_gmw_share_dlap, boolean_gmw_share_bernoulli_sample_dlap,
        random_fixed_point_0_1_boolean_gmw_share_dgau);
    return signed_integer_discrete_gaussian_noise;

  } else {
    ShareWrapper random_bits_of_length_fixed_point_fraction_dlap =
        SecureDPMechanismHelper(*fD_).GenerateRandomBooleanGmwBits(
            fixed_point_fraction_bit_size_, (iteration_2_)*num_of_simd_total_);
    ShareWrapper random_fixed_point_0_1_boolean_gmw_share_dlap =
        SecureDPMechanismHelper(*fD_).UniformFixedPoint_0_1(
            random_bits_of_length_fixed_point_fraction_dlap, fixed_point_bit_size_);

    ShareWrapper boolean_gmw_share_bernoulli_sample_dlap =
        SecureDPMechanismHelper(*fD_).GenerateRandomBooleanGmwBits(1, num_of_simd_total_);

    ShareWrapper random_bits_of_length_fixed_point_fraction_dgau =
        SecureDPMechanismHelper(*fD_).GenerateRandomBooleanGmwBits(
            fixed_point_fraction_bit_size_, (iteration_4_)*num_of_simd_dgau_);
    ShareWrapper random_fixed_point_0_1_boolean_gmw_share_dgau =
        SecureDPMechanismHelper(*fD_).UniformFixedPoint_0_1(
            random_bits_of_length_fixed_point_fraction_dgau, fixed_point_bit_size_);

    SecureSignedInteger signed_integer_discrete_gaussian_noise = FxDiscreteGaussianNoiseGeneration(
        random_fixed_point_0_1_boolean_gmw_share_dlap, boolean_gmw_share_bernoulli_sample_dlap,
        random_fixed_point_0_1_boolean_gmw_share_dgau);

    return signed_integer_discrete_gaussian_noise;
  }
}

SecureSignedInteger SecureDiscreteGaussianMechanismCKS::FxDiscreteGaussianNoiseGeneration(
    const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_dlap,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share_dlap,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
    const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_dgau) {
  assert(t_ != 1);

  std::vector<double> sigma_vector(num_of_simd_dgau_, sigma_);

  std::vector<ShareWrapper> result_vector =
      SecureDPMechanismHelper(*fD_)
          .FxDiscreteGaussianDistribution<double, std::uint64_t, std::int64_t>(
              sigma_vector, random_fixed_point_0_1_boolean_gmw_share_dlap,
              random_unsigned_integer_boolean_gmw_share_dlap,
              boolean_gmw_share_bernoulli_sample_dlap,
              random_fixed_point_0_1_boolean_gmw_share_dgau, iteration_1_, iteration_2_,
              iteration_3_, iteration_4_, upscale_factor_, fixed_point_fraction_bit_size_);

  ShareWrapper signed_integer_boolean_gmw_share_discrete_gaussian_noise = result_vector[0];
  return SecureSignedInteger(signed_integer_boolean_gmw_share_discrete_gaussian_noise);
}

SecureSignedInteger SecureDiscreteGaussianMechanismCKS::FxDiscreteGaussianNoiseGeneration(
    const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_dlap,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
    const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_dgau) {
  assert(t_ == 1);
  std::vector<double> sigma_vector(num_of_simd_dgau_, sigma_);

  std::vector<ShareWrapper> result_vector =
      SecureDPMechanismHelper(*fD_)
          .FxDiscreteGaussianDistribution<double, std::uint64_t, std::int64_t>(
              sigma_vector, random_fixed_point_0_1_boolean_gmw_share_dlap,
              boolean_gmw_share_bernoulli_sample_dlap,
              random_fixed_point_0_1_boolean_gmw_share_dgau, iteration_2_, iteration_3_,
              iteration_4_, fixed_point_fraction_bit_size_);

  ShareWrapper signed_integer_boolean_gmw_share_discrete_gaussian_noise = result_vector[0];

  return SecureSignedInteger(signed_integer_boolean_gmw_share_discrete_gaussian_noise);
}

}  // namespace encrypto::motion