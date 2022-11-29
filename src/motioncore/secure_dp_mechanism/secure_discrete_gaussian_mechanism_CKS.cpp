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
#include "base/backend.h"

namespace encrypto::motion {

SecureDiscreteGaussianMechanismCKS::SecureDiscreteGaussianMechanismCKS(const SharePointer& other)
    : fD_(std::make_unique<ShareWrapper>(other)),
      logger_(fD_.get()->Get()->GetRegister()->GetLogger()) {}

SecureDiscreteGaussianMechanismCKS::SecureDiscreteGaussianMechanismCKS(SharePointer&& other)
    : fD_(std::make_unique<ShareWrapper>(std::move(other))),
      logger_(fD_.get()->Get()->GetRegister()->GetLogger()) {}

// void SecureDiscreteGaussianMechanismCKS::ParameterSetup(double sensitivity_l1, double sigma,
//                                                         long double failure_probability) {
//   num_of_simd_dgau_ = fD_->Get()->GetNumberOfSimdValues();
//   ParameterSetup(sensitivity_l1, sigma, num_of_simd_dgau_, failure_probability);
// }

void SecureDiscreteGaussianMechanismCKS::ParameterSetup(double sensitivity_l1, double sigma,
                                                        std::size_t num_of_simd_dgau,
                                                        long double failure_probability,
                                                        std::size_t fixed_point_bit_size,
                                                        std::size_t fixed_point_fraction_bit_size) {
  std::cout << "SecureDiscreteGaussianMechanismCKS::ParameterSetup" << std::endl;
  std::cout << "sigma: " << sigma << std::endl;

  assert(fD_->Get()->GetNumberOfSimdValues() == num_of_simd_dgau);

  sensitivity_l1_ = sensitivity_l1;
  sigma_ = sigma;
  t_ = floorl(sigma_) + 1;

  fixed_point_bit_size_ = fixed_point_bit_size;
  fixed_point_fraction_bit_size_ = fixed_point_fraction_bit_size;

  failure_probability_requirement_ = failure_probability;

  num_of_simd_dgau_ = num_of_simd_dgau;

  // estimate the number of iterations required to satisfy the security parameter
  DiscreteGaussianDistributionOptimizationStruct<T>
      optimize_discrete_gaussian_distribution_EXP_iteration_result_struct =
          optimize_discrete_gaussian_distribution_EXP_iteration<T, T_int>(
              sigma_, failure_probability_requirement_);

  iteration_1_ =
      optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.iteration_geo_1;
  iteration_2_ =
      optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.iteration_geo_2;
  iteration_3_ =
      optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.iteration_dlap_3;
  iteration_4_ =
      optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.iteration_dgauss_4;
  minimum_total_iteration_ =
      optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.minimum_total_iteration;
  minimum_total_MPC_time_ =
      optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.minimum_total_MPC_time;
  geometric_failure_probability_estimation_ =
      optimize_discrete_gaussian_distribution_EXP_iteration_result_struct
          .geometric_failure_probability_estimation;
  discrete_laplace_failure_probability_estimation_ =
      optimize_discrete_gaussian_distribution_EXP_iteration_result_struct
          .discrete_laplace_failure_probability_estimation;
  discrete_gaussian_failure_probability_estimation_ =
      optimize_discrete_gaussian_distribution_EXP_iteration_result_struct
          .discrete_gaussian_failure_probability_estimation;
  upscale_factor_ =
      optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.upscale_factor;

  numerator_ = optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.numerator;
  denominator_ = optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.denominator;
  log2_denominator_ =
      optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.log2_denominator;

  std::cout << "numerator_: " << numerator_ << std::endl;
  std::cout << "denominator_: " << denominator_ << std::endl;
  std::cout << "log2_denominator_: " << log2_denominator_ << std::endl;

  num_of_simd_geo_ = iteration_3_;
  num_of_simd_dlap_ = iteration_4_;
  num_of_simd_total_ = num_of_simd_geo_ * num_of_simd_dlap_ * num_of_simd_dgau_;

  std::cout << "discrete_gaussian_best_iteration_1: " << iteration_1_ << std::endl;
  std::cout << "discrete_gaussian_best_iteration_2: " << iteration_2_ << std::endl;
  std::cout << "discrete_gaussian_best_iteration_3: " << iteration_3_ << std::endl;
  std::cout << "discrete_gaussian_best_iteration_4: " << iteration_4_ << std::endl;
  std::cout << "minimum_total_iteration_: " << minimum_total_iteration_ << std::endl;
  std::cout << "minimum_total_MPC_time_: " << minimum_total_MPC_time_ << std::endl;
  std::cout << "geometric_failure_probability_estimation_: "
            << geometric_failure_probability_estimation_ << std::endl;
  std::cout << "discrete_laplace_failure_probability_estimation_: "
            << discrete_laplace_failure_probability_estimation_ << std::endl;
  std::cout << "discrete_laplace_failure_probability_estimation_: "
            << discrete_laplace_failure_probability_estimation_ << std::endl;
  std::cout << "upscale_factor_: " << upscale_factor_ << std::endl;

  std::cout << "num_of_simd_geo_: " << num_of_simd_geo_ << std::endl;
  std::cout << "num_of_simd_dlap_: " << num_of_simd_dlap_ << std::endl;
  std::cout << "num_of_simd_dgau_: " << num_of_simd_dgau_ << std::endl;
  std::cout << "num_of_simd_total_: " << num_of_simd_total_ << std::endl;
}

// =========================================================================
// 32-bit floating-point version
// SecureSignedInteger SecureDiscreteGaussianMechanismCKS::FL32DiscreteGaussianNoiseAddition() {
//   SecureSignedInteger signed_integer_noisy_fD =
//       SecureSignedInteger(fD_->Get()) + FL32DiscreteGaussianNoiseGeneration();
//   noisy_fD_ = std::make_unique<ShareWrapper>(signed_integer_noisy_fD.Get().Get());
//   return signed_integer_noisy_fD;
// }

// SecureSignedInteger SecureDiscreteGaussianMechanismCKS::FL32DiscreteGaussianNoiseGeneration() {
//   std::cout << "SecureDiscreteGaussianMechanismCKS::FL32DiscreteGaussianNoiseGeneration"
//             << std::endl;
//   if (t_ != T(1)) {
//     ShareWrapper random_bits_of_length_23_dlap = fD_->GenerateRandomBooleanGmwBits(
//         FLOATINGPOINT32_MANTISSA_BITS, (iteration_1_ + iteration_2_) * num_of_simd_total_);
//     ShareWrapper random_bits_of_length_126_dlap = fD_->GenerateRandomBooleanGmwBits(
//         FLOATINGPOINT32_EXPONENT_BIAS - 1, (iteration_1_ + iteration_2_) * num_of_simd_total_);
//     ShareWrapper random_floating_point_0_1_boolean_gmw_share_dlap = fD_->UniformFloatingPoint32_0_1(
//         random_bits_of_length_23_dlap, random_bits_of_length_126_dlap);

//     // ShareWrapper random_unsigned_integer_boolean_gmw_share_dlap =
//     //     fD_->GenerateRandomUnsignedIntegerBGMW(T(t_), iteration_1_ * num_of_simd_total_);

//     ShareWrapper random_unsigned_integer_boolean_gmw_share_dlap =
//         fD_->GenerateRandomUnsignedIntegerPow2<T>(log2_denominator_,
//                                                   iteration_1_ * num_of_simd_total_);

//     ShareWrapper boolean_gmw_share_bernoulli_sample_dlap =
//         fD_->GenerateRandomBooleanGmwBits(1, num_of_simd_total_);

//     ShareWrapper random_bits_of_length_23_dgau = fD_->GenerateRandomBooleanGmwBits(
//         FLOATINGPOINT32_MANTISSA_BITS, (iteration_4_)*num_of_simd_dgau_);
//     ShareWrapper random_bits_of_length_126_dgau = fD_->GenerateRandomBooleanGmwBits(
//         FLOATINGPOINT32_EXPONENT_BIAS - 1, (iteration_4_)*num_of_simd_dgau_);
//     ShareWrapper random_floating_point_0_1_boolean_gmw_share_dgau = fD_->UniformFloatingPoint32_0_1(
//         random_bits_of_length_23_dgau, random_bits_of_length_126_dgau);

//     SecureSignedInteger signed_integer_discrete_gaussian_noise =
//         FL32DiscreteGaussianNoiseGeneration(random_floating_point_0_1_boolean_gmw_share_dlap,
//                                             random_unsigned_integer_boolean_gmw_share_dlap,
//                                             boolean_gmw_share_bernoulli_sample_dlap,
//                                             random_floating_point_0_1_boolean_gmw_share_dgau);
//     return signed_integer_discrete_gaussian_noise;

//   } else {
//     ShareWrapper random_bits_of_length_23_dlap = fD_->GenerateRandomBooleanGmwBits(
//         FLOATINGPOINT32_MANTISSA_BITS, (iteration_2_)*num_of_simd_total_);
//     ShareWrapper random_bits_of_length_126_dlap = fD_->GenerateRandomBooleanGmwBits(
//         FLOATINGPOINT32_EXPONENT_BIAS - 1, (iteration_2_)*num_of_simd_total_);
//     ShareWrapper random_floating_point_0_1_boolean_gmw_share_dlap = fD_->UniformFloatingPoint32_0_1(
//         random_bits_of_length_23_dlap, random_bits_of_length_126_dlap);

//     ShareWrapper boolean_gmw_share_bernoulli_sample_dlap =
//         fD_->GenerateRandomBooleanGmwBits(1, num_of_simd_total_);

//     ShareWrapper random_bits_of_length_23_dgau = fD_->GenerateRandomBooleanGmwBits(
//         FLOATINGPOINT32_MANTISSA_BITS, (iteration_4_)*num_of_simd_dgau_);
//     ShareWrapper random_bits_of_length_126_dgau = fD_->GenerateRandomBooleanGmwBits(
//         FLOATINGPOINT32_EXPONENT_BIAS - 1, (iteration_4_)*num_of_simd_dgau_);
//     ShareWrapper random_floating_point_0_1_boolean_gmw_share_dgau = fD_->UniformFloatingPoint32_0_1(
//         random_bits_of_length_23_dgau, random_bits_of_length_126_dgau);

//     SecureSignedInteger signed_integer_discrete_gaussian_noise =
//         FL32DiscreteGaussianNoiseGeneration(random_floating_point_0_1_boolean_gmw_share_dlap,
//                                             boolean_gmw_share_bernoulli_sample_dlap,
//                                             random_floating_point_0_1_boolean_gmw_share_dgau);

//     return signed_integer_discrete_gaussian_noise;
//   }
// }

// SecureSignedInteger SecureDiscreteGaussianMechanismCKS::FL32DiscreteGaussianNoiseGeneration(
//     const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
//     const ShareWrapper& random_unsigned_integer_boolean_gmw_share_dlap,
//     const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
//     const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau) {
//   //   num_of_simd_dgau_ = fD_->Get()->GetNumberOfSimdValues();

//   assert(t_ != 1);

//   std::vector<double> sigma_vector(num_of_simd_dgau_, sigma_);

//   std::vector<ShareWrapper> result_vector =
//       fD_->FLDiscreteGaussianDistribution<float, std::uint64_t, std::int64_t>(
//           sigma_vector, random_floating_point_0_1_boolean_gmw_share_dlap,
//           random_unsigned_integer_boolean_gmw_share_dlap, boolean_gmw_share_bernoulli_sample_dlap,
//           random_floating_point_0_1_boolean_gmw_share_dgau, iteration_1_, iteration_2_,
//           iteration_3_, iteration_4_, upscale_factor_);

//   ShareWrapper signed_integer_boolean_gmw_share_discrete_gaussian_noise = result_vector[0];
//   return SecureSignedInteger(signed_integer_boolean_gmw_share_discrete_gaussian_noise);
// }

// SecureSignedInteger SecureDiscreteGaussianMechanismCKS::FL32DiscreteGaussianNoiseGeneration(
//     const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
//     const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
//     const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau) {
//   //   num_of_simd_dgau_ = fD_->Get()->GetNumberOfSimdValues();

//   assert(t_ == 1);
//   std::vector<double> sigma_vector(num_of_simd_dgau_, sigma_);

//   std::vector<ShareWrapper> result_vector =
//       fD_->FLDiscreteGaussianDistribution<float, std::uint64_t, std::int64_t>(
//           sigma_vector, random_floating_point_0_1_boolean_gmw_share_dlap,
//           boolean_gmw_share_bernoulli_sample_dlap, random_floating_point_0_1_boolean_gmw_share_dgau,
//           iteration_2_, iteration_3_, iteration_4_);

//   ShareWrapper signed_integer_boolean_gmw_share_discrete_gaussian_noise = result_vector[0];

//   return SecureSignedInteger(signed_integer_boolean_gmw_share_discrete_gaussian_noise);
// }

// // =================================================================
// // 64-bit floating-point version
// SecureSignedInteger SecureDiscreteGaussianMechanismCKS::FL64DiscreteGaussianNoiseAddition() {
//   SecureSignedInteger signed_integer_noisy_fD =
//       SecureSignedInteger(fD_->Get()) + FL64DiscreteGaussianNoiseGeneration();
//   noisy_fD_ = std::make_unique<ShareWrapper>(signed_integer_noisy_fD.Get().Get());
//   return signed_integer_noisy_fD;
// }

// SecureSignedInteger SecureDiscreteGaussianMechanismCKS::FL64DiscreteGaussianNoiseGeneration() {
//   std::cout << "SecureDiscreteGaussianMechanismCKS::FL64DiscreteGaussianNoiseGeneration"
//             << std::endl;
//   if (t_ != T(1)) {
//     ShareWrapper random_bits_of_length_52_dlap = fD_->GenerateRandomBooleanGmwBits(
//         FLOATINGPOINT_MANTISSA_BITS, (iteration_1_ + iteration_2_) * num_of_simd_total_);
//     ShareWrapper random_bits_of_length_1022_dlap = fD_->GenerateRandomBooleanGmwBits(
//         FLOATINGPOINT_EXPONENT_BIAS - 1, (iteration_1_ + iteration_2_) * num_of_simd_total_);
//     ShareWrapper random_floating_point_0_1_boolean_gmw_share_dlap = fD_->UniformFloatingPoint64_0_1(
//         random_bits_of_length_52_dlap, random_bits_of_length_1022_dlap);

//     // ShareWrapper random_unsigned_integer_boolean_gmw_share_dlap =
//     //     fD_->GenerateRandomUnsignedIntegerBGMW(T(t_), iteration_1_ * num_of_simd_total_);

//     ShareWrapper random_unsigned_integer_boolean_gmw_share_dlap =
//         fD_->GenerateRandomUnsignedIntegerPow2<T>(log2_denominator_,
//                                                   iteration_1_ * num_of_simd_total_);

//     ShareWrapper boolean_gmw_share_bernoulli_sample_dlap =
//         fD_->GenerateRandomBooleanGmwBits(1, num_of_simd_total_);

//     ShareWrapper random_bits_of_length_52_dgau = fD_->GenerateRandomBooleanGmwBits(
//         FLOATINGPOINT_MANTISSA_BITS, (iteration_4_)*num_of_simd_dgau_);
//     ShareWrapper random_bits_of_length_1022_dgau = fD_->GenerateRandomBooleanGmwBits(
//         FLOATINGPOINT_EXPONENT_BIAS - 1, (iteration_4_)*num_of_simd_dgau_);
//     ShareWrapper random_floating_point_0_1_boolean_gmw_share_dgau = fD_->UniformFloatingPoint64_0_1(
//         random_bits_of_length_52_dgau, random_bits_of_length_1022_dgau);

//     SecureSignedInteger signed_integer_discrete_gaussian_noise =
//         FL64DiscreteGaussianNoiseGeneration(random_floating_point_0_1_boolean_gmw_share_dlap,
//                                             random_unsigned_integer_boolean_gmw_share_dlap,
//                                             boolean_gmw_share_bernoulli_sample_dlap,
//                                             random_floating_point_0_1_boolean_gmw_share_dgau);
//     return signed_integer_discrete_gaussian_noise;

//   } else {
//     ShareWrapper random_bits_of_length_52_dlap = fD_->GenerateRandomBooleanGmwBits(
//         FLOATINGPOINT_MANTISSA_BITS, (iteration_2_)*num_of_simd_total_);
//     ShareWrapper random_bits_of_length_1022_dlap = fD_->GenerateRandomBooleanGmwBits(
//         FLOATINGPOINT_EXPONENT_BIAS - 1, (iteration_2_)*num_of_simd_total_);
//     ShareWrapper random_floating_point_0_1_boolean_gmw_share_dlap = fD_->UniformFloatingPoint64_0_1(
//         random_bits_of_length_52_dlap, random_bits_of_length_1022_dlap);

//     ShareWrapper boolean_gmw_share_bernoulli_sample_dlap =
//         fD_->GenerateRandomBooleanGmwBits(1, num_of_simd_total_);

//     ShareWrapper random_bits_of_length_52_dgau = fD_->GenerateRandomBooleanGmwBits(
//         FLOATINGPOINT_MANTISSA_BITS, (iteration_4_)*num_of_simd_dgau_);
//     ShareWrapper random_bits_of_length_1022_dgau = fD_->GenerateRandomBooleanGmwBits(
//         FLOATINGPOINT_EXPONENT_BIAS - 1, (iteration_4_)*num_of_simd_dgau_);
//     ShareWrapper random_floating_point_0_1_boolean_gmw_share_dgau = fD_->UniformFloatingPoint64_0_1(
//         random_bits_of_length_52_dgau, random_bits_of_length_1022_dgau);

//     SecureSignedInteger signed_integer_discrete_gaussian_noise =
//         FL64DiscreteGaussianNoiseGeneration(random_floating_point_0_1_boolean_gmw_share_dlap,
//                                             boolean_gmw_share_bernoulli_sample_dlap,
//                                             random_floating_point_0_1_boolean_gmw_share_dgau);

//     return signed_integer_discrete_gaussian_noise;
//   }
// }

// SecureSignedInteger SecureDiscreteGaussianMechanismCKS::FL64DiscreteGaussianNoiseGeneration(
//     const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
//     const ShareWrapper& random_unsigned_integer_boolean_gmw_share_dlap,
//     const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
//     const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau) {
//   //   num_of_simd_dgau_ = fD_->Get()->GetNumberOfSimdValues();

//   assert(t_ != 1);

//   std::vector<double> sigma_vector(num_of_simd_dgau_, sigma_);

//   std::vector<ShareWrapper> result_vector =
//       fD_->FLDiscreteGaussianDistribution<double, std::uint64_t, std::int64_t>(
//           sigma_vector, random_floating_point_0_1_boolean_gmw_share_dlap,
//           random_unsigned_integer_boolean_gmw_share_dlap, boolean_gmw_share_bernoulli_sample_dlap,
//           random_floating_point_0_1_boolean_gmw_share_dgau, iteration_1_, iteration_2_,
//           iteration_3_, iteration_4_, upscale_factor_);

//   ShareWrapper signed_integer_boolean_gmw_share_discrete_gaussian_noise = result_vector[0];
//   return SecureSignedInteger(signed_integer_boolean_gmw_share_discrete_gaussian_noise);
// }

// SecureSignedInteger SecureDiscreteGaussianMechanismCKS::FL64DiscreteGaussianNoiseGeneration(
//     const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
//     const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
//     const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau) {
//   //   num_of_simd_dgau_ = fD_->Get()->GetNumberOfSimdValues();

//   assert(t_ == 1);
//   std::vector<double> sigma_vector(num_of_simd_dgau_, sigma_);

//   std::vector<ShareWrapper> result_vector =
//       fD_->FLDiscreteGaussianDistribution<double, std::uint64_t, std::int64_t>(
//           sigma_vector, random_floating_point_0_1_boolean_gmw_share_dlap,
//           boolean_gmw_share_bernoulli_sample_dlap, random_floating_point_0_1_boolean_gmw_share_dgau,
//           iteration_2_, iteration_3_, iteration_4_);

//   ShareWrapper signed_integer_boolean_gmw_share_discrete_gaussian_noise = result_vector[0];

//   return SecureSignedInteger(signed_integer_boolean_gmw_share_discrete_gaussian_noise);
// }

// // =========================================================================
// // fixed-point version
// SecureSignedInteger SecureDiscreteGaussianMechanismCKS::FxDiscreteGaussianNoiseAddition() {
//   SecureSignedInteger signed_integer_noisy_fD =
//       SecureSignedInteger(fD_->Get()) + FxDiscreteGaussianNoiseGeneration();
//   noisy_fD_ = std::make_unique<ShareWrapper>(signed_integer_noisy_fD.Get().Get());
//   return signed_integer_noisy_fD;
// }

// SecureSignedInteger SecureDiscreteGaussianMechanismCKS::FxDiscreteGaussianNoiseGeneration() {
//   std::cout << "SecureDiscreteGaussianMechanismCKS::FxDiscreteGaussianNoiseGeneration" << std::endl;
//   if (t_ != T(1)) {
//     ShareWrapper random_bits_of_length_fixed_point_fraction_dlap =
//         fD_->GenerateRandomBooleanGmwBits(fixed_point_fraction_bit_size_,
//                                           (iteration_1_ + iteration_2_) * num_of_simd_total_);
//     ShareWrapper random_fixed_point_0_1_boolean_gmw_share_dlap = fD_->UniformFixedPoint_0_1(
//         random_bits_of_length_fixed_point_fraction_dlap, fixed_point_bit_size_);

//     // ShareWrapper random_unsigned_integer_boolean_gmw_share_dlap =
//     //     fD_->GenerateRandomUnsignedIntegerBGMW(T(t_), iteration_1_ * num_of_simd_total_);

//     ShareWrapper random_unsigned_integer_boolean_gmw_share_dlap =
//         fD_->GenerateRandomUnsignedIntegerPow2<T>(log2_denominator_,
//                                                   iteration_1_ * num_of_simd_total_);

//     ShareWrapper boolean_gmw_share_bernoulli_sample_dlap =
//         fD_->GenerateRandomBooleanGmwBits(1, num_of_simd_total_);

//     ShareWrapper random_bits_of_length_fixed_point_fraction_dgau =
//         fD_->GenerateRandomBooleanGmwBits(fixed_point_fraction_bit_size_,
//                                           (iteration_4_)*num_of_simd_dgau_);
//     ShareWrapper random_fixed_point_0_1_boolean_gmw_share_dgau = fD_->UniformFixedPoint_0_1(
//         random_bits_of_length_fixed_point_fraction_dgau, fixed_point_bit_size_);

//     SecureSignedInteger signed_integer_discrete_gaussian_noise = FxDiscreteGaussianNoiseGeneration(
//         random_fixed_point_0_1_boolean_gmw_share_dlap,
//         random_unsigned_integer_boolean_gmw_share_dlap, boolean_gmw_share_bernoulli_sample_dlap,
//         random_fixed_point_0_1_boolean_gmw_share_dgau);
//     return signed_integer_discrete_gaussian_noise;

//   } else {
//     ShareWrapper random_bits_of_length_fixed_point_fraction_dlap =
//         fD_->GenerateRandomBooleanGmwBits(fixed_point_fraction_bit_size_,
//                                           (iteration_2_)*num_of_simd_total_);
//     ShareWrapper random_fixed_point_0_1_boolean_gmw_share_dlap = fD_->UniformFixedPoint_0_1(
//         random_bits_of_length_fixed_point_fraction_dlap, fixed_point_bit_size_);

//     ShareWrapper boolean_gmw_share_bernoulli_sample_dlap =
//         fD_->GenerateRandomBooleanGmwBits(1, num_of_simd_total_);

//     ShareWrapper random_bits_of_length_fixed_point_fraction_dgau =
//         fD_->GenerateRandomBooleanGmwBits(fixed_point_fraction_bit_size_,
//                                           (iteration_4_)*num_of_simd_dgau_);
//     ShareWrapper random_fixed_point_0_1_boolean_gmw_share_dgau = fD_->UniformFixedPoint_0_1(
//         random_bits_of_length_fixed_point_fraction_dgau, fixed_point_bit_size_);

//     SecureSignedInteger signed_integer_discrete_gaussian_noise = FxDiscreteGaussianNoiseGeneration(
//         random_fixed_point_0_1_boolean_gmw_share_dlap, boolean_gmw_share_bernoulli_sample_dlap,
//         random_fixed_point_0_1_boolean_gmw_share_dgau);

//     return signed_integer_discrete_gaussian_noise;
//   }
// }

// SecureSignedInteger SecureDiscreteGaussianMechanismCKS::FxDiscreteGaussianNoiseGeneration(
//     const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_dlap,
//     const ShareWrapper& random_unsigned_integer_boolean_gmw_share_dlap,
//     const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
//     const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_dgau) {
//   //   num_of_simd_dgau_ = fD_->Get()->GetNumberOfSimdValues();

//   assert(t_ != 1);

//   std::vector<double> sigma_vector(num_of_simd_dgau_, sigma_);

//   std::vector<ShareWrapper> result_vector =
//       fD_->FxDiscreteGaussianDistribution<double, std::uint64_t, std::int64_t>(
//           sigma_vector, random_fixed_point_0_1_boolean_gmw_share_dlap,
//           random_unsigned_integer_boolean_gmw_share_dlap, boolean_gmw_share_bernoulli_sample_dlap,
//           random_fixed_point_0_1_boolean_gmw_share_dgau, iteration_1_, iteration_2_, iteration_3_,
//           iteration_4_, upscale_factor_, fixed_point_fraction_bit_size_);

//   ShareWrapper signed_integer_boolean_gmw_share_discrete_gaussian_noise = result_vector[0];
//   return SecureSignedInteger(signed_integer_boolean_gmw_share_discrete_gaussian_noise);
// }

// SecureSignedInteger SecureDiscreteGaussianMechanismCKS::FxDiscreteGaussianNoiseGeneration(
//     const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_dlap,
//     const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
//     const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_dgau) {
//   //   num_of_simd_dgau_ = fD_->Get()->GetNumberOfSimdValues();

//   assert(t_ == 1);
//   std::vector<double> sigma_vector(num_of_simd_dgau_, sigma_);

//   std::vector<ShareWrapper> result_vector =
//       fD_->FxDiscreteGaussianDistribution<double, std::uint64_t, std::int64_t>(
//           sigma_vector, random_fixed_point_0_1_boolean_gmw_share_dlap,
//           boolean_gmw_share_bernoulli_sample_dlap, random_fixed_point_0_1_boolean_gmw_share_dgau,
//           iteration_2_, iteration_3_, iteration_4_, fixed_point_fraction_bit_size_);

//   ShareWrapper signed_integer_boolean_gmw_share_discrete_gaussian_noise = result_vector[0];

//   return SecureSignedInteger(signed_integer_boolean_gmw_share_discrete_gaussian_noise);
// }

// ===============================================================
// remove later
// void SecureDiscreteGaussianMechanismCKS::ParameterSetup_with_DiscreteLaplaceEKMPP(
//     double sensitivity_l1, double sigma, std::size_t num_of_simd_dgau, long double
//     failure_probability, std::size_t fixed_point_bit_size, std::size_t
//     fixed_point_fraction_bit_size) {
//   std::cout << "SecureDiscreteGaussianMechanismCKS::ParameterSetup_with_DiscreteLaplaceEKMPP"
//             << std::endl;
//   std::cout << "sigma: " << sigma << std::endl;

//   sensitivity_l1_ = sensitivity_l1;
//   sigma_ = sigma;
//   t_ = floorl(sigma_) + 1;

//   epsilon_dlap_ = sensitivity_l1_ / t_;
//   std::cout << "epsilon_dlap_: " << epsilon_dlap_ << std::endl;

//   fixed_point_bit_size_ = fixed_point_bit_size;
//   fixed_point_fraction_bit_size_ = fixed_point_fraction_bit_size;

//   failure_probability_requirement_ = failure_probability;
//   lambda_dlap_ = std::exp(-1.0 / t_);
//   std::cout << "lambda_dlap_: " << lambda_dlap_ << std::endl;

//   num_of_simd_dgau_ = num_of_simd_dgau;

//   // estimate the number of iterations required to satisfy the security parameter
//   std::vector<long double>
//       optimize_discrete_gaussian_distribution_EXP_with_discrete_laplace_EKMPP_iteration_result_vector
//       =
//           optimize_discrete_gaussian_distribution_EXP_with_discrete_laplace_EKMPP_iteration<T,
//                                                                                             T_int>(
//               sigma_, failure_probability_requirement_);

//   iteration_EKMPP_ =
//       optimize_discrete_gaussian_distribution_EXP_with_discrete_laplace_EKMPP_iteration_result_vector
//           [0];
//   total_iteration_ =
//       optimize_discrete_gaussian_distribution_EXP_with_discrete_laplace_EKMPP_iteration_result_vector
//           [1];
//   total_failure_probability_ =
//       optimize_discrete_gaussian_distribution_EXP_with_discrete_laplace_EKMPP_iteration_result_vector
//           [3];

//   std::cout << "iteration_EKMPP_: " << iteration_EKMPP_ << std::endl;
//   std::cout << "total_iteration_: " << total_iteration_ << std::endl;

//   std::cout << "total_failure_probability_: " << total_failure_probability_ << std::endl;
// }

// SecureSignedInteger
// SecureDiscreteGaussianMechanismCKS::FLDiscreteGaussianNoiseAddition_with_DiscreteLaplaceEKMPP() {
//   SecureSignedInteger signed_integer_noisy_fD =
//       SecureSignedInteger(fD_->Get()) +
//       FLDiscreteGaussianNoiseGeneration_with_DiscreteLaplaceEKMPP();
//   noisy_fD_ = std::make_unique<ShareWrapper>(signed_integer_noisy_fD.Get().Get());
//   return signed_integer_noisy_fD;
// }

// SecureSignedInteger
// SecureDiscreteGaussianMechanismCKS::FLDiscreteGaussianNoiseGeneration_with_DiscreteLaplaceEKMPP()
// {
//   SecureLaplaceDiscreteLaplaceMechanismEKMPP secure_laplace_discrete_laplace_mechanism_EKMPP =
//       SecureLaplaceDiscreteLaplaceMechanismEKMPP(fD_->Get());

//   secure_laplace_discrete_laplace_mechanism_EKMPP.ParameterSetup(
//       sensitivity_l1_, epsilon_dlap_, iteration_EKMPP_ * num_of_simd_dgau_);
//   SecureSignedInteger signed_integer_discrete_laplace_noise =
//       secure_laplace_discrete_laplace_mechanism_EKMPP.FL64DiscreteLaplaceNoiseGeneration();

//   ShareWrapper random_bits_of_length_52_dgau =
//       fD_->GenerateRandomBooleanGmwBits(52, (iteration_EKMPP_)*num_of_simd_dgau_);
//   ShareWrapper random_bits_of_length_1022_dgau =
//       fD_->GenerateRandomBooleanGmwBits(1022, (iteration_EKMPP_)*num_of_simd_dgau_);
//   ShareWrapper random_floating_point_0_1_boolean_gmw_share_dgau =
//       fD_->UniformFloatingPoint64_0_1(random_bits_of_length_52_dgau,
//       random_bits_of_length_1022_dgau);

//   return FLDiscreteGaussianNoiseGeneration_with_DiscreteLaplaceEKMPP(
//       signed_integer_discrete_laplace_noise.Get(),
//       random_floating_point_0_1_boolean_gmw_share_dgau);
// }

// SecureSignedInteger
// SecureDiscreteGaussianMechanismCKS::FLDiscreteGaussianNoiseGeneration_with_DiscreteLaplaceEKMPP(
//     const ShareWrapper& boolean_gmw_share_discrete_laplace_sample,
//     const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau) {
//   std::vector<double> sigma_vector(num_of_simd_dgau_, sigma_);

//   std::vector<ShareWrapper> result_vector =
//       fD_->FLDiscreteGaussianDistribution_with_DiscreteLaplaceEKMPP(
//           sigma_vector, boolean_gmw_share_discrete_laplace_sample,
//           random_floating_point_0_1_boolean_gmw_share_dgau, iteration_EKMPP_);

//   ShareWrapper signed_integer_boolean_gmw_share_discrete_gaussian_noise = result_vector[0];
//   return SecureSignedInteger(signed_integer_boolean_gmw_share_discrete_gaussian_noise);
// }

// ===============================================================

// SecureSignedInteger
// SecureDiscreteGaussianMechanismCKS::FxDiscreteGaussianNoiseAddition_with_DiscreteLaplaceEKMPP() {
//   SecureSignedInteger signed_integer_noisy_fD =
//       SecureSignedInteger(fD_->Get()) +
//       FxDiscreteGaussianNoiseGeneration_with_DiscreteLaplaceEKMPP();
//   noisy_fD_ = std::make_unique<ShareWrapper>(signed_integer_noisy_fD.Get().Get());
//   return signed_integer_noisy_fD;
// }

// SecureSignedInteger
// SecureDiscreteGaussianMechanismCKS::FxDiscreteGaussianNoiseGeneration_with_DiscreteLaplaceEKMPP()
// {
//   SecureLaplaceDiscreteLaplaceMechanismEKMPP secure_laplace_discrete_laplace_mechanism_EKMPP =
//       SecureLaplaceDiscreteLaplaceMechanismEKMPP(fD_->Get());

//   secure_laplace_discrete_laplace_mechanism_EKMPP.ParameterSetup(
//       sensitivity_l1_, epsilon_dlap_, iteration_EKMPP_ * num_of_simd_dgau_);
//   SecureSignedInteger signed_integer_discrete_laplace_noise =
//       secure_laplace_discrete_laplace_mechanism_EKMPP.FxDiscreteLaplaceNoiseGeneration();

//   ShareWrapper random_bits_of_length_fixed_point_fraction_dgau =
//   fD_->GenerateRandomBooleanGmwBits(
//       fixed_point_fraction_bit_size_, (iteration_EKMPP_)*num_of_simd_dgau_);
//   ShareWrapper random_fixed_point_0_1_boolean_gmw_share_dgau = fD_->UniformFixedPoint_0_1(
//       random_bits_of_length_fixed_point_fraction_dgau, fixed_point_bit_size_);

//   return FxDiscreteGaussianNoiseGeneration_with_DiscreteLaplaceEKMPP(
//       signed_integer_discrete_laplace_noise.Get(),
//       random_fixed_point_0_1_boolean_gmw_share_dgau);
// }

// SecureSignedInteger
// SecureDiscreteGaussianMechanismCKS::FxDiscreteGaussianNoiseGeneration_with_DiscreteLaplaceEKMPP(
//     const ShareWrapper& boolean_gmw_share_discrete_laplace_sample,
//     const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_dgau) {
//   std::vector<double> sigma_vector(num_of_simd_dgau_, sigma_);

//   std::vector<ShareWrapper> result_vector =
//       fD_->FxDiscreteGaussianDistribution_with_DiscreteLaplaceEKMPP(
//           sigma_vector, boolean_gmw_share_discrete_laplace_sample,
//           random_fixed_point_0_1_boolean_gmw_share_dgau, iteration_EKMPP_,
//           fixed_point_fraction_bit_size_);

//   ShareWrapper signed_integer_boolean_gmw_share_discrete_gaussian_noise = result_vector[0];
//   return SecureSignedInteger(signed_integer_boolean_gmw_share_discrete_gaussian_noise);
// }

}  // namespace encrypto::motion