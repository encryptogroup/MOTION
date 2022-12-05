// MIT License
//
// Copyright (c) 2021 Oleksandr Tkachenko
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

#include "secure_dp_mechanism/secure_integer_scaling_gaussian_mechanism.h"
#include "base/backend.h"

namespace encrypto::motion {
SecureIntegerScalingGaussianMechanism::SecureIntegerScalingGaussianMechanism(
    const SharePointer& other)
    : fD_(std::make_unique<ShareWrapper>(other)),
      logger_(fD_.get()->Get()->GetRegister()->GetLogger()) {}

SecureIntegerScalingGaussianMechanism::SecureIntegerScalingGaussianMechanism(SharePointer&& other)
    : fD_(std::make_unique<ShareWrapper>(std::move(other))),
      logger_(fD_.get()->Get()->GetRegister()->GetLogger()) {}

// void SecureIntegerScalingGaussianMechanism::ParameterSetup(double sensitivity_l1, double sigma,
//                                                            long double failure_probability) {
//   num_of_simd_gau_ = fD_->Get()->GetNumberOfSimdValues();
//   ParameterSetup(sensitivity_l1, sigma, num_of_simd_gau_, failure_probability);
// }

void SecureIntegerScalingGaussianMechanism::ParameterSetup(double sensitivity_l1, double epsilon,
                                                           double delta,
                                                           std::size_t num_of_simd_gau,
                                                           long double failure_probability) {
  epsilon_ = epsilon;
  delta_ = delta;
  std::cout << "epsilon: " << epsilon << std::endl;
  std::cout << "delta_: " << delta_ << std::endl;

  sigma_ = SigmaForGaussian(sensitivity_l0_, sensitivity_lInf_, epsilon_, delta_);
  ParameterSetup(sensitivity_l1, sigma_, num_of_simd_gau, failure_probability);
}

void SecureIntegerScalingGaussianMechanism::ParameterSetup(double sensitivity_l1, double sigma,
                                                           std::size_t num_of_simd_gau,
                                                           long double failure_probability) {
  std::cout << "SecureIntegerScalingGaussianMechanism::ParameterSetup" << std::endl;
  std::cout << "sigma: " << sigma << std::endl;

  sensitivity_l1_ = sensitivity_l1;
  sigma_ = sigma;

  num_of_simd_gau_ = num_of_simd_gau;
  failure_probability_requirement_ = failure_probability;

  // TODO: recheck source code
  resolution_r_ = ceil_power_of_two(2.0 * sigma_ / binomial_bound_);
  log2_resolution_r_ = std::log2(resolution_r_);

  sqrtN_ = 2.0 * sigma_ / resolution_r_;

  m_ = T(floor(M_SQRT2 * sqrtN_ + 1));

 SymmetricalBinomialDistributionOptimizationStruct optimize_symmetrical_binomial_distribution_iteration_result_struct =
      optimize_symmetrical_binomial_distribution_iteration(sqrtN_, failure_probability_requirement_);

  iteration_ = optimize_symmetrical_binomial_distribution_iteration_result_struct.iteration;
  total_failure_probability_ = optimize_symmetrical_binomial_distribution_iteration_result_struct.symmetrical_binomial_failure_probability_estimation;

  std::cout << "2.0 * sigma_ / binomial_bound_: " << 2.0 * sigma_ / binomial_bound_ << std::endl;
  std::cout << "resolution_r_: " << resolution_r_ << std::endl;
  std::cout << "sqrtN_: " << sqrtN_ << std::endl;
  std::cout << "m_: " << m_ << std::endl;
  std::cout << "iteration_: " << iteration_ << std::endl;
  std::cout << "total_failure_probability_: " << total_failure_probability_ << std::endl;
  std::cout << std::endl;
}

SecureFloatingPointCircuitABY SecureIntegerScalingGaussianMechanism::FLGaussianNoiseAddition() {
  SecureFloatingPointCircuitABY floating_point_noisy_fD =
      SecureFloatingPointCircuitABY(fD_->Get()) + FLGaussianNoiseGeneration();
  noisy_fD_ = std::make_unique<ShareWrapper>(floating_point_noisy_fD.Get().Get());
  return floating_point_noisy_fD;
}

// SecureFloatingPointCircuitABY SecureIntegerScalingGaussianMechanism::FLGaussianNoiseGeneration() {
//   std::cout << "SecureIntegerScalingGaussianMechanism::FLGaussianNoiseGeneration" << std::endl;
//   std::size_t geometric_distribution_sampling_bit_length = 100;
//   ShareWrapper random_bits_for_geometric_sampling = fD_->GenerateRandomBooleanGmwBits(
//       geometric_distribution_sampling_bit_length, iteration_ * num_of_simd_gau_);
//   ShareWrapper boolean_gmw_share_geometric_sample =
//       fD_->SimpleGeometricSampling_0(random_bits_for_geometric_sampling);
//   ShareWrapper unsigned_integer_boolean_gmw_share_geometric_sample =
//       fD_->BooleanGmwBitsZeroCompensation(boolean_gmw_share_geometric_sample, FLOATINGPOINT64_BITS);

//   ShareWrapper boolean_gmw_share_random_bits =
//       fD_->GenerateRandomBooleanGmwBits(1, iteration_ * num_of_simd_gau_);

//   ShareWrapper random_unsigned_integer_boolean_gmw_share =
//       fD_->GenerateRandomUnsignedInteger_BGMW(m_, iteration_ * num_of_simd_gau_);

//   ShareWrapper random_bits_of_length_52 =
//       fD_->GenerateRandomBooleanGmwBits(FLOATINGPOINT64_MANTISSA_BITS, iteration_ * num_of_simd_gau_);
//   ShareWrapper random_bits_of_length_1022 = fD_->GenerateRandomBooleanGmwBits(
//       FLOATINGPOINT64_EXPONENT_BIAS - 1, iteration_ * num_of_simd_gau_);
//   ShareWrapper random_floating_point_0_1_boolean_gmw_share =
//       fD_->UniformFloatingPoint64_0_1(random_bits_of_length_52, random_bits_of_length_1022);

//   SecureFloatingPointCircuitABY floating_point_gaussian_noise = FLGaussianNoiseGeneration(
//       unsigned_integer_boolean_gmw_share_geometric_sample, boolean_gmw_share_random_bits,
//       random_unsigned_integer_boolean_gmw_share, random_floating_point_0_1_boolean_gmw_share);

//   return floating_point_gaussian_noise;
// }

// SecureFloatingPointCircuitABY SecureIntegerScalingGaussianMechanism::FLGaussianNoiseGeneration(
//     const ShareWrapper& unsigned_integer_boolean_gmw_share_geometric_sample,
//     const ShareWrapper& boolean_gmw_share_random_bits,
//     const ShareWrapper& random_unsigned_integer_boolean_gmw_share,
//     const ShareWrapper& random_floating_point_0_1_boolean_gmw_share) {
//   std::vector<double> constant_sqrt_n_vector(num_of_simd_gau_, sqrtN_);

//   // sqrtN * sqrt(2) > 2^(64)
//   // use 128-bit unsigned integer and 64-bit floating point
//   if ((sqrtN_ * M_SQRT2 + 1) * 1.5 >= std::exp2(63)) {
//     // extend 64-bit unsigned_integer_boolean_gmw_share_geometric_sample,
//     // 64-bit random_unsigned_integer_boolean_gmw_share
//     // to 128-bit

//     ShareWrapper unsigned_integer_boolean_gmw_share_geometric_sample_extension =
//         fD_->BooleanGmwBitsZeroCompensation(unsigned_integer_boolean_gmw_share_geometric_sample,
//                                             sizeof(__uint128_t) * 8);
//     ShareWrapper random_unsigned_integer_boolean_gmw_share_extension =
//         fD_->BooleanGmwBitsZeroCompensation(random_unsigned_integer_boolean_gmw_share,
//                                             sizeof(__uint128_t) * 8);

//     // TODO: need test
//     std::vector<ShareWrapper> result_vector =
//         fD_->FLSymmetricBinomialDistribution<double, __uint128_t, __int128_t>(
//             constant_sqrt_n_vector, unsigned_integer_boolean_gmw_share_geometric_sample_extension,
//             boolean_gmw_share_random_bits, random_unsigned_integer_boolean_gmw_share_extension,
//             random_floating_point_0_1_boolean_gmw_share, iteration_);

//     ShareWrapper signed_integer_boolean_gmw_share_symmetric_binomial_noise = result_vector[0];
//     // return SecureSignedInteger(signed_integer_boolean_gmw_share_symmetric_binomial_noise)
//     //            .Int2FL(sizeof(double) * 8) *
//     //        double(resolution_r_);
//     return SecureSignedInteger(signed_integer_boolean_gmw_share_symmetric_binomial_noise)
//         .Int2FL(sizeof(double) * 8)
//         .MulPow2m(log2_resolution_r_);
//   }

//   // sqrtN * sqrt(2) < 2^(64)
//   // use 64-bit unsigned integer and 64-bit floating point
//   // std::int64_t overflow with low probability p = 2 ^ (-47)
//   else {
//     std::vector<ShareWrapper> result_vector =
//         fD_->FLSymmetricBinomialDistribution<double, std::uint64_t, std::int64_t>(
//             constant_sqrt_n_vector, unsigned_integer_boolean_gmw_share_geometric_sample,
//             boolean_gmw_share_random_bits, random_unsigned_integer_boolean_gmw_share,
//             random_floating_point_0_1_boolean_gmw_share, iteration_);

//     ShareWrapper signed_integer_boolean_gmw_share_symmetric_binomial_noise = result_vector[0];
//     // return SecureSignedInteger(signed_integer_boolean_gmw_share_symmetric_binomial_noise)
//     //            .Int2FL(sizeof(double) * 8) *
//     //        double(resolution_r_);
//     return SecureSignedInteger(signed_integer_boolean_gmw_share_symmetric_binomial_noise)
//         .Int2FL(sizeof(double) * 8)
//         .MulPow2m(log2_resolution_r_);
//   }

//   // // only for debugging
//   //   return
//   //   SecureSignedInteger(signed_integer_boolean_gmw_share_symmetric_binomial_noise).Int2FL()
//   //          ;
// }

}  // namespace encrypto::motion