// MIT License
//
// Copyright (c) 2022 Liang Zhao
// Cu2ptography and Privacy Engineering Group (ENCRYPTO)
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

#include "secure_dp_mechanism/secure_gaussian_mechanism_KVHSIM.h"
#include "base/backend.h"

namespace encrypto::motion {
SecureGaussianMechanism::SecureGaussianMechanism(const SharePointer& other)
    : fD_(std::make_unique<ShareWrapper>(other)),
      logger_(fD_.get()->Get()->GetRegister()->GetLogger()) {}

SecureGaussianMechanism::SecureGaussianMechanism(SharePointer&& other)
    : fD_(std::make_unique<ShareWrapper>(std::move(other))),
      logger_(fD_.get()->Get()->GetRegister()->GetLogger()) {}

// void SecureGaussianMechanism::ParameterSetup(double sensitivity_l1, double
// epsilon) {
//   std::size_t num_of_simd_gauss_dlap = fD_->Get()->GetNumberOfSimdValues();
//   ParameterSetup(sensitivity_l1, epsilon, num_of_simd_gauss_dlap);
// }

void SecureGaussianMechanism::ParameterSetup(double sensitivity_l1, double mu, double sigma,
                                             std::size_t num_of_simd_gauss,
                                             std::size_t fixed_point_bit_size,
                                             std::size_t fixed_point_fraction_bit_size) {
  assert(fD_->Get()->GetNumberOfSimdValues() == num_of_simd_gauss);

  fixed_point_bit_size_ = fixed_point_bit_size;
  fixed_point_fraction_bit_size_ = fixed_point_fraction_bit_size;

  sensitivity_l1_ = sensitivity_l1;
  mu_ = mu;
  sigma_ = sigma;
  num_of_simd_gauss_ = num_of_simd_gauss;

  // TODO: compute mu, sigma based on epsilon_, delta_
  //   epsilon_ = epsilon;
  //   delta_ = delta;
}

// independent x1, x2 are sampled from Gauss(0,1),
// x1 = sqrt(-2*ln(u1))*cos(2*pi*u2)
// x2 = sqrt(-2*ln(u1))*sin(2*pi*u2)
// as discussed in paper (Are We There Yet? Timing and Floating-Point Attacks on Differential
// Privacy Systems), to mitigate the attack in above paper, we discard x2 and only use x1 as noise,
// however, this may still suffer from attacks
// y is sampled from Gauss(mu,sigma),
// y = sigma*x+mu
//============================================================================
// 32-bit floating point version
// SecureFloatingPointCircuitABY SecureGaussianMechanism::FL32GaussianNoiseAddition() {
//   SecureFloatingPointCircuitABY floating_point_noisy_fD =
//       SecureFloatingPointCircuitABY(fD_->Get()) + FL32GaussianNoiseGeneration();
//   noisy_fD_ = std::make_unique<ShareWrapper>(floating_point_noisy_fD.Get().Get());
//   return floating_point_noisy_fD;
// }

// SecureFloatingPointCircuitABY SecureGaussianMechanism::FL32GaussianNoiseGeneration() {
//   ShareWrapper random_bits_of_length_23_u1 =
//       fD_->GenerateRandomBooleanGmwBits(FLOATINGPOINT32_MANTISSA_BITS, num_of_simd_gauss_);
//   ShareWrapper random_bits_of_length_126_u1 =
//       fD_->GenerateRandomBooleanGmwBits(FLOATINGPOINT32_EXPONENT_BIAS - 1, num_of_simd_gauss_);
//   ShareWrapper random_floating_point_0_1_boolean_gmw_share_u1 =
//       fD_->UniformFloatingPoint32_0_1(random_bits_of_length_23_u1, random_bits_of_length_126_u1);

//   ShareWrapper random_bits_of_length_23_u2 =
//       fD_->GenerateRandomBooleanGmwBits(FLOATINGPOINT32_MANTISSA_BITS, num_of_simd_gauss_);
//   ShareWrapper random_bits_of_length_126_u2 =
//       fD_->GenerateRandomBooleanGmwBits(FLOATINGPOINT32_EXPONENT_BIAS - 1, num_of_simd_gauss_);
//   ShareWrapper random_floating_point_0_1_boolean_gmw_share_u2 =
//       fD_->UniformFloatingPoint32_0_1(random_bits_of_length_23_u2, random_bits_of_length_126_u2);

//   return FL32GaussianNoiseGeneration(random_floating_point_0_1_boolean_gmw_share_u1,
//                                      random_floating_point_0_1_boolean_gmw_share_u2);
// }

// SecureFloatingPointCircuitABY SecureGaussianMechanism::FL32GaussianNoiseGeneration(
//     const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_u1,
//     const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_u2) {
//   SecureFloatingPointCircuitABY floating_point_x1 =
//       (((SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_share_u1).Ln()) *
//         float(-2))
//            .Sqrt()) *
//       ((SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_share_u2) * float(2)))
//           .Cos();

//   SecureFloatingPointCircuitABY floating_point_y;
//   if (mu_ != 0) {
//     floating_point_y = floating_point_x1 * float(sigma_) + float(mu_);
//   } else {
//     floating_point_y = floating_point_x1 * float(sigma_);
//   }

//   return floating_point_y;

//   // // only for debug
//   // return (((SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_share_u1).Ln()) *
//   //          float(-2))
//   //             .Sqrt());
// }

// //============================================================================
// // 64-bit floating point version
// SecureFloatingPointCircuitABY SecureGaussianMechanism::FL64GaussianNoiseAddition() {
//   SecureFloatingPointCircuitABY floating_point_noisy_fD =
//       SecureFloatingPointCircuitABY(fD_->Get()) + FL64GaussianNoiseGeneration();
//   noisy_fD_ = std::make_unique<ShareWrapper>(floating_point_noisy_fD.Get().Get());
//   return floating_point_noisy_fD;
// }

// SecureFloatingPointCircuitABY SecureGaussianMechanism::FL64GaussianNoiseGeneration() {
//   ShareWrapper random_bits_of_length_52_u1 =
//       fD_->GenerateRandomBooleanGmwBits(FLOATINGPOINT_MANTISSA_BITS, num_of_simd_gauss_);
//   ShareWrapper random_bits_of_length_1022_u1 =
//       fD_->GenerateRandomBooleanGmwBits(FLOATINGPOINT_EXPONENT_BIAS - 1, num_of_simd_gauss_);
//   ShareWrapper random_floating_point_0_1_boolean_gmw_share_u1 =
//       fD_->UniformFloatingPoint64_0_1(random_bits_of_length_52_u1, random_bits_of_length_1022_u1);

//   ShareWrapper random_bits_of_length_52_u2 =
//       fD_->GenerateRandomBooleanGmwBits(FLOATINGPOINT_MANTISSA_BITS, num_of_simd_gauss_);
//   ShareWrapper random_bits_of_length_1022_u2 =
//       fD_->GenerateRandomBooleanGmwBits(FLOATINGPOINT_EXPONENT_BIAS - 1, num_of_simd_gauss_);
//   ShareWrapper random_floating_point_0_1_boolean_gmw_share_u2 =
//       fD_->UniformFloatingPoint64_0_1(random_bits_of_length_52_u2, random_bits_of_length_1022_u2);

//   return FL64GaussianNoiseGeneration(random_floating_point_0_1_boolean_gmw_share_u1,
//                                      random_floating_point_0_1_boolean_gmw_share_u2);
// }

// // Lap(lambda) = lambda * (ln(uniform_floating_point64_0_1) - ln(uniform_floating_point64_0_1))
// SecureFloatingPointCircuitABY SecureGaussianMechanism::FL64GaussianNoiseGeneration(
//     const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_u1,
//     const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_u2) {
//   SecureFloatingPointCircuitABY floating_point_x1 =
//       (((SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_share_u1).Ln()) *
//         double(-2))
//            .Sqrt()) *
//       ((SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_share_u2) * double(2)))
//           .Cos();

//   SecureFloatingPointCircuitABY floating_point_y;
//   if (mu_ != 0) {
//     floating_point_y = floating_point_x1 * double(sigma_) + double(mu_);
//   } else {
//     floating_point_y = floating_point_x1 * double(sigma_);
//   }
//   return floating_point_y;
// }

// //============================================================================
// // fixed-point version
// SecureFixedPointCircuitCBMC SecureGaussianMechanism::FxGaussianNoiseAddition() {
//   SecureFixedPointCircuitCBMC fixed_point_noisy_fD =
//       SecureFixedPointCircuitCBMC(fD_->Get()) + FxGaussianNoiseGeneration();
//   noisy_fD_ = std::make_unique<ShareWrapper>(fixed_point_noisy_fD.Get().Get());
//   return fixed_point_noisy_fD;
// }

// SecureFixedPointCircuitCBMC SecureGaussianMechanism::FxGaussianNoiseGeneration() {
//   ShareWrapper random_bits_of_length_fixed_point_fraction_u1 =
//       fD_->GenerateRandomBooleanGmwBits(fixed_point_fraction_bit_size_, num_of_simd_gauss_);
//   ShareWrapper random_fixed_point_0_1_boolean_gmw_share_u1 = fD_->UniformFixedPoint_0_1_Up(
//       random_bits_of_length_fixed_point_fraction_u1, fixed_point_bit_size_);

//   ShareWrapper random_bits_of_length_fixed_point_fraction_u2 =
//       fD_->GenerateRandomBooleanGmwBits(fixed_point_fraction_bit_size_, num_of_simd_gauss_);
//   ShareWrapper random_fixed_point_0_1_boolean_gmw_share_u2 = fD_->UniformFixedPoint_0_1_Up(
//       random_bits_of_length_fixed_point_fraction_u2, fixed_point_bit_size_);

//   return FxGaussianNoiseGeneration(random_fixed_point_0_1_boolean_gmw_share_u1,
//                                    random_fixed_point_0_1_boolean_gmw_share_u2);
// }

// SecureFixedPointCircuitCBMC SecureGaussianMechanism::FxGaussianNoiseGeneration(
//     const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_u1,
//     const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_u2) {

//   SecureFixedPointCircuitCBMC fixed_point_x2 =
//       (((SecureFixedPointCircuitCBMC(random_fixed_point_0_1_boolean_gmw_share_u1).Ln()) *
//         double(-2))
//            .Sqrt_P0132()) *
//       ((SecureFixedPointCircuitCBMC(random_fixed_point_0_1_boolean_gmw_share_u2) * double(4)))
//           .Sin_P3307_0_4();

//   SecureFixedPointCircuitCBMC fixed_point_y;
//   if (mu_ != 0) {
//     fixed_point_y = fixed_point_x2 * double(sigma_) + double(mu_);
//   } else {
//     fixed_point_y = fixed_point_x2 * double(sigma_);
//   }

//   return fixed_point_y;
// }

//============================================================================

}  // namespace encrypto::motion