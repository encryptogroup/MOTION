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

#include "secure_dp_mechanism/secure_laplace_discrete_laplace_mechanism_EKMPP.h"
#include "base/backend.h"

namespace encrypto::motion {
SecureLaplaceDiscreteLaplaceMechanismEKMPP::SecureLaplaceDiscreteLaplaceMechanismEKMPP(
    const SharePointer& other)
    : fD_(std::make_unique<ShareWrapper>(other)),
      logger_(fD_.get()->Get()->GetRegister()->GetLogger()) {}

SecureLaplaceDiscreteLaplaceMechanismEKMPP::SecureLaplaceDiscreteLaplaceMechanismEKMPP(
    SharePointer&& other)
    : fD_(std::make_unique<ShareWrapper>(std::move(other))),
      logger_(fD_.get()->Get()->GetRegister()->GetLogger()) {}

// void SecureLaplaceDiscreteLaplaceMechanismEKMPP::ParameterSetup(double sensitivity_l1, double
// epsilon) {
//   std::size_t num_of_simd_lap_dlap = fD_->Get()->GetNumberOfSimdValues();
//   ParameterSetup(sensitivity_l1, epsilon, num_of_simd_lap_dlap);
// }

void SecureLaplaceDiscreteLaplaceMechanismEKMPP::ParameterSetup(
    double sensitivity_l1, double epsilon, std::size_t num_of_simd_lap_dlap,
    std::size_t fixed_point_bit_size, std::size_t fixed_point_fraction_bit_size) {
  assert(fD_->Get()->GetNumberOfSimdValues() == num_of_simd_lap_dlap);

  fixed_point_bit_size_ = fixed_point_bit_size;
  fixed_point_fraction_bit_size_ = fixed_point_fraction_bit_size;

  sensitivity_l1_ = sensitivity_l1;
  epsilon_ = epsilon;
  num_of_simd_lap_ = num_of_simd_lap_dlap;
  num_of_simd_dlap_ = num_of_simd_lap_dlap;

  // TODO: check parameter calculation
  lambda_lap_ = sensitivity_l1_ / epsilon_;
  lambda_dlap_ = std::exp(-epsilon_ / sensitivity_l1_);
  alpha_dlap_ = -sensitivity_l1_ / epsilon_;

//   std::cout << "lambda_lap_: " << lambda_lap_ << std::endl;
//   std::cout << "lambda_dlap_: " << lambda_dlap_ << std::endl;
//   std::cout << "alpha_dlap_: " << alpha_dlap_ << std::endl;
}

//============================================================================
// // 32-bit floating point version
// SecureFloatingPointCircuitABY
// SecureLaplaceDiscreteLaplaceMechanismEKMPP::FL32LaplaceNoiseAddition() {
//   SecureFloatingPointCircuitABY floating_point_noisy_fD =
//       SecureFloatingPointCircuitABY(fD_->Get()) + FL32LaplaceNoiseGeneration();
//   noisy_fD_ = std::make_unique<ShareWrapper>(floating_point_noisy_fD.Get().Get());
//   return floating_point_noisy_fD;
// }

// SecureFloatingPointCircuitABY
// SecureLaplaceDiscreteLaplaceMechanismEKMPP::FL32LaplaceNoiseGeneration() {
//   ShareWrapper random_bits_of_length_23_rx =
//       fD_->GenerateRandomBooleanGmwBits(FLOATINGPOINT32_MANTISSA_BITS, num_of_simd_lap_);
//   ShareWrapper random_bits_of_length_126_rx =
//       fD_->GenerateRandomBooleanGmwBits(FLOATINGPOINT32_EXPONENT_BIAS - 1, num_of_simd_lap_);
//   ShareWrapper random_floating_point_0_1_boolean_gmw_share_rx =
//       fD_->UniformFloatingPoint32_0_1(random_bits_of_length_23_rx, random_bits_of_length_126_rx);

//   ShareWrapper random_bits_of_length_23_ry =
//       fD_->GenerateRandomBooleanGmwBits(FLOATINGPOINT32_MANTISSA_BITS, num_of_simd_lap_);
//   ShareWrapper random_bits_of_length_126_ry =
//       fD_->GenerateRandomBooleanGmwBits(FLOATINGPOINT32_EXPONENT_BIAS - 1, num_of_simd_lap_);
//   ShareWrapper random_floating_point_0_1_boolean_gmw_share_ry =
//       fD_->UniformFloatingPoint32_0_1(random_bits_of_length_23_ry, random_bits_of_length_126_ry);

//   return FL32LaplaceNoiseGeneration(random_floating_point_0_1_boolean_gmw_share_rx,
//                                     random_floating_point_0_1_boolean_gmw_share_ry);
// }

// // Lap(lambda) = lambda * (ln(uniform_floating_point32_0_1) - ln(uniform_floating_point32_0_1))
// SecureFloatingPointCircuitABY
// SecureLaplaceDiscreteLaplaceMechanismEKMPP::FL32LaplaceNoiseGeneration(
//     const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_rx,
//     const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_ry) {
//   SecureFloatingPointCircuitABY floating_point_lambda_mul_ln_rx_div_ry =
//       (SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_share_rx) /
//        SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_share_ry))
//           .Ln() *
//       float(lambda_lap_);

//   //   // only for debug
//   //   SecureFloatingPointCircuitABY floating_point_lambda_mul_ln_rx_div_ry =
//   //       (SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_share_rx) /
//   //        SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_share_ry));

//   return floating_point_lambda_mul_ln_rx_div_ry;
// }

// //============================================================================
// // 64-bit floating point version
// SecureFloatingPointCircuitABY
// SecureLaplaceDiscreteLaplaceMechanismEKMPP::FL64LaplaceNoiseAddition() {
//   SecureFloatingPointCircuitABY floating_point_noisy_fD =
//       SecureFloatingPointCircuitABY(fD_->Get()) + FL64LaplaceNoiseGeneration();
//   noisy_fD_ = std::make_unique<ShareWrapper>(floating_point_noisy_fD.Get().Get());
//   return floating_point_noisy_fD;
// }

// SecureFloatingPointCircuitABY
// SecureLaplaceDiscreteLaplaceMechanismEKMPP::FL64LaplaceNoiseGeneration() {
//   ShareWrapper random_bits_of_length_52_rx =
//       fD_->GenerateRandomBooleanGmwBits(FLOATINGPOINT_MANTISSA_BITS, num_of_simd_lap_);
//   ShareWrapper random_bits_of_length_1022_rx =
//       fD_->GenerateRandomBooleanGmwBits(FLOATINGPOINT_EXPONENT_BIAS - 1, num_of_simd_lap_);
//   ShareWrapper random_floating_point_0_1_boolean_gmw_share_rx =
//       fD_->UniformFloatingPoint64_0_1(random_bits_of_length_52_rx, random_bits_of_length_1022_rx);

//   ShareWrapper random_bits_of_length_52_ry =
//       fD_->GenerateRandomBooleanGmwBits(FLOATINGPOINT_MANTISSA_BITS, num_of_simd_lap_);
//   ShareWrapper random_bits_of_length_1022_ry =
//       fD_->GenerateRandomBooleanGmwBits(FLOATINGPOINT_EXPONENT_BIAS - 1, num_of_simd_lap_);
//   ShareWrapper random_floating_point_0_1_boolean_gmw_share_ry =
//       fD_->UniformFloatingPoint64_0_1(random_bits_of_length_52_ry, random_bits_of_length_1022_ry);

//   return FL64LaplaceNoiseGeneration(random_floating_point_0_1_boolean_gmw_share_rx,
//                                     random_floating_point_0_1_boolean_gmw_share_ry);
// }

// // Lap(lambda) = lambda * (ln(uniform_floating_point64_0_1) - ln(uniform_floating_point64_0_1))
// SecureFloatingPointCircuitABY
// SecureLaplaceDiscreteLaplaceMechanismEKMPP::FL64LaplaceNoiseGeneration(
//     const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_rx,
//     const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_ry) {
//   SecureFloatingPointCircuitABY floating_point_lambda_mul_ln_rx_div_ry =
//       (SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_share_rx) /
//        SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_share_ry))
//           .Ln() *
//       double(lambda_lap_);

//   //   // only for debug
//   //   SecureFloatingPointCircuitABY floating_point_lambda_mul_ln_rx_div_ry =
//   //       (SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_share_rx) /
//   //        SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_share_ry));

//   return floating_point_lambda_mul_ln_rx_div_ry;
// }

// //============================================================================

// SecureFixedPointCircuitCBMC SecureLaplaceDiscreteLaplaceMechanismEKMPP::FxLaplaceNoiseAddition() {
//   SecureFixedPointCircuitCBMC fixed_point_noisy_fD =
//       SecureFixedPointCircuitCBMC(fD_->Get()) + FxLaplaceNoiseGeneration();
//   noisy_fD_ = std::make_unique<ShareWrapper>(fixed_point_noisy_fD.Get().Get());
//   return fixed_point_noisy_fD;
// }

// SecureFixedPointCircuitCBMC SecureLaplaceDiscreteLaplaceMechanismEKMPP::FxLaplaceNoiseGeneration() {
//   ShareWrapper random_bits_of_length_fixed_point_fraction_rx =
//       fD_->GenerateRandomBooleanGmwBits(fixed_point_fraction_bit_size_, num_of_simd_lap_);
//   ShareWrapper random_fixed_point_0_1_boolean_gmw_share_rx = fD_->UniformFixedPoint_0_1_Up(
//       random_bits_of_length_fixed_point_fraction_rx, fixed_point_bit_size_);

//   ShareWrapper random_bits_of_length_fixed_point_fraction_ry =
//       fD_->GenerateRandomBooleanGmwBits(fixed_point_fraction_bit_size_, num_of_simd_lap_);
//   ShareWrapper random_fixed_point_0_1_boolean_gmw_share_ry = fD_->UniformFixedPoint_0_1_Up(
//       random_bits_of_length_fixed_point_fraction_ry, fixed_point_bit_size_);

//   return FxLaplaceNoiseGeneration(random_fixed_point_0_1_boolean_gmw_share_rx,
//                                   random_fixed_point_0_1_boolean_gmw_share_ry);
// }

// SecureFixedPointCircuitCBMC SecureLaplaceDiscreteLaplaceMechanismEKMPP::FxLaplaceNoiseGeneration(
//     const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_rx,
//     const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_ry) {
//   SecureFixedPointCircuitCBMC fixed_point_lambda_mul_ln_rx_div_ry =
//       (SecureFixedPointCircuitCBMC(random_fixed_point_0_1_boolean_gmw_share_rx) /
//        SecureFixedPointCircuitCBMC(random_fixed_point_0_1_boolean_gmw_share_ry))
//           .Ln() *
//       double(lambda_lap_);

//   //   SecureFixedPointCircuitCBMC fixed_point_lambda_mul_ln_rx_div_ry =
//   //       (SecureFixedPointCircuitCBMC(random_fixed_point_0_1_boolean_gmw_share_rx) /
//   //        SecureFixedPointCircuitCBMC(random_fixed_point_0_1_boolean_gmw_share_ry)).Ln();

//   return fixed_point_lambda_mul_ln_rx_div_ry;
// }

// //============================================================================
// // 32-bit floating point version

// SecureSignedInteger SecureLaplaceDiscreteLaplaceMechanismEKMPP::FL32DiscreteLaplaceNoiseAddition() {
//   SecureSignedInteger signed_integer_noisy_fD =
//       SecureSignedInteger(fD_->Get()) + FL32DiscreteLaplaceNoiseGeneration();
//   noisy_fD_ = std::make_unique<ShareWrapper>(signed_integer_noisy_fD.Get().Get());
//   return signed_integer_noisy_fD;
// }

// SecureSignedInteger
// SecureLaplaceDiscreteLaplaceMechanismEKMPP::FL32DiscreteLaplaceNoiseGeneration() {
//   ShareWrapper random_bits_of_length_23_rx =
//       fD_->GenerateRandomBooleanGmwBits(23, num_of_simd_dlap_);
//   ShareWrapper random_bits_of_length_126_rx =
//       fD_->GenerateRandomBooleanGmwBits(126, num_of_simd_dlap_);
//   ShareWrapper random_floating_point_0_1_boolean_gmw_share_rx =
//       fD_->UniformFloatingPoint32_0_1(random_bits_of_length_23_rx, random_bits_of_length_126_rx);

//   ShareWrapper random_bits_of_length_23_ry =
//       fD_->GenerateRandomBooleanGmwBits(23, num_of_simd_dlap_);
//   ShareWrapper random_bits_of_length_126_ry =
//       fD_->GenerateRandomBooleanGmwBits(126, num_of_simd_dlap_);
//   ShareWrapper random_floating_point_0_1_boolean_gmw_share_ry =
//       fD_->UniformFloatingPoint32_0_1(random_bits_of_length_23_ry, random_bits_of_length_126_ry);

//   return FL32DiscreteLaplaceNoiseGeneration(random_floating_point_0_1_boolean_gmw_share_rx,
//                                             random_floating_point_0_1_boolean_gmw_share_ry);
// }

// SecureSignedInteger SecureLaplaceDiscreteLaplaceMechanismEKMPP::FL32DiscreteLaplaceNoiseGeneration(
//     const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_rx,
//     const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_ry) {
//   // combine rx and ry in SIMD to parallel computation
//   std::vector<ShareWrapper> random_floating_point_0_1_boolean_gmw_share_rx_ry_vector{
//       random_floating_point_0_1_boolean_gmw_share_rx,
//       random_floating_point_0_1_boolean_gmw_share_ry};

//   SecureSignedInteger signed_integer_floor_alpha_mul_ln_rx_ry =
//       ((SecureFloatingPointCircuitABY(
//             ShareWrapper::Simdify(random_floating_point_0_1_boolean_gmw_share_rx_ry_vector))
//             .Ln() *
//         float(alpha_dlap_))
//            .Floor())
//           .FL2Int(IntType_size);

//   // split rx and ry from SIMD
//   std::vector<ShareWrapper> signed_integer_floor_alpha_mul_ln_rx_ry_unsimdify =
//       signed_integer_floor_alpha_mul_ln_rx_ry.Get().Unsimdify();

//   std::vector<ShareWrapper> signed_integer_floor_alpha_mul_ln_rx_vector(
//       signed_integer_floor_alpha_mul_ln_rx_ry_unsimdify.begin(),
//       signed_integer_floor_alpha_mul_ln_rx_ry_unsimdify.begin() + num_of_simd_dlap_);
//   std::vector<ShareWrapper> signed_integer_floor_alpha_mul_ln_ry_vector(
//       signed_integer_floor_alpha_mul_ln_rx_ry_unsimdify.begin() + num_of_simd_dlap_,
//       signed_integer_floor_alpha_mul_ln_rx_ry_unsimdify.begin() + 2 * num_of_simd_dlap_);

//   SecureSignedInteger signed_integer_discrete_laplace_sample =
//       SecureSignedInteger(ShareWrapper::Simdify(signed_integer_floor_alpha_mul_ln_rx_vector)) -
//       SecureSignedInteger(ShareWrapper::Simdify(signed_integer_floor_alpha_mul_ln_ry_vector));

//   return signed_integer_discrete_laplace_sample;
// }

// //============================================================================
// // 64-bit floating point version
// SecureSignedInteger SecureLaplaceDiscreteLaplaceMechanismEKMPP::FL64DiscreteLaplaceNoiseAddition() {
//   SecureSignedInteger signed_integer_noisy_fD =
//       SecureSignedInteger(fD_->Get()) + FL64DiscreteLaplaceNoiseGeneration();
//   noisy_fD_ = std::make_unique<ShareWrapper>(signed_integer_noisy_fD.Get().Get());
//   return signed_integer_noisy_fD;
// }

// SecureSignedInteger
// SecureLaplaceDiscreteLaplaceMechanismEKMPP::FL64DiscreteLaplaceNoiseGeneration() {
//   ShareWrapper random_bits_of_length_52_rx =
//       fD_->GenerateRandomBooleanGmwBits(52, num_of_simd_dlap_);
//   ShareWrapper random_bits_of_length_1022_rx =
//       fD_->GenerateRandomBooleanGmwBits(1022, num_of_simd_dlap_);
//   ShareWrapper random_floating_point_0_1_boolean_gmw_share_rx =
//       fD_->UniformFloatingPoint64_0_1(random_bits_of_length_52_rx, random_bits_of_length_1022_rx);

//   ShareWrapper random_bits_of_length_52_ry =
//       fD_->GenerateRandomBooleanGmwBits(52, num_of_simd_dlap_);
//   ShareWrapper random_bits_of_length_1022_ry =
//       fD_->GenerateRandomBooleanGmwBits(1022, num_of_simd_dlap_);
//   ShareWrapper random_floating_point_0_1_boolean_gmw_share_ry =
//       fD_->UniformFloatingPoint64_0_1(random_bits_of_length_52_ry, random_bits_of_length_1022_ry);

//   return FL64DiscreteLaplaceNoiseGeneration(random_floating_point_0_1_boolean_gmw_share_rx,
//                                             random_floating_point_0_1_boolean_gmw_share_ry);
// }

// SecureSignedInteger SecureLaplaceDiscreteLaplaceMechanismEKMPP::FL64DiscreteLaplaceNoiseGeneration(
//     const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_rx,
//     const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_ry) {
//   // combine rx and ry in SIMD to parallel computation
//   std::vector<ShareWrapper> random_floating_point_0_1_boolean_gmw_share_rx_ry_vector{
//       random_floating_point_0_1_boolean_gmw_share_rx,
//       random_floating_point_0_1_boolean_gmw_share_ry};

//   SecureSignedInteger signed_integer_floor_alpha_mul_ln_rx_ry =
//       ((SecureFloatingPointCircuitABY(
//             ShareWrapper::Simdify(random_floating_point_0_1_boolean_gmw_share_rx_ry_vector))
//             .Ln() *
//         double(alpha_dlap_))
//            .Floor())
//           .FL2Int(IntType_size);

//   // split rx and ry from SIMD
//   std::vector<ShareWrapper> signed_integer_floor_alpha_mul_ln_rx_ry_unsimdify =
//       signed_integer_floor_alpha_mul_ln_rx_ry.Get().Unsimdify();

//   std::vector<ShareWrapper> signed_integer_floor_alpha_mul_ln_rx_vector(
//       signed_integer_floor_alpha_mul_ln_rx_ry_unsimdify.begin(),
//       signed_integer_floor_alpha_mul_ln_rx_ry_unsimdify.begin() + num_of_simd_dlap_);
//   std::vector<ShareWrapper> signed_integer_floor_alpha_mul_ln_ry_vector(
//       signed_integer_floor_alpha_mul_ln_rx_ry_unsimdify.begin() + num_of_simd_dlap_,
//       signed_integer_floor_alpha_mul_ln_rx_ry_unsimdify.begin() + 2 * num_of_simd_dlap_);

//   SecureSignedInteger signed_integer_discrete_laplace_sample =
//       SecureSignedInteger(ShareWrapper::Simdify(signed_integer_floor_alpha_mul_ln_rx_vector)) -
//       SecureSignedInteger(ShareWrapper::Simdify(signed_integer_floor_alpha_mul_ln_ry_vector));

//   return signed_integer_discrete_laplace_sample;
// }

// //============================================================================

// SecureSignedInteger SecureLaplaceDiscreteLaplaceMechanismEKMPP::FxDiscreteLaplaceNoiseAddition() {
//   SecureSignedInteger signed_integer_noisy_fD =
//       SecureSignedInteger(fD_->Get()) + FxDiscreteLaplaceNoiseGeneration();
//   noisy_fD_ = std::make_unique<ShareWrapper>(signed_integer_noisy_fD.Get().Get());
//   return signed_integer_noisy_fD;
// }

// SecureSignedInteger SecureLaplaceDiscreteLaplaceMechanismEKMPP::FxDiscreteLaplaceNoiseGeneration() {
//   ShareWrapper random_bits_of_length_fixed_point_fraction_rx =
//       fD_->GenerateRandomBooleanGmwBits(fixed_point_fraction_bit_size_, num_of_simd_dlap_);
//   ShareWrapper random_fixed_point_0_1_boolean_gmw_share_rx = fD_->UniformFixedPoint_0_1_Up(
//       random_bits_of_length_fixed_point_fraction_rx, fixed_point_bit_size_);

//   ShareWrapper random_bits_of_length_fixed_point_fraction_ry =
//       fD_->GenerateRandomBooleanGmwBits(fixed_point_fraction_bit_size_, num_of_simd_dlap_);
//   ShareWrapper random_fixed_point_0_1_boolean_gmw_share_ry = fD_->UniformFixedPoint_0_1_Up(
//       random_bits_of_length_fixed_point_fraction_ry, fixed_point_bit_size_);

//   return FxDiscreteLaplaceNoiseGeneration(random_fixed_point_0_1_boolean_gmw_share_rx,
//                                           random_fixed_point_0_1_boolean_gmw_share_ry);
// }

// SecureSignedInteger SecureLaplaceDiscreteLaplaceMechanismEKMPP::FxDiscreteLaplaceNoiseGeneration(
//     const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_rx,
//     const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_ry) {
//   // combine rx and ry in SIMD to parallel computation
//   std::vector<ShareWrapper> random_floating_point_0_1_boolean_gmw_share_rx_ry_vector{
//       random_fixed_point_0_1_boolean_gmw_share_rx, random_fixed_point_0_1_boolean_gmw_share_ry};

//   SecureSignedInteger signed_integer_floor_alpha_mul_ln_rx_ry =
//       ((SecureFixedPointCircuitCBMC(
//             ShareWrapper::Simdify(random_floating_point_0_1_boolean_gmw_share_rx_ry_vector))
//             .Ln() *
//         double(alpha_dlap_))
//            .Floor())
//           .RoundedFx2Int();

//   //   // only for debug
//   //   SecureSignedInteger signed_integer_floor_alpha_mul_ln_rx_ry =
//   //       ((SecureFixedPointCircuitCBMC(
//   //             ShareWrapper::Simdify(random_floating_point_0_1_boolean_gmw_share_rx_ry_vector))
//   //             .Ln())
//   //            .Floor())
//   //           .Fx2IntWithFloor();

//   // split rx and ry from SIMD
//   std::vector<ShareWrapper> signed_integer_floor_alpha_mul_ln_rx_ry_unsimdify =
//       signed_integer_floor_alpha_mul_ln_rx_ry.Get().Unsimdify();

//   std::vector<ShareWrapper> signed_integer_floor_alpha_mul_ln_rx_vector(
//       signed_integer_floor_alpha_mul_ln_rx_ry_unsimdify.begin(),
//       signed_integer_floor_alpha_mul_ln_rx_ry_unsimdify.begin() + num_of_simd_dlap_);
//   std::vector<ShareWrapper> signed_integer_floor_alpha_mul_ln_ry_vector(
//       signed_integer_floor_alpha_mul_ln_rx_ry_unsimdify.begin() + num_of_simd_dlap_,
//       signed_integer_floor_alpha_mul_ln_rx_ry_unsimdify.begin() + 2 * num_of_simd_dlap_);

//   SecureSignedInteger signed_integer_discrete_laplace_sample =
//       SecureSignedInteger(ShareWrapper::Simdify(signed_integer_floor_alpha_mul_ln_rx_vector)) -
//       SecureSignedInteger(ShareWrapper::Simdify(signed_integer_floor_alpha_mul_ln_ry_vector));

//   //   // only for debugging
//   //   SecureSignedInteger signed_integer_discrete_laplace_sample =
//   //       SecureSignedInteger(ShareWrapper::Simdify(signed_integer_floor_alpha_mul_ln_rx_vector));

//   return signed_integer_discrete_laplace_sample;
// }

}  // namespace encrypto::motion