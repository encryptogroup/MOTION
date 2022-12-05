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

#include "secure_dp_mechanism/secure_integer_scaling_laplace_mechanism.h"
#include "base/backend.h"

namespace encrypto::motion {
SecureIntegerScalingLaplaceMechanism::SecureIntegerScalingLaplaceMechanism(
    const SharePointer& other)
    : fD_(std::make_unique<ShareWrapper>(other)),
      logger_(fD_.get()->Get()->GetRegister()->GetLogger()) {}

SecureIntegerScalingLaplaceMechanism::SecureIntegerScalingLaplaceMechanism(SharePointer&& other)
    : fD_(std::make_unique<ShareWrapper>(std::move(other))),
      logger_(fD_.get()->Get()->GetRegister()->GetLogger()) {}

// void SecureIntegerScalingLaplaceMechanism::ParameterSetup(double sensitivity_l1, double epsilon,
//                                                           long double failure_probability) {
//   num_of_simd_lap_ = fD_->Get()->GetNumberOfSimdValues();
//   ParameterSetup(sensitivity_l1, epsilon, num_of_simd_lap_, failure_probability);
// }

void SecureIntegerScalingLaplaceMechanism::ParameterSetup(
    double sensitivity_l1, double epsilon, std::size_t num_of_simd_lap,
    long double failure_probability, std::size_t fixed_point_bit_size,
    std::size_t fixed_point_fraction_bit_size) {
  std::cout << "SecureIntegerScalingLaplaceMechanism::ParameterSetup" << std::endl;
  std::cout << "epsilon: " << epsilon << std::endl;

  assert(num_of_simd_lap_ = fD_->Get()->GetNumberOfSimdValues() == num_of_simd_lap);

  sensitivity_l1_ = sensitivity_l1;
  epsilon_ = epsilon;

  num_of_simd_lap_ = num_of_simd_lap;

  fixed_point_fraction_bit_size_ = fixed_point_fraction_bit_size;
  fixed_point_bit_size_ = fixed_point_bit_size;

  failure_probability_requirement_ = failure_probability;

  // TODO: check parameter calculation
  resolution_r_ = ceil_power_of_two(sensitivity_l1_ / epsilon / pow2_k_);
  log2_resolution_r_ = std::log2(resolution_r_);

  delta_r_ = sensitivity_l1_ + resolution_r_;

  lambda_ = resolution_r_ * epsilon_ / delta_r_;

  scale_ = 1.0 / lambda_;

  std::cout << "sensitivity_l1_ / epsilon / pow2_k_: " << sensitivity_l1_ / epsilon / pow2_k_
            << std::endl;
  std::cout << "resolution_r_: " << resolution_r_ << std::endl;
  std::cout << "lambda_: " << lambda_ << std::endl;
  std::cout << "scale_: " << scale_ << std::endl;
  std::cout << std::endl;
}

// // use 32-bit floating point, 64-bit floating point and fixed-point to generate discrete Laplace noise,
// // then, convert the discrete Laplace noise to 64-bit floating point Laplace noise
// // =================================================================================================
// // 32-bit floating point version
// SecureFloatingPointCircuitABY SecureIntegerScalingLaplaceMechanism::FL32LaplaceNoiseAddition() {
//   SecureFloatingPointCircuitABY floating_point_noisy_fD =
//       SecureFloatingPointCircuitABY(fD_->Get()) + FL32LaplaceNoiseGeneration();
//   noisy_fD_ = std::make_unique<ShareWrapper>(floating_point_noisy_fD.Get().Get());
//   return floating_point_noisy_fD;
// }

// SecureFloatingPointCircuitABY SecureIntegerScalingLaplaceMechanism::FL32LaplaceNoiseGeneration() {
//   std::cout << "SecureIntegerScalingLaplaceMechanism::FL32LaplaceNoiseGeneration" << std::endl;
//   SecureDiscreteLaplaceMechanismCKS secure_discrete_laplace_mechanism_CKS =
//       SecureDiscreteLaplaceMechanismCKS(fD_->Get());
//   secure_discrete_laplace_mechanism_CKS.ParameterSetup(sensitivity_l1_, scale_, num_of_simd_lap_,
//                                                        failure_probability_requirement_);
//   SecureSignedInteger signed_integer_discrete_laplace_noise =
//       secure_discrete_laplace_mechanism_CKS.FL32DiscreteLaplaceNoiseGeneration();

//   // SecureFloatingPointCircuitABY floating_point_laplace_noise =
//   //    ( signed_integer_discrete_laplace_noise.Int2FL(sizeof(float) * 8)) * float(resolution_r_);
//   SecureFloatingPointCircuitABY floating_point_laplace_noise =
//       (signed_integer_discrete_laplace_noise.Int2FL(sizeof(double) * 8))
//           .MulPow2m(log2_resolution_r_);

//   return floating_point_laplace_noise;
// }
// // =================================================================================================
// // 64-bit floating point version
// SecureFloatingPointCircuitABY SecureIntegerScalingLaplaceMechanism::FL64LaplaceNoiseAddition() {
//   SecureFloatingPointCircuitABY floating_point_noisy_fD =
//       SecureFloatingPointCircuitABY(fD_->Get()) + FL64LaplaceNoiseGeneration();
//   noisy_fD_ = std::make_unique<ShareWrapper>(floating_point_noisy_fD.Get().Get());
//   return floating_point_noisy_fD;
// }

// SecureFloatingPointCircuitABY SecureIntegerScalingLaplaceMechanism::FL64LaplaceNoiseGeneration() {
//   std::cout << "SecureIntegerScalingLaplaceMechanism::FL64LaplaceNoiseGeneration" << std::endl;
//   SecureDiscreteLaplaceMechanismCKS secure_discrete_laplace_mechanism_CKS =
//       SecureDiscreteLaplaceMechanismCKS(fD_->Get());
//   secure_discrete_laplace_mechanism_CKS.ParameterSetup(sensitivity_l1_, scale_, num_of_simd_lap_,
//                                                        failure_probability_requirement_);
//   SecureSignedInteger signed_integer_discrete_laplace_noise =
//       secure_discrete_laplace_mechanism_CKS.FL64DiscreteLaplaceNoiseGeneration();

//   // SecureFloatingPointCircuitABY floating_point_laplace_noise =
//   //   (  signed_integer_discrete_laplace_noise.Int2FL(sizeof(double) * 8) )* double(resolution_r_);
//   SecureFloatingPointCircuitABY floating_point_laplace_noise =
//       (signed_integer_discrete_laplace_noise.Int2FL(sizeof(double) * 8))
//           .MulPow2m(log2_resolution_r_);

//   return floating_point_laplace_noise;
// }


//===============================================================

// void SecureIntegerScalingLaplaceMechanism::ParameterSetup_with_DiscreteLaplaceEKMPP(
//     double sensitivity_l1, double epsilon, std::size_t num_of_simd_lap,
//     std::size_t fixed_point_bit_size, std::size_t fixed_point_fraction_bit_size) {
//   std::cout << "SecureIntegerScalingLaplaceMechanism::ParameterSetup" << std::endl;
//   std::cout << "epsilon: " << epsilon << std::endl;

//   assert(num_of_simd_lap_ = fD_->Get()->GetNumberOfSimdValues() == num_of_simd_lap);

//   sensitivity_l1_ = sensitivity_l1;
//   epsilon_ = epsilon;

//   num_of_simd_lap_ = num_of_simd_lap;

//   fixed_point_fraction_bit_size_ = fixed_point_fraction_bit_size;
//   fixed_point_bit_size_ = fixed_point_bit_size;

//   failure_probability_requirement_ = 0;

//   resolution_r_ = ceil_power_of_two(sensitivity_l1_ / epsilon / pow2_k_);
//   delta_r_ = sensitivity_l1_ + resolution_r_;

//   lambda_ = resolution_r_ * epsilon_ / delta_r_;

//   scale_ = 1 / lambda_;

//   epsilon_dlap_ = sensitivity_l1_ / scale_;
//   std::cout << "epsilon_dlap_: " << epsilon_dlap_ << std::endl;

//   lambda_dlap_ = std::exp(-1.0 / scale_);
//   std::cout << "lambda_dlap_: " << lambda_dlap_ << std::endl;

//   std::cout << "sensitivity_l1_ / epsilon / pow2_k_: " << sensitivity_l1_ / epsilon / pow2_k_
//             << std::endl;
//   std::cout << "resolution_r_: " << resolution_r_ << std::endl;
//   std::cout << "lambda_: " << lambda_ << std::endl;
//   std::cout << "scale_: " << scale_ << std::endl;
//   std::cout << std::endl;
// }

// SecureFloatingPointCircuitABY
// SecureIntegerScalingLaplaceMechanism::FLLaplaceNoiseAddition_with_DiscreteLaplaceEKMPP() {
//   SecureFloatingPointCircuitABY floating_point_noisy_fD =
//       SecureFloatingPointCircuitABY(fD_->Get()) +
//       FLLaplaceNoiseGeneration_with_DiscreteLaplaceEKMPP();
//   noisy_fD_ = std::make_unique<ShareWrapper>(floating_point_noisy_fD.Get().Get());
//   return floating_point_noisy_fD;
// }

// SecureFloatingPointCircuitABY
// SecureIntegerScalingLaplaceMechanism::FLLaplaceNoiseGeneration_with_DiscreteLaplaceEKMPP() {
//   SecureDPMechanism_PrivaDA secure_laplace_discrete_laplace_mechanism_EKMPP =
//       SecureDPMechanism_PrivaDA(fD_->Get());

//   secure_laplace_discrete_laplace_mechanism_EKMPP.ParameterSetup(sensitivity_l1_, epsilon_dlap_,
//                                                                  num_of_simd_lap_);
//   SecureSignedInteger signed_integer_discrete_laplace_noise =
//       secure_laplace_discrete_laplace_mechanism_EKMPP.FL64DiscreteLaplaceNoiseGeneration();

//   SecureFloatingPointCircuitABY floating_point_laplace_noise =
//       signed_integer_discrete_laplace_noise.Int2FL() * double(resolution_r_);

//   return floating_point_laplace_noise;
// }

// =============================================================

// SecureFixedPointCircuitCBMC
// SecureIntegerScalingLaplaceMechanism::FxLaplaceNoiseAddition_with_DiscreteLaplaceEKMPP() {
//   SecureFixedPointCircuitCBMC fixed_point_noisy_fD =
//       SecureFixedPointCircuitCBMC(fD_->Get()) +
//       FxLaplaceNoiseGeneration_with_DiscreteLaplaceEKMPP();
//   noisy_fD_ = std::make_unique<ShareWrapper>(fixed_point_noisy_fD.Get().Get());
//   return fixed_point_noisy_fD;
// }

// SecureFixedPointCircuitCBMC
// SecureIntegerScalingLaplaceMechanism::FxLaplaceNoiseGeneration_with_DiscreteLaplaceEKMPP() {
//   SecureDPMechanism_PrivaDA secure_laplace_discrete_laplace_mechanism_EKMPP =
//       SecureDPMechanism_PrivaDA(fD_->Get());

//   secure_laplace_discrete_laplace_mechanism_EKMPP.ParameterSetup(
//       sensitivity_l1_, epsilon_dlap_, num_of_simd_lap_, fixed_point_bit_size_,
//       fixed_point_fraction_bit_size_);

//   SecureSignedInteger signed_integer_discrete_laplace_noise =
//       secure_laplace_discrete_laplace_mechanism_EKMPP.FxDiscreteLaplaceNoiseGeneration();

//   SecureFixedPointCircuitCBMC fixed_point_laplace_noise =
//       signed_integer_discrete_laplace_noise.Int2Fx() * resolution_r_;

//   return fixed_point_laplace_noise;
// }

}  // namespace encrypto::motion