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

#include "secure_dp_mechanism/secure_discrete_laplace_mechanism_CKS.h"
#include "base/backend.h"

namespace encrypto::motion {
SecureDiscreteLaplaceMechanismCKS::SecureDiscreteLaplaceMechanismCKS(const SharePointer& other)
    : fD_(std::make_unique<ShareWrapper>(other)),
      logger_(fD_.get()->Get()->GetRegister()->GetLogger()) {}

SecureDiscreteLaplaceMechanismCKS::SecureDiscreteLaplaceMechanismCKS(SharePointer&& other)
    : fD_(std::make_unique<ShareWrapper>(std::move(other))),
      logger_(fD_.get()->Get()->GetRegister()->GetLogger()) {}

// void SecureDiscreteLaplaceMechanismCKS::ParameterSetup(double sensitivity_l1, double scale,
//                                                        long double failure_probability) {
//   num_of_simd_dlap_ = fD_->Get()->GetNumberOfSimdValues();
//   ParameterSetup(sensitivity_l1, scale, num_of_simd_dlap_, failure_probability);
// }

void SecureDiscreteLaplaceMechanismCKS::ParameterSetup(double sensitivity_l1, double scale,
                                                       std::size_t num_of_simd_dlap,
                                                       long double failure_probability,
                                                       std::size_t fixed_point_bit_size,
                                                       std::size_t fixed_point_fraction_bit_size) {
  assert(fD_->Get()->GetNumberOfSimdValues() == num_of_simd_dlap);
  std::cout << "SecureDiscreteLaplaceMechanismCKS::ParameterSetup" << std::endl;
  std::cout << "scale: " << scale << std::endl;
  sensitivity_l1_ = sensitivity_l1;
  scale_ = scale;

  fixed_point_bit_size_ = fixed_point_bit_size;
  fixed_point_fraction_bit_size_ = fixed_point_fraction_bit_size;

  failure_probability_requirement_ = failure_probability;

  // TODO: bound denominator s.t., integer mod still secure

  // convert 1/scale_ = numerator_/denominator_
  // ! the numerator and denominator must be representative as 64-bit unsigned integers
  //   numerator_ = decimalToFraction(1 / scale_)[0];
  //   denominator_ = decimalToFraction(1 / scale_)[1];

  //   std::cout << "numerator_: " << numerator_ << std::endl;
  //   std::cout << "denominator_: " << denominator_ << std::endl;

  num_of_simd_dlap_ = num_of_simd_dlap;

  // estimate the number of iterations required to satisfy the security parameter, i.e., sampling
  // algorithms fail with probability (e.g., 2^(-40)) after iterations
  DiscreteLaplaceDistributionOptimizationStruct<T>
      optimize_discrete_laplace_distribution_EXP_iteration_result_struct =
          optimize_discrete_laplace_distribution_EXP_iteration<T>(scale_,
                                                                  failure_probability_requirement_);

  iteration_1_ = optimize_discrete_laplace_distribution_EXP_iteration_result_struct.iteration_geo_1;
  iteration_2_ = optimize_discrete_laplace_distribution_EXP_iteration_result_struct.iteration_geo_2;
  iteration_3_ =
      optimize_discrete_laplace_distribution_EXP_iteration_result_struct.iteration_dlap_3;
  minimum_total_iteration_ =
      optimize_discrete_laplace_distribution_EXP_iteration_result_struct.minimum_total_iteration;
  minimum_total_MPC_time_ =
      optimize_discrete_laplace_distribution_EXP_iteration_result_struct.minimum_total_MPC_time;
  geometric_failure_probability_estimation_ =
      optimize_discrete_laplace_distribution_EXP_iteration_result_struct
          .geometric_failure_probability_estimation;
  discrete_laplace_failure_probability_estimation_ =
      optimize_discrete_laplace_distribution_EXP_iteration_result_struct
          .discrete_laplace_failure_probability_estimation;
  upscale_factor_ =
      optimize_discrete_laplace_distribution_EXP_iteration_result_struct.upscale_factor;

  numerator_ = optimize_discrete_laplace_distribution_EXP_iteration_result_struct.numerator;
  denominator_ = optimize_discrete_laplace_distribution_EXP_iteration_result_struct.denominator;
  log2_denominator_ =
      optimize_discrete_laplace_distribution_EXP_iteration_result_struct.log2_denominator;

  //   std::cout << "numerator_upscale: " << numerator_ << std::endl;
  //   std::cout << "denominator_upscale: " << denominator_ << std::endl;

  std::cout << "numerator_: " << numerator_ << std::endl;
  std::cout << "denominator_: " << denominator_ << std::endl;
  std::cout << "log2_denominator_: " << log2_denominator_ << std::endl;

  num_of_simd_geo_ = iteration_3_;
  num_of_simd_total_ = num_of_simd_geo_ * num_of_simd_dlap_;

  std::cout << "discrete_laplace_best_iterations_1: " << iteration_1_ << std::endl;
  std::cout << "discrete_laplace_best_iterations_2: " << iteration_2_ << std::endl;
  std::cout << "discrete_laplace_best_iterations_3: " << iteration_3_ << std::endl;
  std::cout << "minimum_total_iteration: " << minimum_total_iteration_ << std::endl;
  std::cout << "minimum_total_MPC_time: " << minimum_total_MPC_time_ << std::endl;
  std::cout << "geometric_failure_probability_estimation: "
            << geometric_failure_probability_estimation_ << std::endl;
  std::cout << "discrete_laplace_failure_probability_estimation: "
            << discrete_laplace_failure_probability_estimation_ << std::endl;
  std::cout << "upscale_factor: " << upscale_factor_ << std::endl;

  std::cout << "num_of_simd_geo_: " << num_of_simd_geo_ << std::endl;
  std::cout << "num_of_simd_dlap_: " << num_of_simd_dlap_ << std::endl;
  std::cout << "num_of_simd_total_: " << num_of_simd_total_ << std::endl;
  std::cout << std::endl;
}

// ============================================================
// ! naive version
// 32-bit floating-point version

SecureSignedInteger SecureDiscreteLaplaceMechanismCKS::FL32DiscreteLaplaceNoiseGeneration_naive() {
  std::cout << "SecureDiscreteLaplaceMechanismCKS::FL32DiscreteLaplaceNoiseGeneration" << std::endl;
  if (denominator_ != T(1)) {
    ShareWrapper random_bits_of_length_23 =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT32_MANTISSA_BITS,
                                          (iteration_1_ + iteration_2_) * num_of_simd_total_);
    ShareWrapper random_bits_of_length_126 =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT32_EXPONENT_BIAS - 1,
                                          (iteration_1_ + iteration_2_) * num_of_simd_total_);
    ShareWrapper random_floating_point_0_1_boolean_gmw_share =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .UniformFloatingPoint32_0_1(random_bits_of_length_23, random_bits_of_length_126);

    ShareWrapper random_unsigned_integer_boolean_gmw_gc_bmr_share;

    // generate differenty types of random unsigned integer,
    // this operation is expensive and the efficiency depends on the MPC protocol
    switch (fD_->Get()->GetProtocol()) {
      case MpcProtocol::kBooleanGmw: {
        random_unsigned_integer_boolean_gmw_gc_bmr_share =
            SecureSamplingAlgorithm_naive(fD_->Get())
                .GenerateRandomUnsignedInteger_BGMW<T, T_expand>(T(denominator_),
                                                                iteration_1_ * num_of_simd_total_);
        break;
      }
      case MpcProtocol::kGarbledCircuit: {
        random_unsigned_integer_boolean_gmw_gc_bmr_share =
            SecureSamplingAlgorithm_naive(fD_->Get())
                .GenerateRandomUnsignedInteger_GC<T, T_expand>(T(denominator_),
                                                              iteration_1_ * num_of_simd_total_);
        break;
      }
      case MpcProtocol::kBmr: {
        random_unsigned_integer_boolean_gmw_gc_bmr_share =
            SecureSamplingAlgorithm_naive(fD_->Get())
                .GenerateRandomUnsignedInteger_BMR<T, T_expand>(T(denominator_),
                                                               iteration_1_ * num_of_simd_total_);
        break;
      }
      default: {
        throw std::runtime_error("Unsupported protocol");
      }
    }

    // ShareWrapper random_unsigned_integer_boolean_gmw_share =
    //     SecureSamplingAlgorithm_naive(fD_->Get())
    //         .GenerateRandomUnsignedIntegerPow2BGMW<T>(log2_denominator_,
    //                                                   iteration_1_ * num_of_simd_total_);

    ShareWrapper boolean_gmw_share_bernoulli_sample =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(1, num_of_simd_total_);

    SecureSignedInteger signed_integer_discrete_laplace_noise =
        FL32DiscreteLaplaceNoiseGeneration_naive(random_floating_point_0_1_boolean_gmw_share,
                                                 random_unsigned_integer_boolean_gmw_gc_bmr_share,
                                                 boolean_gmw_share_bernoulli_sample);
    return signed_integer_discrete_laplace_noise;

  } else {
    ShareWrapper random_bits_of_length_23 =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT32_MANTISSA_BITS,
                                          (iteration_2_)*num_of_simd_total_);
    ShareWrapper random_bits_of_length_126 =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT32_EXPONENT_BIAS - 1,
                                          (iteration_2_)*num_of_simd_total_);
    ShareWrapper random_floating_point_0_1_boolean_gmw_share =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .UniformFloatingPoint32_0_1(random_bits_of_length_23, random_bits_of_length_126);

    ShareWrapper boolean_gmw_share_bernoulli_sample =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(1, num_of_simd_total_);

    SecureSignedInteger signed_integer_discrete_laplace_noise =
        FL32DiscreteLaplaceNoiseGeneration_naive(random_floating_point_0_1_boolean_gmw_share,
                                                 boolean_gmw_share_bernoulli_sample);

    return signed_integer_discrete_laplace_noise;
  }
}

SecureSignedInteger SecureDiscreteLaplaceMechanismCKS::FL32DiscreteLaplaceNoiseGeneration_naive(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_gc_bmr_share,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample) {
  //   num_of_simd_dlap_ = fD_->Get()->GetNumberOfSimdValues();

  assert(denominator_ != 1);

  std::vector<T> numerator_vector(num_of_simd_dlap_, numerator_);
  std::vector<T> denominator_vector(num_of_simd_dlap_, denominator_);

  std::vector<ShareWrapper> result_vector;

  switch (fD_->Get()->GetProtocol()) {
    case MpcProtocol::kBooleanGmw: {
      result_vector =
          SecureSamplingAlgorithm_naive(fD_->Get())
              .FLDiscreteLaplaceDistribution_BGMW<float, std::uint64_t, std::int64_t>(
                  numerator_vector, denominator_vector, random_floating_point_0_1_boolean_gmw_share,
                  random_unsigned_integer_boolean_gmw_gc_bmr_share,
                  boolean_gmw_share_bernoulli_sample, iteration_1_, iteration_2_, iteration_3_);
      break;
    }

    case MpcProtocol::kGarbledCircuit: {
      result_vector =
          SecureSamplingAlgorithm_naive(fD_->Get())
              .FLDiscreteLaplaceDistribution_GC<float, std::uint64_t, std::int64_t>(
                  numerator_vector, denominator_vector,
                  random_floating_point_0_1_boolean_gmw_share
                      .Convert<MpcProtocol::kGarbledCircuit>(),
                  random_unsigned_integer_boolean_gmw_gc_bmr_share,
                  boolean_gmw_share_bernoulli_sample.Convert<MpcProtocol::kGarbledCircuit>(),
                  iteration_1_, iteration_2_, iteration_3_);
      break;
    }

    case MpcProtocol::kBmr: {
      result_vector =
          SecureSamplingAlgorithm_naive(fD_->Get())
              .FLDiscreteLaplaceDistribution_BMR<float, std::uint64_t, std::int64_t>(
                  numerator_vector, denominator_vector,
                  random_floating_point_0_1_boolean_gmw_share.Convert<MpcProtocol::kBmr>(),
                  random_unsigned_integer_boolean_gmw_gc_bmr_share,
                  boolean_gmw_share_bernoulli_sample.Convert<MpcProtocol::kBmr>(), iteration_1_,
                  iteration_2_, iteration_3_);
      break;
    }

    default: {
      throw std::runtime_error("Unsupported protocol");
    }
  }

  ShareWrapper signed_integer_boolean_gmw_share_discrete_laplace_noise = result_vector[0];
  return SecureSignedInteger(signed_integer_boolean_gmw_share_discrete_laplace_noise);
}

SecureSignedInteger SecureDiscreteLaplaceMechanismCKS::FL32DiscreteLaplaceNoiseGeneration_naive(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample) {
  //   num_of_simd_dlap_ = fD_->Get()->GetNumberOfSimdValues();

  assert(denominator_ == 1);
  std::vector<T> numerator_vector(num_of_simd_dlap_, numerator_);
  // std::vector<T> denominator_vector(num_of_simd_dlap_, t_);

  std::vector<ShareWrapper> result_vector;

  //   result_vector = fD_->FLDiscreteLaplaceDistribution<float, std::uint64_t, std::int64_t>(
  //       numerator_vector, random_floating_point_0_1_boolean_gmw_share,
  //       boolean_gmw_share_bernoulli_sample, iteration_2_, iteration_3_);

  switch (fD_->Get()->GetProtocol()) {
    case MpcProtocol::kBooleanGmw: {
      result_vector = SecureSamplingAlgorithm_naive(fD_->Get())
                          .FLDiscreteLaplaceDistribution_BGMW<float, std::uint64_t, std::int64_t>(
                              numerator_vector, random_floating_point_0_1_boolean_gmw_share,
                              boolean_gmw_share_bernoulli_sample, iteration_2_, iteration_3_);
      break;
    }

    case MpcProtocol::kGarbledCircuit: {
      result_vector =
          SecureSamplingAlgorithm_naive(fD_->Get())
              .FLDiscreteLaplaceDistribution_GC<float, std::uint64_t, std::int64_t>(
                  numerator_vector,
                  random_floating_point_0_1_boolean_gmw_share
                      .Convert<MpcProtocol::kGarbledCircuit>(),
                  boolean_gmw_share_bernoulli_sample.Convert<MpcProtocol::kGarbledCircuit>(),
                  iteration_2_, iteration_3_);
      break;
    }

    case MpcProtocol::kBmr: {
      result_vector =
          SecureSamplingAlgorithm_naive(fD_->Get())
              .FLDiscreteLaplaceDistribution_BMR<float, std::uint64_t, std::int64_t>(
                  numerator_vector,
                  random_floating_point_0_1_boolean_gmw_share.Convert<MpcProtocol::kBmr>(),
                  boolean_gmw_share_bernoulli_sample.Convert<MpcProtocol::kBmr>(), iteration_2_,
                  iteration_3_);
      break;
    }

    default: {
      throw std::runtime_error("Unsupported protocol");
    }
  }

  ShareWrapper signed_integer_boolean_gmw_share_discrete_laplace_noise = result_vector[0];
  return SecureSignedInteger(signed_integer_boolean_gmw_share_discrete_laplace_noise);
}

// ============================================================
// ! optimized version
// 32-bit floating-point version

SecureSignedInteger
SecureDiscreteLaplaceMechanismCKS::FL32DiscreteLaplaceNoiseGeneration_optimized() {
  std::cout << "SecureDiscreteLaplaceMechanismCKS::FL32DiscreteLaplaceNoiseGeneration" << std::endl;
  if (denominator_ != T(1)) {
    ShareWrapper random_bits_of_length_23 =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT32_MANTISSA_BITS,
                                          (iteration_1_ + iteration_2_) * num_of_simd_total_);
    ShareWrapper random_bits_of_length_126 =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT32_EXPONENT_BIAS - 1,
                                          (iteration_1_ + iteration_2_) * num_of_simd_total_);
    ShareWrapper random_floating_point_0_1_boolean_gmw_share =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .UniformFloatingPoint32_0_1(random_bits_of_length_23, random_bits_of_length_126);

    // ShareWrapper random_unsigned_integer_boolean_gmw_share =
    //     fD_->GenerateRandomUnsignedInteger_BGMW(T(denominator_), iteration_1_ *
    //     num_of_simd_total_);

    ShareWrapper random_unsigned_integer_boolean_gmw_share =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomUnsignedIntegerPow2BGMW<T>(log2_denominator_,
                                                      iteration_1_ * num_of_simd_total_);

    ShareWrapper boolean_gmw_share_bernoulli_sample =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(1, num_of_simd_total_);

    SecureSignedInteger signed_integer_discrete_laplace_noise =
        FL32DiscreteLaplaceNoiseGeneration_optimized(random_floating_point_0_1_boolean_gmw_share,
                                                     random_unsigned_integer_boolean_gmw_share,
                                                     boolean_gmw_share_bernoulli_sample);
    return signed_integer_discrete_laplace_noise;

  } else {
    ShareWrapper random_bits_of_length_23 =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT32_MANTISSA_BITS,
                                          (iteration_2_)*num_of_simd_total_);
    ShareWrapper random_bits_of_length_126 =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT32_EXPONENT_BIAS - 1,
                                          (iteration_2_)*num_of_simd_total_);
    ShareWrapper random_floating_point_0_1_boolean_gmw_share =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .UniformFloatingPoint32_0_1(random_bits_of_length_23, random_bits_of_length_126);

    ShareWrapper boolean_gmw_share_bernoulli_sample =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(1, num_of_simd_total_);

    SecureSignedInteger signed_integer_discrete_laplace_noise =
        FL32DiscreteLaplaceNoiseGeneration_optimized(random_floating_point_0_1_boolean_gmw_share,
                                                     boolean_gmw_share_bernoulli_sample);

    return signed_integer_discrete_laplace_noise;
  }
}

SecureSignedInteger SecureDiscreteLaplaceMechanismCKS::FL32DiscreteLaplaceNoiseGeneration_optimized(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample) {
  //   num_of_simd_dlap_ = fD_->Get()->GetNumberOfSimdValues();

  assert(denominator_ != 1);

  std::vector<T> numerator_vector(num_of_simd_dlap_, numerator_);
  std::vector<T> denominator_vector(num_of_simd_dlap_, denominator_);

  std::vector<ShareWrapper> result_vector;

  switch (fD_->Get()->GetProtocol()) {
    case MpcProtocol::kBooleanGmw: {
      result_vector =
          SecureSamplingAlgorithm_optimized(fD_->Get())
              .FLDiscreteLaplaceDistribution_BGMW<float, std::uint64_t, std::int64_t>(
                  numerator_vector, denominator_vector, random_floating_point_0_1_boolean_gmw_share,
                  random_unsigned_integer_boolean_gmw_share, boolean_gmw_share_bernoulli_sample,
                  iteration_1_, iteration_2_, iteration_3_);
      break;
    }

    case MpcProtocol::kGarbledCircuit: {
      result_vector =
          SecureSamplingAlgorithm_optimized(fD_->Get())
              .FLDiscreteLaplaceDistribution_GC<float, std::uint64_t, std::int64_t>(
                  numerator_vector, denominator_vector,
                  random_floating_point_0_1_boolean_gmw_share
                      .Convert<MpcProtocol::kGarbledCircuit>(),
                  random_unsigned_integer_boolean_gmw_share.Convert<MpcProtocol::kGarbledCircuit>(),
                  boolean_gmw_share_bernoulli_sample.Convert<MpcProtocol::kGarbledCircuit>(),
                  iteration_1_, iteration_2_, iteration_3_);
      break;
    }

    case MpcProtocol::kBmr: {
      result_vector =
          SecureSamplingAlgorithm_optimized(fD_->Get())
              .FLDiscreteLaplaceDistribution_BMR<float, std::uint64_t, std::int64_t>(
                  numerator_vector, denominator_vector,
                  random_floating_point_0_1_boolean_gmw_share.Convert<MpcProtocol::kBmr>(),
                  random_unsigned_integer_boolean_gmw_share.Convert<MpcProtocol::kBmr>(),
                  boolean_gmw_share_bernoulli_sample.Convert<MpcProtocol::kBmr>(), iteration_1_,
                  iteration_2_, iteration_3_);
      break;
    }

    default: {
      throw std::runtime_error("Unsupported protocol");
    }
  }

  ShareWrapper signed_integer_boolean_gmw_share_discrete_laplace_noise = result_vector[0];
  return SecureSignedInteger(signed_integer_boolean_gmw_share_discrete_laplace_noise);
}

SecureSignedInteger SecureDiscreteLaplaceMechanismCKS::FL32DiscreteLaplaceNoiseGeneration_optimized(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample) {
  //   num_of_simd_dlap_ = fD_->Get()->GetNumberOfSimdValues();

  assert(denominator_ == 1);
  std::vector<T> numerator_vector(num_of_simd_dlap_, numerator_);
  // std::vector<T> denominator_vector(num_of_simd_dlap_, t_);

  std::vector<ShareWrapper> result_vector;

  //   result_vector = fD_->FLDiscreteLaplaceDistribution<float, std::uint64_t, std::int64_t>(
  //       numerator_vector, random_floating_point_0_1_boolean_gmw_share,
  //       boolean_gmw_share_bernoulli_sample, iteration_2_, iteration_3_);

  switch (fD_->Get()->GetProtocol()) {
    case MpcProtocol::kBooleanGmw: {
      result_vector = SecureSamplingAlgorithm_optimized(fD_->Get())
                          .FLDiscreteLaplaceDistribution_BGMW<float, std::uint64_t, std::int64_t>(
                              numerator_vector, random_floating_point_0_1_boolean_gmw_share,
                              boolean_gmw_share_bernoulli_sample, iteration_2_, iteration_3_);
      break;
    }

    case MpcProtocol::kGarbledCircuit: {
      result_vector =
          SecureSamplingAlgorithm_optimized(fD_->Get())
              .FLDiscreteLaplaceDistribution_GC<float, std::uint64_t, std::int64_t>(
                  numerator_vector,
                  random_floating_point_0_1_boolean_gmw_share
                      .Convert<MpcProtocol::kGarbledCircuit>(),
                  boolean_gmw_share_bernoulli_sample.Convert<MpcProtocol::kGarbledCircuit>(),
                  iteration_2_, iteration_3_);
      break;
    }

    case MpcProtocol::kBmr: {
      result_vector =
          SecureSamplingAlgorithm_optimized(fD_->Get())
              .FLDiscreteLaplaceDistribution_BMR<float, std::uint64_t, std::int64_t>(
                  numerator_vector,
                  random_floating_point_0_1_boolean_gmw_share.Convert<MpcProtocol::kBmr>(),
                  boolean_gmw_share_bernoulli_sample.Convert<MpcProtocol::kBmr>(), iteration_2_,
                  iteration_3_);
      break;
    }
    default: {
      throw std::runtime_error("Unsupported protocol");
    }
  }

  ShareWrapper signed_integer_boolean_gmw_share_discrete_laplace_noise = result_vector[0];
  return SecureSignedInteger(signed_integer_boolean_gmw_share_discrete_laplace_noise);
}

// ============================================================
// ! naive version
// 64-bit floating-point version
// SecureSignedInteger SecureDiscreteLaplaceMechanismCKS::FL64DiscreteLaplaceNoiseAddition() {
//   SecureSignedInteger signed_integer_noisy_fD =
//       SecureSignedInteger(fD_->Get()) + FL64DiscreteLaplaceNoiseGeneration();
//   noisy_fD_ = std::make_unique<ShareWrapper>(signed_integer_noisy_fD.Get().Get());
//   return signed_integer_noisy_fD;
// }

SecureSignedInteger SecureDiscreteLaplaceMechanismCKS::FL64DiscreteLaplaceNoiseGeneration_naive() {
  std::cout << "SecureDiscreteLaplaceMechanismCKS::FL64DiscreteLaplaceNoiseGeneration" << std::endl;
  if (denominator_ != T(1)) {
    // std::cout << "000" << std::endl;
    ShareWrapper random_bits_of_length_52 =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT64_MANTISSA_BITS,
                                          (iteration_1_ + iteration_2_) * num_of_simd_total_);
    ShareWrapper random_bits_of_length_1022 =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT64_EXPONENT_BIAS - 1,
                                          (iteration_1_ + iteration_2_) * num_of_simd_total_);
    // std::cout << "111" << std::endl;
    ShareWrapper random_floating_point_0_1_boolean_gmw_share =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .UniformFloatingPoint64_0_1(random_bits_of_length_52, random_bits_of_length_1022);

    // std::cout << "222" << std::endl;
    // ShareWrapper random_unsigned_integer_boolean_gmw_share =
    //     fD_->GenerateRandomUnsignedInteger_BGMW(T(denominator_), iteration_1_ *
    //     num_of_simd_total_);

    // ShareWrapper random_unsigned_integer_boolean_gmw_share =
    //     fD_->GenerateRandomUnsignedIntegerPow2BGMW<T>(log2_denominator_,
    //                                                   iteration_1_ * num_of_simd_total_);

    ShareWrapper random_unsigned_integer_boolean_gmw_gc_bmr_share;

    // generate differenty types of random unsigned integer,
    // this operation is expensive and the efficiency depends on the MPC protocol
    switch (fD_->Get()->GetProtocol()) {
      case MpcProtocol::kBooleanGmw: {
        random_unsigned_integer_boolean_gmw_gc_bmr_share =
            SecureSamplingAlgorithm_naive(fD_->Get())
                .GenerateRandomUnsignedInteger_BGMW<T, T_expand>(T(denominator_),
                                                                iteration_1_ * num_of_simd_total_);
        break;
      }
      case MpcProtocol::kGarbledCircuit: {
        random_unsigned_integer_boolean_gmw_gc_bmr_share =
            SecureSamplingAlgorithm_naive(fD_->Get())
                .GenerateRandomUnsignedInteger_GC<T, T_expand>(T(denominator_),
                                                              iteration_1_ * num_of_simd_total_);
        break;
      }
      case MpcProtocol::kBmr: {
        random_unsigned_integer_boolean_gmw_gc_bmr_share =
            SecureSamplingAlgorithm_naive(fD_->Get())
                .GenerateRandomUnsignedInteger_BMR<T, T_expand>(T(denominator_),
                                                               iteration_1_ * num_of_simd_total_);
        break;
      }
      default: {
        throw std::runtime_error("Unsupported protocol");
      }
    }

    // std::cout << "333" << std::endl;
    ShareWrapper boolean_gmw_share_bernoulli_sample =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(1, num_of_simd_total_);

    SecureSignedInteger signed_integer_discrete_laplace_noise =
        FL64DiscreteLaplaceNoiseGeneration_naive(random_floating_point_0_1_boolean_gmw_share,
                                                 random_unsigned_integer_boolean_gmw_gc_bmr_share,
                                                 boolean_gmw_share_bernoulli_sample);
    return signed_integer_discrete_laplace_noise;

  } else {
    ShareWrapper random_bits_of_length_52 =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT64_MANTISSA_BITS,
                                          (iteration_2_)*num_of_simd_total_);
    ShareWrapper random_bits_of_length_1022 =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT64_EXPONENT_BIAS - 1,
                                          (iteration_2_)*num_of_simd_total_);
    ShareWrapper random_floating_point_0_1_boolean_gmw_share =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .UniformFloatingPoint64_0_1(random_bits_of_length_52, random_bits_of_length_1022);

    ShareWrapper boolean_gmw_share_bernoulli_sample =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(1, num_of_simd_total_);

    SecureSignedInteger signed_integer_discrete_laplace_noise =
        FL64DiscreteLaplaceNoiseGeneration_naive(random_floating_point_0_1_boolean_gmw_share,
                                                 boolean_gmw_share_bernoulli_sample);

    return signed_integer_discrete_laplace_noise;
  }
}

SecureSignedInteger SecureDiscreteLaplaceMechanismCKS::FL64DiscreteLaplaceNoiseGeneration_naive(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_gc_bmr_share,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample) {
  //   num_of_simd_dlap_ = fD_->Get()->GetNumberOfSimdValues();

  assert(denominator_ != 1);

  std::vector<T> numerator_vector(num_of_simd_dlap_, numerator_);
  std::vector<T> denominator_vector(num_of_simd_dlap_, denominator_);

  std::vector<ShareWrapper> result_vector;

  switch (fD_->Get()->GetProtocol()) {
    case MpcProtocol::kBooleanGmw: {
      result_vector =
          SecureSamplingAlgorithm_naive(fD_->Get())
              .FLDiscreteLaplaceDistribution_BGMW<double, std::uint64_t, std::int64_t>(
                  numerator_vector, denominator_vector, random_floating_point_0_1_boolean_gmw_share,
                  random_unsigned_integer_boolean_gmw_gc_bmr_share,
                  boolean_gmw_share_bernoulli_sample, iteration_1_, iteration_2_, iteration_3_);
      break;
    }
    case MpcProtocol::kGarbledCircuit: {
      result_vector =
          SecureSamplingAlgorithm_naive(fD_->Get())
              .FLDiscreteLaplaceDistribution_GC<double, std::uint64_t, std::int64_t>(
                  numerator_vector, denominator_vector,
                  random_floating_point_0_1_boolean_gmw_share
                      .Convert<MpcProtocol::kGarbledCircuit>(),
                  random_unsigned_integer_boolean_gmw_gc_bmr_share,
                  boolean_gmw_share_bernoulli_sample.Convert<MpcProtocol::kGarbledCircuit>(),
                  iteration_1_, iteration_2_, iteration_3_);
      break;
    }

    case MpcProtocol::kBmr: {
      result_vector =
          SecureSamplingAlgorithm_naive(fD_->Get())
              .FLDiscreteLaplaceDistribution_BMR<double, std::uint64_t, std::int64_t>(
                  numerator_vector, denominator_vector,
                  random_floating_point_0_1_boolean_gmw_share.Convert<MpcProtocol::kBmr>(),
                  random_unsigned_integer_boolean_gmw_gc_bmr_share,
                  boolean_gmw_share_bernoulli_sample.Convert<MpcProtocol::kBmr>(), iteration_1_,
                  iteration_2_, iteration_3_);
      break;
    }

    default: {
      throw std::runtime_error("Unsupported protocol");
    }
  }

  ShareWrapper signed_integer_boolean_gmw_share_discrete_laplace_noise = result_vector[0];
  return SecureSignedInteger(signed_integer_boolean_gmw_share_discrete_laplace_noise);
}

SecureSignedInteger SecureDiscreteLaplaceMechanismCKS::FL64DiscreteLaplaceNoiseGeneration_naive(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample) {
  //   num_of_simd_dlap_ = fD_->Get()->GetNumberOfSimdValues();

  assert(denominator_ == 1);
  std::vector<T> numerator_vector(num_of_simd_dlap_, numerator_);
  // std::vector<T> denominator_vector(num_of_simd_dlap_, t_);

  std::vector<ShareWrapper> result_vector;

  switch (fD_->Get()->GetProtocol()) {
    case MpcProtocol::kBooleanGmw: {
      result_vector = SecureSamplingAlgorithm_naive(fD_->Get())
                          .FLDiscreteLaplaceDistribution_BGMW<double, std::uint64_t, std::int64_t>(
                              numerator_vector, random_floating_point_0_1_boolean_gmw_share,
                              boolean_gmw_share_bernoulli_sample, iteration_2_, iteration_3_);
      break;
    }

    case MpcProtocol::kGarbledCircuit: {
      result_vector =
          SecureSamplingAlgorithm_naive(fD_->Get())
              .FLDiscreteLaplaceDistribution_GC<double, std::uint64_t, std::int64_t>(
                  numerator_vector,
                  random_floating_point_0_1_boolean_gmw_share
                      .Convert<MpcProtocol::kGarbledCircuit>(),
                  boolean_gmw_share_bernoulli_sample.Convert<MpcProtocol::kGarbledCircuit>(),
                  iteration_2_, iteration_3_);
      break;
    }

    case MpcProtocol::kBmr: {
      result_vector =
          SecureSamplingAlgorithm_naive(fD_->Get())
              .FLDiscreteLaplaceDistribution_BMR<double, std::uint64_t, std::int64_t>(
                  numerator_vector,
                  random_floating_point_0_1_boolean_gmw_share.Convert<MpcProtocol::kBmr>(),
                  boolean_gmw_share_bernoulli_sample.Convert<MpcProtocol::kBmr>(), iteration_2_,
                  iteration_3_);
      break;
    }

    default: {
      throw std::runtime_error("Unsupported protocol");
    }
  }

  ShareWrapper signed_integer_boolean_gmw_share_discrete_laplace_noise = result_vector[0];
  return SecureSignedInteger(signed_integer_boolean_gmw_share_discrete_laplace_noise);
}

// ============================================================
// ! optimized version
// 64-bit floating-point version
// SecureSignedInteger SecureDiscreteLaplaceMechanismCKS::FL64DiscreteLaplaceNoiseAddition() {
//   SecureSignedInteger signed_integer_noisy_fD =
//       SecureSignedInteger(fD_->Get()) + FL64DiscreteLaplaceNoiseGeneration();
//   noisy_fD_ = std::make_unique<ShareWrapper>(signed_integer_noisy_fD.Get().Get());
//   return signed_integer_noisy_fD;
// }

SecureSignedInteger
SecureDiscreteLaplaceMechanismCKS::FL64DiscreteLaplaceNoiseGeneration_optimized() {
  std::cout << "SecureDiscreteLaplaceMechanismCKS::FL64DiscreteLaplaceNoiseGeneration" << std::endl;
  if (denominator_ != T(1)) {
    // std::cout << "000" << std::endl;
    ShareWrapper random_bits_of_length_52 =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT64_MANTISSA_BITS,
                                          (iteration_1_ + iteration_2_) * num_of_simd_total_);
    ShareWrapper random_bits_of_length_1022 =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT64_EXPONENT_BIAS - 1,
                                          (iteration_1_ + iteration_2_) * num_of_simd_total_);
    // std::cout << "111" << std::endl;
    ShareWrapper random_floating_point_0_1_boolean_gmw_share =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .UniformFloatingPoint64_0_1(random_bits_of_length_52, random_bits_of_length_1022);

    ShareWrapper random_unsigned_integer_boolean_gmw_share =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomUnsignedIntegerPow2BGMW<T>(log2_denominator_,
                                                      iteration_1_ * num_of_simd_total_);

    // std::cout << "333" << std::endl;
    ShareWrapper boolean_gmw_share_bernoulli_sample =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(1, num_of_simd_total_);

    SecureSignedInteger signed_integer_discrete_laplace_noise =
        FL64DiscreteLaplaceNoiseGeneration_optimized(random_floating_point_0_1_boolean_gmw_share,
                                                     random_unsigned_integer_boolean_gmw_share,
                                                     boolean_gmw_share_bernoulli_sample);
    return signed_integer_discrete_laplace_noise;

  } else {
    ShareWrapper random_bits_of_length_52 =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT64_MANTISSA_BITS,
                                          (iteration_2_)*num_of_simd_total_);
    ShareWrapper random_bits_of_length_1022 =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT64_EXPONENT_BIAS - 1,
                                          (iteration_2_)*num_of_simd_total_);
    ShareWrapper random_floating_point_0_1_boolean_gmw_share =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .UniformFloatingPoint64_0_1(random_bits_of_length_52, random_bits_of_length_1022);

    ShareWrapper boolean_gmw_share_bernoulli_sample =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(1, num_of_simd_total_);

    SecureSignedInteger signed_integer_discrete_laplace_noise =
        FL64DiscreteLaplaceNoiseGeneration_optimized(random_floating_point_0_1_boolean_gmw_share,
                                                     boolean_gmw_share_bernoulli_sample);

    return signed_integer_discrete_laplace_noise;
  }
}

SecureSignedInteger SecureDiscreteLaplaceMechanismCKS::FL64DiscreteLaplaceNoiseGeneration_optimized(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample) {
  //   num_of_simd_dlap_ = fD_->Get()->GetNumberOfSimdValues();

  assert(denominator_ != 1);

  std::vector<T> numerator_vector(num_of_simd_dlap_, numerator_);
  std::vector<T> denominator_vector(num_of_simd_dlap_, denominator_);

  std::vector<ShareWrapper> result_vector;

  switch (fD_->Get()->GetProtocol()) {
    case MpcProtocol::kBooleanGmw: {
      result_vector =
          SecureSamplingAlgorithm_optimized(fD_->Get())
              .FLDiscreteLaplaceDistribution_BGMW<double, std::uint64_t, std::int64_t>(
                  numerator_vector, denominator_vector, random_floating_point_0_1_boolean_gmw_share,
                  random_unsigned_integer_boolean_gmw_share, boolean_gmw_share_bernoulli_sample,
                  iteration_1_, iteration_2_, iteration_3_);
      break;
    }
    case MpcProtocol::kGarbledCircuit: {
      result_vector =
          SecureSamplingAlgorithm_optimized(fD_->Get())
              .FLDiscreteLaplaceDistribution_GC<double, std::uint64_t, std::int64_t>(
                  numerator_vector, denominator_vector,
                  random_floating_point_0_1_boolean_gmw_share
                      .Convert<MpcProtocol::kGarbledCircuit>(),
                  random_unsigned_integer_boolean_gmw_share.Convert<MpcProtocol::kGarbledCircuit>(),
                  boolean_gmw_share_bernoulli_sample.Convert<MpcProtocol::kGarbledCircuit>(),
                  iteration_1_, iteration_2_, iteration_3_);
      break;
    }

    case MpcProtocol::kBmr: {
      result_vector =
          SecureSamplingAlgorithm_optimized(fD_->Get())
              .FLDiscreteLaplaceDistribution_BMR<double, std::uint64_t, std::int64_t>(
                  numerator_vector, denominator_vector,
                  random_floating_point_0_1_boolean_gmw_share.Convert<MpcProtocol::kBmr>(),
                  random_unsigned_integer_boolean_gmw_share.Convert<MpcProtocol::kBmr>(),
                  boolean_gmw_share_bernoulli_sample.Convert<MpcProtocol::kBmr>(), iteration_1_,
                  iteration_2_, iteration_3_);
      break;
    }

    default: {
      throw std::runtime_error("Unsupported protocol");
    }
  }

  ShareWrapper signed_integer_boolean_gmw_share_discrete_laplace_noise = result_vector[0];
  return SecureSignedInteger(signed_integer_boolean_gmw_share_discrete_laplace_noise);
}

SecureSignedInteger SecureDiscreteLaplaceMechanismCKS::FL64DiscreteLaplaceNoiseGeneration_optimized(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample) {
  //   num_of_simd_dlap_ = fD_->Get()->GetNumberOfSimdValues();

  assert(denominator_ == 1);
  std::vector<T> numerator_vector(num_of_simd_dlap_, numerator_);
  // std::vector<T> denominator_vector(num_of_simd_dlap_, t_);

  std::vector<ShareWrapper> result_vector;

  switch (fD_->Get()->GetProtocol()) {
    case MpcProtocol::kBooleanGmw: {
      result_vector = SecureSamplingAlgorithm_optimized(fD_->Get())
                          .FLDiscreteLaplaceDistribution_BGMW<double, std::uint64_t, std::int64_t>(
                              numerator_vector, random_floating_point_0_1_boolean_gmw_share,
                              boolean_gmw_share_bernoulli_sample, iteration_2_, iteration_3_);
      break;
    }

    case MpcProtocol::kGarbledCircuit: {
      result_vector =
          SecureSamplingAlgorithm_optimized(fD_->Get())
              .FLDiscreteLaplaceDistribution_GC<double, std::uint64_t, std::int64_t>(
                  numerator_vector,
                  random_floating_point_0_1_boolean_gmw_share
                      .Convert<MpcProtocol::kGarbledCircuit>(),
                  boolean_gmw_share_bernoulli_sample.Convert<MpcProtocol::kGarbledCircuit>(),
                  iteration_2_, iteration_3_);
      break;
    }

    case MpcProtocol::kBmr: {
      result_vector =
          SecureSamplingAlgorithm_optimized(fD_->Get())
              .FLDiscreteLaplaceDistribution_BMR<double, std::uint64_t, std::int64_t>(
                  numerator_vector,
                  random_floating_point_0_1_boolean_gmw_share.Convert<MpcProtocol::kBmr>(),
                  boolean_gmw_share_bernoulli_sample.Convert<MpcProtocol::kBmr>(), iteration_2_,
                  iteration_3_);
      break;
    }

    default: {
      throw std::runtime_error("Unsupported protocol");
    }
  }

  ShareWrapper signed_integer_boolean_gmw_share_discrete_laplace_noise = result_vector[0];
  return SecureSignedInteger(signed_integer_boolean_gmw_share_discrete_laplace_noise);
}

}  // namespace encrypto::motion