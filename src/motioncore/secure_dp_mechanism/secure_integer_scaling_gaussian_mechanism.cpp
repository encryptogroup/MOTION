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

  SymmetricalBinomialDistributionOptimizationStruct
      optimize_symmetrical_binomial_distribution_iteration_result_struct =
          optimize_symmetrical_binomial_distribution_iteration(sqrtN_,
                                                               failure_probability_requirement_);

  iteration_ = optimize_symmetrical_binomial_distribution_iteration_result_struct.iteration;
  total_failure_probability_ = optimize_symmetrical_binomial_distribution_iteration_result_struct
                                   .symmetrical_binomial_failure_probability_estimation;

  std::cout << "2.0 * sigma_ / binomial_bound_: " << 2.0 * sigma_ / binomial_bound_ << std::endl;
  std::cout << "resolution_r_: " << resolution_r_ << std::endl;
  std::cout << "sqrtN_: " << sqrtN_ << std::endl;
  std::cout << "m_: " << m_ << std::endl;
  std::cout << "iteration_: " << iteration_ << std::endl;
  std::cout << "total_failure_probability_: " << total_failure_probability_ << std::endl;
  std::cout << std::endl;
}

// SecureFloatingPointCircuitABY SecureIntegerScalingGaussianMechanism::FLGaussianNoiseAddition() {
//   SecureFloatingPointCircuitABY floating_point_noisy_fD =
//       SecureFloatingPointCircuitABY(fD_->Get()) + FLGaussianNoiseGeneration();
//   noisy_fD_ = std::make_unique<ShareWrapper>(floating_point_noisy_fD.Get().Get());
//   return floating_point_noisy_fD;
// }

// ! naive version
SecureFloatingPointCircuitABY
SecureIntegerScalingGaussianMechanism::FLGaussianNoiseGeneration_naive() {
  std::cout << "SecureIntegerScalingGaussianMechanism::FLGaussianNoiseGeneration_naive" << std::endl;
  std::size_t geometric_distribution_sampling_bit_length = 100;
  ShareWrapper random_bits_for_geometric_sampling =
      SecureSamplingAlgorithm_naive(fD_->Get())
          .GenerateRandomBooleanGmwBits(geometric_distribution_sampling_bit_length,
                                        iteration_ * num_of_simd_gau_);
  ShareWrapper boolean_gmw_share_geometric_sample =
      SecureSamplingAlgorithm_naive(fD_->Get())
          .SimpleGeometricSampling_0(random_bits_for_geometric_sampling);

  ShareWrapper unsigned_integer_boolean_gmw_share_geometric_sample =
      SecureSamplingAlgorithm_naive(fD_->Get())
          .BooleanBitsShareZeroCompensation(boolean_gmw_share_geometric_sample,
                                            FLOATINGPOINT64_BITS);


  ShareWrapper boolean_gmw_share_random_bits =
      SecureSamplingAlgorithm_naive(fD_->Get())
          .GenerateRandomBooleanGmwBits(1, iteration_ * num_of_simd_gau_);

  ShareWrapper random_unsigned_integer_boolean_gmw_gc_bmr_share;
  switch (fD_->Get()->GetProtocol()) {
    case MpcProtocol::kBooleanGmw: {
      random_unsigned_integer_boolean_gmw_gc_bmr_share =
          SecureSamplingAlgorithm_naive(fD_->Get())
              .GenerateRandomUnsignedInteger_BGMW<T, T_expand>(m_, iteration_ * num_of_simd_gau_);
      break;
    }

    case MpcProtocol::kGarbledCircuit: {
      random_unsigned_integer_boolean_gmw_gc_bmr_share =
          SecureSamplingAlgorithm_naive(fD_->Get())
              .GenerateRandomUnsignedInteger_GC<T, T_expand>(m_, iteration_ * num_of_simd_gau_);
      break;
    }

    case MpcProtocol::kBmr: {
      random_unsigned_integer_boolean_gmw_gc_bmr_share =
          SecureSamplingAlgorithm_naive(fD_->Get())
              .GenerateRandomUnsignedInteger_BMR<T, T_expand>(m_, iteration_ * num_of_simd_gau_);
      break;
    }

    default: {
      throw std::runtime_error("Unsupported protocol");
    }
  }

  // ShareWrapper random_unsigned_integer_boolean_gmw_gc_bmr_share =
  //     SecureSamplingAlgorithm_optimized(fD_->Get())
  //         .GenerateRandomUnsignedInteger_BGMW(m_, iteration_ * num_of_simd_gau_);

  ShareWrapper random_bits_of_length_52 =
      SecureSamplingAlgorithm_naive(fD_->Get())
          .GenerateRandomBooleanGmwBits(FLOATINGPOINT64_MANTISSA_BITS,
                                        iteration_ * num_of_simd_gau_);
  ShareWrapper random_bits_of_length_1022 =
      SecureSamplingAlgorithm_naive(fD_->Get())
          .GenerateRandomBooleanGmwBits(FLOATINGPOINT64_EXPONENT_BIAS - 1,
                                        iteration_ * num_of_simd_gau_);
  ShareWrapper random_floating_point_0_1_boolean_gmw_share =
      SecureSamplingAlgorithm_naive(fD_->Get())
          .UniformFloatingPoint64_0_1(random_bits_of_length_52, random_bits_of_length_1022);

  SecureFloatingPointCircuitABY floating_point_gaussian_noise = FLGaussianNoiseGeneration_naive(
      unsigned_integer_boolean_gmw_share_geometric_sample, boolean_gmw_share_random_bits,
      random_unsigned_integer_boolean_gmw_gc_bmr_share,
      random_floating_point_0_1_boolean_gmw_share);

  return floating_point_gaussian_noise;
}

SecureFloatingPointCircuitABY
SecureIntegerScalingGaussianMechanism::FLGaussianNoiseGeneration_naive(
    const ShareWrapper& unsigned_integer_boolean_gmw_share_geometric_sample,
    const ShareWrapper& boolean_gmw_share_random_bits,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_gc_bmr_share,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share) {
  std::vector<double> constant_sqrt_n_vector(num_of_simd_gau_, sqrtN_);

  // sqrtN * sqrt(2) > 2^(64)
  // use 128-bit unsigned integer and 64-bit floating point
  if ((sqrtN_ * M_SQRT2 + 1) * 1.5 >= std::exp2(63)) {
    std::cout << "FLGaussianNoiseGeneration_naive use __uint128_t" << std::endl;
    // extend 64-bit unsigned_integer_boolean_gmw_share_geometric_sample, and 64-bit
    // random_unsigned_integer_boolean_gmw_share to 128-bit

    ShareWrapper unsigned_integer_boolean_gmw_share_geometric_sample_extension =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .BooleanBitsShareZeroCompensation(unsigned_integer_boolean_gmw_share_geometric_sample,
                                              sizeof(T_expand) * 8);
    std::cout << "unsigned_integer_boolean_gmw_share_geometric_sample" << std::endl;

    ShareWrapper random_unsigned_integer_boolean_gmw_gc_bmr_share_extension =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .BooleanBitsShareZeroCompensation(random_unsigned_integer_boolean_gmw_gc_bmr_share,
                                              sizeof(T_expand) * 8);
    std::cout << "random_unsigned_integer_boolean_gmw_gc_bmr_share_extension" << std::endl;

    // TODO: need test
    std::vector<ShareWrapper> result_vector;

    //  =
    //     SecureSamplingAlgorithm_naive(fD_->Get())
    //         .FLSymmetricBinomialDistribution<double, __uint128_t, __int128_t>(
    //             constant_sqrt_n_vector,
    //             unsigned_integer_boolean_gmw_share_geometric_sample_extension,
    //             boolean_gmw_share_random_bits,
    //             random_unsigned_integer_boolean_gmw_share_extension,
    //             random_floating_point_0_1_boolean_gmw_share, iteration_);

    switch (fD_->Get()->GetProtocol()) {
      case MpcProtocol::kBooleanGmw: {
        result_vector = SecureSamplingAlgorithm_naive(fD_->Get())
                            .FLSymmetricBinomialDistribution_BGMW<double, T_expand>(
                                constant_sqrt_n_vector,
                                unsigned_integer_boolean_gmw_share_geometric_sample_extension,
                                boolean_gmw_share_random_bits,
                                random_unsigned_integer_boolean_gmw_gc_bmr_share_extension,
                                random_floating_point_0_1_boolean_gmw_share, iteration_);
        break;
      }

      case MpcProtocol::kGarbledCircuit: {
        result_vector =
            SecureSamplingAlgorithm_naive(fD_->Get())
                .FLSymmetricBinomialDistribution_GC<double, T_expand>(
                    constant_sqrt_n_vector,
                    unsigned_integer_boolean_gmw_share_geometric_sample_extension
                        .Convert<MpcProtocol::kGarbledCircuit>(),
                    boolean_gmw_share_random_bits.Convert<MpcProtocol::kGarbledCircuit>(),
                    random_unsigned_integer_boolean_gmw_gc_bmr_share_extension,
                    random_floating_point_0_1_boolean_gmw_share
                        .Convert<MpcProtocol::kGarbledCircuit>(),
                    iteration_);
        break;
      }

      case MpcProtocol::kBmr: {
        result_vector =
            SecureSamplingAlgorithm_naive(fD_->Get())
                .FLSymmetricBinomialDistribution_BMR<double, T_expand>(
                    constant_sqrt_n_vector,
                    unsigned_integer_boolean_gmw_share_geometric_sample_extension
                        .Convert<MpcProtocol::kBmr>(),
                    boolean_gmw_share_random_bits.Convert<MpcProtocol::kBmr>(),
                    random_unsigned_integer_boolean_gmw_gc_bmr_share_extension,
                    random_floating_point_0_1_boolean_gmw_share.Convert<MpcProtocol::kBmr>(),
                    iteration_);
        break;
      }

      default: {
        throw std::runtime_error("Unsupported protocol");
      }
    }

    ShareWrapper signed_integer_boolean_gmw_gc_bmr_share_symmetric_binomial_noise =
        result_vector[0];

    // less efficient method
    return SecureSignedInteger(signed_integer_boolean_gmw_gc_bmr_share_symmetric_binomial_noise)
               .Int2FL(sizeof(double) * 8) *
           double(resolution_r_);
  }

  // sqrtN * sqrt(2) < 2^(64)
  // use 64-bit unsigned integer and 64-bit floating point
  // std::int64_t overflow with low probability p = 2 ^ (-47)
  else {
    std::vector<ShareWrapper> result_vector;

    // =
    //     SecureSamplingAlgorithm_naive(fD_->Get())
    //         .FLSymmetricBinomialDistribution_BMR<double, T>(
    //             constant_sqrt_n_vector, unsigned_integer_boolean_gmw_share_geometric_sample,
    //             boolean_gmw_share_random_bits, random_unsigned_integer_boolean_gmw_gc_bmr_share,
    //             random_floating_point_0_1_boolean_gmw_share, iteration_);

    switch (fD_->Get()->GetProtocol()) {
      case MpcProtocol::kBooleanGmw: {
        result_vector =
            SecureSamplingAlgorithm_naive(fD_->Get())
                .FLSymmetricBinomialDistribution_BGMW<double, T>(
                    constant_sqrt_n_vector, unsigned_integer_boolean_gmw_share_geometric_sample,
                    boolean_gmw_share_random_bits, random_unsigned_integer_boolean_gmw_gc_bmr_share,
                    random_floating_point_0_1_boolean_gmw_share, iteration_);
        break;
      }

      case MpcProtocol::kGarbledCircuit: {
        result_vector =
            SecureSamplingAlgorithm_naive(fD_->Get())
                .FLSymmetricBinomialDistribution_GC<double, T>(
                    constant_sqrt_n_vector,
                    unsigned_integer_boolean_gmw_share_geometric_sample
                        .Convert<MpcProtocol::kGarbledCircuit>(),
                    boolean_gmw_share_random_bits.Convert<MpcProtocol::kGarbledCircuit>(),
                    random_unsigned_integer_boolean_gmw_gc_bmr_share,
                    random_floating_point_0_1_boolean_gmw_share
                        .Convert<MpcProtocol::kGarbledCircuit>(),
                    iteration_);
        break;
      }

      case MpcProtocol::kBmr: {
        result_vector =
            SecureSamplingAlgorithm_naive(fD_->Get())
                .FLSymmetricBinomialDistribution_BMR<double, T>(
                    constant_sqrt_n_vector,
                    unsigned_integer_boolean_gmw_share_geometric_sample
                        .Convert<MpcProtocol::kBmr>(),
                    boolean_gmw_share_random_bits.Convert<MpcProtocol::kBmr>(),
                    random_unsigned_integer_boolean_gmw_gc_bmr_share,
                    random_floating_point_0_1_boolean_gmw_share.Convert<MpcProtocol::kBmr>(),
                    iteration_);
        break;
      }

      default: {
        throw std::runtime_error("Unsupported protocol");
      }
    }

    ShareWrapper signed_integer_boolean_gmw_share_symmetric_binomial_noise = result_vector[0];
    return SecureSignedInteger(signed_integer_boolean_gmw_share_symmetric_binomial_noise)
               .Int2FL(sizeof(double) * 8) *
           double(resolution_r_);
  }
}

// ! optimized version
SecureFloatingPointCircuitABY
SecureIntegerScalingGaussianMechanism::FLGaussianNoiseGeneration_optimized() {
  std::cout << "SecureIntegerScalingGaussianMechanism::FLGaussianNoiseGeneration" << std::endl;
  std::size_t geometric_distribution_sampling_bit_length = 100;
  ShareWrapper random_bits_for_geometric_sampling =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .GenerateRandomBooleanGmwBits(geometric_distribution_sampling_bit_length,
                                        iteration_ * num_of_simd_gau_);
  ShareWrapper boolean_gmw_share_geometric_sample =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .SimpleGeometricSampling_0(random_bits_for_geometric_sampling);
  ShareWrapper unsigned_integer_boolean_gmw_share_geometric_sample =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .BooleanBitsShareZeroCompensation(boolean_gmw_share_geometric_sample,
                                            FLOATINGPOINT64_BITS);

  ShareWrapper boolean_gmw_share_random_bits =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .GenerateRandomBooleanGmwBits(1, iteration_ * num_of_simd_gau_);

  ShareWrapper random_unsigned_integer_boolean_gmw_share =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .GenerateRandomUnsignedIntegerPow2_BGMW<T>(m_, iteration_ * num_of_simd_gau_);

  ShareWrapper random_bits_of_length_52 =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .GenerateRandomBooleanGmwBits(FLOATINGPOINT64_MANTISSA_BITS,
                                        iteration_ * num_of_simd_gau_);
  ShareWrapper random_bits_of_length_1022 =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .GenerateRandomBooleanGmwBits(FLOATINGPOINT64_EXPONENT_BIAS - 1,
                                        iteration_ * num_of_simd_gau_);
  ShareWrapper random_floating_point_0_1_boolean_gmw_share =
      SecureSamplingAlgorithm_optimized(fD_->Get())
          .UniformFloatingPoint64_0_1(random_bits_of_length_52, random_bits_of_length_1022);

  SecureFloatingPointCircuitABY floating_point_gaussian_noise = FLGaussianNoiseGeneration_optimized(
      unsigned_integer_boolean_gmw_share_geometric_sample, boolean_gmw_share_random_bits,
      random_unsigned_integer_boolean_gmw_share, random_floating_point_0_1_boolean_gmw_share);

  return floating_point_gaussian_noise;
}

SecureFloatingPointCircuitABY
SecureIntegerScalingGaussianMechanism::FLGaussianNoiseGeneration_optimized(
    const ShareWrapper& unsigned_integer_boolean_gmw_share_geometric_sample,
    const ShareWrapper& boolean_gmw_share_random_bits,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share) {
  std::vector<double> constant_sqrt_n_vector(num_of_simd_gau_, sqrtN_);

  // sqrtN * sqrt(2) > 2^(64)
  // use 128-bit unsigned integer and 64-bit floating point
  if ((sqrtN_ * M_SQRT2 + 1) * 1.5 >= std::exp2(63)) {
    std::cout << "FLGaussianNoiseGeneration use __uint128_t" << std::endl;
    // extend 64-bit unsigned_integer_boolean_gmw_share_geometric_sample, and 64-bit
    // random_unsigned_integer_boolean_gmw_share to 128-bit

    ShareWrapper unsigned_integer_boolean_gmw_share_geometric_sample_extension =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .BooleanBitsShareZeroCompensation(unsigned_integer_boolean_gmw_share_geometric_sample,
                                              sizeof(T_expand) * 8);
    ShareWrapper random_unsigned_integer_boolean_gmw_share_extension =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .BooleanBitsShareZeroCompensation(random_unsigned_integer_boolean_gmw_share,
                                              sizeof(T_expand) * 8);

    // TODO: need test
    std::vector<ShareWrapper> result_vector;

    //  =
    //     SecureSamplingAlgorithm_optimized(fD_->Get())
    //         .FLSymmetricBinomialDistribution<double, __uint128_t, __int128_t>(
    //             constant_sqrt_n_vector,
    //             unsigned_integer_boolean_gmw_share_geometric_sample_extension,
    //             boolean_gmw_share_random_bits,
    //             random_unsigned_integer_boolean_gmw_share_extension,
    //             random_floating_point_0_1_boolean_gmw_share, iteration_);

    switch (fD_->Get()->GetProtocol()) {
      case MpcProtocol::kBooleanGmw: {
        result_vector = SecureSamplingAlgorithm_optimized(fD_->Get())
                            .FLSymmetricBinomialDistribution_BGMW<double, T_expand>(
                                constant_sqrt_n_vector,
                                unsigned_integer_boolean_gmw_share_geometric_sample_extension,
                                boolean_gmw_share_random_bits,
                                random_unsigned_integer_boolean_gmw_share_extension,
                                random_floating_point_0_1_boolean_gmw_share, iteration_);
        break;
      }

      case MpcProtocol::kGarbledCircuit: {
        result_vector =
            SecureSamplingAlgorithm_optimized(fD_->Get())
                .FLSymmetricBinomialDistribution_GC<double, T_expand>(
                    constant_sqrt_n_vector,
                    unsigned_integer_boolean_gmw_share_geometric_sample_extension
                        .Convert<MpcProtocol::kGarbledCircuit>(),
                    boolean_gmw_share_random_bits.Convert<MpcProtocol::kGarbledCircuit>(),
                    random_unsigned_integer_boolean_gmw_share_extension
                        .Convert<MpcProtocol::kGarbledCircuit>(),
                    random_floating_point_0_1_boolean_gmw_share
                        .Convert<MpcProtocol::kGarbledCircuit>(),
                    iteration_);
        break;
      }

      case MpcProtocol::kBmr: {
        result_vector =
            SecureSamplingAlgorithm_optimized(fD_->Get())
                .FLSymmetricBinomialDistribution_BMR<double, T_expand>(
                    constant_sqrt_n_vector,
                    unsigned_integer_boolean_gmw_share_geometric_sample_extension
                        .Convert<MpcProtocol::kBmr>(),
                    boolean_gmw_share_random_bits.Convert<MpcProtocol::kBmr>(),
                    random_unsigned_integer_boolean_gmw_share_extension
                        .Convert<MpcProtocol::kBmr>(),
                    random_floating_point_0_1_boolean_gmw_share.Convert<MpcProtocol::kBmr>(),
                    iteration_);
        break;
      }

      default: {
        throw std::runtime_error("Unsupported protocol");
      }
    }

    ShareWrapper signed_integer_boolean_gmw_gc_bmr_share_symmetric_binomial_noise =
        result_vector[0];

    return SecureSignedInteger(signed_integer_boolean_gmw_gc_bmr_share_symmetric_binomial_noise)
        .Int2FL(sizeof(double) * 8)
        .MulPow2m(log2_resolution_r_);
  }

  // sqrtN * sqrt(2) < 2^(64)
  // use 64-bit unsigned integer and 64-bit floating point
  // std::int64_t overflow with low probability p = 2 ^ (-47)
  else {
    std::vector<ShareWrapper> result_vector;

    // =
    //     SecureSamplingAlgorithm_optimized(fD_->Get())
    //         .FLSymmetricBinomialDistribution_BMR<double, T>(
    //             constant_sqrt_n_vector, unsigned_integer_boolean_gmw_share_geometric_sample,
    //             boolean_gmw_share_random_bits, random_unsigned_integer_boolean_gmw_gc_bmr_share,
    //             random_floating_point_0_1_boolean_gmw_share, iteration_);

    switch (fD_->Get()->GetProtocol()) {
      case MpcProtocol::kBooleanGmw: {
        result_vector =
            SecureSamplingAlgorithm_optimized(fD_->Get())
                .FLSymmetricBinomialDistribution_BGMW<double, T>(
                    constant_sqrt_n_vector, unsigned_integer_boolean_gmw_share_geometric_sample,
                    boolean_gmw_share_random_bits, random_unsigned_integer_boolean_gmw_share,
                    random_floating_point_0_1_boolean_gmw_share, iteration_);
        break;
      }

      case MpcProtocol::kGarbledCircuit: {
        result_vector =
            SecureSamplingAlgorithm_optimized(fD_->Get())
                .FLSymmetricBinomialDistribution_GC<double, T>(
                    constant_sqrt_n_vector,
                    unsigned_integer_boolean_gmw_share_geometric_sample
                        .Convert<MpcProtocol::kGarbledCircuit>(),
                    boolean_gmw_share_random_bits.Convert<MpcProtocol::kGarbledCircuit>(),
                    random_unsigned_integer_boolean_gmw_share
                        .Convert<MpcProtocol::kGarbledCircuit>(),
                    random_floating_point_0_1_boolean_gmw_share
                        .Convert<MpcProtocol::kGarbledCircuit>(),
                    iteration_);
        break;
      }

      case MpcProtocol::kBmr: {
        result_vector =
            SecureSamplingAlgorithm_optimized(fD_->Get())
                .FLSymmetricBinomialDistribution_BMR<double, T>(
                    constant_sqrt_n_vector,
                    unsigned_integer_boolean_gmw_share_geometric_sample
                        .Convert<MpcProtocol::kBmr>(),
                    boolean_gmw_share_random_bits.Convert<MpcProtocol::kBmr>(),
                    random_unsigned_integer_boolean_gmw_share.Convert<MpcProtocol::kBmr>(),
                    random_floating_point_0_1_boolean_gmw_share.Convert<MpcProtocol::kBmr>(),
                    iteration_);
        break;
      }

      default: {
        throw std::runtime_error("Unsupported protocol");
      }
    }

    ShareWrapper signed_integer_boolean_gmw_share_symmetric_binomial_noise = result_vector[0];
    return SecureSignedInteger(signed_integer_boolean_gmw_share_symmetric_binomial_noise)
        .Int2FL(sizeof(double) * 8)
        .MulPow2m(log2_resolution_r_);
  }
}

}  // namespace encrypto::motion