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
// ! naive version
// 32-bit floating-point version

SecureSignedInteger
SecureDiscreteGaussianMechanismCKS::FL32DiscreteGaussianNoiseGeneration_naive() {
  std::cout << "SecureDiscreteGaussianMechanismCKS::FL32DiscreteGaussianNoiseGeneration_naive"
            << std::endl;

  if (t_ != T(1)) {
    ShareWrapper random_bits_of_length_23_dlap =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT32_MANTISSA_BITS,
                                          (iteration_1_ + iteration_2_) * num_of_simd_total_);
    ShareWrapper random_bits_of_length_126_dlap =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT32_EXPONENT_BIAS - 1,
                                          (iteration_1_ + iteration_2_) * num_of_simd_total_);
    ShareWrapper random_floating_point_0_1_boolean_gmw_share_dlap =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .UniformFloatingPoint32_0_1(random_bits_of_length_23_dlap,
                                        random_bits_of_length_126_dlap);

    ShareWrapper random_unsigned_integer_boolean_gmw_gc_bmr_share_dlap;

    // generate differenty types of random unsigned integer,
    // this operation is expensive and the efficiency depends on the MPC protocol
    switch (fD_->Get()->GetProtocol()) {
      case MpcProtocol::kBooleanGmw: {
        random_unsigned_integer_boolean_gmw_gc_bmr_share_dlap =
            SecureSamplingAlgorithm_naive(fD_->Get())
                .GenerateRandomUnsignedInteger_BGMW<T, T_expand>(T(t_),
                                                                 iteration_1_ * num_of_simd_total_);
        break;
      }
      case MpcProtocol::kGarbledCircuit: {
        random_unsigned_integer_boolean_gmw_gc_bmr_share_dlap =
            SecureSamplingAlgorithm_naive(fD_->Get())
                .GenerateRandomUnsignedInteger_GC<T, T_expand>(T(t_),
                                                               iteration_1_ * num_of_simd_total_);
        break;
      }
      case MpcProtocol::kBmr: {
        random_unsigned_integer_boolean_gmw_gc_bmr_share_dlap =
            SecureSamplingAlgorithm_naive(fD_->Get())
                .GenerateRandomUnsignedInteger_BMR<T, T_expand>(T(t_),
                                                                iteration_1_ * num_of_simd_total_);
        break;
      }
      default: {
        throw std::runtime_error("Unsupported protocol");
      }
    }

    // ShareWrapper random_unsigned_integer_boolean_gmw_share_dlap =
    //     fD_->GenerateRandomUnsignedIntegerPow2_BGMW<T>(log2_denominator_,
    //                                               iteration_1_ * num_of_simd_total_);

    ShareWrapper boolean_gmw_share_bernoulli_sample_dlap =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(1, num_of_simd_total_);

    ShareWrapper random_bits_of_length_23_dgau =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT32_MANTISSA_BITS,
                                          (iteration_4_)*num_of_simd_dgau_);
    ShareWrapper random_bits_of_length_126_dgau =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT32_EXPONENT_BIAS - 1,
                                          (iteration_4_)*num_of_simd_dgau_);
    ShareWrapper random_floating_point_0_1_boolean_gmw_share_dgau =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .UniformFloatingPoint32_0_1(random_bits_of_length_23_dgau,
                                        random_bits_of_length_126_dgau);

    SecureSignedInteger signed_integer_discrete_gaussian_noise =
        FL32DiscreteGaussianNoiseGeneration_naive(
            random_floating_point_0_1_boolean_gmw_share_dlap,
            random_unsigned_integer_boolean_gmw_gc_bmr_share_dlap,
            boolean_gmw_share_bernoulli_sample_dlap,
            random_floating_point_0_1_boolean_gmw_share_dgau);
    return signed_integer_discrete_gaussian_noise;

  } else {
    ShareWrapper random_bits_of_length_23_dlap =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT32_MANTISSA_BITS,
                                          (iteration_2_)*num_of_simd_total_);
    ShareWrapper random_bits_of_length_126_dlap =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT32_EXPONENT_BIAS - 1,
                                          (iteration_2_)*num_of_simd_total_);
    ShareWrapper random_floating_point_0_1_boolean_gmw_share_dlap =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .UniformFloatingPoint32_0_1(random_bits_of_length_23_dlap,
                                        random_bits_of_length_126_dlap);

    ShareWrapper boolean_gmw_share_bernoulli_sample_dlap =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(1, num_of_simd_total_);

    ShareWrapper random_bits_of_length_23_dgau =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT32_MANTISSA_BITS,
                                          (iteration_4_)*num_of_simd_dgau_);
    ShareWrapper random_bits_of_length_126_dgau =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT32_EXPONENT_BIAS - 1,
                                          (iteration_4_)*num_of_simd_dgau_);
    ShareWrapper random_floating_point_0_1_boolean_gmw_share_dgau =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .UniformFloatingPoint32_0_1(random_bits_of_length_23_dgau,
                                        random_bits_of_length_126_dgau);

    SecureSignedInteger signed_integer_discrete_gaussian_noise =
        FL32DiscreteGaussianNoiseGeneration_naive(random_floating_point_0_1_boolean_gmw_share_dlap,
                                                  boolean_gmw_share_bernoulli_sample_dlap,
                                                  random_floating_point_0_1_boolean_gmw_share_dgau);

    return signed_integer_discrete_gaussian_noise;
  }
}

SecureSignedInteger SecureDiscreteGaussianMechanismCKS::FL32DiscreteGaussianNoiseGeneration_naive(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_gc_bmr_share_dlap,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau) {
  //   num_of_simd_dgau_ = fD_->Get()->GetNumberOfSimdValues();

  assert(t_ != 1);

  std::cout << "assert(t_ != 1);" << std::endl;

  std::vector<double> sigma_vector(num_of_simd_dgau_, sigma_);

  std::vector<ShareWrapper> result_vector;

  switch (fD_->Get()->GetProtocol()) {
    case MpcProtocol::kBooleanGmw: {
      std::cout << "case MpcProtocol::kBooleanGmw" << std::endl;
      result_vector = SecureSamplingAlgorithm_naive(fD_->Get())
                          .FLDiscreteGaussianDistribution_BGMW<float, std::uint64_t, std::int64_t>(
                              sigma_vector, random_floating_point_0_1_boolean_gmw_share_dlap,
                              random_unsigned_integer_boolean_gmw_gc_bmr_share_dlap,
                              boolean_gmw_share_bernoulli_sample_dlap,
                              random_floating_point_0_1_boolean_gmw_share_dgau, iteration_1_,
                              iteration_2_, iteration_3_, iteration_4_);
      break;
    }

    case MpcProtocol::kGarbledCircuit: {
      result_vector =
          SecureSamplingAlgorithm_naive(fD_->Get())
              .FLDiscreteGaussianDistribution_GC<float, std::uint64_t, std::int64_t>(
                  sigma_vector,
                  random_floating_point_0_1_boolean_gmw_share_dlap
                      .Convert<MpcProtocol::kGarbledCircuit>(),
                  random_unsigned_integer_boolean_gmw_gc_bmr_share_dlap,
                  boolean_gmw_share_bernoulli_sample_dlap.Convert<MpcProtocol::kGarbledCircuit>(),
                  random_floating_point_0_1_boolean_gmw_share_dgau
                      .Convert<MpcProtocol::kGarbledCircuit>(),
                  iteration_1_, iteration_2_, iteration_3_, iteration_4_);
      break;
    }

    case MpcProtocol::kBmr: {
      result_vector =
          SecureSamplingAlgorithm_naive(fD_->Get())
              .FLDiscreteGaussianDistribution_BMR<float, std::uint64_t, std::int64_t>(
                  sigma_vector,
                  random_floating_point_0_1_boolean_gmw_share_dlap.Convert<MpcProtocol::kBmr>(),
                  random_unsigned_integer_boolean_gmw_gc_bmr_share_dlap,
                  boolean_gmw_share_bernoulli_sample_dlap.Convert<MpcProtocol::kBmr>(),
                  random_floating_point_0_1_boolean_gmw_share_dgau.Convert<MpcProtocol::kBmr>(),
                  iteration_1_, iteration_2_, iteration_3_, iteration_4_);
      break;
    }

    default: {
      throw std::runtime_error("Unsupported protocol");
    }
  }

  ShareWrapper signed_integer_boolean_gmw_share_discrete_gaussian_noise = result_vector[0];
  return SecureSignedInteger(signed_integer_boolean_gmw_share_discrete_gaussian_noise);
}

SecureSignedInteger SecureDiscreteGaussianMechanismCKS::FL32DiscreteGaussianNoiseGeneration_naive(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau) {
  //   num_of_simd_dgau_ = fD_->Get()->GetNumberOfSimdValues();

  assert(t_ == 1);

  std::cout << "assert(t_ == 1);" << std::endl;

  std::vector<double> sigma_vector(num_of_simd_dgau_, sigma_);

  std::vector<ShareWrapper> result_vector;

  switch (fD_->Get()->GetProtocol()) {
    case MpcProtocol::kBooleanGmw: {
      result_vector = SecureSamplingAlgorithm_naive(fD_->Get())
                          .FLDiscreteGaussianDistribution_BGMW<float, std::uint64_t, std::int64_t>(
                              sigma_vector, random_floating_point_0_1_boolean_gmw_share_dlap,
                              boolean_gmw_share_bernoulli_sample_dlap,
                              random_floating_point_0_1_boolean_gmw_share_dgau, iteration_2_,
                              iteration_3_, iteration_4_);
      break;
    }

    case MpcProtocol::kGarbledCircuit: {
      result_vector =
          SecureSamplingAlgorithm_naive(fD_->Get())
              .FLDiscreteGaussianDistribution_GC<float, std::uint64_t, std::int64_t>(
                  sigma_vector,
                  random_floating_point_0_1_boolean_gmw_share_dlap
                      .Convert<MpcProtocol::kGarbledCircuit>(),
                  boolean_gmw_share_bernoulli_sample_dlap.Convert<MpcProtocol::kGarbledCircuit>(),
                  random_floating_point_0_1_boolean_gmw_share_dgau
                      .Convert<MpcProtocol::kGarbledCircuit>(),
                  iteration_2_, iteration_3_, iteration_4_);
      break;
    }

    case MpcProtocol::kBmr: {
      result_vector =
          SecureSamplingAlgorithm_naive(fD_->Get())
              .FLDiscreteGaussianDistribution_BMR<float, std::uint64_t, std::int64_t>(
                  sigma_vector,
                  random_floating_point_0_1_boolean_gmw_share_dlap.Convert<MpcProtocol::kBmr>(),
                  boolean_gmw_share_bernoulli_sample_dlap.Convert<MpcProtocol::kBmr>(),
                  random_floating_point_0_1_boolean_gmw_share_dgau.Convert<MpcProtocol::kBmr>(),
                  iteration_2_, iteration_3_, iteration_4_);
      break;
    }

    default: {
      throw std::runtime_error("Unsupported protocol");
    }
  }

  //   =
  //       fD_->FLDiscreteGaussianDistribution<float, std::uint64_t, std::int64_t>(
  //           sigma_vector, random_floating_point_0_1_boolean_gmw_share_dlap,
  //           boolean_gmw_share_bernoulli_sample_dlap,
  //           random_floating_point_0_1_boolean_gmw_share_dgau, iteration_2_, iteration_3_,
  //           iteration_4_);

  ShareWrapper signed_integer_boolean_gmw_share_discrete_gaussian_noise = result_vector[0];

  return SecureSignedInteger(signed_integer_boolean_gmw_share_discrete_gaussian_noise);
}

// =========================================================================
// ! optimized version
// 32-bit floating-point version

SecureSignedInteger
SecureDiscreteGaussianMechanismCKS::FL32DiscreteGaussianNoiseGeneration_optimized() {
  std::cout << "SecureDiscreteGaussianMechanismCKS::FL32DiscreteGaussianNoiseGeneration_optimized"
            << std::endl;

  if (t_ != T(1)) {
    ShareWrapper random_bits_of_length_23_dlap =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT32_MANTISSA_BITS,
                                          (iteration_1_ + iteration_2_) * num_of_simd_total_);
    ShareWrapper random_bits_of_length_126_dlap =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT32_EXPONENT_BIAS - 1,
                                          (iteration_1_ + iteration_2_) * num_of_simd_total_);
    ShareWrapper random_floating_point_0_1_boolean_gmw_share_dlap =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .UniformFloatingPoint32_0_1(random_bits_of_length_23_dlap,
                                        random_bits_of_length_126_dlap);

    // more efficient method
    ShareWrapper random_unsigned_integer_boolean_gmw_share_dlap =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomUnsignedIntegerPow2_BGMW<T>(log2_denominator_,
                                                       iteration_1_ * num_of_simd_total_);

    ShareWrapper boolean_gmw_share_bernoulli_sample_dlap =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(1, num_of_simd_total_);

    ShareWrapper random_bits_of_length_23_dgau =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT32_MANTISSA_BITS,
                                          (iteration_4_)*num_of_simd_dgau_);
    ShareWrapper random_bits_of_length_126_dgau =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT32_EXPONENT_BIAS - 1,
                                          (iteration_4_)*num_of_simd_dgau_);
    ShareWrapper random_floating_point_0_1_boolean_gmw_share_dgau =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .UniformFloatingPoint32_0_1(random_bits_of_length_23_dgau,
                                        random_bits_of_length_126_dgau);

    SecureSignedInteger signed_integer_discrete_gaussian_noise =
        FL32DiscreteGaussianNoiseGeneration_optimized(
            random_floating_point_0_1_boolean_gmw_share_dlap,
            random_unsigned_integer_boolean_gmw_share_dlap, boolean_gmw_share_bernoulli_sample_dlap,
            random_floating_point_0_1_boolean_gmw_share_dgau);
    return signed_integer_discrete_gaussian_noise;

  } else {
    ShareWrapper random_bits_of_length_23_dlap =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT32_MANTISSA_BITS,
                                          (iteration_2_)*num_of_simd_total_);
    ShareWrapper random_bits_of_length_126_dlap =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT32_EXPONENT_BIAS - 1,
                                          (iteration_2_)*num_of_simd_total_);
    ShareWrapper random_floating_point_0_1_boolean_gmw_share_dlap =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .UniformFloatingPoint32_0_1(random_bits_of_length_23_dlap,
                                        random_bits_of_length_126_dlap);

    ShareWrapper boolean_gmw_share_bernoulli_sample_dlap =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(1, num_of_simd_total_);

    ShareWrapper random_bits_of_length_23_dgau =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT32_MANTISSA_BITS,
                                          (iteration_4_)*num_of_simd_dgau_);
    ShareWrapper random_bits_of_length_126_dgau =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT32_EXPONENT_BIAS - 1,
                                          (iteration_4_)*num_of_simd_dgau_);
    ShareWrapper random_floating_point_0_1_boolean_gmw_share_dgau =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .UniformFloatingPoint32_0_1(random_bits_of_length_23_dgau,
                                        random_bits_of_length_126_dgau);

    SecureSignedInteger signed_integer_discrete_gaussian_noise =
        FL32DiscreteGaussianNoiseGeneration_optimized(
            random_floating_point_0_1_boolean_gmw_share_dlap,
            boolean_gmw_share_bernoulli_sample_dlap,
            random_floating_point_0_1_boolean_gmw_share_dgau);

    return signed_integer_discrete_gaussian_noise;
  }
}

SecureSignedInteger
SecureDiscreteGaussianMechanismCKS::FL32DiscreteGaussianNoiseGeneration_optimized(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share_dlap,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau) {
  //   num_of_simd_dgau_ = fD_->Get()->GetNumberOfSimdValues();

  assert(t_ != 1);

  std::vector<double> sigma_vector(num_of_simd_dgau_, sigma_);

  std::vector<ShareWrapper> result_vector;

  switch (fD_->Get()->GetProtocol()) {
    case MpcProtocol::kBooleanGmw: {
      result_vector = SecureSamplingAlgorithm_optimized(fD_->Get())
                          .FLDiscreteGaussianDistribution_BGMW<float, std::uint64_t, std::int64_t>(
                              sigma_vector, random_floating_point_0_1_boolean_gmw_share_dlap,
                              random_unsigned_integer_boolean_gmw_share_dlap,
                              boolean_gmw_share_bernoulli_sample_dlap,
                              random_floating_point_0_1_boolean_gmw_share_dgau, iteration_1_,
                              iteration_2_, iteration_3_, iteration_4_);
      break;
    }

    case MpcProtocol::kGarbledCircuit: {
      result_vector =
          SecureSamplingAlgorithm_optimized(fD_->Get())
              .FLDiscreteGaussianDistribution_GC<float, std::uint64_t, std::int64_t>(
                  sigma_vector,
                  random_floating_point_0_1_boolean_gmw_share_dlap
                      .Convert<MpcProtocol::kGarbledCircuit>(),
                  random_unsigned_integer_boolean_gmw_share_dlap
                      .Convert<MpcProtocol::kGarbledCircuit>(),
                  boolean_gmw_share_bernoulli_sample_dlap.Convert<MpcProtocol::kGarbledCircuit>(),
                  random_floating_point_0_1_boolean_gmw_share_dgau
                      .Convert<MpcProtocol::kGarbledCircuit>(),
                  iteration_1_, iteration_2_, iteration_3_, iteration_4_);
      break;
    }

    case MpcProtocol::kBmr: {
      result_vector =
          SecureSamplingAlgorithm_optimized(fD_->Get())
              .FLDiscreteGaussianDistribution_BMR<float, std::uint64_t, std::int64_t>(
                  sigma_vector,
                  random_floating_point_0_1_boolean_gmw_share_dlap.Convert<MpcProtocol::kBmr>(),
                  random_unsigned_integer_boolean_gmw_share_dlap.Convert<MpcProtocol::kBmr>(),
                  boolean_gmw_share_bernoulli_sample_dlap.Convert<MpcProtocol::kBmr>(),
                  random_floating_point_0_1_boolean_gmw_share_dgau.Convert<MpcProtocol::kBmr>(),
                  iteration_1_, iteration_2_, iteration_3_, iteration_4_);
      break;
    }

    default: {
      throw std::runtime_error("Unsupported protocol");
    }
  }

  ShareWrapper signed_integer_boolean_gmw_share_discrete_gaussian_noise = result_vector[0];
  return SecureSignedInteger(signed_integer_boolean_gmw_share_discrete_gaussian_noise);
}

SecureSignedInteger
SecureDiscreteGaussianMechanismCKS::FL32DiscreteGaussianNoiseGeneration_optimized(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau) {
  //   num_of_simd_dgau_ = fD_->Get()->GetNumberOfSimdValues();

  assert(t_ == 1);
  std::vector<double> sigma_vector(num_of_simd_dgau_, sigma_);

  std::vector<ShareWrapper> result_vector;

  switch (fD_->Get()->GetProtocol()) {
    case MpcProtocol::kBooleanGmw: {
      result_vector = SecureSamplingAlgorithm_optimized(fD_->Get())
                          .FLDiscreteGaussianDistribution_BGMW<float, std::uint64_t, std::int64_t>(
                              sigma_vector, random_floating_point_0_1_boolean_gmw_share_dlap,
                              boolean_gmw_share_bernoulli_sample_dlap,
                              random_floating_point_0_1_boolean_gmw_share_dgau, iteration_2_,
                              iteration_3_, iteration_4_);
      break;
    }

    case MpcProtocol::kGarbledCircuit: {
      result_vector =
          SecureSamplingAlgorithm_optimized(fD_->Get())
              .FLDiscreteGaussianDistribution_GC<float, std::uint64_t, std::int64_t>(
                  sigma_vector,
                  random_floating_point_0_1_boolean_gmw_share_dlap
                      .Convert<MpcProtocol::kGarbledCircuit>(),
                  boolean_gmw_share_bernoulli_sample_dlap.Convert<MpcProtocol::kGarbledCircuit>(),
                  random_floating_point_0_1_boolean_gmw_share_dgau
                      .Convert<MpcProtocol::kGarbledCircuit>(),
                  iteration_2_, iteration_3_, iteration_4_);
      break;
    }

    case MpcProtocol::kBmr: {
      result_vector =
          SecureSamplingAlgorithm_optimized(fD_->Get())
              .FLDiscreteGaussianDistribution_BMR<float, std::uint64_t, std::int64_t>(
                  sigma_vector,
                  random_floating_point_0_1_boolean_gmw_share_dlap.Convert<MpcProtocol::kBmr>(),
                  boolean_gmw_share_bernoulli_sample_dlap.Convert<MpcProtocol::kBmr>(),
                  random_floating_point_0_1_boolean_gmw_share_dgau.Convert<MpcProtocol::kBmr>(),
                  iteration_2_, iteration_3_, iteration_4_);
      break;
    }

    default: {
      throw std::runtime_error("Unsupported protocol");
    }
  }

  //   =
  //       fD_->FLDiscreteGaussianDistribution<float, std::uint64_t, std::int64_t>(
  //           sigma_vector, random_floating_point_0_1_boolean_gmw_share_dlap,
  //           boolean_gmw_share_bernoulli_sample_dlap,
  //           random_floating_point_0_1_boolean_gmw_share_dgau, iteration_2_, iteration_3_,
  //           iteration_4_);

  ShareWrapper signed_integer_boolean_gmw_share_discrete_gaussian_noise = result_vector[0];

  return SecureSignedInteger(signed_integer_boolean_gmw_share_discrete_gaussian_noise);
}

// =================================================================
// ! naive version
// 64-bit floating-point version
// SecureSignedInteger SecureDiscreteGaussianMechanismCKS::FL64DiscreteGaussianNoiseAddition() {
//   SecureSignedInteger signed_integer_noisy_fD =
//       SecureSignedInteger(fD_->Get()) + FL64DiscreteGaussianNoiseGeneration();
//   noisy_fD_ = std::make_unique<ShareWrapper>(signed_integer_noisy_fD.Get().Get());
//   return signed_integer_noisy_fD;
// }

SecureSignedInteger
SecureDiscreteGaussianMechanismCKS::FL64DiscreteGaussianNoiseGeneration_naive() {
  std::cout << "SecureDiscreteGaussianMechanismCKS::FL64DiscreteGaussianNoiseGeneration_naive"
            << std::endl;
  if (t_ != T(1)) {
    ShareWrapper random_bits_of_length_52_dlap =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT64_MANTISSA_BITS,
                                          (iteration_1_ + iteration_2_) * num_of_simd_total_);
    ShareWrapper random_bits_of_length_1022_dlap =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT64_EXPONENT_BIAS - 1,
                                          (iteration_1_ + iteration_2_) * num_of_simd_total_);
    ShareWrapper random_floating_point_0_1_boolean_gmw_share_dlap =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .UniformFloatingPoint64_0_1(random_bits_of_length_52_dlap,
                                        random_bits_of_length_1022_dlap);

    ShareWrapper random_unsigned_integer_boolean_gmw_gc_bmr_share;

    //  =
    //     fD_->GenerateRandomUnsignedInteger_BGMW(T(t_), iteration_1_ * num_of_simd_total_);

    switch (fD_->Get()->GetProtocol()) {
      case MpcProtocol::kBooleanGmw: {
        random_unsigned_integer_boolean_gmw_gc_bmr_share =
            SecureSamplingAlgorithm_naive(fD_->Get())
                .GenerateRandomUnsignedInteger_BGMW<T, T_expand>(T(t_),
                                                                 iteration_1_ * num_of_simd_total_);
        break;
      }

      case MpcProtocol::kGarbledCircuit: {
        random_unsigned_integer_boolean_gmw_gc_bmr_share =
            SecureSamplingAlgorithm_naive(fD_->Get())
                .GenerateRandomUnsignedInteger_GC<T, T_expand>(T(t_),
                                                               iteration_1_ * num_of_simd_total_);
        break;
      }

      case MpcProtocol::kBmr: {
        random_unsigned_integer_boolean_gmw_gc_bmr_share =
            SecureSamplingAlgorithm_naive(fD_->Get())
                .GenerateRandomUnsignedInteger_BMR<T, T_expand>(T(t_),
                                                                iteration_1_ * num_of_simd_total_);
        break;
      }

      default: {
        throw std::runtime_error("Unsupported protocol");
      }
    }

    // ShareWrapper random_unsigned_integer_boolean_gmw_share_dlap =
    //     SecureSamplingAlgorithm_naive(fD_->Get())
    //         .GenerateRandomUnsignedIntegerPow2_BGMW<T>(log2_denominator_,
    //                                                   iteration_1_ * num_of_simd_total_);

    ShareWrapper boolean_gmw_share_bernoulli_sample_dlap =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(1, num_of_simd_total_);

    ShareWrapper random_bits_of_length_52_dgau =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT64_MANTISSA_BITS,
                                          (iteration_4_)*num_of_simd_dgau_);
    ShareWrapper random_bits_of_length_1022_dgau =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT64_EXPONENT_BIAS - 1,
                                          (iteration_4_)*num_of_simd_dgau_);
    ShareWrapper random_floating_point_0_1_boolean_gmw_share_dgau =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .UniformFloatingPoint64_0_1(random_bits_of_length_52_dgau,
                                        random_bits_of_length_1022_dgau);

    SecureSignedInteger signed_integer_discrete_gaussian_noise =
        FL64DiscreteGaussianNoiseGeneration_naive(random_floating_point_0_1_boolean_gmw_share_dlap,
                                                  random_unsigned_integer_boolean_gmw_gc_bmr_share,
                                                  boolean_gmw_share_bernoulli_sample_dlap,
                                                  random_floating_point_0_1_boolean_gmw_share_dgau);
    return signed_integer_discrete_gaussian_noise;

  } else {
    ShareWrapper random_bits_of_length_52_dlap =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT64_MANTISSA_BITS,
                                          (iteration_2_)*num_of_simd_total_);
    ShareWrapper random_bits_of_length_1022_dlap =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT64_EXPONENT_BIAS - 1,
                                          (iteration_2_)*num_of_simd_total_);
    ShareWrapper random_floating_point_0_1_boolean_gmw_share_dlap =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .UniformFloatingPoint64_0_1(random_bits_of_length_52_dlap,
                                        random_bits_of_length_1022_dlap);

    ShareWrapper boolean_gmw_share_bernoulli_sample_dlap =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(1, num_of_simd_total_);

    ShareWrapper random_bits_of_length_52_dgau =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT64_MANTISSA_BITS,
                                          (iteration_4_)*num_of_simd_dgau_);
    ShareWrapper random_bits_of_length_1022_dgau =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT64_EXPONENT_BIAS - 1,
                                          (iteration_4_)*num_of_simd_dgau_);
    ShareWrapper random_floating_point_0_1_boolean_gmw_share_dgau =
        SecureSamplingAlgorithm_naive(fD_->Get())
            .UniformFloatingPoint64_0_1(random_bits_of_length_52_dgau,
                                        random_bits_of_length_1022_dgau);

    SecureSignedInteger signed_integer_discrete_gaussian_noise =
        FL64DiscreteGaussianNoiseGeneration_naive(random_floating_point_0_1_boolean_gmw_share_dlap,
                                                  boolean_gmw_share_bernoulli_sample_dlap,
                                                  random_floating_point_0_1_boolean_gmw_share_dgau);

    return signed_integer_discrete_gaussian_noise;
  }
}

SecureSignedInteger SecureDiscreteGaussianMechanismCKS::FL64DiscreteGaussianNoiseGeneration_naive(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_gc_bmr_share_dlap,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau) {
  //   num_of_simd_dgau_ = fD_->Get()->GetNumberOfSimdValues();

  assert(t_ != 1);

  std::vector<double> sigma_vector(num_of_simd_dgau_, sigma_);

  std::vector<ShareWrapper> result_vector;

  switch (fD_->Get()->GetProtocol()) {
    case MpcProtocol::kBooleanGmw: {
      result_vector = SecureSamplingAlgorithm_naive(fD_->Get())
                          .FLDiscreteGaussianDistribution_BGMW<double, std::uint64_t, std::int64_t>(
                              sigma_vector, random_floating_point_0_1_boolean_gmw_share_dlap,
                              random_unsigned_integer_boolean_gmw_gc_bmr_share_dlap,
                              boolean_gmw_share_bernoulli_sample_dlap,
                              random_floating_point_0_1_boolean_gmw_share_dgau, iteration_1_,
                              iteration_2_, iteration_3_, iteration_4_);
      break;
    }

    case MpcProtocol::kGarbledCircuit: {
      result_vector =
          SecureSamplingAlgorithm_naive(fD_->Get())
              .FLDiscreteGaussianDistribution_GC<double, std::uint64_t, std::int64_t>(
                  sigma_vector,
                  random_floating_point_0_1_boolean_gmw_share_dlap
                      .Convert<MpcProtocol::kGarbledCircuit>(),
                  random_unsigned_integer_boolean_gmw_gc_bmr_share_dlap,
                  boolean_gmw_share_bernoulli_sample_dlap.Convert<MpcProtocol::kGarbledCircuit>(),
                  random_floating_point_0_1_boolean_gmw_share_dgau
                      .Convert<MpcProtocol::kGarbledCircuit>(),
                  iteration_1_, iteration_2_, iteration_3_, iteration_4_);
      break;
    }

    case MpcProtocol::kBmr: {
      result_vector =
          SecureSamplingAlgorithm_naive(fD_->Get())
              .FLDiscreteGaussianDistribution_BMR<double, std::uint64_t, std::int64_t>(
                  sigma_vector,
                  random_floating_point_0_1_boolean_gmw_share_dlap.Convert<MpcProtocol::kBmr>(),
                  random_unsigned_integer_boolean_gmw_gc_bmr_share_dlap,
                  boolean_gmw_share_bernoulli_sample_dlap.Convert<MpcProtocol::kBmr>(),
                  random_floating_point_0_1_boolean_gmw_share_dgau.Convert<MpcProtocol::kBmr>(),
                  iteration_1_, iteration_2_, iteration_3_, iteration_4_);
      break;
    }

    default: {
      throw std::runtime_error("Unsupported protocol");
    }
  }

  //    =
  //       fD_->FLDiscreteGaussianDistribution<double, std::uint64_t, std::int64_t>(
  //           sigma_vector, random_floating_point_0_1_boolean_gmw_share_dlap,
  //           random_unsigned_integer_boolean_gmw_share_dlap,
  //           boolean_gmw_share_bernoulli_sample_dlap,
  //           random_floating_point_0_1_boolean_gmw_share_dgau, iteration_1_, iteration_2_,
  //           iteration_3_, iteration_4_, upscale_factor_);

  ShareWrapper signed_integer_boolean_gmw_share_discrete_gaussian_noise = result_vector[0];
  return SecureSignedInteger(signed_integer_boolean_gmw_share_discrete_gaussian_noise);
}

SecureSignedInteger SecureDiscreteGaussianMechanismCKS::FL64DiscreteGaussianNoiseGeneration_naive(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau) {
  //   num_of_simd_dgau_ = fD_->Get()->GetNumberOfSimdValues();

  assert(t_ == 1);
  std::vector<double> sigma_vector(num_of_simd_dgau_, sigma_);

  std::vector<ShareWrapper> result_vector;

  switch (fD_->Get()->GetProtocol()) {
    case MpcProtocol::kBooleanGmw: {
      result_vector = SecureSamplingAlgorithm_naive(fD_->Get())
                          .FLDiscreteGaussianDistribution_BGMW<double, std::uint64_t, std::int64_t>(
                              sigma_vector, random_floating_point_0_1_boolean_gmw_share_dlap,
                              boolean_gmw_share_bernoulli_sample_dlap,
                              random_floating_point_0_1_boolean_gmw_share_dgau, iteration_2_,
                              iteration_3_, iteration_4_);
      break;
    }

    case MpcProtocol::kGarbledCircuit: {
      result_vector =
          SecureSamplingAlgorithm_naive(fD_->Get())
              .FLDiscreteGaussianDistribution_GC<double, std::uint64_t, std::int64_t>(
                  sigma_vector,
                  random_floating_point_0_1_boolean_gmw_share_dlap
                      .Convert<MpcProtocol::kGarbledCircuit>(),
                  boolean_gmw_share_bernoulli_sample_dlap.Convert<MpcProtocol::kGarbledCircuit>(),
                  random_floating_point_0_1_boolean_gmw_share_dgau
                      .Convert<MpcProtocol::kGarbledCircuit>(),
                  iteration_2_, iteration_3_, iteration_4_);
      break;
    }

    case MpcProtocol::kBmr: {
      result_vector =
          SecureSamplingAlgorithm_naive(fD_->Get())
              .FLDiscreteGaussianDistribution_BMR<double, std::uint64_t, std::int64_t>(
                  sigma_vector,
                  random_floating_point_0_1_boolean_gmw_share_dlap.Convert<MpcProtocol::kBmr>(),
                  boolean_gmw_share_bernoulli_sample_dlap.Convert<MpcProtocol::kBmr>(),
                  random_floating_point_0_1_boolean_gmw_share_dgau.Convert<MpcProtocol::kBmr>(),
                  iteration_2_, iteration_3_, iteration_4_);
      break;
    }

    default: {
      throw std::runtime_error("Unsupported protocol");
    }
  }

  //   = fD_->FLDiscreteGaussianDistribution<double, std::uint64_t, std::int64_t>(
  //       sigma_vector, random_floating_point_0_1_boolean_gmw_share_dlap,
  //       boolean_gmw_share_bernoulli_sample_dlap,
  //       random_floating_point_0_1_boolean_gmw_share_dgau, iteration_2_, iteration_3_,
  //       iteration_4_);

  ShareWrapper signed_integer_boolean_gmw_share_discrete_gaussian_noise = result_vector[0];

  return SecureSignedInteger(signed_integer_boolean_gmw_share_discrete_gaussian_noise);
}

// ! optimized version
// 64-bit floating-point version
// SecureSignedInteger SecureDiscreteGaussianMechanismCKS::FL64DiscreteGaussianNoiseAddition() {
//   SecureSignedInteger signed_integer_noisy_fD =
//       SecureSignedInteger(fD_->Get()) + FL64DiscreteGaussianNoiseGeneration();
//   noisy_fD_ = std::make_unique<ShareWrapper>(signed_integer_noisy_fD.Get().Get());
//   return signed_integer_noisy_fD;
// }

SecureSignedInteger
SecureDiscreteGaussianMechanismCKS::FL64DiscreteGaussianNoiseGeneration_optimized() {
  std::cout << "SecureDiscreteGaussianMechanismCKS::FL64DiscreteGaussianNoiseGeneration_optimized"
            << std::endl;
  if (t_ != T(1)) {
    ShareWrapper random_bits_of_length_52_dlap =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT64_MANTISSA_BITS,
                                          (iteration_1_ + iteration_2_) * num_of_simd_total_);
    ShareWrapper random_bits_of_length_1022_dlap =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT64_EXPONENT_BIAS - 1,
                                          (iteration_1_ + iteration_2_) * num_of_simd_total_);
    ShareWrapper random_floating_point_0_1_boolean_gmw_share_dlap =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .UniformFloatingPoint64_0_1(random_bits_of_length_52_dlap,
                                        random_bits_of_length_1022_dlap);

    // ShareWrapper random_unsigned_integer_boolean_gmw_gc_bmr_share;

    //  =
    //     fD_->GenerateRandomUnsignedInteger_BGMW(T(t_), iteration_1_ * num_of_simd_total_);

    ShareWrapper random_unsigned_integer_boolean_gmw_share_dlap =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomUnsignedIntegerPow2_BGMW<T>(log2_denominator_,
                                                       iteration_1_ * num_of_simd_total_);

    ShareWrapper boolean_gmw_share_bernoulli_sample_dlap =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(1, num_of_simd_total_);

    ShareWrapper random_bits_of_length_52_dgau =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT64_MANTISSA_BITS,
                                          (iteration_4_)*num_of_simd_dgau_);
    ShareWrapper random_bits_of_length_1022_dgau =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT64_EXPONENT_BIAS - 1,
                                          (iteration_4_)*num_of_simd_dgau_);
    ShareWrapper random_floating_point_0_1_boolean_gmw_share_dgau =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .UniformFloatingPoint64_0_1(random_bits_of_length_52_dgau,
                                        random_bits_of_length_1022_dgau);

    SecureSignedInteger signed_integer_discrete_gaussian_noise =
        FL64DiscreteGaussianNoiseGeneration_optimized(
            random_floating_point_0_1_boolean_gmw_share_dlap,
            random_unsigned_integer_boolean_gmw_share_dlap, boolean_gmw_share_bernoulli_sample_dlap,
            random_floating_point_0_1_boolean_gmw_share_dgau);
    return signed_integer_discrete_gaussian_noise;

  } else {
    ShareWrapper random_bits_of_length_52_dlap =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT64_MANTISSA_BITS,
                                          (iteration_2_)*num_of_simd_total_);
    ShareWrapper random_bits_of_length_1022_dlap =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT64_EXPONENT_BIAS - 1,
                                          (iteration_2_)*num_of_simd_total_);
    ShareWrapper random_floating_point_0_1_boolean_gmw_share_dlap =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .UniformFloatingPoint64_0_1(random_bits_of_length_52_dlap,
                                        random_bits_of_length_1022_dlap);

    ShareWrapper boolean_gmw_share_bernoulli_sample_dlap =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(1, num_of_simd_total_);

    ShareWrapper random_bits_of_length_52_dgau =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT64_MANTISSA_BITS,
                                          (iteration_4_)*num_of_simd_dgau_);
    ShareWrapper random_bits_of_length_1022_dgau =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .GenerateRandomBooleanGmwBits(FLOATINGPOINT64_EXPONENT_BIAS - 1,
                                          (iteration_4_)*num_of_simd_dgau_);
    ShareWrapper random_floating_point_0_1_boolean_gmw_share_dgau =
        SecureSamplingAlgorithm_optimized(fD_->Get())
            .UniformFloatingPoint64_0_1(random_bits_of_length_52_dgau,
                                        random_bits_of_length_1022_dgau);

    SecureSignedInteger signed_integer_discrete_gaussian_noise =
        FL64DiscreteGaussianNoiseGeneration_optimized(
            random_floating_point_0_1_boolean_gmw_share_dlap,
            boolean_gmw_share_bernoulli_sample_dlap,
            random_floating_point_0_1_boolean_gmw_share_dgau);

    return signed_integer_discrete_gaussian_noise;
  }
}

SecureSignedInteger
SecureDiscreteGaussianMechanismCKS::FL64DiscreteGaussianNoiseGeneration_optimized(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share_dlap,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau) {
  //   num_of_simd_dgau_ = fD_->Get()->GetNumberOfSimdValues();

  assert(t_ != 1);

  std::vector<double> sigma_vector(num_of_simd_dgau_, sigma_);

  std::vector<ShareWrapper> result_vector;

  switch (fD_->Get()->GetProtocol()) {
    case MpcProtocol::kBooleanGmw: {
      result_vector = SecureSamplingAlgorithm_optimized(fD_->Get())
                          .FLDiscreteGaussianDistribution_BGMW<double, std::uint64_t, std::int64_t>(
                              sigma_vector, random_floating_point_0_1_boolean_gmw_share_dlap,
                              random_unsigned_integer_boolean_gmw_share_dlap,
                              boolean_gmw_share_bernoulli_sample_dlap,
                              random_floating_point_0_1_boolean_gmw_share_dgau, iteration_1_,
                              iteration_2_, iteration_3_, iteration_4_);
      break;
    }

    case MpcProtocol::kGarbledCircuit: {
      result_vector =
          SecureSamplingAlgorithm_optimized(fD_->Get())
              .FLDiscreteGaussianDistribution_GC<double, std::uint64_t, std::int64_t>(
                  sigma_vector,
                  random_floating_point_0_1_boolean_gmw_share_dlap
                      .Convert<MpcProtocol::kGarbledCircuit>(),
                  random_unsigned_integer_boolean_gmw_share_dlap
                      .Convert<MpcProtocol::kGarbledCircuit>(),
                  boolean_gmw_share_bernoulli_sample_dlap.Convert<MpcProtocol::kGarbledCircuit>(),
                  random_floating_point_0_1_boolean_gmw_share_dgau
                      .Convert<MpcProtocol::kGarbledCircuit>(),
                  iteration_1_, iteration_2_, iteration_3_, iteration_4_);
      break;
    }

    case MpcProtocol::kBmr: {
      result_vector =
          SecureSamplingAlgorithm_optimized(fD_->Get())
              .FLDiscreteGaussianDistribution_BMR<double, std::uint64_t, std::int64_t>(
                  sigma_vector,
                  random_floating_point_0_1_boolean_gmw_share_dlap.Convert<MpcProtocol::kBmr>(),
                  random_unsigned_integer_boolean_gmw_share_dlap.Convert<MpcProtocol::kBmr>(),
                  boolean_gmw_share_bernoulli_sample_dlap.Convert<MpcProtocol::kBmr>(),
                  random_floating_point_0_1_boolean_gmw_share_dgau.Convert<MpcProtocol::kBmr>(),
                  iteration_1_, iteration_2_, iteration_3_, iteration_4_);
      break;
    }

    default: {
      throw std::runtime_error("Unsupported protocol");
    }
  }

  //    =
  //       fD_->FLDiscreteGaussianDistribution<double, std::uint64_t, std::int64_t>(
  //           sigma_vector, random_floating_point_0_1_boolean_gmw_share_dlap,
  //           random_unsigned_integer_boolean_gmw_share_dlap,
  //           boolean_gmw_share_bernoulli_sample_dlap,
  //           random_floating_point_0_1_boolean_gmw_share_dgau, iteration_1_, iteration_2_,
  //           iteration_3_, iteration_4_, upscale_factor_);

  ShareWrapper signed_integer_boolean_gmw_share_discrete_gaussian_noise = result_vector[0];
  return SecureSignedInteger(signed_integer_boolean_gmw_share_discrete_gaussian_noise);
}

SecureSignedInteger
SecureDiscreteGaussianMechanismCKS::FL64DiscreteGaussianNoiseGeneration_optimized(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau) {
  //   num_of_simd_dgau_ = fD_->Get()->GetNumberOfSimdValues();

  assert(t_ == 1);
  std::vector<double> sigma_vector(num_of_simd_dgau_, sigma_);

  std::vector<ShareWrapper> result_vector;

  switch (fD_->Get()->GetProtocol()) {
    case MpcProtocol::kBooleanGmw: {
      result_vector = SecureSamplingAlgorithm_optimized(fD_->Get())
                          .FLDiscreteGaussianDistribution_BGMW<double, std::uint64_t, std::int64_t>(
                              sigma_vector, random_floating_point_0_1_boolean_gmw_share_dlap,
                              boolean_gmw_share_bernoulli_sample_dlap,
                              random_floating_point_0_1_boolean_gmw_share_dgau, iteration_2_,
                              iteration_3_, iteration_4_);
      break;
    }

    case MpcProtocol::kGarbledCircuit: {
      result_vector =
          SecureSamplingAlgorithm_optimized(fD_->Get())
              .FLDiscreteGaussianDistribution_GC<double, std::uint64_t, std::int64_t>(
                  sigma_vector,
                  random_floating_point_0_1_boolean_gmw_share_dlap
                      .Convert<MpcProtocol::kGarbledCircuit>(),
                  boolean_gmw_share_bernoulli_sample_dlap.Convert<MpcProtocol::kGarbledCircuit>(),
                  random_floating_point_0_1_boolean_gmw_share_dgau
                      .Convert<MpcProtocol::kGarbledCircuit>(),
                  iteration_2_, iteration_3_, iteration_4_);
      break;
    }

    case MpcProtocol::kBmr: {
      result_vector =
          SecureSamplingAlgorithm_optimized(fD_->Get())
              .FLDiscreteGaussianDistribution_BMR<double, std::uint64_t, std::int64_t>(
                  sigma_vector,
                  random_floating_point_0_1_boolean_gmw_share_dlap.Convert<MpcProtocol::kBmr>(),
                  boolean_gmw_share_bernoulli_sample_dlap.Convert<MpcProtocol::kBmr>(),
                  random_floating_point_0_1_boolean_gmw_share_dgau.Convert<MpcProtocol::kBmr>(),
                  iteration_2_, iteration_3_, iteration_4_);
      break;
    }

    default: {
      throw std::runtime_error("Unsupported protocol");
    }
  }

  //   = fD_->FLDiscreteGaussianDistribution<double, std::uint64_t, std::int64_t>(
  //       sigma_vector, random_floating_point_0_1_boolean_gmw_share_dlap,
  //       boolean_gmw_share_bernoulli_sample_dlap,
  //       random_floating_point_0_1_boolean_gmw_share_dgau, iteration_2_, iteration_3_,
  //       iteration_4_);

  ShareWrapper signed_integer_boolean_gmw_share_discrete_gaussian_noise = result_vector[0];

  return SecureSignedInteger(signed_integer_boolean_gmw_share_discrete_gaussian_noise);
}

}  // namespace encrypto::motion