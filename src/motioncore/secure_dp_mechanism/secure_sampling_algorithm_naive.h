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

#pragma once

#include "protocols/share_wrapper.h"
#include "secure_type/secure_fixed_point_circuit_CBMC.h"
#include "secure_type/secure_floating_point_circuit_ABY.h"
#include "secure_type/secure_signed_integer.h"
#include "secure_type/secure_unsigned_integer.h"

namespace encrypto::motion {

class Logger;
class SecureUnsignedInteger;
class SecureSignedInteger;
class SecureFloatingPointCircuitABY;
class SecureFixedPointCircuitCBMC;

/// \brief class to wrap sampling algorithms
class SecureSamplingAlgorithm_naive {
 public:
  SecureSamplingAlgorithm_naive() = default;

  SecureSamplingAlgorithm_naive(const SecureSamplingAlgorithm_naive& other)
      : SecureSamplingAlgorithm_naive(*other.share_) {}

  SecureSamplingAlgorithm_naive(SecureSamplingAlgorithm_naive&& other)
      : SecureSamplingAlgorithm_naive(std::move(*other.share_)) {
    other.share_->Get().reset();
  }

  SecureSamplingAlgorithm_naive(const ShareWrapper& other)
      : SecureSamplingAlgorithm_naive(*other) {}

  SecureSamplingAlgorithm_naive(ShareWrapper&& other)
      : SecureSamplingAlgorithm_naive(std::move(*other)) {
    other.Get().reset();
  }

  SecureSamplingAlgorithm_naive(const SharePointer& other);

  SecureSamplingAlgorithm_naive(SharePointer&& other);

  SecureSamplingAlgorithm_naive& operator=(const SecureSamplingAlgorithm_naive& other) {
    this->share_ = other.share_;
    this->logger_ = other.logger_;
    return *this;
  }

  SecureSamplingAlgorithm_naive& operator=(SecureSamplingAlgorithm_naive&& other) {
    this->share_ = std::move(other.share_);
    this->logger_ = std::move(other.logger_);
    return *this;
  }

  ShareWrapper& Get() { return *share_; }

  const ShareWrapper& Get() const { return *share_; }

  ShareWrapper& operator->() { return *share_; }

  const ShareWrapper& operator->() const { return *share_; }

  //   SecureSamplingAlgorithm_naive() : share_(nullptr){};

  //   SecureSamplingAlgorithm_naive(const SharePointer& other);

  //   SecureSamplingAlgorithm_naive(const ShareWrapper& other) :
  //   SecureSamplingAlgorithm_naive(*other) {}

 public:
  ShareWrapper BooleanGmwBitsZeroCompensation(const ShareWrapper& share_bits,
                                              const std::size_t num_of_total_bits) const;

  // each party generates random boolean gmw bits locally
  ShareWrapper GenerateRandomBooleanGmwBits(const std::size_t num_of_bits,
                                            const std::size_t num_of_simd) const;

  // each party generates random unsigned integer of data type T in range [0, 2^k-1] locally,
  // without interactions, the share is Boolean GWM
  template <typename T>
  ShareWrapper GenerateRandomUnsignedIntegerPow2BGMW(std::size_t bit_size_k,
                                                 const std::size_t num_of_simd) const;

  // each party generates random unsigned integer of data type T in range [0, 2^k-1] locally,
  // without interactions, convert share to Garbled Circuit
  template <typename T>
  ShareWrapper GenerateRandomUnsignedIntegerPow2GC(std::size_t bit_size_k,
                                                 const std::size_t num_of_simd) const;

  // each party generates random unsigned integer of data type T in range [0, 2^k-1] locally,
  // without interactions, convert share to BMR
  template <typename T>
  ShareWrapper GenerateRandomUnsignedIntegerPow2BMR(std::size_t bit_size_k,
                                                 const std::size_t num_of_simd) const;

  // generate random integer in range [0, m),
  // with security parameter s = sizeof(T) * 8 - upper_bound_of_m
  // TODO: generate 256-bit circuit for mod to improve security parameters
  template <typename T, typename T_expand = get_expanded_type<T>>
  ShareWrapper GenerateRandomUnsignedIntegerBGMW(T m, const std::size_t num_of_simd) const;

  template <typename T, typename T_expand = get_expanded_type<T>>
  ShareWrapper GenerateRandomUnsignedIntegerBMR(T m, const std::size_t num_of_simd) const;

  template <typename T, typename T_expand = get_expanded_type<T>>
  ShareWrapper GenerateRandomUnsignedIntegerGC(T m, const std::size_t num_of_simd) const;

  // generate a geometric random variable x, i.e.,
  // count the number of 0s in random bits until the first 1 (including the first 1 bit),
  // PDF: (1-p)^(x-1) * p, p = 0.5, x is {1, 2, 3, ...},
  // if there is no 1 in the random_bits, treat as if the last bit is 1
  ShareWrapper SimpleGeometricSampling_1(const ShareWrapper& random_bits) const;

  // generate a geometric random variable x, i.e.,
  // count the number of 0s in random bits until the first 1 (excluding the first 1 bit),
  // PDF: (1-p)^(x) * p, p = 0.5, x is {0, 1, 2, 3, ...},
  // if there is no 1 in the random_bits, treat as if the last bit is 1
  ShareWrapper SimpleGeometricSampling_0(const ShareWrapper& random_bits) const;

  // generate uniform floating-point (64-bit) in [0,1)
  // based on paper (On Signiﬁcance of the Least Significant Bits For Differential Privacy)
  // random_bits_of_length_52 for mantissa
  // random_bits_of_length_1022 for unbiased exponent
  ShareWrapper UniformFloatingPoint64_0_1(const ShareWrapper& random_bits_of_length_52,
                                          const ShareWrapper& random_bits_of_length_1022) const;

  // generate uniform floating-point (32-bit) in [0,1)
  // random_bits_of_length_23 for mantissa
  // random_bits_of_length_126 for unbiased exponent
  ShareWrapper UniformFloatingPoint32_0_1(const ShareWrapper& random_bits_of_length_23,
                                          const ShareWrapper& random_bits_of_length_126) const;

  // generate uniform fixed point in [0,1)
  ShareWrapper UniformFixedPoint_0_1(const ShareWrapper& random_bits_of_length_fixed_point_fraction,
                                     const std::size_t fixed_point_bit_size = 64) const;

  // generate uniform fixed point in (0,1]
  ShareWrapper UniformFixedPoint_0_1_Up(
      const ShareWrapper& random_bits_of_length_fixed_point_fraction,
      const std::size_t fixed_point_bit_size = 64) const;

  // ============================================================
  // sampling algorithms based on floating-point arithmetic, Boolean GMW

  // sample from a Geometric distribution (PDF: (1 - p)^k * p), where p =
  // 1-e^(-numerator/denominator),
  // using bmgw floating-point (32-bit or 64-bit).
  // based on paper (The Discrete Gaussian for Differential Privacy)
  template <typename FloatType = double, typename UintType = std::uint64_t,
            typename IntType = std::make_signed_t<UintType>, typename A = std::allocator<UintType>>
  std::vector<ShareWrapper> FLGeometricDistributionEXP_BGMW(
      const std::vector<UintType>& constant_unsigned_integer_numerator_vector,
      const std::vector<UintType>& constant_unsigned_integer_denominator_vector,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
      const ShareWrapper& random_unsigned_integer_boolean_gmw_share, std::size_t iteration_1,
      std::size_t iteration_2) const;

  // a special case for FLGeometricDistributionEXP, where the denominator
  // equals to one, and the first for loop is skipped
  template <typename FloatType = double, typename UintType = std::uint64_t,
            typename IntType = std::make_signed_t<UintType>, typename A = std::allocator<UintType>>
  std::vector<ShareWrapper> FLGeometricDistributionEXP_BGMW(
      const std::vector<UintType>& constant_unsigned_integer_numerator_vector,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
      std::size_t iteration_2) const;

  // sample from a discrete Laplace(t) distribution, where Pr[x] =
  // exp(-abs(x)/t)*(exp(1/t)-1)/(exp(1/t)+1) #casts scale to Fraction
  // based on paper (The Discrete Gaussian for Differential Privacy)
  template <typename FloatType = double, typename UintType = std::uint64_t,
            typename IntType = std::make_signed_t<UintType>, typename A = std::allocator<UintType>>
  std::vector<ShareWrapper> FLDiscreteLaplaceDistribution_BGMW(
      const std::vector<UintType>& constant_unsigned_integer_numerator_vector,
      const std::vector<UintType>& constant_unsigned_integer_denominator_vector,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_geo,
      const ShareWrapper& random_unsigned_integer_boolean_gmw_share_geo,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap, std::size_t iteration_1,
      std::size_t iteration_2, std::size_t iteration_3) const;

  // a special case for FLDiscreteLaplaceDistribution, where the denominator
  // equals to one.
  template <typename FloatType = double, typename UintType = std::uint64_t,
            typename IntType = std::make_signed_t<UintType>, typename A = std::allocator<UintType>>
  std::vector<ShareWrapper> FLDiscreteLaplaceDistribution_BGMW(
      const std::vector<UintType>& constant_unsigned_integer_numerator_vector,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_geo,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap, std::size_t iteration_2,
      std::size_t iteration_3) const;

  // sample from a discrete Gaussian distribution
  // based on paper (The Discrete Gaussian for Differential Privacy)
  template <typename FloatType = double, typename UintType = std::uint64_t,
            typename IntType = std::make_signed_t<UintType>, typename A = std::allocator<UintType>>
  std::vector<ShareWrapper> FLDiscreteGaussianDistribution_BGMW(
      const std::vector<double>& constant_floating_point_sigma_vector,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
      const ShareWrapper& random_unsigned_integer_boolean_gmw_share_dlap,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau, std::size_t iteration_1,
      std::size_t iteration_2, std::size_t iteration_3, std::size_t iteration_4) const;

  // special case for FLDiscreteGaussianDistribution, where floor(sigma) + 1 =0
  template <typename FloatType = double, typename UintType = std::uint64_t,
            typename IntType = std::make_signed_t<UintType>, typename A = std::allocator<UintType>>
  std::vector<ShareWrapper> FLDiscreteGaussianDistribution_BGMW(
      const std::vector<double>& constant_floating_point_sigma_vector,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau, std::size_t iteration_2,
      std::size_t iteration_3, std::size_t iteration_4) const;

  // sample from a symmerical binomial distribution
  // based on paper (Secure Noise Generation,
  //
  // https://github.com/google/differential-privacy/blob/main/common_docs/Secure_Noise_Generation.pdf)
  template <typename FloatType = double, typename UintType = std::uint64_t>
  std::vector<ShareWrapper> FLSymmetricBinomialDistribution_BGMW(
      std::vector<double> constant_sqrt_n_vector,
      const ShareWrapper& unsigned_integer_boolean_gmw_share_geometric_sample,
      const ShareWrapper& boolean_gmw_share_random_bits,
      const ShareWrapper& random_unsigned_integer_boolean_gmw_share,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share, std::size_t iteration) const;

  // ============================================================
  // sampling algorithms based on floating-point arithmetic, Garbled Circuit

  // sample from a Geometric distribution (PDF: (1 - p)^k * p), where p =
  // 1-e^(-numerator/denominator),
  // using bmgw floating-point (32-bit or 64-bit).
  // based on paper (The Discrete Gaussian for Differential Privacy)
  template <typename FloatType = double, typename UintType = std::uint64_t,
            typename IntType = std::make_signed_t<UintType>, typename A = std::allocator<UintType>>
  std::vector<ShareWrapper> FLGeometricDistributionEXP_GC(
      const std::vector<UintType>& constant_unsigned_integer_numerator_vector,
      const std::vector<UintType>& constant_unsigned_integer_denominator_vector,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
      const ShareWrapper& random_unsigned_integer_boolean_gmw_share, std::size_t iteration_1,
      std::size_t iteration_2) const;

  // a special case for FLGeometricDistributionEXP, where the denominator
  // equals to one, and the first for loop is skipped
  template <typename FloatType = double, typename UintType = std::uint64_t,
            typename IntType = std::make_signed_t<UintType>, typename A = std::allocator<UintType>>
  std::vector<ShareWrapper> FLGeometricDistributionEXP_GC(
      const std::vector<UintType>& constant_unsigned_integer_numerator_vector,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
      std::size_t iteration_2) const;

  // sample from a discrete Laplace(t) distribution, where Pr[x] =
  // exp(-abs(x)/t)*(exp(1/t)-1)/(exp(1/t)+1) #casts scale to Fraction
  // based on paper (The Discrete Gaussian for Differential Privacy)
  template <typename FloatType = double, typename UintType = std::uint64_t,
            typename IntType = std::make_signed_t<UintType>, typename A = std::allocator<UintType>>
  std::vector<ShareWrapper> FLDiscreteLaplaceDistribution_GC(
      const std::vector<UintType>& constant_unsigned_integer_numerator_vector,
      const std::vector<UintType>& constant_unsigned_integer_denominator_vector,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_geo,
      const ShareWrapper& random_unsigned_integer_boolean_gmw_share_geo,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap, std::size_t iteration_1,
      std::size_t iteration_2, std::size_t iteration_3) const;

  // a special case for FLDiscreteLaplaceDistribution, where the denominator
  // equals to one.
  template <typename FloatType = double, typename UintType = std::uint64_t,
            typename IntType = std::make_signed_t<UintType>, typename A = std::allocator<UintType>>
  std::vector<ShareWrapper> FLDiscreteLaplaceDistribution_GC(
      const std::vector<UintType>& constant_unsigned_integer_numerator_vector,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_geo,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap, std::size_t iteration_2,
      std::size_t iteration_3) const;

  // sample from a discrete Gaussian distribution
  // based on paper (The Discrete Gaussian for Differential Privacy)
  template <typename FloatType = double, typename UintType = std::uint64_t,
            typename IntType = std::make_signed_t<UintType>, typename A = std::allocator<UintType>>
  std::vector<ShareWrapper> FLDiscreteGaussianDistribution_GC(
      const std::vector<double>& constant_floating_point_sigma_vector,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
      const ShareWrapper& random_unsigned_integer_boolean_gmw_share_dlap,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau, std::size_t iteration_1,
      std::size_t iteration_2, std::size_t iteration_3, std::size_t iteration_4) const;

  // special case for FLDiscreteGaussianDistribution, where floor(sigma) + 1 =0
  template <typename FloatType = double, typename UintType = std::uint64_t,
            typename IntType = std::make_signed_t<UintType>, typename A = std::allocator<UintType>>
  std::vector<ShareWrapper> FLDiscreteGaussianDistribution_GC(
      const std::vector<double>& constant_floating_point_sigma_vector,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau, std::size_t iteration_2,
      std::size_t iteration_3, std::size_t iteration_4) const;

  // sample from a symmerical binomial distribution
  // based on paper (Secure Noise Generation,
  //
  // https://github.com/google/differential-privacy/blob/main/common_docs/Secure_Noise_Generation.pdf)
  template <typename FloatType = double, typename UintType = std::uint64_t>
  std::vector<ShareWrapper> FLSymmetricBinomialDistribution_GC(
      std::vector<double> constant_sqrt_n_vector,
      const ShareWrapper& unsigned_integer_boolean_gmw_share_geometric_sample,
      const ShareWrapper& boolean_gmw_share_random_bits,
      const ShareWrapper& random_unsigned_integer_boolean_gmw_share,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share, std::size_t iteration) const;

  // ============================================================
  // sampling algorithms based on floating-point arithmetic, BMR

  // sample from a Geometric distribution (PDF: (1 - p)^k * p), where p =
  // 1-e^(-numerator/denominator),
  // using bmgw floating-point (32-bit or 64-bit).
  // based on paper (The Discrete Gaussian for Differential Privacy)
  template <typename FloatType = double, typename UintType = std::uint64_t,
            typename IntType = std::make_signed_t<UintType>, typename A = std::allocator<UintType>>
  std::vector<ShareWrapper> FLGeometricDistributionEXP_BMR(
      const std::vector<UintType>& constant_unsigned_integer_numerator_vector,
      const std::vector<UintType>& constant_unsigned_integer_denominator_vector,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
      const ShareWrapper& random_unsigned_integer_boolean_gmw_share, std::size_t iteration_1,
      std::size_t iteration_2) const;

  // a special case for FLGeometricDistributionEXP, where the denominator
  // equals to one, and the first for loop is skipped
  template <typename FloatType = double, typename UintType = std::uint64_t,
            typename IntType = std::make_signed_t<UintType>, typename A = std::allocator<UintType>>
  std::vector<ShareWrapper> FLGeometricDistributionEXP_BMR(
      const std::vector<UintType>& constant_unsigned_integer_numerator_vector,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
      std::size_t iteration_2) const;

  // sample from a discrete Laplace(t) distribution, where Pr[x] =
  // exp(-abs(x)/t)*(exp(1/t)-1)/(exp(1/t)+1) #casts scale to Fraction
  // based on paper (The Discrete Gaussian for Differential Privacy)
  template <typename FloatType = double, typename UintType = std::uint64_t,
            typename IntType = std::make_signed_t<UintType>, typename A = std::allocator<UintType>>
  std::vector<ShareWrapper> FLDiscreteLaplaceDistribution_BMR(
      const std::vector<UintType>& constant_unsigned_integer_numerator_vector,
      const std::vector<UintType>& constant_unsigned_integer_denominator_vector,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_geo,
      const ShareWrapper& random_unsigned_integer_boolean_gmw_share_geo,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap, std::size_t iteration_1,
      std::size_t iteration_2, std::size_t iteration_3) const;

  // a special case for FLDiscreteLaplaceDistribution, where the denominator
  // equals to one.
  template <typename FloatType = double, typename UintType = std::uint64_t,
            typename IntType = std::make_signed_t<UintType>, typename A = std::allocator<UintType>>
  std::vector<ShareWrapper> FLDiscreteLaplaceDistribution_BMR(
      const std::vector<UintType>& constant_unsigned_integer_numerator_vector,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_geo,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap, std::size_t iteration_2,
      std::size_t iteration_3) const;

  // sample from a discrete Gaussian distribution
  // based on paper (The Discrete Gaussian for Differential Privacy)
  template <typename FloatType = double, typename UintType = std::uint64_t,
            typename IntType = std::make_signed_t<UintType>, typename A = std::allocator<UintType>>
  std::vector<ShareWrapper> FLDiscreteGaussianDistribution_BMR(
      const std::vector<double>& constant_floating_point_sigma_vector,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
      const ShareWrapper& random_unsigned_integer_boolean_gmw_share_dlap,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau, std::size_t iteration_1,
      std::size_t iteration_2, std::size_t iteration_3, std::size_t iteration_4) const;

  // special case for FLDiscreteGaussianDistribution, where floor(sigma) + 1 =0
  template <typename FloatType = double, typename UintType = std::uint64_t,
            typename IntType = std::make_signed_t<UintType>, typename A = std::allocator<UintType>>
  std::vector<ShareWrapper> FLDiscreteGaussianDistribution_BMR(
      const std::vector<double>& constant_floating_point_sigma_vector,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau, std::size_t iteration_2,
      std::size_t iteration_3, std::size_t iteration_4) const;

  // sample from a symmerical binomial distribution
  // based on paper (Secure Noise Generation,
  //
  // https://github.com/google/differential-privacy/blob/main/common_docs/Secure_Noise_Generation.pdf)
  template <typename FloatType = double, typename UintType = std::uint64_t>
  std::vector<ShareWrapper> FLSymmetricBinomialDistribution_BMR(
      std::vector<double> constant_sqrt_n_vector,
      const ShareWrapper& unsigned_integer_boolean_gmw_share_geometric_sample,
      const ShareWrapper& boolean_gmw_share_random_bits,
      const ShareWrapper& random_unsigned_integer_boolean_gmw_share,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share, std::size_t iteration) const;

  // ============================================================

 private:
  std::shared_ptr<ShareWrapper> share_{nullptr};
  std::shared_ptr<Logger> logger_{nullptr};
};
}  // namespace encrypto::motion