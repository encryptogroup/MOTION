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
namespace encrypto::motion {

// primary reference: https://github.com/liangzhao-darmstadt/Securely-Realizing-Output-Privacy-in-MPC-using-Differential-Privacy/blob/dev/Securely%20Realizing%20Output%20Privacy%20in%20MPC%20using%20Differential%20Privacy.pdf

class SecureDPMechanismHelper {
 public:
  SecureDPMechanismHelper() : share_(nullptr){};

  SecureDPMechanismHelper(const SharePointer& share) : share_(share) {}

  SecureDPMechanismHelper(const ShareWrapper& sw) : share_(sw.Get()) {}

  SecureDPMechanismHelper(const SecureDPMechanismHelper& sw) : share_(sw.share_) {}

 public:
  /// \brief generates random boolean gmw bits locally
  ShareWrapper GenerateRandomBooleanGmwBits(const std::size_t num_of_wires,
                                            const std::size_t num_of_bits) const;

  /// \brief generates random integer in range [0, m),
  // with security parameter s = sizeof(T) * 8 - upper_bound_of_m
  // TODO: generate 256-bit circuit for modulo reduction to improve security parameters
  template <typename T>
  ShareWrapper GenerateRandomUnsignedInteger(T m, const std::size_t num_of_simd) const;

  /// \brief add zero bits boolean bits, s.t., it have num_of_total_bits bits
  ShareWrapper BooleanGmwBitsZeroCompensation(const ShareWrapper& boolean_gmw_share_bits,
                                              const std::size_t num_of_total_bits) const;

  // PreOr algorithm with O(log(k) rounds based on SecureSCM-D.9.2, ref:
  // (https://faui1-files.cs.fau.de/filepool/publications/octavian_securescm/SecureSCM-D.9.2.pdf)
  // and MP-SPDZ (https://github.com/data61/MP-SPDZ)
  ShareWrapper PreOrL() const;

  // PreOr algorithm with O(log(k) rounds based on SecureSCM-D.9.2, ref:
  // (https://faui1-files.cs.fau.de/filepool/publications/octavian_securescm/SecureSCM-D.9.2.pdf)
  // and MP-SPDZ (https://github.com/data61/MP-SPDZ)
  ShareWrapper PreOrL(const ShareWrapper& random_bits) const;

  /// \brief counts the number of 0 in random bits until the first 1 (including the first 1 bit)
  // (1-p)^(k-1) * p, p = 0.5, k is {1, 2, 3, ...}
  // if there is no 1 in the random_bits, treat as if the last bit is 1
  ShareWrapper SimpleGeometricSampling_1(const ShareWrapper& random_bits) const;

  /// \brief counts the number of 0 in random bits until the first 1 (excluding the first 1 bit)
  // (1-p)^(k) * p, p = 0.5, k is {0, 1, 2, 3, ...}
  // if there is no 1 in the random_bits, treat as if the last bit is 1
  ShareWrapper SimpleGeometricSampling_0(const ShareWrapper& random_bits) const;

  /// \brief generates uniform floating-point (64-bit) in [0,1)
  // based on paper (On Signiﬁcance of the Least Signiﬁcant Bits For Differential Privacy)
  // random_bits_of_length_52 for mantissa
  // random_bits_of_length_1022 for unbiased exponent
  ShareWrapper UniformFloatingPoint64_0_1(const ShareWrapper& random_bits_of_length_52,
                                          const ShareWrapper& random_bits_of_length_1022) const;

  /// \brief generates uniform floating-point (32-bit) in [0,1)
  // random_bits_of_length_23 for mantissa
  // random_bits_of_length_126 for unbiased exponent
  ShareWrapper UniformFloatingPoint32_0_1(const ShareWrapper& random_bits_of_length_23,
                                          const ShareWrapper& random_bits_of_length_126) const;

  /// \brief generates uniform fixed point in [0,1)
  // T: integer to represent fixed point
  ShareWrapper UniformFixedPoint_0_1(const ShareWrapper& random_bits_of_length_fixed_point_fraction,
                                     const std::size_t fixed_point_bit_size = 64) const;

  /// \brief generates uniform fixed point in (0,1]
  // T: integer to represent fixed point
  ShareWrapper UniformFixedPoint_0_1_Up(
      const ShareWrapper& random_bits_of_length_fixed_point_fraction,
      const std::size_t fixed_point_bit_size = 64) const;

  // use the inverted binary tree to select the first element yi such that ci = 1
  // y = y0 || ... || yn
  // c = c0 || ... || cn
  std::vector<ShareWrapper> InvertBinaryTreeSelection(
      const std::vector<ShareWrapper>& boolean_gmw_share_y_vector,
      const std::vector<ShareWrapper>& boolean_gmw_share_c_vector) const;

  // reshape shares in input into a larger share with num_of_wires wires and num_of_simd bits in
  // each wire
  // for example: num_of_wires = 2, num_of_simd = 3
  // std::vector {s_0, s_1, s_2, s_3, s_4, s_5} -> wire_1, wire_2,
  // wire_1: {s_0, s_2, s_4}, wire_2: {s_1, s_3, s_5}
  static std::vector<ShareWrapper> SimdifyReshapeHorizontal(std::vector<ShareWrapper> input,
                                                            std::size_t num_of_wires,
                                                            std::size_t num_of_simd);

  // reshape shares in input into a larger share with num_of_wires wires and num_of_simd bits in
  // each wire
  // for example: num_of_wires = 2, num_of_simd = 3
  // std::vector {s_0, s_1, s_2, s_3, s_4, s_5} -> wire_1, wire_2,
  // wire_1: {s_0, s_1, s_2}, wire_2: {s_3, s_4, s_5}
  static std::vector<ShareWrapper> SimdifyReshapeVertical(std::vector<ShareWrapper> input,
                                                          std::size_t num_of_wires,
                                                          std::size_t num_of_simd);

  // reshape shares in input into a larger share with num_of_wires wires and num_of_simd bits in
  // each wire
  // for example: num_of_wires = 2, num_of_simd = 3
  // std::vector {s_0, s_1, s_2} -> wire_1, wire_2,
  // wire_1: {s_0, s_1, s_2}, wire_2: {s_0, s_1, s_2}
  static std::vector<ShareWrapper> SimdifyDuplicateHorizontal(std::vector<ShareWrapper> input,
                                                              std::size_t num_of_wires);

  // reshape shares in input into a larger share with num_of_wires wires and num_of_simd bits in
  // each wire
  // for example: num_of_wires = 2, num_of_simd = 3
  // std::vector {s_0, s_1} -> wire_1, wire_2,
  // wire_1: {s_0, s_0}, wire_2: {s_1, s_1}
  static std::vector<ShareWrapper> SimdifyDuplicateVertical(std::vector<ShareWrapper> input,
                                                            std::size_t num_of_simd);

  // =================================================================
  // following functions are implemented with floating-point arithmetic
  // =================================================================

  /// \brief generates geometric random variable
  // based on (https://github.com/google/differential-privacy/blob/main/go/noise/laplace_noise.go)
  // TODO: this method cost too much memory, cannot use SIMD to eliminate the FOR loops
  template <typename T>
  ShareWrapper GeometricSamplingWithBinarySearch(
      const T L0, const T R0, const double lambda, const std::size_t iteration,
      const std::vector<ShareWrapper>& uniform_floating_point_0_1_vector) const;

  /// \brief samples from Bernoulli distribution function with probability p
  ShareWrapper FLBernoulliDistribution(
      const ShareWrapper& floating_point_boolean_gmw_share_p,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_vector) const;

  /// \brief samples from Geometric distribution (PDF: (1 - p)^k * p), where p =
  // 1-e^(-numerator/denominator),
  // using bmgw floating-point (32-bit or 64-bit).
  // based on paper (The Discrete Gaussian for Differential Privacy)
  template <typename FLType = float, typename T = std::uint64_t, typename T_int = std::int64_t>
  std::vector<ShareWrapper> FLGeometricDistributionEXP(
      const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
      const std::vector<std::uint64_t>& constant_unsigned_integer_denominator_vector,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
      const ShareWrapper& random_unsigned_integer_boolean_gmw_share, std::size_t iteration_1,
      std::size_t iteration_2) const;

  // special case for FLGeometricDistributionEXP, where denominator
  // equals to one.
  template <typename FLType = float, typename T = std::uint64_t, typename T_int = std::int64_t>
  std::vector<ShareWrapper> FLGeometricDistributionEXP(
      const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
      std::size_t iteration_2) const;

  /// \brief samples from a discrete Laplace distribution
  /// (Geo(x|scale=denominator/numerator) = exp(-abs(x)/scale)*(exp(1/scale)-1)/(exp(1/scale)+1)
  /// #casts scale to Fraction,
  // #assumes scale>=0
  // based on paper (The Discrete Gaussian for Differential Privacy)
  template <typename FLType = float, typename T = std::uint64_t, typename T_int = std::int64_t>
  std::vector<ShareWrapper> FLDiscreteLaplaceDistribution(
      const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
      const std::vector<std::uint64_t>& constant_unsigned_integer_denominator_vector,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_geo,
      const ShareWrapper& random_unsigned_integer_boolean_gmw_share_geo,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap, std::size_t iteration_1,
      std::size_t iteration_2, std::size_t iteration_3) const;

  // special case for FLDiscreteLaplaceDistribution, where denominator
  // equals to one.
  template <typename FLType = float, typename T = std::uint64_t, typename T_int = std::int64_t>
  std::vector<ShareWrapper> FLDiscreteLaplaceDistribution(
      const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_geo,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap, std::size_t iteration_2,
      std::size_t iteration_3) const;

  /// \brief samples from a discrete Gaussian distribution
  // based on paper (The Discrete Gaussian for Differential Privacy)
  template <typename FLType = float, typename T = std::uint64_t, typename T_int = std::int64_t>
  std::vector<ShareWrapper> FLDiscreteGaussianDistribution(
      const std::vector<double>& constant_floating_point_sigma_vector,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
      const ShareWrapper& random_unsigned_integer_boolean_gmw_share_dlap,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau, std::size_t iteration_1,
      std::size_t iteration_2, std::size_t iteration_3, std::size_t iteration_4,
      std::size_t upscale_factor = 1) const;

  // special case for FLDiscreteGaussianDistribution, where floor(sigma) + 1 =0
  template <typename FLType = float, typename T = std::uint64_t, typename T_int = std::int64_t>
  std::vector<ShareWrapper> FLDiscreteGaussianDistribution(
      const std::vector<double>& constant_floating_point_sigma_vector,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau, std::size_t iteration_2,
      std::size_t iteration_3, std::size_t iteration_4) const;

  // based on paper (Secure Noise Generation,
  // https://github.com/google/differential-privacy/blob/main/common_docs/Secure_Noise_Generation.pdf)
  template <typename FLType = double, typename IntType = __uint128_t,
            typename IntType_int = __int128_t>
  std::vector<ShareWrapper> FLSymmetricBinomialDistribution(
      std::vector<double> constant_sqrt_n_vector,
      const ShareWrapper& unsigned_integer_boolean_gmw_share_geometric_sample,
      const ShareWrapper& boolean_gmw_share_random_bits,
      const ShareWrapper& random_unsigned_integer_boolean_gmw_share,
      const ShareWrapper& random_floating_point_0_1_boolean_gmw_share, std::size_t iteration) const;

  // =================================================================
  // following functions are implemented with fixed-point arithmetic
  // =================================================================

  template <typename FxType = double, typename T = std::uint64_t, typename T_int = std::int64_t>
  std::vector<ShareWrapper> FxGeometricDistributionEXP(
      const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
      const std::vector<std::uint64_t>& constant_unsigned_integer_denominator_vector,
      const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share,
      const ShareWrapper& random_unsigned_integer_boolean_gmw_share, std::size_t iteration_1,
      std::size_t iteration_2, std::size_t fixed_point_fraction_bit_size) const;

  template <typename FxType = double, typename T = std::uint64_t, typename T_int = std::int64_t>
  std::vector<ShareWrapper> FxGeometricDistributionEXP(
      const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
      const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share, std::size_t iteration_2,
      std::size_t fixed_point_fraction_bit_size) const;

  template <typename FxType = double, typename T = std::uint64_t, typename T_int = std::int64_t>
  std::vector<ShareWrapper> FxDiscreteLaplaceDistribution(
      const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
      const std::vector<std::uint64_t>& constant_unsigned_integer_denominator_vector,
      const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_geo,
      const ShareWrapper& random_unsigned_integer_boolean_gmw_share_geo,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap, std::size_t iteration_1,
      std::size_t iteration_2, std::size_t iteration_3,
      std::size_t fixed_point_fraction_bit_size) const;

  template <typename FxType = double, typename T = std::uint64_t, typename T_int = std::int64_t>
  std::vector<ShareWrapper> FxDiscreteLaplaceDistribution(
      const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
      const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_geo,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap, std::size_t iteration_2,
      std::size_t iteration_3, std::size_t fixed_point_fraction_bit_size) const;

  template <typename FxType = double, typename T = std::uint64_t, typename T_int = std::int64_t>
  std::vector<ShareWrapper> FxDiscreteGaussianDistribution(
      const std::vector<double>& constant_fixed_point_sigma_vector,
      const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_dlap,
      const ShareWrapper& random_unsigned_integer_boolean_gmw_share_dlap,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
      const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_dgau, std::size_t iteration_1,
      std::size_t iteration_2, std::size_t iteration_3, std::size_t iteration_4,
      std::size_t upscale_factor, std::size_t fixed_point_fraction_bit_size) const;

  template <typename FxType = double, typename T = std::uint64_t, typename T_int = std::int64_t>
  std::vector<ShareWrapper> FxDiscreteGaussianDistribution(
      const std::vector<double>& constant_fixed_point_sigma_vector,
      const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_dlap,
      const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
      const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_dgau, std::size_t iteration_2,
      std::size_t iteration_3, std::size_t iteration_4,
      std::size_t fixed_point_fraction_bit_size) const;

 private:
  SharePointer share_;
};

}  // namespace encrypto::motion