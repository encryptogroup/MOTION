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
#include "secure_dp_mechanism/secure_sampling_algorithm_optimized.h"
#include <fmt/format.h>
#include <iterator>

#include "algorithm/algorithm_description.h"
#include "algorithm/boolean_algorithms.h"
#include "base/backend.h"
#include "base/register.h"
#include "protocols/data_management/unsimdify_gate.h"
#include "utility/bit_vector.h"
#include "utility/constants.h"
#include "utility/logger.h"

namespace encrypto::motion {

SecureSamplingAlgorithm_optimized::SecureSamplingAlgorithm_optimized(const SharePointer& other)
    : share_(std::make_unique<ShareWrapper>(other)),
      logger_(share_.get()->Get()->GetRegister()->GetLogger()) {}

SecureSamplingAlgorithm_optimized::SecureSamplingAlgorithm_optimized(SharePointer&& other)
    : share_(std::make_unique<ShareWrapper>(std::move(other))),
      logger_(share_.get()->Get()->GetRegister()->GetLogger()) {}

ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomBooleanGmwBits(
    const std::size_t num_of_bits, const std::size_t num_of_simd) const {
  std::vector<BitVector<>> random_bitvector_vector;
  random_bitvector_vector.reserve(num_of_bits);

  for (std::size_t i = 0; i < num_of_bits; i++) {
    random_bitvector_vector.emplace_back(BitVector<>::SecureRandom(num_of_simd));
  }

  //   std::size_t party_id = (share_->Get())->GetBackend().GetCommunicationLayer().GetMyId();

  //   ShareWrapper boolean_gmw_share_random_bits =
  //       (share_->Get())->GetBackend().BooleanGmwInput(party_id, random_bitvector_vector);

  // each parties locally generate random bits
  ShareWrapper boolean_gmw_share_random_bits =
      (share_->Get())->GetBackend().ConstantAsBooleanGmwInput(random_bitvector_vector);

  return boolean_gmw_share_random_bits;
}

ShareWrapper SecureSamplingAlgorithm_optimized::BooleanBitsShareZeroCompensation(
    const ShareWrapper& boolean_gmw_gc_bmr_share_bits, const std::size_t num_of_total_bits) const {
  //   std::size_t T_size = sizeof(UintType) * 8;

  std::size_t boolean_gmw_gc_bmr_share_bits_vector_size =
      boolean_gmw_gc_bmr_share_bits.Split().size();

  //   std::cout << "boolean_gmw_share_bits_vector_size: " << boolean_gmw_share_bits_vector_size
  //             << std::endl;

  //   assert(boolean_gmw_share_bits_vector_size > num_of_total_bits);

  std::vector<ShareWrapper> boolean_gmw_gc_bmr_share_bits_vector =
      boolean_gmw_gc_bmr_share_bits.Split();

  //   ShareWrapper constant_boolean_gmw_share_zero =
  //   boolean_gmw_share_bits_vector[0] ^ boolean_gmw_share_bits_vector[0];

  ShareWrapper constant_boolean_gmw_gc_bmr_share_zero;
  switch (boolean_gmw_gc_bmr_share_bits->GetProtocol()) {
    case MpcProtocol::kBooleanGmw: {
      constant_boolean_gmw_gc_bmr_share_zero =
          boolean_gmw_gc_bmr_share_bits_vector[0].CreateConstantAsBooleanGmwInput(false);
      break;
    }
    case MpcProtocol::kGarbledCircuit: {
      constant_boolean_gmw_gc_bmr_share_zero =
          boolean_gmw_gc_bmr_share_bits_vector[0].CreateConstantAsGCInput(false);
      break;
    }
    case MpcProtocol::kBmr: {
      constant_boolean_gmw_gc_bmr_share_zero =
          boolean_gmw_gc_bmr_share_bits_vector[0].CreateConstantAsBmrInput(false);
      break;
    }

    default: {
      throw std::runtime_error("Unsupported protocol");
    }
  }

  //   ShareWrapper constant_boolean_gmw_gc_bmr_share_zero =
  //       boolean_gmw_gc_bmr_share_bits_vector[0].CreateConstantAsBooleanGmwInput(false);

  std::vector<ShareWrapper> boolean_gmw_gc_bmr_share_bits_with_zero_compensation_vector(
      num_of_total_bits);
  for (std::size_t i = 0; i < num_of_total_bits; i++) {
    boolean_gmw_gc_bmr_share_bits_with_zero_compensation_vector[i] =
        constant_boolean_gmw_gc_bmr_share_zero;
  }

  for (std::size_t i = 0; i < boolean_gmw_gc_bmr_share_bits_vector_size; i++) {
    boolean_gmw_gc_bmr_share_bits_with_zero_compensation_vector[i] =
        boolean_gmw_gc_bmr_share_bits_vector[i];
  }

  return ShareWrapper::Concatenate(boolean_gmw_gc_bmr_share_bits_with_zero_compensation_vector);
}

// =================================================================================================
// generate random integers locally using BooleanGMW

template <typename T>
ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedIntegerPow2_BGMW(
    std::size_t bit_size_k, const std::size_t num_of_simd) const {
  assert(sizeof(T) * 8 >= bit_size_k);
  std::size_t T_size = sizeof(T) * 8;

  // generate random bits to build random unsigned integer in range [0,2^k-1]
  ShareWrapper boolean_gmw_share_random_bits =
      GenerateRandomBooleanGmwBits(bit_size_k, num_of_simd);

  // generate constant zero bits
  std::vector<BitVector<>> constant_zero_bitvector_vector;
  constant_zero_bitvector_vector.reserve(T_size - bit_size_k);

  // compensate the rest bits with zero bits
  for (std::size_t i = 0; i < T_size - bit_size_k; i++) {
    constant_zero_bitvector_vector.emplace_back(num_of_simd);
  }

  ShareWrapper boolean_gmw_share_constant_zero_bits =
      (share_->Get())->GetBackend().ConstantAsBooleanGmwInput(constant_zero_bitvector_vector);

  ShareWrapper boolean_gmw_random_unsigned_integer = ShareWrapper::Concatenate(
      std::vector{boolean_gmw_share_random_bits, boolean_gmw_share_constant_zero_bits});

  return boolean_gmw_random_unsigned_integer;
}

template ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedIntegerPow2_BGMW<
    std::uint8_t>(std::size_t bit_size_k, const std::size_t num_of_simd) const;
template ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedIntegerPow2_BGMW<
    std::uint16_t>(std::size_t bit_size_k, const std::size_t num_of_simd) const;
template ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedIntegerPow2_BGMW<
    std::uint32_t>(std::size_t bit_size_k, const std::size_t num_of_simd) const;
template ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedIntegerPow2_BGMW<
    std::uint64_t>(std::size_t bit_size_k, const std::size_t num_of_simd) const;
template ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedIntegerPow2_BGMW<
    __uint128_t>(std::size_t bit_size_k, const std::size_t num_of_simd) const;

template <typename T>
ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedIntegerPow2_GC(
    std::size_t bit_size_k, const std::size_t num_of_simd) const {
  assert(sizeof(T) * 8 >= bit_size_k);
  std::size_t T_size = sizeof(T) * 8;

  // generate random bits to build random unsigned integer in range [0,2^k-1]
  ShareWrapper boolean_gmw_share_random_bits =
      GenerateRandomBooleanGmwBits(bit_size_k, num_of_simd);

  // generate constant zero bits
  std::vector<BitVector<>> constant_zero_bitvector_vector;
  constant_zero_bitvector_vector.reserve(T_size - bit_size_k);

  // compensate the rest bits with zero bits
  for (std::size_t i = 0; i < T_size - bit_size_k; i++) {
    constant_zero_bitvector_vector.emplace_back(num_of_simd);
  }

  ShareWrapper boolean_gmw_share_constant_zero_bits =
      (share_->Get())->GetBackend().ConstantAsBooleanGmwInput(constant_zero_bitvector_vector);

  ShareWrapper boolean_gmw_random_unsigned_integer = ShareWrapper::Concatenate(
      std::vector{boolean_gmw_share_random_bits, boolean_gmw_share_constant_zero_bits});

  return boolean_gmw_random_unsigned_integer.Convert<MpcProtocol::kGarbledCircuit>();
}

template ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedIntegerPow2_GC<
    std::uint8_t>(std::size_t bit_size_k, const std::size_t num_of_simd) const;
template ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedIntegerPow2_GC<
    std::uint16_t>(std::size_t bit_size_k, const std::size_t num_of_simd) const;
template ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedIntegerPow2_GC<
    std::uint32_t>(std::size_t bit_size_k, const std::size_t num_of_simd) const;
template ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedIntegerPow2_GC<
    std::uint64_t>(std::size_t bit_size_k, const std::size_t num_of_simd) const;
template ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedIntegerPow2_GC<
    __uint128_t>(std::size_t bit_size_k, const std::size_t num_of_simd) const;

template <typename T>
ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedIntegerPow2_BMR(
    std::size_t bit_size_k, const std::size_t num_of_simd) const {
  assert(sizeof(T) * 8 >= bit_size_k);
  std::size_t T_size = sizeof(T) * 8;

  // generate random bits to build random unsigned integer in range [0,2^k-1]
  ShareWrapper boolean_gmw_share_random_bits =
      GenerateRandomBooleanGmwBits(bit_size_k, num_of_simd);

  // generate constant zero bits
  std::vector<BitVector<>> constant_zero_bitvector_vector;
  constant_zero_bitvector_vector.reserve(T_size - bit_size_k);

  // compensate the rest bits with zero bits
  for (std::size_t i = 0; i < T_size - bit_size_k; i++) {
    constant_zero_bitvector_vector.emplace_back(num_of_simd);
  }

  ShareWrapper boolean_gmw_share_constant_zero_bits =
      (share_->Get())->GetBackend().ConstantAsBooleanGmwInput(constant_zero_bitvector_vector);

  ShareWrapper boolean_gmw_random_unsigned_integer = ShareWrapper::Concatenate(
      std::vector{boolean_gmw_share_random_bits, boolean_gmw_share_constant_zero_bits});

  return boolean_gmw_random_unsigned_integer.Convert<MpcProtocol::kBmr>();
}

template ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedIntegerPow2_BMR<
    std::uint8_t>(std::size_t bit_size_k, const std::size_t num_of_simd) const;
template ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedIntegerPow2_BMR<
    std::uint16_t>(std::size_t bit_size_k, const std::size_t num_of_simd) const;
template ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedIntegerPow2_BMR<
    std::uint32_t>(std::size_t bit_size_k, const std::size_t num_of_simd) const;
template ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedIntegerPow2_BMR<
    std::uint64_t>(std::size_t bit_size_k, const std::size_t num_of_simd) const;
template ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedIntegerPow2_BMR<
    __uint128_t>(std::size_t bit_size_k, const std::size_t num_of_simd) const;

// =================================================================================================
// ! generate random unsigned integer using modular reduction
// ! this is expensive

template <typename T, typename T_expand>
ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedInteger_BGMW(
    T m, const std::size_t num_of_simd) const {
  std::size_t T_expand_size = sizeof(T_expand) * 8;
  ShareWrapper boolean_gmw_share_random_bits =
      GenerateRandomBooleanGmwBits(T_expand_size, num_of_simd);
  SecureUnsignedInteger random_unsigned_integer =
      SecureUnsignedInteger(boolean_gmw_share_random_bits);
  SecureUnsignedInteger random_unsigned_integer_bgmw_0_m = random_unsigned_integer.Mod(T_expand(m));

  return random_unsigned_integer_bgmw_0_m.TruncateToHalfSize();
}

template ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedInteger_BGMW<
    std::uint8_t, std::uint16_t>(std::uint8_t m, const std::size_t num_of_simd) const;
template ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedInteger_BGMW<
    std::uint16_t, std::uint32_t>(std::uint16_t m, const std::size_t num_of_simd) const;
template ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedInteger_BGMW<
    std::uint32_t, std::uint64_t>(std::uint32_t m, const std::size_t num_of_simd) const;
template ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedInteger_BGMW<
    std::uint64_t, __uint128_t>(std::uint64_t m, const std::size_t num_of_simd) const;

// ! this need 256-bit modular reduction circuit
// template ShareWrapper
// SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedInteger_BGMW<__uint128_t>(
//     __uint128_t m, const std::size_t num_of_simd) const;

template <typename T, typename T_expand>
ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedInteger_BMR(
    T m, const std::size_t num_of_simd) const {
  std::size_t T_expand_size = sizeof(T_expand) * 8;
  ShareWrapper boolean_gmw_share_random_bits =
      GenerateRandomBooleanGmwBits(T_expand_size, num_of_simd);
  SecureUnsignedInteger random_unsigned_integer =
      SecureUnsignedInteger(boolean_gmw_share_random_bits.Convert<MpcProtocol::kBmr>());

  SecureUnsignedInteger random_unsigned_integer_bmr_share_0_m =
      random_unsigned_integer.Mod(T_expand(m));

  return random_unsigned_integer_bmr_share_0_m.TruncateToHalfSize();
}

template ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedInteger_BMR<
    std::uint8_t, std::uint16_t>(std::uint8_t m, const std::size_t num_of_simd) const;
template ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedInteger_BMR<
    std::uint16_t, std::uint32_t>(std::uint16_t m, const std::size_t num_of_simd) const;
template ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedInteger_BMR<
    std::uint32_t, std::uint64_t>(std::uint32_t m, const std::size_t num_of_simd) const;
template ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedInteger_BMR<
    std::uint64_t, __uint128_t>(std::uint64_t m, const std::size_t num_of_simd) const;

// ! this need 256-bit modular reduction circuit
// template ShareWrapper
// SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedInteger_BMR<__uint128_t>(
//     __uint128_t m, const std::size_t num_of_simd) const;

template <typename T, typename T_expand>
ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedInteger_GC(
    T m, const std::size_t num_of_simd) const {
  std::size_t T_expand_size = sizeof(T_expand) * 8;
  ShareWrapper boolean_gmw_share_random_bits =
      GenerateRandomBooleanGmwBits(T_expand_size, num_of_simd);
  SecureUnsignedInteger random_unsigned_integer =
      SecureUnsignedInteger(boolean_gmw_share_random_bits.Convert<MpcProtocol::kGarbledCircuit>());
  SecureUnsignedInteger random_unsigned_integer_gc_share_0_m =
      random_unsigned_integer.Mod(T_expand(m));

  return random_unsigned_integer_gc_share_0_m.TruncateToHalfSize();
}

template ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedInteger_GC<
    std::uint8_t, std::uint16_t>(std::uint8_t m, const std::size_t num_of_simd) const;
template ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedInteger_GC<
    std::uint16_t, std::uint32_t>(std::uint16_t m, const std::size_t num_of_simd) const;
template ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedInteger_GC<
    std::uint32_t, std::uint64_t>(std::uint32_t m, const std::size_t num_of_simd) const;
template ShareWrapper SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedInteger_GC<
    std::uint64_t, __uint128_t>(std::uint64_t m, const std::size_t num_of_simd) const;

// ! this need 256-bit modular reduction circuit
// template ShareWrapper
// SecureSamplingAlgorithm_optimized::GenerateRandomUnsignedInteger_GC<__uint128_t>(
//     __uint128_t m, const std::size_t num_of_simd) const;

// =================================================================================================
// Geometric(p = 0.5)

// TODO: what if input random_bits are BMR or GC
ShareWrapper SecureSamplingAlgorithm_optimized::SimpleGeometricSampling_1(
    const ShareWrapper& random_bits) const {
  ShareWrapper random_bits_pre_or = random_bits.PreOrL();

  std::vector<ShareWrapper> random_bits_pre_or_vector = random_bits_pre_or.Split();

  //   ShareWrapper constant_boolean_gmw_share_one =
  //       random_bits_pre_or_vector[0] ^ (~random_bits_pre_or_vector[0]);
  //   ShareWrapper constant_boolean_gmw_share_zero =
  //       random_bits_pre_or_vector[0] ^ (random_bits_pre_or_vector[0]);
  ShareWrapper constant_boolean_gmw_share_one =
      (random_bits_pre_or_vector[0]).CreateConstantAsBooleanGmwInput(true);
  ShareWrapper constant_boolean_gmw_share_zero =
      (random_bits_pre_or_vector[0]).CreateConstantAsBooleanGmwInput(false);

  std::size_t num_of_random_bits = random_bits_pre_or_vector.size();

  std::vector<ShareWrapper> random_bits_pre_or_vector_right_shift_by_1_vector(num_of_random_bits);
  random_bits_pre_or_vector_right_shift_by_1_vector[0] = constant_boolean_gmw_share_zero;
  for (std::size_t i = 1; i < num_of_random_bits; i++) {
    random_bits_pre_or_vector_right_shift_by_1_vector[i] = random_bits_pre_or_vector[i - 1];
  }

  ShareWrapper random_bits_pre_or_right_shift_by_1 =
      ShareWrapper::Concatenate(random_bits_pre_or_vector_right_shift_by_1_vector);

  ShareWrapper random_bits_pre_or_right_shift_by_1_invert = ~random_bits_pre_or_right_shift_by_1;

  ShareWrapper hamming_weight =
      encrypto::motion::algorithm::HammingWeight(random_bits_pre_or_right_shift_by_1_invert);

  return hamming_weight;
}

ShareWrapper SecureSamplingAlgorithm_optimized::SimpleGeometricSampling_0(
    const ShareWrapper& random_bits) const {
  ShareWrapper random_bits_pre_or = random_bits.PreOrL();

  //   std::vector<ShareWrapper> random_bits_pre_or_vector = random_bits_pre_or.Split();

  //   ShareWrapper random_bits_pre_or = Concatenate(random_bits_pre_or_vector);
  ShareWrapper random_bits_pre_or_invert = ~random_bits_pre_or;
  ShareWrapper hamming_weight =
      encrypto::motion::algorithm::HammingWeight(random_bits_pre_or_invert);

  return hamming_weight;
}

// =================================================================================================
// uniformly random floating-point

// TODO: change this to support BooleanGMW, Garbled Circuit and BMR,
// TODO: change its sub-protocols also
ShareWrapper SecureSamplingAlgorithm_optimized::UniformFloatingPoint64_0_1(
    const ShareWrapper& random_bits_of_length_52,
    const ShareWrapper& random_bits_of_length_1022) const {
  //   std::cout << "UniformFloatingPoint64_0_1" << std::endl;

  using T = std::uint16_t;
  std::size_t T_size = sizeof(T) * 8;

  std::size_t double_precision_floating_point_bit_length = 64;
  std::size_t double_precision_floating_point_mantissa_bit_length = 52;
  std::size_t double_precision_floating_point_exponent_bit_length = 11;
  std::size_t double_precision_floating_point_sign_bit_length = 1;

  // TODO: we assume that the geomertic sampling always success (there is always 1 in
  // random_bits_of_length_1022), the probability for this assumption to fail is 2^(-1022)

  ShareWrapper boolean_gmw_share_geometric_sample =
      SimpleGeometricSampling_1(random_bits_of_length_1022);

  //   std::cout << "UniformFloatingPoint64_0_1 SimpleGeometricSampling_1" << std::endl;

  // compensate boolean_gmw_share_geometric_sample with 0 and convert to secure unsigned integer
  std::vector<ShareWrapper> boolean_gmw_share_geometric_sample_vector =
      boolean_gmw_share_geometric_sample.Split();
  std::size_t boolean_gmw_share_geometric_sample_vector_size =
      boolean_gmw_share_geometric_sample_vector.size();

  //   ShareWrapper constant_boolean_gmw_share_zero =
  //       boolean_gmw_share_geometric_sample_vector[0] ^
  //       boolean_gmw_share_geometric_sample_vector[0];
  ShareWrapper constant_boolean_gmw_share_zero =
      boolean_gmw_share_geometric_sample_vector[0].CreateConstantAsBooleanGmwInput(false);

  //   std::cout << "UniformFloatingPoint64_0_1 000" << std::endl;
  //   ShareWrapper constant_boolean_gmw_share_one = boolean_gmw_share_geometric_sample_vector[0] ^
  //                                                 (~boolean_gmw_share_geometric_sample_vector[0]);
  ShareWrapper constant_boolean_gmw_share_one =
      boolean_gmw_share_geometric_sample_vector[0].CreateConstantAsBooleanGmwInput(true);

  //   std::cout << "UniformFloatingPoint64_0_1 111" << std::endl;
  std::vector<ShareWrapper> boolean_gmw_share_exponent_unbiased_vector(T_size);
  for (std::size_t i = 0; i < T_size; i++) {
    boolean_gmw_share_exponent_unbiased_vector[i] = constant_boolean_gmw_share_zero;
  }

  for (std::size_t i = 0; i < boolean_gmw_share_geometric_sample_vector_size; i++) {
    boolean_gmw_share_exponent_unbiased_vector[i] = boolean_gmw_share_geometric_sample_vector[i];
  }

  SecureUnsignedInteger secure_unsigned_integer_unbiased_exponent =
      SecureUnsignedInteger(ShareWrapper::Concatenate(boolean_gmw_share_exponent_unbiased_vector));

  //   std::cout << "UniformFloatingPoint64_0_1 111" << std::endl;

  //   std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  std::size_t num_of_simd = random_bits_of_length_52->GetNumberOfSimdValues();
  //   std::cout << "num_of_simd: " << num_of_simd << std::endl;

  //   std::cout<<"share_->GetNumberOfSimdValues(): "<<share_->GetNumberOfSimdValues()<<std::endl;
  //   std::cout<<"random_bits_of_length_52->GetNumberOfSimdValues():
  //   "<<random_bits_of_length_52->GetNumberOfSimdValues()<<std::endl;
  //   std::cout<<"random_bits_of_length_1022->GetNumberOfSimdValues():
  //   "<<random_bits_of_length_1022->GetNumberOfSimdValues()<<std::endl;

  std::vector<T> vector_of_1023(num_of_simd, 1023);

  SecureUnsignedInteger secure_unsigned_integer_constant_1023 = SecureUnsignedInteger(
      (share_->Get())->GetBackend().ConstantAsBooleanGmwInput(ToInput<T>(vector_of_1023)));

  //   std::cout << "UniformFloatingPoint64_0_1 222" << std::endl;
  //   std::cout << "222" << std::endl;
  // biased_exponent = 1023 - geo
  SecureUnsignedInteger secure_unsigned_integer_biased_exponent =
      secure_unsigned_integer_constant_1023 - secure_unsigned_integer_unbiased_exponent;

  //   std::cout << "UniformFloatingPoint64_0_1 333" << std::endl;
  // only for debug
  // SecureUnsignedInteger secure_unsigned_integer_biased_exponent =
  //     secure_unsigned_integer_biased_exponent;

  // extract 11 bits from secure_unsigned_integer_biased_exponent
  std::vector<ShareWrapper> boolean_gmw_share_biased_exponent_with_zero_compensation_vector =
      secure_unsigned_integer_biased_exponent.Get().Split();

  std::vector<ShareWrapper> boolean_gmw_share_biased_exponent_vector(
      boolean_gmw_share_biased_exponent_with_zero_compensation_vector.begin(),
      boolean_gmw_share_biased_exponent_with_zero_compensation_vector.begin() +
          double_precision_floating_point_exponent_bit_length);

  std::vector<ShareWrapper> boolean_gmw_share_uniform_floating_point_vector;
  boolean_gmw_share_uniform_floating_point_vector.reserve(
      double_precision_floating_point_bit_length);

  std::vector<ShareWrapper> boolean_gmw_share_mantissa_vector = random_bits_of_length_52.Split();

  //   std::cout << "random_bits_of_length_52.Split().size(): "
  //             << random_bits_of_length_52.Split().size() << std::endl;

  // set the mantissa bits
  for (std::size_t i = 0; i < double_precision_floating_point_mantissa_bit_length; i++) {
    boolean_gmw_share_uniform_floating_point_vector.emplace_back(
        boolean_gmw_share_mantissa_vector[i]);
  }

  // set the exponent bits
  for (std::size_t i = 0; i < double_precision_floating_point_exponent_bit_length; i++) {
    boolean_gmw_share_uniform_floating_point_vector.emplace_back(
        boolean_gmw_share_biased_exponent_vector[i]);
  }

  // set the sign bit
  boolean_gmw_share_uniform_floating_point_vector.emplace_back(constant_boolean_gmw_share_zero);

  return ShareWrapper::Concatenate(boolean_gmw_share_uniform_floating_point_vector);
}

ShareWrapper SecureSamplingAlgorithm_optimized::UniformFloatingPoint32_0_1(
    const ShareWrapper& random_bits_of_length_23,
    const ShareWrapper& random_bits_of_length_126) const {
  //   std::cout << "UniformFloatingPoint32_0_1" << std::endl;

  using T = std::uint8_t;
  std::size_t T_size = sizeof(T) * 8;

  std::size_t single_precision_floating_point_bit_length = 32;
  std::size_t single_precision_floating_point_mantissa_bit_length = 23;
  std::size_t single_precision_floating_point_exponent_bit_length = 8;
  std::size_t single_precision_floating_point_sign_bit_length = 1;

  // TODO: we assume that the geomertic sampling always success (there is always 1 in
  // random_bits_of_length_126), the probability for this assumption to fail is 2^(-126)

  ShareWrapper boolean_gmw_share_geometric_sample =
      SimpleGeometricSampling_1(random_bits_of_length_126);

  //   std::cout << "UniformFloatingPoint32_0_1 SimpleGeometricSampling_1" << std::endl;

  // compensate boolean_gmw_share_geometric_sample with 0 and convert to secure unsigned integer
  std::vector<ShareWrapper> boolean_gmw_share_geometric_sample_vector =
      boolean_gmw_share_geometric_sample.Split();
  std::size_t boolean_gmw_share_geometric_sample_vector_size =
      boolean_gmw_share_geometric_sample_vector.size();

  //   ShareWrapper constant_boolean_gmw_share_zero =
  //       boolean_gmw_share_geometric_sample_vector[0] ^
  //       boolean_gmw_share_geometric_sample_vector[0];
  ShareWrapper constant_boolean_gmw_share_zero =
      boolean_gmw_share_geometric_sample_vector[0].CreateConstantAsBooleanGmwInput(false);

  //   std::cout << "UniformFloatingPoint32_0_1 000" << std::endl;
  //   ShareWrapper constant_boolean_gmw_share_one = boolean_gmw_share_geometric_sample_vector[0] ^
  //                                                 (~boolean_gmw_share_geometric_sample_vector[0]);
  ShareWrapper constant_boolean_gmw_share_one =
      boolean_gmw_share_geometric_sample_vector[0].CreateConstantAsBooleanGmwInput(true);

  //   std::cout << "UniformFloatingPoint32_0_1 111" << std::endl;
  std::vector<ShareWrapper> boolean_gmw_share_exponent_unbiased_vector(T_size);
  for (std::size_t i = 0; i < T_size; i++) {
    boolean_gmw_share_exponent_unbiased_vector[i] = constant_boolean_gmw_share_zero;
  }

  for (std::size_t i = 0; i < boolean_gmw_share_geometric_sample_vector_size; i++) {
    boolean_gmw_share_exponent_unbiased_vector[i] = boolean_gmw_share_geometric_sample_vector[i];
  }

  SecureUnsignedInteger secure_unsigned_integer_unbiased_exponent =
      SecureUnsignedInteger(ShareWrapper::Concatenate(boolean_gmw_share_exponent_unbiased_vector));

  //   std::cout << "UniformFloatingPoint32_0_1 111" << std::endl;

  //   std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  std::size_t num_of_simd = random_bits_of_length_23->GetNumberOfSimdValues();
  //   std::cout << "num_of_simd: " << num_of_simd << std::endl;

  //   std::cout<<"share_->GetNumberOfSimdValues(): "<<share_->GetNumberOfSimdValues()<<std::endl;
  //   std::cout<<"random_bits_of_length_23->GetNumberOfSimdValues():
  //   "<<random_bits_of_length_23->GetNumberOfSimdValues()<<std::endl;
  //   std::cout<<"random_bits_of_length_126->GetNumberOfSimdValues():
  //   "<<random_bits_of_length_126->GetNumberOfSimdValues()<<std::endl;

  std::vector<T> vector_of_127(num_of_simd, 127);

  SecureUnsignedInteger secure_unsigned_integer_constant_127 = SecureUnsignedInteger(
      (share_->Get())->GetBackend().ConstantAsBooleanGmwInput(ToInput<T>(vector_of_127)));

  //   std::cout << "UniformFloatingPoint32_0_1 222" << std::endl;
  //   std::cout << "222" << std::endl;
  // biased_exponent = 127 - geo
  SecureUnsignedInteger secure_unsigned_integer_biased_exponent =
      secure_unsigned_integer_constant_127 - secure_unsigned_integer_unbiased_exponent;

  //   std::cout << "UniformFloatingPoint32_0_1 333" << std::endl;
  // only for debug
  // SecureUnsignedInteger secure_unsigned_integer_biased_exponent =
  //     secure_unsigned_integer_biased_exponent;

  // extract 8 bits from secure_unsigned_integer_biased_exponent
  std::vector<ShareWrapper> boolean_gmw_share_biased_exponent_with_zero_compensation_vector =
      secure_unsigned_integer_biased_exponent.Get().Split();

  std::vector<ShareWrapper> boolean_gmw_share_biased_exponent_vector(
      boolean_gmw_share_biased_exponent_with_zero_compensation_vector.begin(),
      boolean_gmw_share_biased_exponent_with_zero_compensation_vector.begin() +
          single_precision_floating_point_exponent_bit_length);

  std::vector<ShareWrapper> boolean_gmw_share_uniform_floating_point_vector;
  boolean_gmw_share_uniform_floating_point_vector.reserve(
      single_precision_floating_point_bit_length);

  std::vector<ShareWrapper> boolean_gmw_share_mantissa_vector = random_bits_of_length_23.Split();

  //   std::cout << "random_bits_of_length_23.Split().size(): "
  //             << random_bits_of_length_23.Split().size() << std::endl;

  // set the mantissa bits
  for (std::size_t i = 0; i < single_precision_floating_point_mantissa_bit_length; i++) {
    boolean_gmw_share_uniform_floating_point_vector.emplace_back(
        boolean_gmw_share_mantissa_vector[i]);
  }

  // set the exponent bits
  for (std::size_t i = 0; i < single_precision_floating_point_exponent_bit_length; i++) {
    boolean_gmw_share_uniform_floating_point_vector.emplace_back(
        boolean_gmw_share_biased_exponent_vector[i]);
  }

  // set the sign bit
  boolean_gmw_share_uniform_floating_point_vector.emplace_back(constant_boolean_gmw_share_zero);

  return ShareWrapper::Concatenate(boolean_gmw_share_uniform_floating_point_vector);
}

// =================================================================================================
// uniformly random fixed-point
ShareWrapper SecureSamplingAlgorithm_optimized::UniformFixedPoint_0_1(
    const ShareWrapper& random_bits_of_length_fixed_point_fraction,
    const std::size_t fixed_point_bit_size) const {
  ShareWrapper fixed_point_boolean_gmw_share_0_1 = BooleanBitsShareZeroCompensation(
      random_bits_of_length_fixed_point_fraction, fixed_point_bit_size);

  return fixed_point_boolean_gmw_share_0_1;
}

ShareWrapper SecureSamplingAlgorithm_optimized::UniformFixedPoint_0_1_Up(
    const ShareWrapper& random_bits_of_length_fixed_point_fraction,
    const std::size_t fixed_point_bit_size) const {
  // uniform fixed point in [0,1)
  ShareWrapper boolean_gmw_share_uniform_fixed_point_0_1 =
      UniformFixedPoint_0_1(random_bits_of_length_fixed_point_fraction, fixed_point_bit_size);

  std::vector<ShareWrapper> random_bits_of_length_fixed_point_fraction_vector =
      random_bits_of_length_fixed_point_fraction.Split();

  //   ShareWrapper constant_boolean_gmw_share_one =
  //       random_bits_of_length_fixed_point_fraction_vector[0] ^
  //       (~random_bits_of_length_fixed_point_fraction_vector[0]);
  ShareWrapper constant_boolean_gmw_share_one =
      random_bits_of_length_fixed_point_fraction_vector[0].CreateConstantAsBooleanGmwInput(true);

  ShareWrapper fixed_point_boolean_gmw_share_minimum_representable_value =
      BooleanBitsShareZeroCompensation(constant_boolean_gmw_share_one, fixed_point_bit_size);

  // convert it to field (0,1] by adding the minimum representable fixed point value
  ShareWrapper boolean_gmw_share_uniform_fixed_point_0_1_up =
      (SecureUnsignedInteger(fixed_point_boolean_gmw_share_minimum_representable_value) +
       SecureUnsignedInteger(boolean_gmw_share_uniform_fixed_point_0_1))
          .Get();

  return boolean_gmw_share_uniform_fixed_point_0_1_up;
}

// ====================================================================
// ! optimized floating-point version in Boolean GMW

template <typename FloatType, typename UintType, typename IntType, typename A>
std::vector<ShareWrapper> SecureSamplingAlgorithm_optimized::FLGeometricDistributionEXP_BGMW(
    const std::vector<UintType>& constant_unsigned_integer_numerator_vector,
    const std::vector<UintType>& constant_unsigned_integer_denominator_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share, std::size_t iteration_1,
    std::size_t iteration_2) const {
  std::size_t num_of_simd_geo = constant_unsigned_integer_numerator_vector.size();

  assert(constant_unsigned_integer_numerator_vector.size() ==
         constant_unsigned_integer_denominator_vector.size());
  assert(random_floating_point_0_1_boolean_gmw_share->GetNumberOfSimdValues() ==
         (iteration_1 + iteration_2) * num_of_simd_geo);
  assert(random_unsigned_integer_boolean_gmw_share->GetNumberOfSimdValues() ==
         iteration_1 * num_of_simd_geo);

  //   using UintType = std::uint64_t;
  //   using IntType = std::int64_t;

  std::size_t FLType_size = sizeof(FloatType) * 8;

  // if numerator or denominator are all ones, we can avoid some computations in MPC
  bool numerator_are_all_ones =
      VectorAllEqualToValue<UintType>(constant_unsigned_integer_numerator_vector, UintType(1));
  bool denominator_are_all_ones =
      VectorAllEqualToValue<UintType>(constant_unsigned_integer_denominator_vector, UintType(1));

  assert(!denominator_are_all_ones);

  // ! case 1: denominator are not all ones
  //   if (!denominator_are_all_ones) {
  //   std::cout << " if (!denominator_are_all_ones)" << std::endl;
  ShareWrapper unsigned_integer_boolean_gmw_share_denominator =
      ((share_->Get())
           ->GetBackend()
           .ConstantAsBooleanGmwInput(
               ToInput<UintType>(constant_unsigned_integer_denominator_vector)));

  // convert denominator to FloatType type in plaintext instead of converting in MPC
  std::vector<FloatType> constant_floating_point_denominator_vector(num_of_simd_geo);
  for (std::size_t i = 0; i < num_of_simd_geo; i++) {
    UintType denominator_tmp = constant_unsigned_integer_denominator_vector[i];
    constant_floating_point_denominator_vector[i] = FloatType(IntType(denominator_tmp));
  }

  // convert plaintext of denominator (in floating-point) to MPC constant shares
  ShareWrapper floating_point_boolean_gmw_share_denominator =
      ((share_->Get())
           ->GetBackend()
           .ConstantAsBooleanGmwInput(
               ToInput<FloatType, std::true_type>(constant_floating_point_denominator_vector)));

  // reshape the vector of denominator in preparation for the SIMD operations
  std::vector<ShareWrapper> floating_point_boolean_gmw_share_denominator_expand =
      ShareWrapper::SimdifyDuplicateVertical(
          floating_point_boolean_gmw_share_denominator.Unsimdify(), iteration_1);

  ShareWrapper floating_point_boolean_gmw_share_denominator_simdify =
      ShareWrapper::Simdify(floating_point_boolean_gmw_share_denominator_expand);

  // convert the random unsigned integer to floating-point numbers
  SecureFloatingPointCircuitABY floating_point_random_unsigned_integer =
      SecureUnsignedInteger(random_unsigned_integer_boolean_gmw_share).Int2FL(FLType_size);

  // reshape the vector of random unsigned integer in preparation for the SIMD operations
  SecureFloatingPointCircuitABY floating_point_unsigned_integer_denominator_simdify =
      SecureFloatingPointCircuitABY(floating_point_boolean_gmw_share_denominator_simdify);

  // =====================================================
  // TODO: this division can be saved by compute e^(-1/t) alone
  //   SecureFloatingPointCircuitABY floating_point_random_unsigned_integer_div_denominator =
  //       floating_point_random_unsigned_integer /
  //       floating_point_unsigned_integer_denominator_simdify;

  //   SecureFloatingPointCircuitABY floating_point_exp_neg_random_unsigned_integer_div_denominator
  //   =
  //       floating_point_random_unsigned_integer_div_denominator.Neg().Exp();
  // =====================================================
  // TODO: save this division by computing e^(-1/t) first

  SecureFloatingPointCircuitABY floating_point_exp_neg_random_unsigned_integer_div_denominator =
      floating_point_random_unsigned_integer.Exp() *
      FloatType(std::exp(-constant_unsigned_integer_denominator_vector[0]));

  // =====================================================

  std::vector<FloatType> vector_of_exp_neg_one(num_of_simd_geo * iteration_2, std::exp(-1.0));
  SecureFloatingPointCircuitABY floating_point_constant_exp_neg_one = SecureFloatingPointCircuitABY(
      (share_->Get())
          ->GetBackend()
          .ConstantAsBooleanGmwInput(ToInput<FloatType, std::true_type>(vector_of_exp_neg_one)));

  // TODO: use unsigned integer comparison instead
  // merge the floating-point comparison operation together
  ShareWrapper floating_point_Bernoulli_distribution_parameter_p = ShareWrapper::Simdify(
      std::vector{floating_point_exp_neg_random_unsigned_integer_div_denominator.Get(),
                  floating_point_constant_exp_neg_one.Get()});

  ShareWrapper boolean_gmw_share_Bernoulli_sample =
      SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_share) <
      SecureFloatingPointCircuitABY(floating_point_Bernoulli_distribution_parameter_p);

  std::vector<ShareWrapper> boolean_gmw_share_Bernoulli_sample_unsimdify =
      boolean_gmw_share_Bernoulli_sample.Unsimdify();
  std::vector<ShareWrapper> boolean_gmw_share_Bernoulli_sample_part_1_vector(
      boolean_gmw_share_Bernoulli_sample_unsimdify.begin(),
      boolean_gmw_share_Bernoulli_sample_unsimdify.begin() + iteration_1 * num_of_simd_geo);

  std::vector<ShareWrapper> boolean_gmw_share_Bernoulli_sample_part_2_vector(
      boolean_gmw_share_Bernoulli_sample_unsimdify.begin() + iteration_1 * num_of_simd_geo,
      boolean_gmw_share_Bernoulli_sample_unsimdify.begin() + iteration_1 * num_of_simd_geo +
          iteration_2 * num_of_simd_geo);

  std::vector<ShareWrapper> boolean_gmw_share_b1_vector = ShareWrapper::SimdifyReshapeHorizontal(
      boolean_gmw_share_Bernoulli_sample_part_1_vector, iteration_1, num_of_simd_geo);

  std::vector<ShareWrapper> boolean_gmw_share_b2_vector = ShareWrapper::SimdifyReshapeHorizontal(
      boolean_gmw_share_Bernoulli_sample_part_2_vector, iteration_2, num_of_simd_geo);

  std::vector<ShareWrapper> random_unsigned_integer_boolean_gmw_share_unsimdify =
      random_unsigned_integer_boolean_gmw_share.Unsimdify();
  //   std::vector<ShareWrapper> random_unsigned_integer_boolean_gmw_share_for_b1_vector =
  //       ShareWrapper::SimdifyReshapeHorizontal(random_unsigned_integer_boolean_gmw_share.Unsimdify(),
  //                                              iteration_1, num_of_simd_geo);
  std::vector<ShareWrapper> random_unsigned_integer_boolean_gmw_share_for_b1_vector =
      ShareWrapper::SimdifyReshapeHorizontal(random_unsigned_integer_boolean_gmw_share_unsimdify,
                                             iteration_1, num_of_simd_geo);

  std::vector<ShareWrapper> boolean_gmw_share_u = share_->InvertBinaryTreeSelection(
      random_unsigned_integer_boolean_gmw_share_for_b1_vector, boolean_gmw_share_b1_vector);

  std::vector<ShareWrapper> boolean_gmw_share_constant_j;
  boolean_gmw_share_constant_j.reserve(iteration_2);
  for (std::size_t j = 0; j < iteration_2; j++) {
    std::vector<UintType> vector_of_constant_j(num_of_simd_geo, j);
    boolean_gmw_share_constant_j.emplace_back(
        (share_->Get())
            ->GetBackend()
            .ConstantAsBooleanGmwInput(ToInput<UintType>(vector_of_constant_j)));
  }

  std::vector<ShareWrapper> boolean_gmw_share_b2_invert_vector;
  boolean_gmw_share_b2_invert_vector.reserve(iteration_2);
  for (std::size_t i = 0; i < iteration_2; i++) {
    boolean_gmw_share_b2_invert_vector.emplace_back(~boolean_gmw_share_b2_vector[i]);
  }

  std::vector<ShareWrapper> boolean_gmw_share_v = share_->InvertBinaryTreeSelection(
      boolean_gmw_share_constant_j, boolean_gmw_share_b2_invert_vector);

  SecureUnsignedInteger unsigned_integer_w =
      SecureUnsignedInteger(boolean_gmw_share_v[0]) *
          SecureUnsignedInteger(unsigned_integer_boolean_gmw_share_denominator) +
      SecureUnsignedInteger(boolean_gmw_share_u[0]);

  // case 1.1
  // numerator's vector elements are not all equal to one
  if (!numerator_are_all_ones) {
    //================================================================
    ShareWrapper unsigned_integer_boolean_gmw_share_numerator =
        ((share_->Get())
             ->GetBackend()
             .ConstantAsBooleanGmwInput(
                 ToInput<UintType>(constant_unsigned_integer_numerator_vector)));
    // TODO: optimize integer division with floating-point division
    // TODO: using Garbled Circuit for division instead
    SecureUnsignedInteger unsigned_integer_geometric_sample =
        unsigned_integer_w / SecureUnsignedInteger(unsigned_integer_boolean_gmw_share_numerator);
    //================================================================
    // ShareWrapper unsigned_integer_boolean_gmw_share_numerator =
    //     ((share_->Get())
    //          ->GetBackend()
    //          .ConstantAsBooleanGmwInput(
    //              ToInput<UintType>(constant_unsigned_integer_numerator_vector)));

    // TODO: test if floating-point division is faster
    // SecureFloatingPointCircuitABY floating_point_geometric_sample =
    //     unsigned_integer_w.Int2FL(sizeof(double) * 8) /
    //     unsigned_integer_boolean_gmw_share_numerator.Int2FL(sizeof(double) * 8);
    // SecureUnsignedInteger unsigned_integer_geometric_sample =
    //     floating_point_geometric_sample.FL2Int(sizeof(UintType) * 8);
    //================================================================
    // TODO: convert to BMR integer division
    //     ShareWrapper unsigned_integer_bmr_share_numerator =
    //         ((share_->Get())
    //              ->GetBackend()
    //              .ConstantAsBmrInput(ToInput<UintType>(constant_unsigned_integer_numerator_vector)));

    //     SecureUnsignedInteger unsigned_integer_bmr_share_geometric_sample =
    //         SecureUnsignedInteger(unsigned_integer_w.Get().Convert<MpcProtocol::kBmr>) /
    //         SecureUnsignedInteger(unsigned_integer_bmr_share_numerator);
    // SecureUnsignedInteger
    // unsigned_integer_boolean_gmw_share_geometric_sample=SecureUnsignedInteger(unsigned_integer_bmr_share_geometric_sample.Get());
    //================================================================

    ShareWrapper boolean_gmw_share_success_flag = (boolean_gmw_share_u[1] & boolean_gmw_share_v[1]);

    std::vector<ShareWrapper> result_vector;
    result_vector.reserve(2);
    result_vector.emplace_back(unsigned_integer_geometric_sample.Get());
    result_vector.emplace_back(boolean_gmw_share_success_flag);

    // only for debug
    // result_vector.emplace_back(floating_point_boolean_gmw_share_denominator_simdify);  //
    // // 2
    // result_vector.emplace_back(floating_point_random_unsigned_integer.Get());               // 3
    // result_vector.emplace_back(floating_point_unsigned_integer_denominator_simdify.Get());  //
    // // 4
    // result_vector.emplace_back(floating_point_random_unsigned_integer_div_denominator.Get());
    // // 5
    // result_vector.emplace_back(boolean_gmw_share_v[0]);  // 6
    // result_vector.emplace_back(boolean_gmw_share_u[0]);  //
    // // 7
    // result_vector.emplace_back(unsigned_integer_w.Get());  // 8

    return result_vector;
  }

  // case 1.2
  // if the numerator's vector elements are all equal to one, we can save the division operation
  else {
    // save MPC computation here
    SecureUnsignedInteger unsigned_integer_geometric_sample = unsigned_integer_w;

    ShareWrapper boolean_gmw_share_success_flag = (boolean_gmw_share_u[1] & boolean_gmw_share_v[1]);

    std::vector<ShareWrapper> result_vector;
    result_vector.reserve(2);
    result_vector.emplace_back(unsigned_integer_geometric_sample.Get());
    result_vector.emplace_back(boolean_gmw_share_success_flag);

    // only for debug
    // result_vector.emplace_back(floating_point_boolean_gmw_share_denominator_simdify);  //
    // // 2
    // result_vector.emplace_back(floating_point_random_unsigned_integer.Get());               // 3
    // result_vector.emplace_back(floating_point_unsigned_integer_denominator_simdify.Get());  //
    //                                                                                         // 4
    // result_vector.emplace_back(floating_point_random_unsigned_integer_div_denominator.Get());
    // // 5
    // result_vector.emplace_back(boolean_gmw_share_v[0]);  // 6
    // result_vector.emplace_back(boolean_gmw_share_u[0]);  //
    // // 7
    // result_vector.emplace_back(unsigned_integer_w.Get());  // 8

    return result_vector;
  }
  //   }
}

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLGeometricDistributionEXP_BGMW<
    float, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const std::vector<std::uint64_t>& constant_unsigned_integer_denominator_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share, std::size_t iteration_1,
    std::size_t iteration_2) const;

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLGeometricDistributionEXP_BGMW<
    double, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const std::vector<std::uint64_t>& constant_unsigned_integer_denominator_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share, std::size_t iteration_1,
    std::size_t iteration_2) const;

template <typename FloatType, typename UintType, typename IntType, typename A>
std::vector<ShareWrapper> SecureSamplingAlgorithm_optimized::FLGeometricDistributionEXP_BGMW(
    const std::vector<UintType>& constant_unsigned_integer_numerator_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
    std::size_t iteration_2) const {
  std::size_t num_of_simd_geo = constant_unsigned_integer_numerator_vector.size();

  assert(random_floating_point_0_1_boolean_gmw_share->GetNumberOfSimdValues() ==
         (iteration_2)*num_of_simd_geo);

  //   using UintType = std::uint64_t;
  //   using IntType = std::int64_t;

  // if numerator or denominator are all ones, we can avoid some computations in MPC
  bool numerator_are_all_ones =
      VectorAllEqualToValue<UintType>(constant_unsigned_integer_numerator_vector, UintType(1));
  bool denominator_are_all_ones = true;

  // ! case 2:
  // if the denominator vector's elements are all ones, we can skip the first for loop iterations
  //   if (denominator_are_all_ones) {
  std::vector<FloatType> vector_of_exp_neg_one(num_of_simd_geo * iteration_2, std::exp(-1.0));
  SecureFloatingPointCircuitABY floating_point_constant_exp_neg_one = SecureFloatingPointCircuitABY(
      (share_->Get())
          ->GetBackend()
          .ConstantAsBooleanGmwInput(ToInput<FloatType, std::true_type>(vector_of_exp_neg_one)));

  ShareWrapper floating_point_Bernoulli_distribution_parameter_p =
      floating_point_constant_exp_neg_one.Get();
  ShareWrapper boolean_gmw_share_Bernoulli_sample =
      SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_share) <
      SecureFloatingPointCircuitABY(floating_point_Bernoulli_distribution_parameter_p);

  std::vector<ShareWrapper> boolean_gmw_share_Bernoulli_sample_unsimdify =
      boolean_gmw_share_Bernoulli_sample.Unsimdify();

  std::vector<ShareWrapper> boolean_gmw_share_Bernoulli_sample_part_2_vector(
      boolean_gmw_share_Bernoulli_sample_unsimdify.begin(),
      boolean_gmw_share_Bernoulli_sample_unsimdify.begin() + iteration_2 * num_of_simd_geo);

  // std::cout << "boolean_gmw_share_Bernoulli_sample_part_2_vector.size(): "
  //           << boolean_gmw_share_Bernoulli_sample_part_2_vector.size() << std::endl;

  std::vector<ShareWrapper> boolean_gmw_share_b2_vector = ShareWrapper::SimdifyReshapeHorizontal(
      boolean_gmw_share_Bernoulli_sample_part_2_vector, iteration_2, num_of_simd_geo);

  //   std::cout << "333" << std::endl;
  std::vector<ShareWrapper> boolean_gmw_share_constant_j;
  boolean_gmw_share_constant_j.reserve(iteration_2);
  for (std::size_t j = 0; j < iteration_2; j++) {
    std::vector<UintType> vector_of_constant_j(num_of_simd_geo, j);
    boolean_gmw_share_constant_j.emplace_back(
        (share_->Get())
            ->GetBackend()
            .ConstantAsBooleanGmwInput(ToInput<UintType>(vector_of_constant_j)));
  }

  // invert boolean_gmw_share_b2_vector
  std::vector<ShareWrapper> boolean_gmw_share_b2_invert_vector;
  boolean_gmw_share_b2_invert_vector.reserve(iteration_2);
  for (std::size_t i = 0; i < iteration_2; i++) {
    boolean_gmw_share_b2_invert_vector.emplace_back(~boolean_gmw_share_b2_vector[i]);
  }

  std::vector<ShareWrapper> boolean_gmw_share_v = share_->InvertBinaryTreeSelection(
      boolean_gmw_share_constant_j, boolean_gmw_share_b2_invert_vector);

  SecureUnsignedInteger unsigned_integer_w = SecureUnsignedInteger(boolean_gmw_share_v[0]);

  // case 2.1
  // the numerator's vector elements are not all ones
  if (!numerator_are_all_ones) {
    ShareWrapper unsigned_integer_boolean_gmw_share_numerator =
        ((share_->Get())
             ->GetBackend()
             .ConstantAsBooleanGmwInput(
                 ToInput<UintType>(constant_unsigned_integer_numerator_vector)));

    // TODO: optimize using floating-point division instead
    SecureUnsignedInteger unsigned_integer_geometric_sample =
        unsigned_integer_w / SecureUnsignedInteger(unsigned_integer_boolean_gmw_share_numerator);

    ShareWrapper boolean_gmw_share_success_flag = (boolean_gmw_share_v[1]);

    std::vector<ShareWrapper> result_vector;
    result_vector.reserve(2);
    result_vector.emplace_back(unsigned_integer_geometric_sample.Get());
    result_vector.emplace_back(boolean_gmw_share_success_flag);

    return result_vector;
  }

  // case 2.2
  // if the numerator's vector elements are all ones, we can avoid the division operation
  else {
    SecureUnsignedInteger unsigned_integer_geometric_sample = unsigned_integer_w;

    ShareWrapper boolean_gmw_share_success_flag = (boolean_gmw_share_v[1]);

    std::vector<ShareWrapper> result_vector;
    result_vector.reserve(2);
    result_vector.emplace_back(unsigned_integer_geometric_sample.Get());
    result_vector.emplace_back(boolean_gmw_share_success_flag);

    return result_vector;
  }
  //   }
}

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLGeometricDistributionEXP_BGMW<
    float, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share, std::size_t iteration_2) const;

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLGeometricDistributionEXP_BGMW<
    double, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share, std::size_t iteration_2) const;

template <typename FloatType, typename UintType, typename IntType, typename A>
std::vector<ShareWrapper> SecureSamplingAlgorithm_optimized::FLDiscreteLaplaceDistribution_BGMW(
    const std::vector<UintType>& constant_unsigned_integer_numerator_vector,
    const std::vector<UintType>& constant_unsigned_integer_denominator_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample, std::size_t iteration_1,
    std::size_t iteration_2, std::size_t iteration_3) const {
  //   using UintType = std::uint64_t;

  // same as FLGeometricDistributionEXP except with more iteration_3
  std::size_t num_of_simd_geo = iteration_3;
  std::size_t num_of_simd_dlap = constant_unsigned_integer_numerator_vector.size();
  std::size_t num_of_simd_total = num_of_simd_dlap * num_of_simd_geo;

  assert(constant_unsigned_integer_numerator_vector.size() ==
         constant_unsigned_integer_denominator_vector.size());
  assert(random_floating_point_0_1_boolean_gmw_share->GetNumberOfSimdValues() ==
         (iteration_1 + iteration_2) * num_of_simd_total);
  assert(random_unsigned_integer_boolean_gmw_share->GetNumberOfSimdValues() ==
         iteration_1 * num_of_simd_total);
  assert(boolean_gmw_share_bernoulli_sample->GetNumberOfSimdValues() == num_of_simd_total);

  //   std::vector<ShareWrapper> unsigned_integer_numerator_geo_vector =
  //       ShareWrapper::SimdifyDuplicateVertical(
  //           unsigned_integer_boolean_gmw_share_numerator.Unsimdify(), num_of_simd_geo);
  //   ShareWrapper unsigned_integer_numerator_geo =
  //       ShareWrapper::Simdify(unsigned_integer_numerator_geo_vector);

  //   std::vector<ShareWrapper> unsigned_integer_denominator_geo_vector =
  //       ShareWrapper::SimdifyDuplicateVertical(
  //           unsigned_integer_boolean_gmw_share_denominator.Unsimdify(), num_of_simd_geo);
  //   ShareWrapper unsigned_integer_denominator_geo =
  //       ShareWrapper::Simdify(unsigned_integer_denominator_geo_vector);

  //   std::vector<std::uint64_t> constant_unsigned_integer_numerator_geo_vector(num_of_simd_total);
  //   std::vector<std::uint64_t>
  //   constant_unsigned_integer_denominator_geo_vector(num_of_simd_total);
  std::vector<UintType> constant_unsigned_integer_numerator_geo_vector(num_of_simd_total);
  std::vector<UintType> constant_unsigned_integer_denominator_geo_vector(num_of_simd_total);

  for (std::size_t i = 0; i < num_of_simd_dlap; i++) {
    for (std::size_t j = 0; j < num_of_simd_geo; j++) {
      constant_unsigned_integer_numerator_geo_vector[i * num_of_simd_geo + j] =
          constant_unsigned_integer_numerator_vector[i];
      constant_unsigned_integer_denominator_geo_vector[i * num_of_simd_geo + j] =
          constant_unsigned_integer_denominator_vector[i];
    }
  }

  std::vector<ShareWrapper> geometric_sample_vector =
      FLGeometricDistributionEXP_BGMW<FloatType, UintType, IntType, A>(
          constant_unsigned_integer_numerator_geo_vector,
          constant_unsigned_integer_denominator_geo_vector,
          random_floating_point_0_1_boolean_gmw_share, random_unsigned_integer_boolean_gmw_share,
          iteration_1, iteration_2);

  ShareWrapper boolean_gmw_share_sign = boolean_gmw_share_bernoulli_sample;
  ShareWrapper unsigned_integer_geometric_sample_boolean_gmw_share_magnitude =
      geometric_sample_vector[0];
  ShareWrapper boolean_gmw_share_magnitude_EQZ =
      SecureSignedInteger(unsigned_integer_geometric_sample_boolean_gmw_share_magnitude).IsZero();

  // magnitude*(1-2*sign)
  SecureSignedInteger signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign =
      SecureSignedInteger(unsigned_integer_geometric_sample_boolean_gmw_share_magnitude)
          .Neg(boolean_gmw_share_sign);

  ShareWrapper boolean_gmw_share_choice =
      ~(boolean_gmw_share_sign & boolean_gmw_share_magnitude_EQZ) & geometric_sample_vector[1];

  std::vector<ShareWrapper>
      signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign_reshape_vector =
          ShareWrapper::SimdifyReshapeHorizontal(
              signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign.Get().Unsimdify(),
              iteration_3, num_of_simd_dlap);

  std::vector<ShareWrapper> boolean_gmw_share_choice_reshape_vector =
      ShareWrapper::SimdifyReshapeHorizontal(boolean_gmw_share_choice.Unsimdify(), iteration_3,
                                             num_of_simd_dlap);

  std::vector<ShareWrapper> boolean_gmw_share_discrete_laplace_sample_vector =
      share_->InvertBinaryTreeSelection(
          signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign_reshape_vector,
          boolean_gmw_share_choice_reshape_vector);

  //   // only for debug
  //   boolean_gmw_share_discrete_laplace_sample_vector.emplace_back(boolean_gmw_share_sign);  //
  //   2 boolean_gmw_share_discrete_laplace_sample_vector.emplace_back(
  //       unsigned_integer_geometric_sample_boolean_gmw_share_magnitude);  // 3
  //   boolean_gmw_share_discrete_laplace_sample_vector.emplace_back(
  //       unsigned_integer_numerator_geo);  // 4
  //   boolean_gmw_share_discrete_laplace_sample_vector.emplace_back(
  //       unsigned_integer_denominator_geo);  // 5
  //   boolean_gmw_share_discrete_laplace_sample_vector.emplace_back(
  //       unsigned_integer_with_magnitude_mul_one_minus_two_mul_as_sign.Get()); //
  //       6
  //   boolean_gmw_share_discrete_laplace_sample_vector.emplace_back(boolean_gmw_share_choice);
  //
  //   7

  return boolean_gmw_share_discrete_laplace_sample_vector;
}

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLDiscreteLaplaceDistribution_BGMW<
    float, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const std::vector<std::uint64_t>& constant_unsigned_integer_denominator_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample, std::size_t iteration_1,
    std::size_t iteration_2, std::size_t iteration_3) const;

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLDiscreteLaplaceDistribution_BGMW<
    double, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const std::vector<std::uint64_t>& constant_unsigned_integer_denominator_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample, std::size_t iteration_1,
    std::size_t iteration_2, std::size_t iteration_3) const;

template <typename FloatType, typename UintType, typename IntType, typename A>
std::vector<ShareWrapper> SecureSamplingAlgorithm_optimized::FLDiscreteLaplaceDistribution_BGMW(
    const std::vector<UintType>& constant_unsigned_integer_numerator_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample, std::size_t iteration_2,
    std::size_t iteration_3) const {
  //   using UintType = std::uint64_t;

  // same as FLGeometricDistributionEXP except with more iteration_3
  std::size_t num_of_simd_geo = iteration_3;
  std::size_t num_of_simd_dlap = constant_unsigned_integer_numerator_vector.size();
  std::size_t num_of_simd_total = num_of_simd_dlap * num_of_simd_geo;

  //   assert(constant_unsigned_integer_numerator_vector.size() ==
  //          constant_unsigned_integer_denominator_vector.size());
  assert(random_floating_point_0_1_boolean_gmw_share->GetNumberOfSimdValues() ==
         (iteration_2)*num_of_simd_total);
  assert(boolean_gmw_share_bernoulli_sample->GetNumberOfSimdValues() == num_of_simd_total);

  //   std::vector<ShareWrapper> unsigned_integer_numerator_geo_vector =
  //       ShareWrapper::SimdifyDuplicateVertical(
  //           unsigned_integer_boolean_gmw_share_numerator.Unsimdify(), num_of_simd_geo);
  //   ShareWrapper unsigned_integer_numerator_geo =
  //       ShareWrapper::Simdify(unsigned_integer_numerator_geo_vector);

  //   std::vector<ShareWrapper> unsigned_integer_denominator_geo_vector =
  //       ShareWrapper::SimdifyDuplicateVertical(
  //           unsigned_integer_boolean_gmw_share_denominator.Unsimdify(), num_of_simd_geo);
  //   ShareWrapper unsigned_integer_denominator_geo =
  //       ShareWrapper::Simdify(unsigned_integer_denominator_geo_vector);

  std::vector<UintType> constant_unsigned_integer_numerator_geo_vector(num_of_simd_total);
  for (std::size_t i = 0; i < num_of_simd_dlap; i++) {
    for (std::size_t j = 0; j < num_of_simd_geo; j++) {
      constant_unsigned_integer_numerator_geo_vector[i * num_of_simd_geo + j] =
          constant_unsigned_integer_numerator_vector[i];
    }
  }

  std::vector<ShareWrapper> geometric_sample_vector =
      FLGeometricDistributionEXP_BGMW<FloatType, UintType, IntType, A>(
          constant_unsigned_integer_numerator_geo_vector,
          random_floating_point_0_1_boolean_gmw_share, iteration_2);

  ShareWrapper boolean_gmw_share_sign = boolean_gmw_share_bernoulli_sample;
  ShareWrapper unsigned_integer_geometric_sample_boolean_gmw_share_magnitude =
      geometric_sample_vector[0];
  ShareWrapper boolean_gmw_share_magnitude_EQZ =
      SecureSignedInteger(unsigned_integer_geometric_sample_boolean_gmw_share_magnitude).IsZero();

  // magnitude*(1-2*sign)
  SecureSignedInteger signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign =
      SecureSignedInteger(unsigned_integer_geometric_sample_boolean_gmw_share_magnitude)
          .Neg(boolean_gmw_share_sign);

  ShareWrapper boolean_gmw_share_choice =
      ~(boolean_gmw_share_sign & boolean_gmw_share_magnitude_EQZ) & geometric_sample_vector[1];

  std::vector<ShareWrapper>
      signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign_reshape_vector =
          ShareWrapper::SimdifyReshapeHorizontal(
              signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign.Get().Unsimdify(),
              iteration_3, num_of_simd_dlap);

  std::vector<ShareWrapper> boolean_gmw_share_choice_reshape_vector =
      ShareWrapper::SimdifyReshapeHorizontal(boolean_gmw_share_choice.Unsimdify(), iteration_3,
                                             num_of_simd_dlap);

  std::vector<ShareWrapper> boolean_gmw_share_discrete_laplace_sample_vector =
      share_->InvertBinaryTreeSelection(
          signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign_reshape_vector,
          boolean_gmw_share_choice_reshape_vector);

  //   // only for debug
  // boolean_gmw_share_discrete_laplace_sample_vector.emplace_back(boolean_gmw_share_sign);  //
  // // 2
  //  boolean_gmw_share_discrete_laplace_sample_vector.emplace_back(
  //     unsigned_integer_geometric_sample_boolean_gmw_share_magnitude);  // 3
  // boolean_gmw_share_discrete_laplace_sample_vector.emplace_back(
  //     unsigned_integer_numerator_geo);  // 4
  // boolean_gmw_share_discrete_laplace_sample_vector.emplace_back(
  //     unsigned_integer_denominator_geo);  // 5
  // boolean_gmw_share_discrete_laplace_sample_vector.emplace_back(
  //     unsigned_integer_with_magnitude_mul_one_minus_two_mul_as_sign.Get()); //
  //     // 6
  // boolean_gmw_share_discrete_laplace_sample_vector.emplace_back(boolean_gmw_share_choice); //
  // // 7

  return boolean_gmw_share_discrete_laplace_sample_vector;
}

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLDiscreteLaplaceDistribution_BGMW<
    float, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample, std::size_t iteration_2,
    std::size_t iteration_3) const;

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLDiscreteLaplaceDistribution_BGMW<
    double, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample, std::size_t iteration_2,
    std::size_t iteration_3) const;

template <typename FloatType, typename UintType, typename IntType, typename A>
std::vector<ShareWrapper> SecureSamplingAlgorithm_optimized::FLDiscreteGaussianDistribution_BGMW(
    const std::vector<double>& constant_floating_point_sigma_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share_dlap,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau, std::size_t iteration_1,
    std::size_t iteration_2, std::size_t iteration_3, std::size_t iteration_4) const {
  //   using UintType = std::uint64_t;

  std::size_t FLType_size = sizeof(FloatType) * 8;

  std::size_t num_of_simd_dgau = constant_floating_point_sigma_vector.size();
  std::size_t num_of_simd_geo = iteration_3;
  std::size_t num_of_simd_dlap = iteration_4;
  std::size_t num_of_simd_total = num_of_simd_dlap * num_of_simd_geo * num_of_simd_dgau;

  assert(random_floating_point_0_1_boolean_gmw_share_dlap->GetNumberOfSimdValues() ==
         (iteration_1 + iteration_2) * num_of_simd_total);
  assert(random_unsigned_integer_boolean_gmw_share_dlap->GetNumberOfSimdValues() ==
         iteration_1 * num_of_simd_total);

  assert(boolean_gmw_share_bernoulli_sample_dlap->GetNumberOfSimdValues() == num_of_simd_total);
  assert(random_floating_point_0_1_boolean_gmw_share_dgau->GetNumberOfSimdValues() ==
         iteration_4 * num_of_simd_dgau);

  // std::cout << "000" << std::endl;

  std::vector<UintType> constant_unsigned_integer_t_vector(num_of_simd_dgau);
  for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
    constant_unsigned_integer_t_vector[i] = floor(constant_floating_point_sigma_vector[i]) + 1;
  }

  //   std::vector<UintType> constant_unsigned_integer_t_dlap_vector(num_of_simd_dgau *
  //   num_of_simd_dlap);
  std::vector<UintType> constant_unsigned_integer_numerator_dlap_vector(num_of_simd_dgau *
                                                                        num_of_simd_dlap);
  std::vector<UintType> constant_unsigned_integer_denominator_dlap_vector(num_of_simd_dgau *
                                                                          num_of_simd_dlap);

  // std::cout << "111" << std::endl;
  for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
    for (std::size_t j = 0; j < num_of_simd_dlap; j++) {
      //   constant_unsigned_integer_t_dlap_vector[i * num_of_simd_dlap + j] =
      //       constant_unsigned_integer_t_vector[i];
      constant_unsigned_integer_denominator_dlap_vector[i * num_of_simd_dlap + j] =
          constant_unsigned_integer_t_vector[i];
      constant_unsigned_integer_numerator_dlap_vector[i * num_of_simd_dlap + j] = UintType(1);
    }
  }

  std::vector<ShareWrapper> boolean_gmw_share_discrete_laplace_sample_vector =
      FLDiscreteLaplaceDistribution_BGMW<FloatType, UintType, IntType, A>(
          constant_unsigned_integer_numerator_dlap_vector,
          constant_unsigned_integer_denominator_dlap_vector,
          random_floating_point_0_1_boolean_gmw_share_dlap,
          random_unsigned_integer_boolean_gmw_share_dlap, boolean_gmw_share_bernoulli_sample_dlap,
          iteration_1, iteration_2, iteration_3);

  // std::cout << "222" << std::endl;
  std::vector<FloatType> constant_floating_point_sigma_square_div_t_vector(num_of_simd_dgau);
  std::vector<FloatType> constant_floating_point_two_mul_sigma_square_vector(num_of_simd_dgau);
  for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
    constant_floating_point_sigma_square_div_t_vector[i] =
        constant_floating_point_sigma_vector[i] * constant_floating_point_sigma_vector[i] /
        FloatType(constant_unsigned_integer_t_vector[i]);
    constant_floating_point_two_mul_sigma_square_vector[i] =
        2.0 * constant_floating_point_sigma_vector[i] * constant_floating_point_sigma_vector[i];
  }

  // std::cout << "333" << std::endl;
  SecureFloatingPointCircuitABY constant_floating_point_sigma_square_div_t =
      SecureFloatingPointCircuitABY(
          (share_->Get())
              ->GetBackend()
              .ConstantAsBooleanGmwInput(ToInput<FloatType, std::true_type>(
                  constant_floating_point_sigma_square_div_t_vector)));

  SecureFloatingPointCircuitABY constant_floating_point_two_mul_sigma_square =
      SecureFloatingPointCircuitABY(
          (share_->Get())
              ->GetBackend()
              .ConstantAsBooleanGmwInput(ToInput<FloatType, std::true_type>(
                  constant_floating_point_two_mul_sigma_square_vector)));

  // std::cout << "444" << std::endl;
  ShareWrapper boolean_gmw_share_Y = boolean_gmw_share_discrete_laplace_sample_vector[0];
  SecureFloatingPointCircuitABY floating_point_C_bernoulli_parameter =
      (((SecureSignedInteger(boolean_gmw_share_Y).Int2FL(FLType_size).Abs() -
         SecureFloatingPointCircuitABY(ShareWrapper::Simdify(ShareWrapper::SimdifyDuplicateVertical(
             constant_floating_point_sigma_square_div_t.Get().Unsimdify(), iteration_4))))
            .Sqr()) /
       (SecureFloatingPointCircuitABY(ShareWrapper::Simdify(ShareWrapper::SimdifyDuplicateVertical(
           constant_floating_point_two_mul_sigma_square.Get().Unsimdify(), iteration_4)))))
          .Neg()
          .Exp();

  // std::cout << "555" << std::endl;
  ShareWrapper boolean_gmw_share_bernoulli =
      SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_share_dgau) <
      floating_point_C_bernoulli_parameter;

  ShareWrapper boolean_gmw_share_choice =
      boolean_gmw_share_bernoulli & boolean_gmw_share_discrete_laplace_sample_vector[1];

  std::vector<ShareWrapper> boolean_gmw_share_Y_reshape = ShareWrapper::SimdifyReshapeHorizontal(
      boolean_gmw_share_Y.Unsimdify(), iteration_4, num_of_simd_dgau);
  std::vector<ShareWrapper> boolean_gmw_share_choice_reshape =
      ShareWrapper::SimdifyReshapeHorizontal(boolean_gmw_share_choice.Unsimdify(), iteration_4,
                                             num_of_simd_dgau);

  // std::cout << "666" << std::endl;
  std::vector<ShareWrapper> boolean_gmw_share_result_vector = share_->InvertBinaryTreeSelection(
      boolean_gmw_share_Y_reshape, boolean_gmw_share_choice_reshape);

  //   // only for debug
  boolean_gmw_share_result_vector.emplace_back(
      boolean_gmw_share_discrete_laplace_sample_vector[0]);  // 2
  boolean_gmw_share_result_vector.emplace_back(
      boolean_gmw_share_discrete_laplace_sample_vector[1]);                   //
                                                                              // 3
  boolean_gmw_share_result_vector.emplace_back(boolean_gmw_share_bernoulli);  //
  // 4
  boolean_gmw_share_result_vector.emplace_back(boolean_gmw_share_choice);                    // 5
  boolean_gmw_share_result_vector.emplace_back(floating_point_C_bernoulli_parameter.Get());  //
  // 6
  boolean_gmw_share_result_vector.emplace_back(
      SecureSignedInteger(boolean_gmw_share_Y).Get());  // 7
  boolean_gmw_share_result_vector.emplace_back(
      SecureFloatingPointCircuitABY(
          ShareWrapper::Simdify(ShareWrapper::SimdifyDuplicateVertical(
              constant_floating_point_sigma_square_div_t.Get().Unsimdify(), iteration_4)))
          .Get());  // 8

  return boolean_gmw_share_result_vector;
}

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLDiscreteGaussianDistribution_BGMW<
    float, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<double>& constant_floating_point_sigma_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share_dlap,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau, std::size_t iteration_1,
    std::size_t iteration_2, std::size_t iteration_3, std::size_t iteration_4) const;

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLDiscreteGaussianDistribution_BGMW<
    double, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<double>& constant_floating_point_sigma_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share_dlap,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau, std::size_t iteration_1,
    std::size_t iteration_2, std::size_t iteration_3, std::size_t iteration_4) const;

template <typename FloatType, typename UintType, typename IntType, typename A>
std::vector<ShareWrapper> SecureSamplingAlgorithm_optimized::FLDiscreteGaussianDistribution_BGMW(
    const std::vector<double>& constant_floating_point_sigma_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau, std::size_t iteration_2,
    std::size_t iteration_3, std::size_t iteration_4) const {
  //   using UintType = std::uint64_t;

  std::size_t FLType_size = sizeof(FloatType) * 8;

  std::size_t num_of_simd_dgau = constant_floating_point_sigma_vector.size();
  std::size_t num_of_simd_geo = iteration_3;
  std::size_t num_of_simd_dlap = iteration_4;
  std::size_t num_of_simd_total = num_of_simd_dlap * num_of_simd_geo * num_of_simd_dgau;

  assert(random_floating_point_0_1_boolean_gmw_share_dlap->GetNumberOfSimdValues() ==
         (iteration_2)*num_of_simd_total);

  assert(boolean_gmw_share_bernoulli_sample_dlap->GetNumberOfSimdValues() == num_of_simd_total);
  assert(random_floating_point_0_1_boolean_gmw_share_dgau->GetNumberOfSimdValues() ==
         iteration_4 * num_of_simd_dgau);

  //   std::cout << "000" << std::endl;

  std::vector<UintType> constant_unsigned_integer_t_vector(num_of_simd_dgau);
  for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
    constant_unsigned_integer_t_vector[i] = floor(constant_floating_point_sigma_vector[i]) + 1;
  }

  // t = 1
  assert(VectorAllEqualToValue<UintType>(constant_unsigned_integer_t_vector, UintType(1)));

  //   std::vector<UintType> constant_unsigned_integer_t_dlap_vector(num_of_simd_dgau *
  //   num_of_simd_dlap);
  std::vector<UintType> constant_unsigned_integer_numerator_dlap_vector(num_of_simd_dgau *
                                                                        num_of_simd_dlap);

  //   std::cout << "111" << std::endl;
  for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
    for (std::size_t j = 0; j < num_of_simd_dlap; j++) {
      //   constant_unsigned_integer_t_dlap_vector[i * num_of_simd_dlap + j] =
      //       constant_unsigned_integer_t_vector[i];
      constant_unsigned_integer_numerator_dlap_vector[i * num_of_simd_dlap + j] = UintType(1);
    }
  }

  std::vector<ShareWrapper> boolean_gmw_share_discrete_laplace_sample_vector =
      FLDiscreteLaplaceDistribution_BGMW<FloatType, UintType, IntType, A>(
          constant_unsigned_integer_numerator_dlap_vector,
          random_floating_point_0_1_boolean_gmw_share_dlap, boolean_gmw_share_bernoulli_sample_dlap,
          iteration_2, iteration_3);

  //   std::cout << "222" << std::endl;
  std::vector<FloatType> constant_floating_point_sigma_square_div_t_vector(num_of_simd_dgau);
  std::vector<FloatType> constant_floating_point_two_mul_sigma_square_vector(num_of_simd_dgau);
  for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
    constant_floating_point_sigma_square_div_t_vector[i] =
        constant_floating_point_sigma_vector[i] * constant_floating_point_sigma_vector[i];
    constant_floating_point_two_mul_sigma_square_vector[i] =
        2.0 * constant_floating_point_sigma_vector[i] * constant_floating_point_sigma_vector[i];
  }

  //   std::cout << "333" << std::endl;
  SecureFloatingPointCircuitABY constant_floating_point_sigma_square_div_t =
      SecureFloatingPointCircuitABY(
          (share_->Get())
              ->GetBackend()
              .ConstantAsBooleanGmwInput(ToInput<FloatType, std::true_type>(
                  constant_floating_point_sigma_square_div_t_vector)));

  SecureFloatingPointCircuitABY constant_floating_point_two_mul_sigma_square =
      SecureFloatingPointCircuitABY(
          (share_->Get())
              ->GetBackend()
              .ConstantAsBooleanGmwInput(ToInput<FloatType, std::true_type>(
                  constant_floating_point_two_mul_sigma_square_vector)));

  //   std::cout << "444" << std::endl;
  ShareWrapper boolean_gmw_share_Y = boolean_gmw_share_discrete_laplace_sample_vector[0];
  SecureFloatingPointCircuitABY floating_point_C_bernoulli_parameter =
      (((SecureSignedInteger(boolean_gmw_share_Y).Int2FL(FLType_size).Abs() -
         SecureFloatingPointCircuitABY(ShareWrapper::Simdify(ShareWrapper::SimdifyDuplicateVertical(
             constant_floating_point_sigma_square_div_t.Get().Unsimdify(), iteration_4))))
            .Sqr()) /
       (SecureFloatingPointCircuitABY(ShareWrapper::Simdify(ShareWrapper::SimdifyDuplicateVertical(
           constant_floating_point_two_mul_sigma_square.Get().Unsimdify(), iteration_4)))))
          .Neg()
          .Exp();

  //   std::cout << "555" << std::endl;
  ShareWrapper boolean_gmw_share_bernoulli =
      SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_share_dgau) <
      floating_point_C_bernoulli_parameter;

  ShareWrapper boolean_gmw_share_choice =
      boolean_gmw_share_bernoulli & boolean_gmw_share_discrete_laplace_sample_vector[1];

  std::vector<ShareWrapper> boolean_gmw_share_Y_reshape = ShareWrapper::SimdifyReshapeHorizontal(
      boolean_gmw_share_Y.Unsimdify(), iteration_4, num_of_simd_dgau);
  std::vector<ShareWrapper> boolean_gmw_share_choice_reshape =
      ShareWrapper::SimdifyReshapeHorizontal(boolean_gmw_share_choice.Unsimdify(), iteration_4,
                                             num_of_simd_dgau);

  //   std::cout << "666" << std::endl;
  std::vector<ShareWrapper> boolean_gmw_share_result_vector = share_->InvertBinaryTreeSelection(
      boolean_gmw_share_Y_reshape, boolean_gmw_share_choice_reshape);

  //   // only for debug
  boolean_gmw_share_result_vector.emplace_back(
      boolean_gmw_share_discrete_laplace_sample_vector[0]);  // 2
  boolean_gmw_share_result_vector.emplace_back(
      boolean_gmw_share_discrete_laplace_sample_vector[1]);                                  //
                                                                                             // 3
  boolean_gmw_share_result_vector.emplace_back(boolean_gmw_share_bernoulli);                 //
                                                                                             // 4
  boolean_gmw_share_result_vector.emplace_back(boolean_gmw_share_choice);                    // 5
  boolean_gmw_share_result_vector.emplace_back(floating_point_C_bernoulli_parameter.Get());  //
                                                                                             // 6
  boolean_gmw_share_result_vector.emplace_back(
      SecureSignedInteger(boolean_gmw_share_Y).Get());  // 7
  boolean_gmw_share_result_vector.emplace_back(
      SecureFloatingPointCircuitABY(
          ShareWrapper::Simdify(ShareWrapper::SimdifyDuplicateVertical(
              constant_floating_point_sigma_square_div_t.Get().Unsimdify(), iteration_4)))
          .Get());  // 8

  return boolean_gmw_share_result_vector;
}

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLDiscreteGaussianDistribution_BGMW<
    float, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<double>& constant_floating_point_sigma_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau, std::size_t iteration_2,
    std::size_t iteration_3, std::size_t iteration_4) const;

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLDiscreteGaussianDistribution_BGMW<
    double, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<double>& constant_floating_point_sigma_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau, std::size_t iteration_2,
    std::size_t iteration_3, std::size_t iteration_4) const;

// TODO: after benchmarking, use more floating-point
template <typename FloatType, typename UintType>
std::vector<ShareWrapper> SecureSamplingAlgorithm_optimized::FLSymmetricBinomialDistribution_BGMW(
    std::vector<double> constant_sqrt_n_vector,
    const ShareWrapper& unsigned_integer_boolean_gmw_share_geometric_sample,
    const ShareWrapper& boolean_gmw_share_random_bits,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share, std::size_t iteration) const {
  std::size_t num_of_simd = constant_sqrt_n_vector.size();
  //   using UintType = std::uint64_t;
  std::size_t FLType_size = sizeof(FloatType) * 8;

  assert(unsigned_integer_boolean_gmw_share_geometric_sample->GetNumberOfSimdValues() ==
         iteration * num_of_simd);
  assert(boolean_gmw_share_random_bits->GetNumberOfSimdValues() == iteration * num_of_simd);
  assert(random_unsigned_integer_boolean_gmw_share->GetNumberOfSimdValues() ==
         iteration * num_of_simd);
  assert(random_floating_point_0_1_boolean_gmw_share->GetNumberOfSimdValues() ==
         iteration * num_of_simd);

  std::vector<UintType> constant_m_vector(num_of_simd * iteration);
  std::vector<FloatType> constant_m_div_4_vector(num_of_simd * iteration);
  std::vector<UintType> constant_neg_sqrt_n_mul_lnn_div_2_vector(num_of_simd * iteration);
  std::vector<UintType> constant_sqrt_n_mul_sqrt_lnn_div_2_vector(num_of_simd * iteration);
  std::vector<FloatType> constant_p_coefficient_1_vector(num_of_simd * iteration);
  std::vector<FloatType> constant_p_coefficient_2_vector(num_of_simd * iteration);
  for (std::size_t i = 0; i < num_of_simd; i++) {
    for (std::size_t j = 0; j < iteration; j++) {
      constant_m_vector[i * iteration + j] =
          UintType(floor(M_SQRT2 * constant_sqrt_n_vector[i] + 1.0));

      constant_m_div_4_vector[i * iteration + j] =
          FloatType(constant_m_vector[i * iteration + j]) / 4.0;

      constant_sqrt_n_mul_sqrt_lnn_div_2_vector[i * iteration + j] =
          UintType(floor(constant_sqrt_n_vector[i] * sqrt(log(constant_sqrt_n_vector[i]) / 2.0)));

      constant_neg_sqrt_n_mul_lnn_div_2_vector[i * iteration + j] =
          -constant_sqrt_n_mul_sqrt_lnn_div_2_vector[i * iteration + j];

      constant_p_coefficient_1_vector[i * iteration + j] =
          sqrt(2.0 / M_PI) / constant_sqrt_n_vector[i] *
          (1.0 - 0.4 * pow(log(constant_sqrt_n_vector[i]) * 2, 1.5) / constant_sqrt_n_vector[i]);

      constant_p_coefficient_2_vector[i * iteration + j] = M_SQRT2 / constant_sqrt_n_vector[i];
    }
  }

  // std::cout << "000"<< std::endl;
  ShareWrapper signed_integer_boolean_gmw_share_s =
      unsigned_integer_boolean_gmw_share_geometric_sample;

  SecureSignedInteger signed_integer_s = SecureSignedInteger(signed_integer_boolean_gmw_share_s);
  SecureSignedInteger signed_integer_neg_s_minus_one = signed_integer_s.Neg() - UintType(1);

  ShareWrapper signed_integer_boolean_gmw_share_k = boolean_gmw_share_random_bits.Mux(
      signed_integer_boolean_gmw_share_s, signed_integer_neg_s_minus_one.Get());

  ShareWrapper signed_integer_constant_boolean_gmw_share_m =
      (share_->Get())->GetBackend().ConstantAsBooleanGmwInput(ToInput<UintType>(constant_m_vector));
  ShareWrapper floating_point_constant_boolean_gmw_share_m_div_4 =
      (share_->Get())
          ->GetBackend()
          .ConstantAsBooleanGmwInput(ToInput<FloatType, std::true_type>(constant_m_div_4_vector));

  // std::cout << "111"<< std::endl;
  SecureSignedInteger signed_integer_i =
      SecureSignedInteger(signed_integer_boolean_gmw_share_k) *
          SecureSignedInteger(signed_integer_constant_boolean_gmw_share_m) +
      SecureSignedInteger(random_unsigned_integer_boolean_gmw_share);

  ShareWrapper constant_boolean_gmw_share_neg_sqrt_n_mul_lnn_div_2 =
      (share_->Get())
          ->GetBackend()
          .ConstantAsBooleanGmwInput(ToInput<UintType>(constant_neg_sqrt_n_mul_lnn_div_2_vector));
  ShareWrapper constant_boolean_gmw_share_sqrt_n_mul_lnn_div_2 =
      (share_->Get())
          ->GetBackend()
          .ConstantAsBooleanGmwInput(ToInput<UintType>(constant_sqrt_n_mul_sqrt_lnn_div_2_vector));

  ShareWrapper constant_boolean_gmw_share_p_coefficient_1 =
      (share_->Get())
          ->GetBackend()
          .ConstantAsBooleanGmwInput(
              ToInput<FloatType, std::true_type>(constant_p_coefficient_1_vector));
  ShareWrapper constant_boolean_gmw_share_p_coefficient_2 =
      (share_->Get())
          ->GetBackend()
          .ConstantAsBooleanGmwInput(
              ToInput<FloatType, std::true_type>(constant_p_coefficient_2_vector));

  // std::cout << "222"<< std::endl;

  //   ShareWrapper boolean_gmw_share_i_in_range_condition =
  //       (signed_integer_i.GEQ(
  //           SecureSignedInteger(constant_boolean_gmw_share_neg_sqrt_n_mul_lnn_div_2))) &
  //
  (signed_integer_i.LE(SecureSignedInteger(constant_boolean_gmw_share_sqrt_n_mul_lnn_div_2)));
  ShareWrapper boolean_gmw_share_i_in_range_condition = signed_integer_i.InRange(
      SecureSignedInteger(constant_boolean_gmw_share_sqrt_n_mul_lnn_div_2));

  SecureFloatingPointCircuitABY floating_point_p_i =
      SecureFloatingPointCircuitABY(constant_boolean_gmw_share_p_coefficient_1) *
      ((((SecureFloatingPointCircuitABY(constant_boolean_gmw_share_p_coefficient_2) *
          signed_integer_i.Int2FL(FLType_size))
             .Sqr())
            .Neg())
           .Exp());

  //   // only for debug
  //   SecureFloatingPointCircuitABY floating_point_exp_i =
  //       ((((SecureFloatingPointCircuitABY(constant_boolean_gmw_share_p_coefficient_2) *
  //           signed_integer_i.Int2FL())
  //              .Sqr())
  //             .Neg())
  //            .Exp());

  // this step can be saved by computing boolean_gmw_share_i_in_range_condition
  //   ShareWrapper floating_point_p_i_greater_than_zero = floating_point_p_i > double(0);

  SecureFloatingPointCircuitABY floating_point_pow2_s =
      (signed_integer_s.Int2FL(FLType_size)).Exp2();

  SecureFloatingPointCircuitABY floating_point_p_i_mul_f =
      floating_point_p_i * floating_point_pow2_s *
      SecureFloatingPointCircuitABY(floating_point_constant_boolean_gmw_share_m_div_4);

  ShareWrapper boolean_gmw_share_Bernoulli_c =
      SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_share) <
      floating_point_p_i_mul_f;

  //   ShareWrapper boolean_gmw_share_Bernoulli_c_invert = ~boolean_gmw_share_Bernoulli_c;

  //   ShareWrapper boolean_gmw_share_choice = boolean_gmw_share_i_in_range_condition &
  //                                           floating_point_p_i_greater_than_zero &
  //                                           boolean_gmw_share_Bernoulli_c_invert;
  //   ShareWrapper boolean_gmw_share_choice =
  //       boolean_gmw_share_i_in_range_condition & boolean_gmw_share_Bernoulli_c_invert;
  ShareWrapper boolean_gmw_share_choice =
      boolean_gmw_share_i_in_range_condition & boolean_gmw_share_Bernoulli_c;

  // std::cout << "444"<< std::endl;
  std::vector<ShareWrapper> signed_integer_i_reshape_vector =
      ShareWrapper::SimdifyReshapeHorizontal(signed_integer_i.Get().Unsimdify(), iteration,
                                             num_of_simd);
  std::vector<ShareWrapper> boolean_gmw_share_choice_reshape_vector =
      ShareWrapper::SimdifyReshapeHorizontal(boolean_gmw_share_choice.Unsimdify(), iteration,
                                             num_of_simd);

  std::vector<ShareWrapper> boolean_gmw_share_result_vector = share_->InvertBinaryTreeSelection(
      signed_integer_i_reshape_vector, boolean_gmw_share_choice_reshape_vector);

  // only for debug
  boolean_gmw_share_result_vector.emplace_back(floating_point_p_i.Get());  // 2
  boolean_gmw_share_result_vector.emplace_back(signed_integer_i.Get());    // 3
  boolean_gmw_share_result_vector.emplace_back((signed_integer_i.Int2FL(FLType_size).Get()));
  // 4
  boolean_gmw_share_result_vector.emplace_back(
      (boolean_gmw_share_i_in_range_condition.Get()));                                  // 5
  boolean_gmw_share_result_vector.emplace_back((floating_point_pow2_s.Get()));          // 6
  boolean_gmw_share_result_vector.emplace_back((floating_point_p_i_mul_f.Get()));       // 7
  boolean_gmw_share_result_vector.emplace_back((boolean_gmw_share_choice.Get()));       // 8
  boolean_gmw_share_result_vector.emplace_back((boolean_gmw_share_Bernoulli_c.Get()));  // 9
  boolean_gmw_share_result_vector.emplace_back(
      (random_floating_point_0_1_boolean_gmw_share.Get()));  // 10
  boolean_gmw_share_result_vector.emplace_back((signed_integer_s.Int2FL(FLType_size).Get()));
  // 11

  return boolean_gmw_share_result_vector;
}

// constant_sqrt_n * sqrt(2) < 2^(64)
template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLSymmetricBinomialDistribution_BGMW<double, std::uint64_t>(
    std::vector<double> constant_sqrt_n_vector,
    const ShareWrapper& unsigned_integer_boolean_gmw_share_geometric_sample,
    const ShareWrapper& boolean_gmw_share_random_bits,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share, std::size_t iteration) const;

// constant_sqrt_n * sqrt(2) < 2^(128)
template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLSymmetricBinomialDistribution_BGMW<double, __uint128_t>(
    std::vector<double> constant_sqrt_n_vector,
    const ShareWrapper& unsigned_integer_boolean_gmw_share_geometric_sample,
    const ShareWrapper& boolean_gmw_share_random_bits,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share, std::size_t iteration) const;

// ========================================================================================================================================
// ! optimized floating-point version in Garbled Circuit

template <typename FloatType, typename UintType, typename IntType, typename A>
std::vector<ShareWrapper> SecureSamplingAlgorithm_optimized::FLGeometricDistributionEXP_GC(
    const std::vector<UintType>& constant_unsigned_integer_numerator_vector,
    const std::vector<UintType>& constant_unsigned_integer_denominator_vector,
    const ShareWrapper& random_floating_point_0_1_gc_share,
    const ShareWrapper& random_unsigned_integer_gc_share, std::size_t iteration_1,
    std::size_t iteration_2) const {
  std::size_t num_of_simd_geo = constant_unsigned_integer_numerator_vector.size();

  assert(constant_unsigned_integer_numerator_vector.size() ==
         constant_unsigned_integer_denominator_vector.size());
  assert(random_floating_point_0_1_gc_share->GetNumberOfSimdValues() ==
         (iteration_1 + iteration_2) * num_of_simd_geo);
  assert(random_unsigned_integer_gc_share->GetNumberOfSimdValues() ==
         iteration_1 * num_of_simd_geo);

  //   using UintType = std::uint64_t;
  //   using IntType = std::int64_t;

  std::size_t FLType_size = sizeof(FloatType) * 8;

  // if numerator or denominator are all ones, we can avoid some computations in MPC
  bool numerator_are_all_ones =
      VectorAllEqualToValue<UintType>(constant_unsigned_integer_numerator_vector, UintType(1));
  bool denominator_are_all_ones =
      VectorAllEqualToValue<UintType>(constant_unsigned_integer_denominator_vector, UintType(1));

  assert(!denominator_are_all_ones);

  // ! case 1: denominator are not all ones
  //   if (!denominator_are_all_ones) {
  //   std::cout << " if (!denominator_are_all_ones)" << std::endl;
  ShareWrapper unsigned_integer_gc_share_denominator =
      ((share_->Get())
           ->GetBackend()
           .ConstantAsGCInput(ToInput<UintType>(constant_unsigned_integer_denominator_vector)));

  // convert denominator to FloatType type in plaintext instead of converting in MPC
  std::vector<FloatType> constant_floating_point_denominator_vector(num_of_simd_geo);
  for (std::size_t i = 0; i < num_of_simd_geo; i++) {
    UintType denominator_tmp = constant_unsigned_integer_denominator_vector[i];
    constant_floating_point_denominator_vector[i] = FloatType(IntType(denominator_tmp));
  }

  // convert plaintext of denominator (in floating-point) to MPC constant shares
  ShareWrapper floating_point_gc_share_denominator =
      ((share_->Get())
           ->GetBackend()
           .ConstantAsGCInput(
               ToInput<FloatType, std::true_type>(constant_floating_point_denominator_vector)));

  // reshape the vector of denominator in preparation for the SIMD operations
  std::vector<ShareWrapper> floating_point_gc_share_denominator_expand =
      ShareWrapper::SimdifyDuplicateVertical(floating_point_gc_share_denominator.Unsimdify(),
                                             iteration_1);

  ShareWrapper floating_point_gc_share_denominator_simdify =
      ShareWrapper::Simdify(floating_point_gc_share_denominator_expand);

  // std::cout<<"001"<<std::endl;

  // convert the random unsigned integer to floating-point numbers
  SecureFloatingPointCircuitABY floating_point_random_unsigned_integer =
      SecureUnsignedInteger(random_unsigned_integer_gc_share).Int2FL(FLType_size);

  // reshape the vector of random unsigned integer in preparation for the SIMD operations
  SecureFloatingPointCircuitABY floating_point_unsigned_integer_denominator_simdify =
      SecureFloatingPointCircuitABY(floating_point_gc_share_denominator_simdify);

  // =====================================================
  // TODO: this division can be saved by compute e^(-1/t) alone
  //   SecureFloatingPointCircuitABY floating_point_random_unsigned_integer_div_denominator =
  //       floating_point_random_unsigned_integer /
  //       floating_point_unsigned_integer_denominator_simdify;

  //   SecureFloatingPointCircuitABY floating_point_exp_neg_random_unsigned_integer_div_denominator
  //   =
  //       floating_point_random_unsigned_integer_div_denominator.Neg().Exp();
  // =====================================================
  // TODO: save this division by computing e^(-1/t) first

  SecureFloatingPointCircuitABY floating_point_exp_neg_random_unsigned_integer_div_denominator =
      floating_point_random_unsigned_integer.Exp() *
      FloatType(std::exp(-constant_unsigned_integer_denominator_vector[0]));

  // =====================================================

  std::vector<FloatType> vector_of_exp_neg_one(num_of_simd_geo * iteration_2, std::exp(-1.0));
  SecureFloatingPointCircuitABY floating_point_constant_exp_neg_one = SecureFloatingPointCircuitABY(
      (share_->Get())
          ->GetBackend()
          .ConstantAsGCInput(ToInput<FloatType, std::true_type>(vector_of_exp_neg_one)));

  // std::cout<<"002"<<std::endl;

  // TODO: use unsigned integer comparison instead
  // merge the floating-point comparison operation together
  ShareWrapper floating_point_Bernoulli_distribution_parameter_p = ShareWrapper::Simdify(
      std::vector{floating_point_exp_neg_random_unsigned_integer_div_denominator.Get(),
                  floating_point_constant_exp_neg_one.Get()});

  ShareWrapper gc_share_Bernoulli_sample =
      SecureFloatingPointCircuitABY(random_floating_point_0_1_gc_share) <
      SecureFloatingPointCircuitABY(floating_point_Bernoulli_distribution_parameter_p);

  // std::cout<<"003"<<std::endl;

  std::vector<ShareWrapper> gc_share_Bernoulli_sample_unsimdify =
      gc_share_Bernoulli_sample.Unsimdify();
  std::vector<ShareWrapper> gc_share_Bernoulli_sample_part_1_vector(
      gc_share_Bernoulli_sample_unsimdify.begin(),
      gc_share_Bernoulli_sample_unsimdify.begin() + iteration_1 * num_of_simd_geo);

  std::vector<ShareWrapper> gc_share_Bernoulli_sample_part_2_vector(
      gc_share_Bernoulli_sample_unsimdify.begin() + iteration_1 * num_of_simd_geo,
      gc_share_Bernoulli_sample_unsimdify.begin() + iteration_1 * num_of_simd_geo +
          iteration_2 * num_of_simd_geo);

  // std::cout<<"004"<<std::endl;

  std::vector<ShareWrapper> gc_share_b1_vector = ShareWrapper::SimdifyReshapeHorizontal(
      gc_share_Bernoulli_sample_part_1_vector, iteration_1, num_of_simd_geo);

  std::vector<ShareWrapper> gc_share_b2_vector = ShareWrapper::SimdifyReshapeHorizontal(
      gc_share_Bernoulli_sample_part_2_vector, iteration_2, num_of_simd_geo);

  // std::cout<<"005"<<std::endl;
  std::vector<ShareWrapper> random_unsigned_integer_gc_share_unsimdify =
      random_unsigned_integer_gc_share.Unsimdify();
  //   std::vector<ShareWrapper> random_unsigned_integer_gc_share_for_b1_vector =
  //       ShareWrapper::SimdifyReshapeHorizontal(random_unsigned_integer_gc_share.Unsimdify(),
  //                                              iteration_1, num_of_simd_geo);
  std::vector<ShareWrapper> random_unsigned_integer_gc_share_for_b1_vector =
      ShareWrapper::SimdifyReshapeHorizontal(random_unsigned_integer_gc_share_unsimdify,
                                             iteration_1, num_of_simd_geo);
  // std::cout<<"006"<<std::endl;
  std::vector<ShareWrapper> gc_share_u = share_->InvertBinaryTreeSelection(
      random_unsigned_integer_gc_share_for_b1_vector, gc_share_b1_vector);
  // std::cout<<"007"<<std::endl;
  std::vector<ShareWrapper> gc_share_constant_j;
  gc_share_constant_j.reserve(iteration_2);
  for (std::size_t j = 0; j < iteration_2; j++) {
    std::vector<UintType> vector_of_constant_j(num_of_simd_geo, j);
    gc_share_constant_j.emplace_back(
        (share_->Get())->GetBackend().ConstantAsGCInput(ToInput<UintType>(vector_of_constant_j)));
  }

  std::vector<ShareWrapper> gc_share_b2_invert_vector;
  gc_share_b2_invert_vector.reserve(iteration_2);
  for (std::size_t i = 0; i < iteration_2; i++) {
    gc_share_b2_invert_vector.emplace_back(~gc_share_b2_vector[i]);
  }

  std::vector<ShareWrapper> gc_share_v =
      share_->InvertBinaryTreeSelection(gc_share_constant_j, gc_share_b2_invert_vector);

  SecureUnsignedInteger unsigned_integer_w =
      SecureUnsignedInteger(gc_share_v[0]) *
          SecureUnsignedInteger(unsigned_integer_gc_share_denominator) +
      SecureUnsignedInteger(gc_share_u[0]);
  // std::cout<<"008"<<std::endl;
  // case 1.1
  // numerator's vector elements are not all equal to one
  if (!numerator_are_all_ones) {
    // =================================================================
    ShareWrapper unsigned_integer_gc_share_numerator =
        ((share_->Get())
             ->GetBackend()
             .ConstantAsGCInput(ToInput<UintType>(constant_unsigned_integer_numerator_vector)));
    // std::cout<<"009"<<std::endl;
    // TODO: optimize integer division with floating-point division
    // TODO: using Garbled Circuit for division instead
    SecureUnsignedInteger unsigned_integer_geometric_sample =
        unsigned_integer_w / SecureUnsignedInteger(unsigned_integer_gc_share_numerator);
    // =================================================================
    // TODO: test if floating-point division is faster
    // ShareWrapper unsigned_integer_gc_share_numerator =
    //     ((share_->Get())
    //          ->GetBackend()
    //          .ConstantAsGCInput(ToInput<UintType>(constant_unsigned_integer_numerator_vector)));
    // SecureFloatingPointCircuitABY floating_point_geometric_sample =
    //     (unsigned_integer_w.Int2FL(sizeof(double) * 8)) /
    //     (SecureUnsignedInteger(unsigned_integer_gc_share_numerator).Int2FL(sizeof(double) * 8))
    //         .Floor();
    // SecureUnsignedInteger unsigned_integer_geometric_sample =
    //     SecureUnsignedInteger((floating_point_geometric_sample.FL2Int(sizeof(UintType) * 8)).Get());

    // =================================================================

    // std::cout<<"010"<<std::endl;
    ShareWrapper gc_share_success_flag = (gc_share_u[1] & gc_share_v[1]);

    // std::cout<<"011"<<std::endl;
    std::vector<ShareWrapper> result_vector;
    result_vector.reserve(2);
    result_vector.emplace_back(unsigned_integer_geometric_sample.Get());
    result_vector.emplace_back(gc_share_success_flag);

    // only for debug
    // result_vector.emplace_back(floating_point_gc_share_denominator_simdify);  //
    // // 2
    // result_vector.emplace_back(floating_point_random_unsigned_integer.Get());               // 3
    // result_vector.emplace_back(floating_point_unsigned_integer_denominator_simdify.Get());  //
    // // 4
    // result_vector.emplace_back(floating_point_random_unsigned_integer_div_denominator.Get());
    // // 5
    // result_vector.emplace_back(gc_share_v[0]);  // 6
    // result_vector.emplace_back(gc_share_u[0]);  //
    // // 7
    // result_vector.emplace_back(unsigned_integer_w.Get());  // 8

    return result_vector;
  }

  // case 1.2
  // if the numerator's vector elements are all equal to one, we can save the division operation
  else {
    // save MPC computation here
    SecureUnsignedInteger unsigned_integer_geometric_sample = unsigned_integer_w;

    ShareWrapper gc_share_success_flag = (gc_share_u[1] & gc_share_v[1]);

    std::vector<ShareWrapper> result_vector;
    result_vector.reserve(2);
    result_vector.emplace_back(unsigned_integer_geometric_sample.Get());
    result_vector.emplace_back(gc_share_success_flag);

    // // only for debug
    // result_vector.emplace_back(floating_point_gc_share_denominator_simdify);  //
    // // 2
    // result_vector.emplace_back(floating_point_random_unsigned_integer.Get());               // 3
    // result_vector.emplace_back(floating_point_unsigned_integer_denominator_simdify.Get());  //
    //                                                                                         // 4
    // result_vector.emplace_back(floating_point_random_unsigned_integer_div_denominator.Get());
    // // 5
    // result_vector.emplace_back(gc_share_v[0]);  // 6
    // result_vector.emplace_back(gc_share_u[0]);  //
    // // 7
    // result_vector.emplace_back(unsigned_integer_w.Get());  // 8

    return result_vector;
  }
  //   }
}

template std::vector<ShareWrapper> SecureSamplingAlgorithm_optimized::FLGeometricDistributionEXP_GC<
    float, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const std::vector<std::uint64_t>& constant_unsigned_integer_denominator_vector,
    const ShareWrapper& random_floating_point_0_1_gc_share,
    const ShareWrapper& random_unsigned_integer_gc_share, std::size_t iteration_1,
    std::size_t iteration_2) const;

template std::vector<ShareWrapper> SecureSamplingAlgorithm_optimized::FLGeometricDistributionEXP_GC<
    double, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const std::vector<std::uint64_t>& constant_unsigned_integer_denominator_vector,
    const ShareWrapper& random_floating_point_0_1_gc_share,
    const ShareWrapper& random_unsigned_integer_gc_share, std::size_t iteration_1,
    std::size_t iteration_2) const;

template <typename FloatType, typename UintType, typename IntType, typename A>
std::vector<ShareWrapper> SecureSamplingAlgorithm_optimized::FLGeometricDistributionEXP_GC(
    const std::vector<UintType>& constant_unsigned_integer_numerator_vector,
    const ShareWrapper& random_floating_point_0_1_gc_share, std::size_t iteration_2) const {
  std::size_t num_of_simd_geo = constant_unsigned_integer_numerator_vector.size();

  assert(random_floating_point_0_1_gc_share->GetNumberOfSimdValues() ==
         (iteration_2)*num_of_simd_geo);

  //   using UintType = std::uint64_t;
  //   using IntType = std::int64_t;

  // if numerator or denominator are all ones, we can avoid some computations in MPC
  bool numerator_are_all_ones =
      VectorAllEqualToValue<UintType>(constant_unsigned_integer_numerator_vector, UintType(1));
  bool denominator_are_all_ones = true;

  // ! case 2:
  // if the denominator vector's elements are all ones, we can skip the first for loop iterations
  //   if (denominator_are_all_ones) {
  std::vector<FloatType> vector_of_exp_neg_one(num_of_simd_geo * iteration_2, std::exp(-1.0));
  SecureFloatingPointCircuitABY floating_point_constant_exp_neg_one = SecureFloatingPointCircuitABY(
      (share_->Get())
          ->GetBackend()
          .ConstantAsGCInput(ToInput<FloatType, std::true_type>(vector_of_exp_neg_one)));

  ShareWrapper floating_point_Bernoulli_distribution_parameter_p =
      floating_point_constant_exp_neg_one.Get();
  ShareWrapper gc_share_Bernoulli_sample =
      SecureFloatingPointCircuitABY(random_floating_point_0_1_gc_share) <
      SecureFloatingPointCircuitABY(floating_point_Bernoulli_distribution_parameter_p);

  std::vector<ShareWrapper> gc_share_Bernoulli_sample_unsimdify =
      gc_share_Bernoulli_sample.Unsimdify();

  std::vector<ShareWrapper> gc_share_Bernoulli_sample_part_2_vector(
      gc_share_Bernoulli_sample_unsimdify.begin(),
      gc_share_Bernoulli_sample_unsimdify.begin() + iteration_2 * num_of_simd_geo);

  // std::cout << "gc_share_Bernoulli_sample_part_2_vector.size(): "
  //           << gc_share_Bernoulli_sample_part_2_vector.size() << std::endl;

  std::vector<ShareWrapper> gc_share_b2_vector = ShareWrapper::SimdifyReshapeHorizontal(
      gc_share_Bernoulli_sample_part_2_vector, iteration_2, num_of_simd_geo);

  //   std::cout << "333" << std::endl;
  std::vector<ShareWrapper> gc_share_constant_j;
  gc_share_constant_j.reserve(iteration_2);
  for (std::size_t j = 0; j < iteration_2; j++) {
    std::vector<UintType> vector_of_constant_j(num_of_simd_geo, j);
    gc_share_constant_j.emplace_back(
        (share_->Get())->GetBackend().ConstantAsGCInput(ToInput<UintType>(vector_of_constant_j)));
  }

  // invert gc_share_b2_vector
  std::vector<ShareWrapper> gc_share_b2_invert_vector;
  gc_share_b2_invert_vector.reserve(iteration_2);
  for (std::size_t i = 0; i < iteration_2; i++) {
    gc_share_b2_invert_vector.emplace_back(~gc_share_b2_vector[i]);
  }

  std::vector<ShareWrapper> gc_share_v =
      share_->InvertBinaryTreeSelection(gc_share_constant_j, gc_share_b2_invert_vector);

  SecureUnsignedInteger unsigned_integer_w = SecureUnsignedInteger(gc_share_v[0]);

  // case 2.1
  // the numerator's vector elements are not all ones
  if (!numerator_are_all_ones) {
    ShareWrapper unsigned_integer_gc_share_numerator =
        ((share_->Get())
             ->GetBackend()
             .ConstantAsGCInput(ToInput<UintType>(constant_unsigned_integer_numerator_vector)));

    // TODO: optimize using floating-point division instead
    SecureUnsignedInteger unsigned_integer_geometric_sample =
        unsigned_integer_w / SecureUnsignedInteger(unsigned_integer_gc_share_numerator);

    ShareWrapper gc_share_success_flag = (gc_share_v[1]);

    std::vector<ShareWrapper> result_vector;
    result_vector.reserve(2);
    result_vector.emplace_back(unsigned_integer_geometric_sample.Get());
    result_vector.emplace_back(gc_share_success_flag);

    return result_vector;
  }

  // case 2.2
  // if the numerator's vector elements are all ones, we can avoid the division operation
  else {
    SecureUnsignedInteger unsigned_integer_geometric_sample = unsigned_integer_w;

    ShareWrapper gc_share_success_flag = (gc_share_v[1]);

    std::vector<ShareWrapper> result_vector;
    result_vector.reserve(2);
    result_vector.emplace_back(unsigned_integer_geometric_sample.Get());
    result_vector.emplace_back(gc_share_success_flag);

    return result_vector;
  }
  //   }
}

template std::vector<ShareWrapper> SecureSamplingAlgorithm_optimized::FLGeometricDistributionEXP_GC<
    float, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const ShareWrapper& random_floating_point_0_1_gc_share, std::size_t iteration_2) const;

template std::vector<ShareWrapper> SecureSamplingAlgorithm_optimized::FLGeometricDistributionEXP_GC<
    double, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const ShareWrapper& random_floating_point_0_1_gc_share, std::size_t iteration_2) const;

template <typename FloatType, typename UintType, typename IntType, typename A>
std::vector<ShareWrapper> SecureSamplingAlgorithm_optimized::FLDiscreteLaplaceDistribution_GC(
    const std::vector<UintType>& constant_unsigned_integer_numerator_vector,
    const std::vector<UintType>& constant_unsigned_integer_denominator_vector,
    const ShareWrapper& random_floating_point_0_1_gc_share,
    const ShareWrapper& random_unsigned_integer_gc_share,
    const ShareWrapper& gc_share_bernoulli_sample, std::size_t iteration_1, std::size_t iteration_2,
    std::size_t iteration_3) const {
  //   using UintType = std::uint64_t;

  // same as FLGeometricDistributionEXP except with more iteration_3
  std::size_t num_of_simd_geo = iteration_3;
  std::size_t num_of_simd_dlap = constant_unsigned_integer_numerator_vector.size();
  std::size_t num_of_simd_total = num_of_simd_dlap * num_of_simd_geo;

  assert(constant_unsigned_integer_numerator_vector.size() ==
         constant_unsigned_integer_denominator_vector.size());
  assert(random_floating_point_0_1_gc_share->GetNumberOfSimdValues() ==
         (iteration_1 + iteration_2) * num_of_simd_total);
  assert(random_unsigned_integer_gc_share->GetNumberOfSimdValues() ==
         iteration_1 * num_of_simd_total);
  assert(gc_share_bernoulli_sample->GetNumberOfSimdValues() == num_of_simd_total);

  //   std::vector<ShareWrapper> unsigned_integer_numerator_geo_vector =
  //       ShareWrapper::SimdifyDuplicateVertical(
  //           unsigned_integer_gc_share_numerator.Unsimdify(), num_of_simd_geo);
  //   ShareWrapper unsigned_integer_numerator_geo =
  //       ShareWrapper::Simdify(unsigned_integer_numerator_geo_vector);

  //   std::vector<ShareWrapper> unsigned_integer_denominator_geo_vector =
  //       ShareWrapper::SimdifyDuplicateVertical(
  //           unsigned_integer_gc_share_denominator.Unsimdify(), num_of_simd_geo);
  //   ShareWrapper unsigned_integer_denominator_geo =
  //       ShareWrapper::Simdify(unsigned_integer_denominator_geo_vector);

  //   std::vector<std::uint64_t> constant_unsigned_integer_numerator_geo_vector(num_of_simd_total);
  //   std::vector<std::uint64_t>
  //   constant_unsigned_integer_denominator_geo_vector(num_of_simd_total);
  std::vector<UintType> constant_unsigned_integer_numerator_geo_vector(num_of_simd_total);
  std::vector<UintType> constant_unsigned_integer_denominator_geo_vector(num_of_simd_total);

  for (std::size_t i = 0; i < num_of_simd_dlap; i++) {
    for (std::size_t j = 0; j < num_of_simd_geo; j++) {
      constant_unsigned_integer_numerator_geo_vector[i * num_of_simd_geo + j] =
          constant_unsigned_integer_numerator_vector[i];
      constant_unsigned_integer_denominator_geo_vector[i * num_of_simd_geo + j] =
          constant_unsigned_integer_denominator_vector[i];
    }
  }

  //   std::cout<<"000"<< std::endl;

  std::vector<ShareWrapper> geometric_sample_vector =
      FLGeometricDistributionEXP_GC<FloatType, UintType, IntType, A>(
          constant_unsigned_integer_numerator_geo_vector,
          constant_unsigned_integer_denominator_geo_vector, random_floating_point_0_1_gc_share,
          random_unsigned_integer_gc_share, iteration_1, iteration_2);

  //   std::cout<<"111"<< std::endl;
  ShareWrapper gc_share_sign = gc_share_bernoulli_sample;
  ShareWrapper unsigned_integer_geometric_sample_gc_share_magnitude = geometric_sample_vector[0];
  ShareWrapper gc_share_magnitude_EQZ =
      SecureSignedInteger(unsigned_integer_geometric_sample_gc_share_magnitude).IsZero();

  // magnitude*(1-2*sign)
  SecureSignedInteger signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign =
      SecureSignedInteger(unsigned_integer_geometric_sample_gc_share_magnitude).Neg(gc_share_sign);

  ShareWrapper gc_share_choice =
      ~(gc_share_sign & gc_share_magnitude_EQZ) & geometric_sample_vector[1];

  std::vector<ShareWrapper>
      signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign_reshape_vector =
          ShareWrapper::SimdifyReshapeHorizontal(
              signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign.Get().Unsimdify(),
              iteration_3, num_of_simd_dlap);

  std::vector<ShareWrapper> gc_share_choice_reshape_vector = ShareWrapper::SimdifyReshapeHorizontal(
      gc_share_choice.Unsimdify(), iteration_3, num_of_simd_dlap);

  std::vector<ShareWrapper> gc_share_discrete_laplace_sample_vector =
      share_->InvertBinaryTreeSelection(
          signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign_reshape_vector,
          gc_share_choice_reshape_vector);

  //   // only for debug
  //   gc_share_discrete_laplace_sample_vector.emplace_back(gc_share_sign);  //
  //   2 gc_share_discrete_laplace_sample_vector.emplace_back(
  //       unsigned_integer_geometric_sample_gc_share_magnitude);  // 3
  //   gc_share_discrete_laplace_sample_vector.emplace_back(
  //       unsigned_integer_numerator_geo);  // 4
  //   gc_share_discrete_laplace_sample_vector.emplace_back(
  //       unsigned_integer_denominator_geo);  // 5
  //   gc_share_discrete_laplace_sample_vector.emplace_back(
  //       unsigned_integer_with_magnitude_mul_one_minus_two_mul_as_sign.Get()); //
  //       6
  //   gc_share_discrete_laplace_sample_vector.emplace_back(gc_share_choice);
  //
  //   7

  return gc_share_discrete_laplace_sample_vector;
}

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLDiscreteLaplaceDistribution_GC<
    float, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const std::vector<std::uint64_t>& constant_unsigned_integer_denominator_vector,
    const ShareWrapper& random_floating_point_0_1_gc_share,
    const ShareWrapper& random_unsigned_integer_gc_share,
    const ShareWrapper& gc_share_bernoulli_sample, std::size_t iteration_1, std::size_t iteration_2,
    std::size_t iteration_3) const;

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLDiscreteLaplaceDistribution_GC<
    double, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const std::vector<std::uint64_t>& constant_unsigned_integer_denominator_vector,
    const ShareWrapper& random_floating_point_0_1_gc_share,
    const ShareWrapper& random_unsigned_integer_gc_share,
    const ShareWrapper& gc_share_bernoulli_sample, std::size_t iteration_1, std::size_t iteration_2,
    std::size_t iteration_3) const;

template <typename FloatType, typename UintType, typename IntType, typename A>
std::vector<ShareWrapper> SecureSamplingAlgorithm_optimized::FLDiscreteLaplaceDistribution_GC(
    const std::vector<UintType>& constant_unsigned_integer_numerator_vector,
    const ShareWrapper& random_floating_point_0_1_gc_share,
    const ShareWrapper& gc_share_bernoulli_sample, std::size_t iteration_2,
    std::size_t iteration_3) const {
  //   using UintType = std::uint64_t;

  // same as FLGeometricDistributionEXP except with more iteration_3
  std::size_t num_of_simd_geo = iteration_3;
  std::size_t num_of_simd_dlap = constant_unsigned_integer_numerator_vector.size();
  std::size_t num_of_simd_total = num_of_simd_dlap * num_of_simd_geo;

  //   assert(constant_unsigned_integer_numerator_vector.size() ==
  //          constant_unsigned_integer_denominator_vector.size());
  assert(random_floating_point_0_1_gc_share->GetNumberOfSimdValues() ==
         (iteration_2)*num_of_simd_total);
  assert(gc_share_bernoulli_sample->GetNumberOfSimdValues() == num_of_simd_total);

  //   std::vector<ShareWrapper> unsigned_integer_numerator_geo_vector =
  //       ShareWrapper::SimdifyDuplicateVertical(
  //           unsigned_integer_gc_share_numerator.Unsimdify(), num_of_simd_geo);
  //   ShareWrapper unsigned_integer_numerator_geo =
  //       ShareWrapper::Simdify(unsigned_integer_numerator_geo_vector);

  //   std::vector<ShareWrapper> unsigned_integer_denominator_geo_vector =
  //       ShareWrapper::SimdifyDuplicateVertical(
  //           unsigned_integer_gc_share_denominator.Unsimdify(), num_of_simd_geo);
  //   ShareWrapper unsigned_integer_denominator_geo =
  //       ShareWrapper::Simdify(unsigned_integer_denominator_geo_vector);

  std::vector<UintType> constant_unsigned_integer_numerator_geo_vector(num_of_simd_total);
  for (std::size_t i = 0; i < num_of_simd_dlap; i++) {
    for (std::size_t j = 0; j < num_of_simd_geo; j++) {
      constant_unsigned_integer_numerator_geo_vector[i * num_of_simd_geo + j] =
          constant_unsigned_integer_numerator_vector[i];
    }
  }

  std::vector<ShareWrapper> geometric_sample_vector =
      FLGeometricDistributionEXP_GC<FloatType, UintType, IntType, A>(
          constant_unsigned_integer_numerator_geo_vector, random_floating_point_0_1_gc_share,
          iteration_2);

  ShareWrapper gc_share_sign = gc_share_bernoulli_sample;
  ShareWrapper unsigned_integer_geometric_sample_gc_share_magnitude = geometric_sample_vector[0];
  ShareWrapper gc_share_magnitude_EQZ =
      SecureSignedInteger(unsigned_integer_geometric_sample_gc_share_magnitude).IsZero();

  // magnitude*(1-2*sign)
  SecureSignedInteger signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign =
      SecureSignedInteger(unsigned_integer_geometric_sample_gc_share_magnitude).Neg(gc_share_sign);

  ShareWrapper gc_share_choice =
      ~(gc_share_sign & gc_share_magnitude_EQZ) & geometric_sample_vector[1];

  std::vector<ShareWrapper>
      signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign_reshape_vector =
          ShareWrapper::SimdifyReshapeHorizontal(
              signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign.Get().Unsimdify(),
              iteration_3, num_of_simd_dlap);

  std::vector<ShareWrapper> gc_share_choice_reshape_vector = ShareWrapper::SimdifyReshapeHorizontal(
      gc_share_choice.Unsimdify(), iteration_3, num_of_simd_dlap);

  std::vector<ShareWrapper> gc_share_discrete_laplace_sample_vector =
      share_->InvertBinaryTreeSelection(
          signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign_reshape_vector,
          gc_share_choice_reshape_vector);

  //   // only for debug
  // gc_share_discrete_laplace_sample_vector.emplace_back(gc_share_sign);  //
  // // 2
  //  gc_share_discrete_laplace_sample_vector.emplace_back(
  //     unsigned_integer_geometric_sample_gc_share_magnitude);  // 3
  // gc_share_discrete_laplace_sample_vector.emplace_back(
  //     unsigned_integer_numerator_geo);  // 4
  // gc_share_discrete_laplace_sample_vector.emplace_back(
  //     unsigned_integer_denominator_geo);  // 5
  // gc_share_discrete_laplace_sample_vector.emplace_back(
  //     unsigned_integer_with_magnitude_mul_one_minus_two_mul_as_sign.Get()); //
  //     // 6
  // gc_share_discrete_laplace_sample_vector.emplace_back(gc_share_choice); //
  // // 7

  return gc_share_discrete_laplace_sample_vector;
}

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLDiscreteLaplaceDistribution_GC<
    float, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const ShareWrapper& random_floating_point_0_1_gc_share,
    const ShareWrapper& gc_share_bernoulli_sample, std::size_t iteration_2,
    std::size_t iteration_3) const;

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLDiscreteLaplaceDistribution_GC<
    double, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const ShareWrapper& random_floating_point_0_1_gc_share,
    const ShareWrapper& gc_share_bernoulli_sample, std::size_t iteration_2,
    std::size_t iteration_3) const;

template <typename FloatType, typename UintType, typename IntType, typename A>
std::vector<ShareWrapper> SecureSamplingAlgorithm_optimized::FLDiscreteGaussianDistribution_GC(
    const std::vector<double>& constant_floating_point_sigma_vector,
    const ShareWrapper& random_floating_point_0_1_gc_share_dlap,
    const ShareWrapper& random_unsigned_integer_gc_share_dlap,
    const ShareWrapper& gc_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_gc_share_dgau, std::size_t iteration_1,
    std::size_t iteration_2, std::size_t iteration_3, std::size_t iteration_4) const {
  //   using UintType = std::uint64_t;

  std::size_t FLType_size = sizeof(FloatType) * 8;

  std::size_t num_of_simd_dgau = constant_floating_point_sigma_vector.size();
  std::size_t num_of_simd_geo = iteration_3;
  std::size_t num_of_simd_dlap = iteration_4;
  std::size_t num_of_simd_total = num_of_simd_dlap * num_of_simd_geo * num_of_simd_dgau;

  assert(random_floating_point_0_1_gc_share_dlap->GetNumberOfSimdValues() ==
         (iteration_1 + iteration_2) * num_of_simd_total);
  assert(random_unsigned_integer_gc_share_dlap->GetNumberOfSimdValues() ==
         iteration_1 * num_of_simd_total);

  assert(gc_share_bernoulli_sample_dlap->GetNumberOfSimdValues() == num_of_simd_total);
  assert(random_floating_point_0_1_gc_share_dgau->GetNumberOfSimdValues() ==
         iteration_4 * num_of_simd_dgau);

  // std::cout << "000" << std::endl;

  std::vector<UintType> constant_unsigned_integer_t_vector(num_of_simd_dgau);
  for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
    constant_unsigned_integer_t_vector[i] = floor(constant_floating_point_sigma_vector[i]) + 1;
  }

  //   std::vector<UintType> constant_unsigned_integer_t_dlap_vector(num_of_simd_dgau *
  //   num_of_simd_dlap);
  std::vector<UintType> constant_unsigned_integer_numerator_dlap_vector(num_of_simd_dgau *
                                                                        num_of_simd_dlap);
  std::vector<UintType> constant_unsigned_integer_denominator_dlap_vector(num_of_simd_dgau *
                                                                          num_of_simd_dlap);

  // std::cout << "111" << std::endl;
  for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
    for (std::size_t j = 0; j < num_of_simd_dlap; j++) {
      //   constant_unsigned_integer_t_dlap_vector[i * num_of_simd_dlap + j] =
      //       constant_unsigned_integer_t_vector[i];
      constant_unsigned_integer_denominator_dlap_vector[i * num_of_simd_dlap + j] =
          constant_unsigned_integer_t_vector[i];
      constant_unsigned_integer_numerator_dlap_vector[i * num_of_simd_dlap + j] = UintType(1);
    }
  }

  std::vector<ShareWrapper> gc_share_discrete_laplace_sample_vector =
      FLDiscreteLaplaceDistribution_GC<FloatType, UintType, IntType, A>(
          constant_unsigned_integer_numerator_dlap_vector,
          constant_unsigned_integer_denominator_dlap_vector,
          random_floating_point_0_1_gc_share_dlap, random_unsigned_integer_gc_share_dlap,
          gc_share_bernoulli_sample_dlap, iteration_1, iteration_2, iteration_3);

  // std::cout << "222" << std::endl;
  std::vector<FloatType> constant_floating_point_sigma_square_div_t_vector(num_of_simd_dgau);
  std::vector<FloatType> constant_floating_point_two_mul_sigma_square_vector(num_of_simd_dgau);
  for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
    constant_floating_point_sigma_square_div_t_vector[i] =
        constant_floating_point_sigma_vector[i] * constant_floating_point_sigma_vector[i] /
        FloatType(constant_unsigned_integer_t_vector[i]);
    constant_floating_point_two_mul_sigma_square_vector[i] =
        2.0 * constant_floating_point_sigma_vector[i] * constant_floating_point_sigma_vector[i];
  }

  // std::cout << "333" << std::endl;
  SecureFloatingPointCircuitABY constant_floating_point_sigma_square_div_t =
      SecureFloatingPointCircuitABY((share_->Get())
                                        ->GetBackend()
                                        .ConstantAsGCInput(ToInput<FloatType, std::true_type>(
                                            constant_floating_point_sigma_square_div_t_vector)));

  SecureFloatingPointCircuitABY constant_floating_point_two_mul_sigma_square =
      SecureFloatingPointCircuitABY((share_->Get())
                                        ->GetBackend()
                                        .ConstantAsGCInput(ToInput<FloatType, std::true_type>(
                                            constant_floating_point_two_mul_sigma_square_vector)));

  // std::cout << "444" << std::endl;
  ShareWrapper gc_share_Y = gc_share_discrete_laplace_sample_vector[0];
  SecureFloatingPointCircuitABY floating_point_C_bernoulli_parameter =
      (((SecureSignedInteger(gc_share_Y).Int2FL(FLType_size).Abs() -
         SecureFloatingPointCircuitABY(ShareWrapper::Simdify(ShareWrapper::SimdifyDuplicateVertical(
             constant_floating_point_sigma_square_div_t.Get().Unsimdify(), iteration_4))))
            .Sqr()) /
       (SecureFloatingPointCircuitABY(ShareWrapper::Simdify(ShareWrapper::SimdifyDuplicateVertical(
           constant_floating_point_two_mul_sigma_square.Get().Unsimdify(), iteration_4)))))
          .Neg()
          .Exp();

  // std::cout << "555" << std::endl;
  ShareWrapper gc_share_bernoulli =
      SecureFloatingPointCircuitABY(random_floating_point_0_1_gc_share_dgau) <
      floating_point_C_bernoulli_parameter;

  ShareWrapper gc_share_choice = gc_share_bernoulli & gc_share_discrete_laplace_sample_vector[1];

  std::vector<ShareWrapper> gc_share_Y_reshape =
      ShareWrapper::SimdifyReshapeHorizontal(gc_share_Y.Unsimdify(), iteration_4, num_of_simd_dgau);
  std::vector<ShareWrapper> gc_share_choice_reshape = ShareWrapper::SimdifyReshapeHorizontal(
      gc_share_choice.Unsimdify(), iteration_4, num_of_simd_dgau);

  // std::cout << "666" << std::endl;
  std::vector<ShareWrapper> gc_share_result_vector =
      share_->InvertBinaryTreeSelection(gc_share_Y_reshape, gc_share_choice_reshape);

  //   // only for debug
  gc_share_result_vector.emplace_back(gc_share_discrete_laplace_sample_vector[0]);  // 2
  gc_share_result_vector.emplace_back(gc_share_discrete_laplace_sample_vector[1]);  //
                                                                                    // 3
  gc_share_result_vector.emplace_back(gc_share_bernoulli);                          //
  // 4
  gc_share_result_vector.emplace_back(gc_share_choice);                             // 5
  gc_share_result_vector.emplace_back(floating_point_C_bernoulli_parameter.Get());  //
  // 6
  gc_share_result_vector.emplace_back(SecureSignedInteger(gc_share_Y).Get());  // 7
  gc_share_result_vector.emplace_back(
      SecureFloatingPointCircuitABY(
          ShareWrapper::Simdify(ShareWrapper::SimdifyDuplicateVertical(
              constant_floating_point_sigma_square_div_t.Get().Unsimdify(), iteration_4)))
          .Get());  // 8

  return gc_share_result_vector;
}

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLDiscreteGaussianDistribution_GC<
    float, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<double>& constant_floating_point_sigma_vector,
    const ShareWrapper& random_floating_point_0_1_gc_share_dlap,
    const ShareWrapper& random_unsigned_integer_gc_share_dlap,
    const ShareWrapper& gc_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_gc_share_dgau, std::size_t iteration_1,
    std::size_t iteration_2, std::size_t iteration_3, std::size_t iteration_4) const;

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLDiscreteGaussianDistribution_GC<
    double, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<double>& constant_floating_point_sigma_vector,
    const ShareWrapper& random_floating_point_0_1_gc_share_dlap,
    const ShareWrapper& random_unsigned_integer_gc_share_dlap,
    const ShareWrapper& gc_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_gc_share_dgau, std::size_t iteration_1,
    std::size_t iteration_2, std::size_t iteration_3, std::size_t iteration_4) const;

template <typename FloatType, typename UintType, typename IntType, typename A>
std::vector<ShareWrapper> SecureSamplingAlgorithm_optimized::FLDiscreteGaussianDistribution_GC(
    const std::vector<double>& constant_floating_point_sigma_vector,
    const ShareWrapper& random_floating_point_0_1_gc_share_dlap,
    const ShareWrapper& gc_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_gc_share_dgau, std::size_t iteration_2,
    std::size_t iteration_3, std::size_t iteration_4) const {
  //   using UintType = std::uint64_t;

  std::size_t FLType_size = sizeof(FloatType) * 8;

  std::size_t num_of_simd_dgau = constant_floating_point_sigma_vector.size();
  std::size_t num_of_simd_geo = iteration_3;
  std::size_t num_of_simd_dlap = iteration_4;
  std::size_t num_of_simd_total = num_of_simd_dlap * num_of_simd_geo * num_of_simd_dgau;

  assert(random_floating_point_0_1_gc_share_dlap->GetNumberOfSimdValues() ==
         (iteration_2)*num_of_simd_total);

  assert(gc_share_bernoulli_sample_dlap->GetNumberOfSimdValues() == num_of_simd_total);
  assert(random_floating_point_0_1_gc_share_dgau->GetNumberOfSimdValues() ==
         iteration_4 * num_of_simd_dgau);

  //   std::cout << "000" << std::endl;

  std::vector<UintType> constant_unsigned_integer_t_vector(num_of_simd_dgau);
  for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
    constant_unsigned_integer_t_vector[i] = floor(constant_floating_point_sigma_vector[i]) + 1;
  }

  // t = 1
  assert(VectorAllEqualToValue<UintType>(constant_unsigned_integer_t_vector, UintType(1)));

  //   std::vector<UintType> constant_unsigned_integer_t_dlap_vector(num_of_simd_dgau *
  //   num_of_simd_dlap);
  std::vector<UintType> constant_unsigned_integer_numerator_dlap_vector(num_of_simd_dgau *
                                                                        num_of_simd_dlap);

  //   std::cout << "111" << std::endl;
  for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
    for (std::size_t j = 0; j < num_of_simd_dlap; j++) {
      //   constant_unsigned_integer_t_dlap_vector[i * num_of_simd_dlap + j] =
      //       constant_unsigned_integer_t_vector[i];
      constant_unsigned_integer_numerator_dlap_vector[i * num_of_simd_dlap + j] = UintType(1);
    }
  }

  std::vector<ShareWrapper> gc_share_discrete_laplace_sample_vector =
      FLDiscreteLaplaceDistribution_GC<FloatType, UintType, IntType, A>(
          constant_unsigned_integer_numerator_dlap_vector, random_floating_point_0_1_gc_share_dlap,
          gc_share_bernoulli_sample_dlap, iteration_2, iteration_3);

  //   std::cout << "222" << std::endl;
  std::vector<FloatType> constant_floating_point_sigma_square_div_t_vector(num_of_simd_dgau);
  std::vector<FloatType> constant_floating_point_two_mul_sigma_square_vector(num_of_simd_dgau);
  for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
    constant_floating_point_sigma_square_div_t_vector[i] =
        constant_floating_point_sigma_vector[i] * constant_floating_point_sigma_vector[i];
    constant_floating_point_two_mul_sigma_square_vector[i] =
        2.0 * constant_floating_point_sigma_vector[i] * constant_floating_point_sigma_vector[i];
  }

  //   std::cout << "333" << std::endl;
  SecureFloatingPointCircuitABY constant_floating_point_sigma_square_div_t =
      SecureFloatingPointCircuitABY((share_->Get())
                                        ->GetBackend()
                                        .ConstantAsGCInput(ToInput<FloatType, std::true_type>(
                                            constant_floating_point_sigma_square_div_t_vector)));

  SecureFloatingPointCircuitABY constant_floating_point_two_mul_sigma_square =
      SecureFloatingPointCircuitABY((share_->Get())
                                        ->GetBackend()
                                        .ConstantAsGCInput(ToInput<FloatType, std::true_type>(
                                            constant_floating_point_two_mul_sigma_square_vector)));

  //   std::cout << "444" << std::endl;
  ShareWrapper gc_share_Y = gc_share_discrete_laplace_sample_vector[0];
  SecureFloatingPointCircuitABY floating_point_C_bernoulli_parameter =
      (((SecureSignedInteger(gc_share_Y).Int2FL(FLType_size).Abs() -
         SecureFloatingPointCircuitABY(ShareWrapper::Simdify(ShareWrapper::SimdifyDuplicateVertical(
             constant_floating_point_sigma_square_div_t.Get().Unsimdify(), iteration_4))))
            .Sqr()) /
       (SecureFloatingPointCircuitABY(ShareWrapper::Simdify(ShareWrapper::SimdifyDuplicateVertical(
           constant_floating_point_two_mul_sigma_square.Get().Unsimdify(), iteration_4)))))
          .Neg()
          .Exp();

  //   std::cout << "555" << std::endl;
  ShareWrapper gc_share_bernoulli =
      SecureFloatingPointCircuitABY(random_floating_point_0_1_gc_share_dgau) <
      floating_point_C_bernoulli_parameter;

  ShareWrapper gc_share_choice = gc_share_bernoulli & gc_share_discrete_laplace_sample_vector[1];

  std::vector<ShareWrapper> gc_share_Y_reshape =
      ShareWrapper::SimdifyReshapeHorizontal(gc_share_Y.Unsimdify(), iteration_4, num_of_simd_dgau);
  std::vector<ShareWrapper> gc_share_choice_reshape = ShareWrapper::SimdifyReshapeHorizontal(
      gc_share_choice.Unsimdify(), iteration_4, num_of_simd_dgau);

  //   std::cout << "666" << std::endl;
  std::vector<ShareWrapper> gc_share_result_vector =
      share_->InvertBinaryTreeSelection(gc_share_Y_reshape, gc_share_choice_reshape);

  //   // only for debug
  gc_share_result_vector.emplace_back(gc_share_discrete_laplace_sample_vector[0]);  // 2
  gc_share_result_vector.emplace_back(gc_share_discrete_laplace_sample_vector[1]);  //
                                                                                    // 3
  gc_share_result_vector.emplace_back(gc_share_bernoulli);                          //
                                                                                    // 4
  gc_share_result_vector.emplace_back(gc_share_choice);                             // 5
  gc_share_result_vector.emplace_back(floating_point_C_bernoulli_parameter.Get());  //
                                                                                    // 6
  gc_share_result_vector.emplace_back(SecureSignedInteger(gc_share_Y).Get());       // 7
  gc_share_result_vector.emplace_back(
      SecureFloatingPointCircuitABY(
          ShareWrapper::Simdify(ShareWrapper::SimdifyDuplicateVertical(
              constant_floating_point_sigma_square_div_t.Get().Unsimdify(), iteration_4)))
          .Get());  // 8

  return gc_share_result_vector;
}

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLDiscreteGaussianDistribution_GC<
    float, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<double>& constant_floating_point_sigma_vector,
    const ShareWrapper& random_floating_point_0_1_gc_share_dlap,
    const ShareWrapper& gc_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_gc_share_dgau, std::size_t iteration_2,
    std::size_t iteration_3, std::size_t iteration_4) const;

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLDiscreteGaussianDistribution_GC<
    double, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<double>& constant_floating_point_sigma_vector,
    const ShareWrapper& random_floating_point_0_1_gc_share_dlap,
    const ShareWrapper& gc_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_gc_share_dgau, std::size_t iteration_2,
    std::size_t iteration_3, std::size_t iteration_4) const;

// TODO: after benchmarking, use more floating-point
template <typename FloatType, typename UintType>
std::vector<ShareWrapper> SecureSamplingAlgorithm_optimized::FLSymmetricBinomialDistribution_GC(
    std::vector<double> constant_sqrt_n_vector,
    const ShareWrapper& unsigned_integer_gc_share_geometric_sample,
    const ShareWrapper& gc_share_random_bits, const ShareWrapper& random_unsigned_integer_gc_share,
    const ShareWrapper& random_floating_point_0_1_gc_share, std::size_t iteration) const {
  std::size_t num_of_simd = constant_sqrt_n_vector.size();
  //   using UintType = std::uint64_t;
  std::size_t FLType_size = sizeof(FloatType) * 8;

  assert(unsigned_integer_gc_share_geometric_sample->GetNumberOfSimdValues() ==
         iteration * num_of_simd);
  assert(gc_share_random_bits->GetNumberOfSimdValues() == iteration * num_of_simd);
  assert(random_unsigned_integer_gc_share->GetNumberOfSimdValues() == iteration * num_of_simd);
  assert(random_floating_point_0_1_gc_share->GetNumberOfSimdValues() == iteration * num_of_simd);

  std::vector<UintType> constant_m_vector(num_of_simd * iteration);
  std::vector<FloatType> constant_m_div_4_vector(num_of_simd * iteration);
  std::vector<UintType> constant_neg_sqrt_n_mul_lnn_div_2_vector(num_of_simd * iteration);
  std::vector<UintType> constant_sqrt_n_mul_sqrt_lnn_div_2_vector(num_of_simd * iteration);
  std::vector<FloatType> constant_p_coefficient_1_vector(num_of_simd * iteration);
  std::vector<FloatType> constant_p_coefficient_2_vector(num_of_simd * iteration);
  for (std::size_t i = 0; i < num_of_simd; i++) {
    for (std::size_t j = 0; j < iteration; j++) {
      constant_m_vector[i * iteration + j] =
          UintType(floor(M_SQRT2 * constant_sqrt_n_vector[i] + 1.0));

      constant_m_div_4_vector[i * iteration + j] =
          FloatType(constant_m_vector[i * iteration + j]) / 4.0;

      constant_sqrt_n_mul_sqrt_lnn_div_2_vector[i * iteration + j] =
          UintType(floor(constant_sqrt_n_vector[i] * sqrt(log(constant_sqrt_n_vector[i]) / 2.0)));

      constant_neg_sqrt_n_mul_lnn_div_2_vector[i * iteration + j] =
          -constant_sqrt_n_mul_sqrt_lnn_div_2_vector[i * iteration + j];

      constant_p_coefficient_1_vector[i * iteration + j] =
          sqrt(2.0 / M_PI) / constant_sqrt_n_vector[i] *
          (1.0 - 0.4 * pow(log(constant_sqrt_n_vector[i]) * 2, 1.5) / constant_sqrt_n_vector[i]);

      constant_p_coefficient_2_vector[i * iteration + j] = M_SQRT2 / constant_sqrt_n_vector[i];
    }
  }

  // std::cout << "000"<< std::endl;
  ShareWrapper signed_integer_gc_share_s = unsigned_integer_gc_share_geometric_sample;

  SecureSignedInteger signed_integer_s = SecureSignedInteger(signed_integer_gc_share_s);
  SecureSignedInteger signed_integer_neg_s_minus_one = signed_integer_s.Neg() - UintType(1);

  ShareWrapper signed_integer_gc_share_k =
      gc_share_random_bits.Mux(signed_integer_gc_share_s, signed_integer_neg_s_minus_one.Get());

  ShareWrapper signed_integer_constant_gc_share_m =
      (share_->Get())->GetBackend().ConstantAsGCInput(ToInput<UintType>(constant_m_vector));
  ShareWrapper floating_point_constant_gc_share_m_div_4 =
      (share_->Get())
          ->GetBackend()
          .ConstantAsGCInput(ToInput<FloatType, std::true_type>(constant_m_div_4_vector));

  // std::cout << "111"<< std::endl;
  SecureSignedInteger signed_integer_i =
      SecureSignedInteger(signed_integer_gc_share_k) *
          SecureSignedInteger(signed_integer_constant_gc_share_m) +
      SecureSignedInteger(random_unsigned_integer_gc_share);

  ShareWrapper constant_gc_share_neg_sqrt_n_mul_lnn_div_2 =
      (share_->Get())
          ->GetBackend()
          .ConstantAsGCInput(ToInput<UintType>(constant_neg_sqrt_n_mul_lnn_div_2_vector));
  ShareWrapper constant_gc_share_sqrt_n_mul_lnn_div_2 =
      (share_->Get())
          ->GetBackend()
          .ConstantAsGCInput(ToInput<UintType>(constant_sqrt_n_mul_sqrt_lnn_div_2_vector));

  ShareWrapper constant_gc_share_p_coefficient_1 =
      (share_->Get())
          ->GetBackend()
          .ConstantAsGCInput(ToInput<FloatType, std::true_type>(constant_p_coefficient_1_vector));
  ShareWrapper constant_gc_share_p_coefficient_2 =
      (share_->Get())
          ->GetBackend()
          .ConstantAsGCInput(ToInput<FloatType, std::true_type>(constant_p_coefficient_2_vector));

  // std::cout << "222"<< std::endl;

  //   ShareWrapper gc_share_i_in_range_condition =
  //       (signed_integer_i.GEQ(
  //           SecureSignedInteger(constant_gc_share_neg_sqrt_n_mul_lnn_div_2))) &
  //
  (signed_integer_i.LE(SecureSignedInteger(constant_gc_share_sqrt_n_mul_lnn_div_2)));
  ShareWrapper gc_share_i_in_range_condition =
      signed_integer_i.InRange(SecureSignedInteger(constant_gc_share_sqrt_n_mul_lnn_div_2));

  SecureFloatingPointCircuitABY floating_point_p_i =
      SecureFloatingPointCircuitABY(constant_gc_share_p_coefficient_1) *
      ((((SecureFloatingPointCircuitABY(constant_gc_share_p_coefficient_2) *
          signed_integer_i.Int2FL(FLType_size))
             .Sqr())
            .Neg())
           .Exp());

  //   // only for debug
  //   SecureFloatingPointCircuitABY floating_point_exp_i =
  //       ((((SecureFloatingPointCircuitABY(constant_gc_share_p_coefficient_2) *
  //           signed_integer_i.Int2FL())
  //              .Sqr())
  //             .Neg())
  //            .Exp());

  // this step can be saved by computing gc_share_i_in_range_condition
  //   ShareWrapper floating_point_p_i_greater_than_zero = floating_point_p_i > double(0);

  SecureFloatingPointCircuitABY floating_point_pow2_s =
      (signed_integer_s.Int2FL(FLType_size)).Exp2();

  SecureFloatingPointCircuitABY floating_point_p_i_mul_f =
      floating_point_p_i * floating_point_pow2_s *
      SecureFloatingPointCircuitABY(floating_point_constant_gc_share_m_div_4);

  ShareWrapper gc_share_Bernoulli_c =
      SecureFloatingPointCircuitABY(random_floating_point_0_1_gc_share) < floating_point_p_i_mul_f;

  //   ShareWrapper gc_share_Bernoulli_c_invert = ~gc_share_Bernoulli_c;

  //   ShareWrapper gc_share_choice = gc_share_i_in_range_condition &
  //                                           floating_point_p_i_greater_than_zero &
  //                                           gc_share_Bernoulli_c_invert;
  //   ShareWrapper gc_share_choice =
  //       gc_share_i_in_range_condition & gc_share_Bernoulli_c_invert;
  ShareWrapper gc_share_choice = gc_share_i_in_range_condition & gc_share_Bernoulli_c;

  // std::cout << "444"<< std::endl;
  std::vector<ShareWrapper> signed_integer_i_reshape_vector =
      ShareWrapper::SimdifyReshapeHorizontal(signed_integer_i.Get().Unsimdify(), iteration,
                                             num_of_simd);
  std::vector<ShareWrapper> gc_share_choice_reshape_vector =
      ShareWrapper::SimdifyReshapeHorizontal(gc_share_choice.Unsimdify(), iteration, num_of_simd);

  std::vector<ShareWrapper> gc_share_result_vector = share_->InvertBinaryTreeSelection(
      signed_integer_i_reshape_vector, gc_share_choice_reshape_vector);

  // only for debug
  gc_share_result_vector.emplace_back(floating_point_p_i.Get());  // 2
  gc_share_result_vector.emplace_back(signed_integer_i.Get());    // 3
  gc_share_result_vector.emplace_back((signed_integer_i.Int2FL(FLType_size).Get()));
  // 4
  gc_share_result_vector.emplace_back((gc_share_i_in_range_condition.Get()));       // 5
  gc_share_result_vector.emplace_back((floating_point_pow2_s.Get()));               // 6
  gc_share_result_vector.emplace_back((floating_point_p_i_mul_f.Get()));            // 7
  gc_share_result_vector.emplace_back((gc_share_choice.Get()));                     // 8
  gc_share_result_vector.emplace_back((gc_share_Bernoulli_c.Get()));                // 9
  gc_share_result_vector.emplace_back((random_floating_point_0_1_gc_share.Get()));  // 10
  gc_share_result_vector.emplace_back((signed_integer_s.Int2FL(FLType_size).Get()));
  // 11

  return gc_share_result_vector;
}

// constant_sqrt_n * sqrt(2) < 2^(64)
template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLSymmetricBinomialDistribution_GC<double, std::uint64_t>(
    std::vector<double> constant_sqrt_n_vector,
    const ShareWrapper& unsigned_integer_gc_share_geometric_sample,
    const ShareWrapper& gc_share_random_bits, const ShareWrapper& random_unsigned_integer_gc_share,
    const ShareWrapper& random_floating_point_0_1_gc_share, std::size_t iteration) const;

// constant_sqrt_n * sqrt(2) < 2^(128)
template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLSymmetricBinomialDistribution_GC<double, __uint128_t>(
    std::vector<double> constant_sqrt_n_vector,
    const ShareWrapper& unsigned_integer_gc_share_geometric_sample,
    const ShareWrapper& gc_share_random_bits, const ShareWrapper& random_unsigned_integer_gc_share,
    const ShareWrapper& random_floating_point_0_1_gc_share, std::size_t iteration) const;

// ========================================================================================================================================
// ! optimized floating-point version in BMR

template <typename FloatType, typename UintType, typename IntType, typename A>
std::vector<ShareWrapper> SecureSamplingAlgorithm_optimized::FLGeometricDistributionEXP_BMR(
    const std::vector<UintType>& constant_unsigned_integer_numerator_vector,
    const std::vector<UintType>& constant_unsigned_integer_denominator_vector,
    const ShareWrapper& random_floating_point_0_1_bmr_share,
    const ShareWrapper& random_unsigned_integer_bmr_share, std::size_t iteration_1,
    std::size_t iteration_2) const {
  std::size_t num_of_simd_geo = constant_unsigned_integer_numerator_vector.size();

  assert(constant_unsigned_integer_numerator_vector.size() ==
         constant_unsigned_integer_denominator_vector.size());
  assert(random_floating_point_0_1_bmr_share->GetNumberOfSimdValues() ==
         (iteration_1 + iteration_2) * num_of_simd_geo);
  assert(random_unsigned_integer_bmr_share->GetNumberOfSimdValues() ==
         iteration_1 * num_of_simd_geo);

  //   using UintType = std::uint64_t;
  //   using IntType = std::int64_t;

  std::size_t FLType_size = sizeof(FloatType) * 8;

  // if numerator or denominator are all ones, we can avoid some computations in MPC
  bool numerator_are_all_ones =
      VectorAllEqualToValue<UintType>(constant_unsigned_integer_numerator_vector, UintType(1));
  bool denominator_are_all_ones =
      VectorAllEqualToValue<UintType>(constant_unsigned_integer_denominator_vector, UintType(1));

  assert(!denominator_are_all_ones);

  // ! case 1: denominator are not all ones
  //   if (!denominator_are_all_ones) {
  //   std::cout << " if (!denominator_are_all_ones)" << std::endl;
  ShareWrapper unsigned_integer_bmr_share_denominator =
      ((share_->Get())
           ->GetBackend()
           .ConstantAsBmrInput(ToInput<UintType>(constant_unsigned_integer_denominator_vector)));

  // convert denominator to FloatType type in plaintext instead of converting in MPC
  std::vector<FloatType> constant_floating_point_denominator_vector(num_of_simd_geo);
  for (std::size_t i = 0; i < num_of_simd_geo; i++) {
    UintType denominator_tmp = constant_unsigned_integer_denominator_vector[i];
    constant_floating_point_denominator_vector[i] = FloatType(IntType(denominator_tmp));
  }

  // convert plaintext of denominator (in floating-point) to MPC constant shares
  ShareWrapper floating_point_bmr_share_denominator =
      ((share_->Get())
           ->GetBackend()
           .ConstantAsBmrInput(
               ToInput<FloatType, std::true_type>(constant_floating_point_denominator_vector)));

  // reshape the vector of denominator in preparation for the SIMD operations
  std::vector<ShareWrapper> floating_point_bmr_share_denominator_expand =
      ShareWrapper::SimdifyDuplicateVertical(floating_point_bmr_share_denominator.Unsimdify(),
                                             iteration_1);

  ShareWrapper floating_point_bmr_share_denominator_simdify =
      ShareWrapper::Simdify(floating_point_bmr_share_denominator_expand);

  // std::cout<<"001"<<std::endl;

  // convert the random unsigned integer to floating-point numbers
  SecureFloatingPointCircuitABY floating_point_random_unsigned_integer =
      SecureUnsignedInteger(random_unsigned_integer_bmr_share).Int2FL(FLType_size);

  // reshape the vector of random unsigned integer in preparation for the SIMD operations
  SecureFloatingPointCircuitABY floating_point_unsigned_integer_denominator_simdify =
      SecureFloatingPointCircuitABY(floating_point_bmr_share_denominator_simdify);

  // TODO: this division can be saved by compute e^(-1/t) alone
  SecureFloatingPointCircuitABY floating_point_random_unsigned_integer_div_denominator =
      floating_point_random_unsigned_integer / floating_point_unsigned_integer_denominator_simdify;

  SecureFloatingPointCircuitABY floating_point_exp_neg_random_unsigned_integer_div_denominator =
      floating_point_random_unsigned_integer_div_denominator.Neg().Exp();

  std::vector<FloatType> vector_of_exp_neg_one(num_of_simd_geo * iteration_2, std::exp(-1.0));
  SecureFloatingPointCircuitABY floating_point_constant_exp_neg_one = SecureFloatingPointCircuitABY(
      (share_->Get())
          ->GetBackend()
          .ConstantAsBmrInput(ToInput<FloatType, std::true_type>(vector_of_exp_neg_one)));

  // std::cout<<"002"<<std::endl;

  // TODO: use unsigned integer comparison instead
  // merge the floating-point comparison operation together
  ShareWrapper floating_point_Bernoulli_distribution_parameter_p = ShareWrapper::Simdify(
      std::vector{floating_point_exp_neg_random_unsigned_integer_div_denominator.Get(),
                  floating_point_constant_exp_neg_one.Get()});

  ShareWrapper bmr_share_Bernoulli_sample =
      SecureFloatingPointCircuitABY(random_floating_point_0_1_bmr_share) <
      SecureFloatingPointCircuitABY(floating_point_Bernoulli_distribution_parameter_p);

  // std::cout<<"003"<<std::endl;

  std::vector<ShareWrapper> bmr_share_Bernoulli_sample_unsimdify =
      bmr_share_Bernoulli_sample.Unsimdify();
  std::vector<ShareWrapper> bmr_share_Bernoulli_sample_part_1_vector(
      bmr_share_Bernoulli_sample_unsimdify.begin(),
      bmr_share_Bernoulli_sample_unsimdify.begin() + iteration_1 * num_of_simd_geo);

  std::vector<ShareWrapper> bmr_share_Bernoulli_sample_part_2_vector(
      bmr_share_Bernoulli_sample_unsimdify.begin() + iteration_1 * num_of_simd_geo,
      bmr_share_Bernoulli_sample_unsimdify.begin() + iteration_1 * num_of_simd_geo +
          iteration_2 * num_of_simd_geo);

  // std::cout<<"004"<<std::endl;

  std::vector<ShareWrapper> bmr_share_b1_vector = ShareWrapper::SimdifyReshapeHorizontal(
      bmr_share_Bernoulli_sample_part_1_vector, iteration_1, num_of_simd_geo);

  std::vector<ShareWrapper> bmr_share_b2_vector = ShareWrapper::SimdifyReshapeHorizontal(
      bmr_share_Bernoulli_sample_part_2_vector, iteration_2, num_of_simd_geo);

  // std::cout<<"005"<<std::endl;
  std::vector<ShareWrapper> random_unsigned_integer_bmr_share_unsimdify =
      random_unsigned_integer_bmr_share.Unsimdify();
  //   std::vector<ShareWrapper> random_unsigned_integer_bmr_share_for_b1_vector =
  //       ShareWrapper::SimdifyReshapeHorizontal(random_unsigned_integer_bmr_share.Unsimdify(),
  //                                              iteration_1, num_of_simd_geo);
  std::vector<ShareWrapper> random_unsigned_integer_bmr_share_for_b1_vector =
      ShareWrapper::SimdifyReshapeHorizontal(random_unsigned_integer_bmr_share_unsimdify,
                                             iteration_1, num_of_simd_geo);
  // std::cout<<"006"<<std::endl;
  std::vector<ShareWrapper> bmr_share_u = share_->InvertBinaryTreeSelection(
      random_unsigned_integer_bmr_share_for_b1_vector, bmr_share_b1_vector);
  // std::cout<<"007"<<std::endl;
  std::vector<ShareWrapper> bmr_share_constant_j;
  bmr_share_constant_j.reserve(iteration_2);
  for (std::size_t j = 0; j < iteration_2; j++) {
    std::vector<UintType> vector_of_constant_j(num_of_simd_geo, j);
    bmr_share_constant_j.emplace_back(
        (share_->Get())->GetBackend().ConstantAsBmrInput(ToInput<UintType>(vector_of_constant_j)));
  }

  std::vector<ShareWrapper> bmr_share_b2_invert_vector;
  bmr_share_b2_invert_vector.reserve(iteration_2);
  for (std::size_t i = 0; i < iteration_2; i++) {
    bmr_share_b2_invert_vector.emplace_back(~bmr_share_b2_vector[i]);
  }

  std::vector<ShareWrapper> bmr_share_v =
      share_->InvertBinaryTreeSelection(bmr_share_constant_j, bmr_share_b2_invert_vector);

  SecureUnsignedInteger unsigned_integer_w =
      SecureUnsignedInteger(bmr_share_v[0]) *
          SecureUnsignedInteger(unsigned_integer_bmr_share_denominator) +
      SecureUnsignedInteger(bmr_share_u[0]);
  // std::cout<<"008"<<std::endl;
  // case 1.1
  // numerator's vector elements are not all equal to one
  if (!numerator_are_all_ones) {
    ShareWrapper unsigned_integer_bmr_share_numerator =
        ((share_->Get())
             ->GetBackend()
             .ConstantAsBmrInput(ToInput<UintType>(constant_unsigned_integer_numerator_vector)));
    // std::cout<<"009"<<std::endl;
    // TODO: optimize integer division with floating-point division
    // TODO: using Garbled Circuit for division instead
    SecureUnsignedInteger unsigned_integer_geometric_sample =
        unsigned_integer_w / SecureUnsignedInteger(unsigned_integer_bmr_share_numerator);

    // std::cout<<"010"<<std::endl;
    ShareWrapper bmr_share_success_flag = (bmr_share_u[1] & bmr_share_v[1]);

    // std::cout<<"011"<<std::endl;
    std::vector<ShareWrapper> result_vector;
    result_vector.reserve(2);
    result_vector.emplace_back(unsigned_integer_geometric_sample.Get());
    result_vector.emplace_back(bmr_share_success_flag);

    // // only for debug
    result_vector.emplace_back(floating_point_bmr_share_denominator_simdify);  //
    // 2
    result_vector.emplace_back(floating_point_random_unsigned_integer.Get());               // 3
    result_vector.emplace_back(floating_point_unsigned_integer_denominator_simdify.Get());  //
    // 4
    result_vector.emplace_back(floating_point_random_unsigned_integer_div_denominator.Get());
    // 5
    result_vector.emplace_back(bmr_share_v[0]);  // 6
    result_vector.emplace_back(bmr_share_u[0]);  //
    // 7
    result_vector.emplace_back(unsigned_integer_w.Get());  // 8

    return result_vector;
  }

  // case 1.2
  // if the numerator's vector elements are all equal to one, we can save the division operation
  else {
    // save MPC computation here
    SecureUnsignedInteger unsigned_integer_geometric_sample = unsigned_integer_w;

    ShareWrapper bmr_share_success_flag = (bmr_share_u[1] & bmr_share_v[1]);

    std::vector<ShareWrapper> result_vector;
    result_vector.reserve(2);
    result_vector.emplace_back(unsigned_integer_geometric_sample.Get());
    result_vector.emplace_back(bmr_share_success_flag);

    // // only for debug
    result_vector.emplace_back(floating_point_bmr_share_denominator_simdify);  //
    // 2
    result_vector.emplace_back(floating_point_random_unsigned_integer.Get());               // 3
    result_vector.emplace_back(floating_point_unsigned_integer_denominator_simdify.Get());  //
                                                                                            // 4
    result_vector.emplace_back(floating_point_random_unsigned_integer_div_denominator.Get());
    // 5
    result_vector.emplace_back(bmr_share_v[0]);  // 6
    result_vector.emplace_back(bmr_share_u[0]);  //
    // 7
    result_vector.emplace_back(unsigned_integer_w.Get());  // 8

    return result_vector;
  }
  //   }
}

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLGeometricDistributionEXP_BMR<
    float, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const std::vector<std::uint64_t>& constant_unsigned_integer_denominator_vector,
    const ShareWrapper& random_floating_point_0_1_bmr_share,
    const ShareWrapper& random_unsigned_integer_bmr_share, std::size_t iteration_1,
    std::size_t iteration_2) const;

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLGeometricDistributionEXP_BMR<
    double, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const std::vector<std::uint64_t>& constant_unsigned_integer_denominator_vector,
    const ShareWrapper& random_floating_point_0_1_bmr_share,
    const ShareWrapper& random_unsigned_integer_bmr_share, std::size_t iteration_1,
    std::size_t iteration_2) const;

template <typename FloatType, typename UintType, typename IntType, typename A>
std::vector<ShareWrapper> SecureSamplingAlgorithm_optimized::FLGeometricDistributionEXP_BMR(
    const std::vector<UintType>& constant_unsigned_integer_numerator_vector,
    const ShareWrapper& random_floating_point_0_1_bmr_share, std::size_t iteration_2) const {
  std::size_t num_of_simd_geo = constant_unsigned_integer_numerator_vector.size();

  assert(random_floating_point_0_1_bmr_share->GetNumberOfSimdValues() ==
         (iteration_2)*num_of_simd_geo);

  //   using UintType = std::uint64_t;
  //   using IntType = std::int64_t;

  // if numerator or denominator are all ones, we can avoid some computations in MPC
  bool numerator_are_all_ones =
      VectorAllEqualToValue<UintType>(constant_unsigned_integer_numerator_vector, UintType(1));
  bool denominator_are_all_ones = true;

  // ! case 2:
  // if the denominator vector's elements are all ones, we can skip the first for loop iterations
  //   if (denominator_are_all_ones) {
  std::vector<FloatType> vector_of_exp_neg_one(num_of_simd_geo * iteration_2, std::exp(-1.0));
  SecureFloatingPointCircuitABY floating_point_constant_exp_neg_one = SecureFloatingPointCircuitABY(
      (share_->Get())
          ->GetBackend()
          .ConstantAsBmrInput(ToInput<FloatType, std::true_type>(vector_of_exp_neg_one)));

  ShareWrapper floating_point_Bernoulli_distribution_parameter_p =
      floating_point_constant_exp_neg_one.Get();
  ShareWrapper bmr_share_Bernoulli_sample =
      SecureFloatingPointCircuitABY(random_floating_point_0_1_bmr_share) <
      SecureFloatingPointCircuitABY(floating_point_Bernoulli_distribution_parameter_p);

  std::vector<ShareWrapper> bmr_share_Bernoulli_sample_unsimdify =
      bmr_share_Bernoulli_sample.Unsimdify();

  std::vector<ShareWrapper> bmr_share_Bernoulli_sample_part_2_vector(
      bmr_share_Bernoulli_sample_unsimdify.begin(),
      bmr_share_Bernoulli_sample_unsimdify.begin() + iteration_2 * num_of_simd_geo);

  // std::cout << "bmr_share_Bernoulli_sample_part_2_vector.size(): "
  //           << bmr_share_Bernoulli_sample_part_2_vector.size() << std::endl;

  std::vector<ShareWrapper> bmr_share_b2_vector = ShareWrapper::SimdifyReshapeHorizontal(
      bmr_share_Bernoulli_sample_part_2_vector, iteration_2, num_of_simd_geo);

  //   std::cout << "333" << std::endl;
  std::vector<ShareWrapper> bmr_share_constant_j;
  bmr_share_constant_j.reserve(iteration_2);
  for (std::size_t j = 0; j < iteration_2; j++) {
    std::vector<UintType> vector_of_constant_j(num_of_simd_geo, j);
    bmr_share_constant_j.emplace_back(
        (share_->Get())->GetBackend().ConstantAsBmrInput(ToInput<UintType>(vector_of_constant_j)));
  }

  // invert bmr_share_b2_vector
  std::vector<ShareWrapper> bmr_share_b2_invert_vector;
  bmr_share_b2_invert_vector.reserve(iteration_2);
  for (std::size_t i = 0; i < iteration_2; i++) {
    bmr_share_b2_invert_vector.emplace_back(~bmr_share_b2_vector[i]);
  }

  std::vector<ShareWrapper> bmr_share_v =
      share_->InvertBinaryTreeSelection(bmr_share_constant_j, bmr_share_b2_invert_vector);

  SecureUnsignedInteger unsigned_integer_w = SecureUnsignedInteger(bmr_share_v[0]);

  // case 2.1
  // the numerator's vector elements are not all ones
  if (!numerator_are_all_ones) {
    ShareWrapper unsigned_integer_bmr_share_numerator =
        ((share_->Get())
             ->GetBackend()
             .ConstantAsBmrInput(ToInput<UintType>(constant_unsigned_integer_numerator_vector)));

    // TODO: optimize using floating-point division instead
    SecureUnsignedInteger unsigned_integer_geometric_sample =
        unsigned_integer_w / SecureUnsignedInteger(unsigned_integer_bmr_share_numerator);

    ShareWrapper bmr_share_success_flag = (bmr_share_v[1]);

    std::vector<ShareWrapper> result_vector;
    result_vector.reserve(2);
    result_vector.emplace_back(unsigned_integer_geometric_sample.Get());
    result_vector.emplace_back(bmr_share_success_flag);

    return result_vector;
  }

  // case 2.2
  // if the numerator's vector elements are all ones, we can avoid the division operation
  else {
    SecureUnsignedInteger unsigned_integer_geometric_sample = unsigned_integer_w;

    ShareWrapper bmr_share_success_flag = (bmr_share_v[1]);

    std::vector<ShareWrapper> result_vector;
    result_vector.reserve(2);
    result_vector.emplace_back(unsigned_integer_geometric_sample.Get());
    result_vector.emplace_back(bmr_share_success_flag);

    return result_vector;
  }
  //   }
}

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLGeometricDistributionEXP_BMR<
    float, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const ShareWrapper& random_floating_point_0_1_bmr_share, std::size_t iteration_2) const;

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLGeometricDistributionEXP_BMR<
    double, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const ShareWrapper& random_floating_point_0_1_bmr_share, std::size_t iteration_2) const;

template <typename FloatType, typename UintType, typename IntType, typename A>
std::vector<ShareWrapper> SecureSamplingAlgorithm_optimized::FLDiscreteLaplaceDistribution_BMR(
    const std::vector<UintType>& constant_unsigned_integer_numerator_vector,
    const std::vector<UintType>& constant_unsigned_integer_denominator_vector,
    const ShareWrapper& random_floating_point_0_1_bmr_share,
    const ShareWrapper& random_unsigned_integer_bmr_share,
    const ShareWrapper& bmr_share_bernoulli_sample, std::size_t iteration_1,
    std::size_t iteration_2, std::size_t iteration_3) const {
  //   using UintType = std::uint64_t;

  // same as FLGeometricDistributionEXP except with more iteration_3
  std::size_t num_of_simd_geo = iteration_3;
  std::size_t num_of_simd_dlap = constant_unsigned_integer_numerator_vector.size();
  std::size_t num_of_simd_total = num_of_simd_dlap * num_of_simd_geo;

  assert(constant_unsigned_integer_numerator_vector.size() ==
         constant_unsigned_integer_denominator_vector.size());
  assert(random_floating_point_0_1_bmr_share->GetNumberOfSimdValues() ==
         (iteration_1 + iteration_2) * num_of_simd_total);
  assert(random_unsigned_integer_bmr_share->GetNumberOfSimdValues() ==
         iteration_1 * num_of_simd_total);
  assert(bmr_share_bernoulli_sample->GetNumberOfSimdValues() == num_of_simd_total);

  //   std::vector<ShareWrapper> unsigned_integer_numerator_geo_vector =
  //       ShareWrapper::SimdifyDuplicateVertical(
  //           unsigned_integer_bmr_share_numerator.Unsimdify(), num_of_simd_geo);
  //   ShareWrapper unsigned_integer_numerator_geo =
  //       ShareWrapper::Simdify(unsigned_integer_numerator_geo_vector);

  //   std::vector<ShareWrapper> unsigned_integer_denominator_geo_vector =
  //       ShareWrapper::SimdifyDuplicateVertical(
  //           unsigned_integer_bmr_share_denominator.Unsimdify(), num_of_simd_geo);
  //   ShareWrapper unsigned_integer_denominator_geo =
  //       ShareWrapper::Simdify(unsigned_integer_denominator_geo_vector);

  //   std::vector<std::uint64_t> constant_unsigned_integer_numerator_geo_vector(num_of_simd_total);
  //   std::vector<std::uint64_t>
  //   constant_unsigned_integer_denominator_geo_vector(num_of_simd_total);
  std::vector<UintType> constant_unsigned_integer_numerator_geo_vector(num_of_simd_total);
  std::vector<UintType> constant_unsigned_integer_denominator_geo_vector(num_of_simd_total);

  for (std::size_t i = 0; i < num_of_simd_dlap; i++) {
    for (std::size_t j = 0; j < num_of_simd_geo; j++) {
      constant_unsigned_integer_numerator_geo_vector[i * num_of_simd_geo + j] =
          constant_unsigned_integer_numerator_vector[i];
      constant_unsigned_integer_denominator_geo_vector[i * num_of_simd_geo + j] =
          constant_unsigned_integer_denominator_vector[i];
    }
  }

  //   std::cout<<"000"<< std::endl;

  std::vector<ShareWrapper> geometric_sample_vector =
      FLGeometricDistributionEXP_BMR<FloatType, UintType, IntType, A>(
          constant_unsigned_integer_numerator_geo_vector,
          constant_unsigned_integer_denominator_geo_vector, random_floating_point_0_1_bmr_share,
          random_unsigned_integer_bmr_share, iteration_1, iteration_2);

  //   std::cout<<"111"<< std::endl;
  ShareWrapper bmr_share_sign = bmr_share_bernoulli_sample;
  ShareWrapper unsigned_integer_geometric_sample_bmr_share_magnitude = geometric_sample_vector[0];
  ShareWrapper bmr_share_magnitude_EQZ =
      SecureSignedInteger(unsigned_integer_geometric_sample_bmr_share_magnitude).IsZero();

  // magnitude*(1-2*sign)
  SecureSignedInteger signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign =
      SecureSignedInteger(unsigned_integer_geometric_sample_bmr_share_magnitude)
          .Neg(bmr_share_sign);

  ShareWrapper bmr_share_choice =
      ~(bmr_share_sign & bmr_share_magnitude_EQZ) & geometric_sample_vector[1];

  std::vector<ShareWrapper>
      signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign_reshape_vector =
          ShareWrapper::SimdifyReshapeHorizontal(
              signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign.Get().Unsimdify(),
              iteration_3, num_of_simd_dlap);

  std::vector<ShareWrapper> bmr_share_choice_reshape_vector =
      ShareWrapper::SimdifyReshapeHorizontal(bmr_share_choice.Unsimdify(), iteration_3,
                                             num_of_simd_dlap);

  std::vector<ShareWrapper> bmr_share_discrete_laplace_sample_vector =
      share_->InvertBinaryTreeSelection(
          signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign_reshape_vector,
          bmr_share_choice_reshape_vector);

  //   // only for debug
  //   bmr_share_discrete_laplace_sample_vector.emplace_back(bmr_share_sign);  //
  //   2 bmr_share_discrete_laplace_sample_vector.emplace_back(
  //       unsigned_integer_geometric_sample_bmr_share_magnitude);  // 3
  //   bmr_share_discrete_laplace_sample_vector.emplace_back(
  //       unsigned_integer_numerator_geo);  // 4
  //   bmr_share_discrete_laplace_sample_vector.emplace_back(
  //       unsigned_integer_denominator_geo);  // 5
  //   bmr_share_discrete_laplace_sample_vector.emplace_back(
  //       unsigned_integer_with_magnitude_mul_one_minus_two_mul_as_sign.Get()); //
  //       6
  //   bmr_share_discrete_laplace_sample_vector.emplace_back(bmr_share_choice);
  //
  //   7

  return bmr_share_discrete_laplace_sample_vector;
}

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLDiscreteLaplaceDistribution_BMR<
    float, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const std::vector<std::uint64_t>& constant_unsigned_integer_denominator_vector,
    const ShareWrapper& random_floating_point_0_1_bmr_share,
    const ShareWrapper& random_unsigned_integer_bmr_share,
    const ShareWrapper& bmr_share_bernoulli_sample, std::size_t iteration_1,
    std::size_t iteration_2, std::size_t iteration_3) const;

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLDiscreteLaplaceDistribution_BMR<
    double, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const std::vector<std::uint64_t>& constant_unsigned_integer_denominator_vector,
    const ShareWrapper& random_floating_point_0_1_bmr_share,
    const ShareWrapper& random_unsigned_integer_bmr_share,
    const ShareWrapper& bmr_share_bernoulli_sample, std::size_t iteration_1,
    std::size_t iteration_2, std::size_t iteration_3) const;

template <typename FloatType, typename UintType, typename IntType, typename A>
std::vector<ShareWrapper> SecureSamplingAlgorithm_optimized::FLDiscreteLaplaceDistribution_BMR(
    const std::vector<UintType>& constant_unsigned_integer_numerator_vector,
    const ShareWrapper& random_floating_point_0_1_bmr_share,
    const ShareWrapper& bmr_share_bernoulli_sample, std::size_t iteration_2,
    std::size_t iteration_3) const {
  //   using UintType = std::uint64_t;

  // same as FLGeometricDistributionEXP except with more iteration_3
  std::size_t num_of_simd_geo = iteration_3;
  std::size_t num_of_simd_dlap = constant_unsigned_integer_numerator_vector.size();
  std::size_t num_of_simd_total = num_of_simd_dlap * num_of_simd_geo;

  //   assert(constant_unsigned_integer_numerator_vector.size() ==
  //          constant_unsigned_integer_denominator_vector.size());
  assert(random_floating_point_0_1_bmr_share->GetNumberOfSimdValues() ==
         (iteration_2)*num_of_simd_total);
  assert(bmr_share_bernoulli_sample->GetNumberOfSimdValues() == num_of_simd_total);

  //   std::vector<ShareWrapper> unsigned_integer_numerator_geo_vector =
  //       ShareWrapper::SimdifyDuplicateVertical(
  //           unsigned_integer_bmr_share_numerator.Unsimdify(), num_of_simd_geo);
  //   ShareWrapper unsigned_integer_numerator_geo =
  //       ShareWrapper::Simdify(unsigned_integer_numerator_geo_vector);

  //   std::vector<ShareWrapper> unsigned_integer_denominator_geo_vector =
  //       ShareWrapper::SimdifyDuplicateVertical(
  //           unsigned_integer_bmr_share_denominator.Unsimdify(), num_of_simd_geo);
  //   ShareWrapper unsigned_integer_denominator_geo =
  //       ShareWrapper::Simdify(unsigned_integer_denominator_geo_vector);

  std::vector<UintType> constant_unsigned_integer_numerator_geo_vector(num_of_simd_total);
  for (std::size_t i = 0; i < num_of_simd_dlap; i++) {
    for (std::size_t j = 0; j < num_of_simd_geo; j++) {
      constant_unsigned_integer_numerator_geo_vector[i * num_of_simd_geo + j] =
          constant_unsigned_integer_numerator_vector[i];
    }
  }

  std::vector<ShareWrapper> geometric_sample_vector =
      FLGeometricDistributionEXP_BMR<FloatType, UintType, IntType, A>(
          constant_unsigned_integer_numerator_geo_vector, random_floating_point_0_1_bmr_share,
          iteration_2);

  ShareWrapper bmr_share_sign = bmr_share_bernoulli_sample;
  ShareWrapper unsigned_integer_geometric_sample_bmr_share_magnitude = geometric_sample_vector[0];
  ShareWrapper bmr_share_magnitude_EQZ =
      SecureSignedInteger(unsigned_integer_geometric_sample_bmr_share_magnitude).IsZero();

  // magnitude*(1-2*sign)
  SecureSignedInteger signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign =
      SecureSignedInteger(unsigned_integer_geometric_sample_bmr_share_magnitude)
          .Neg(bmr_share_sign);

  ShareWrapper bmr_share_choice =
      ~(bmr_share_sign & bmr_share_magnitude_EQZ) & geometric_sample_vector[1];

  std::vector<ShareWrapper>
      signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign_reshape_vector =
          ShareWrapper::SimdifyReshapeHorizontal(
              signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign.Get().Unsimdify(),
              iteration_3, num_of_simd_dlap);

  std::vector<ShareWrapper> bmr_share_choice_reshape_vector =
      ShareWrapper::SimdifyReshapeHorizontal(bmr_share_choice.Unsimdify(), iteration_3,
                                             num_of_simd_dlap);

  std::vector<ShareWrapper> bmr_share_discrete_laplace_sample_vector =
      share_->InvertBinaryTreeSelection(
          signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign_reshape_vector,
          bmr_share_choice_reshape_vector);

  //   // only for debug
  // bmr_share_discrete_laplace_sample_vector.emplace_back(bmr_share_sign);  //
  // // 2
  //  bmr_share_discrete_laplace_sample_vector.emplace_back(
  //     unsigned_integer_geometric_sample_bmr_share_magnitude);  // 3
  // bmr_share_discrete_laplace_sample_vector.emplace_back(
  //     unsigned_integer_numerator_geo);  // 4
  // bmr_share_discrete_laplace_sample_vector.emplace_back(
  //     unsigned_integer_denominator_geo);  // 5
  // bmr_share_discrete_laplace_sample_vector.emplace_back(
  //     unsigned_integer_with_magnitude_mul_one_minus_two_mul_as_sign.Get()); //
  //     // 6
  // bmr_share_discrete_laplace_sample_vector.emplace_back(bmr_share_choice); //
  // // 7

  return bmr_share_discrete_laplace_sample_vector;
}

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLDiscreteLaplaceDistribution_BMR<
    float, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const ShareWrapper& random_floating_point_0_1_bmr_share,
    const ShareWrapper& bmr_share_bernoulli_sample, std::size_t iteration_2,
    std::size_t iteration_3) const;

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLDiscreteLaplaceDistribution_BMR<
    double, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const ShareWrapper& random_floating_point_0_1_bmr_share,
    const ShareWrapper& bmr_share_bernoulli_sample, std::size_t iteration_2,
    std::size_t iteration_3) const;

template <typename FloatType, typename UintType, typename IntType, typename A>
std::vector<ShareWrapper> SecureSamplingAlgorithm_optimized::FLDiscreteGaussianDistribution_BMR(
    const std::vector<double>& constant_floating_point_sigma_vector,
    const ShareWrapper& random_floating_point_0_1_bmr_share_dlap,
    const ShareWrapper& random_unsigned_integer_bmr_share_dlap,
    const ShareWrapper& bmr_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_bmr_share_dgau, std::size_t iteration_1,
    std::size_t iteration_2, std::size_t iteration_3, std::size_t iteration_4) const {
  //   using UintType = std::uint64_t;

  std::size_t FLType_size = sizeof(FloatType) * 8;

  std::size_t num_of_simd_dgau = constant_floating_point_sigma_vector.size();
  std::size_t num_of_simd_geo = iteration_3;
  std::size_t num_of_simd_dlap = iteration_4;
  std::size_t num_of_simd_total = num_of_simd_dlap * num_of_simd_geo * num_of_simd_dgau;

  assert(random_floating_point_0_1_bmr_share_dlap->GetNumberOfSimdValues() ==
         (iteration_1 + iteration_2) * num_of_simd_total);
  assert(random_unsigned_integer_bmr_share_dlap->GetNumberOfSimdValues() ==
         iteration_1 * num_of_simd_total);

  assert(bmr_share_bernoulli_sample_dlap->GetNumberOfSimdValues() == num_of_simd_total);
  assert(random_floating_point_0_1_bmr_share_dgau->GetNumberOfSimdValues() ==
         iteration_4 * num_of_simd_dgau);

  // std::cout << "000" << std::endl;

  std::vector<UintType> constant_unsigned_integer_t_vector(num_of_simd_dgau);
  for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
    constant_unsigned_integer_t_vector[i] = floor(constant_floating_point_sigma_vector[i]) + 1;
  }

  //   std::vector<UintType> constant_unsigned_integer_t_dlap_vector(num_of_simd_dgau *
  //   num_of_simd_dlap);
  std::vector<UintType> constant_unsigned_integer_numerator_dlap_vector(num_of_simd_dgau *
                                                                        num_of_simd_dlap);
  std::vector<UintType> constant_unsigned_integer_denominator_dlap_vector(num_of_simd_dgau *
                                                                          num_of_simd_dlap);

  // std::cout << "111" << std::endl;
  for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
    for (std::size_t j = 0; j < num_of_simd_dlap; j++) {
      //   constant_unsigned_integer_t_dlap_vector[i * num_of_simd_dlap + j] =
      //       constant_unsigned_integer_t_vector[i];
      constant_unsigned_integer_denominator_dlap_vector[i * num_of_simd_dlap + j] =
          constant_unsigned_integer_t_vector[i];
      constant_unsigned_integer_numerator_dlap_vector[i * num_of_simd_dlap + j] = UintType(1);
    }
  }

  std::vector<ShareWrapper> bmr_share_discrete_laplace_sample_vector =
      FLDiscreteLaplaceDistribution_BMR<FloatType, UintType, IntType, A>(
          constant_unsigned_integer_numerator_dlap_vector,
          constant_unsigned_integer_denominator_dlap_vector,
          random_floating_point_0_1_bmr_share_dlap, random_unsigned_integer_bmr_share_dlap,
          bmr_share_bernoulli_sample_dlap, iteration_1, iteration_2, iteration_3);

  // std::cout << "222" << std::endl;
  std::vector<FloatType> constant_floating_point_sigma_square_div_t_vector(num_of_simd_dgau);
  std::vector<FloatType> constant_floating_point_two_mul_sigma_square_vector(num_of_simd_dgau);
  for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
    constant_floating_point_sigma_square_div_t_vector[i] =
        constant_floating_point_sigma_vector[i] * constant_floating_point_sigma_vector[i] /
        FloatType(constant_unsigned_integer_t_vector[i]);
    constant_floating_point_two_mul_sigma_square_vector[i] =
        2.0 * constant_floating_point_sigma_vector[i] * constant_floating_point_sigma_vector[i];
  }

  // std::cout << "333" << std::endl;
  SecureFloatingPointCircuitABY constant_floating_point_sigma_square_div_t =
      SecureFloatingPointCircuitABY((share_->Get())
                                        ->GetBackend()
                                        .ConstantAsBmrInput(ToInput<FloatType, std::true_type>(
                                            constant_floating_point_sigma_square_div_t_vector)));

  SecureFloatingPointCircuitABY constant_floating_point_two_mul_sigma_square =
      SecureFloatingPointCircuitABY((share_->Get())
                                        ->GetBackend()
                                        .ConstantAsBmrInput(ToInput<FloatType, std::true_type>(
                                            constant_floating_point_two_mul_sigma_square_vector)));

  // std::cout << "444" << std::endl;
  ShareWrapper bmr_share_Y = bmr_share_discrete_laplace_sample_vector[0];
  SecureFloatingPointCircuitABY floating_point_C_bernoulli_parameter =
      (((SecureSignedInteger(bmr_share_Y).Int2FL(FLType_size).Abs() -
         SecureFloatingPointCircuitABY(ShareWrapper::Simdify(ShareWrapper::SimdifyDuplicateVertical(
             constant_floating_point_sigma_square_div_t.Get().Unsimdify(), iteration_4))))
            .Sqr()) /
       (SecureFloatingPointCircuitABY(ShareWrapper::Simdify(ShareWrapper::SimdifyDuplicateVertical(
           constant_floating_point_two_mul_sigma_square.Get().Unsimdify(), iteration_4)))))
          .Neg()
          .Exp();

  // std::cout << "555" << std::endl;
  ShareWrapper bmr_share_bernoulli =
      SecureFloatingPointCircuitABY(random_floating_point_0_1_bmr_share_dgau) <
      floating_point_C_bernoulli_parameter;

  ShareWrapper bmr_share_choice = bmr_share_bernoulli & bmr_share_discrete_laplace_sample_vector[1];

  std::vector<ShareWrapper> bmr_share_Y_reshape = ShareWrapper::SimdifyReshapeHorizontal(
      bmr_share_Y.Unsimdify(), iteration_4, num_of_simd_dgau);
  std::vector<ShareWrapper> bmr_share_choice_reshape = ShareWrapper::SimdifyReshapeHorizontal(
      bmr_share_choice.Unsimdify(), iteration_4, num_of_simd_dgau);

  // std::cout << "666" << std::endl;
  std::vector<ShareWrapper> bmr_share_result_vector =
      share_->InvertBinaryTreeSelection(bmr_share_Y_reshape, bmr_share_choice_reshape);

  //   // only for debug
  bmr_share_result_vector.emplace_back(bmr_share_discrete_laplace_sample_vector[0]);  // 2
  bmr_share_result_vector.emplace_back(bmr_share_discrete_laplace_sample_vector[1]);  //
                                                                                      // 3
  bmr_share_result_vector.emplace_back(bmr_share_bernoulli);                          //
  // 4
  bmr_share_result_vector.emplace_back(bmr_share_choice);                            // 5
  bmr_share_result_vector.emplace_back(floating_point_C_bernoulli_parameter.Get());  //
  // 6
  bmr_share_result_vector.emplace_back(SecureSignedInteger(bmr_share_Y).Get());  // 7
  bmr_share_result_vector.emplace_back(
      SecureFloatingPointCircuitABY(
          ShareWrapper::Simdify(ShareWrapper::SimdifyDuplicateVertical(
              constant_floating_point_sigma_square_div_t.Get().Unsimdify(), iteration_4)))
          .Get());  // 8

  return bmr_share_result_vector;
}

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLDiscreteGaussianDistribution_BMR<
    float, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<double>& constant_floating_point_sigma_vector,
    const ShareWrapper& random_floating_point_0_1_bmr_share_dlap,
    const ShareWrapper& random_unsigned_integer_bmr_share_dlap,
    const ShareWrapper& bmr_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_bmr_share_dgau, std::size_t iteration_1,
    std::size_t iteration_2, std::size_t iteration_3, std::size_t iteration_4) const;

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLDiscreteGaussianDistribution_BMR<
    double, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<double>& constant_floating_point_sigma_vector,
    const ShareWrapper& random_floating_point_0_1_bmr_share_dlap,
    const ShareWrapper& random_unsigned_integer_bmr_share_dlap,
    const ShareWrapper& bmr_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_bmr_share_dgau, std::size_t iteration_1,
    std::size_t iteration_2, std::size_t iteration_3, std::size_t iteration_4) const;

template <typename FloatType, typename UintType, typename IntType, typename A>
std::vector<ShareWrapper> SecureSamplingAlgorithm_optimized::FLDiscreteGaussianDistribution_BMR(
    const std::vector<double>& constant_floating_point_sigma_vector,
    const ShareWrapper& random_floating_point_0_1_bmr_share_dlap,
    const ShareWrapper& bmr_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_bmr_share_dgau, std::size_t iteration_2,
    std::size_t iteration_3, std::size_t iteration_4) const {
  //   using UintType = std::uint64_t;

  std::size_t FLType_size = sizeof(FloatType) * 8;

  std::size_t num_of_simd_dgau = constant_floating_point_sigma_vector.size();
  std::size_t num_of_simd_geo = iteration_3;
  std::size_t num_of_simd_dlap = iteration_4;
  std::size_t num_of_simd_total = num_of_simd_dlap * num_of_simd_geo * num_of_simd_dgau;

  assert(random_floating_point_0_1_bmr_share_dlap->GetNumberOfSimdValues() ==
         (iteration_2)*num_of_simd_total);

  assert(bmr_share_bernoulli_sample_dlap->GetNumberOfSimdValues() == num_of_simd_total);
  assert(random_floating_point_0_1_bmr_share_dgau->GetNumberOfSimdValues() ==
         iteration_4 * num_of_simd_dgau);

  //   std::cout << "000" << std::endl;

  std::vector<UintType> constant_unsigned_integer_t_vector(num_of_simd_dgau);
  for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
    constant_unsigned_integer_t_vector[i] = floor(constant_floating_point_sigma_vector[i]) + 1;
  }

  // t = 1
  assert(VectorAllEqualToValue<UintType>(constant_unsigned_integer_t_vector, UintType(1)));

  //   std::vector<UintType> constant_unsigned_integer_t_dlap_vector(num_of_simd_dgau *
  //   num_of_simd_dlap);
  std::vector<UintType> constant_unsigned_integer_numerator_dlap_vector(num_of_simd_dgau *
                                                                        num_of_simd_dlap);

  //   std::cout << "111" << std::endl;
  for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
    for (std::size_t j = 0; j < num_of_simd_dlap; j++) {
      //   constant_unsigned_integer_t_dlap_vector[i * num_of_simd_dlap + j] =
      //       constant_unsigned_integer_t_vector[i];
      constant_unsigned_integer_numerator_dlap_vector[i * num_of_simd_dlap + j] = UintType(1);
    }
  }

  std::vector<ShareWrapper> bmr_share_discrete_laplace_sample_vector =
      FLDiscreteLaplaceDistribution_BMR<FloatType, UintType, IntType, A>(
          constant_unsigned_integer_numerator_dlap_vector, random_floating_point_0_1_bmr_share_dlap,
          bmr_share_bernoulli_sample_dlap, iteration_2, iteration_3);

  //   std::cout << "222" << std::endl;
  std::vector<FloatType> constant_floating_point_sigma_square_div_t_vector(num_of_simd_dgau);
  std::vector<FloatType> constant_floating_point_two_mul_sigma_square_vector(num_of_simd_dgau);
  for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
    constant_floating_point_sigma_square_div_t_vector[i] =
        constant_floating_point_sigma_vector[i] * constant_floating_point_sigma_vector[i];
    constant_floating_point_two_mul_sigma_square_vector[i] =
        2.0 * constant_floating_point_sigma_vector[i] * constant_floating_point_sigma_vector[i];
  }

  //   std::cout << "333" << std::endl;
  SecureFloatingPointCircuitABY constant_floating_point_sigma_square_div_t =
      SecureFloatingPointCircuitABY((share_->Get())
                                        ->GetBackend()
                                        .ConstantAsBmrInput(ToInput<FloatType, std::true_type>(
                                            constant_floating_point_sigma_square_div_t_vector)));

  SecureFloatingPointCircuitABY constant_floating_point_two_mul_sigma_square =
      SecureFloatingPointCircuitABY((share_->Get())
                                        ->GetBackend()
                                        .ConstantAsBmrInput(ToInput<FloatType, std::true_type>(
                                            constant_floating_point_two_mul_sigma_square_vector)));

  //   std::cout << "444" << std::endl;
  ShareWrapper bmr_share_Y = bmr_share_discrete_laplace_sample_vector[0];
  SecureFloatingPointCircuitABY floating_point_C_bernoulli_parameter =
      (((SecureSignedInteger(bmr_share_Y).Int2FL(FLType_size).Abs() -
         SecureFloatingPointCircuitABY(ShareWrapper::Simdify(ShareWrapper::SimdifyDuplicateVertical(
             constant_floating_point_sigma_square_div_t.Get().Unsimdify(), iteration_4))))
            .Sqr()) /
       (SecureFloatingPointCircuitABY(ShareWrapper::Simdify(ShareWrapper::SimdifyDuplicateVertical(
           constant_floating_point_two_mul_sigma_square.Get().Unsimdify(), iteration_4)))))
          .Neg()
          .Exp();

  //   std::cout << "555" << std::endl;
  ShareWrapper bmr_share_bernoulli =
      SecureFloatingPointCircuitABY(random_floating_point_0_1_bmr_share_dgau) <
      floating_point_C_bernoulli_parameter;

  ShareWrapper bmr_share_choice = bmr_share_bernoulli & bmr_share_discrete_laplace_sample_vector[1];

  std::vector<ShareWrapper> bmr_share_Y_reshape = ShareWrapper::SimdifyReshapeHorizontal(
      bmr_share_Y.Unsimdify(), iteration_4, num_of_simd_dgau);
  std::vector<ShareWrapper> bmr_share_choice_reshape = ShareWrapper::SimdifyReshapeHorizontal(
      bmr_share_choice.Unsimdify(), iteration_4, num_of_simd_dgau);

  //   std::cout << "666" << std::endl;
  std::vector<ShareWrapper> bmr_share_result_vector =
      share_->InvertBinaryTreeSelection(bmr_share_Y_reshape, bmr_share_choice_reshape);

  //   // only for debug
  bmr_share_result_vector.emplace_back(bmr_share_discrete_laplace_sample_vector[0]);  // 2
  bmr_share_result_vector.emplace_back(bmr_share_discrete_laplace_sample_vector[1]);  //
                                                                                      // 3
  bmr_share_result_vector.emplace_back(bmr_share_bernoulli);                          //
                                                                                      // 4
  bmr_share_result_vector.emplace_back(bmr_share_choice);                             // 5
  bmr_share_result_vector.emplace_back(floating_point_C_bernoulli_parameter.Get());   //
                                                                                      // 6
  bmr_share_result_vector.emplace_back(SecureSignedInteger(bmr_share_Y).Get());       // 7
  bmr_share_result_vector.emplace_back(
      SecureFloatingPointCircuitABY(
          ShareWrapper::Simdify(ShareWrapper::SimdifyDuplicateVertical(
              constant_floating_point_sigma_square_div_t.Get().Unsimdify(), iteration_4)))
          .Get());  // 8

  return bmr_share_result_vector;
}

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLDiscreteGaussianDistribution_BMR<
    float, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<double>& constant_floating_point_sigma_vector,
    const ShareWrapper& random_floating_point_0_1_bmr_share_dlap,
    const ShareWrapper& bmr_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_bmr_share_dgau, std::size_t iteration_2,
    std::size_t iteration_3, std::size_t iteration_4) const;

template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLDiscreteGaussianDistribution_BMR<
    double, std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
    const std::vector<double>& constant_floating_point_sigma_vector,
    const ShareWrapper& random_floating_point_0_1_bmr_share_dlap,
    const ShareWrapper& bmr_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_bmr_share_dgau, std::size_t iteration_2,
    std::size_t iteration_3, std::size_t iteration_4) const;

// TODO: after benchmarking, use more floating-point
template <typename FloatType, typename UintType>
std::vector<ShareWrapper> SecureSamplingAlgorithm_optimized::FLSymmetricBinomialDistribution_BMR(
    std::vector<double> constant_sqrt_n_vector,
    const ShareWrapper& unsigned_integer_bmr_share_geometric_sample,
    const ShareWrapper& bmr_share_random_bits,
    const ShareWrapper& random_unsigned_integer_bmr_share,
    const ShareWrapper& random_floating_point_0_1_bmr_share, std::size_t iteration) const {
  std::size_t num_of_simd = constant_sqrt_n_vector.size();
  //   using UintType = std::uint64_t;
  std::size_t FLType_size = sizeof(FloatType) * 8;

  assert(unsigned_integer_bmr_share_geometric_sample->GetNumberOfSimdValues() ==
         iteration * num_of_simd);
  assert(bmr_share_random_bits->GetNumberOfSimdValues() == iteration * num_of_simd);
  assert(random_unsigned_integer_bmr_share->GetNumberOfSimdValues() == iteration * num_of_simd);
  assert(random_floating_point_0_1_bmr_share->GetNumberOfSimdValues() == iteration * num_of_simd);

  std::vector<UintType> constant_m_vector(num_of_simd * iteration);
  std::vector<FloatType> constant_m_div_4_vector(num_of_simd * iteration);
  std::vector<UintType> constant_neg_sqrt_n_mul_lnn_div_2_vector(num_of_simd * iteration);
  std::vector<UintType> constant_sqrt_n_mul_sqrt_lnn_div_2_vector(num_of_simd * iteration);
  std::vector<FloatType> constant_p_coefficient_1_vector(num_of_simd * iteration);
  std::vector<FloatType> constant_p_coefficient_2_vector(num_of_simd * iteration);
  for (std::size_t i = 0; i < num_of_simd; i++) {
    for (std::size_t j = 0; j < iteration; j++) {
      constant_m_vector[i * iteration + j] =
          UintType(floor(M_SQRT2 * constant_sqrt_n_vector[i] + 1.0));

      constant_m_div_4_vector[i * iteration + j] =
          FloatType(constant_m_vector[i * iteration + j]) / 4.0;

      constant_sqrt_n_mul_sqrt_lnn_div_2_vector[i * iteration + j] =
          UintType(floor(constant_sqrt_n_vector[i] * sqrt(log(constant_sqrt_n_vector[i]) / 2.0)));

      constant_neg_sqrt_n_mul_lnn_div_2_vector[i * iteration + j] =
          -constant_sqrt_n_mul_sqrt_lnn_div_2_vector[i * iteration + j];

      constant_p_coefficient_1_vector[i * iteration + j] =
          sqrt(2.0 / M_PI) / constant_sqrt_n_vector[i] *
          (1.0 - 0.4 * pow(log(constant_sqrt_n_vector[i]) * 2, 1.5) / constant_sqrt_n_vector[i]);

      constant_p_coefficient_2_vector[i * iteration + j] = M_SQRT2 / constant_sqrt_n_vector[i];
    }
  }

  // std::cout << "000"<< std::endl;
  ShareWrapper signed_integer_bmr_share_s = unsigned_integer_bmr_share_geometric_sample;

  SecureSignedInteger signed_integer_s = SecureSignedInteger(signed_integer_bmr_share_s);
  SecureSignedInteger signed_integer_neg_s_minus_one = signed_integer_s.Neg() - UintType(1);

  ShareWrapper signed_integer_bmr_share_k =
      bmr_share_random_bits.Mux(signed_integer_bmr_share_s, signed_integer_neg_s_minus_one.Get());

  ShareWrapper signed_integer_constant_bmr_share_m =
      (share_->Get())->GetBackend().ConstantAsBmrInput(ToInput<UintType>(constant_m_vector));
  ShareWrapper floating_point_constant_bmr_share_m_div_4 =
      (share_->Get())
          ->GetBackend()
          .ConstantAsBmrInput(ToInput<FloatType, std::true_type>(constant_m_div_4_vector));

  // std::cout << "111"<< std::endl;
  SecureSignedInteger signed_integer_i =
      SecureSignedInteger(signed_integer_bmr_share_k) *
          SecureSignedInteger(signed_integer_constant_bmr_share_m) +
      SecureSignedInteger(random_unsigned_integer_bmr_share);

  ShareWrapper constant_bmr_share_neg_sqrt_n_mul_lnn_div_2 =
      (share_->Get())
          ->GetBackend()
          .ConstantAsBmrInput(ToInput<UintType>(constant_neg_sqrt_n_mul_lnn_div_2_vector));
  ShareWrapper constant_bmr_share_sqrt_n_mul_lnn_div_2 =
      (share_->Get())
          ->GetBackend()
          .ConstantAsBmrInput(ToInput<UintType>(constant_sqrt_n_mul_sqrt_lnn_div_2_vector));

  ShareWrapper constant_bmr_share_p_coefficient_1 =
      (share_->Get())
          ->GetBackend()
          .ConstantAsBmrInput(ToInput<FloatType, std::true_type>(constant_p_coefficient_1_vector));
  ShareWrapper constant_bmr_share_p_coefficient_2 =
      (share_->Get())
          ->GetBackend()
          .ConstantAsBmrInput(ToInput<FloatType, std::true_type>(constant_p_coefficient_2_vector));

  // std::cout << "222"<< std::endl;

  //   ShareWrapper bmr_share_i_in_range_condition =
  //       (signed_integer_i.GEQ(
  //           SecureSignedInteger(constant_bmr_share_neg_sqrt_n_mul_lnn_div_2))) &
  //
  (signed_integer_i.LE(SecureSignedInteger(constant_bmr_share_sqrt_n_mul_lnn_div_2)));
  ShareWrapper bmr_share_i_in_range_condition =
      signed_integer_i.InRange(SecureSignedInteger(constant_bmr_share_sqrt_n_mul_lnn_div_2));

  SecureFloatingPointCircuitABY floating_point_p_i =
      SecureFloatingPointCircuitABY(constant_bmr_share_p_coefficient_1) *
      ((((SecureFloatingPointCircuitABY(constant_bmr_share_p_coefficient_2) *
          signed_integer_i.Int2FL(FLType_size))
             .Sqr())
            .Neg())
           .Exp());

  //   // only for debug
  //   SecureFloatingPointCircuitABY floating_point_exp_i =
  //       ((((SecureFloatingPointCircuitABY(constant_bmr_share_p_coefficient_2) *
  //           signed_integer_i.Int2FL())
  //              .Sqr())
  //             .Neg())
  //            .Exp());

  // this step can be saved by computing bmr_share_i_in_range_condition
  //   ShareWrapper floating_point_p_i_greater_than_zero = floating_point_p_i > double(0);

  SecureFloatingPointCircuitABY floating_point_pow2_s =
      (signed_integer_s.Int2FL(FLType_size)).Exp2();

  SecureFloatingPointCircuitABY floating_point_p_i_mul_f =
      floating_point_p_i * floating_point_pow2_s *
      SecureFloatingPointCircuitABY(floating_point_constant_bmr_share_m_div_4);

  ShareWrapper bmr_share_Bernoulli_c =
      SecureFloatingPointCircuitABY(random_floating_point_0_1_bmr_share) < floating_point_p_i_mul_f;

  //   ShareWrapper bmr_share_Bernoulli_c_invert = ~bmr_share_Bernoulli_c;

  //   ShareWrapper bmr_share_choice = bmr_share_i_in_range_condition &
  //                                           floating_point_p_i_greater_than_zero &
  //                                           bmr_share_Bernoulli_c_invert;
  //   ShareWrapper bmr_share_choice =
  //       bmr_share_i_in_range_condition & bmr_share_Bernoulli_c_invert;
  ShareWrapper bmr_share_choice = bmr_share_i_in_range_condition & bmr_share_Bernoulli_c;

  // std::cout << "444"<< std::endl;
  std::vector<ShareWrapper> signed_integer_i_reshape_vector =
      ShareWrapper::SimdifyReshapeHorizontal(signed_integer_i.Get().Unsimdify(), iteration,
                                             num_of_simd);
  std::vector<ShareWrapper> bmr_share_choice_reshape_vector =
      ShareWrapper::SimdifyReshapeHorizontal(bmr_share_choice.Unsimdify(), iteration, num_of_simd);

  std::vector<ShareWrapper> bmr_share_result_vector = share_->InvertBinaryTreeSelection(
      signed_integer_i_reshape_vector, bmr_share_choice_reshape_vector);

  // only for debug
  bmr_share_result_vector.emplace_back(floating_point_p_i.Get());  // 2
  bmr_share_result_vector.emplace_back(signed_integer_i.Get());    // 3
  bmr_share_result_vector.emplace_back((signed_integer_i.Int2FL(FLType_size).Get()));
  // 4
  bmr_share_result_vector.emplace_back((bmr_share_i_in_range_condition.Get()));       // 5
  bmr_share_result_vector.emplace_back((floating_point_pow2_s.Get()));                // 6
  bmr_share_result_vector.emplace_back((floating_point_p_i_mul_f.Get()));             // 7
  bmr_share_result_vector.emplace_back((bmr_share_choice.Get()));                     // 8
  bmr_share_result_vector.emplace_back((bmr_share_Bernoulli_c.Get()));                // 9
  bmr_share_result_vector.emplace_back((random_floating_point_0_1_bmr_share.Get()));  // 10
  bmr_share_result_vector.emplace_back((signed_integer_s.Int2FL(FLType_size).Get()));
  // 11

  return bmr_share_result_vector;
}

// constant_sqrt_n * sqrt(2) < 2^(64)
template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLSymmetricBinomialDistribution_BMR<double, std::uint64_t>(
    std::vector<double> constant_sqrt_n_vector,
    const ShareWrapper& unsigned_integer_bmr_share_geometric_sample,
    const ShareWrapper& bmr_share_random_bits,
    const ShareWrapper& random_unsigned_integer_bmr_share,
    const ShareWrapper& random_floating_point_0_1_bmr_share, std::size_t iteration) const;

// constant_sqrt_n * sqrt(2) < 2^(128)
template std::vector<ShareWrapper>
SecureSamplingAlgorithm_optimized::FLSymmetricBinomialDistribution_BMR<double, __uint128_t>(
    std::vector<double> constant_sqrt_n_vector,
    const ShareWrapper& unsigned_integer_bmr_share_geometric_sample,
    const ShareWrapper& bmr_share_random_bits,
    const ShareWrapper& random_unsigned_integer_bmr_share,
    const ShareWrapper& random_floating_point_0_1_bmr_share, std::size_t iteration) const;

// ====================================================================

SecureFloatingPointCircuitABY SecureSamplingAlgorithm_optimized ::FL32LaplaceNoiseGeneration(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_gc_bmr_share_ry, double lambda_lap) {
  SecureFloatingPointCircuitABY floating_point_lambda_mul_ln_rx_div_ry =
      (SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx) /
       SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_gc_bmr_share_ry))
          .Ln() *
      float(lambda_lap);

  return floating_point_lambda_mul_ln_rx_div_ry;
}

SecureFloatingPointCircuitABY SecureSamplingAlgorithm_optimized ::FL64LaplaceNoiseGeneration(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_gc_bmr_share_ry, double lambda_lap) {
  SecureFloatingPointCircuitABY floating_point_lambda_mul_ln_rx_div_ry =
      (SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx) /
       SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_gc_bmr_share_ry))
          .Ln() *
      double(lambda_lap);

  return floating_point_lambda_mul_ln_rx_div_ry;
}

template <typename IntType>
SecureSignedInteger SecureSamplingAlgorithm_optimized::FL32DiscreteLaplaceNoiseGeneration(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_gc_bmr_share_ry, double alpha_dlap_) {
  // combine rx and ry in SIMD to parallel computation
  std::vector<ShareWrapper> random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx_ry_vector{
      random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx,
      random_floating_point_0_1_boolean_gmw_gc_bmr_share_ry};

  std::size_t num_of_simd_dlap =
      random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx->GetNumberOfSimdValues();

  SecureSignedInteger signed_integer_floor_alpha_mul_ln_rx_ry =
      ((SecureFloatingPointCircuitABY(
            ShareWrapper::Simdify(random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx_ry_vector))
            .Ln() *
        float(alpha_dlap_))
           .Floor())
          .FL2Int(sizeof(IntType) * 8);

  // split rx and ry from SIMD
  std::vector<ShareWrapper> signed_integer_floor_alpha_mul_ln_rx_ry_unsimdify =
      signed_integer_floor_alpha_mul_ln_rx_ry.Get().Unsimdify();

  std::vector<ShareWrapper> signed_integer_floor_alpha_mul_ln_rx_vector(
      signed_integer_floor_alpha_mul_ln_rx_ry_unsimdify.begin(),
      signed_integer_floor_alpha_mul_ln_rx_ry_unsimdify.begin() + num_of_simd_dlap);
  std::vector<ShareWrapper> signed_integer_floor_alpha_mul_ln_ry_vector(
      signed_integer_floor_alpha_mul_ln_rx_ry_unsimdify.begin() + num_of_simd_dlap,
      signed_integer_floor_alpha_mul_ln_rx_ry_unsimdify.begin() + 2 * num_of_simd_dlap);

  SecureSignedInteger signed_integer_discrete_laplace_sample =
      SecureSignedInteger(ShareWrapper::Simdify(signed_integer_floor_alpha_mul_ln_rx_vector)) -
      SecureSignedInteger(ShareWrapper::Simdify(signed_integer_floor_alpha_mul_ln_ry_vector));

  return signed_integer_discrete_laplace_sample;
}

template SecureSignedInteger
SecureSamplingAlgorithm_optimized::FL32DiscreteLaplaceNoiseGeneration<std::uint64_t>(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_gc_bmr_share_ry, double alpha_dlap_);

template <typename IntType>
SecureSignedInteger SecureSamplingAlgorithm_optimized::FL64DiscreteLaplaceNoiseGeneration(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_gc_bmr_share_ry, double alpha_dlap_) {
  // combine rx and ry in SIMD to parallel computation
  std::vector<ShareWrapper> random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx_ry_vector{
      random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx,
      random_floating_point_0_1_boolean_gmw_gc_bmr_share_ry};

  std::size_t num_of_simd_dlap =
      random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx->GetNumberOfSimdValues();

  SecureSignedInteger signed_integer_floor_alpha_mul_ln_rx_ry =
      ((SecureFloatingPointCircuitABY(
            ShareWrapper::Simdify(random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx_ry_vector))
            .Ln() *
        double(alpha_dlap_))
           .Floor())
          .FL2Int(sizeof(IntType) * 8);

  // split rx and ry from SIMD
  std::vector<ShareWrapper> signed_integer_floor_alpha_mul_ln_rx_ry_unsimdify =
      signed_integer_floor_alpha_mul_ln_rx_ry.Get().Unsimdify();

  std::vector<ShareWrapper> signed_integer_floor_alpha_mul_ln_rx_vector(
      signed_integer_floor_alpha_mul_ln_rx_ry_unsimdify.begin(),
      signed_integer_floor_alpha_mul_ln_rx_ry_unsimdify.begin() + num_of_simd_dlap);
  std::vector<ShareWrapper> signed_integer_floor_alpha_mul_ln_ry_vector(
      signed_integer_floor_alpha_mul_ln_rx_ry_unsimdify.begin() + num_of_simd_dlap,
      signed_integer_floor_alpha_mul_ln_rx_ry_unsimdify.begin() + 2 * num_of_simd_dlap);

  SecureSignedInteger signed_integer_discrete_laplace_sample =
      SecureSignedInteger(ShareWrapper::Simdify(signed_integer_floor_alpha_mul_ln_rx_vector)) -
      SecureSignedInteger(ShareWrapper::Simdify(signed_integer_floor_alpha_mul_ln_ry_vector));

  return signed_integer_discrete_laplace_sample;
}

template SecureSignedInteger
SecureSamplingAlgorithm_optimized::FL64DiscreteLaplaceNoiseGeneration<std::uint64_t>(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_gc_bmr_share_rx,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_gc_bmr_share_ry, double alpha_dlap_);

SecureFloatingPointCircuitABY SecureSamplingAlgorithm_optimized::FL32GaussianNoiseGeneration(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_u1,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_u2, double mu, double sigma) {
  // std::cout<<"001"<< std::endl;
  SecureFloatingPointCircuitABY floating_point_x1 =
      (((SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_share_u1).Ln()) *
        float(-2))
           .Sqrt()) *
      ((SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_share_u2) * float(2)))
          .Cos();

  // std::cout<<"002"<< std::endl;
  SecureFloatingPointCircuitABY floating_point_y;
  if (mu != 0) {
    // std::cout<<"003"<< std::endl;
    floating_point_y = floating_point_x1 * float(sigma) + float(mu);
  } else {
    // std::cout<<"004"<< std::endl;
    floating_point_y = floating_point_x1 * float(sigma);
  }
  // std::cout<<"004_1"<< std::endl;
  return floating_point_y;
}

SecureFloatingPointCircuitABY SecureSamplingAlgorithm_optimized::FL64GaussianNoiseGeneration(
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_u1,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_u2, double mu, double sigma) {
  //    std::cout<<"005"<< std::endl;
  SecureFloatingPointCircuitABY floating_point_x1 =
      (((SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_share_u1).Ln()) *
        double(-2))
           .Sqrt()) *
      ((SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_share_u2) * double(2)))
          .Cos();

  //    std::cout<<"006"<< std::endl;
  SecureFloatingPointCircuitABY floating_point_y;
  if (mu != 0) {
    //    std::cout<<"007"<< std::endl;
    floating_point_y = floating_point_x1 * double(sigma) + double(mu);
  } else {
    //    std::cout<<"008"<< std::endl;
    floating_point_y = floating_point_x1 * double(sigma);
  }
  //    std::cout<<"009"<< std::endl;
  return floating_point_y;
}

}  // namespace encrypto::motion