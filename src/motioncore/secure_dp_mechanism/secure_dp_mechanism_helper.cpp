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

#include "secure_dp_mechanism/secure_dp_mechanism_helper.h"
#include "algorithm/boolean_algorithms.h"
#include "base/backend.h"
#include "protocols/constant/constant_share_wrapper.h"
#include "secure_type/secure_fixed_point_circuit_CBMC.h"
#include "secure_type/secure_floating_point_circuit_ABY.h"
#include "secure_type/secure_unsigned_integer.h"
#include "utility/MOTION_dp_mechanism_helper/snapping_mechanism.h"

namespace encrypto::motion {

ShareWrapper SecureDPMechanismHelper::GenerateRandomBooleanGmwBits(
    const std::size_t num_of_wires, const std::size_t num_of_bits) const {
  std::vector<BitVector<>> random_bitvector_vector;
  random_bitvector_vector.reserve(num_of_wires);

  for (std::size_t i = 0; i < num_of_wires; i++) {
    random_bitvector_vector.emplace_back(BitVector<>::SecureRandom(num_of_bits));
  }

  // each party locally generates random bits as share of a publicly unknown bit-string
  ShareWrapper boolean_gmw_share_random_bits =
      share_->GetBackend().ConstantAsBooleanGmwInput(random_bitvector_vector);

  return boolean_gmw_share_random_bits;
}

template <typename T>
ShareWrapper SecureDPMechanismHelper::GenerateRandomUnsignedInteger(
    T m, const std::size_t num_of_simd) const {
  std::size_t T_size = sizeof(T) * 8;
  ShareWrapper boolean_gmw_share_random_bits = GenerateRandomBooleanGmwBits(T_size, num_of_simd);

  // ============================================================
  // a. BGMW (cost less memory, but slower than BMR)
  SecureUnsignedInteger random_unsigned_integer =
      SecureUnsignedInteger(boolean_gmw_share_random_bits);
  SecureUnsignedInteger random_unsigned_integer_0_m = random_unsigned_integer.Mod(m);
  return random_unsigned_integer_0_m.Get();
  //   ============================================================
  // b. BMR (cost more memory, but faster than BGMW)
  //   SecureUnsignedInteger random_unsigned_integer =
  //       SecureUnsignedInteger(boolean_gmw_share_random_bits.Convert<MpcProtocol::kBmr>());
  //   ShareWrapper random_unsigned_integer_bmr_share_0_m =
  //   ((random_unsigned_integer.Mod(m)).Get()); ShareWrapper
  //   random_unsigned_integer_boolean_gmw_share_0_m =
  //       random_unsigned_integer_bmr_share_0_m.Convert<MpcProtocol::kBooleanGmw>();
  //   return random_unsigned_integer_boolean_gmw_share_0_m;
  // ============================================================
}

template ShareWrapper SecureDPMechanismHelper::GenerateRandomUnsignedInteger<std::uint8_t>(
    std::uint8_t m, const std::size_t num_of_simd) const;
template ShareWrapper SecureDPMechanismHelper::GenerateRandomUnsignedInteger<std::uint16_t>(
    std::uint16_t m, const std::size_t num_of_simd) const;
template ShareWrapper SecureDPMechanismHelper::GenerateRandomUnsignedInteger<std::uint32_t>(
    std::uint32_t m, const std::size_t num_of_simd) const;
template ShareWrapper SecureDPMechanismHelper::GenerateRandomUnsignedInteger<std::uint64_t>(
    std::uint64_t m, const std::size_t num_of_simd) const;
template ShareWrapper SecureDPMechanismHelper::GenerateRandomUnsignedInteger<__uint128_t>(
    __uint128_t m, const std::size_t num_of_simd) const;

ShareWrapper SecureDPMechanismHelper::BooleanGmwBitsZeroCompensation(
    const ShareWrapper& boolean_gmw_share_bits, const std::size_t num_of_total_bits) const {
  std::size_t boolean_gmw_share_bits_vector_size = boolean_gmw_share_bits.Split().size();
  std::vector<ShareWrapper> boolean_gmw_share_bits_vector = boolean_gmw_share_bits.Split();

  ShareWrapper constant_boolean_gmw_share_zero =
      boolean_gmw_share_bits_vector[0] ^ boolean_gmw_share_bits_vector[0];

  std::vector<ShareWrapper> boolean_gmw_share_bits_with_zero_compensation_vector(num_of_total_bits);
  for (std::size_t i = 0; i < num_of_total_bits; i++) {
    boolean_gmw_share_bits_with_zero_compensation_vector[i] = constant_boolean_gmw_share_zero;
  }

  for (std::size_t i = 0; i < boolean_gmw_share_bits_vector_size; i++) {
    boolean_gmw_share_bits_with_zero_compensation_vector[i] = boolean_gmw_share_bits_vector[i];
  }

  return ShareWrapper::Concatenate(boolean_gmw_share_bits_with_zero_compensation_vector);
}

ShareWrapper SecureDPMechanismHelper::PreOrL() const {
  ShareWrapper share_x = share_;
  return PreOrL(share_x);
}

ShareWrapper SecureDPMechanismHelper::PreOrL(const ShareWrapper& random_bits) const {
  auto share_x = *random_bits;
  assert(share_x);
  assert(share_x->GetCircuitType() == CircuitType::kBoolean);

  if (share_x->GetProtocol() == MpcProtocol::kArithmeticGmw) {
    throw std::runtime_error(
        "Boolean PreOr operations are not supported for Arithmetic GMW shares");
  } else {
    std::size_t k = share_x->GetBitLength();
    std::vector<ShareWrapper> preOr_list = ShareWrapper(share_x).Split();

    std::size_t log_k = std::size_t(ceil(log2(k)));
    std::size_t kmax = static_cast<std::uint32_t>(pow(2, log_k));

    for (std::uint32_t i = 0; i < log_k; i++) {
      for (std::uint32_t j = 0; j < kmax / static_cast<std::uint32_t>(pow(2, i + 1)); j++) {
        std::size_t y = static_cast<std::uint32_t>(pow(2, i)) +
                        j * static_cast<std::uint32_t>(pow(2, i + 1)) - 1;
        for (std::uint32_t z = 1; z < static_cast<std::uint32_t>(pow(2, i)) + 1; z++) {
          if (y + z < k) {
            preOr_list[y + z] = preOr_list[y] | preOr_list[y + z];
          }
        }
      }
    }
    return ShareWrapper::Concatenate(preOr_list);
  }
}

ShareWrapper SecureDPMechanismHelper::SimpleGeometricSampling_1(
    const ShareWrapper& random_bits) const {
  ShareWrapper random_bits_pre_or = SecureDPMechanismHelper(random_bits).PreOrL();

  std::vector<ShareWrapper> random_bits_pre_or_vector = random_bits_pre_or.Split();
  ShareWrapper constant_boolean_gmw_share_one =
      random_bits_pre_or_vector[0] ^ (~random_bits_pre_or_vector[0]);
  ShareWrapper constant_boolean_gmw_share_zero =
      random_bits_pre_or_vector[0] ^ (random_bits_pre_or_vector[0]);
  std::size_t size_of_random_bits = random_bits_pre_or_vector.size();

  std::vector<ShareWrapper> random_bits_pre_or_vector_right_shift_by_1_vector(size_of_random_bits);
  random_bits_pre_or_vector_right_shift_by_1_vector[0] = constant_boolean_gmw_share_zero;
  for (std::size_t i = 1; i < size_of_random_bits; i++) {
    random_bits_pre_or_vector_right_shift_by_1_vector[i] = random_bits_pre_or_vector[i - 1];
  }

  ShareWrapper random_bits_pre_or_right_shift_by_1 =
      ShareWrapper::Concatenate(random_bits_pre_or_vector_right_shift_by_1_vector);

  ShareWrapper random_bits_pre_or_right_shift_by_1_invert = ~random_bits_pre_or_right_shift_by_1;

  ShareWrapper hamming_weight =
      encrypto::motion::algorithm::HammingWeight(random_bits_pre_or_right_shift_by_1_invert);

  return hamming_weight;
}

ShareWrapper SecureDPMechanismHelper::SimpleGeometricSampling_0(
    const ShareWrapper& random_bits) const {
  ShareWrapper random_bits_pre_or = SecureDPMechanismHelper(random_bits).PreOrL();

  ShareWrapper random_bits_pre_or_invert = ~random_bits_pre_or;
  ShareWrapper hamming_weight =
      encrypto::motion::algorithm::HammingWeight(random_bits_pre_or_invert);

  return hamming_weight;
}

ShareWrapper SecureDPMechanismHelper::UniformFloatingPoint64_0_1(
    const ShareWrapper& random_bits_of_length_52,
    const ShareWrapper& random_bits_of_length_1022) const {
  using T = std::uint16_t;
  std::size_t T_size = sizeof(T) * 8;

  // ! we assume that the geomertic sampling always success (there is always 1 in
  // random_bits_of_length_1022), the probability for this assumption to fail is 2^(-1022)

  ShareWrapper boolean_gmw_share_geometric_sample =
      SimpleGeometricSampling_1(random_bits_of_length_1022);

  // compensate boolean_gmw_share_geometric_sample with 0 and convert to secure unsigned integer
  std::vector<ShareWrapper> boolean_gmw_share_geometric_sample_vector =
      boolean_gmw_share_geometric_sample.Split();
  std::size_t boolean_gmw_share_geometric_sample_vector_size =
      boolean_gmw_share_geometric_sample_vector.size();

  ShareWrapper constant_boolean_gmw_share_zero =
      boolean_gmw_share_geometric_sample_vector[0] ^ boolean_gmw_share_geometric_sample_vector[0];

  ShareWrapper constant_boolean_gmw_share_one = boolean_gmw_share_geometric_sample_vector[0] ^
                                                (~boolean_gmw_share_geometric_sample_vector[0]);

  std::vector<ShareWrapper> boolean_gmw_share_exponent_unbiased_vector(T_size);
  for (std::size_t i = 0; i < T_size; i++) {
    boolean_gmw_share_exponent_unbiased_vector[i] = constant_boolean_gmw_share_zero;
  }

  for (std::size_t i = 0; i < boolean_gmw_share_geometric_sample_vector_size; i++) {
    boolean_gmw_share_exponent_unbiased_vector[i] = boolean_gmw_share_geometric_sample_vector[i];
  }

  // biased_exponent = 1023 - geo
  SecureUnsignedInteger secure_unsigned_integer_unbiased_exponent =
      SecureUnsignedInteger(ShareWrapper::Concatenate(boolean_gmw_share_exponent_unbiased_vector));

  std::size_t num_of_simd = random_bits_of_length_52->GetNumberOfSimdValues();
  std::vector<T> vector_of_1023(num_of_simd, 1023);

  SecureUnsignedInteger secure_unsigned_integer_constant_1023 = SecureUnsignedInteger(
      share_->GetBackend().ConstantAsBooleanGmwInput(ToInput<T>(vector_of_1023)));

  SecureUnsignedInteger secure_unsigned_integer_biased_exponent =
      secure_unsigned_integer_constant_1023 - secure_unsigned_integer_unbiased_exponent;

  // extract 11 bits from secure_unsigned_integer_biased_exponent
  std::vector<ShareWrapper> boolean_gmw_share_biased_exponent_with_zero_compensation_vector =
      secure_unsigned_integer_biased_exponent.Get().Split();

  std::vector<ShareWrapper> boolean_gmw_share_biased_exponent_vector(
      boolean_gmw_share_biased_exponent_with_zero_compensation_vector.begin(),
      boolean_gmw_share_biased_exponent_with_zero_compensation_vector.begin() +
          FLOATINGPOINT_EXPONENT_BITS);

  std::vector<ShareWrapper> boolean_gmw_share_uniform_floating_point_vector;
  boolean_gmw_share_uniform_floating_point_vector.reserve(FLOATINGPOINT_BITS);

  std::vector<ShareWrapper> boolean_gmw_share_mantissa_vector = random_bits_of_length_52.Split();

  for (std::size_t i = 0; i < FLOATINGPOINT_MANTISSA_BITS; i++) {
    boolean_gmw_share_uniform_floating_point_vector.emplace_back(
        boolean_gmw_share_mantissa_vector[i]);
  }

  for (std::size_t i = 0; i < FLOATINGPOINT_EXPONENT_BITS; i++) {
    boolean_gmw_share_uniform_floating_point_vector.emplace_back(
        boolean_gmw_share_biased_exponent_vector[i]);
  }

  boolean_gmw_share_uniform_floating_point_vector.emplace_back(constant_boolean_gmw_share_zero);

  return ShareWrapper::Concatenate(boolean_gmw_share_uniform_floating_point_vector);
}

ShareWrapper SecureDPMechanismHelper::UniformFloatingPoint32_0_1(
    const ShareWrapper& random_bits_of_length_23,
    const ShareWrapper& random_bits_of_length_126) const {
  using T = std::uint8_t;
  std::size_t T_size = sizeof(T) * 8;

  std::size_t single_precision_floating_point_bit_length = FLOATINGPOINT32_BITS;
  std::size_t single_precision_floating_point_mantissa_bit_length = FLOATINGPOINT32_MANTISSA_BITS;
  std::size_t single_precision_floating_point_exponent_bit_length = FLOATINGPOINT32_EXPONENT_BITS;
  std::size_t single_precision_floating_point_sign_bit_length = FLOATINGPOINT32_SIGN_BITS;

  // ! we assume that the geomertic sampling always success (there is always 1 in
  // random_bits_of_length_126), the probability for this assumption to fail is 2^(-126)

  ShareWrapper boolean_gmw_share_geometric_sample =
      SimpleGeometricSampling_1(random_bits_of_length_126);

  // compensate boolean_gmw_share_geometric_sample with 0 and convert to secure unsigned integer
  std::vector<ShareWrapper> boolean_gmw_share_geometric_sample_vector =
      boolean_gmw_share_geometric_sample.Split();
  std::size_t boolean_gmw_share_geometric_sample_vector_size =
      boolean_gmw_share_geometric_sample_vector.size();

  ShareWrapper constant_boolean_gmw_share_zero =
      boolean_gmw_share_geometric_sample_vector[0] ^ boolean_gmw_share_geometric_sample_vector[0];

  ShareWrapper constant_boolean_gmw_share_one = boolean_gmw_share_geometric_sample_vector[0] ^
                                                (~boolean_gmw_share_geometric_sample_vector[0]);

  std::vector<ShareWrapper> boolean_gmw_share_exponent_unbiased_vector(T_size);
  for (std::size_t i = 0; i < T_size; i++) {
    boolean_gmw_share_exponent_unbiased_vector[i] = constant_boolean_gmw_share_zero;
  }

  for (std::size_t i = 0; i < boolean_gmw_share_geometric_sample_vector_size; i++) {
    boolean_gmw_share_exponent_unbiased_vector[i] = boolean_gmw_share_geometric_sample_vector[i];
  }

  SecureUnsignedInteger secure_unsigned_integer_unbiased_exponent =
      SecureUnsignedInteger(ShareWrapper::Concatenate(boolean_gmw_share_exponent_unbiased_vector));

  std::size_t num_of_simd = random_bits_of_length_23->GetNumberOfSimdValues();

  std::vector<T> vector_of_127(num_of_simd, 127);

  SecureUnsignedInteger secure_unsigned_integer_constant_127 = SecureUnsignedInteger(
      share_->GetBackend().ConstantAsBooleanGmwInput(ToInput<T>(vector_of_127)));

  // biased_exponent = 127 - geo
  SecureUnsignedInteger secure_unsigned_integer_biased_exponent =
      secure_unsigned_integer_constant_127 - secure_unsigned_integer_unbiased_exponent;

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

  for (std::size_t i = 0; i < single_precision_floating_point_mantissa_bit_length; i++) {
    boolean_gmw_share_uniform_floating_point_vector.emplace_back(
        boolean_gmw_share_mantissa_vector[i]);
  }

  for (std::size_t i = 0; i < single_precision_floating_point_exponent_bit_length; i++) {
    boolean_gmw_share_uniform_floating_point_vector.emplace_back(
        boolean_gmw_share_biased_exponent_vector[i]);
  }

  boolean_gmw_share_uniform_floating_point_vector.emplace_back(constant_boolean_gmw_share_zero);

  return ShareWrapper::Concatenate(boolean_gmw_share_uniform_floating_point_vector);
}

ShareWrapper SecureDPMechanismHelper::UniformFixedPoint_0_1(
    const ShareWrapper& random_bits_of_length_fixed_point_fraction,
    const std::size_t fixed_point_bit_size) const {
  ShareWrapper fixed_point_boolean_gmw_share_0_1 = BooleanGmwBitsZeroCompensation(
      random_bits_of_length_fixed_point_fraction, fixed_point_bit_size);

  return fixed_point_boolean_gmw_share_0_1;
}

ShareWrapper SecureDPMechanismHelper::UniformFixedPoint_0_1_Up(
    const ShareWrapper& random_bits_of_length_fixed_point_fraction,
    const std::size_t fixed_point_bit_size) const {
  // uniform fixed point in [0,1)
  ShareWrapper boolean_gmw_share_uniform_fixed_point_0_1 =
      UniformFixedPoint_0_1(random_bits_of_length_fixed_point_fraction, fixed_point_bit_size);

  std::vector<ShareWrapper> random_bits_of_length_fixed_point_fraction_vector =
      random_bits_of_length_fixed_point_fraction.Split();

  ShareWrapper constant_boolean_gmw_share_one =
      random_bits_of_length_fixed_point_fraction_vector[0] ^
      (~random_bits_of_length_fixed_point_fraction_vector[0]);

  ShareWrapper fixed_point_boolean_gmw_share_minimum_representable_value =
      BooleanGmwBitsZeroCompensation(constant_boolean_gmw_share_one, fixed_point_bit_size);

  // convert it to field (0,1] by adding the minimum representable fixed point value
  ShareWrapper boolean_gmw_share_uniform_fixed_point_0_1_up =
      (SecureUnsignedInteger(fixed_point_boolean_gmw_share_minimum_representable_value) +
       SecureUnsignedInteger(boolean_gmw_share_uniform_fixed_point_0_1))
          .Get();

  return boolean_gmw_share_uniform_fixed_point_0_1_up;
}

std::vector<ShareWrapper> SecureDPMechanismHelper::InvertBinaryTreeSelection(
    const std::vector<ShareWrapper>& boolean_gmw_share_y_vector,
    const std::vector<ShareWrapper>& boolean_gmw_share_c_vector) const {
  std::size_t num_of_leaf = boolean_gmw_share_y_vector.size();

  if (num_of_leaf == 1) {
    std::vector<ShareWrapper> boolean_gmw_share_result_vector;
    boolean_gmw_share_result_vector.reserve(2);
    boolean_gmw_share_result_vector.emplace_back(boolean_gmw_share_y_vector[0]);
    boolean_gmw_share_result_vector.emplace_back(boolean_gmw_share_c_vector[0]);
    return boolean_gmw_share_result_vector;
  }

  else if (num_of_leaf == 2) {
    ShareWrapper boolean_gmw_left_leaf_c = boolean_gmw_share_c_vector[0];
    ShareWrapper boolean_gmw_right_leaf_c = boolean_gmw_share_c_vector[1];

    // compute the new leaf
    ShareWrapper boolean_gmw_share_left_leaf_c_xor_right_leaf_c =
        boolean_gmw_left_leaf_c ^ boolean_gmw_right_leaf_c;

    ShareWrapper boolean_gmw_share_left_selection_and_right_selection =
        (boolean_gmw_left_leaf_c.XCOTMul(boolean_gmw_share_y_vector[0])) ^
        (boolean_gmw_right_leaf_c.XCOTMul(boolean_gmw_share_y_vector[1]));

    ShareWrapper boolean_gmw_share_left_c_and_right_c =
        boolean_gmw_left_leaf_c & boolean_gmw_right_leaf_c;

    ShareWrapper boolean_gmw_new_leaf_y =
        (boolean_gmw_share_left_leaf_c_xor_right_leaf_c.XCOTMul(
            boolean_gmw_share_left_selection_and_right_selection)) ^
        (boolean_gmw_share_left_c_and_right_c.XCOTMul(boolean_gmw_share_y_vector[0]));

    ShareWrapper boolean_gmw_new_leaf_c =
        boolean_gmw_share_left_leaf_c_xor_right_leaf_c ^ boolean_gmw_share_left_c_and_right_c;

    std::vector<ShareWrapper> boolean_gmw_share_new_leaf_vector;
    boolean_gmw_share_new_leaf_vector.reserve(2);
    boolean_gmw_share_new_leaf_vector.emplace_back(boolean_gmw_new_leaf_y);
    boolean_gmw_share_new_leaf_vector.emplace_back(boolean_gmw_new_leaf_c);
    return boolean_gmw_share_new_leaf_vector;

  }

  // recursive call
  else {
    std::vector<ShareWrapper> boolean_gmw_share_new_left_leaf_vector = InvertBinaryTreeSelection(
        std::vector<ShareWrapper>(boolean_gmw_share_y_vector.begin(),
                                  boolean_gmw_share_y_vector.begin() + num_of_leaf / 2),
        std::vector<ShareWrapper>(boolean_gmw_share_c_vector.begin(),
                                  boolean_gmw_share_c_vector.begin() + num_of_leaf / 2));
    std::vector<ShareWrapper> boolean_gmw_share_new_right_leaf_vector = InvertBinaryTreeSelection(
        std::vector<ShareWrapper>(boolean_gmw_share_y_vector.begin() + num_of_leaf / 2,
                                  boolean_gmw_share_y_vector.end()),
        std::vector<ShareWrapper>(boolean_gmw_share_c_vector.begin() + num_of_leaf / 2,
                                  boolean_gmw_share_c_vector.end()));

    std::vector<ShareWrapper> boolean_gmw_share_new_leaf_y_vector;
    boolean_gmw_share_new_leaf_y_vector.reserve(2);
    boolean_gmw_share_new_leaf_y_vector.emplace_back(boolean_gmw_share_new_left_leaf_vector[0]);
    boolean_gmw_share_new_leaf_y_vector.emplace_back(boolean_gmw_share_new_right_leaf_vector[0]);

    std::vector<ShareWrapper> boolean_gmw_share_new_leaf_c_vector;
    boolean_gmw_share_new_leaf_c_vector.reserve(2);
    boolean_gmw_share_new_leaf_c_vector.emplace_back(boolean_gmw_share_new_left_leaf_vector[1]);
    boolean_gmw_share_new_leaf_c_vector.emplace_back(boolean_gmw_share_new_right_leaf_vector[1]);

    std::vector<ShareWrapper> boolean_gmw_new_leaf_vector = InvertBinaryTreeSelection(
        boolean_gmw_share_new_leaf_y_vector, boolean_gmw_share_new_leaf_c_vector);
    return boolean_gmw_new_leaf_vector;
  }
}

std::vector<ShareWrapper> SecureDPMechanismHelper::SimdifyReshapeHorizontal(
    std::vector<ShareWrapper> input, std::size_t num_of_wires, std::size_t num_of_simd) {
  assert(input.size() == num_of_simd * num_of_wires);

  std::vector<ShareWrapper> result_vector;
  result_vector.reserve(num_of_wires);

  for (std::size_t i = 0; i < num_of_wires; i++) {
    std::vector<ShareWrapper> boolean_gmw_share_wire_tmp;
    boolean_gmw_share_wire_tmp.reserve(num_of_simd);
    for (std::size_t j = 0; j < num_of_simd; j++) {
      boolean_gmw_share_wire_tmp.emplace_back(input[i + j * num_of_wires]);
    }
    result_vector.emplace_back(ShareWrapper::Simdify(boolean_gmw_share_wire_tmp));
  }
  return result_vector;
}

std::vector<ShareWrapper> SecureDPMechanismHelper::SimdifyReshapeVertical(
    std::vector<ShareWrapper> input, std::size_t num_of_wires, std::size_t num_of_simd) {
  assert(input.size() == num_of_simd * num_of_wires);

  std::vector<ShareWrapper> result_vector;
  result_vector.reserve(num_of_wires);

  for (std::size_t i = 0; i < num_of_wires; i++) {
    std::vector<ShareWrapper> boolean_gmw_share_wire_tmp;
    boolean_gmw_share_wire_tmp.reserve(num_of_simd);
    for (std::size_t j = 0; j < num_of_simd; j++) {
      boolean_gmw_share_wire_tmp.emplace_back(input[i * num_of_simd + j]);
    }
    result_vector.emplace_back(ShareWrapper::Simdify(boolean_gmw_share_wire_tmp));
  }

  return result_vector;
}

std::vector<ShareWrapper> SecureDPMechanismHelper::SimdifyDuplicateHorizontal(
    std::vector<ShareWrapper> input, std::size_t num_of_wires) {
  //   assert(input.size() == num_of_simd);
  std::size_t num_of_simd = input.size();

  std::vector<ShareWrapper> result_vector;
  result_vector.reserve(num_of_wires);

  for (std::size_t i = 0; i < num_of_wires; i++) {
    std::vector<ShareWrapper> boolean_gmw_share_wire_tmp;
    boolean_gmw_share_wire_tmp.reserve(num_of_simd);
    for (std::size_t j = 0; j < num_of_simd; j++) {
      boolean_gmw_share_wire_tmp.emplace_back(input[j]);
    }
    result_vector.emplace_back(ShareWrapper::Simdify(boolean_gmw_share_wire_tmp));
  }

  return result_vector;
}

std::vector<ShareWrapper> SecureDPMechanismHelper::SimdifyDuplicateVertical(
    std::vector<ShareWrapper> input, std::size_t num_of_simd) {
  //   assert(input.size() == num_of_wires);
  std::size_t num_of_wires = input.size();

  std::vector<ShareWrapper> result_vector;
  result_vector.reserve(num_of_wires);

  for (std::size_t i = 0; i < num_of_wires; i++) {
    std::vector<ShareWrapper> boolean_gmw_share_wire_tmp;
    boolean_gmw_share_wire_tmp.reserve(num_of_simd);
    for (std::size_t j = 0; j < num_of_simd; j++) {
      boolean_gmw_share_wire_tmp.emplace_back(input[i]);
    }
    result_vector.emplace_back(ShareWrapper::Simdify(boolean_gmw_share_wire_tmp));
  }

  return result_vector;
}

// ! this sampling function need further optimization
template <typename T>
ShareWrapper SecureDPMechanismHelper::GeometricSamplingWithBinarySearch(
    const T L0, const T R0, const double lambda, const std::size_t iteration,
    const std::vector<ShareWrapper>& uniform_floating_point_0_1_boolean_gmw_share_vector) const {
  // plaintext computation
  T M0 = L0 - (log(0.5) + log(1 + exp(-lambda * (R0 - L0)))) / lambda;

  std::cout << "M0: " << M0 << std::endl;

  if (!(M0 > L0)) {
    M0 = L0 + 1;
  } else if (!(M0 < R0)) {
    M0 = R0 - 1;
  }
  std::cout << "M0: " << M0 << std::endl;

  double Q0 = (exp(-lambda * (M0 - L0)) - 1) / (exp(-lambda * (R0 - L0)) - 1);
  std::cout << "Q0: " << Q0 << std::endl;

  // computation in MPC
  std::cout << "computation in MPC" << std::endl;

  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  SecureFloatingPointCircuitABY floating_point_constant_Q0 = SecureFloatingPointCircuitABY(
      ConstantShareWrapper(share_).CreateConstantBooleanGmwInput<T>(Q0));
  SecureSignedInteger signed_integer_constant_M0 =
      SecureSignedInteger(ConstantShareWrapper(share_).CreateConstantBooleanGmwInput<T>(M0));
  SecureSignedInteger signed_integer_constant_L0 =
      SecureSignedInteger(ConstantShareWrapper(share_).CreateConstantBooleanGmwInput<T>(L0));
  SecureSignedInteger signed_integer_constant_R0 =
      SecureSignedInteger(ConstantShareWrapper(share_).CreateConstantBooleanGmwInput<T>(R0));

  ShareWrapper boolean_gmw_share_cond_U0_gt_Q0 =
      SecureFloatingPointCircuitABY(uniform_floating_point_0_1_boolean_gmw_share_vector[0]) >
      floating_point_constant_Q0;
  ShareWrapper boolean_gmw_share_cond_U0_leq_Q0 = ~boolean_gmw_share_cond_U0_gt_Q0;

  // TODO; benchmark secure unsigned integer and decide if computation in integer or in
  // floating-point
  SecureSignedInteger signed_integer_R0 =
      signed_integer_constant_M0.MulBooleanGmwBit(boolean_gmw_share_cond_U0_leq_Q0) +
      signed_integer_constant_R0.MulBooleanGmwBit(boolean_gmw_share_cond_U0_gt_Q0);

  SecureSignedInteger signed_integer_L0 =
      signed_integer_constant_M0.MulBooleanGmwBit(boolean_gmw_share_cond_U0_gt_Q0) +
      signed_integer_constant_L0.MulBooleanGmwBit(boolean_gmw_share_cond_U0_leq_Q0);

  ShareWrapper boolean_gmw_share_fg0 = ~((signed_integer_L0 + T(1)) < signed_integer_R0);

  std::vector<SecureSignedInteger> signed_integer_M_vector(iteration);
  std::vector<SecureFloatingPointCircuitABY> floating_point_Q_vector(iteration);
  std::vector<SecureSignedInteger> signed_integer_L_vector(iteration);
  std::vector<SecureSignedInteger> signed_integer_R_vector(iteration);
  std::vector<ShareWrapper> boolean_gmw_share_fg_vector(iteration);

  signed_integer_M_vector[0] = signed_integer_constant_M0;
  floating_point_Q_vector[0] = floating_point_constant_Q0;
  signed_integer_L_vector[0] = signed_integer_L0;
  signed_integer_R_vector[0] = signed_integer_R0;
  boolean_gmw_share_fg_vector[0] = boolean_gmw_share_fg0;

  for (std::size_t j = 1; j < iteration; j++) {
    std::cout << "j: " << j << std::endl;
    signed_integer_M_vector[j] =
        (signed_integer_L_vector[j - 1].Int2FL() -
         (((((signed_integer_R_vector[j - 1] - signed_integer_L_vector[j - 1]).Int2FL() * (-lambda))
                .Exp()) +
           (1.0))
              .Ln() +
          (log(0.5))) /
             (lambda))
            .FL2Int();

    ShareWrapper boolean_gmw_share_cond_Mj_leq_L_j_minus_1 =
        ~(signed_integer_M_vector[j] > signed_integer_L_vector[j - 1]);

    ShareWrapper boolean_gmw_share_cond_Mj_geq_R_j_minus_1 =
        ~(signed_integer_M_vector[j] < signed_integer_R_vector[j - 1]);

    ShareWrapper boolean_gmw_share_cond_Mj_gt_L_j_minus_1_lt_R_j_minus_1 =
        ~(boolean_gmw_share_cond_Mj_leq_L_j_minus_1 | boolean_gmw_share_cond_Mj_geq_R_j_minus_1);

    signed_integer_M_vector[j] = (signed_integer_L_vector[j - 1] + T(1))
                                     .MulBooleanGmwBit(boolean_gmw_share_cond_Mj_leq_L_j_minus_1) +
                                 (signed_integer_R_vector[j - 1] - T(1))
                                     .MulBooleanGmwBit(boolean_gmw_share_cond_Mj_geq_R_j_minus_1) +
                                 signed_integer_M_vector[j].MulBooleanGmwBit(
                                     boolean_gmw_share_cond_Mj_gt_L_j_minus_1_lt_R_j_minus_1);

    floating_point_Q_vector[j] =
        (((signed_integer_M_vector[j] - signed_integer_L_vector[j - 1]).Int2FL() * (-lambda))
             .Exp() -
         double(1)) /
        (((signed_integer_R_vector[j - 1] - signed_integer_L_vector[j - 1]).Int2FL() * (-lambda))
             .Exp() -
         double(1));

    ShareWrapper boolean_gmw_share_cond_Uj_gt_Qj =
        SecureFloatingPointCircuitABY(uniform_floating_point_0_1_boolean_gmw_share_vector[j]) >
        floating_point_Q_vector[j];
    ShareWrapper boolean_gmw_share_cond_Uj_leq_Qj = ~boolean_gmw_share_cond_Uj_gt_Qj;

    signed_integer_R_vector[j] =
        signed_integer_M_vector[j].MulBooleanGmwBit(boolean_gmw_share_cond_Uj_leq_Qj) +
        signed_integer_R_vector[j - 1].MulBooleanGmwBit(boolean_gmw_share_cond_Uj_gt_Qj);
    signed_integer_L_vector[j] =
        signed_integer_M_vector[j].MulBooleanGmwBit(boolean_gmw_share_cond_Uj_gt_Qj) +
        signed_integer_L_vector[j - 1].MulBooleanGmwBit(boolean_gmw_share_cond_Uj_leq_Qj);

    boolean_gmw_share_fg_vector[j] =
        ~((signed_integer_L_vector[j] + T(1)) < signed_integer_R_vector[j]);
  }

  std::vector<ShareWrapper> boolean_gmw_share_one_hot_choose_vector(iteration);
  boolean_gmw_share_one_hot_choose_vector[0] =
      boolean_gmw_share_fg_vector[0] ^ boolean_gmw_share_fg_vector[0];
  for (std::size_t j = 1; j < iteration; j++) {
    boolean_gmw_share_one_hot_choose_vector[j] =
        boolean_gmw_share_fg_vector[j - 1] ^ boolean_gmw_share_fg_vector[j];
  }

  SecureSignedInteger signed_integer_result =
      signed_integer_R_vector[0].MulBooleanGmwBit(boolean_gmw_share_one_hot_choose_vector[0]);

  // TODO: optimize low depth
  for (std::size_t j = 1; j < iteration; j++) {
    signed_integer_result = signed_integer_result + signed_integer_R_vector[j].MulBooleanGmwBit(
                                                        boolean_gmw_share_one_hot_choose_vector[j]);
  }
  return signed_integer_result.Get();
}

template ShareWrapper SecureDPMechanismHelper::GeometricSamplingWithBinarySearch<std::uint64_t>(
    const std::uint64_t L0, const std::uint64_t R0, const double lambda,
    const std::size_t iteration,
    const std::vector<ShareWrapper>& uniform_floating_point_0_1_boolean_gmw_share_vector) const;

ShareWrapper SecureDPMechanismHelper::FLBernoulliDistribution(
    const ShareWrapper& floating_point_boolean_gmw_share_p,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share) const {
  SecureFloatingPointCircuitABY uniform_floating_point64_0_1 =
      SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_share);

  ShareWrapper boolean_gmw_share_uniform_floating_point_less_than_p =
      uniform_floating_point64_0_1 <
      SecureFloatingPointCircuitABY(floating_point_boolean_gmw_share_p);

  return boolean_gmw_share_uniform_floating_point_less_than_p;
}

template <typename FLType, typename T, typename T_int>
std::vector<ShareWrapper> SecureDPMechanismHelper::FLGeometricDistributionEXP(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const std::vector<std::uint64_t>& constant_unsigned_integer_denominator_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share, std::size_t iteration_1,
    std::size_t iteration_2) const {
  std::size_t num_of_simd = constant_unsigned_integer_numerator_vector.size();

  assert(constant_unsigned_integer_numerator_vector.size() ==
         constant_unsigned_integer_denominator_vector.size());
  assert(random_floating_point_0_1_boolean_gmw_share->GetNumberOfSimdValues() ==
         (iteration_1 + iteration_2) * num_of_simd);
  assert(random_unsigned_integer_boolean_gmw_share->GetNumberOfSimdValues() ==
         iteration_1 * num_of_simd);

  std::size_t FLType_size = sizeof(FLType) * 8;

  // if numerator or denominator are all ones, we can avoid some computations in MPC
  bool numerator_are_all_ones =
      VectorAllEqualToValue<T>(constant_unsigned_integer_numerator_vector, T(1));
  bool denominator_are_all_ones =
      VectorAllEqualToValue<T>(constant_unsigned_integer_denominator_vector, T(1));

  assert(!denominator_are_all_ones);

  // case 1: denominator are not all ones
  ShareWrapper unsigned_integer_boolean_gmw_share_denominator =
      (share_->GetBackend().ConstantAsBooleanGmwInput(
          ToInput<T>(constant_unsigned_integer_denominator_vector)));

  // convert denominator to FLType type in plaintext instead of converting in MPC
  std::vector<FLType> constant_floating_point_denominator_vector(num_of_simd);
  for (std::size_t i = 0; i < num_of_simd; i++) {
    T denominator_tmp = constant_unsigned_integer_denominator_vector[i];
    constant_floating_point_denominator_vector[i] = FLType(T_int(denominator_tmp));
  }
  ShareWrapper floating_point_boolean_gmw_share_denominator =
      (share_->GetBackend().ConstantAsBooleanGmwInput(
          ToInput<FLType, std::true_type>(constant_floating_point_denominator_vector)));

  std::vector<ShareWrapper> floating_point_boolean_gmw_share_denominator_expand =
      SecureDPMechanismHelper::SimdifyDuplicateVertical(
          floating_point_boolean_gmw_share_denominator.Unsimdify(), iteration_1);

  ShareWrapper floating_point_boolean_gmw_share_denominator_simdify =
      ShareWrapper::Simdify(floating_point_boolean_gmw_share_denominator_expand);

  SecureFloatingPointCircuitABY floating_point_random_unsigned_integer =
      SecureUnsignedInteger(random_unsigned_integer_boolean_gmw_share).Int2FL(FLType_size);

  SecureFloatingPointCircuitABY floating_point_unsigned_integer_denominator_simdify =
      SecureFloatingPointCircuitABY(floating_point_boolean_gmw_share_denominator_simdify);

  SecureFloatingPointCircuitABY floating_point_random_unsigned_integer_div_denominator =
      floating_point_random_unsigned_integer / floating_point_unsigned_integer_denominator_simdify;

  SecureFloatingPointCircuitABY floating_point_exp_neg_random_unsigned_integer_div_denominator =
      floating_point_random_unsigned_integer_div_denominator.Neg().Exp();
  std::vector<FLType> vector_of_exp_neg_one(num_of_simd * iteration_2, std::exp(-1.0));
  SecureFloatingPointCircuitABY floating_point_constant_exp_neg_one =
      SecureFloatingPointCircuitABY(share_->GetBackend().ConstantAsBooleanGmwInput(
          ToInput<FLType, std::true_type>(vector_of_exp_neg_one)));

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
      boolean_gmw_share_Bernoulli_sample_unsimdify.begin() + iteration_1 * num_of_simd);

  std::vector<ShareWrapper> boolean_gmw_share_Bernoulli_sample_part_2_vector(
      boolean_gmw_share_Bernoulli_sample_unsimdify.begin() + iteration_1 * num_of_simd,
      boolean_gmw_share_Bernoulli_sample_unsimdify.begin() + iteration_1 * num_of_simd +
          iteration_2 * num_of_simd);

  std::vector<ShareWrapper> boolean_gmw_share_b1_vector =
      SecureDPMechanismHelper::SimdifyReshapeHorizontal(
          boolean_gmw_share_Bernoulli_sample_part_1_vector, iteration_1, num_of_simd);

  std::vector<ShareWrapper> boolean_gmw_share_b2_vector =
      SecureDPMechanismHelper::SimdifyReshapeHorizontal(
          boolean_gmw_share_Bernoulli_sample_part_2_vector, iteration_2, num_of_simd);

  // otherwise, random_unsigned_integer_boolean_gmw_share cannot call Unsimdify()
  ShareWrapper random_unsigned_integer_boolean_gmw_share_clone =
      random_unsigned_integer_boolean_gmw_share;

  std::vector<ShareWrapper> random_unsigned_integer_boolean_gmw_share_unsimdify =
      random_unsigned_integer_boolean_gmw_share_clone.Unsimdify();

  std::vector<ShareWrapper> random_unsigned_integer_boolean_gmw_share_for_b1_vector =
      SecureDPMechanismHelper::SimdifyReshapeHorizontal(
          random_unsigned_integer_boolean_gmw_share_unsimdify, iteration_1, num_of_simd);

  std::vector<ShareWrapper> boolean_gmw_share_u = InvertBinaryTreeSelection(
      random_unsigned_integer_boolean_gmw_share_for_b1_vector, boolean_gmw_share_b1_vector);

  std::vector<ShareWrapper> boolean_gmw_share_constant_j;
  boolean_gmw_share_constant_j.reserve(iteration_2);
  for (std::size_t j = 0; j < iteration_2; j++) {
    std::vector<T> vector_of_constant_j(num_of_simd, j);
    boolean_gmw_share_constant_j.emplace_back(
        share_->GetBackend().ConstantAsBooleanGmwInput(ToInput<T>(vector_of_constant_j)));
  }

  std::vector<ShareWrapper> boolean_gmw_share_b2_invert_vector;
  boolean_gmw_share_b2_invert_vector.reserve(iteration_2);
  for (std::size_t i = 0; i < iteration_2; i++) {
    boolean_gmw_share_b2_invert_vector.emplace_back(~boolean_gmw_share_b2_vector[i]);
  }

  std::vector<ShareWrapper> boolean_gmw_share_v =
      InvertBinaryTreeSelection(boolean_gmw_share_constant_j, boolean_gmw_share_b2_invert_vector);

  SecureUnsignedInteger unsigned_integer_w =
      SecureUnsignedInteger(boolean_gmw_share_v[0]) *
          SecureUnsignedInteger(unsigned_integer_boolean_gmw_share_denominator) +
      SecureUnsignedInteger(boolean_gmw_share_u[0]);

  // case 1.1
  // numerator's vector elements are not all equal to one
  if (!numerator_are_all_ones) {
    ShareWrapper unsigned_integer_boolean_gmw_share_numerator =
        (share_->GetBackend().ConstantAsBooleanGmwInput(
            ToInput<T>(constant_unsigned_integer_numerator_vector)));

    SecureUnsignedInteger unsigned_integer_geometric_sample =
        unsigned_integer_w / SecureUnsignedInteger(unsigned_integer_boolean_gmw_share_numerator);

    ShareWrapper boolean_gmw_share_success_flag = (boolean_gmw_share_u[1] & boolean_gmw_share_v[1]);

    std::vector<ShareWrapper> result_vector;
    result_vector.reserve(2);
    result_vector.emplace_back(unsigned_integer_geometric_sample.Get());
    result_vector.emplace_back(boolean_gmw_share_success_flag);

    return result_vector;
  }

  // case 1.2
  // if the numerator's vector elements are all equal to one, we can save computations
  else {
    // save MPC computation here
    SecureUnsignedInteger unsigned_integer_geometric_sample = unsigned_integer_w;

    ShareWrapper boolean_gmw_share_success_flag = (boolean_gmw_share_u[1] & boolean_gmw_share_v[1]);

    std::vector<ShareWrapper> result_vector;
    result_vector.reserve(2);
    result_vector.emplace_back(unsigned_integer_geometric_sample.Get());
    result_vector.emplace_back(boolean_gmw_share_success_flag);

    return result_vector;
  }
  //   }
}

template std::vector<ShareWrapper>
SecureDPMechanismHelper::FLGeometricDistributionEXP<float, std::uint64_t, std::int64_t>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const std::vector<std::uint64_t>& constant_unsigned_integer_denominator_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share, std::size_t iteration_1,
    std::size_t iteration_2) const;

template std::vector<ShareWrapper>
SecureDPMechanismHelper::FLGeometricDistributionEXP<double, std::uint64_t, std::int64_t>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const std::vector<std::uint64_t>& constant_unsigned_integer_denominator_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share, std::size_t iteration_1,
    std::size_t iteration_2) const;

template <typename FLType, typename T, typename T_int>
std::vector<ShareWrapper> SecureDPMechanismHelper::FLGeometricDistributionEXP(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
    std::size_t iteration_2) const {
  std::size_t num_of_simd = constant_unsigned_integer_numerator_vector.size();

  assert(random_floating_point_0_1_boolean_gmw_share->GetNumberOfSimdValues() ==
         (iteration_2)*num_of_simd);

  // if numerator or denominator are all ones, we can avoid some computations in MPC
  bool numerator_are_all_ones =
      VectorAllEqualToValue<T>(constant_unsigned_integer_numerator_vector, T(1));
  bool denominator_are_all_ones = true;

  // case 2
  // if the denominator vector's elements are all ones, we can save computations
  std::vector<FLType> vector_of_exp_neg_one(num_of_simd * iteration_2, std::exp(-1.0));
  SecureFloatingPointCircuitABY floating_point_constant_exp_neg_one =
      SecureFloatingPointCircuitABY(share_->GetBackend().ConstantAsBooleanGmwInput(
          ToInput<FLType, std::true_type>(vector_of_exp_neg_one)));

  ShareWrapper floating_point_Bernoulli_distribution_parameter_p =
      floating_point_constant_exp_neg_one.Get();
  ShareWrapper boolean_gmw_share_Bernoulli_sample =
      SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_share) <
      SecureFloatingPointCircuitABY(floating_point_Bernoulli_distribution_parameter_p);

  std::vector<ShareWrapper> boolean_gmw_share_Bernoulli_sample_unsimdify =
      boolean_gmw_share_Bernoulli_sample.Unsimdify();

  std::vector<ShareWrapper> boolean_gmw_share_Bernoulli_sample_part_2_vector(
      boolean_gmw_share_Bernoulli_sample_unsimdify.begin(),
      boolean_gmw_share_Bernoulli_sample_unsimdify.begin() + iteration_2 * num_of_simd);

  std::vector<ShareWrapper> boolean_gmw_share_b2_vector =
      SecureDPMechanismHelper::SimdifyReshapeHorizontal(
          boolean_gmw_share_Bernoulli_sample_part_2_vector, iteration_2, num_of_simd);

  std::vector<ShareWrapper> boolean_gmw_share_constant_j;
  boolean_gmw_share_constant_j.reserve(iteration_2);
  for (std::size_t j = 0; j < iteration_2; j++) {
    std::vector<T> vector_of_constant_j(num_of_simd, j);
    boolean_gmw_share_constant_j.emplace_back(
        share_->GetBackend().ConstantAsBooleanGmwInput(ToInput<T>(vector_of_constant_j)));
  }

  // invert boolean_gmw_share_b2_vector
  std::vector<ShareWrapper> boolean_gmw_share_b2_invert_vector;
  boolean_gmw_share_b2_invert_vector.reserve(iteration_2);
  for (std::size_t i = 0; i < iteration_2; i++) {
    boolean_gmw_share_b2_invert_vector.emplace_back(~boolean_gmw_share_b2_vector[i]);
  }

  std::vector<ShareWrapper> boolean_gmw_share_v =
      InvertBinaryTreeSelection(boolean_gmw_share_constant_j, boolean_gmw_share_b2_invert_vector);

  // save MPC computation here
  SecureUnsignedInteger unsigned_integer_w = SecureUnsignedInteger(boolean_gmw_share_v[0]);

  // case 2.1
  // the numerator's vector elements are not all ones
  if (!numerator_are_all_ones) {
    ShareWrapper unsigned_integer_boolean_gmw_share_numerator =
        (share_->GetBackend().ConstantAsBooleanGmwInput(
            ToInput<T>(constant_unsigned_integer_numerator_vector)));

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
  // if the numerator's vector elements are all ones, we can save computations
  else {
    // save MPC computation here
    SecureUnsignedInteger unsigned_integer_geometric_sample = unsigned_integer_w;

    ShareWrapper boolean_gmw_share_success_flag = (boolean_gmw_share_v[1]);

    std::vector<ShareWrapper> result_vector;
    result_vector.reserve(2);
    result_vector.emplace_back(unsigned_integer_geometric_sample.Get());
    result_vector.emplace_back(boolean_gmw_share_success_flag);

    return result_vector;
  }
}

template std::vector<ShareWrapper>
SecureDPMechanismHelper::FLGeometricDistributionEXP<float, std::uint64_t, std::int64_t>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share, std::size_t iteration_2) const;

template std::vector<ShareWrapper>
SecureDPMechanismHelper::FLGeometricDistributionEXP<double, std::uint64_t, std::int64_t>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share, std::size_t iteration_2) const;

template <typename FLType, typename T, typename T_int>
std::vector<ShareWrapper> SecureDPMechanismHelper::FLDiscreteLaplaceDistribution(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const std::vector<std::uint64_t>& constant_unsigned_integer_denominator_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample, std::size_t iteration_1,
    std::size_t iteration_2, std::size_t iteration_3) const {
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

  std::vector<std::uint64_t> constant_unsigned_integer_numerator_geo_vector(num_of_simd_total);
  std::vector<std::uint64_t> constant_unsigned_integer_denominator_geo_vector(num_of_simd_total);
  for (std::size_t i = 0; i < num_of_simd_dlap; i++) {
    for (std::size_t j = 0; j < num_of_simd_geo; j++) {
      constant_unsigned_integer_numerator_geo_vector[i * num_of_simd_geo + j] =
          constant_unsigned_integer_numerator_vector[i];
      constant_unsigned_integer_denominator_geo_vector[i * num_of_simd_geo + j] =
          constant_unsigned_integer_denominator_vector[i];
    }
  }

  std::vector<ShareWrapper> geometric_sample_vector = FLGeometricDistributionEXP<FLType, T, T_int>(
      constant_unsigned_integer_numerator_geo_vector,
      constant_unsigned_integer_denominator_geo_vector, random_floating_point_0_1_boolean_gmw_share,
      random_unsigned_integer_boolean_gmw_share, iteration_1, iteration_2);

  ShareWrapper boolean_gmw_share_sign = boolean_gmw_share_bernoulli_sample;
  ShareWrapper unsigned_integer_geometric_sample_boolean_gmw_share_magnitude =
      geometric_sample_vector[0];
  ShareWrapper boolean_gmw_share_magnitude_EQZ =
      SecureSignedInteger(unsigned_integer_geometric_sample_boolean_gmw_share_magnitude).EQZ();

  // magnitude*(1-2*sign)
  SecureSignedInteger signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign =
      SecureSignedInteger(unsigned_integer_geometric_sample_boolean_gmw_share_magnitude)
          .Neg(boolean_gmw_share_sign);

  ShareWrapper boolean_gmw_share_choice =
      ~(boolean_gmw_share_sign & boolean_gmw_share_magnitude_EQZ) & geometric_sample_vector[1];

  std::vector<ShareWrapper>
      signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign_reshape_vector =
          SecureDPMechanismHelper::SimdifyReshapeHorizontal(
              signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign.Get().Unsimdify(),
              iteration_3, num_of_simd_dlap);

  std::vector<ShareWrapper> boolean_gmw_share_choice_reshape_vector =
      SecureDPMechanismHelper::SimdifyReshapeHorizontal(boolean_gmw_share_choice.Unsimdify(),
                                                        iteration_3, num_of_simd_dlap);

  std::vector<ShareWrapper> boolean_gmw_share_discrete_laplace_sample_vector =
      InvertBinaryTreeSelection(
          signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign_reshape_vector,
          boolean_gmw_share_choice_reshape_vector);

  return boolean_gmw_share_discrete_laplace_sample_vector;
}

template std::vector<ShareWrapper>
SecureDPMechanismHelper::FLDiscreteLaplaceDistribution<float, std::uint64_t, std::int64_t>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const std::vector<std::uint64_t>& constant_unsigned_integer_denominator_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample, std::size_t iteration_1,
    std::size_t iteration_2, std::size_t iteration_3) const;

template std::vector<ShareWrapper>
SecureDPMechanismHelper::FLDiscreteLaplaceDistribution<double, std::uint64_t, std::int64_t>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const std::vector<std::uint64_t>& constant_unsigned_integer_denominator_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample, std::size_t iteration_1,
    std::size_t iteration_2, std::size_t iteration_3) const;

template <typename FLType, typename T, typename T_int>
std::vector<ShareWrapper> SecureDPMechanismHelper::FLDiscreteLaplaceDistribution(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample, std::size_t iteration_2,
    std::size_t iteration_3) const {
  // same as FLGeometricDistributionEXP except with more iteration_3
  std::size_t num_of_simd_geo = iteration_3;
  std::size_t num_of_simd_dlap = constant_unsigned_integer_numerator_vector.size();
  std::size_t num_of_simd_total = num_of_simd_dlap * num_of_simd_geo;
  
  assert(random_floating_point_0_1_boolean_gmw_share->GetNumberOfSimdValues() ==
         (iteration_2)*num_of_simd_total);
  assert(boolean_gmw_share_bernoulli_sample->GetNumberOfSimdValues() == num_of_simd_total);

  std::vector<std::uint64_t> constant_unsigned_integer_numerator_geo_vector(num_of_simd_total);
  for (std::size_t i = 0; i < num_of_simd_dlap; i++) {
    for (std::size_t j = 0; j < num_of_simd_geo; j++) {
      constant_unsigned_integer_numerator_geo_vector[i * num_of_simd_geo + j] =
          constant_unsigned_integer_numerator_vector[i];
    }
  }

  std::vector<ShareWrapper> geometric_sample_vector = FLGeometricDistributionEXP<FLType, T, T_int>(
      constant_unsigned_integer_numerator_geo_vector, random_floating_point_0_1_boolean_gmw_share,
      iteration_2);

  ShareWrapper boolean_gmw_share_sign = boolean_gmw_share_bernoulli_sample;
  ShareWrapper unsigned_integer_geometric_sample_boolean_gmw_share_magnitude =
      geometric_sample_vector[0];
  ShareWrapper boolean_gmw_share_magnitude_EQZ =
      SecureSignedInteger(unsigned_integer_geometric_sample_boolean_gmw_share_magnitude).EQZ();

  // magnitude*(1-2*sign)
  SecureSignedInteger signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign =
      SecureSignedInteger(unsigned_integer_geometric_sample_boolean_gmw_share_magnitude)
          .Neg(boolean_gmw_share_sign);

  ShareWrapper boolean_gmw_share_choice =
      ~(boolean_gmw_share_sign & boolean_gmw_share_magnitude_EQZ) & geometric_sample_vector[1];

  std::vector<ShareWrapper>
      signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign_reshape_vector =
          SecureDPMechanismHelper::SimdifyReshapeHorizontal(
              signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign.Get().Unsimdify(),
              iteration_3, num_of_simd_dlap);

  std::vector<ShareWrapper> boolean_gmw_share_choice_reshape_vector =
      SecureDPMechanismHelper::SimdifyReshapeHorizontal(boolean_gmw_share_choice.Unsimdify(),
                                                        iteration_3, num_of_simd_dlap);

  std::vector<ShareWrapper> boolean_gmw_share_discrete_laplace_sample_vector =
      InvertBinaryTreeSelection(
          signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign_reshape_vector,
          boolean_gmw_share_choice_reshape_vector);

  return boolean_gmw_share_discrete_laplace_sample_vector;
}

template std::vector<ShareWrapper>
SecureDPMechanismHelper::FLDiscreteLaplaceDistribution<float, std::uint64_t, std::int64_t>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample, std::size_t iteration_2,
    std::size_t iteration_3) const;

template std::vector<ShareWrapper>
SecureDPMechanismHelper::FLDiscreteLaplaceDistribution<double, std::uint64_t, std::int64_t>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample, std::size_t iteration_2,
    std::size_t iteration_3) const;

template <typename FLType, typename T, typename T_int>
std::vector<ShareWrapper> SecureDPMechanismHelper::FLDiscreteGaussianDistribution(
    const std::vector<double>& constant_floating_point_sigma_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share_dlap,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau, std::size_t iteration_1,
    std::size_t iteration_2, std::size_t iteration_3, std::size_t iteration_4,
    std::size_t upscale_factor) const {
  std::size_t FLType_size = sizeof(FLType) * 8;

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

  std::vector<T> constant_unsigned_integer_t_vector(num_of_simd_dgau);
  for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
    constant_unsigned_integer_t_vector[i] = floor(constant_floating_point_sigma_vector[i]) + 1;
  }

  std::vector<T> constant_unsigned_integer_numerator_dlap_vector(num_of_simd_dgau *
                                                                 num_of_simd_dlap);
  std::vector<T> constant_unsigned_integer_denominator_dlap_vector(num_of_simd_dgau *
                                                                   num_of_simd_dlap);

  for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
    for (std::size_t j = 0; j < num_of_simd_dlap; j++) {
      constant_unsigned_integer_denominator_dlap_vector[i * num_of_simd_dlap + j] =
          constant_unsigned_integer_t_vector[i] * T(upscale_factor);
      constant_unsigned_integer_numerator_dlap_vector[i * num_of_simd_dlap + j] =
          T(1) * T(upscale_factor);
    }
  }

  std::vector<ShareWrapper> boolean_gmw_share_discrete_laplace_sample_vector =
      FLDiscreteLaplaceDistribution<FLType, T, T_int>(
          constant_unsigned_integer_numerator_dlap_vector,
          constant_unsigned_integer_denominator_dlap_vector,
          random_floating_point_0_1_boolean_gmw_share_dlap,
          random_unsigned_integer_boolean_gmw_share_dlap, boolean_gmw_share_bernoulli_sample_dlap,
          iteration_1, iteration_2, iteration_3);

  std::vector<FLType> constant_floating_point_sigma_square_div_t_vector(num_of_simd_dgau);
  std::vector<FLType> constant_floating_point_two_mul_sigma_square_vector(num_of_simd_dgau);
  for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
    constant_floating_point_sigma_square_div_t_vector[i] =
        constant_floating_point_sigma_vector[i] * constant_floating_point_sigma_vector[i] /
        FLType(constant_unsigned_integer_t_vector[i]);
    constant_floating_point_two_mul_sigma_square_vector[i] =
        2.0 * constant_floating_point_sigma_vector[i] * constant_floating_point_sigma_vector[i];
  }

  SecureFloatingPointCircuitABY constant_floating_point_sigma_square_div_t =
      SecureFloatingPointCircuitABY(share_->GetBackend().ConstantAsBooleanGmwInput(
          ToInput<FLType, std::true_type>(constant_floating_point_sigma_square_div_t_vector)));

  SecureFloatingPointCircuitABY constant_floating_point_two_mul_pow2_sigma =
      SecureFloatingPointCircuitABY(share_->GetBackend().ConstantAsBooleanGmwInput(
          ToInput<FLType, std::true_type>(constant_floating_point_two_mul_sigma_square_vector)));

  ShareWrapper boolean_gmw_share_Y = boolean_gmw_share_discrete_laplace_sample_vector[0];
  SecureFloatingPointCircuitABY floating_point_C_bernoulli_parameter =
      (((SecureSignedInteger(boolean_gmw_share_Y).Int2FL(FLType_size).Abs() -
         SecureFloatingPointCircuitABY(
             ShareWrapper::Simdify(SecureDPMechanismHelper::SimdifyDuplicateVertical(
                 constant_floating_point_sigma_square_div_t.Get().Unsimdify(), iteration_4))))
            .Sqr()) /
       (SecureFloatingPointCircuitABY(
           ShareWrapper::Simdify(SecureDPMechanismHelper::SimdifyDuplicateVertical(
               constant_floating_point_two_mul_pow2_sigma.Get().Unsimdify(), iteration_4)))))
          .Neg()
          .Exp();

  ShareWrapper boolean_gmw_share_bernoulli =
      SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_share_dgau) <
      floating_point_C_bernoulli_parameter;

  ShareWrapper boolean_gmw_share_choice =
      boolean_gmw_share_bernoulli & boolean_gmw_share_discrete_laplace_sample_vector[1];

  std::vector<ShareWrapper> boolean_gmw_share_Y_reshape =
      SecureDPMechanismHelper::SimdifyReshapeHorizontal(boolean_gmw_share_Y.Unsimdify(),
                                                        iteration_4, num_of_simd_dgau);
  std::vector<ShareWrapper> boolean_gmw_share_choice_reshape =
      SecureDPMechanismHelper::SimdifyReshapeHorizontal(boolean_gmw_share_choice.Unsimdify(),
                                                        iteration_4, num_of_simd_dgau);

  std::vector<ShareWrapper> boolean_gmw_share_result_vector =
      InvertBinaryTreeSelection(boolean_gmw_share_Y_reshape, boolean_gmw_share_choice_reshape);

  return boolean_gmw_share_result_vector;
}

template std::vector<ShareWrapper>
SecureDPMechanismHelper::FLDiscreteGaussianDistribution<float, std::uint64_t, std::int64_t>(
    const std::vector<double>& constant_floating_point_sigma_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share_dlap,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau, std::size_t iteration_1,
    std::size_t iteration_2, std::size_t iteration_3, std::size_t iteration_4,
    std::size_t upscale_factor) const;

template std::vector<ShareWrapper>
SecureDPMechanismHelper::FLDiscreteGaussianDistribution<double, std::uint64_t, std::int64_t>(
    const std::vector<double>& constant_floating_point_sigma_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share_dlap,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau, std::size_t iteration_1,
    std::size_t iteration_2, std::size_t iteration_3, std::size_t iteration_4,
    std::size_t upscale_factor) const;

template <typename FLType, typename T, typename T_int>
std::vector<ShareWrapper> SecureDPMechanismHelper::FLDiscreteGaussianDistribution(
    const std::vector<double>& constant_floating_point_sigma_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau, std::size_t iteration_2,
    std::size_t iteration_3, std::size_t iteration_4) const {
  std::size_t FLType_size = sizeof(FLType) * 8;

  std::size_t num_of_simd_dgau = constant_floating_point_sigma_vector.size();
  std::size_t num_of_simd_geo = iteration_3;
  std::size_t num_of_simd_dlap = iteration_4;
  std::size_t num_of_simd_total = num_of_simd_dlap * num_of_simd_geo * num_of_simd_dgau;

  assert(random_floating_point_0_1_boolean_gmw_share_dlap->GetNumberOfSimdValues() ==
         (iteration_2)*num_of_simd_total);

  assert(boolean_gmw_share_bernoulli_sample_dlap->GetNumberOfSimdValues() == num_of_simd_total);
  assert(random_floating_point_0_1_boolean_gmw_share_dgau->GetNumberOfSimdValues() ==
         iteration_4 * num_of_simd_dgau);

  std::vector<T> constant_unsigned_integer_t_vector(num_of_simd_dgau);
  for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
    constant_unsigned_integer_t_vector[i] = floor(constant_floating_point_sigma_vector[i]) + 1;
  }

  // t = 1
  assert(VectorAllEqualToValue<T>(constant_unsigned_integer_t_vector, T(1)));

  std::vector<T> constant_unsigned_integer_numerator_dlap_vector(num_of_simd_dgau *
                                                                 num_of_simd_dlap);

  for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
    for (std::size_t j = 0; j < num_of_simd_dlap; j++) {
      constant_unsigned_integer_numerator_dlap_vector[i * num_of_simd_dlap + j] = T(1);
    }
  }

  std::vector<ShareWrapper> boolean_gmw_share_discrete_laplace_sample_vector =
      FLDiscreteLaplaceDistribution<FLType, T, T_int>(
          constant_unsigned_integer_numerator_dlap_vector,
          random_floating_point_0_1_boolean_gmw_share_dlap, boolean_gmw_share_bernoulli_sample_dlap,
          iteration_2, iteration_3);

  std::vector<FLType> constant_floating_point_sigma_square_div_t_vector(num_of_simd_dgau);
  std::vector<FLType> constant_floating_point_two_mul_sigma_square_vector(num_of_simd_dgau);
  for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
    constant_floating_point_sigma_square_div_t_vector[i] =
        constant_floating_point_sigma_vector[i] * constant_floating_point_sigma_vector[i];
    constant_floating_point_two_mul_sigma_square_vector[i] =
        2.0 * constant_floating_point_sigma_vector[i] * constant_floating_point_sigma_vector[i];
  }

  SecureFloatingPointCircuitABY constant_floating_point_sigma_square_div_t =
      SecureFloatingPointCircuitABY(share_->GetBackend().ConstantAsBooleanGmwInput(
          ToInput<FLType, std::true_type>(constant_floating_point_sigma_square_div_t_vector)));

  SecureFloatingPointCircuitABY constant_floating_point_two_mul_pow2_sigma =
      SecureFloatingPointCircuitABY(share_->GetBackend().ConstantAsBooleanGmwInput(
          ToInput<FLType, std::true_type>(constant_floating_point_two_mul_sigma_square_vector)));

  ShareWrapper boolean_gmw_share_Y = boolean_gmw_share_discrete_laplace_sample_vector[0];
  SecureFloatingPointCircuitABY floating_point_C_bernoulli_parameter =
      (((SecureSignedInteger(boolean_gmw_share_Y).Int2FL(FLType_size).Abs() -
         SecureFloatingPointCircuitABY(
             ShareWrapper::Simdify(SecureDPMechanismHelper::SimdifyDuplicateVertical(
                 constant_floating_point_sigma_square_div_t.Get().Unsimdify(), iteration_4))))
            .Sqr()) /
       (SecureFloatingPointCircuitABY(
           ShareWrapper::Simdify(SecureDPMechanismHelper::SimdifyDuplicateVertical(
               constant_floating_point_two_mul_pow2_sigma.Get().Unsimdify(), iteration_4)))))
          .Neg()
          .Exp();

  ShareWrapper boolean_gmw_share_bernoulli =
      SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_share_dgau) <
      floating_point_C_bernoulli_parameter;

  ShareWrapper boolean_gmw_share_choice =
      boolean_gmw_share_bernoulli & boolean_gmw_share_discrete_laplace_sample_vector[1];

  std::vector<ShareWrapper> boolean_gmw_share_Y_reshape =
      SecureDPMechanismHelper::SimdifyReshapeHorizontal(boolean_gmw_share_Y.Unsimdify(),
                                                        iteration_4, num_of_simd_dgau);
  std::vector<ShareWrapper> boolean_gmw_share_choice_reshape =
      SecureDPMechanismHelper::SimdifyReshapeHorizontal(boolean_gmw_share_choice.Unsimdify(),
                                                        iteration_4, num_of_simd_dgau);

  std::vector<ShareWrapper> boolean_gmw_share_result_vector =
      InvertBinaryTreeSelection(boolean_gmw_share_Y_reshape, boolean_gmw_share_choice_reshape);

  return boolean_gmw_share_result_vector;
}

template std::vector<ShareWrapper>
SecureDPMechanismHelper::FLDiscreteGaussianDistribution<float, std::uint64_t, std::int64_t>(
    const std::vector<double>& constant_floating_point_sigma_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau, std::size_t iteration_2,
    std::size_t iteration_3, std::size_t iteration_4) const;

template std::vector<ShareWrapper>
SecureDPMechanismHelper::FLDiscreteGaussianDistribution<double, std::uint64_t, std::int64_t>(
    const std::vector<double>& constant_floating_point_sigma_vector,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dlap,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share_dgau, std::size_t iteration_2,
    std::size_t iteration_3, std::size_t iteration_4) const;

template <typename FLType, typename IntType, typename IntType_int>
std::vector<ShareWrapper> SecureDPMechanismHelper::FLSymmetricBinomialDistribution(
    std::vector<double> constant_sqrt_n_vector,
    const ShareWrapper& unsigned_integer_boolean_gmw_share_geometric_sample,
    const ShareWrapper& boolean_gmw_share_random_bits,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share, std::size_t iteration) const {
  std::size_t num_of_simd = constant_sqrt_n_vector.size();
  std::size_t FLType_size = sizeof(FLType) * 8;

  assert(unsigned_integer_boolean_gmw_share_geometric_sample->GetNumberOfSimdValues() ==
         iteration * num_of_simd);
  assert(boolean_gmw_share_random_bits->GetNumberOfSimdValues() == iteration * num_of_simd);
  assert(random_unsigned_integer_boolean_gmw_share->GetNumberOfSimdValues() ==
         iteration * num_of_simd);
  assert(random_floating_point_0_1_boolean_gmw_share->GetNumberOfSimdValues() ==
         iteration * num_of_simd);

  std::vector<IntType> constant_m_vector(num_of_simd * iteration);
  std::vector<FLType> constant_m_div_4_vector(num_of_simd * iteration);
  std::vector<IntType> constant_neg_sqrt_n_mul_lnn_div_2_vector(num_of_simd * iteration);
  std::vector<IntType> constant_sqrt_n_mul_lnn_div_2_vector(num_of_simd * iteration);
  std::vector<FLType> constant_p_coefficient_1_vector(num_of_simd * iteration);
  std::vector<FLType> constant_p_coefficient_2_vector(num_of_simd * iteration);
  for (std::size_t i = 0; i < num_of_simd; i++) {
    for (std::size_t j = 0; j < iteration; j++) {
      constant_m_vector[i * iteration + j] =
          IntType(floor(M_SQRT2 * constant_sqrt_n_vector[i] + 1));

      constant_m_div_4_vector[i * iteration + j] =
          FLType(constant_m_vector[i * iteration + j]) / 4.0;

      constant_sqrt_n_mul_lnn_div_2_vector[i * iteration + j] =
          IntType(floor(constant_sqrt_n_vector[i] * log(constant_sqrt_n_vector[i]) / 2));

      constant_neg_sqrt_n_mul_lnn_div_2_vector[i * iteration + j] =
          -constant_sqrt_n_mul_lnn_div_2_vector[i * iteration + j];

      constant_p_coefficient_1_vector[i * iteration + j] =
          sqrt(2.0 / M_PI) / constant_sqrt_n_vector[i] *
          (1.0 - 0.4 * pow(log(constant_sqrt_n_vector[i]) * 2, 1.5) / constant_sqrt_n_vector[i]);

      constant_p_coefficient_2_vector[i * iteration + j] = M_SQRT2 / constant_sqrt_n_vector[i];
    }
  }

  ShareWrapper signed_integer_boolean_gmw_share_s =
      unsigned_integer_boolean_gmw_share_geometric_sample;

  SecureSignedInteger signed_integer_s = SecureSignedInteger(signed_integer_boolean_gmw_share_s);
  SecureSignedInteger signed_integer_neg_s_minus_one = signed_integer_s.Neg() - IntType(1);

  ShareWrapper signed_integer_boolean_gmw_share_k = boolean_gmw_share_random_bits.Mux(
      signed_integer_boolean_gmw_share_s, signed_integer_neg_s_minus_one.Get());

  ShareWrapper signed_integer_constant_boolean_gmw_share_m =
      share_->GetBackend().ConstantAsBooleanGmwInput(ToInput<IntType>(constant_m_vector));
  ShareWrapper floating_point_constant_boolean_gmw_share_m_div_4 =
      share_->GetBackend().ConstantAsBooleanGmwInput(
          ToInput<FLType, std::true_type>(constant_m_div_4_vector));

  SecureSignedInteger signed_integer_i =
      SecureSignedInteger(signed_integer_boolean_gmw_share_k) *
          SecureSignedInteger(signed_integer_constant_boolean_gmw_share_m) +
      SecureSignedInteger(random_unsigned_integer_boolean_gmw_share);

  ShareWrapper constant_boolean_gmw_share_neg_sqrt_n_mul_lnn_div_2 =
      share_->GetBackend().ConstantAsBooleanGmwInput(
          ToInput<IntType>(constant_neg_sqrt_n_mul_lnn_div_2_vector));
  ShareWrapper constant_boolean_gmw_share_sqrt_n_mul_lnn_div_2 =
      share_->GetBackend().ConstantAsBooleanGmwInput(
          ToInput<IntType>(constant_sqrt_n_mul_lnn_div_2_vector));

  ShareWrapper constant_boolean_gmw_share_p_coefficient_1 =
      share_->GetBackend().ConstantAsBooleanGmwInput(
          ToInput<FLType, std::true_type>(constant_p_coefficient_1_vector));
  ShareWrapper constant_boolean_gmw_share_p_coefficient_2 =
      share_->GetBackend().ConstantAsBooleanGmwInput(
          ToInput<FLType, std::true_type>(constant_p_coefficient_2_vector));
  ShareWrapper boolean_gmw_share_i_in_range_condition = signed_integer_i.InRange(
      SecureSignedInteger(constant_boolean_gmw_share_sqrt_n_mul_lnn_div_2));

  SecureFloatingPointCircuitABY floating_point_p_i =
      SecureFloatingPointCircuitABY(constant_boolean_gmw_share_p_coefficient_1) *
      ((((SecureFloatingPointCircuitABY(constant_boolean_gmw_share_p_coefficient_2) *
          signed_integer_i.Int2FL(FLType_size))
             .Sqr())
            .Neg())
           .Exp());

  SecureFloatingPointCircuitABY floating_point_pow2_s =
      (signed_integer_s.Int2FL(FLType_size)).Exp2();

  SecureFloatingPointCircuitABY floating_point_p_i_mul_f =
      floating_point_p_i * floating_point_pow2_s *
      SecureFloatingPointCircuitABY(floating_point_constant_boolean_gmw_share_m_div_4);

  ShareWrapper boolean_gmw_share_Bernoulli_c =
      SecureFloatingPointCircuitABY(random_floating_point_0_1_boolean_gmw_share) <
      floating_point_p_i_mul_f;

  ShareWrapper boolean_gmw_share_choice =
      boolean_gmw_share_i_in_range_condition & boolean_gmw_share_Bernoulli_c;

  std::vector<ShareWrapper> signed_integer_i_reshape_vector =
      SecureDPMechanismHelper::SimdifyReshapeHorizontal(signed_integer_i.Get().Unsimdify(),
                                                        iteration, num_of_simd);
  std::vector<ShareWrapper> boolean_gmw_share_choice_reshape_vector =
      SecureDPMechanismHelper::SimdifyReshapeHorizontal(boolean_gmw_share_choice.Unsimdify(),
                                                        iteration, num_of_simd);

  std::vector<ShareWrapper> boolean_gmw_share_result_vector = InvertBinaryTreeSelection(
      signed_integer_i_reshape_vector, boolean_gmw_share_choice_reshape_vector);

  return boolean_gmw_share_result_vector;
}

// constant_sqrt_n * sqrt(2) < 2^(64)
template std::vector<ShareWrapper>
SecureDPMechanismHelper::FLSymmetricBinomialDistribution<double, std::uint64_t, std::int64_t>(
    std::vector<double> constant_sqrt_n_vector,
    const ShareWrapper& unsigned_integer_boolean_gmw_share_geometric_sample,
    const ShareWrapper& boolean_gmw_share_random_bits,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share, std::size_t iteration) const;

// constant_sqrt_n * sqrt(2) < 2^(128)
template std::vector<ShareWrapper>
SecureDPMechanismHelper::FLSymmetricBinomialDistribution<double, __uint128_t, __int128_t>(
    std::vector<double> constant_sqrt_n_vector,
    const ShareWrapper& unsigned_integer_boolean_gmw_share_geometric_sample,
    const ShareWrapper& boolean_gmw_share_random_bits,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share,
    const ShareWrapper& random_floating_point_0_1_boolean_gmw_share, std::size_t iteration) const;

template <typename FxType, typename T, typename T_int>
std::vector<ShareWrapper> SecureDPMechanismHelper::FxGeometricDistributionEXP(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const std::vector<std::uint64_t>& constant_unsigned_integer_denominator_vector,
    const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share, std::size_t iteration_1,
    std::size_t iteration_2, std::size_t fixed_point_fraction_bit_size) const {
  std::size_t num_of_simd = constant_unsigned_integer_numerator_vector.size();

  assert(constant_unsigned_integer_numerator_vector.size() ==
         constant_unsigned_integer_denominator_vector.size());
  assert(random_fixed_point_0_1_boolean_gmw_share->GetNumberOfSimdValues() ==
         (iteration_1 + iteration_2) * num_of_simd);
  assert(random_unsigned_integer_boolean_gmw_share->GetNumberOfSimdValues() ==
         iteration_1 * num_of_simd);

  // if numerator or denominator are all ones, we can avoid some computations in MPC
  bool numerator_are_all_ones =
      VectorAllEqualToValue<T>(constant_unsigned_integer_numerator_vector, T(1));
  bool denominator_are_all_ones =
      VectorAllEqualToValue<T>(constant_unsigned_integer_denominator_vector, T(1));

  assert(!denominator_are_all_ones);

  // case 1: denominator are not all ones
  ShareWrapper unsigned_integer_boolean_gmw_share_denominator =
      (share_->GetBackend().ConstantAsBooleanGmwInput(
          ToInput<T>(constant_unsigned_integer_denominator_vector)));

  // convert denominator to fixed point type in plaintext instead of converting in MPC computation
  std::vector<FxType> constant_fixed_point_denominator_vector(num_of_simd);
  for (std::size_t i = 0; i < num_of_simd; i++) {
    T denominator_tmp = constant_unsigned_integer_denominator_vector[i];
    constant_fixed_point_denominator_vector[i] = FxType(T_int(denominator_tmp));
  }

  ShareWrapper fixed_point_boolean_gmw_share_denominator =
      (share_->GetBackend().ConstantAsBooleanGmwInput(FixedPointToInput<T, T_int>(
          constant_fixed_point_denominator_vector, fixed_point_fraction_bit_size)));

  std::vector<ShareWrapper> fixed_point_boolean_gmw_share_denominator_expand =
      SecureDPMechanismHelper::SimdifyDuplicateVertical(
          fixed_point_boolean_gmw_share_denominator.Unsimdify(), iteration_1);

  ShareWrapper fixed_point_boolean_gmw_share_denominator_simdify =
      ShareWrapper::Simdify(fixed_point_boolean_gmw_share_denominator_expand);

  SecureFixedPointCircuitCBMC fixed_point_random_unsigned_integer =
      SecureUnsignedInteger(random_unsigned_integer_boolean_gmw_share)
          .Int2Fx(fixed_point_fraction_bit_size);

  SecureFixedPointCircuitCBMC fixed_point_unsigned_integer_denominator_simdify =
      SecureFixedPointCircuitCBMC(fixed_point_boolean_gmw_share_denominator_simdify);

  SecureFixedPointCircuitCBMC fixed_point_random_unsigned_integer_div_denominator =
      fixed_point_random_unsigned_integer / fixed_point_unsigned_integer_denominator_simdify;

  SecureFixedPointCircuitCBMC fixed_point_exp_neg_random_unsigned_integer_div_denominator =
      fixed_point_random_unsigned_integer_div_denominator.Neg().Exp();

  std::vector<FxType> vector_of_exp_neg_one(num_of_simd * iteration_2, std::exp(-1.0));
  SecureFixedPointCircuitCBMC fixed_point_constant_exp_neg_one =
      SecureFixedPointCircuitCBMC(share_->GetBackend().ConstantAsBooleanGmwInput(
          FixedPointToInput<T, T_int>(vector_of_exp_neg_one, fixed_point_fraction_bit_size)));

  ShareWrapper fixed_point_Bernoulli_distribution_parameter_p = ShareWrapper::Simdify(
      std::vector{fixed_point_exp_neg_random_unsigned_integer_div_denominator.Get(),
                  fixed_point_constant_exp_neg_one.Get()});

  ShareWrapper boolean_gmw_share_Bernoulli_sample =
      SecureFixedPointCircuitCBMC(random_fixed_point_0_1_boolean_gmw_share) <
      SecureFixedPointCircuitCBMC(fixed_point_Bernoulli_distribution_parameter_p);

  std::vector<ShareWrapper> boolean_gmw_share_Bernoulli_sample_unsimdify =
      boolean_gmw_share_Bernoulli_sample.Unsimdify();
  std::vector<ShareWrapper> boolean_gmw_share_Bernoulli_sample_part_1_vector(
      boolean_gmw_share_Bernoulli_sample_unsimdify.begin(),
      boolean_gmw_share_Bernoulli_sample_unsimdify.begin() + iteration_1 * num_of_simd);

  std::vector<ShareWrapper> boolean_gmw_share_Bernoulli_sample_part_2_vector(
      boolean_gmw_share_Bernoulli_sample_unsimdify.begin() + iteration_1 * num_of_simd,
      boolean_gmw_share_Bernoulli_sample_unsimdify.begin() + iteration_1 * num_of_simd +
          iteration_2 * num_of_simd);

  std::vector<ShareWrapper> boolean_gmw_share_b1_vector =
      SecureDPMechanismHelper::SimdifyReshapeHorizontal(
          boolean_gmw_share_Bernoulli_sample_part_1_vector, iteration_1, num_of_simd);

  std::vector<ShareWrapper> boolean_gmw_share_b2_vector =
      SecureDPMechanismHelper::SimdifyReshapeHorizontal(
          boolean_gmw_share_Bernoulli_sample_part_2_vector, iteration_2, num_of_simd);

  ShareWrapper random_unsigned_integer_boolean_gmw_share_clone =
      random_unsigned_integer_boolean_gmw_share;

  std::vector<ShareWrapper> random_unsigned_integer_boolean_gmw_share_unsimdify =
      random_unsigned_integer_boolean_gmw_share_clone.Unsimdify();

  std::vector<ShareWrapper> random_unsigned_integer_boolean_gmw_share_for_b1_vector =
      SecureDPMechanismHelper::SimdifyReshapeHorizontal(
          random_unsigned_integer_boolean_gmw_share_unsimdify, iteration_1, num_of_simd);

  std::vector<ShareWrapper> boolean_gmw_share_u = InvertBinaryTreeSelection(
      random_unsigned_integer_boolean_gmw_share_for_b1_vector, boolean_gmw_share_b1_vector);

  std::vector<ShareWrapper> boolean_gmw_share_constant_j;
  boolean_gmw_share_constant_j.reserve(iteration_2);
  for (std::size_t j = 0; j < iteration_2; j++) {
    std::vector<T> vector_of_constant_j(num_of_simd, j);
    boolean_gmw_share_constant_j.emplace_back(
        share_->GetBackend().ConstantAsBooleanGmwInput(ToInput<T>(vector_of_constant_j)));
  }

  std::vector<ShareWrapper> boolean_gmw_share_b2_invert_vector;
  boolean_gmw_share_b2_invert_vector.reserve(iteration_2);
  for (std::size_t i = 0; i < iteration_2; i++) {
    boolean_gmw_share_b2_invert_vector.emplace_back(~boolean_gmw_share_b2_vector[i]);
  }

  std::vector<ShareWrapper> boolean_gmw_share_v =
      InvertBinaryTreeSelection(boolean_gmw_share_constant_j, boolean_gmw_share_b2_invert_vector);

  SecureUnsignedInteger unsigned_integer_w =
      SecureUnsignedInteger(boolean_gmw_share_v[0]) *
          SecureUnsignedInteger(unsigned_integer_boolean_gmw_share_denominator) +
      SecureUnsignedInteger(boolean_gmw_share_u[0]);

  // case 1.1
  // numerator's vector elements are not all equal to one
  if (!numerator_are_all_ones) {
    ShareWrapper unsigned_integer_boolean_gmw_share_numerator =
        (share_->GetBackend().ConstantAsBooleanGmwInput(
            ToInput<T>(constant_unsigned_integer_numerator_vector)));

    SecureUnsignedInteger unsigned_integer_geometric_sample =
        unsigned_integer_w / SecureUnsignedInteger(unsigned_integer_boolean_gmw_share_numerator);

    ShareWrapper boolean_gmw_share_success_flag = (boolean_gmw_share_u[1] & boolean_gmw_share_v[1]);

    std::vector<ShareWrapper> result_vector;
    result_vector.reserve(2);
    result_vector.emplace_back(unsigned_integer_geometric_sample.Get());
    result_vector.emplace_back(boolean_gmw_share_success_flag);

    return result_vector;
  }

  // case 1.2
  // if the numerator's vector elements are all equal to one, we can save computations
  else {
    // save MPC computation here
    SecureUnsignedInteger unsigned_integer_geometric_sample = unsigned_integer_w;

    ShareWrapper boolean_gmw_share_success_flag = (boolean_gmw_share_u[1] & boolean_gmw_share_v[1]);

    std::vector<ShareWrapper> result_vector;
    result_vector.reserve(2);
    result_vector.emplace_back(unsigned_integer_geometric_sample.Get());
    result_vector.emplace_back(boolean_gmw_share_success_flag);

    return result_vector;
  }
}

template std::vector<ShareWrapper>
SecureDPMechanismHelper::FxGeometricDistributionEXP<double, std::uint64_t, std::int64_t>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const std::vector<std::uint64_t>& constant_unsigned_integer_denominator_vector,
    const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share, std::size_t iteration_1,
    std::size_t iteration_2, std::size_t fixed_point_fraction_bit_size) const;

template <typename FxType, typename T, typename T_int>
std::vector<ShareWrapper> SecureDPMechanismHelper::FxGeometricDistributionEXP(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share, std::size_t iteration_2,
    std::size_t fixed_point_fraction_bit_size) const {
  std::size_t num_of_simd = constant_unsigned_integer_numerator_vector.size();

  assert(random_fixed_point_0_1_boolean_gmw_share->GetNumberOfSimdValues() ==
         (iteration_2)*num_of_simd);

  // if numerator or denominator are all ones, we can avoid some computations in MPC
  bool numerator_are_all_ones =
      VectorAllEqualToValue<T>(constant_unsigned_integer_numerator_vector, T(1));
  bool denominator_are_all_ones = true;

  // case 2
  // if the denominator vector's elements are all ones, we can save computations
  std::vector<FxType> vector_of_exp_neg_one(num_of_simd * iteration_2, std::exp(-1.0));
  SecureFixedPointCircuitCBMC fixed_point_constant_exp_neg_one =
      SecureFixedPointCircuitCBMC(share_->GetBackend().ConstantAsBooleanGmwInput(
          FixedPointToInput<T, T_int>(vector_of_exp_neg_one, fixed_point_fraction_bit_size)));
  ShareWrapper fixed_point_Bernoulli_distribution_parameter_p =
      fixed_point_constant_exp_neg_one.Get();

  ShareWrapper boolean_gmw_share_Bernoulli_sample =
      SecureFixedPointCircuitCBMC(random_fixed_point_0_1_boolean_gmw_share) <
      SecureFixedPointCircuitCBMC(fixed_point_Bernoulli_distribution_parameter_p);

  std::vector<ShareWrapper> boolean_gmw_share_Bernoulli_sample_unsimdify =
      boolean_gmw_share_Bernoulli_sample.Unsimdify();

  std::vector<ShareWrapper> boolean_gmw_share_Bernoulli_sample_part_2_vector(
      boolean_gmw_share_Bernoulli_sample_unsimdify.begin(),
      boolean_gmw_share_Bernoulli_sample_unsimdify.begin() + iteration_2 * num_of_simd);

  std::vector<ShareWrapper> boolean_gmw_share_b2_vector = SecureDPMechanismHelper::SimdifyReshapeHorizontal(
      boolean_gmw_share_Bernoulli_sample_part_2_vector, iteration_2, num_of_simd);

  std::vector<ShareWrapper> boolean_gmw_share_constant_j;
  boolean_gmw_share_constant_j.reserve(iteration_2);
  for (std::size_t j = 0; j < iteration_2; j++) {
    std::vector<T> vector_of_constant_j(num_of_simd, j);
    boolean_gmw_share_constant_j.emplace_back(
        share_->GetBackend().ConstantAsBooleanGmwInput(ToInput<T>(vector_of_constant_j)));
  }

  // invert boolean_gmw_share_b2_vector
  std::vector<ShareWrapper> boolean_gmw_share_b2_invert_vector;
  boolean_gmw_share_b2_invert_vector.reserve(iteration_2);
  for (std::size_t i = 0; i < iteration_2; i++) {
    boolean_gmw_share_b2_invert_vector.emplace_back(~boolean_gmw_share_b2_vector[i]);
  }

  std::vector<ShareWrapper> boolean_gmw_share_v =
      InvertBinaryTreeSelection(boolean_gmw_share_constant_j, boolean_gmw_share_b2_invert_vector);

  // save MPC computation here
  SecureUnsignedInteger unsigned_integer_w = SecureUnsignedInteger(boolean_gmw_share_v[0]);

  // case 2.1
  // the numerator's vector elements are not all ones
  if (!numerator_are_all_ones) {
    ShareWrapper unsigned_integer_boolean_gmw_share_numerator =
        (share_->GetBackend().ConstantAsBooleanGmwInput(
            ToInput<T>(constant_unsigned_integer_numerator_vector)));
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
  // if the numerator's vector elements are all ones, we can save computations
  else {
    // save MPC computation here
    SecureUnsignedInteger unsigned_integer_geometric_sample = unsigned_integer_w;

    ShareWrapper boolean_gmw_share_success_flag = (boolean_gmw_share_v[1]);

    std::vector<ShareWrapper> result_vector;
    result_vector.reserve(2);
    result_vector.emplace_back(unsigned_integer_geometric_sample.Get());
    result_vector.emplace_back(boolean_gmw_share_success_flag);

    return result_vector;
  }
}

template std::vector<ShareWrapper>
SecureDPMechanismHelper::FxGeometricDistributionEXP<double, std::uint64_t, std::int64_t>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share, std::size_t iteration_2,
    std::size_t fixed_point_fraction_bit_size) const;

template <typename FxType, typename T, typename T_int>
std::vector<ShareWrapper> SecureDPMechanismHelper::FxDiscreteLaplaceDistribution(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const std::vector<std::uint64_t>& constant_unsigned_integer_denominator_vector,
    const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample, std::size_t iteration_1,
    std::size_t iteration_2, std::size_t iteration_3,
    std::size_t fixed_point_fraction_bit_size) const {
  // same as FxGeometricDistributionEXP except with more iteration_3
  std::size_t num_of_simd_geo = iteration_3;
  std::size_t num_of_simd_dlap = constant_unsigned_integer_numerator_vector.size();
  std::size_t num_of_simd_total = num_of_simd_dlap * num_of_simd_geo;

  assert(constant_unsigned_integer_numerator_vector.size() ==
         constant_unsigned_integer_denominator_vector.size());
  assert(random_fixed_point_0_1_boolean_gmw_share->GetNumberOfSimdValues() ==
         (iteration_1 + iteration_2) * num_of_simd_total);
  assert(random_unsigned_integer_boolean_gmw_share->GetNumberOfSimdValues() ==
         iteration_1 * num_of_simd_total);
  assert(boolean_gmw_share_bernoulli_sample->GetNumberOfSimdValues() == num_of_simd_total);

  std::vector<std::uint64_t> constant_unsigned_integer_numerator_geo_vector(num_of_simd_total);
  std::vector<std::uint64_t> constant_unsigned_integer_denominator_geo_vector(num_of_simd_total);
  for (std::size_t i = 0; i < num_of_simd_dlap; i++) {
    for (std::size_t j = 0; j < num_of_simd_geo; j++) {
      constant_unsigned_integer_numerator_geo_vector[i * num_of_simd_geo + j] =
          constant_unsigned_integer_numerator_vector[i];
      constant_unsigned_integer_denominator_geo_vector[i * num_of_simd_geo + j] =
          constant_unsigned_integer_denominator_vector[i];
    }
  }

  std::vector<ShareWrapper> geometric_sample_vector = FxGeometricDistributionEXP<FxType, T, T_int>(
      constant_unsigned_integer_numerator_geo_vector,
      constant_unsigned_integer_denominator_geo_vector, random_fixed_point_0_1_boolean_gmw_share,
      random_unsigned_integer_boolean_gmw_share, iteration_1, iteration_2,
      fixed_point_fraction_bit_size);

  ShareWrapper boolean_gmw_share_sign = boolean_gmw_share_bernoulli_sample;
  ShareWrapper unsigned_integer_geometric_sample_boolean_gmw_share_magnitude =
      geometric_sample_vector[0];
  ShareWrapper boolean_gmw_share_magnitude_EQZ =
      SecureSignedInteger(unsigned_integer_geometric_sample_boolean_gmw_share_magnitude).EQZ();

  // magnitude*(1-2*sign)
  SecureSignedInteger signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign =
      SecureSignedInteger(unsigned_integer_geometric_sample_boolean_gmw_share_magnitude)
          .Neg(boolean_gmw_share_sign);

  ShareWrapper boolean_gmw_share_choice =
      ~(boolean_gmw_share_sign & boolean_gmw_share_magnitude_EQZ) & geometric_sample_vector[1];

  std::vector<ShareWrapper>
      signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign_reshape_vector =
          SecureDPMechanismHelper::SimdifyReshapeHorizontal(
              signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign.Get().Unsimdify(),
              iteration_3, num_of_simd_dlap);

  std::vector<ShareWrapper> boolean_gmw_share_choice_reshape_vector =
      SecureDPMechanismHelper::SimdifyReshapeHorizontal(boolean_gmw_share_choice.Unsimdify(),
                                                        iteration_3, num_of_simd_dlap);

  std::vector<ShareWrapper> boolean_gmw_share_discrete_laplace_sample_vector =
      InvertBinaryTreeSelection(
          signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign_reshape_vector,
          boolean_gmw_share_choice_reshape_vector);

  return boolean_gmw_share_discrete_laplace_sample_vector;
}

template std::vector<ShareWrapper>
SecureDPMechanismHelper::FxDiscreteLaplaceDistribution<double, std::uint64_t, std::int64_t>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const std::vector<std::uint64_t>& constant_unsigned_integer_denominator_vector,
    const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample, std::size_t iteration_1,
    std::size_t iteration_2, std::size_t iteration_3,
    std::size_t fixed_point_fraction_bit_size) const;

template <typename FxType, typename T, typename T_int>
std::vector<ShareWrapper> SecureDPMechanismHelper::FxDiscreteLaplaceDistribution(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample, std::size_t iteration_2,
    std::size_t iteration_3, std::size_t fixed_point_fraction_bit_size) const {
  // same as FLGeometricDistributionEXP except with more iteration_3
  std::size_t num_of_simd_geo = iteration_3;
  std::size_t num_of_simd_dlap = constant_unsigned_integer_numerator_vector.size();
  std::size_t num_of_simd_total = num_of_simd_dlap * num_of_simd_geo;

  assert(random_fixed_point_0_1_boolean_gmw_share->GetNumberOfSimdValues() ==
         (iteration_2)*num_of_simd_total);
  assert(boolean_gmw_share_bernoulli_sample->GetNumberOfSimdValues() == num_of_simd_total);

  std::vector<std::uint64_t> constant_unsigned_integer_numerator_geo_vector(num_of_simd_total);
  for (std::size_t i = 0; i < num_of_simd_dlap; i++) {
    for (std::size_t j = 0; j < num_of_simd_geo; j++) {
      constant_unsigned_integer_numerator_geo_vector[i * num_of_simd_geo + j] =
          constant_unsigned_integer_numerator_vector[i];
    }
  }
  std::vector<ShareWrapper> geometric_sample_vector = FxGeometricDistributionEXP<FxType, T, T_int>(
      constant_unsigned_integer_numerator_geo_vector, random_fixed_point_0_1_boolean_gmw_share,
      iteration_2, fixed_point_fraction_bit_size);

  ShareWrapper boolean_gmw_share_sign = boolean_gmw_share_bernoulli_sample;
  ShareWrapper unsigned_integer_geometric_sample_boolean_gmw_share_magnitude =
      geometric_sample_vector[0];
  ShareWrapper boolean_gmw_share_magnitude_EQZ =
      SecureSignedInteger(unsigned_integer_geometric_sample_boolean_gmw_share_magnitude).EQZ();

  // magnitude*(1-2*sign)
  SecureSignedInteger signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign =
      SecureSignedInteger(unsigned_integer_geometric_sample_boolean_gmw_share_magnitude)
          .Neg(boolean_gmw_share_sign);

  ShareWrapper boolean_gmw_share_choice =
      ~(boolean_gmw_share_sign & boolean_gmw_share_magnitude_EQZ) & geometric_sample_vector[1];

  std::vector<ShareWrapper>
      signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign_reshape_vector =
          SecureDPMechanismHelper::SimdifyReshapeHorizontal(
              signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign.Get().Unsimdify(),
              iteration_3, num_of_simd_dlap);

  std::vector<ShareWrapper> boolean_gmw_share_choice_reshape_vector =
      SecureDPMechanismHelper::SimdifyReshapeHorizontal(boolean_gmw_share_choice.Unsimdify(),
                                                        iteration_3, num_of_simd_dlap);

  std::vector<ShareWrapper> boolean_gmw_share_discrete_laplace_sample_vector =
      InvertBinaryTreeSelection(
          signed_integer_with_magnitude_mul_one_minus_two_mul_as_sign_reshape_vector,
          boolean_gmw_share_choice_reshape_vector);

  return boolean_gmw_share_discrete_laplace_sample_vector;
}

template std::vector<ShareWrapper>
SecureDPMechanismHelper::FxDiscreteLaplaceDistribution<double, std::uint64_t, std::int64_t>(
    const std::vector<std::uint64_t>& constant_unsigned_integer_numerator_vector,
    const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample, std::size_t iteration_2,
    std::size_t iteration_3, std::size_t fixed_point_fraction_bit_size) const;

template <typename FxType, typename T, typename T_int>
std::vector<ShareWrapper> SecureDPMechanismHelper::FxDiscreteGaussianDistribution(
    const std::vector<double>& constant_fixed_point_sigma_vector,
    const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_dlap,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share_dlap,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
    const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_dgau, std::size_t iteration_1,
    std::size_t iteration_2, std::size_t iteration_3, std::size_t iteration_4,
    std::size_t upscale_factor, std::size_t fixed_point_fraction_bit_size) const {
  std::size_t num_of_simd_dgau = constant_fixed_point_sigma_vector.size();
  std::size_t num_of_simd_geo = iteration_3;
  std::size_t num_of_simd_dlap = iteration_4;
  std::size_t num_of_simd_total = num_of_simd_dlap * num_of_simd_geo * num_of_simd_dgau;

  assert(random_fixed_point_0_1_boolean_gmw_share_dlap->GetNumberOfSimdValues() ==
         (iteration_1 + iteration_2) * num_of_simd_total);
  assert(random_unsigned_integer_boolean_gmw_share_dlap->GetNumberOfSimdValues() ==
         iteration_1 * num_of_simd_total);

  assert(boolean_gmw_share_bernoulli_sample_dlap->GetNumberOfSimdValues() == num_of_simd_total);
  assert(random_fixed_point_0_1_boolean_gmw_share_dgau->GetNumberOfSimdValues() ==
         iteration_4 * num_of_simd_dgau);

  std::vector<T> constant_unsigned_integer_t_vector(num_of_simd_dgau);
  for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
    constant_unsigned_integer_t_vector[i] = floor(constant_fixed_point_sigma_vector[i]) + 1;
  }

  std::vector<T> constant_unsigned_integer_numerator_dlap_vector(num_of_simd_dgau *
                                                                 num_of_simd_dlap);
  std::vector<T> constant_unsigned_integer_denominator_dlap_vector(num_of_simd_dgau *
                                                                   num_of_simd_dlap);

  for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
    for (std::size_t j = 0; j < num_of_simd_dlap; j++) {
      constant_unsigned_integer_denominator_dlap_vector[i * num_of_simd_dlap + j] =
          constant_unsigned_integer_t_vector[i] * T(upscale_factor);
      constant_unsigned_integer_numerator_dlap_vector[i * num_of_simd_dlap + j] =
          T(1) * T(upscale_factor);
    }
  }

  std::vector<ShareWrapper> boolean_gmw_share_discrete_laplace_sample_vector =
      FxDiscreteLaplaceDistribution<FxType, T, T_int>(
          constant_unsigned_integer_numerator_dlap_vector,
          constant_unsigned_integer_denominator_dlap_vector,
          random_fixed_point_0_1_boolean_gmw_share_dlap,
          random_unsigned_integer_boolean_gmw_share_dlap, boolean_gmw_share_bernoulli_sample_dlap,
          iteration_1, iteration_2, iteration_3, fixed_point_fraction_bit_size);

  std::vector<FxType> constant_fixed_point_sigma_square_div_t_vector(num_of_simd_dgau);
  std::vector<FxType> constant_fixed_point_two_mul_sigma_square_vector(num_of_simd_dgau);
  for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
    constant_fixed_point_sigma_square_div_t_vector[i] =
        constant_fixed_point_sigma_vector[i] * constant_fixed_point_sigma_vector[i] /
        FxType(constant_unsigned_integer_t_vector[i]);
    constant_fixed_point_two_mul_sigma_square_vector[i] =
        2.0 * constant_fixed_point_sigma_vector[i] * constant_fixed_point_sigma_vector[i];
  }

  SecureFixedPointCircuitCBMC constant_fixed_point_sigma_square_div_t = SecureFixedPointCircuitCBMC(
      share_->GetBackend().ConstantAsBooleanGmwInput(FixedPointToInput<T, T_int>(
          constant_fixed_point_sigma_square_div_t_vector, fixed_point_fraction_bit_size)));

  SecureFixedPointCircuitCBMC constant_fixed_point_two_mul_pow2_sigma = SecureFixedPointCircuitCBMC(
      share_->GetBackend().ConstantAsBooleanGmwInput(FixedPointToInput<T, T_int>(
          constant_fixed_point_two_mul_sigma_square_vector, fixed_point_fraction_bit_size)));

  ShareWrapper boolean_gmw_share_Y = boolean_gmw_share_discrete_laplace_sample_vector[0];
  SecureFixedPointCircuitCBMC fixed_point_C_bernoulli_parameter =
      (((SecureSignedInteger(boolean_gmw_share_Y).Int2Fx().Abs() -
         SecureFixedPointCircuitCBMC(ShareWrapper::Simdify(SecureDPMechanismHelper::SimdifyDuplicateVertical(
             constant_fixed_point_sigma_square_div_t.Get().Unsimdify(), iteration_4))))
            .Sqr()) /
       (SecureFixedPointCircuitCBMC(ShareWrapper::Simdify(SecureDPMechanismHelper::SimdifyDuplicateVertical(
           constant_fixed_point_two_mul_pow2_sigma.Get().Unsimdify(), iteration_4)))))
          .Neg()
          .Exp();

  ShareWrapper boolean_gmw_share_bernoulli =
      SecureFixedPointCircuitCBMC(random_fixed_point_0_1_boolean_gmw_share_dgau) <
      fixed_point_C_bernoulli_parameter;

  ShareWrapper boolean_gmw_share_choice =
      boolean_gmw_share_bernoulli & boolean_gmw_share_discrete_laplace_sample_vector[1];

  std::vector<ShareWrapper> boolean_gmw_share_Y_reshape = SecureDPMechanismHelper::SimdifyReshapeHorizontal(
      boolean_gmw_share_Y.Unsimdify(), iteration_4, num_of_simd_dgau);
  std::vector<ShareWrapper> boolean_gmw_share_choice_reshape =
      SecureDPMechanismHelper::SimdifyReshapeHorizontal(boolean_gmw_share_choice.Unsimdify(), iteration_4,
                                             num_of_simd_dgau);

  std::vector<ShareWrapper> boolean_gmw_share_result_vector =
      InvertBinaryTreeSelection(boolean_gmw_share_Y_reshape, boolean_gmw_share_choice_reshape);

  return boolean_gmw_share_result_vector;
}

template std::vector<ShareWrapper>
SecureDPMechanismHelper::FxDiscreteGaussianDistribution<double, std::uint64_t, std::int64_t>(
    const std::vector<double>& constant_fixed_point_sigma_vector,
    const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_dlap,
    const ShareWrapper& random_unsigned_integer_boolean_gmw_share_dlap,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
    const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_dgau, std::size_t iteration_1,
    std::size_t iteration_2, std::size_t iteration_3, std::size_t iteration_4,
    std::size_t upscale_factor, std::size_t fixed_point_fraction_bit_size) const;

template <typename FxType, typename T, typename T_int>
std::vector<ShareWrapper> SecureDPMechanismHelper::FxDiscreteGaussianDistribution(
    const std::vector<double>& constant_fixed_point_sigma_vector,
    const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_dlap,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
    const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_dgau, std::size_t iteration_2,
    std::size_t iteration_3, std::size_t iteration_4,
    std::size_t fixed_point_fraction_bit_size) const {
  std::size_t num_of_simd_dgau = constant_fixed_point_sigma_vector.size();
  std::size_t num_of_simd_geo = iteration_3;
  std::size_t num_of_simd_dlap = iteration_4;
  std::size_t num_of_simd_total = num_of_simd_dlap * num_of_simd_geo * num_of_simd_dgau;

  assert(random_fixed_point_0_1_boolean_gmw_share_dlap->GetNumberOfSimdValues() ==
         (iteration_2)*num_of_simd_total);

  assert(boolean_gmw_share_bernoulli_sample_dlap->GetNumberOfSimdValues() == num_of_simd_total);
  assert(random_fixed_point_0_1_boolean_gmw_share_dgau->GetNumberOfSimdValues() ==
         iteration_4 * num_of_simd_dgau);

  std::vector<T> constant_unsigned_integer_t_vector(num_of_simd_dgau);
  for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
    constant_unsigned_integer_t_vector[i] = floor(constant_fixed_point_sigma_vector[i]) + 1;
  }

  // t = 1
  assert(VectorAllEqualToValue<T>(constant_unsigned_integer_t_vector, T(1)));

  std::vector<T> constant_unsigned_integer_numerator_dlap_vector(num_of_simd_dgau *
                                                                 num_of_simd_dlap);

  for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
    for (std::size_t j = 0; j < num_of_simd_dlap; j++) {
      constant_unsigned_integer_numerator_dlap_vector[i * num_of_simd_dlap + j] = T(1);
    }
  }

  std::vector<ShareWrapper> boolean_gmw_share_discrete_laplace_sample_vector =
      FxDiscreteLaplaceDistribution<FxType, T, T_int>(
          constant_unsigned_integer_numerator_dlap_vector,
          random_fixed_point_0_1_boolean_gmw_share_dlap, boolean_gmw_share_bernoulli_sample_dlap,
          iteration_2, iteration_3, fixed_point_fraction_bit_size);

  std::vector<FxType> constant_fixed_point_sigma_square_div_t_vector(num_of_simd_dgau);
  std::vector<FxType> constant_fixed_point_two_mul_sigma_square_vector(num_of_simd_dgau);
  for (std::size_t i = 0; i < num_of_simd_dgau; i++) {
    constant_fixed_point_sigma_square_div_t_vector[i] =
        constant_fixed_point_sigma_vector[i] * constant_fixed_point_sigma_vector[i];
    constant_fixed_point_two_mul_sigma_square_vector[i] =
        2.0 * constant_fixed_point_sigma_vector[i] * constant_fixed_point_sigma_vector[i];
  }

  SecureFixedPointCircuitCBMC constant_fixed_point_sigma_square_div_t = SecureFixedPointCircuitCBMC(
      share_->GetBackend().ConstantAsBooleanGmwInput(FixedPointToInput<T, T_int>(
          constant_fixed_point_sigma_square_div_t_vector, fixed_point_fraction_bit_size)));

  SecureFixedPointCircuitCBMC constant_fixed_point_two_mul_pow2_sigma = SecureFixedPointCircuitCBMC(
      share_->GetBackend().ConstantAsBooleanGmwInput(FixedPointToInput<T, T_int>(
          constant_fixed_point_two_mul_sigma_square_vector, fixed_point_fraction_bit_size)));

  ShareWrapper boolean_gmw_share_Y = boolean_gmw_share_discrete_laplace_sample_vector[0];
  SecureFixedPointCircuitCBMC fixed_point_C_bernoulli_parameter =
      (((SecureSignedInteger(boolean_gmw_share_Y).Int2Fx().Abs() -
         SecureFixedPointCircuitCBMC(
             ShareWrapper::Simdify(SecureDPMechanismHelper::SimdifyDuplicateVertical(
                 constant_fixed_point_sigma_square_div_t.Get().Unsimdify(), iteration_4))))
            .Sqr()) /
       (SecureFixedPointCircuitCBMC(
           ShareWrapper::Simdify(SecureDPMechanismHelper::SimdifyDuplicateVertical(
               constant_fixed_point_two_mul_pow2_sigma.Get().Unsimdify(), iteration_4)))))
          .Neg()
          .Exp();

  ShareWrapper boolean_gmw_share_bernoulli =
      SecureFixedPointCircuitCBMC(random_fixed_point_0_1_boolean_gmw_share_dgau) <
      fixed_point_C_bernoulli_parameter;

  ShareWrapper boolean_gmw_share_choice =
      boolean_gmw_share_bernoulli & boolean_gmw_share_discrete_laplace_sample_vector[1];

  std::vector<ShareWrapper> boolean_gmw_share_Y_reshape =
      SecureDPMechanismHelper::SimdifyReshapeHorizontal(boolean_gmw_share_Y.Unsimdify(),
                                                        iteration_4, num_of_simd_dgau);
  std::vector<ShareWrapper> boolean_gmw_share_choice_reshape =
      SecureDPMechanismHelper::SimdifyReshapeHorizontal(boolean_gmw_share_choice.Unsimdify(),
                                                        iteration_4, num_of_simd_dgau);

  std::vector<ShareWrapper> boolean_gmw_share_result_vector =
      InvertBinaryTreeSelection(boolean_gmw_share_Y_reshape, boolean_gmw_share_choice_reshape);

  return boolean_gmw_share_result_vector;
}

template std::vector<ShareWrapper>
SecureDPMechanismHelper::FxDiscreteGaussianDistribution<double, std::uint64_t, std::int64_t>(
    const std::vector<double>& constant_fixed_point_sigma_vector,
    const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_dlap,
    const ShareWrapper& boolean_gmw_share_bernoulli_sample_dlap,
    const ShareWrapper& random_fixed_point_0_1_boolean_gmw_share_dgau, std::size_t iteration_2,
    std::size_t iteration_3, std::size_t iteration_4,
    std::size_t fixed_point_fraction_bit_size) const;

}  // namespace encrypto::motion
