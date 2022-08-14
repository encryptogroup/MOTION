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

#include "secure_dp_mechanism/secure_snapping_mechanism.h"
#include "base/backend.h"
#include "secure_dp_mechanism/secure_dp_mechanism_helper.h"

namespace encrypto::motion {
SecureSnappingMechanism::SecureSnappingMechanism(const SharePointer& other)
    : fD_(std::make_unique<ShareWrapper>(other)),
      logger_(fD_.get()->Get()->GetRegister()->GetLogger()) {}

SecureSnappingMechanism::SecureSnappingMechanism(SharePointer&& other)
    : fD_(std::make_unique<ShareWrapper>(std::move(other))),
      logger_(fD_.get()->Get()->GetRegister()->GetLogger()) {}

SecureFloatingPointCircuitABY SecureSnappingMechanism::SnappingAndNoiseAddition() {
  using FLType = std::uint64_t;
  using FLType_int = std::int64_t;
  std::size_t num_of_simd = fD_->Get()->GetNumberOfSimdValues();

  ShareWrapper random_bits_of_length_52 =
      SecureDPMechanismHelper(*fD_).GenerateRandomBooleanGmwBits(FLOATINGPOINT_MANTISSA_BITS,
                                                                 num_of_simd);
  ShareWrapper random_bits_of_length_1022 =
      SecureDPMechanismHelper(*fD_).GenerateRandomBooleanGmwBits(FLOATINGPOINT_EXPONENT_BIAS - 1,
                                                                 num_of_simd);
  ShareWrapper boolean_gmw_share_sign_bit = SecureDPMechanismHelper(*fD_).GenerateRandomBooleanGmwBits(1, num_of_simd);

  return SnappingAndNoiseAddition(random_bits_of_length_52, random_bits_of_length_1022,
                                  boolean_gmw_share_sign_bit);
}

SecureFloatingPointCircuitABY SecureSnappingMechanism::SnappingAndNoiseAddition(
    const ShareWrapper& random_bits_of_length_52, const ShareWrapper& random_bits_of_length_1022,
    const ShareWrapper& boolean_gmw_share_sign_bit) {
  using FLType = std::uint64_t;
  using FLType_int = std::int64_t;
  std::size_t num_of_simd = fD_->Get()->GetNumberOfSimdValues();

  FLType m = get_smallest_greater_or_eq_power_of_two(double_to_int<FLType>(lambda_));
  double sigma = pow(2, m);

  SecureFloatingPointCircuitABY floating_point_fD = SecureFloatingPointCircuitABY(*fD_);
  SecureFloatingPointCircuitABY floating_point_clampB_fD = floating_point_fD.ClampB(clamp_B_);

  std::vector<double> vector_of_lambda(num_of_simd, lambda_);

  SecureFloatingPointCircuitABY floating_point_lambda =
      SecureFloatingPointCircuitABY(fD_->Get()->GetBackend().ConstantAsBooleanGmwInput(
          ToInput<double, std::true_type>(vector_of_lambda)));

  ShareWrapper floating_point_boolean_gmw_share_uniform_floating_point_0_1 =
      SecureDPMechanismHelper(*fD_).UniformFloatingPoint64_0_1(random_bits_of_length_52, random_bits_of_length_1022);

  return SnappingAndNoiseAddition(floating_point_boolean_gmw_share_uniform_floating_point_0_1,
                                  boolean_gmw_share_sign_bit);
}

SecureFloatingPointCircuitABY SecureSnappingMechanism::SnappingAndNoiseAddition(
    const ShareWrapper& floating_point_boolean_gmw_share_uniform_floating_point_0_1,
    const ShareWrapper& boolean_gmw_share_sign_bit) {
  using FLType = std::uint64_t;
  using FLType_int = std::int64_t;
  std::size_t num_of_simd = fD_->Get()->GetNumberOfSimdValues();

  FLType m = get_smallest_greater_or_eq_power_of_two(double_to_int<FLType>(lambda_));
  double sigma = pow(2, m);

  SecureFloatingPointCircuitABY floating_point_fD = SecureFloatingPointCircuitABY(*fD_);
  SecureFloatingPointCircuitABY floating_point_clampB_fD = floating_point_fD.ClampB(clamp_B_);

  std::vector<double> vector_of_lambda(num_of_simd, lambda_);

  SecureFloatingPointCircuitABY floating_point_lambda =
      SecureFloatingPointCircuitABY(fD_->Get()->GetBackend().ConstantAsBooleanGmwInput(
          ToInput<double, std::true_type>(vector_of_lambda)));

  // LN(U*)
  SecureFloatingPointCircuitABY floating_point_LN_U_star =
      SecureFloatingPointCircuitABY(floating_point_boolean_gmw_share_uniform_floating_point_0_1)
          .Ln();

  // lambda * LN(U*)
  SecureFloatingPointCircuitABY floating_point_lambda_mul_LN_U_star =
      floating_point_lambda * floating_point_LN_U_star;

  // S * lambda * LN(U*)
  // set S as the sign
  std::vector<ShareWrapper> floating_point_S_mul_lambda_mul_LN_U_star_vector =
      floating_point_lambda_mul_LN_U_star.Get().Split();
  floating_point_S_mul_lambda_mul_LN_U_star_vector.back() =
      floating_point_S_mul_lambda_mul_LN_U_star_vector.back() ^ boolean_gmw_share_sign_bit;

  SecureFloatingPointCircuitABY floating_point_S_mul_lambda_mul_LN_U_star =
      SecureFloatingPointCircuitABY(
          ShareWrapper::Concatenate(floating_point_S_mul_lambda_mul_LN_U_star_vector));

  SecureFloatingPointCircuitABY floating_point_before_round =
      floating_point_clampB_fD + floating_point_S_mul_lambda_mul_LN_U_star;

  // round to multiple of sigma
  // a. divide by m
  SecureFloatingPointCircuitABY floating_point_mul_pow2_m = floating_point_before_round.DivPow2m(m);

  // b. round to nearest integer
  SecureFloatingPointCircuitABY floating_point_round_to_integer =
      floating_point_mul_pow2_m.RoundToNearestInteger();

  // c. multiply by m to round to multiple of sigma
  SecureFloatingPointCircuitABY floating_point_round_to_sigma =
      floating_point_round_to_integer.MulPow2m(m);

  SecureFloatingPointCircuitABY floating_result = floating_point_round_to_sigma.ClampB(clamp_B_);

  // return floating_result.Get();
  return floating_result;
}

}  // namespace encrypto::motion