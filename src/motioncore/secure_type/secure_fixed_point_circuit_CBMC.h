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
#include "secure_type/secure_floating_point_circuit_ABY.h"
#include "secure_type/secure_signed_integer.h"
#include "secure_type/secure_unsigned_integer.h"

namespace encrypto::motion {

class Logger;

class SecureFloatingPointCircuitABY;
class SecureUnsignedInteger;
class SecureSignedInteger;

// SecureFixedPointCircuitCBMC supports fixed-point number type:
// FIXEDPOINT_BITS 64, FIXEDPOINT_INTEGER_BITS 48, FIXEDPOINT_FRACTION_BITS 16,
// circuits are generated with CBMC-GC-2.
// For other fixed-point types, it needs to generate new circuits using CBMC-GC
// (https://gitlab.com/securityengineering/CBMC-GC-2/-/tree/master/)
class SecureFixedPointCircuitCBMC {
 public:
  SecureFixedPointCircuitCBMC() = default;

  SecureFixedPointCircuitCBMC(const SecureFixedPointCircuitCBMC& other)
      : SecureFixedPointCircuitCBMC(*other.share_) {}

  SecureFixedPointCircuitCBMC(SecureFixedPointCircuitCBMC&& other)
      : SecureFixedPointCircuitCBMC(std::move(*other.share_)) {
    other.share_->Get().reset();
  }

  SecureFixedPointCircuitCBMC(const ShareWrapper& other) : SecureFixedPointCircuitCBMC(*other) {}

  SecureFixedPointCircuitCBMC(ShareWrapper&& other)
      : SecureFixedPointCircuitCBMC(std::move(*other)) {
    other.Get().reset();
  }

  SecureFixedPointCircuitCBMC(const SharePointer& other);

  SecureFixedPointCircuitCBMC(SharePointer&& other);

  SecureFixedPointCircuitCBMC& operator=(const SecureFixedPointCircuitCBMC& other) {
    this->share_ = other.share_;
    this->logger_ = other.logger_;
    return *this;
  }

  SecureFixedPointCircuitCBMC& operator=(SecureFixedPointCircuitCBMC&& other) {
    this->share_ = std::move(other.share_);
    this->logger_ = std::move(other.logger_);
    return *this;
  }

  ShareWrapper& Get() { return *share_; }

  const ShareWrapper& Get() const { return *share_; }

  ShareWrapper& operator->() { return *share_; }

  const ShareWrapper& operator->() const { return *share_; }

  SecureFixedPointCircuitCBMC operator+(const SecureFixedPointCircuitCBMC& other) const;

  SecureFixedPointCircuitCBMC& operator+=(const SecureFixedPointCircuitCBMC& other) {
    *this = *this + other;
    return *this;
  }

  SecureFixedPointCircuitCBMC operator-(const SecureFixedPointCircuitCBMC& other) const;

  SecureFixedPointCircuitCBMC& operator-=(const SecureFixedPointCircuitCBMC& other) {
    *this = *this - other;
    return *this;
  }

  // TODO: use overflow_free circuit, benchmark
  SecureFixedPointCircuitCBMC operator*(const SecureFixedPointCircuitCBMC& other) const;

  SecureFixedPointCircuitCBMC& operator*=(const SecureFixedPointCircuitCBMC& other) {
    *this = *this * other;
    return *this;
  }

  // TODO: use overflow_free circuit, benchmark
  SecureFixedPointCircuitCBMC operator/(const SecureFixedPointCircuitCBMC& other) const;

  SecureFixedPointCircuitCBMC& operator/=(const SecureFixedPointCircuitCBMC& other) {
    *this = *this / other;
    return *this;
  }

  // ! this method is not accurate when b is greater than 2^16=65536 (because of truncation )
  // improve or remove later
  SecureFixedPointCircuitCBMC Div_Goldschmidt(const SecureFixedPointCircuitCBMC& other) const;

  ShareWrapper operator>(const SecureFixedPointCircuitCBMC& other) const;

  ShareWrapper operator<(const SecureFixedPointCircuitCBMC& other) const;

  ShareWrapper operator==(const SecureFixedPointCircuitCBMC& other) const;

  SecureFixedPointCircuitCBMC operator+(const double& constant_value) const;
  SecureFixedPointCircuitCBMC operator-(const double& constant_value) const;
  SecureFixedPointCircuitCBMC operator*(const double constant_value) const;
  SecureFixedPointCircuitCBMC operator/(const double& constant_value) const;
  ShareWrapper operator<(const double& constant_value) const;
  ShareWrapper operator>(const double& constant_value) const;
  ShareWrapper operator==(const double& constant_value) const;

  SecureFixedPointCircuitCBMC MulBooleanBit(
      const ShareWrapper& boolean_gmw_bmr_gc_bit_share_other) const;

  ShareWrapper IsNeg() const;
  ShareWrapper IsZero() const;

  SecureFixedPointCircuitCBMC Neg() const;

  SecureFixedPointCircuitCBMC Abs() const;

  SecureFixedPointCircuitCBMC Ceil() const;

  SecureFixedPointCircuitCBMC Floor() const;

  // round fixed-point to nearest integer
  SecureSignedInteger Fx2Int(std::size_t integer_bit_length = 64) const;

  // convert rounded fixed point to 64-bit signed integer
  SecureSignedInteger RoundedFx2Int() const;

  SecureFloatingPointCircuitABY Fx2FL(std::size_t floating_point_bit_length) const;

  // TODO: inaccurate for large input value
  // improve or remove later
  SecureFixedPointCircuitCBMC Sqrt() const;

  // ! only accurate for input in range [0.5, 1.0]
  SecureFixedPointCircuitCBMC Sqrt_P0132() const;

  // ! only accurate for input in range [0.0, 1.0]
  SecureFixedPointCircuitCBMC Exp2_P1045() const;

  // TODO: need to generate efficient circuits
  // 2^(-x)
  // x in range [0,1]
  // ! only accurate for input in range [-1.0, 0.0]
  SecureFixedPointCircuitCBMC Exp2_P1045_Neg_0_1() const;

  // TODO: need to generate efficient circuits
  // ! only accurate for input in range [0.5, 1.0]
  SecureFixedPointCircuitCBMC Log2_P2508() const;

  // based on Log2_P2508
  SecureFixedPointCircuitCBMC Ln() const;

  // based on Exp2_P1045
  SecureFixedPointCircuitCBMC Exp() const;

  // TODO: use optimized circuit
  SecureFixedPointCircuitCBMC Sqr() const;

  // output sin(x*0.5*pi)
  // x in range(0,1)
  SecureFixedPointCircuitCBMC Sin_P3307_0_1() const;

  // output sin(y*0.5*pi)
  // x in range(0,4)
  SecureFixedPointCircuitCBMC Sin_P3307_0_4() const;

  // TODO: generate circuit
  // output cos(x)
  // x in range (0,pi/2)
  SecureFixedPointCircuitCBMC Cos_P3508() const;

  /// \brief internally extracts the ShareWrapper/SharePointer from input and
  /// calls ShareWrapper::Simdify(std::span<SharePointer> input)
  static SecureFixedPointCircuitCBMC Simdify(std::span<SecureFixedPointCircuitCBMC> input);
  //
  /// \brief internally extracts shares from each entry in input and calls
  /// Simdify(std::span<SecureFixedPointCircuitCBMC> input) from the result
  static SecureFixedPointCircuitCBMC Simdify(std::vector<SecureFixedPointCircuitCBMC>&& input);

  /// \brief constructs a SubsetGate that returns values stored at positions in this->share_.
  /// Internally calls ShareWrapper Subset(std::span<std::size_t> positions).
  SecureFixedPointCircuitCBMC Subset(std::span<const size_t> positions);

  /// \brief constructs a SubsetGate that returns values stored at positions in this->share_.
  /// Internally calls SecureFixedPointCircuitCBMC Subset(std::span<std::size_t> positions).
  SecureFixedPointCircuitCBMC Subset(std::vector<size_t>&& positions);

  /// \brief decomposes this->share_->Get() into shares with exactly 1 SIMD value.
  /// See the description in ShareWrapper::Unsimdify for reference.
  std::vector<SecureFixedPointCircuitCBMC> Unsimdify() const;

  /// \brief constructs an output gate, which reconstructs the cleartext result. The default
  /// parameter for the output owner corresponds to all parties being the output owners.
  /// Uses ShareWrapper::Out.
  SecureFixedPointCircuitCBMC Out(
      std::size_t output_owner = std::numeric_limits<std::int64_t>::max()) const;

  /// \brief converts the information on the wires to T in type Unsigned Integer.
  /// See the description in ShareWrapper::As for reference.
  template <typename T>
  T As() const;

  template <typename T, typename A = std::allocator<T>>
  std::vector<T, A> AsVector() const;

  // TODO: add function argument
  /// \brief converts the information on the wires to T type Unsigned Integer.
  /// See the description in ShareWrapper::As for reference.
  template <typename FxType, typename FxType_int = std::make_signed_t<FxType>>
  double AsFixedPoint(std::size_t fixed_point_bit_length = 64,
                      std::size_t fixed_point_fraction_part_bit_length = 16) const;

  // TODO: add function argument
  /// \brief converts the information on the wires to T type Unsigned Integer.
  /// See the description in ShareWrapper::As for reference.
  template <typename FxType, typename FxType_int = std::make_signed_t<FxType>>
  std::vector<double> AsFixedPointVector(
      std::size_t fixed_point_bit_length = 64,
      std::size_t fixed_point_fraction_part_bit_length = 16) const;

 public:
  // different integer bits and fraction bits settings for fixed point numbers
  // std::size_t total_bits_ = 64;
  // std::size_t fraction_bits_ = 16;

  std::size_t k_ = 64;
  std::size_t f_ = 16;

 private:
  std::shared_ptr<ShareWrapper> share_{nullptr};

  std::shared_ptr<Logger> logger_{nullptr};

  std::string ConstructPath(const FixedPointOperationType type, const std::size_t bitlength,
                            std::string suffix = "", const std::size_t integer_bit_length = 64,
                            const std::size_t floating_point_bit_length = 64) const;
};

}  // namespace encrypto::motion
