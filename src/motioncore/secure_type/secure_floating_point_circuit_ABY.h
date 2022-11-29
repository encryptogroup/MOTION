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
#include "secure_type/secure_signed_integer.h"
#include "secure_type/secure_unsigned_integer.h"

namespace encrypto::motion {

class Logger;

class SecureFixedPointCircuitCBMC;

class SecureUnsignedInteger;
class SecureSignedInteger;

// support single-precision (32 bits) floating point and double-precision (64 bits) floating point
// operations

// floating-point circuits or C program source:
// ABY: https://github.com/encryptogroup/ABY/tree/public/bin/circ, (circuits are optimized for both,
// low depth and low number of AND gates, with a priority on low-depth, we convert circuit to
// .bristol with python program manually.
// SoftFloat-2c: http://www.jhauser.us/arithmetic/SoftFloat.html
class SecureFloatingPointCircuitABY {
 public:
  SecureFloatingPointCircuitABY() = default;

  SecureFloatingPointCircuitABY(const SecureFloatingPointCircuitABY& other)
      : SecureFloatingPointCircuitABY(*other.share_) {}

  SecureFloatingPointCircuitABY(SecureFloatingPointCircuitABY&& other)
      : SecureFloatingPointCircuitABY(std::move(*other.share_)) {
    other.share_->Get().reset();
  }

  SecureFloatingPointCircuitABY(const ShareWrapper& other)
      : SecureFloatingPointCircuitABY(*other) {}

  SecureFloatingPointCircuitABY(ShareWrapper&& other)
      : SecureFloatingPointCircuitABY(std::move(*other)) {
    other.Get().reset();
  }

  SecureFloatingPointCircuitABY(const SharePointer& other);

  SecureFloatingPointCircuitABY(SharePointer&& other);

  SecureFloatingPointCircuitABY& operator=(const SecureFloatingPointCircuitABY& other) {
    this->share_ = other.share_;
    this->logger_ = other.logger_;
    return *this;
  }

  SecureFloatingPointCircuitABY& operator=(SecureFloatingPointCircuitABY&& other) {
    this->share_ = std::move(other.share_);
    this->logger_ = std::move(other.logger_);
    return *this;
  }

  ShareWrapper& Get() { return *share_; }

  const ShareWrapper& Get() const { return *share_; }

  ShareWrapper& operator->() { return *share_; }

  const ShareWrapper& operator->() const { return *share_; }

  SecureFloatingPointCircuitABY operator+(const SecureFloatingPointCircuitABY& other) const;

  SecureFloatingPointCircuitABY& operator+=(const SecureFloatingPointCircuitABY& other) {
    *this = *this + other;
    return *this;
  }

  SecureFloatingPointCircuitABY operator-(const SecureFloatingPointCircuitABY& other) const;

  SecureFloatingPointCircuitABY& operator-=(const SecureFloatingPointCircuitABY& other) {
    *this = *this - other;
    return *this;
  }

  SecureFloatingPointCircuitABY operator*(const SecureFloatingPointCircuitABY& other) const;

  SecureFloatingPointCircuitABY& operator*=(const SecureFloatingPointCircuitABY& other) {
    *this = *this * other;
    return *this;
  }

  SecureFloatingPointCircuitABY operator/(const SecureFloatingPointCircuitABY& other) const;

  SecureFloatingPointCircuitABY& operator/=(const SecureFloatingPointCircuitABY& other) {
    *this = *this / other;
    return *this;
  }

  ShareWrapper operator<(const SecureFloatingPointCircuitABY& other) const;

  ShareWrapper operator>(const SecureFloatingPointCircuitABY& other) const;

  ShareWrapper operator==(const SecureFloatingPointCircuitABY& other) const;

  /// \brief operations with constant value
  // TODO: support garbled circuit protocol
  SecureFloatingPointCircuitABY operator+(const float& constant_value) const;
  SecureFloatingPointCircuitABY operator-(const float& constant_value) const;
  SecureFloatingPointCircuitABY operator*(const float& constant_value) const;
  SecureFloatingPointCircuitABY operator/(const float& constant_value) const;
  ShareWrapper operator<(const float& constant_value) const;
  ShareWrapper operator>(const float& constant_value) const;
  ShareWrapper operator==(const float& constant_value) const;

  SecureFloatingPointCircuitABY operator+(const double& constant_value) const;
  SecureFloatingPointCircuitABY operator-(const double& constant_value) const;
  SecureFloatingPointCircuitABY operator*(const double& constant_value) const;
  SecureFloatingPointCircuitABY operator/(const double& constant_value) const;
  ShareWrapper operator<(const double& constant_value) const;
  ShareWrapper operator>(const double& constant_value) const;
  ShareWrapper operator==(const double& constant_value) const;

  // multiplication each Boolean bit of *this with a bit share
  SecureFloatingPointCircuitABY MulBooleanBit(
      const ShareWrapper& boolean_gmw_bmr_gc_bit_share_other) const;

  /// \brief equals to zero
  ShareWrapper IsZero() const;

  /// \brief  is negative
  ShareWrapper IsNeg() const;

  // convert *this to negative floating-point
  SecureFloatingPointCircuitABY Neg() const;

  // absolute value of *this
  SecureFloatingPointCircuitABY Abs() const;

  // exp2(*this)
  SecureFloatingPointCircuitABY Exp2() const;

  // log2(*this)
  SecureFloatingPointCircuitABY Log2() const;

  // exp(*this)
  SecureFloatingPointCircuitABY Exp() const;

  // ln(*this)
  SecureFloatingPointCircuitABY Ln() const;

  // square
  SecureFloatingPointCircuitABY Sqr() const;

  // square root
  SecureFloatingPointCircuitABY Sqrt() const;

  // sine function
  SecureFloatingPointCircuitABY Sin() const;

  // cosine function
  SecureFloatingPointCircuitABY Cos() const;

  // convert 32-bit floating point to 64-bit floating point
  SecureFloatingPointCircuitABY ConvertSinglePrecisionToDoublePrecision() const;

  // convert 64-bit floating point to 32-bit floating point
  // ! may cause loss of precision
  SecureFloatingPointCircuitABY ConvertDoublePrecisionToSinglePrecision() const;

  // output the greatest integer less than or equal to *this
  SecureFloatingPointCircuitABY Ceil() const;

  // output the least integer less than or equal to *this
  SecureFloatingPointCircuitABY Floor() const;

  // round floating point (*this) to the nearest signed integer
  // this may cause overflow if the integer does not have enough bits
  // for example:
  // round(10.3) -> 10
  // round(10.5) -> 11
  // round(-10.3) -> 10
  // round(-10.5) -> -11
  SecureSignedInteger FL2Int(std::size_t integer_bit_length = 64u) const;

  // implement in class SecureSignedInteger
  // SecureFloatingPointCircuitABY Int2FL() const;

  // implement in class SecureFixedPointCircuitCBMC
  // SecureFloatingPointCircuitABY Fx2FL() const;

  // TODO: implement
  // convert 32-bit/64-bit floating point tp 64-bit signed integer
  SecureFixedPointCircuitCBMC FL2Fx(std::size_t fixed_point_fraction_bit_size = 16,
                                    std::size_t fixed_point_bit_length = 64) const;

  // multiply with 2^m
  // faster than floating-point multiplication
  SecureFloatingPointCircuitABY MulPow2m(std::int64_t m) const;

  // divide by 2^m
  // faster than floating-point division
  SecureFloatingPointCircuitABY DivPow2m(std::int64_t m) const;

  // used in the snapping mechanism (paper: On Significance of the Least Significant Bits For
  // Differential Privacy, 2012). for example: return x if -B < x < B, return -B if x < -B return B
  // if x > B
  SecureFloatingPointCircuitABY ClampB(double B);

  // used in the snapping mechanism (paper: On Significance of the Least Significant Bits For
  // Differential Privacy, 2012).
  // round floating-point number to the nearest integer
  // with deterministic rounding.
  // circuit is generated with CBMC-GC based on the code from
  // (https://github.com/ctcovington/floating_point).
  SecureFloatingPointCircuitABY RoundToNearestInteger();

  /// \brief internally extracts the ShareWrapper/SharePointer from input and
  /// calls ShareWrapper::Simdify(std::span<SharePointer> input)
  static SecureFloatingPointCircuitABY Simdify(std::span<SecureFloatingPointCircuitABY> input);

  //
  /// \brief internally extracts shares from each entry in input and calls
  /// Simdify(std::span<SecureFloatingPointCircuitABY> input) from the result
  static SecureFloatingPointCircuitABY Simdify(std::vector<SecureFloatingPointCircuitABY>&& input);

  /// \brief constructs a SubsetGate that returns values stored at positions in this->share_.
  /// Internally calls ShareWrapper Subset(std::span<std::size_t> positions).
  SecureFloatingPointCircuitABY Subset(std::span<const size_t> positions);

  /// \brief constructs a SubsetGate that returns values stored at positions in this->share_.
  /// Internally calls SecureFloatingPointCircuitABY Subset(std::span<std::size_t> positions).
  SecureFloatingPointCircuitABY Subset(std::vector<size_t>&& positions);

  /// \brief decomposes this->share_->Get() into shares with exactly 1 SIMD value.
  /// See the description in ShareWrapper::Unsimdify for reference.
  std::vector<SecureFloatingPointCircuitABY> Unsimdify() const;

  /// \brief constructs an output gate, which reconstructs the cleartext result. The default
  /// parameter for the output owner corresponds to all parties being the output owners.
  /// Uses ShareWrapper::Out.
  SecureFloatingPointCircuitABY Out(
      std::size_t output_owner = std::numeric_limits<std::int64_t>::max()) const;

  /// \brief converts the information on the wires to T in type Unsigned Integer.
  /// See the description in ShareWrapper::As for reference.
  template <typename T>
  T As() const;

  /// \brief converts the information on the wires to a veoctor of T in type Unsigned Integer.
  /// See the description in ShareWrapper::As for reference.
  template <typename T, typename A = std::allocator<T>>
  std::vector<T, A> AsVector() const;

  /// \brief converts the information on the wires to floating-point number(data type: float,
  /// double). See the description in ShareWrapper::As for reference.
  template <typename FLType>
  FLType AsFloatingPoint() const;

  /// \brief converts the information on the wires to floating-point vector (data type: float,
  /// double). See the description in ShareWrapper::As for reference.
  // used for SIMD
  template <typename FLType, typename A = std::allocator<FLType>>
  std::vector<FLType, A> AsFloatingPointVector() const;

 private:
  std::shared_ptr<ShareWrapper> share_{nullptr};
  std::shared_ptr<Logger> logger_{nullptr};

  std::string ConstructPath(const FloatingPointOperationType type, const std::size_t bitlength,
                            std::string suffix = "",
                            const std::size_t integer_bit_length = 0) const;
};

}  // namespace encrypto::motion
