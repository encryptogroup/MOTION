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
#include "utility/meta.hpp"
namespace encrypto::motion {

class Logger;

class SecureFixedPointCircuitCBMC;
class SecureFloatingPointCircuitABY;

class SecureSignedInteger {
 public:
  SecureSignedInteger() = default;

  SecureSignedInteger(const SecureSignedInteger& other) : SecureSignedInteger(*other.share_) {}

  SecureSignedInteger(SecureSignedInteger&& other) : SecureSignedInteger(std::move(*other.share_)) {
    other.share_->Get().reset();
  }

  SecureSignedInteger(const ShareWrapper& other) : SecureSignedInteger(*other) {}

  SecureSignedInteger(ShareWrapper&& other) : SecureSignedInteger(std::move(*other)) {
    other.Get().reset();
  }

  SecureSignedInteger(const SharePointer& other);

  SecureSignedInteger(SharePointer&& other);

  SecureSignedInteger& operator=(const SecureSignedInteger& other) {
    this->share_ = other.share_;
    this->logger_ = other.logger_;
    return *this;
  }

  SecureSignedInteger& operator=(SecureSignedInteger&& other) {
    this->share_ = std::move(other.share_);
    this->logger_ = std::move(other.logger_);
    return *this;
  }

  ShareWrapper& Get() { return *share_; }

  const ShareWrapper& Get() const { return *share_; }

  ShareWrapper& operator->() { return *share_; }

  const ShareWrapper& operator->() const { return *share_; }

  SecureSignedInteger operator+(const SecureSignedInteger& other) const;

  SecureSignedInteger& operator+=(const SecureSignedInteger& other) {
    *this = *this + other;
    return *this;
  }

  SecureSignedInteger operator-(const SecureSignedInteger& other) const;

  SecureSignedInteger& operator-=(const SecureSignedInteger& other) {
    *this = *this - other;
    return *this;
  }

  SecureSignedInteger operator*(const SecureSignedInteger& other) const;

  SecureSignedInteger& operator*=(const SecureSignedInteger& other) {
    *this = *this * other;
    return *this;
  }

  // ! 128-bit circuit for division are not optimized because HyCC time out
  // TODO: regenerate circuit
  SecureSignedInteger operator/(const SecureSignedInteger& other) const;

  SecureSignedInteger& operator/=(const SecureSignedInteger& other) {
    *this = *this / other;
    return *this;
  }

  ShareWrapper operator<(const SecureSignedInteger& other) const;

  ShareWrapper operator>(const SecureSignedInteger& other) const;

  ShareWrapper operator==(const SecureSignedInteger& other) const;

  // TODO: support garbled circuit
  /// \brief operations with constant value
  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  SecureSignedInteger operator+(const T& constant_value) const;

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  SecureSignedInteger operator-(const T& constant_value) const;

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  SecureSignedInteger operator*(const T& constant_value) const;

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  SecureSignedInteger operator/(const T& constant_value) const;

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  ShareWrapper operator<(const T& constant_value) const;

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  ShareWrapper operator>(const T& constant_value) const;

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  ShareWrapper operator==(const T& constant_value) const;

  /// \brief mulitplication with a Boolean GMW bit
  SecureSignedInteger MulBooleanGmwBit(const ShareWrapper& boolean_gmw_share_other) const;

  /// \brief is greater than or equals to zero
  ShareWrapper GEQ(const SecureSignedInteger& other) const;

  /// \brief is less than or equals to zero
  ShareWrapper LEQ(const SecureSignedInteger& other) const;

  /// \brief -other <= (*this) <= other
  // other is a positive integer
  ShareWrapper InRange(const SecureSignedInteger& other) const;

  /// \brief equals to zero
  ShareWrapper EQZ() const;

  /// \brief is less than zero
  ShareWrapper LTZ() const;

  // convert *this to negative integers if boolean_gmw_or_bmr_share_sign = 0,
  // otherwise, remain unchanged
  SecureSignedInteger Neg(const ShareWrapper& boolean_gmw_or_bmr_share_sign) const;

  // convert *this to negative integers
  SecureSignedInteger Neg() const;

  // convert (32/64/128-bit) SecureSignedInteger to (32/64-bit) SecureFloatingPointCircuitESAT
  SecureFloatingPointCircuitABY Int2FL(std::size_t floating_point_bit_length = 64) const;

  // convert SecureSignedInteger to 64-bit SecureFixedPointCircuitCBMC
  SecureFixedPointCircuitCBMC Int2Fx(std::size_t fraction_bit_size = 16) const;

  /// \brief internally extracts the ShareWrapper/SharePointer from input and
  /// calls ShareWrapper::Simdify(std::span<SharePointer> input)
  static SecureSignedInteger Simdify(std::span<SecureSignedInteger> input);

  //
  /// \brief internally extracts shares from each entry in input and calls
  /// Simdify(std::span<SecureSignedInteger> input) from the result
  static SecureSignedInteger Simdify(std::vector<SecureSignedInteger>&& input);

  /// \brief constructs a SubsetGate that returns values stored at positions in this->share_.
  /// Internally calls ShareWrapper Subset(std::span<std::size_t> positions).
  SecureSignedInteger Subset(std::span<const size_t> positions);

  /// \brief constructs a SubsetGate that returns values stored at positions in this->share_.
  /// Internally calls SecureSignedInteger Subset(std::span<std::size_t> positions).
  SecureSignedInteger Subset(std::vector<size_t>&& positions);

  /// \brief decomposes this->share_->Get() into shares with exactly 1 SIMD value.
  /// See the description in ShareWrapper::Unsimdify for reference.
  std::vector<SecureSignedInteger> Unsimdify() const;

  /// \brief constructs an output gate, which reconstructs the cleartext result. The default
  /// parameter for the output owner corresponds to all parties being the output owners.
  /// Uses ShareWrapper::Out.
  SecureSignedInteger Out(
      std::size_t output_owner = std::numeric_limits<std::int64_t>::max()) const;

  /// \brief converts the information on the wires to T in type Unsigned Integer.
  /// See the description in ShareWrapper::As for reference.
  template <typename T>
  T As() const;

  /// \brief converts the information on the wires to a veoctor of T in type Unsigned Integer.
  /// See the description in ShareWrapper::As for reference.
  template <typename T, typename A = std::allocator<T>>
  std::vector<T, A> AsVector() const;

 private:
  std::shared_ptr<ShareWrapper> share_{nullptr};
  std::shared_ptr<Logger> logger_{nullptr};

  std::string ConstructPath(const SignedIntegerOperationType type, const std::size_t bitlength,
                            std::string suffix = "",
                            const std::size_t floating_point_bit_length = 64) const;
};

}  // namespace encrypto::motion
