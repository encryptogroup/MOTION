// MIT License
//
// Copyright (c) 2022 Oleksandr Tkachenko
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

#include "secure_unsigned_integer.h"

namespace encrypto::motion {

/// \b implements an interface for signed arithmetic on standard C++ data types and 128-bit integers
/// using the two's complement representation.
class SecureSignedInteger {
 public:
  SecureSignedInteger() = default;
  SecureSignedInteger(SecureUnsignedInteger share) : share_(share) {}
  SecureSignedInteger(ShareWrapper share) : share_(share) {}
  SecureSignedInteger(SharePointer share) : share_(share) {}

  virtual ~SecureSignedInteger() = default;

  SecureSignedInteger& operator=(const SecureSignedInteger& other) {
    share_ = other.share_;
    return *this;
  }

  SecureSignedInteger& operator=(SecureSignedInteger&& other) {
    share_ = std::move(other.share_);
    return *this;
  }

  ShareWrapper& Get() { return share_.Get(); }

  const ShareWrapper& Get() const { return share_.Get(); }

  ShareWrapper& operator->() { return share_.Get(); }

  const ShareWrapper& operator->() const { return share_.Get(); }

  SecureSignedInteger operator+(const SecureSignedInteger& other) const {
    return this->share_ + other.share_;
  }

  SecureSignedInteger& operator+=(const SecureSignedInteger& other) {
    *this = *this + other;
    return *this;
  }

  SecureSignedInteger operator-(const SecureSignedInteger& other) const {
    return this->share_ - other.share_;
  }

  SecureSignedInteger& operator-=(const SecureSignedInteger& other) {
    *this = *this - other;
    return *this;
  }

  SecureSignedInteger operator*(const SecureSignedInteger& other) const {
    return this->share_ * other.share_;
  }

  SecureSignedInteger& operator*=(const SecureSignedInteger& other) {
    *this = *this * other;
    return *this;
  }

  SecureSignedInteger operator/(const SecureSignedInteger& other) const {
    // TODO implement
    throw std::runtime_error("Not implemented yet");
    return this->share_ + other.share_;
  }

  SecureSignedInteger& operator/=(const SecureSignedInteger& other) {
    *this = *this / other;
    return *this;
  }

  ShareWrapper operator>(const SecureSignedInteger& other) const {
    // TODO implement
    throw std::runtime_error("Not implemented yet");
    return this->share_ > other.share_;
  }

  ShareWrapper operator==(const SecureSignedInteger& other) const {
    return this->share_ == other.share_;
  }

  /// \brief internally extracts the ShareWrapper/SharePointer from input and
  /// calls ShareWrapper::Simdify(std::span<SharePointer> input)
  static SecureSignedInteger Simdify(std::span<SecureSignedInteger> input);
  //
  /// \brief internally extracts shares from each entry in input and calls
  /// Simdify(std::span<SecureUnsignedInteger> input) from the result
  static SecureSignedInteger Simdify(std::vector<SecureSignedInteger>&& input);

  /// \brief constructs a SubsetGate that returns values stored at positions in this->share_.
  /// Internally calls ShareWrapper Subset(std::span<std::size_t> positions).
  SecureSignedInteger Subset(std::span<const size_t> positions);

  /// \brief constructs a SubsetGate that returns values stored at positions in this->share_.
  /// Internally calls SecureUnsignedInteger Subset(std::span<std::size_t> positions).
  SecureSignedInteger Subset(std::vector<size_t>&& positions);

  /// \brief decomposes this->share_->Get() into shares with exactly 1 SIMD value.
  /// See the description in ShareWrapper::Unsimdify for reference.
  std::vector<SecureSignedInteger> Unsimdify() const;

  /// \brief constructs an output gate, which reconstructs the cleartext result. The default
  /// parameter for the output owner corresponds to all parties being the output owners.
  /// Uses ShareWrapper::Out.
  SecureSignedInteger Out(
      std::size_t output_owner = std::numeric_limits<std::int64_t>::max()) const;

  /// \brief converts the information on the wires to T in type Signed Integer.
  /// See the description in ShareWrapper::As for reference.
  template <typename T>
  T As() const;

 private:
  SecureUnsignedInteger share_;
};

}  // namespace encrypto::motion