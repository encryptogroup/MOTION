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
#include "secure_type/secure_floating_point32_agmw_ABZS.h"
#include "secure_type/secure_floating_point64_agmw_ABZS.h"
#include "secure_type/secure_floating_point_circuit_ABY.h"

namespace encrypto::motion {

class Logger;

class SecureFixedPointCircuitCBMC;
class SecureUnsignedInteger;
class SecureFloatingPointCircuitABY;

class SecureSnappingMechanism {
 public:
  SecureSnappingMechanism() = default;

  SecureSnappingMechanism(const SecureSnappingMechanism& other)
      : SecureSnappingMechanism(*other.fD_) {}

  SecureSnappingMechanism(SecureSnappingMechanism&& other)
      : SecureSnappingMechanism(std::move(*other.fD_)) {
    other.fD_->Get().reset();
  }

  SecureSnappingMechanism(const ShareWrapper& other) : SecureSnappingMechanism(*other) {}

  SecureSnappingMechanism(ShareWrapper&& other) : SecureSnappingMechanism(std::move(*other)) {
    other.Get().reset();
  }

  SecureSnappingMechanism(const SharePointer& other);

  SecureSnappingMechanism(SharePointer&& other);

  SecureSnappingMechanism& operator=(const SecureSnappingMechanism& other) {
    this->fD_ = other.fD_;
    this->logger_ = other.logger_;
    return *this;
  }

  SecureSnappingMechanism& operator=(SecureSnappingMechanism&& other) {
    this->fD_ = std::move(other.fD_);
    this->logger_ = std::move(other.logger_);
    return *this;
  }

  ShareWrapper& Get() { return *fD_; }
  const ShareWrapper& Get() const { return *fD_; }
  ShareWrapper& operator->() { return *fD_; }
  const ShareWrapper& operator->() const { return *fD_; }

  void ParameterSetup(double sensitivity, double lambda, double clamp_B) {
    sensitivity_ = sensitivity;
    lambda_ = lambda;
    clamp_B_ = clamp_B;
  }

  SecureFloatingPointCircuitABY SnappingAndNoiseAddition();

  SecureFloatingPointCircuitABY SnappingAndNoiseAddition(
      const ShareWrapper& random_bits_of_length_52, const ShareWrapper& random_bits_of_length_1022,
      const ShareWrapper& boolean_gmw_share_sign_bit);

  SecureFloatingPointCircuitABY SnappingAndNoiseAddition(
      const ShareWrapper& floating_point_boolean_gmw_share_uniform_floating_point_0_1,
      const ShareWrapper& boolean_gmw_share_sign_bit);

  /// \brief constructs an output gate, which reconstructs the cleartext result. The default
  /// parameter for the output owner corresponds to all parties being the output owners.
  /// Uses ShareWrapper::Out.
  SecureFloatingPointCircuitABY Out(
      std::size_t output_owner = std::numeric_limits<std::int64_t>::max()) const;

  /// \brief converts the information on the wires to T in type Unsigned Integer.
  /// See the description in ShareWrapper::As for reference.
  template <typename T>
  T As() const;

  /// \brief converts the information on the wires to T in type floating-point (float, double).
  /// See the description in ShareWrapper::As for reference.
  template <typename FLType = double>
  FLType AsFloatingPoint() const;

  /// \brief converts the information on the wires to T in type floating-point (float, double).
  /// See the description in ShareWrapper::As for reference.
  template <typename FLType = double, typename A = std::allocator<FLType>>
  std::vector<FLType, A> AsFloatingPointVector() const;

 public:
  // the sensitivity must be calibrated to 1
  double sensitivity_ = 1;
  double lambda_ = 0.01;
  double clamp_B_ = 2;

 private:
 // fD_ is 64-bit floating point number
  std::shared_ptr<ShareWrapper> fD_{nullptr};
  std::shared_ptr<Logger> logger_{nullptr};
};
}  // namespace encrypto::motion