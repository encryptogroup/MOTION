// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko
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

class Logger;

class SecureUnsignedInteger {
 public:
  SecureUnsignedInteger() = default;

  SecureUnsignedInteger(const SecureUnsignedInteger& other)
      : SecureUnsignedInteger(*other.share_) {}

  SecureUnsignedInteger(SecureUnsignedInteger&& other)
      : SecureUnsignedInteger(std::move(*other.share_)) {
    other.share_->Get().reset();
  }

  SecureUnsignedInteger(const ShareWrapper& other) : SecureUnsignedInteger(*other) {}

  SecureUnsignedInteger(ShareWrapper&& other) : SecureUnsignedInteger(std::move(*other)) {
    other.Get().reset();
  }

  SecureUnsignedInteger(const SharePointer& other);

  SecureUnsignedInteger(SharePointer&& other);

  SecureUnsignedInteger& operator=(const SecureUnsignedInteger& other) {
    this->share_ = other.share_;
    this->logger_ = other.logger_;
    return *this;
  }

  SecureUnsignedInteger& operator=(SecureUnsignedInteger&& other) {
    this->share_ = std::move(other.share_);
    this->logger_ = std::move(other.logger_);
    return *this;
  }

  ShareWrapper& Get() { return *share_; }

  const ShareWrapper& Get() const { return *share_; }

  ShareWrapper& operator->() { return *share_; }

  const ShareWrapper& operator->() const { return *share_; }

  SecureUnsignedInteger operator+(const SecureUnsignedInteger& other) const;

  SecureUnsignedInteger& operator+=(const SecureUnsignedInteger& other) {
    *this = *this + other;
    return *this;
  }

  SecureUnsignedInteger operator-(const SecureUnsignedInteger& other) const;

  SecureUnsignedInteger& operator-=(const SecureUnsignedInteger& other) {
    *this = *this - other;
    return *this;
  }

  SecureUnsignedInteger operator*(const SecureUnsignedInteger& other) const;

  SecureUnsignedInteger& operator*=(const SecureUnsignedInteger& other) {
    *this = *this * other;
    return *this;
  }

  SecureUnsignedInteger operator/(const SecureUnsignedInteger& other) const;

  SecureUnsignedInteger& operator/=(const SecureUnsignedInteger& other) {
    *this = *this / other;
    return *this;
  }

  ShareWrapper operator>(const SecureUnsignedInteger& other) const;

  ShareWrapper operator==(const SecureUnsignedInteger& other) const;

 private:
  std::shared_ptr<ShareWrapper> share_{nullptr};
  std::shared_ptr<Logger> logger_{nullptr};

  std::string ConstructPath(const IntegerOperationType type, const std::size_t bitlength,
                            std::string suffix = "") const;
};

}  // namespace encrypto::motion
