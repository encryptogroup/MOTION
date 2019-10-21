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

#include "share/share_wrapper.h"

namespace MOTION {

class SecureUnsignedInteger {
 public:
  SecureUnsignedInteger() = delete;

  SecureUnsignedInteger(const SecureUnsignedInteger& other)
      : SecureUnsignedInteger(*other.share_) {}

  SecureUnsignedInteger(SecureUnsignedInteger&& other)
      : SecureUnsignedInteger(std::move(*other.share_)) {
    other.share_->Get().reset();
  }

  SecureUnsignedInteger(const Shares::ShareWrapper& other) : SecureUnsignedInteger(*other) {}

  SecureUnsignedInteger(Shares::ShareWrapper&& other) : SecureUnsignedInteger(std::move(*other)) {
    other.Get().reset();
  }

  SecureUnsignedInteger(const Shares::SharePtr& other) {
    share_ = std::make_unique<Shares::ShareWrapper>(other);
  }

  SecureUnsignedInteger(Shares::SharePtr&& other) {
    share_ = std::make_unique<Shares::ShareWrapper>(std::move(other));
  }

 private:
  std::unique_ptr<Shares::ShareWrapper> share_{nullptr};
};

}