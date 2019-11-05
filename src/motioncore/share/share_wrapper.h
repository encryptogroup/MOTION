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

#include <cassert>
#include <memory>
#include <vector>

#include "share.h"
#include "utility/typedefs.h"

namespace ENCRYPTO {
class AlgorithmDescription;
}

namespace MOTION::Shares {
class Share;
using SharePtr = std::shared_ptr<Share>;

class ShareWrapper {
 public:
  ShareWrapper(const SharePtr &share) : share_(share) { assert(share_); }
  ShareWrapper(const ShareWrapper &sw) : share_(sw.share_) { assert(sw.share_); }

  ShareWrapper() = delete;

  void operator=(SharePtr share) { share_ = share; }
  void operator=(const ShareWrapper &sw) { share_ = sw.share_; }

  ShareWrapper operator~() const;

  ShareWrapper operator^(const ShareWrapper &other) const;

  ShareWrapper &operator^=(const ShareWrapper &other) {
    *this = *this ^ other;
    return *this;
  }

  ShareWrapper operator&(const ShareWrapper &other) const;

  ShareWrapper &operator&=(const ShareWrapper &other) {
    *this = *this & other;
    return *this;
  }

  ShareWrapper operator|(const ShareWrapper &other) const;

  ShareWrapper &operator|=(const ShareWrapper &other) {
    *this = *this | other;
    return *this;
  }

  ShareWrapper operator+(const ShareWrapper &other) const;

  ShareWrapper &operator+=(const ShareWrapper &other) {
    *this = *this + other;
    return *this;
  }

  ShareWrapper operator-(const ShareWrapper &other) const;

  ShareWrapper &operator-=(const ShareWrapper &other) {
    *this = *this - other;
    return *this;
  }

  ShareWrapper operator*(const ShareWrapper &other) const;

  ShareWrapper &operator*=(const ShareWrapper &other) {
    *this = *this * other;
    return *this;
  }

  ShareWrapper operator==(const ShareWrapper &other) const;

  // use this as the selection bit
  // returns this ? a : b
  ShareWrapper MUX(const ShareWrapper &a, const ShareWrapper &b) const;

  template <typename MOTION::MPCProtocol p>
  ShareWrapper Convert() const;

  SharePtr &Get() { return share_; }

  const SharePtr &Get() const { return share_; }

  const SharePtr &operator*() const { return share_; }

  const SharePtr &operator->() const { return share_; }

  const SharePtr Out(std::size_t output_owner = std::numeric_limits<std::int64_t>::max()) const;

  std::vector<ShareWrapper> Split() const;

  static ShareWrapper Join(const std::vector<ShareWrapper>::const_iterator _begin,
                           const std::vector<ShareWrapper>::const_iterator _end) {
    const auto v{std::vector<ShareWrapper>(_begin, _end)};
    return Join(v);
  }

  static ShareWrapper Join(const std::vector<ShareWrapper> &v);

  ShareWrapper Evaluate(const std::shared_ptr<const ENCRYPTO::AlgorithmDescription> &algo) const {
    return Evaluate(*algo);
  }

  ShareWrapper Evaluate(const ENCRYPTO::AlgorithmDescription &algo) const;

 private:
  SharePtr share_;

  template <typename T>
  ShareWrapper Add(SharePtr share, SharePtr other) const;

  template <typename T>
  ShareWrapper Sub(SharePtr share, SharePtr other) const;

  template <typename T>
  ShareWrapper Mul(SharePtr share, SharePtr other) const;

  ShareWrapper ArithmeticGMWToBMR() const;

  ShareWrapper BooleanGMWToBMR() const;

  ShareWrapper BMRToBooleanGMW() const;
};
}