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

#include "gate/arithmetic_gmw_gate.h"
#include "gate/boolean_gmw_gate.h"

#include "share/arithmetic_gmw_share.h"
#include "share/boolean_gmw_share.h"

namespace ABYN::Shares {
class ShareWrapper {
 public:
  ShareWrapper(const SharePtr &share) : share_(share) {}
  ShareWrapper(const ShareWrapper &sw) : share_(sw.share_) {}

  ShareWrapper() = delete;

  void operator=(SharePtr share) { share_ = share; }
  void operator=(const ShareWrapper &sw) { share_ = sw.share_; }

  ShareWrapper &operator^(const ShareWrapper &other);

  ShareWrapper &operator^=(const ShareWrapper &other) {
    *this = *this ^ other;
    return *this;
  }

  ShareWrapper &operator&(const ShareWrapper &other);

  ShareWrapper &operator&=(const ShareWrapper &other) {
    *this = *this & other;
    return *this;
  }

  ShareWrapper &operator+(const ShareWrapper &other);

  ShareWrapper &operator+=(const ShareWrapper &other) {
    *this = *this + other;
    return *this;
  }

  ShareWrapper &operator*([[maybe_unused]] const ShareWrapper &other) {
    throw std::runtime_error("Arithmetic GMW multiplication is not implemented yet");
  }

  ShareWrapper &operator*=(const ShareWrapper &other) {
    *this = *this * other;
    return *this;
  }

  SharePtr &Get() { return share_; }

  const SharePtr &operator*() const { return share_; }

  const SharePtr &operator->() const { return share_; }

  const SharePtr Out(std::size_t output_owner = std::numeric_limits<std::int64_t>::max());

 private:
  SharePtr share_;

  template <typename T>
  ShareWrapper Add(SharePtr share, SharePtr other) {
    auto this_a = std::dynamic_pointer_cast<ArithmeticShare<T>>(share);
    assert(this_a);
    auto this_wire_a = this_a->GetArithmeticWire();

    auto other_a = std::dynamic_pointer_cast<ArithmeticShare<T>>(other);
    assert(other_a);
    auto other_wire_a = other_a->GetArithmeticWire();

    auto addition_gate =
        std::make_shared<Gates::Arithmetic::ArithmeticAdditionGate<T>>(this_wire_a, other_wire_a);
    auto addition_gate_cast = std::static_pointer_cast<Gates::Interfaces::Gate>(addition_gate);
    share_->GetRegister()->RegisterNextGate(addition_gate_cast);
    auto res = std::static_pointer_cast<Shares::Share>(addition_gate->GetOutputAsArithmeticShare());

    return ShareWrapper(res);
  }
};
}