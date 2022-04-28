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

#include "protocols/gate.h"
#include "utility/bit_vector.h"
#include "utility/block.h"
#include "utility/reusable_future.h"

namespace encrypto::motion::proto::bmr {

class Share;
using SharePointer = std::shared_ptr<Share>;

}  // namespace encrypto::motion::proto::bmr

namespace encrypto::motion::proto::boolean_gmw {

class Share;
using SharePointer = std::shared_ptr<Share>;

}  // namespace encrypto::motion::proto::boolean_gmw

namespace encrypto::motion {

class Share;
using SharePointer = std::shared_ptr<Share>;

class ShareWrapper;

class BmrToBooleanGmwGate final : public OneGate {
 public:
  BmrToBooleanGmwGate(const SharePointer& parent);

  ~BmrToBooleanGmwGate() final = default;

  void EvaluateSetup() final override;

  void EvaluateOnline() final override;

  bool NeedsSetup() const override { return false; }

  const proto::boolean_gmw::SharePointer GetOutputAsGmwShare() const;

  const SharePointer GetOutputAsShare() const;

  BmrToBooleanGmwGate() = delete;

  BmrToBooleanGmwGate(const Gate&) = delete;
};

class BooleanGmwToBmrGate final : public OneGate {
 public:
  BooleanGmwToBmrGate(const SharePointer& parent);

  ~BooleanGmwToBmrGate() final = default;

  void EvaluateSetup() final override;

  void EvaluateOnline() final override;

  const proto::bmr::SharePointer GetOutputAsBmrShare() const;

  const SharePointer GetOutputAsShare() const;

  BooleanGmwToBmrGate() = delete;

  BooleanGmwToBmrGate(const Gate&) = delete;

 private:
  std::vector<ReusableFiberFuture<std::vector<std::uint8_t>>> received_public_values_;
  std::vector<ReusableFiberFuture<std::vector<std::uint8_t>>> received_public_keys_;
};

class ArithmeticGmwToBmrGate final : public OneGate {
 public:
  ArithmeticGmwToBmrGate(const SharePointer& parent);

  ~ArithmeticGmwToBmrGate() final = default;

  void EvaluateSetup() final override;

  void EvaluateOnline() final override;

  bool NeedsSetup() const override { return false; }

  const proto::bmr::SharePointer GetOutputAsBmrShare() const;

  const SharePointer GetOutputAsShare() const;

  ArithmeticGmwToBmrGate() = delete;

  ArithmeticGmwToBmrGate(const Gate&) = delete;

 private:
  ReusableFiberPromise<std::vector<BitVector<>>>* input_promise_;
};

}  // namespace encrypto::motion
