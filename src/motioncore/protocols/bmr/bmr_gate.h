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

#include "bmr_share.h"

#include <future>
#include <span>

#include "protocols/boolean_gmw/boolean_gmw_gate.h"
#include "protocols/gate.h"
#include "utility/bit_vector.h"
#include "utility/block.h"
#include "utility/reusable_future.h"

namespace encrypto::motion {

class OtVectorSender;
class OtVectorReceiver;
class FixedXcOt128Sender;
class FixedXcOt128Receiver;
class XcOtBitSender;
class XcOtBitReceiver;

}  // namespace encrypto::motion

namespace encrypto::motion::proto::bmr {

class InputGate final : public motion::InputGate {
  using Base = motion::InputGate;

 public:
  InputGate(std::size_t number_of_simd, std::size_t bit_size, std::size_t input_owner_id,
            Backend& backend);

  InputGate(std::span<const motion::BitVector<>> input, std::size_t input_owner_id,
            Backend& backend);

  InputGate(std::vector<motion::BitVector<>>&& input, std::size_t input_owner_id, Backend& backend);

  void InitializationHelper();

  ~InputGate() final = default;

  void EvaluateSetup() final override;

  void EvaluateOnline() final override;

  const bmr::SharePointer GetOutputAsBmrShare() const;

  const motion::SharePointer GetOutputAsShare() const;

  auto& GetInputPromise() { return input_promise_; }

 protected:
  std::size_t number_of_simd_{0};  ///< Number of parallel values on wires
  std::size_t bit_size_{0};        ///< Number of wires
  ReusableFiberFuture<std::vector<std::uint8_t>> received_public_values_;
  std::vector<ReusableFiberFuture<std::vector<std::uint8_t>>> received_public_keys_;
  ReusableFiberFuture<std::vector<BitVector<>>> input_future_;
  ReusableFiberPromise<std::vector<BitVector<>>> input_promise_;
};

constexpr std::size_t kAll = std::numeric_limits<std::int64_t>::max();

class OutputGate final : public motion::OutputGate {
  using Base = motion::OutputGate;

 public:
  OutputGate(const motion::SharePointer& parent, std::size_t output_owner = kAll);

  ~OutputGate() final = default;

  void EvaluateSetup() final override;

  void EvaluateOnline() final override;

  bool NeedsSetup() const override { return false; }

  const bmr::SharePointer GetOutputAsBmrShare() const;

  const motion::SharePointer GetOutputAsShare() const;

 protected:
  boolean_gmw::SharePointer gmw_output_share_;
  std::shared_ptr<boolean_gmw::OutputGate> output_gate_;

  std::vector<motion::BitVector<>> output_;
  std::vector<std::vector<motion::BitVector<>>> shared_outputs_;

  bool is_my_output_ = false;

  std::mutex m;
};

class XorGate final : public TwoGate {
 public:
  XorGate(const motion::SharePointer& a, const motion::SharePointer& b);

  ~XorGate() final = default;

  void EvaluateSetup() final override;

  void EvaluateOnline() final override;

  const bmr::SharePointer GetOutputAsBmrShare() const;

  const motion::SharePointer GetOutputAsShare() const;

  XorGate() = delete;

  XorGate(const Gate&) = delete;
};

class InvGate final : public OneGate {
 public:
  InvGate(const motion::SharePointer& parent);

  ~InvGate() final = default;

  void EvaluateSetup() final override;

  void EvaluateOnline() final override;

  const bmr::SharePointer GetOutputAsBmrShare() const;

  const motion::SharePointer GetOutputAsShare() const;

  InvGate() = delete;

  InvGate(const Gate&) = delete;
};

class AndGate final : public TwoGate {
 public:
  AndGate(const motion::SharePointer& a, const motion::SharePointer& b);

  ~AndGate() final;

  void EvaluateSetup() final override;

  void EvaluateOnline() final override;

  const bmr::SharePointer GetOutputAsBmrShare() const;

  const motion::SharePointer GetOutputAsShare() const;

  AndGate() = delete;

  AndGate(const Gate&) = delete;

 private:
  std::vector<std::vector<std::unique_ptr<motion::XcOtBitSender>>> sender_ots_1_;
  std::vector<std::vector<std::unique_ptr<motion::FixedXcOt128Sender>>> sender_ots_kappa_;
  std::vector<std::vector<std::unique_ptr<motion::XcOtBitReceiver>>> receiver_ots_1_;
  std::vector<std::vector<std::unique_ptr<motion::FixedXcOt128Receiver>>> receiver_ots_kappa_;

  std::vector<ReusableFiberFuture<std::vector<std::uint8_t>>> received_garbled_rows_;

  // buffer to store all garbled tables for all wires
  // structure: wires X (simd X (row_00 || row_01 || row_10 || row_11))
  motion::Block128Vector garbled_tables_;

  void GenerateRandomness();
};

}  // namespace encrypto::motion::proto::bmr
