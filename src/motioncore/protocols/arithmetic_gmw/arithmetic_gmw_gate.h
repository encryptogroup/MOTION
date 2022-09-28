// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko, Lennart Braun
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

#include "arithmetic_gmw_share.h"
#include "arithmetic_gmw_wire.h"

#include <memory>
#include <span>

#include "base/motion_base_provider.h"
#include "multiplication_triple/mt_provider.h"
#include "multiplication_triple/sp_provider.h"
#include "protocols/gate.h"
#include "utility/reusable_future.h"

//  Forward Declaration
namespace encrypto::motion::proto::boolean_gmw {
  class Wire;
  using WirePointer = std::shared_ptr<boolean_gmw::Wire>;
}
namespace encrypto::motion::proto::arithmetic_gmw {

//
//     | <- one unsigned integer input
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- one SharePointer(new arithmetic_gmw::Share) output
//

template <typename T>
class InputGate final : public motion::InputGate {
  using Base = motion::InputGate;

 public:
  InputGate(std::span<const T> input, std::size_t input_owner, Backend& backend);
  InputGate(std::vector<T>&& input, std::size_t input_owner, Backend& backend);
  InputGate(std::size_t simd_values, std::size_t input_owner, Backend& backend)
  : InputGate(std::vector<T>(simd_values, T(0)), input_owner, backend) {}

  void InitializationHelper();

  ~InputGate() final = default;
  
  //Sets input values after construction but before evaluating the online phase.
  //The input can only be set once, before EvaluateOnline() was called and only 
  //if all input values were set to 0 during construction.
  void SetAndCommit(std::vector<T> input);

  void EvaluateSetup() final override;
  // non-interactive input sharing based on distributed in advance randomness seeds
  void EvaluateOnline() final override;

  bool NeedsSetup() const override { return false; }

  // perhaps, we should return a copy of the pointer and not move it for the case we need it
  // multiple times
  arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticShare();
  arithmetic_gmw::WirePointer<T> GetOutputArithmeticWire();

 private:
  std::size_t arithmetic_sharing_id_;

  std::vector<T> input_;
};

constexpr std::size_t kAll = std::numeric_limits<std::int64_t>::max();

template <typename T>
class OutputGate final : public motion::OutputGate {
  using Base = motion::OutputGate;

 public:
  OutputGate(const arithmetic_gmw::WirePointer<T>& parent, std::size_t output_owner = kAll);
  OutputGate(const arithmetic_gmw::SharePointer<T>& parent, std::size_t output_owner);
  OutputGate(const motion::SharePointer& parent, std::size_t output_owner);

  ~OutputGate() final = default;

  void EvaluateSetup() final override;
  void EvaluateOnline() final override;

  bool NeedsSetup() const override { return false; }

  // perhaps, we should return a copy of the pointer and not move it for the  case we need it
  // multiple times
  arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticShare();

 protected:
  // indicates whether this party obtains the output
  bool is_my_output_ = false;

  std::vector<motion::ReusableFiberFuture<std::vector<std::uint8_t>>> output_message_futures_;

  std::mutex m;
};

template <typename T>
class AdditionGate final : public motion::TwoGate {
 public:
  AdditionGate(const arithmetic_gmw::WirePointer<T>& a, const arithmetic_gmw::WirePointer<T>& b);
  ~AdditionGate() final = default;

  void EvaluateSetup() final override;
  void EvaluateOnline() final override;

  bool NeedsSetup() const override { return false; }

  // perhaps, we should return a copy of the pointer and not move it for the case we need it
  // multiple times
  arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticShare();

  AdditionGate() = delete;
  AdditionGate(Gate&) = delete;
};

template <typename T>
class SubtractionGate final : public motion::TwoGate {
 public:
  SubtractionGate(const arithmetic_gmw::WirePointer<T>& a, const arithmetic_gmw::WirePointer<T>& b);
  ~SubtractionGate() final = default;

  void EvaluateSetup() final override;
  void EvaluateOnline() final override;

  bool NeedsSetup() const override { return false; }

  // perhaps, we should return a copy of the pointer and not move it for the case we need it
  // multiple times
  arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticShare();

  SubtractionGate() = delete;
  SubtractionGate(Gate&) = delete;
};

template <typename T>
class MultiplicationGate final : public motion::TwoGate {
 public:
  MultiplicationGate(const arithmetic_gmw::WirePointer<T>& a,
                     const arithmetic_gmw::WirePointer<T>& b);
  ~MultiplicationGate() final = default;

  void EvaluateSetup() final override;
  void EvaluateOnline() final override;

  bool NeedsSetup() const override { return false; }

  // perhaps, we should return a copy of the pointer and not move it for the case we need it
  // multiple times
  arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticShare();

  MultiplicationGate() = delete;
  MultiplicationGate(Gate&) = delete;

 private:
  std::vector<motion::ReusableFiberFuture<std::vector<std::uint8_t>>> d_futures_;
  std::vector<motion::ReusableFiberFuture<std::vector<std::uint8_t>>> e_futures_;

  std::size_t number_of_mts_, mt_offset_;
};

// Multiplication of an arithmetic share with a boolean bit.
// Based on [ST21]: https://iacr.org/2021/029.pdf
template <typename T>
class HybridMultiplicationGate final : public motion::TwoGate {
 public:
  HybridMultiplicationGate(const boolean_gmw::WirePointer& bit,
                           const arithmetic_gmw::WirePointer<T>& integer);

  ~HybridMultiplicationGate() final = default;

  void EvaluateSetup() final override;
  void EvaluateOnline() final override;

  bool NeedsSetup() const override { return false; }

  // perhaps, we should return a copy of the pointer and not move it for the
  // case we need it multiple times
  arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticShare();

  HybridMultiplicationGate() = delete;

  HybridMultiplicationGate(Gate&) = delete;

 private:
  std::unique_ptr<AcOtReceiver<T>> ot_receiver_;
  std::unique_ptr<AcOtSender<T>> ot_sender_;
};

template <typename T>
class SquareGate final : public motion::OneGate {
 public:
  SquareGate(const arithmetic_gmw::WirePointer<T>& a);
  ~SquareGate() final = default;

  void EvaluateSetup() final override;
  void EvaluateOnline() final override;

  bool NeedsSetup() const override { return false; }

  // perhaps, we should return a copy of the pointer and not move it for the case we need it
  // multiple times
  arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticShare();

  SquareGate() = delete;
  SquareGate(Gate&) = delete;

 private:
  arithmetic_gmw::WirePointer<T> d_;
  std::shared_ptr<OutputGate<T>> d_output_;

  std::size_t number_of_sps_, sp_offset_;
};

}  // namespace encrypto::motion::proto::arithmetic_gmw
