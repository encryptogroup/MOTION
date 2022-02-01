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

#include "boolean_gmw_share.h"

#include <span>

#include "oblivious_transfer/ot_flavors.h"
#include "protocols/gate.h"
#include "utility/bit_vector.h"
#include "utility/reusable_future.h"

namespace encrypto::motion::proto::boolean_gmw {

class InputGate final : public motion::InputGate {
  using Base = motion::InputGate;

 public:
  InputGate(std::span<const BitVector<>> input, std::size_t party_id, Backend& backend);

  InputGate(std::vector<BitVector<>>&& input, std::size_t party_id, Backend& backend);

  void InitializationHelper();

  ~InputGate() final = default;

  void EvaluateSetup() final override;

  void EvaluateOnline() final override;

  bool NeedsSetup() const override { return false; }

  const boolean_gmw::SharePointer GetOutputAsGmwShare();

 protected:
  /// two-dimensional vector for storing the raw inputs
  std::vector<BitVector<>> input_;

  std::size_t bits_;                ///< Number of parallel values on wires
  std::size_t boolean_sharing_id_;  ///< Sharing ID for Boolean GMW for generating
  ///< correlated randomness using AES CTR
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

  const boolean_gmw::SharePointer GetOutputAsGmwShare() const;

  const motion::SharePointer GetOutputAsShare() const;

 protected:
  // indicates whether this party obtains the output
  bool is_my_output_ = false;

  std::vector<ReusableFiberFuture<std::vector<std::uint8_t>>> output_message_futures_;

  std::mutex m_;
};

class XorGate final : public TwoGate {
 public:
  XorGate(const motion::SharePointer& a, const motion::SharePointer& b);

  ~XorGate() final = default;

  void EvaluateSetup() final override;

  void EvaluateOnline() final override;

  bool NeedsSetup() const override { return false; }

  const boolean_gmw::SharePointer GetOutputAsGmwShare() const;

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

  bool NeedsSetup() const override { return false; }

  const boolean_gmw::SharePointer GetOutputAsGmwShare() const;

  const motion::SharePointer GetOutputAsShare() const;

  InvGate() = delete;

  InvGate(const Gate&) = delete;
};

class AndGate final : public TwoGate {
 public:
  AndGate(const motion::SharePointer& a, const motion::SharePointer& b);

  ~AndGate() final = default;

  void EvaluateSetup() final override;

  void EvaluateOnline() final override;

  bool NeedsSetup() const override { return false; }

  const boolean_gmw::SharePointer GetOutputAsGmwShare() const;

  const motion::SharePointer GetOutputAsShare() const;

  AndGate() = delete;

  AndGate(const Gate&) = delete;

 private:
  std::size_t mt_offset_;
  std::size_t mt_bitlen_;

  std::shared_ptr<motion::Share> d_, e_;
  std::shared_ptr<OutputGate> d_output_, e_output_;
};

class MuxGate final : public ThreeGate {
 public:
  /// \brief Provides the functionality of ternary expression "s ? a : b";
  /// \param a first input share
  /// \param b second input share
  /// \param s selection bit share
  MuxGate(const motion::SharePointer& a, const motion::SharePointer& b,
          const motion::SharePointer& s);

  ~MuxGate() final = default;

  void EvaluateSetup() final override;

  void EvaluateOnline() final override;

  bool NeedsSetup() const override { return false; }

  const boolean_gmw::SharePointer GetOutputAsGmwShare() const;

  const motion::SharePointer GetOutputAsShare() const;

  MuxGate() = delete;

  MuxGate(const Gate&) = delete;

 private:
  std::vector<std::unique_ptr<XcOtReceiver>> ot_receiver_;
  std::vector<std::unique_ptr<XcOtSender>> ot_sender_;
};

}  // namespace encrypto::motion::proto::boolean_gmw