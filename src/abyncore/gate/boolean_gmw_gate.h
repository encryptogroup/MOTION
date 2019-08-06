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

#include "gate.h"

#include "share/boolean_gmw_share.h"
#include "utility/bit_vector.h"

namespace ABYN::Gates::GMW {

class GMWInputGate final : public Gates::Interfaces::InputGate {
 public:
  GMWInputGate(const std::vector<ENCRYPTO::BitVector<>> &input, std::size_t party_id,
               std::weak_ptr<Backend> reg);

  GMWInputGate(std::vector<ENCRYPTO::BitVector<>> &&input, std::size_t party_id,
               std::weak_ptr<Backend> reg);

  void InitializationHelper();

  ~GMWInputGate() final = default;

  void EvaluateSetup() final;

  void EvaluateOnline() final;

  const Shares::GMWSharePtr GetOutputAsGMWShare();

 protected:
  /// two-dimensional vector for storing the raw inputs
  std::vector<ENCRYPTO::BitVector<>> input_;

  std::size_t bits_;                ///< Number of parallel values on wires
  std::size_t boolean_sharing_id_;  ///< Sharing ID for Boolean GMW for generating
  ///< correlated randomness using AES CTR
};

class GMWOutputGate final : public Interfaces::OutputGate {
 public:
  GMWOutputGate(const std::vector<Wires::WirePtr> &parent, std::size_t output_owner);

  ~GMWOutputGate() final = default;

  void EvaluateSetup() final { SetSetupIsReady(); }

  void EvaluateOnline() final;

  const Shares::GMWSharePtr GetOutputAsGMWShare() const;

  const Shares::SharePtr GetOutputAsShare() const;

 protected:
  std::vector<ENCRYPTO::BitVector<>> output_;
  std::vector<std::vector<ENCRYPTO::BitVector<>>> shared_outputs_;

  // indicates whether this party obtains the output
  bool is_my_output_ = false;

  std::mutex m;
};

class GMWXORGate final : public Gates::Interfaces::TwoGate {
 public:
  GMWXORGate(const Shares::GMWSharePtr &a, const Shares::GMWSharePtr &b);

  ~GMWXORGate() final = default;

  void EvaluateSetup() final { SetSetupIsReady(); }

  void EvaluateOnline() final;

  const Shares::GMWSharePtr GetOutputAsGMWShare() const;

  const Shares::SharePtr GetOutputAsShare() const;

  GMWXORGate() = delete;

  GMWXORGate(const Gate &) = delete;
};

}  // namespace ABYN::Gates::GMW