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
#include "utility/reusable_future.h"

namespace ENCRYPTO::ObliviousTransfer {
class OTVectorSender;
class OTVectorReceiver;
}  // namespace ENCRYPTO::ObliviousTransfer

namespace MOTION::Gates::GMW {

class GMWInputGate final : public Gates::Interfaces::InputGate {
 public:
  GMWInputGate(const std::vector<ENCRYPTO::BitVector<>> &input, std::size_t party_id,
               std::weak_ptr<Backend> backend);

  GMWInputGate(std::vector<ENCRYPTO::BitVector<>> &&input, std::size_t party_id,
               std::weak_ptr<Backend> backend);

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

constexpr std::size_t ALL = std::numeric_limits<std::int64_t>::max();

class GMWOutputGate final : public Interfaces::OutputGate {
 public:
  GMWOutputGate(const Shares::SharePtr &parent, std::size_t output_owner = ALL);

  ~GMWOutputGate() final = default;

  void EvaluateSetup() final;

  void EvaluateOnline() final;

  const Shares::GMWSharePtr GetOutputAsGMWShare() const;

  const Shares::SharePtr GetOutputAsShare() const;

 protected:
  // indicates whether this party obtains the output
  bool is_my_output_ = false;

  std::vector<ENCRYPTO::ReusableFiberFuture<std::vector<std::uint8_t>>> output_message_futures_;

  std::mutex m;
};

class GMWXORGate final : public Gates::Interfaces::TwoGate {
 public:
  GMWXORGate(const Shares::SharePtr &a, const Shares::SharePtr &b);

  ~GMWXORGate() final = default;

  void EvaluateSetup() final;

  void EvaluateOnline() final;

  const Shares::GMWSharePtr GetOutputAsGMWShare() const;

  const Shares::SharePtr GetOutputAsShare() const;

  GMWXORGate() = delete;

  GMWXORGate(const Gate &) = delete;
};

class GMWINVGate final : public Gates::Interfaces::OneGate {
 public:
  GMWINVGate(const Shares::SharePtr &parent);

  ~GMWINVGate() final = default;

  void EvaluateSetup() final;

  void EvaluateOnline() final;

  const Shares::GMWSharePtr GetOutputAsGMWShare() const;

  const Shares::SharePtr GetOutputAsShare() const;

  GMWINVGate() = delete;

  GMWINVGate(const Gate &) = delete;
};

class GMWANDGate final : public Gates::Interfaces::TwoGate {
 public:
  GMWANDGate(const Shares::SharePtr &a, const Shares::SharePtr &b);

  ~GMWANDGate() final = default;

  void EvaluateSetup() final;

  void EvaluateOnline() final;

  const Shares::GMWSharePtr GetOutputAsGMWShare() const;

  const Shares::SharePtr GetOutputAsShare() const;

  GMWANDGate() = delete;

  GMWANDGate(const Gate &) = delete;

 private:
  std::size_t mt_offset_;
  std::size_t mt_bitlen_;

  std::shared_ptr<Shares::Share> d_, e_;
  std::shared_ptr<GMWOutputGate> d_out_, e_out_;
};

class GMWMUXGate final : public Gates::Interfaces::ThreeGate {
 public:
  /// \brief Provides the functionality of ternary expression "s ? a : b";
  /// \param a first input share
  /// \param b second input share
  /// \param s selection bit share
  GMWMUXGate(const Shares::SharePtr &a, const Shares::SharePtr &b, const Shares::SharePtr &s);

  ~GMWMUXGate() final = default;

  void EvaluateSetup() final;

  void EvaluateOnline() final;

  const Shares::GMWSharePtr GetOutputAsGMWShare() const;

  const Shares::SharePtr GetOutputAsShare() const;

  GMWMUXGate() = delete;

  GMWMUXGate(const Gate &) = delete;

 private:
  std::vector<std::shared_ptr<ENCRYPTO::ObliviousTransfer::OTVectorReceiver>> ot_receiver_;
  std::vector<std::shared_ptr<ENCRYPTO::ObliviousTransfer::OTVectorSender>> ot_sender_;
};

}  // namespace MOTION::Gates::GMW
