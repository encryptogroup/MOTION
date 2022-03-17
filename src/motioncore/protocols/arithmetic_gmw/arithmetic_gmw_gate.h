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

#include <span>

#include "base/motion_base_provider.h"
#include "communication/fbs_headers/output_message_generated.h"
#include "multiplication_triple/mt_provider.h"
#include "multiplication_triple/sp_provider.h"
#include "primitives/sharing_randomness_generator.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/gate.h"
#include "utility/reusable_future.h"

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

  void InitializationHelper();

  ~InputGate() final = default;

  void EvaluateSetup() final override;
  // non-interactive input sharing based on distributed in advance randomness seeds
  void EvaluateOnline() final override;

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

  // perhaps, we should return a copy of the pointer and not move it for the case we need it
  // multiple times
  arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticShare();

  MultiplicationGate() = delete;
  MultiplicationGate(Gate&) = delete;

 private:
  arithmetic_gmw::WirePointer<T> d_, e_;
  std::shared_ptr<OutputGate<T>> d_output_, e_output_;

  std::size_t number_of_mts_, mt_offset_;
};

// Multiplication of an arithmetic share with a boolean bit.
// Based on [ST21]: https://iacr.org/2021/029.pdf
template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class HybridMultiplicationGate final : public motion::TwoGate {
 public:
  HybridMultiplicationGate(boolean_gmw::WirePointer& bit,
                           arithmetic_gmw::WirePointer<T>& integer)
      : TwoGate(bit->GetBackend()) {
    // this gate works only for two parties
    assert(GetCommunicationLayer().GetNumberOfParties() == 2);
    parent_a_ = {std::static_pointer_cast<motion::Wire>(bit)};
    parent_b_ = {std::static_pointer_cast<motion::Wire>(integer)};

    assert(parent_a_.at(0)->GetNumberOfSimdValues() == parent_b_.at(0)->GetNumberOfSimdValues());
    assert(parent_a_.at(0)->GetBitLength() == 1);

    requires_online_interaction_ = true;
    gate_type_ = GateType::kInteractive;

    gate_id_ = GetRegister().NextGateId();

    RegisterWaitingFor(parent_a_.at(0)->GetWireId());
    parent_a_.at(0)->RegisterWaitingGate(gate_id_);

    RegisterWaitingFor(parent_b_.at(0)->GetWireId());
    parent_b_.at(0)->RegisterWaitingGate(gate_id_);

    const std::size_t number_of_simd_values = parent_a_[0]->GetNumberOfSimdValues();
    {
      auto w = std::static_pointer_cast<motion::Wire>(
          std::make_shared<arithmetic_gmw::Wire<T>>(backend_, number_of_simd_values));
      GetRegister().RegisterNextWire(w);
      output_wires_ = {std::move(w)};
    }

    const std::size_t number_of_parties{GetCommunicationLayer().GetNumberOfParties()};
    const std::size_t my_id = GetCommunicationLayer().GetMyId();

    for (std::size_t i = 0; i < number_of_parties; ++i) {
      if (i == my_id) continue;
      ot_sender_ = GetOtProvider(i).template RegisterSendAcOt<T>(number_of_simd_values);
      ot_receiver_ = GetOtProvider(i).template RegisterReceiveAcOt<T>(number_of_simd_values);
    }

    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                    parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    GetLogger().LogDebug(fmt::format(
        "Created an arithmetic_gmw::HybridMultiplicationGate with following properties: {}",
        gate_info));
  }

  ~HybridMultiplicationGate() final = default;

  void EvaluateSetup() final override {
    SetSetupIsReady();
    GetRegister().IncrementEvaluatedGatesSetupCounter();
  }

  void EvaluateOnline() final override {
    WaitSetup();
    assert(setup_is_ready_);
    parent_a_.at(0)->GetIsReadyCondition().Wait();
    parent_b_.at(0)->GetIsReadyCondition().Wait();

    const auto bw =
        std::dynamic_pointer_cast<boolean_gmw::Wire>(parent_a_.at(0));
    assert(bw);
    const auto aw = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(
        parent_b_.at(0));
    assert(aw);

    auto a_out = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
    assert(a_out);
    a_out->GetMutableValues().reserve(aw->GetNumberOfSimdValues());

    auto& bv = bw->GetValues();
    auto& av = aw->GetValues();

    std::vector<T> ot_data;
    ot_data.reserve(bv.GetSize());
    for (std::size_t i = 0; i != bv.GetSize(); ++i) {
      // (-1)^<b>_i^B * <v>_i^A + r as AC-OT msgs for party i-1
      ot_data.emplace_back(bv[i] ? -av[i] : av[i]);
      // Locally calculate <b>_i^B * <v>_i^A
      a_out->GetMutableValues().emplace_back(bv[i] ? av[i] : static_cast<T>(0));
    }

    // AcOt Send and Recieve

    ot_sender_->WaitSetup();
    ot_sender_->SetCorrelations(ot_data);
    ot_sender_->SendMessages();

    ot_receiver_->WaitSetup();
    ot_receiver_->SetChoices(bv);
    ot_receiver_->SendCorrections();

    const std::size_t number_of_simd_values = parent_a_[0]->GetNumberOfSimdValues();

    ot_sender_->ComputeOutputs();
    ot_receiver_->ComputeOutputs();

    // parse OT outputs
    std::vector<T> ot_sender_output{ot_sender_->GetOutputs()};
    std::vector<T> ot_receiver_output{ot_receiver_->GetOutputs()};

    // Compute the result
    for (std::size_t simd_i = 0; simd_i < number_of_simd_values; ++simd_i) {
      a_out->GetMutableValues()[simd_i] += ot_receiver_output[simd_i] - ot_sender_output[simd_i];
    }

    GetLogger().LogDebug(
        fmt::format("Evaluated arithmetic_gmw::HybridMultiplicationGate with id#{}", gate_id_));
    SetOnlineIsReady();
    GetRegister().IncrementEvaluatedGatesOnlineCounter();
  }

  // perhaps, we should return a copy of the pointer and not move it for the
  // case we need it multiple times
  arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticShare() {
    auto arithmetic_wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
    assert(arithmetic_wire);
    auto result = std::make_shared<arithmetic_gmw::Share<T>>(arithmetic_wire);
    return result;
  }

  HybridMultiplicationGate() = delete;

  HybridMultiplicationGate(Gate&) = delete;

 private:
  std::unique_ptr<AcOtReceiver<T>> ot_receiver_;
  std::unique_ptr<AcOtSender<T>> ot_sender_;
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class SquareGate final : public motion::OneGate {
 public:
  SquareGate(const arithmetic_gmw::WirePointer<T>& a);
  ~SquareGate() final = default;

  void EvaluateSetup() final override;
  void EvaluateOnline() final override;

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
