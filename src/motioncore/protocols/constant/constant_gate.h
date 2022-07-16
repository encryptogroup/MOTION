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

#include "constant_wire.h"

#include "base/register.h"
#include "communication/communication_layer.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_share.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_wire.h"
#include "protocols/gate.h"
#include "utility/bit_vector.h"
#include "utility/constants.h"
#include "utility/logger.h"

namespace encrypto::motion::proto {

class Share;
using SharePointer = std::shared_ptr<Share>;

// constant input gates do not inherit from InputGate, since they have no owner
class ConstantBooleanInputGate final : public Gate {
 public:
  ConstantBooleanInputGate(bool b, Backend& backend)
      : ConstantBooleanInputGate(BitVector<>(1, b), backend) {}

  ConstantBooleanInputGate(BitVector<>&& bv, Backend& backend)
      : ConstantBooleanInputGate(std::vector<BitVector<>>{std::move(bv)}, backend) {}

  ConstantBooleanInputGate(const BitVector<>& bv, Backend& backend)
      : ConstantBooleanInputGate(std::vector<BitVector<>>{bv}, backend) {}

  ConstantBooleanInputGate(std::vector<BitVector<>>&& v, Backend& backend);

  ConstantBooleanInputGate(const std::vector<BitVector<>>& v, Backend& backend);

  ~ConstantBooleanInputGate() final = default;

  void EvaluateSetup() final override {}

  void EvaluateOnline() final override {}

  bool NeedsSetup() const override { return false; }

  bool NeedsOnline() const override { return false; }

  motion::SharePointer GetOutputAsShare() const;
};

// constant input gates do not inherit from InputGate, since they have no owner
template <typename T>
class ConstantArithmeticInputGate final : public Gate {
 public:
  ConstantArithmeticInputGate(const std::vector<T>& v, Backend& backend);

  ConstantArithmeticInputGate(std::vector<T>&& v, Backend& backend);

  ~ConstantArithmeticInputGate() final = default;

  void EvaluateSetup() final override {}

  void EvaluateOnline() final override {}

  bool NeedsSetup() const override { return false; }

  bool NeedsOnline() const override { return false; }

  motion::SharePointer GetOutputAsShare() const;
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class ConstantArithmeticAdditionGate final : public TwoGate {
 public:
  ConstantArithmeticAdditionGate(const ConstantArithmeticWirePointer<T>& a,
                                 const arithmetic_gmw::WirePointer<T>& b)
      : ConstantArithmeticAdditionGate(b, a) {}

  ConstantArithmeticAdditionGate(const arithmetic_gmw::WirePointer<T>& a,
                                 const ConstantArithmeticWirePointer<T>& b)
      : TwoGate(a->GetBackend()) {
    parent_a_ = {std::static_pointer_cast<Wire>(a)};
    parent_b_ = {std::static_pointer_cast<Wire>(b)};

    assert(parent_a_.at(0)->GetNumberOfSimdValues() == parent_b_.at(0)->GetNumberOfSimdValues());

    // assert that not both parent are const
    // TODO: a separate gate for this probably rather rare case
    // needs some mediocre implementation effort if implemented with a deferred inputs option
    assert(!parent_a_.at(0)->IsConstant() && parent_b_.at(0)->IsConstant());

    {
      auto w = GetRegister().template EmplaceWire<arithmetic_gmw::Wire<T>>(
          backend_, a->GetNumberOfSimdValues());
      output_wires_ = {std::move(w)};
    }

    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                    parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    GetLogger().LogDebug(fmt::format(
        "Created an ConstantArithmeticAdditionGate with following properties: {}", gate_info));
  }

  ~ConstantArithmeticAdditionGate() final = default;

  void EvaluateSetup() final override {}

  void EvaluateOnline() final override {
    // nothing to setup, no need to wait/check
    parent_a_.at(0)->GetIsReadyCondition().Wait();
    parent_b_.at(0)->GetIsReadyCondition().Wait();

    auto non_constant_wire_origin = parent_a_.at(0);
    auto constant_wire_origin = parent_b_.at(0);

    auto non_constant_wire =
        std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(non_constant_wire_origin);
    auto constant_wire =
        std::dynamic_pointer_cast<const ConstantArithmeticWire<T>>(constant_wire_origin);

    assert(non_constant_wire);
    assert(constant_wire);

    std::vector<T> output;
    if (GetCommunicationLayer().GetMyId() ==
        (gate_id_ % GetCommunicationLayer().GetNumberOfParties())) {
      output = RestrictAddVectors<T>(constant_wire->GetValues(), non_constant_wire->GetValues());
    } else {
      output = non_constant_wire->GetValues();
    }

    auto arithmetic_wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
    arithmetic_wire->GetMutableValues() = std::move(output);

    GetLogger().LogDebug(
        fmt::format("Evaluated arithmetic_gmw::AdditionGate with id#{}", gate_id_));
  }

  bool NeedsSetup() const override { return false; }

  // perhaps, we should return a copy of the pointer and not move it for the
  // case we need it multiple times
  arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticShare() {
    auto arithmetic_wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
    assert(arithmetic_wire);
    auto result = std::make_shared<arithmetic_gmw::Share<T>>(arithmetic_wire);
    return result;
  }

  ConstantArithmeticAdditionGate() = delete;

  ConstantArithmeticAdditionGate(Gate&) = delete;
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class ConstantArithmeticMultiplicationGate final : public TwoGate {
 public:
  ConstantArithmeticMultiplicationGate(const ConstantArithmeticWirePointer<T>& a,
                                       const arithmetic_gmw::WirePointer<T>& b)
      : ConstantArithmeticMultiplicationGate(b, a) {}

  ConstantArithmeticMultiplicationGate(const arithmetic_gmw::WirePointer<T>& a,
                                       const ConstantArithmeticWirePointer<T>& b)
      : TwoGate(a->GetBackend()) {
    parent_a_ = {std::static_pointer_cast<Wire>(a)};
    parent_b_ = {std::static_pointer_cast<Wire>(b)};

    assert(parent_a_.at(0)->GetNumberOfSimdValues() == parent_b_.at(0)->GetNumberOfSimdValues());

    // assert that not both parent are const
    // TODO: a separate gate for this probably rather rare case
    // needs some mediocre implementation effort if implemented with a deferred inputs option
    assert(!parent_a_.at(0)->IsConstant() && parent_b_.at(0)->IsConstant());
    {
      auto w = GetRegister().template EmplaceWire<arithmetic_gmw::Wire<T>>(
          backend_, a->GetNumberOfSimdValues());
      output_wires_ = {std::move(w)};
    }

    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                    parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    GetLogger().LogDebug(fmt::format(
        "Created an ConstantArithmeticMultiplicationGate with following properties: {}", gate_info));
  }

  ~ConstantArithmeticMultiplicationGate() final = default;

  void EvaluateSetup() final override {}

  void EvaluateOnline() final override {
    // nothing to setup, no need to wait/check
    parent_a_.at(0)->GetIsReadyCondition().Wait();
    parent_b_.at(0)->GetIsReadyCondition().Wait();

    auto non_constant_wire_origin = parent_a_.at(0);
    auto constant_wire_origin = parent_b_.at(0);

    auto non_constant_wire =
        std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(non_constant_wire_origin);
    auto constant_wire =
        std::dynamic_pointer_cast<const ConstantArithmeticWire<T>>(constant_wire_origin);

    assert(non_constant_wire);
    assert(constant_wire);

    std::vector<T> output =
        RestrictMulVectors<T>(constant_wire->GetValues(), non_constant_wire->GetValues());

    auto arithmetic_wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
    arithmetic_wire->GetMutableValues() = std::move(output);

    GetLogger().LogDebug(
        fmt::format("Evaluated arithmetic_gmw::MultiplicationGate with id#{}", gate_id_));
  }

  bool NeedsSetup() const override { return false; }

  // perhaps, we should return a copy of the pointer and not move it for the
  // case we need it multiple times
  arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticShare() {
    auto arithmetic_wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
    assert(arithmetic_wire);
    auto result = std::make_shared<arithmetic_gmw::Share<T>>(arithmetic_wire);
    return result;
  }

  ConstantArithmeticMultiplicationGate() = delete;

  ConstantArithmeticMultiplicationGate(Gate&) = delete;
};

}  // namespace encrypto::motion::proto
