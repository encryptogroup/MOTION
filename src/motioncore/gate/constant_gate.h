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

#include "base/configuration.h"
#include "base/register.h"
#include "gate.h"
#include "share/arithmetic_gmw_share.h"
#include "utility/bit_vector.h"
#include "utility/constants.h"
#include "utility/logger.h"
#include "wire/arithmetic_gmw_wire.h"
#include "wire/constant_wire.h"

namespace MOTION {

namespace Shares {
class Share;
using SharePtr = std::shared_ptr<Share>;
}  // namespace Shares

namespace Gates {

// constant input gates do not inherit from InputGate, since they have no owner
class ConstantBooleanInputGate : public Gate {
 public:
  ConstantBooleanInputGate(bool b, Backend& backend)
      : ConstantBooleanInputGate(ENCRYPTO::BitVector<>(b), backend) {}

  ConstantBooleanInputGate(ENCRYPTO::BitVector<>&& bv, Backend& backend)
      : ConstantBooleanInputGate(std::vector<ENCRYPTO::BitVector<>>{std::move(bv)}, backend) {}

  ConstantBooleanInputGate(const ENCRYPTO::BitVector<>& bv, Backend& backend)
      : ConstantBooleanInputGate(std::vector<ENCRYPTO::BitVector<>>{bv}, backend) {}

  ConstantBooleanInputGate(std::vector<ENCRYPTO::BitVector<>>&& v, Backend& backend);

  ConstantBooleanInputGate(const std::vector<ENCRYPTO::BitVector<>>& v, Backend& backend);

  ~ConstantBooleanInputGate() final = default;

  void InitializationHelper();

  void EvaluateSetup() final {
    SetSetupIsReady();
    GetRegister().IncrementEvaluatedGateSetupsCounter();
  }

  void EvaluateOnline() final {
    WaitSetup();
    SetOnlineIsReady();
    GetRegister().IncrementEvaluatedGatesCounter();
  }

  MOTION::Shares::SharePtr GetOutputAsShare() const;
};

namespace Arithmetic {

// constant input gates do not inherit from InputGate, since they have no owner
template <typename T>
class ConstantArithmeticInputGate : public Gate {
 public:
  ConstantArithmeticInputGate(const std::vector<T>& v, Backend& backend);

  ConstantArithmeticInputGate(std::vector<T>&& v, Backend& backend);

  ~ConstantArithmeticInputGate() final = default;

  void InitializationHelper() {
    static_assert(!std::is_same_v<T, bool>);

    gate_id_ = GetRegister().NextGateId();
    if constexpr (MOTION::MOTION_VERBOSE_DEBUG) {
      GetLogger().LogTrace(
          fmt::format("Created a ConstantArithmeticInputGate with global id {}", gate_id_));
    }

    for (auto& w : output_wires_) GetRegister().RegisterNextWire(w);

    auto gate_info = fmt::format("uint{}_t type, gate id {}", sizeof(T) * 8, gate_id_);
    GetLogger().LogDebug(fmt::format(
        "Allocated a ConstantArithmeticInputGate with following properties: {}", gate_info));
  }

  void EvaluateSetup() final {
    SetSetupIsReady();
    GetRegister().IncrementEvaluatedGateSetupsCounter();
  };

  void EvaluateOnline() final {
    WaitSetup();
    SetOnlineIsReady();
    GetRegister().IncrementEvaluatedGatesCounter();
  };

  MOTION::Shares::SharePtr GetOutputAsShare() const;
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class ConstantArithmeticAdditionGate final : public MOTION::Gates::Interfaces::TwoGate {
 public:
  ConstantArithmeticAdditionGate(const MOTION::Wires::ConstantArithmeticWirePtr<T>& a,
                                 const MOTION::Wires::ArithmeticWirePtr<T>& b)
      : ConstantArithmeticAdditionGate(b, a) {}

  ConstantArithmeticAdditionGate(const MOTION::Wires::ArithmeticWirePtr<T>& a,
                                 const MOTION::Wires::ConstantArithmeticWirePtr<T>& b)
      : TwoGate(a->GetBackend()) {
    parent_a_ = {std::static_pointer_cast<MOTION::Wires::Wire>(a)};
    parent_b_ = {std::static_pointer_cast<MOTION::Wires::Wire>(b)};

    assert(parent_a_.at(0)->GetNumOfSIMDValues() == parent_b_.at(0)->GetNumOfSIMDValues());

    // assert that not both parent are const
    // TODO: a separate gate for this probably rather rare case
    // needs some mediocre implementation effort if implemented with a deferred inputs option
    assert(!parent_a_.at(0)->IsConstant() && parent_b_.at(0)->IsConstant());

    requires_online_interaction_ = false;
    gate_type_ = GateType::NonInteractive;

    gate_id_ = GetRegister().NextGateId();

    RegisterWaitingFor(parent_a_.at(0)->GetWireId());
    parent_a_.at(0)->RegisterWaitingGate(gate_id_);

    RegisterWaitingFor(parent_b_.at(0)->GetWireId());
    parent_b_.at(0)->RegisterWaitingGate(gate_id_);

    {
      auto w = std::make_shared<Wires::ArithmeticWire<T>>(backend_, a->GetNumOfSIMDValues());
      GetRegister().RegisterNextWire(w);
      output_wires_ = {std::move(w)};
    }

    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                    parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    GetLogger().LogDebug(fmt::format(
        "Created an ConstantArithmeticAdditionGate with following properties: {}", gate_info));
  }

  ~ConstantArithmeticAdditionGate() final = default;

  void EvaluateSetup() final {
    SetSetupIsReady();
    GetRegister().IncrementEvaluatedGateSetupsCounter();
  }

  void EvaluateOnline() final {
    WaitSetup();
    assert(setup_is_ready_);

    parent_a_.at(0)->GetIsReadyCondition().Wait();
    parent_b_.at(0)->GetIsReadyCondition().Wait();

    auto non_const_wire_orig = parent_a_.at(0);
    auto const_wire_orig = parent_b_.at(0);

    auto ncwire = std::dynamic_pointer_cast<const Wires::ArithmeticWire<T>>(non_const_wire_orig);
    auto cwire = std::dynamic_pointer_cast<const Wires::ConstantArithmeticWire<T>>(const_wire_orig);

    assert(ncwire);
    assert(cwire);

    std::vector<T> output;
    if (GetConfig().GetMyId() == (gate_id_ % GetConfig().GetNumOfParties()))
      output = Helpers::RestrictAddVectors(cwire->GetValues(), ncwire->GetValues());
    else {
      output = ncwire->GetValues();
    }

    auto arithmetic_wire =
        std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(output_wires_.at(0));
    arithmetic_wire->GetMutableValues() = std::move(output);

    GetLogger().LogDebug(fmt::format("Evaluated ArithmeticAdditionGate with id#{}", gate_id_));
    SetOnlineIsReady();
    GetRegister().IncrementEvaluatedGatesCounter();
  }

  // perhaps, we should return a copy of the pointer and not move it for the
  // case we need it multiple times
  MOTION::Shares::ArithmeticSharePtr<T> GetOutputAsArithmeticShare() {
    auto arithmetic_wire =
        std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(output_wires_.at(0));
    assert(arithmetic_wire);
    auto result = std::make_shared<MOTION::Shares::ArithmeticShare<T>>(arithmetic_wire);
    return result;
  }

  ConstantArithmeticAdditionGate() = delete;

  ConstantArithmeticAdditionGate(Gate&) = delete;
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class ConstantArithmeticMultiplicationGate final : public MOTION::Gates::Interfaces::TwoGate {
 public:
  ConstantArithmeticMultiplicationGate(const MOTION::Wires::ConstantArithmeticWirePtr<T>& a,
                                       const MOTION::Wires::ArithmeticWirePtr<T>& b)
      : ConstantArithmeticMultiplicationGate(b, a) {}

  ConstantArithmeticMultiplicationGate(const MOTION::Wires::ArithmeticWirePtr<T>& a,
                                       const MOTION::Wires::ConstantArithmeticWirePtr<T>& b)
      : TwoGate(a->GetBackend()) {
    parent_a_ = {std::static_pointer_cast<MOTION::Wires::Wire>(a)};
    parent_b_ = {std::static_pointer_cast<MOTION::Wires::Wire>(b)};

    assert(parent_a_.at(0)->GetNumOfSIMDValues() == parent_b_.at(0)->GetNumOfSIMDValues());

    // assert that not both parent are const
    // TODO: a separate gate for this probably rather rare case
    // needs some mediocre implementation effort if implemented with a deferred inputs option
    assert(!parent_a_.at(0)->IsConstant() && parent_b_.at(0)->IsConstant());

    requires_online_interaction_ = false;
    gate_type_ = GateType::NonInteractive;

    gate_id_ = GetRegister().NextGateId();

    RegisterWaitingFor(parent_a_.at(0)->GetWireId());
    parent_a_.at(0)->RegisterWaitingGate(gate_id_);

    RegisterWaitingFor(parent_b_.at(0)->GetWireId());
    parent_b_.at(0)->RegisterWaitingGate(gate_id_);

    {
      auto w = std::make_shared<Wires::ArithmeticWire<T>>(backend_, a->GetNumOfSIMDValues());
      GetRegister().RegisterNextWire(w);
      output_wires_ = {std::move(w)};
    }

    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                    parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    GetLogger().LogDebug(fmt::format(
        "Created an ConstantArithmeticAdditionGate with following properties: {}", gate_info));
  }

  ~ConstantArithmeticMultiplicationGate() final = default;

  void EvaluateSetup() final {
    SetSetupIsReady();
    GetRegister().IncrementEvaluatedGateSetupsCounter();
  }

  void EvaluateOnline() final {
    WaitSetup();
    assert(setup_is_ready_);

    parent_a_.at(0)->GetIsReadyCondition().Wait();
    parent_b_.at(0)->GetIsReadyCondition().Wait();

    auto non_const_wire_orig = parent_a_.at(0);
    auto const_wire_orig = parent_b_.at(0);

    auto ncwire = std::dynamic_pointer_cast<const Wires::ArithmeticWire<T>>(non_const_wire_orig);
    auto cwire = std::dynamic_pointer_cast<const Wires::ConstantArithmeticWire<T>>(const_wire_orig);

    assert(ncwire);
    assert(cwire);

    std::vector<T> output = Helpers::RestrictMulVectors(cwire->GetValues(), ncwire->GetValues());

    auto arithmetic_wire =
        std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(output_wires_.at(0));
    arithmetic_wire->GetMutableValues() = std::move(output);

    GetLogger().LogDebug(fmt::format("Evaluated ArithmeticAdditionGate with id#{}", gate_id_));
    SetOnlineIsReady();
    GetRegister().IncrementEvaluatedGatesCounter();
  }

  // perhaps, we should return a copy of the pointer and not move it for the
  // case we need it multiple times
  MOTION::Shares::ArithmeticSharePtr<T> GetOutputAsArithmeticShare() {
    auto arithmetic_wire =
        std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(output_wires_.at(0));
    assert(arithmetic_wire);
    auto result = std::make_shared<MOTION::Shares::ArithmeticShare<T>>(arithmetic_wire);
    return result;
  }

  ConstantArithmeticMultiplicationGate() = delete;

  ConstantArithmeticMultiplicationGate(Gate&) = delete;
};

}  // namespace Arithmetic
}  // namespace Gates
}  // namespace MOTION
