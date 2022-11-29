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

// added by Liang Zhao
// #include "protocols/share.h"
#include <span>
#include "constant_share.h"
#include "protocols/boolean_gmw/boolean_gmw_gate.h"
#include "protocols/boolean_gmw/boolean_gmw_share.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
// #include "protocols/wire_wrapper.h"
#include "utility/reusable_future.h"
namespace encrypto::motion::proto {

class Share;
using SharePointer = std::shared_ptr<Share>;

// added by Liang Zhao
constexpr std::size_t kAll = std::numeric_limits<std::int64_t>::max();

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

  // added by Liang Zhao
  ConstantBooleanInputGate(std::span<const BitVector<>> v, Backend& backend);

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

    // std::cout<<"parent_a_.at(0)->GetNumberOfSimdValues():
    // "<<parent_a_.at(0)->GetNumberOfSimdValues()<<std::endl;
    // std::cout<<"parent_b_.at(0)->GetNumberOfSimdValues():
    // "<<parent_b_.at(0)->GetNumberOfSimdValues()<<std::endl;

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

  // added by Liang Zhao
  ConstantArithmeticAdditionGate(const ConstantArithmeticWirePointer<T>& a,
                                 const ConstantArithmeticWirePointer<T>& b)
      : TwoGate(a->GetBackend()) {
    both_input_wires_are_constant = true;
    parent_a_ = {std::static_pointer_cast<Wire>(a)};
    parent_b_ = {std::static_pointer_cast<Wire>(b)};

    assert(parent_a_.at(0)->GetNumberOfSimdValues() == parent_b_.at(0)->GetNumberOfSimdValues());

    // assert that both parent are const
    assert(parent_a_.at(0)->IsConstant() && parent_b_.at(0)->IsConstant());

    std::vector<T> output = RestrictAddVectors<T>(a->GetValues(), b->GetValues());

    output_wires_.emplace_back(GetRegister().template EmplaceWire<ConstantArithmeticWire<T>>(
        std::move(output), a->GetBackend()));

    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                    parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    GetLogger().LogDebug(fmt::format(
        "Created an  ConstantArithmeticAdditionGate with following properties: {}", gate_info));
  }

  ~ConstantArithmeticAdditionGate() final = default;

  void EvaluateSetup() final override {}

  void EvaluateOnline() final override {
    if (!both_input_wires_are_constant) {  // nothing to setup, no need to wait/check
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

      auto arithmetic_wire =
          std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
      arithmetic_wire->GetMutableValues() = std::move(output);

      GetLogger().LogDebug(
          fmt::format("Evaluated arithmetic_gmw::AdditionGate with id#{}", gate_id_));
    }

    // a + b
    else {
    }
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

  // added by Liang Zhao
  ConstantArithmeticSharePointer<T> GetOutputAsConstantArithmeticShare() {
    auto constant_arithmetic_wire =
        std::dynamic_pointer_cast<ConstantArithmeticWire<T>>(output_wires_.at(0));
    assert(constant_arithmetic_wire);
    auto result = std::make_shared<ConstantArithmeticShare<T>>(constant_arithmetic_wire);
    return result;
  }

  ConstantArithmeticAdditionGate() = delete;

  ConstantArithmeticAdditionGate(Gate&) = delete;

 private:
  bool both_input_wires_are_constant = false;
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class ConstantArithmeticSubtractionGate final : public TwoGate {
 public:
  ConstantArithmeticSubtractionGate(const ConstantArithmeticWirePointer<T>& a,
                                    const arithmetic_gmw::WirePointer<T>& b)
      : TwoGate(a->GetBackend()) {
    first_input_wire_is_constant = true;
    parent_a_ = {std::static_pointer_cast<Wire>(a)};
    parent_b_ = {std::static_pointer_cast<Wire>(b)};

    assert(parent_a_.at(0)->GetNumberOfSimdValues() == parent_b_.at(0)->GetNumberOfSimdValues());

    // assert that not both parent are const
    assert(parent_a_.at(0)->IsConstant() && !parent_b_.at(0)->IsConstant());

    {
      auto w = GetRegister().template EmplaceWire<arithmetic_gmw::Wire<T>>(
          backend_, a->GetNumberOfSimdValues());
      output_wires_ = {std::move(w)};
    }

    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                    parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    GetLogger().LogDebug(fmt::format(
        "Created an ConstantArithmeticSubtractionGate with following properties: {}", gate_info));
  }

  ConstantArithmeticSubtractionGate(const arithmetic_gmw::WirePointer<T>& a,
                                    const ConstantArithmeticWirePointer<T>& b)
      : TwoGate(a->GetBackend()) {
    second_input_wire_is_constant = true;

    // std::cout<<"001"<<std::endl;

    parent_a_ = {std::static_pointer_cast<Wire>(a)};
    parent_b_ = {std::static_pointer_cast<Wire>(b)};

    assert(parent_a_.at(0)->GetNumberOfSimdValues() == parent_b_.at(0)->GetNumberOfSimdValues());

    // assert that not both parent are const
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
        "Created an ConstantArithmeticSubtractionGate with following properties: {}", gate_info));
  }

  ConstantArithmeticSubtractionGate(const ConstantArithmeticWirePointer<T>& a,
                                    const ConstantArithmeticWirePointer<T>& b)
      : TwoGate(a->GetBackend()) {
    both_input_wires_are_constant = true;
    parent_a_ = {std::static_pointer_cast<Wire>(a)};
    parent_b_ = {std::static_pointer_cast<Wire>(b)};

    assert(parent_a_.at(0)->GetNumberOfSimdValues() == parent_b_.at(0)->GetNumberOfSimdValues());

    // assert that both parent are const
    assert(parent_a_.at(0)->IsConstant() && parent_b_.at(0)->IsConstant());

    std::vector<T> output = SubVectors<T>(a->GetValues(), b->GetValues());

    output_wires_.emplace_back(GetRegister().template EmplaceWire<ConstantArithmeticWire<T>>(
        std::move(output), a->GetBackend()));

    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                    parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    GetLogger().LogDebug(fmt::format(
        "Created an  ConstantArithmeticSubtractionGate with following properties: {}", gate_info));
  }

  ~ConstantArithmeticSubtractionGate() final = default;

  void EvaluateSetup() final override {}

  void EvaluateOnline() final override {
    // a - <b>
    if (!both_input_wires_are_constant &&
        first_input_wire_is_constant) {  // nothing to setup, no need to wait/check

      // parent_a_.at(0)->GetIsReadyCondition().Wait();
      parent_b_.at(0)->GetIsReadyCondition().Wait();

      auto constant_wire_origin = parent_a_.at(0);
      auto non_constant_wire_origin = parent_b_.at(0);

      auto constant_wire =
          std::dynamic_pointer_cast<const ConstantArithmeticWire<T>>(constant_wire_origin);
      auto non_constant_wire =
          std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(non_constant_wire_origin);

      assert(constant_wire);
      assert(non_constant_wire);

      std::vector<T> output;
      if (GetCommunicationLayer().GetMyId() ==
          (gate_id_ % GetCommunicationLayer().GetNumberOfParties())) {
        output = SubVectors<T>(constant_wire->GetValues(), non_constant_wire->GetValues());
      } else {
        std::vector<T> non_constant_wire_neg;
        non_constant_wire_neg = MinusVectors<T>(non_constant_wire->GetValues());
        output = non_constant_wire_neg;
        // output = non_constant_wire->GetValues();
      }

      auto arithmetic_wire =
          std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
      arithmetic_wire->GetMutableValues() = std::move(output);

      GetLogger().LogDebug(
          fmt::format("Evaluated arithmetic_gmw::SubtractionGate with id#{}", gate_id_));
    }

    // <a> - b
    else if (!both_input_wires_are_constant && second_input_wire_is_constant) {
      // std::cout<<"002"<<std::endl;
      parent_a_.at(0)->GetIsReadyCondition().Wait();
      // parent_b_.at(0)->GetIsReadyCondition().Wait();

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
        output = SubVectors<T>(non_constant_wire->GetValues(), constant_wire->GetValues());
      } else {
        output = non_constant_wire->GetValues();
      }

      auto arithmetic_wire =
          std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
      arithmetic_wire->GetMutableValues() = std::move(output);

      GetLogger().LogDebug(
          fmt::format("Evaluated arithmetic_gmw::SubtractionGate with id#{}", gate_id_));

    }

    // a - b
    else {
    }
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

  ConstantArithmeticSharePointer<T> GetOutputAsConstantArithmeticShare() {
    auto constant_arithmetic_wire =
        std::dynamic_pointer_cast<ConstantArithmeticWire<T>>(output_wires_.at(0));
    assert(constant_arithmetic_wire);
    auto result = std::make_shared<ConstantArithmeticShare<T>>(constant_arithmetic_wire);
    return result;
  }

  ConstantArithmeticSubtractionGate() = delete;

  ConstantArithmeticSubtractionGate(Gate&) = delete;

 private:
  bool both_input_wires_are_constant = false;
  bool first_input_wire_is_constant = false;
  bool second_input_wire_is_constant = false;
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
    GetLogger().LogDebug(
        fmt::format("Created an ConstantArithmeticMultiplicationGate with following properties: {}",
                    gate_info));
  }

  // added by Liang Zhao
  ConstantArithmeticMultiplicationGate(const ConstantArithmeticWirePointer<T>& a,
                                       const ConstantArithmeticWirePointer<T>& b)
      : TwoGate(a->GetBackend()) {
    both_input_wires_are_constant = true;
    parent_a_ = {std::static_pointer_cast<Wire>(a)};
    parent_b_ = {std::static_pointer_cast<Wire>(b)};

    assert(parent_a_.at(0)->GetNumberOfSimdValues() == parent_b_.at(0)->GetNumberOfSimdValues());

    // assert that both parent are const
    assert(parent_a_.at(0)->IsConstant() && parent_b_.at(0)->IsConstant());

    std::vector<T> output = RestrictMulVectors<T>(a->GetValues(), b->GetValues());

    output_wires_.emplace_back(GetRegister().template EmplaceWire<ConstantArithmeticWire<T>>(
        std::move(output), a->GetBackend()));

    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                    parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    GetLogger().LogDebug(fmt::format(
        "Created an  ConstantArithmeticMultiplicationGate with following properties: {}",
        gate_info));
  }

  ~ConstantArithmeticMultiplicationGate() final = default;

  void EvaluateSetup() final override {}

  void EvaluateOnline() final override {
    // <a> * b
    if (!both_input_wires_are_constant) {  // nothing to setup, no need to wait/check
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

      auto arithmetic_wire =
          std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
      arithmetic_wire->GetMutableValues() = std::move(output);

      GetLogger().LogDebug(
          fmt::format("Evaluated arithmetic_gmw::MultiplicationGate with id#{}", gate_id_));
    }

    // a * b
    else {
    }
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

  // added by Liang Zhao
  ConstantArithmeticSharePointer<T> GetOutputAsConstantArithmeticShare() {
    auto constant_arithmetic_wire =
        std::dynamic_pointer_cast<ConstantArithmeticWire<T>>(output_wires_.at(0));
    assert(constant_arithmetic_wire);
    auto result = std::make_shared<ConstantArithmeticShare<T>>(constant_arithmetic_wire);
    return result;
  }

  ConstantArithmeticMultiplicationGate() = delete;

  ConstantArithmeticMultiplicationGate(Gate&) = delete;

 private:
  bool both_input_wires_are_constant = false;
};

// // added by Liang Zhao
// template <typename T>
// class ArithmeticGmwValueLessThanGate final : public TwoGate {
//  public:
//   ArithmeticGmwValueLessThanGate(const arithmetic_gmw::WirePointer<T>& a,
//                                  const arithmetic_gmw::WirePointer<T>& b,
//                                  bool set_zero_as_maximum = false)
//       : TwoGate(a->GetBackend()) {
//     parent_a_ = {std::static_pointer_cast<Wire>(a)};
//     parent_b_ = {std::static_pointer_cast<Wire>(b)};

//     set_zero_as_maximum_ = set_zero_as_maximum;

//     assert(parent_a_.at(0)->GetNumberOfSimdValues() ==
//     parent_b_.at(0)->GetNumberOfSimdValues());

//     requires_online_interaction_ = false;
//     gate_type_ = GateType::kNonInteractive;

//     gate_id_ = GetRegister().NextGateId();

//     RegisterWaitingFor(parent_a_.at(0)->GetWireId());
//     parent_a_.at(0)->RegisterWaitingGate(gate_id_);

//     RegisterWaitingFor(parent_b_.at(0)->GetWireId());
//     parent_b_.at(0)->RegisterWaitingGate(gate_id_);

//     num_of_output_wires_ = parent_a_.size();
//     num_of_simd_ = a->GetNumberOfSimdValues();

//     // reserve for boolean output wires
//     boolean_output_wires_.reserve(num_of_output_wires_);
//     auto& boolean_wire =
//     boolean_output_wires_.emplace_back(std::static_pointer_cast<motion::Wire>(
//         std::make_shared<motion::proto::boolean_gmw::Wire>(backend_, num_of_simd_)));
//     GetRegister().RegisterNextWire(boolean_wire);

//     // reserve for arithmetic output wire
//     arithmetic_output_wires_.reserve(num_of_output_wires_);
//     auto& arithmetic_wire =
//         arithmetic_output_wires_.emplace_back(std::static_pointer_cast<motion::Wire>(
//             std::make_shared<motion::proto::arithmetic_gmw::Wire<T>>(backend_, num_of_simd_)));
//     GetRegister().RegisterNextWire(arithmetic_wire);

//     // a < b
//     if (a->IsPubliclyKnownWire() && b->IsPubliclyKnownWire()) {
//       boolean_output_wires_.at(0)->SetAsPubliclyKnownWire();
//       arithmetic_output_wires_.at(0)->SetAsPubliclyKnownWire();
//     }

//     // <a> < <b>
//     // <>: publicly unknown share value
//     else {
//       boolean_output_wires_.at(0)->SetAsPubliclyUnknownWire();
//       arithmetic_output_wires_.at(0)->SetAsPubliclyUnknownWire();
//     }

//     auto gate_info =
//         fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
//                     parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
//     GetLogger().LogDebug(fmt::format(
//         "Created an ArithmeticGmwValueLessThanGate with following properties: {}", gate_info));
//   }

//   ~ArithmeticGmwValueLessThanGate() final = default;

//   void EvaluateSetup() final override {
//     SetSetupIsReady();
//     GetRegister().IncrementEvaluatedGatesSetupCounter();
//   }

//   void EvaluateOnline() final override {
//     WaitSetup();
//     assert(setup_is_ready_);

//     parent_a_.at(0)->GetIsReadyCondition().Wait();
//     parent_b_.at(0)->GetIsReadyCondition().Wait();

//     auto input_wire_a = parent_a_.at(0);
//     auto input_wire_b = parent_b_.at(0);

//     auto arithmetic_input_wire_a =
//         std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(input_wire_a);
//     auto arithmetic_input_wire_b =
//         std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(input_wire_b);

//     // std::cout << "arithmetic_input_wire_a: " <<
//     // unsigned(arithmetic_input_wire_a->GetValues().at(0))
//     //           << std::endl;
//     // std::cout << "arithmetic_input_wire_b: " <<
//     // unsigned(arithmetic_input_wire_b->GetValues().at(0))
//     //           << std::endl;

//     assert(arithmetic_input_wire_a);
//     assert(arithmetic_input_wire_b);

//     bool output;
//     std::vector<bool> output_vector(num_of_simd_);
//     // std::cout << "set_zero_as_maximum_: " << set_zero_as_maximum_ << std::endl;

//     for (std::size_t i = 0; i < num_of_simd_; i++) {
//       // take zero as the minimum value
//       if (!set_zero_as_maximum_) {
//         // output =
//         //     arithmetic_input_wire_a->GetValues().at(0) <
//         //     arithmetic_input_wire_b->GetValues().at(0);
//         output_vector[i] =
//             arithmetic_input_wire_a->GetValues().at(i) <
//             arithmetic_input_wire_b->GetValues().at(i);
//       }

//       // take zero as the maximum value
//       else {
//         // // a = 0 (set a as maximum value)
//         // if (arithmetic_input_wire_a->GetValues().at(0) == 0) {
//         //   // std::cout << "arithmetic_input_wire_a->GetValues().at(0) == 0" << std::endl;
//         //   output = false;
//         // }

//         // b = 0, a != 0
//         if ((arithmetic_input_wire_b->GetValues().at(i) == 0) &&
//             (arithmetic_input_wire_a->GetValues().at(i) != 0)) {
//           output_vector[i] = true;
//         } else {
//           output_vector[i] = arithmetic_input_wire_a->GetValues().at(i) <
//                              arithmetic_input_wire_b->GetValues().at(i);
//         }
//       }
//     }

//     BitVector<> boolean_output_bitvector = BitVector(output_vector);
//     std::vector<T> arithmetic_output(num_of_simd_);
//     for (std::size_t i = 0; i < num_of_simd_; i++) {
//       arithmetic_output[i] = output_vector[i];
//     }

//     // std::cout << "LessThanGate evaluate online " << std::endl;
//     // std::cout << "arithmetic_input_wire_a->GetValues().at(0): "
//     //           << arithmetic_input_wire_a->GetValues().at(0) << std::endl;
//     // std::cout << "arithmetic_input_wire_b->GetValues().at(0): "
//     //           << arithmetic_input_wire_b->GetValues().at(0) << std::endl;
//     // std::cout << "less than result: " << output << std::endl;

//     // assign comparison result to output wires
//     auto boolean_output_wire =
//         std::dynamic_pointer_cast<motion::proto::boolean_gmw::Wire>(boolean_output_wires_.at(0));
//     boolean_output_wire->GetMutableValues() = boolean_output_bitvector;

//     auto arithmetic_output_wire =
//     std::dynamic_pointer_cast<motion::proto::arithmetic_gmw::Wire<T>>(
//         arithmetic_output_wires_.at(0));
//     arithmetic_output_wire->GetMutableValues() = arithmetic_output;

//     GetLogger().LogDebug(
//         fmt::format("Evaluated ArithmeticGmwValueLessThanGate with id#{}", gate_id_));

//     // SetOnlineIsReady();
//     boolean_output_wire->SetOnlineFinished();
//     arithmetic_output_wire->SetOnlineFinished();
//     // set online condition ready
//     {
//       std::scoped_lock lock(online_is_ready_condition_.GetMutex());
//       online_is_ready_ = true;
//     }
//     online_is_ready_condition_.NotifyAll();

//     GetRegister().IncrementEvaluatedGatesOnlineCounter();
//   }

//   motion::proto::boolean_gmw::SharePointer GetOutputAsBooleanGmwValue() {
//     auto boolean_output_share =
//         std::make_shared<motion::proto::boolean_gmw::Share>(boolean_output_wires_);
//     return boolean_output_share;
//   }

//   motion::proto::arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticGmwValue() {
//     auto arithmetic_output_share =
//         std::make_shared<motion::proto::arithmetic_gmw::Share<T>>(arithmetic_output_wires_);
//     return arithmetic_output_share;
//   }

//   ArithmeticGmwValueLessThanGate() = delete;

//   ArithmeticGmwValueLessThanGate(Gate&) = delete;

//  private:
//   std::size_t num_of_output_wires_;
//   std::size_t num_of_simd_;

//   std::vector<WirePointer> arithmetic_output_wires_;
//   std::vector<WirePointer> boolean_output_wires_;

//   bool set_zero_as_maximum_ = false;
// };

// // added by Liang Zhao
// template <typename T>
// class ArithmeticGmwValueAdditionGate final : public TwoGate {
//  public:
//   ArithmeticGmwValueAdditionGate(const arithmetic_gmw::WirePointer<T>& a,
//                                  const arithmetic_gmw::WirePointer<T>& b)
//       : TwoGate(a->GetBackend()) {
//     parent_a_ = {std::static_pointer_cast<Wire>(a)};
//     parent_b_ = {std::static_pointer_cast<Wire>(b)};

//     assert(parent_a_.at(0)->GetNumberOfSimdValues() ==
//     parent_b_.at(0)->GetNumberOfSimdValues());

//     requires_online_interaction_ = false;
//     gate_type_ = GateType::kNonInteractive;

//     gate_id_ = GetRegister().NextGateId();

//     RegisterWaitingFor(parent_a_.at(0)->GetWireId());
//     parent_a_.at(0)->RegisterWaitingGate(gate_id_);

//     RegisterWaitingFor(parent_b_.at(0)->GetWireId());
//     parent_b_.at(0)->RegisterWaitingGate(gate_id_);

//     // reserve for output wires
//     {
//       auto w = std::make_shared<arithmetic_gmw::Wire<T>>(backend_, a->GetNumberOfSimdValues());
//       GetRegister().RegisterNextWire(w);
//       output_wires_ = {std::move(w)};
//     }

//     // <a> + b, a + <b>, <a> + <b>
//     // <>: publicly unknown share value
//     if (!(a->IsPubliclyKnownWire() && b->IsPubliclyKnownWire())) {
//       output_wires_.at(0)->SetAsPubliclyUnknownWire();
//     }
//     // a + b
//     else {
//       output_wires_.at(0)->SetAsPubliclyKnownWire();
//     }

//     auto gate_info =
//         fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
//                     parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
//     GetLogger().LogDebug(fmt::format(
//         "Created an ArithmeticGmwValueAdditionGate with following properties: {}", gate_info));
//   }

//   ~ArithmeticGmwValueAdditionGate() final = default;

//   void EvaluateSetup() final override {
//     SetSetupIsReady();
//     GetRegister().IncrementEvaluatedGatesSetupCounter();
//   }

//   void EvaluateOnline() final override {
//     WaitSetup();
//     assert(setup_is_ready_);

//     // std::cout << "ArithmeticGmwValueAdditionGate EvaluateOnline " << std::endl;

//     parent_a_.at(0)->GetIsReadyCondition().Wait();
//     parent_b_.at(0)->GetIsReadyCondition().Wait();

//     auto input_wire_a = parent_a_.at(0);
//     auto input_wire_b = parent_b_.at(0);

//     auto arithmetic_input_wire_a =
//         std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(input_wire_a);
//     auto arithmetic_input_wire_b =
//         std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(input_wire_b);

//     assert(arithmetic_input_wire_a);
//     assert(arithmetic_input_wire_b);

//     auto arithmetic_output_wire =
//         std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));

//     std::vector<T> output_vector;

//     // a + b
//     if (arithmetic_input_wire_a->IsPubliclyKnownWire() &&
//         arithmetic_input_wire_b->IsPubliclyKnownWire()) {
//       output_vector = RestrictAddVectors(arithmetic_input_wire_a->GetValues(),
//                                          arithmetic_input_wire_b->GetValues());
//       // arithmetic_output_wire->SetAsPubliclyKnownWire();
//     }

//     // <a> + b
//     else if ((!arithmetic_input_wire_a->IsPubliclyKnownWire()) &&
//              arithmetic_input_wire_b->IsPubliclyKnownWire()) {
//       if (GetCommunicationLayer().GetMyId() ==
//           (gate_id_ % GetCommunicationLayer().GetNumberOfParties())) {
//         output_vector = RestrictAddVectors(arithmetic_input_wire_a->GetValues(),
//                                            arithmetic_input_wire_b->GetValues());
//       } else {
//         output_vector = arithmetic_input_wire_a->GetValues();
//       }
//       // arithmetic_output_wireake->SetAsPublicUnknown(clearm);
//     }

//     // a + <b>
//     else if (arithmetic_input_wire_a->IsPubliclyKnownWire() &&
//              (!arithmetic_input_wire_b->IsPubliclyKnownWire())) {
//       if (GetCommunicationLayer().GetMyId() ==
//           (gate_id_ % GetCommunicationLayer().GetNumberOfParties())) {
//         output_vector = RestrictAddVectors(arithmetic_input_wire_a->GetValues(),
//                                            arithmetic_input_wire_b->GetValues());
//       } else {
//         output_vector = arithmetic_input_wire_b->GetValues();
//       }
//       // arithmetic_output_wire->SetAsPubliclyUnknownWire();
//     }

//     // <a> + <b>
//     else if (!(arithmetic_input_wire_a->IsPubliclyKnownWire()) &&
//              !(arithmetic_input_wire_b->IsPubliclyKnownWire())) {
//       // std::cout << "<a> + <b>" << std::endl;
//       output_vector = RestrictAddVectors(arithmetic_input_wire_a->GetValues(),
//                                          arithmetic_input_wire_b->GetValues());
//       // arithmetic_output_wire->SetAsPubliclyUnknownWire();
//     }

//     // constant_output_vector =
//     //     RestrictAddVectors(arithmetic_input_wire_a->GetValues(),
//     //     arithmetic_input_wire_b->GetValues());

//     // std::cout << "output_vector.size(): " << output_vector.size() << std::endl;

//     // assign addition result to output wires
//     arithmetic_output_wire->GetMutableValues() = output_vector;

//     GetLogger().LogDebug(
//         fmt::format("Evaluated ArithmeticGmwValueAdditionGate with id#{}", gate_id_));
//     SetOnlineIsReady();
//     GetRegister().IncrementEvaluatedGatesOnlineCounter();
//   }

//   arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticGmwValue() {
//     auto arithmetic_output_wire =
//         std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
//     assert(arithmetic_output_wire);
//     auto result = std::make_shared<arithmetic_gmw::Share<T>>(arithmetic_output_wire);
//     return result;
//   }

//   ArithmeticGmwValueAdditionGate() = delete;

//   ArithmeticGmwValueAdditionGate(Gate&) = delete;
// };

// // added by Liang Zhao
// template <typename T>
// class ArithmeticGmwValueSubtractionGate final : public TwoGate {
//  public:
//   ArithmeticGmwValueSubtractionGate(const arithmetic_gmw::WirePointer<T>& a,
//                                     const arithmetic_gmw::WirePointer<T>& b)
//       : TwoGate(a->GetBackend()) {
//     // std::cout << "ArithmeticGmwValueSubtractionGate" << std::endl;
//     parent_a_ = {std::static_pointer_cast<Wire>(a)};
//     parent_b_ = {std::static_pointer_cast<Wire>(b)};

//     assert(parent_a_.at(0)->GetNumberOfSimdValues() ==
//     parent_b_.at(0)->GetNumberOfSimdValues());

//     num_of_simd_ = parent_a_.at(0)->GetNumberOfSimdValues();

//     requires_online_interaction_ = false;
//     gate_type_ = GateType::kNonInteractive;

//     gate_id_ = GetRegister().NextGateId();

//     RegisterWaitingFor(parent_a_.at(0)->GetWireId());
//     parent_a_.at(0)->RegisterWaitingGate(gate_id_);

//     RegisterWaitingFor(parent_b_.at(0)->GetWireId());
//     parent_b_.at(0)->RegisterWaitingGate(gate_id_);

//     // reserve for output wires
//     {
//       auto w = std::make_shared<arithmetic_gmw::Wire<T>>(backend_, num_of_simd_);
//       GetRegister().RegisterNextWire(w);
//       output_wires_ = {std::move(w)};
//     }

//     // <a> - b, a - <b>, <a> - <b>
//     // <>: publicly unknown share value
//     if (!(a->IsPubliclyKnownWire() && b->IsPubliclyKnownWire())) {
//       output_wires_.at(0)->SetAsPubliclyUnknownWire();
//     }
//     // a - b
//     else {
//       output_wires_.at(0)->SetAsPubliclyKnownWire();
//     }
//     // std::cout << "finish public property for output wires" << std::endl;

//     auto gate_info =
//         fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
//                     parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
//     GetLogger().LogDebug(fmt::format(
//         "Created an ArithmeticGmwValueSubtractionGate with following properties: {}",
//         gate_info));
//   }

//   ~ArithmeticGmwValueSubtractionGate() final = default;

//   void EvaluateSetup() final override {
//     SetSetupIsReady();
//     GetRegister().IncrementEvaluatedGatesSetupCounter();
//   }

//   void EvaluateOnline() final override {
//     WaitSetup();
//     assert(setup_is_ready_);

//     parent_a_.at(0)->GetIsReadyCondition().Wait();
//     parent_b_.at(0)->GetIsReadyCondition().Wait();

//     auto input_wire_a = parent_a_.at(0);
//     auto input_wire_b = parent_b_.at(0);

//     auto arithmetic_input_wire_a =
//         std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(input_wire_a);
//     auto arithmetic_input_wire_b =
//         std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(input_wire_b);

//     assert(arithmetic_input_wire_a);
//     assert(arithmetic_input_wire_b);

//     auto arithmetic_output_wire =
//         std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));

//     std::vector<T> output_vector;

//     // a - b
//     if (arithmetic_input_wire_a->IsPubliclyKnownWire() &&
//         arithmetic_input_wire_b->IsPubliclyKnownWire()) {
//       // std::cout << "a - b" << std::endl;
//       output_vector = RestrictSubVectors(arithmetic_input_wire_a->GetValues(),
//                                          arithmetic_input_wire_b->GetValues());
//       // arithmetic_output_wire->SetAsPubliclyKnownWire();
//     }

//     // <a> - b
//     else if ((!arithmetic_input_wire_a->IsPubliclyKnownWire()) &&
//              arithmetic_input_wire_b->IsPubliclyKnownWire()) {
//       // std::cout << "<a> - b" << std::endl;
//       if (GetCommunicationLayer().GetMyId() ==
//           (gate_id_ % GetCommunicationLayer().GetNumberOfParties())) {
//         output_vector = RestrictSubVectors(arithmetic_input_wire_a->GetValues(),
//                                            arithmetic_input_wire_b->GetValues());
//       } else {
//         output_vector = arithmetic_input_wire_a->GetValues();
//       }
//       // arithmetic_output_wire->SetAsPubliclyUnknownWire();
//     }

//     // a - <b>
//     else if (arithmetic_input_wire_a->IsPubliclyKnownWire() &&
//              (!arithmetic_input_wire_b->IsPubliclyKnownWire())) {
//       // std::cout << "a - <b>" << std::endl;

//       if (GetCommunicationLayer().GetMyId() ==
//           (gate_id_ % GetCommunicationLayer().GetNumberOfParties())) {
//         output_vector = RestrictSubVectors(arithmetic_input_wire_a->GetValues(),
//                                            arithmetic_input_wire_b->GetValues());

//         // std::cout << "arithmetic_input_wire_a->GetValues(): "
//         //           << unsigned(arithmetic_input_wire_a->GetValues().at(0)) << std::endl;
//         // std::cout << "arithmetic_input_wire_b->GetValues(): "
//         //           << unsigned(arithmetic_input_wire_b->GetValues().at(0)) << std::endl;

//         // std::cout << "output_vector: " << unsigned(output_vector.at(0)) << std::endl;

//       } else {
//         std::vector<T> arithmetic_value_wire_b_minus = arithmetic_input_wire_b->GetValues();

//         // arithmetic_value_wire_b_minus.at(0) = -arithmetic_value_wire_b_minus.at(0);
//         arithmetic_value_wire_b_minus = MinusVectors(arithmetic_value_wire_b_minus);

//         output_vector = arithmetic_value_wire_b_minus;

//         // std::cout << "arithmetic_input_wire_b->GetValues(): "
//         //           << unsigned(arithmetic_input_wire_b->GetValues().at(0)) << std::endl;
//         // std::cout << "arithmetic_value_wire_b_minus: "
//         //           << unsigned(arithmetic_value_wire_b_minus.at(0)) << std::endl;

//         // std::cout << "output_vector: " << unsigned(output_vector.at(0)) << std::endl;
//       }
//       // arithmetic_output_wire->SetAsPubliclyUnknownWire();
//     }

//     // <a> - <b>
//     else if (!(arithmetic_input_wire_a->IsPubliclyKnownWire()) &&
//              !(arithmetic_input_wire_b->IsPubliclyKnownWire())) {
//       // std::cout << "<a> - <b>" << std::endl;
//       output_vector = RestrictSubVectors(arithmetic_input_wire_a->GetValues(),
//                                          arithmetic_input_wire_b->GetValues());
//       // arithmetic_output_wire->SetAsPubliclyUnknownWire();
//     }

//     arithmetic_output_wire->GetMutableValues() = output_vector;

//     GetLogger().LogDebug(
//         fmt::format("Evaluated ArithmeticGmwValueSubtractionGate with id#{}", gate_id_));
//     SetOnlineIsReady();
//     GetRegister().IncrementEvaluatedGatesOnlineCounter();
//   }

//   // perhaps, we should return a copy of the pointer and not move it for the
//   // case we need it multiple times
//   arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticGmwValue() {
//     auto arithmetic_output_wire =
//         std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
//     assert(arithmetic_output_wire);
//     auto result = std::make_shared<arithmetic_gmw::Share<T>>(arithmetic_output_wire);
//     return result;
//   }

//   ArithmeticGmwValueSubtractionGate() = delete;

//   ArithmeticGmwValueSubtractionGate(Gate&) = delete;

//  private:
//   std::size_t num_of_simd_;
// };

// // added by Liang Zhao
// // a and b are publicly known values (all parties hold the same value) after evaluation of
// previouse
// // gates the output is a publicly known value, that all parties hold the same value
// template <typename T>
// class ArithmeticGmwValueMinusGate final : public OneGate {
//  public:
//   ArithmeticGmwValueMinusGate(const arithmetic_gmw::WirePointer<T>& a) :
//   OneGate(a->GetBackend())
//   {
//     parent_ = {std::static_pointer_cast<Wire>(a)};
//     // std::cout << "ArithmeticGmwValueMinusGate" << std::endl;

//     requires_online_interaction_ = false;
//     gate_type_ = GateType::kNonInteractive;

//     gate_id_ = GetRegister().NextGateId();

//     RegisterWaitingFor(parent_.at(0)->GetWireId());
//     parent_.at(0)->RegisterWaitingGate(gate_id_);

//     // reserve for output wires
//     {
//       auto w = std::make_shared<arithmetic_gmw::Wire<T>>(backend_, a->GetNumberOfSimdValues());
//       GetRegister().RegisterNextWire(w);
//       output_wires_ = {std::move(w)};
//     }

//     // -<a>
//     // <>: publicly unknown share value
//     if (!(a->IsPubliclyKnownWire())) {
//       output_wires_.at(0)->SetAsPubliclyUnknownWire();
//     }
//     // -a
//     else {
//       output_wires_.at(0)->SetAsPubliclyKnownWire();
//     }

//     auto gate_info = fmt::format("uint{}_t type, gate id {}, parents: {}", sizeof(T) * 8,
//     gate_id_,
//                                  parent_.at(0)->GetWireId());
//     GetLogger().LogDebug(fmt::format(
//         "Created an ArithmeticGmwValueMinusGate with following properties: {}", gate_info));
//   }

//   ~ArithmeticGmwValueMinusGate() final = default;

//   void EvaluateSetup() final override {
//     SetSetupIsReady();
//     GetRegister().IncrementEvaluatedGatesSetupCounter();
//   }

//   void EvaluateOnline() final override {
//     WaitSetup();
//     assert(setup_is_ready_);

//     parent_.at(0)->GetIsReadyCondition().Wait();

//     auto input_wire_a = parent_.at(0);

//     auto arithmetic_input_wire_a =
//         std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(input_wire_a);

//     assert(arithmetic_input_wire_a);

//     std::vector<T> output_vector;

//     // -a
//     if (arithmetic_input_wire_a->IsPubliclyKnownWire()) {
//       output_vector = MinusVectors(arithmetic_input_wire_a->GetValues());
//       // arithmetic_output_wire->SetAsPubliclyKnownWire();
//     }

//     // -<a>
//     else if ((!arithmetic_input_wire_a->IsPubliclyKnownWire())) {
//       output_vector = MinusVectors(arithmetic_input_wire_a->GetValues());
//     }

//     // std::cout << "minus: " << output_vector[0] << std::endl;
//     // arithmetic_output_wire->SetAsPubliclyUnknownWire();

//     // assign minus result to output wires
//     auto arithmetic_output_wire =
//         std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
//     arithmetic_output_wire->GetMutableValues() = output_vector;

//     GetLogger().LogDebug(fmt::format("Evaluated ArithmeticGmwValueMinusGate with id#{}",
//     gate_id_)); SetOnlineIsReady(); GetRegister().IncrementEvaluatedGatesOnlineCounter();
//   }

//   // perhaps, we should return a copy of the pointer and not move it for the
//   // case we need it multiple times
//   arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticGmwValue() {
//     auto arithmetic_output_wire =
//         std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
//     assert(arithmetic_output_wire);
//     auto result = std::make_shared<arithmetic_gmw::Share<T>>(arithmetic_output_wire);
//     return result;
//   }

//   ArithmeticGmwValueMinusGate() = delete;

//   ArithmeticGmwValueMinusGate(Gate&) = delete;
// };

// // added by Liang Zhao
// // a and b are publicly known values (all parties hold the same value) after evaluation of
// previous
// // gates, the output is a publicly known value, that all parties hold the same value
// template <typename T>
// class ArithmeticGmwValueMultiplicationGate final : public TwoGate {
//  public:
//   ArithmeticGmwValueMultiplicationGate(const arithmetic_gmw::WirePointer<T>& a,
//                                        const arithmetic_gmw::WirePointer<T>& b)
//       : TwoGate(a->GetBackend()) {
//     parent_a_ = {std::static_pointer_cast<Wire>(a)};
//     parent_b_ = {std::static_pointer_cast<Wire>(b)};

//     assert(parent_a_.at(0)->GetNumberOfSimdValues() ==
//     parent_b_.at(0)->GetNumberOfSimdValues()); assert(a->IsPubliclyKnownWire() ||
//     b->IsPubliclyKnownWire());

//     // assert that not both parent are const
//     // TODO: a separate gate for this probably rather rare case
//     // needs some mediocre implementation effort if implemented with a deferred inputs option

//     requires_online_interaction_ = false;
//     gate_type_ = GateType::kNonInteractive;

//     gate_id_ = GetRegister().NextGateId();

//     RegisterWaitingFor(parent_a_.at(0)->GetWireId());
//     parent_a_.at(0)->RegisterWaitingGate(gate_id_);

//     RegisterWaitingFor(parent_b_.at(0)->GetWireId());
//     parent_b_.at(0)->RegisterWaitingGate(gate_id_);

//     // reserve for output wires
//     {
//       auto w = std::make_shared<arithmetic_gmw::Wire<T>>(backend_, a->GetNumberOfSimdValues());
//       GetRegister().RegisterNextWire(w);
//       output_wires_ = {std::move(w)};
//     }

//     // <a> * b, a * <b>
//     // <>: publicly unknown share value
//     if (!(a->IsPubliclyKnownWire() && b->IsPubliclyKnownWire())) {
//       output_wires_.at(0)->SetAsPubliclyUnknownWire();
//     }
//     // a * b
//     else {
//       output_wires_.at(0)->SetAsPubliclyKnownWire();
//     }

//     auto gate_info =
//         fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
//                     parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
//     GetLogger().LogDebug(fmt::format(
//         "Created an ArithmeticGmwValueMinusGate with following properties: {}", gate_info));
//   }

//   ~ArithmeticGmwValueMultiplicationGate() final = default;

//   void EvaluateSetup() final override {
//     SetSetupIsReady();
//     GetRegister().IncrementEvaluatedGatesSetupCounter();
//   }

//   void EvaluateOnline() final override {
//     WaitSetup();
//     assert(setup_is_ready_);

//     parent_a_.at(0)->GetIsReadyCondition().Wait();
//     parent_b_.at(0)->GetIsReadyCondition().Wait();

//     auto input_wire_a = parent_a_.at(0);
//     auto input_wire_b = parent_b_.at(0);

//     auto arithmetic_input_wire_a =
//         std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(input_wire_a);
//     auto arithmetic_input_wire_b =
//         std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(input_wire_b);

//     assert(arithmetic_input_wire_a);
//     assert(arithmetic_input_wire_b);

//     auto arithmetic_output_wire =
//         std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));

//     std::vector<T> output_vector;
//     //     std::cout << "before RestrictMulVectors" << std::endl;
//     // std::cout<<"arithmetic_input_wire_a->GetValues().size():
//     // "<<arithmetic_input_wire_a->GetValues().size()<<std::endl;
//     // std::cout<<"arithmetic_input_wire_b->GetValues().size():
//     // "<<arithmetic_input_wire_b->GetValues().size()<<std::endl;

//     output_vector = RestrictMulVectors(arithmetic_input_wire_a->GetValues(),
//                                        arithmetic_input_wire_b->GetValues());

//     // std::cout << "after RestrictMulVectors" << std::endl;
//     arithmetic_output_wire->GetMutableValues() = output_vector;

//     GetLogger().LogDebug(
//         fmt::format("Evaluated ArithmeticGmwValueMultiplicationGate with id#{}", gate_id_));
//     SetOnlineIsReady();
//     GetRegister().IncrementEvaluatedGatesOnlineCounter();
//   }

//   arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticGmwValue() {
//     auto arithmetic_output_wire =
//         std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
//     assert(arithmetic_output_wire);
//     auto arithmetic_output_share =
//         std::make_shared<arithmetic_gmw::Share<T>>(arithmetic_output_wire);
//     return arithmetic_output_share;
//   }

//   ArithmeticGmwValueMultiplicationGate() = delete;

//   ArithmeticGmwValueMultiplicationGate(Gate&) = delete;
// };

// // added by Liang Zhao
// // a and b are publicly known values (all parties hold the same value) after evaluation of
// previouse
// // gates the output is a publicly known value, that all parties hold the same value
// template <typename T>
// class ArithmeticGmwValueDivisionGate final : public TwoGate {
//  public:
//   ArithmeticGmwValueDivisionGate(const arithmetic_gmw::WirePointer<T>& a,
//                                  const arithmetic_gmw::WirePointer<T>& b)
//       : TwoGate(a->GetBackend()) {
//     // std::cout << "ArithmeticGmwValueDivisionGate" << std::endl;
//     parent_a_ = {std::static_pointer_cast<Wire>(a)};
//     parent_b_ = {std::static_pointer_cast<Wire>(b)};

//     assert(parent_a_.at(0)->GetNumberOfSimdValues() ==
//     parent_b_.at(0)->GetNumberOfSimdValues());
//     // assert(a->IsPubliclyKnownWire() && b->IsPubliclyKnownWire());

//     // assert that not both parent are const
//     // TODO: a separate gate for this probably rather rare case
//     // needs some mediocre implementation effort if implemented with a deferred inputs option

//     requires_online_interaction_ = false;
//     gate_type_ = GateType::kNonInteractive;

//     gate_id_ = GetRegister().NextGateId();

//     RegisterWaitingFor(parent_a_.at(0)->GetWireId());
//     parent_a_.at(0)->RegisterWaitingGate(gate_id_);

//     RegisterWaitingFor(parent_b_.at(0)->GetWireId());
//     parent_b_.at(0)->RegisterWaitingGate(gate_id_);

//     // reserve for output wires
//     {
//       auto w = std::make_shared<arithmetic_gmw::Wire<T>>(backend_, a->GetNumberOfSimdValues());
//       GetRegister().RegisterNextWire(w);
//       output_wires_ = {std::move(w)};
//     }

//     // a / b
//     if (a->IsPubliclyKnownWire() && b->IsPubliclyKnownWire()) {
//       output_wires_.at(0)->SetAsPubliclyKnownWire();
//     }

//     // <a> / b
//     // <>: publicly unknown share value
//     else {
//       output_wires_.at(0)->SetAsPubliclyUnknownWire();
//     }

//     auto gate_info =
//         fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
//                     parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
//     GetLogger().LogDebug(fmt::format(
//         "Created an ArithmeticGmwValueDivisionGate with following properties: {}", gate_info));
//   }

//   ~ArithmeticGmwValueDivisionGate() final = default;

//   void EvaluateSetup() final override {
//     SetSetupIsReady();
//     GetRegister().IncrementEvaluatedGatesSetupCounter();
//   }

//   void EvaluateOnline() final override {
//     WaitSetup();
//     assert(setup_is_ready_);

//     parent_a_.at(0)->GetIsReadyCondition().Wait();
//     parent_b_.at(0)->GetIsReadyCondition().Wait();

//     auto input_wire_a = parent_a_.at(0);
//     auto input_wire_b = parent_b_.at(0);

//     auto arithmetic_input_wire_a =
//         std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(input_wire_a);
//     auto arithmetic_input_wire_b =
//         std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(input_wire_b);

//     assert(arithmetic_input_wire_a);
//     assert(arithmetic_input_wire_b);

//     // std::cout<<"RestrictDivVectors before"<<std::endl;

//     std::vector<T> output_vector = RestrictDivVectors(arithmetic_input_wire_a->GetValues(),
//                                                       arithmetic_input_wire_b->GetValues());
//     // std::cout<<"RestrictDivVectors after"<<std::endl;

//     auto arithmetic_output_wire =
//         std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
//     arithmetic_output_wire->GetMutableValues() = std::move(output_vector);

//     GetLogger().LogDebug(
//         fmt::format("Evaluated ArithmeticGmwValueDivisionGate with id#{}", gate_id_));
//     SetOnlineIsReady();
//     GetRegister().IncrementEvaluatedGatesOnlineCounter();
//   }

//   arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticGmwValue() {
//     auto arithmetic_output_wire =
//         std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
//     assert(arithmetic_output_wire);
//     auto arithmetic_output_share =
//         std::make_shared<arithmetic_gmw::Share<T>>(arithmetic_output_wire);
//     return arithmetic_output_share;
//   }

//   ArithmeticGmwValueDivisionGate() = delete;

//   ArithmeticGmwValueDivisionGate(Gate&) = delete;
// };

// // added by Liang Zhao
// template <typename T, typename U>
// class ArithmeticGmwValueModularReductionWithWrapGate final : public OneGate {
//  public:
//   ArithmeticGmwValueModularReductionWithWrapGate(const arithmetic_gmw::WirePointer<T>& a)
//       : OneGate(a->GetBackend()) {
//     // std::cout << "ArithmeticGmwValueModularReductionWithWrapGate" << std::endl;
//     parent_ = {std::static_pointer_cast<Wire>(a)};

//     // assert(a->IsPubliclyKnownWire());

//     // assert that not both parent are const
//     // TODO: a separate gate for this probably rather rare case
//     // needs some mediocre implementation effort if implemented with a deferred inputs option

//     requires_online_interaction_ = false;
//     gate_type_ = GateType::kNonInteractive;

//     gate_id_ = GetRegister().NextGateId();

//     RegisterWaitingFor(parent_.at(0)->GetWireId());
//     parent_.at(0)->RegisterWaitingGate(gate_id_);

//     // RegisterWaitingFor(parent_b_.at(0)->GetWireId());
//     // parent_b_.at(0)->RegisterWaitingGate(gate_id_);

//     // reserve for output wires
//     {
//       auto wire_remainder =
//           std::make_shared<arithmetic_gmw::Wire<U>>(backend_, a->GetNumberOfSimdValues());
//       GetRegister().RegisterNextWire(wire_remainder);
//       output_wires_remainder_ = {std::move(wire_remainder)};

//       auto wire_wrap =
//           std::make_shared<arithmetic_gmw::Wire<U>>(backend_, a->GetNumberOfSimdValues());
//       GetRegister().RegisterNextWire(wire_wrap);
//       output_wires_wrap_ = {std::move(wire_wrap)};
//     }

//     if (a->IsPubliclyKnownWire()) {
//       output_wires_remainder_.at(0)->SetAsPubliclyKnownWire();
//       output_wires_wrap_.at(0)->SetAsPubliclyKnownWire();
//     } else {
//       output_wires_remainder_.at(0)->SetAsPubliclyUnknownWire();
//       output_wires_wrap_.at(0)->SetAsPubliclyUnknownWire();
//     }

//     // std::cout << "logger error" << std::endl;
//     // std::cout << "gate_id_: " << gate_id_ << std::endl;
//     // std::cout << "sizeof(T) * 8: " << sizeof(T) * 8 << std::endl;
//     // std::cout << "parent_.at(0)->GetWireId(): " << parent_.at(0)->GetWireId() << std::endl;

//     auto gate_info = fmt::format("uint{}_t type, gate id {}, parents: {}", sizeof(T) * 8,
//     gate_id_,
//                                  parent_.at(0)->GetWireId());
//     GetLogger().LogDebug(fmt::format(
//         "Created an ArithmeticGmwValueModularReductionWithWrapGate with following properties:
//         {}", gate_info));
//   }

//   ~ArithmeticGmwValueModularReductionWithWrapGate() final = default;

//   void EvaluateSetup() final override {
//     SetSetupIsReady();
//     GetRegister().IncrementEvaluatedGatesSetupCounter();
//   }

//   void EvaluateOnline() final override {
//     WaitSetup();
//     assert(setup_is_ready_);

//     parent_.at(0)->GetIsReadyCondition().Wait();

//     auto input_wire_a = parent_.at(0);

//     auto arithmetic_input_wire_a =
//         std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(input_wire_a);

//     assert(arithmetic_input_wire_a);

//     std::vector<std::vector<U>> output_vector =
//         ModularReductionWithWrapVectors<T, U>(arithmetic_input_wire_a->GetValues());

//     // std::cout << std::endl;
//     // std::cout << "remainder: " << unsigned(output_vector[0][0]) << std::endl;
//     // std::cout << "wrap: " << unsigned(output_vector[1][0]) << std::endl;

//     // std::cout << std::endl;

//     // assign modulo conversion result to output wires
//     auto arithmetic_output_wire_remainder =
//         std::dynamic_pointer_cast<arithmetic_gmw::Wire<U>>(output_wires_remainder_.at(0));
//     arithmetic_output_wire_remainder->GetMutableValues() = std::move(output_vector[0]);
//     auto arithmetic_output_wire_wrap =
//         std::dynamic_pointer_cast<arithmetic_gmw::Wire<U>>(output_wires_wrap_.at(0));
//     arithmetic_output_wire_wrap->GetMutableValues() = std::move(output_vector[1]);

//     GetLogger().LogDebug(fmt::format(
//         "Evaluated ArithmeticGmwValueModularReductionWithWrapGate with id#{}", gate_id_));

//     // SetOnlineIsReady();
//     arithmetic_output_wire_remainder->SetOnlineFinished();
//     arithmetic_output_wire_wrap->SetOnlineFinished();
//     {
//       std::scoped_lock lock(online_is_ready_condition_.GetMutex());
//       online_is_ready_ = true;
//     }
//     online_is_ready_condition_.NotifyAll();

//     GetRegister().IncrementEvaluatedGatesOnlineCounter();
//   }

//   arithmetic_gmw::SharePointer<U> GetWrapAsArithmeticGmwValue() {
//     auto arithmetic_output_wire_wrap =
//         std::dynamic_pointer_cast<arithmetic_gmw::Wire<U>>(output_wires_wrap_.at(0));
//     assert(arithmetic_output_wire_wrap);
//     auto arithmetic_output_share_wrap =
//         std::make_shared<arithmetic_gmw::Share<U>>(arithmetic_output_wire_wrap);
//     return arithmetic_output_share_wrap;
//   }

//   arithmetic_gmw::SharePointer<U> GetRemainderAsArithmeticGmwValue() {
//     auto arithmetic_output_wire_remainder =
//         std::dynamic_pointer_cast<arithmetic_gmw::Wire<U>>(output_wires_remainder_.at(0));
//     assert(arithmetic_output_wire_remainder);
//     auto arithmetic_output_share_remainder =
//         std::make_shared<arithmetic_gmw::Share<U>>(arithmetic_output_wire_remainder);
//     return arithmetic_output_share_remainder;
//   }

//   ArithmeticGmwValueModularReductionWithWrapGate() = delete;

//   ArithmeticGmwValueModularReductionWithWrapGate(Gate&) = delete;

//  private:
//   std::vector<WirePointer> output_wires_remainder_;
//   std::vector<WirePointer> output_wires_wrap_;
// };

// // added by Liang Zhao
// template <typename T>
// class ArithmeticGmwValueModularReductionGate final : public TwoGate {
//  public:
//   ArithmeticGmwValueModularReductionGate(const arithmetic_gmw::WirePointer<T>& x,
//                                          const arithmetic_gmw::WirePointer<T>& modulo)
//       : TwoGate(x->GetBackend()) {
//     // std::cout << "ArithmeticGmwValueModularReductionGate" << std::endl;
//     parent_a_ = {std::static_pointer_cast<Wire>(x)};
//     parent_b_ = {std::static_pointer_cast<Wire>(modulo)};
//     assert(modulo->IsPubliclyKnownWire());

//     // assert that not both parent are const
//     // TODO: a separate gate for this probably rather rare case
//     // needs some mediocre implementation effort if implemented with a deferred inputs option

//     requires_online_interaction_ = false;
//     gate_type_ = GateType::kNonInteractive;

//     gate_id_ = GetRegister().NextGateId();

//     RegisterWaitingFor(parent_a_.at(0)->GetWireId());
//     parent_a_.at(0)->RegisterWaitingGate(gate_id_);

//     RegisterWaitingFor(parent_b_.at(0)->GetWireId());
//     parent_b_.at(0)->RegisterWaitingGate(gate_id_);

//     // reserve for output wires
//     {
//       auto wire_remainder =
//           std::make_shared<arithmetic_gmw::Wire<T>>(backend_, x->GetNumberOfSimdValues());
//       GetRegister().RegisterNextWire(wire_remainder);
//       output_wires_remainder_ = {std::move(wire_remainder)};
//     }

//     if (x->IsPubliclyKnownWire()) {
//       output_wires_remainder_.at(0)->SetAsPubliclyKnownWire();
//     } else {
//       output_wires_remainder_.at(0)->SetAsPubliclyUnknownWire();
//     }

//     // std::cout << "logger error" << std::endl;
//     // std::cout << "gate_id_: " << gate_id_ << std::endl;
//     // std::cout << "sizeof(T) * 8: " << sizeof(T) * 8 << std::endl;
//     // std::cout << "parent_.at(0)->GetWireId(): " << parent_.at(0)->GetWireId() << std::endl;

//     auto gate_info =
//         fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
//                     parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
//     GetLogger().LogDebug(fmt::format(
//         "Created an ArithmeticGmwValueModularReductionGate with following properties: {}",
//         gate_info));
//   }

//   ~ArithmeticGmwValueModularReductionGate() final = default;

//   void EvaluateSetup() final override {
//     SetSetupIsReady();
//     GetRegister().IncrementEvaluatedGatesSetupCounter();
//   }

//   void EvaluateOnline() final override {
//     WaitSetup();
//     assert(setup_is_ready_);

//     parent_a_.at(0)->GetIsReadyCondition().Wait();
//     parent_b_.at(0)->GetIsReadyCondition().Wait();

//     auto input_wire_a = parent_a_.at(0);
//     auto input_wire_b = parent_b_.at(0);

//     auto arithmetic_input_wire_a =
//         std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(input_wire_a);
//     assert(arithmetic_input_wire_a);

//     auto arithmetic_input_wire_b =
//         std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(input_wire_b);
//     assert(arithmetic_input_wire_b);

//     std::vector<T> output_vector =
//     ModularReductionVectors<T>(arithmetic_input_wire_a->GetValues(),
//                                                               arithmetic_input_wire_b->GetValues());

//     // std::cout << std::endl;
//     // std::cout << "remainder: " << unsigned(output_vector[0][0]) << std::endl;
//     // std::cout << "wrap: " << unsigned(output_vector[1][0]) << std::endl;

//     // std::cout << std::endl;

//     // assign modulo conversion result to output wires
//     auto arithmetic_output_wire_remainder =
//         std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_remainder_.at(0));
//     arithmetic_output_wire_remainder->GetMutableValues() = std::move(output_vector);

//     GetLogger().LogDebug(
//         fmt::format("Evaluated ArithmeticGmwValueModularReductionGate with id#{}", gate_id_));

//     // SetOnlineIsReady();
//     arithmetic_output_wire_remainder->SetOnlineFinished();
//     {
//       std::scoped_lock lock(online_is_ready_condition_.GetMutex());
//       online_is_ready_ = true;
//     }
//     online_is_ready_condition_.NotifyAll();

//     GetRegister().IncrementEvaluatedGatesOnlineCounter();
//   }

//   arithmetic_gmw::SharePointer<T> GetRemainderAsArithmeticGmwValue() {
//     auto arithmetic_output_wire_remainder =
//         std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_remainder_.at(0));
//     assert(arithmetic_output_wire_remainder);
//     auto arithmetic_output_share_remainder =
//         std::make_shared<arithmetic_gmw::Share<T>>(arithmetic_output_wire_remainder);
//     return arithmetic_output_share_remainder;
//   }

//   ArithmeticGmwValueModularReductionGate() = delete;

//   ArithmeticGmwValueModularReductionGate(Gate&) = delete;

//  private:
//   std::vector<WirePointer> output_wires_remainder_;
// };

// // added by Liang Zhao
// // convert arithmetic value to boolean value
// // arithmetic value is of type T, boolean value has same bit length as type U
// template <typename T, typename U>
// class ArithmeticGmwValueToBooleanGmwValueGate final : public OneGate {
//  public:
//   ArithmeticGmwValueToBooleanGmwValueGate(const arithmetic_gmw::WirePointer<T>& a)
//       : OneGate(a->GetBackend()) {
//     parent_ = {std::static_pointer_cast<Wire>(a)};

//     // std::cout << "ArithmeticGmwValueToBooleanGmwValueGate" << std::endl;

//     requires_online_interaction_ = false;
//     gate_type_ = GateType::kNonInteractive;

//     gate_id_ = GetRegister().NextGateId();

//     RegisterWaitingFor(parent_.at(0)->GetWireId());
//     parent_.at(0)->RegisterWaitingGate(gate_id_);

//     number_of_wires_ = sizeof(U) * 8;
//     number_of_simd_values_ = a->GetNumberOfSimdValues();

//     // create output wires
//     output_wires_.reserve(number_of_wires_);
//     if (a->IsPubliclyKnownWire()) {
//       for (size_t i = 0; i < number_of_wires_; ++i) {
//         auto& w = output_wires_.emplace_back(std::static_pointer_cast<encrypto::motion::Wire>(
//             std::make_shared<boolean_gmw::Wire>(backend_, number_of_simd_values_)));
//         GetRegister().RegisterNextWire(w);
//         w->SetAsPubliclyKnownWire();
//       }
//     } else {
//       for (size_t i = 0; i < number_of_wires_; ++i) {
//         auto& w = output_wires_.emplace_back(std::static_pointer_cast<encrypto::motion::Wire>(
//             std::make_shared<boolean_gmw::Wire>(backend_, number_of_simd_values_)));
//         GetRegister().RegisterNextWire(w);
//       }
//     }

//     // {
//     //   // reserve for output wires
//     //   auto w = std::make_shared<arithmetic_gmw::Wire<T>>(backend_,
//     a->GetNumberOfSimdValues());
//     //   GetRegister().RegisterNextWire(w);
//     //   output_wires_ = {std::move(w)};

//     //   // assign for the output wires
//     //   auto constant_wire_origin = parent_.at(0);
//     //   auto constant_wire =
//     //       std::dynamic_pointer_cast<const ConstantArithmeticWire<T>>(constant_wire_origin);

//     //   auto arithmetic_wire =
//     //       std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
//     //   arithmetic_wire->GetMutableValues() = constant_wire->GetValues();
//     //   arithmetic_wire->SetAsPubliclyKnownWire();
//     //   std::cout << "ArithmeticGmwValueToBooleanGmwValueGate,constant_wire: "
//     //             << constant_wire->GetValues()[0] << std::endl;
//     // }

//     auto gate_info = fmt::format("uint{}_t type, gate id {}, parents: {}", sizeof(T) * 8,
//     gate_id_,
//                                  parent_.at(0)->GetWireId());
//     GetLogger().LogDebug(
//         fmt::format("Created an ArithmeticGmwValueToBooleanGmwValueGate with "
//                     "following properties: {}",
//                     gate_info));
//   }

//   ~ArithmeticGmwValueToBooleanGmwValueGate() final = default;

//   void EvaluateSetup() final override {
//     SetSetupIsReady();
//     GetRegister().IncrementEvaluatedGatesSetupCounter();
//   }

//   void EvaluateOnline() final override {
//     WaitSetup();
//     assert(setup_is_ready_);

//     for (auto& wire : parent_) {
//       wire->GetIsReadyCondition().Wait();
//     }

//     auto arithmetic_parent_wire =
//         std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(parent_.at(0));

//     // convert arithmetic value to boolean value of type T
//     std::vector<BitVector<>> output_vector =
//         motion::ToInput(arithmetic_parent_wire->GetValues().at(0));

//     // fill the sizeof(U)-sizeof(T) bits of output_vector with zeros
//     std::size_t zero_bits_length = sizeof(U) * 8 - sizeof(T) * 8;
//     for (std::size_t i = 0; i < zero_bits_length; ++i) {
//       output_vector.emplace_back(BitVector(1, false));
//     }

//     for (std::size_t i = 0; i < number_of_wires_; ++i) {
//       auto wire_output = std::dynamic_pointer_cast<boolean_gmw::Wire>(output_wires_.at(i));
//       wire_output->GetMutableValues() = output_vector[i];
//     }

//     SetOnlineIsReady();
//     GetRegister().IncrementEvaluatedGatesOnlineCounter();
//   }

//   // perhaps, we should return a copy of the pointer and not move it for the
//   // case we need it multiple times
//   boolean_gmw::SharePointer GetOutputAsBooleanGmwValue() {
//     auto result = std::make_shared<boolean_gmw::Share>(output_wires_);
//     return result;
//   }

//   ArithmeticGmwValueToBooleanGmwValueGate() = delete;

//   ArithmeticGmwValueToBooleanGmwValueGate(Gate&) = delete;

//  private:
//   // std::size_t bit_length_ = 0;
//   std::size_t number_of_wires_;
//   std::size_t number_of_simd_values_;
// };

// // added by Liang Zhao
// // convert arithmetic value to boolean value
// // arithmetic value is of type T, boolean value has same bit length as type T
// template <typename T>
// class ArithmeticGmwValueBitDecompositionGate final : public motion::OneGate {
//  public:
//   ArithmeticGmwValueBitDecompositionGate(const arithmetic_gmw::WirePointer<T>& parent,
//                                          std::size_t output_owner = kAll)
//       : OneGate(parent->GetBackend()) {
//     // std::cout << "ArithmeticGmwValueBitDecompositionGate" << std::endl;
//     assert(parent);
//     // assert(parent->IsPubliclyKnownWire());

//     if (parent->GetProtocol() != MpcProtocol::kArithmeticGmw) {
//       auto sharing_type = to_string(parent->GetProtocol());
//       throw(std::runtime_error((fmt::format(
//           "Arithmetic ArithmeticGmwValueBitDecompositionGate expects an arithmetic share, "
//           "got a share of type {}",
//           sharing_type))));
//     }

//     parent_ = {parent};

//     // TODO should support SIMD now
//     num_of_simd_ = parent_[0]->GetNumberOfSimdValues();

//     // create boolean output wires
//     // constexpr auto number_of_wires{sizeof(T) * 8};
//     number_of_wires_ = sizeof(T) * 8;
//     // std::cout << "number_of_wires: " << number_of_wires_ << std::endl;

//     requires_online_interaction_ = false;
//     gate_type_ = GateType::kNonInteractive;

//     // // create the arithmetic output wires
//     // arithmetic_wires_.emplace_back(
//     //     std::make_shared<motion::proto::arithmetic_gmw::Wire<T>>(backend_, num_of_simd_));
//     // GetRegister().RegisterNextWire(arithmetic_wires_.at(0));

//     // create the boolean output wires
//     boolean_wires_.reserve(number_of_wires_);
//     if (parent_.at(0)->IsPubliclyKnownWire()) {
//       for (size_t i = 0; i < number_of_wires_; i++) {
//         auto& w = boolean_wires_.emplace_back(std::static_pointer_cast<motion::Wire>(
//             std::make_shared<boolean_gmw::Wire>(backend_, num_of_simd_)));
//         GetRegister().RegisterNextWire(w);
//         boolean_wires_.at(i)->SetAsPubliclyKnownWire();
//       }
//     } else {
//       for (size_t i = 0; i < number_of_wires_; i++) {
//         auto& w = boolean_wires_.emplace_back(std::static_pointer_cast<motion::Wire>(
//             std::make_shared<boolean_gmw::Wire>(backend_, num_of_simd_)));
//         GetRegister().RegisterNextWire(w);
//       }
//     }

//     // // create the output gate to reconstruct the a
//     // auto arithmetic_parent_wire =
//     //     std::dynamic_pointer_cast<motion::proto::arithmetic_gmw::Wire<T>>(parent_.at(0));
//     // arithmetic_output_gate_ =
//     // std::make_shared<motion::proto::arithmetic_gmw::OutputGate<T>>(arithmetic_parent_wire);
//     // GetRegister().RegisterNextGate(arithmetic_output_gate_);

//     // register this gate
//     gate_id_ = GetRegister().NextGateId();

//     // register this gate with the parent_ wires
//     for (auto& wire : parent_) {
//       RegisterWaitingFor(wire->GetWireId());
//       wire->RegisterWaitingGate(gate_id_);
//     }

//     if constexpr (kDebug) {
//       auto gate_info = fmt::format("gate id {}", gate_id_);
//       GetLogger().LogDebug(fmt::format(
//           "Allocate an ArithmeticGmwValueBitDecompositionGate with following properties: {}",
//           gate_info));
//     }

//     // std::cout << "finish create ArithmeticGmwValueBitDecompositionGate" << std::endl;
//   }

//   ArithmeticGmwValueBitDecompositionGate(const arithmetic_gmw::SharePointer<T>& parent,
//                                          std::size_t output_owner = kAll)
//       : ArithmeticGmwValueBitDecompositionGate(parent->GetArithmeticWire(), output_owner) {
//     assert(parent);
//   }

//   // ArithmeticGmwValueBitDecompositionGate(const motion::SharePointer& parent, std::size_t
//   // output_owner = kAll) {
//   //   assert(parent);

//   //   const arithmetic_gmw::SharePointer<T>& airthmetic_share_parent =
//   //       std::dynamic_pointer_cast<const arithmetic_gmw::Share<T>>(parent);
//   //   ArithmeticGmwValueBitDecompositionGate(airthmetic_share_parent, output_owner);
//   // }

//   ~ArithmeticGmwValueBitDecompositionGate() final = default;

//   void EvaluateSetup() final override {
//     SetSetupIsReady();
//     GetRegister().IncrementEvaluatedGatesSetupCounter();
//   }

//   void EvaluateOnline() final override {
//     // std::cout << "ArithmeticGmwValueBitDecompositionGate EvaluateOnline" << std::endl;

//     // setup needs to be done first
//     WaitSetup();
//     assert(setup_is_ready_);

//     // wait for the parent wires to obtain their values
//     for (const auto& wire : parent_) {
//       wire->GetIsReadyCondition().Wait();
//     }

//     // // wait for output gate to reconstruct a
//     // arithmetic_output_gate_->WaitOnline();
//     // const auto arithmetic_share = arithmetic_output_gate_->GetOutputAsArithmeticShare();
//     // const auto& output_wire = arithmetic_share->GetWires().at(0);
//     // const auto arithmetic_output_wire =
//     //     std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(output_wire);

//     // assign parent value to arithmetic_wire
//     // std::cout << "assign parent value to arithmetic_wire" << std::endl;
//     std::vector<T> arithmetic_wire_value_parent;

//     if (parent_.at(0)->GetProtocol() == MpcProtocol::kArithmeticGmw) {
//       auto arithmetic_wire_parent =
//           std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(parent_.at(0));

//       arithmetic_wire_value_parent = arithmetic_wire_parent->GetValues();
//     } else if (parent_.at(0)->GetProtocol() == MpcProtocol::kArithmeticConstant) {
//       auto arithmetic_wire_parent =
//           std::dynamic_pointer_cast<proto::ConstantArithmeticWire<T>>(parent_.at(0));

//       arithmetic_wire_value_parent = arithmetic_wire_parent->GetValues();
//     }

//     // bit-decompose the reconstructed arithmetic value into Boolean bits
//     std::vector<BitVector<>> boolean_output;
//     boolean_output = ToInput<T>(arithmetic_wire_value_parent);
//     // std::cout << "arithmetic_wire_parent: " << arithmetic_wire_value_parent.at(0) <<
//     std::endl;
//     // std::cout << "boolean_output.at(i).Get(0): " << std::endl;
//     for (auto i = 0ull; i < number_of_wires_; i++) {
//       // boolean_output.emplace_back(1, ((arithmetic_wire_value_parent.at(0) >> i) & 1) == 1);
//       // std::cout << boolean_output.at(i).Get(0);
//       auto boolean_wire = std::dynamic_pointer_cast<boolean_gmw::Wire>(boolean_wires_.at(i));
//       boolean_wire->GetMutableValues() = boolean_output.at(i);
//       boolean_wire->SetOnlineFinished();
//     }
//     // std::cout << std::endl;

//     // std::cout << "reverse order" << std::endl;
//     // for (auto i = 0ull; i < number_of_wires_; i++) {
//     //   std::cout << boolean_output.at(number_of_wires_ - 1 - i).Get(0);
//     // }
//     // std::cout << std::endl;

//     // std::cout << "SetOnlineIsReady: " << std::endl;
//     SetOnlineIsReady();
//     GetRegister().IncrementEvaluatedGatesOnlineCounter();
//     // std::cout << "Evaluate online finish: " << std::endl;
//   }

//   // the output value is publicly known after EvaluateOnline()
//   const motion::proto::boolean_gmw::SharePointer GetOutputAsBooleanGmwValue() {
//     auto boolean_output_share =
//     std::make_shared<motion::proto::boolean_gmw::Share>(boolean_wires_);
//     assert(boolean_output_share);
//     // auto output_share = std::static_pointer_cast<motion::Share>(boolean_output_share);
//     // assert(output_share);
//     if (parent_.at(0)->IsPubliclyKnownWire()) {
//       boolean_output_share->SetAsPubliclyKnownShare();
//     }
//     return boolean_output_share;
//   }

//   // // the output value is publicly known value after EvaluateOnline()
//   // const arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticGmwValue() {
//   //   auto arithmetic_output_wire =
//   //       std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(arithmetic_wires_.at(0));
//   //   assert(arithmetic_output_wire);
//   //   auto arithmetic_output_share =
//   //       std::make_shared<arithmetic_gmw::Share<T>>(arithmetic_output_wire);
//   //   return arithmetic_output_share;
//   // }

//   ArithmeticGmwValueBitDecompositionGate() = delete;

//   ArithmeticGmwValueBitDecompositionGate(Gate&) = delete;

//  private:
//   // // indicates whether this party obtains the output
//   // bool is_my_output_ = false;

//   // wires to store the bits of after bit-decomposition
//   std::vector<motion::WirePointer> boolean_wires_;

//   // // wires to store the arithmetic value
//   // std::vector<arithmetic_gmw::WirePointer<T>> arithmetic_wires_;

//   // std::int64_t output_owner_ = -1;
//   // std::vector<motion::ReusableFiberFuture<std::vector<std::uint8_t>>>
//   output_message_futures_;
//   // std::mutex m;

//   // arithmetic_gmw::WirePointer<T> parent_R_;
//   // arithmetic_gmw::WirePointer<T> parent_M_;
//   // std::size_t M_;

//   std::shared_ptr<motion::proto::arithmetic_gmw::OutputGate<T>> arithmetic_output_gate_;

//   // motion::proto::arithmetic_gmw::SharePointer<T> arithmetic_share;

//   std::size_t num_of_simd_;
//   // std::size_t number_of_wires_;

//   std::size_t number_of_wires_;
//   // std::size_t number_of_simd_values_;
// };

// // added by Liang Zhao
// // convert arithmetic value to boolean value
// // arithmetic value is of type T, boolean value has same bit length as type T
// template <typename T, typename DigitType>
// class ArithmeticGmwValueDigitDecompositionGate final : public motion::OneGate {
//  public:
//   ArithmeticGmwValueDigitDecompositionGate(const arithmetic_gmw::WirePointer<T>& parent,
//                                            std::size_t digit_bit_size,
//                                            std::size_t output_owner = kAll)
//       : OneGate(parent->GetBackend()) {
//     // std::cout << "ArithmeticGmwValueDigitDecompositionGate" << std::endl;
//     assert(parent);
//     assert(digit_bit_size > 1);
//     assert(sizeof(T) * 8 > digit_bit_size);
//     assert(sizeof(DigitType) * 8 >= digit_bit_size);

//     // assert(parent->IsPubliclyKnownWire());

//     if (parent->GetProtocol() != MpcProtocol::kArithmeticGmw) {
//       auto sharing_type = to_string(parent->GetProtocol());
//       throw(std::runtime_error((fmt::format(
//           "Arithmetic ArithmeticGmwValueDigitDecompositionGate expects an arithmetic share, "
//           "got a share of type {}",
//           sharing_type))));
//     }

//     parent_ = {parent};

//     // ??? not support SIMD yet
//     num_of_simd_ = parent_[0]->GetNumberOfSimdValues();

//     // std::cout << "num_of_simd_: " << num_of_simd_ << std::endl;

//     // create boolean output wires
//     number_of_bits_ = sizeof(T) * 8;
//     digit_bit_size_ = digit_bit_size;
//     number_of_digits_ = ceil(double(number_of_bits_) / digit_bit_size_);

//     // std::cout << "number_of_digits_: " << number_of_digits_ << std::endl;

//     requires_online_interaction_ = false;
//     gate_type_ = GateType::kNonInteractive;

//     // create the arithmetic digit output wires
//     arithmetic_gmw_digit_wires_.reserve(number_of_digits_);
//     if (parent_.at(0)->IsPubliclyKnownWire()) {
//       for (size_t i = 0; i < number_of_digits_; i++) {
//         auto& w =
//         arithmetic_gmw_digit_wires_.emplace_back(std::static_pointer_cast<motion::Wire>(
//             std::make_shared<arithmetic_gmw::Wire<DigitType>>(backend_, num_of_simd_)));
//         GetRegister().RegisterNextWire(w);
//         arithmetic_gmw_digit_wires_.at(i)->SetAsPubliclyKnownWire();
//       }
//     } else {
//       for (size_t i = 0; i < number_of_digits_; i++) {
//         auto& w =
//         arithmetic_gmw_digit_wires_.emplace_back(std::static_pointer_cast<motion::Wire>(
//             std::make_shared<arithmetic_gmw::Wire<DigitType>>(backend_, num_of_simd_)));
//         GetRegister().RegisterNextWire(w);
//       }
//     }

//     // std::cout << "create the arithmetic digit output wires" << std::endl;

//     // register this gate
//     gate_id_ = GetRegister().NextGateId();

//     // register this gate with the parent_ wires
//     for (auto& wire : parent_) {
//       RegisterWaitingFor(wire->GetWireId());
//       wire->RegisterWaitingGate(gate_id_);
//     }

//     if constexpr (kDebug) {
//       auto gate_info = fmt::format("gate id {}", gate_id_);
//       GetLogger().LogDebug(fmt::format(
//           "Allocate an ArithmeticGmwValueDigitDecompositionGate with following properties: {}",
//           gate_info));
//     }

//     // std::cout << "finish create ArithmeticGmwValueDigitDecompositionGate" << std::endl;
//   }

//   // ArithmeticGmwValueDigitDecompositionGate(const arithmetic_gmw::SharePointer<T> &parent,
//   //                                       std::size_t output_owner = kAll)
//   //     : ArithmeticGmwValueDigitDecompositionGate(parent->GetArithmeticWire(), output_owner)
//   // {
//   //     assert(parent);
//   // }

//   // ArithmeticGmwValueDigitDecompositionGate(const motion::SharePointer& parent, std::size_t
//   // output_owner = kAll) {
//   //   assert(parent);

//   //   const arithmetic_gmw::SharePointer<T>& airthmetic_share_parent =
//   //       std::dynamic_pointer_cast<const arithmetic_gmw::Share<T>>(parent);
//   //   ArithmeticGmwValueDigitDecompositionGate(airthmetic_share_parent, output_owner);
//   // }

//   ~ArithmeticGmwValueDigitDecompositionGate() final = default;

//   void EvaluateSetup() final override {
//     SetSetupIsReady();
//     GetRegister().IncrementEvaluatedGatesSetupCounter();
//   }

//   void EvaluateOnline() final override {
//     // std::cout << "ArithmeticGmwValueDigitDecompositionGate EvaluateOnline" << std::endl;

//     // setup needs to be done first
//     WaitSetup();
//     assert(setup_is_ready_);

//     // wait for the parent wires to obtain their values
//     for (const auto& wire : parent_) {
//       wire->GetIsReadyCondition().Wait();
//     }

//     // assign parent value to arithmetic_wire
//     // std::cout << "assign parent value to arithmetic_wire" << std::endl;
//     std::vector<T> arithmetic_wire_value_parent;
//     if (parent_.at(0)->GetProtocol() == MpcProtocol::kArithmeticGmw) {
//       auto arithmetic_wire_parent =
//           std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(parent_.at(0));

//       arithmetic_wire_value_parent = arithmetic_wire_parent->GetValues();

//     } else if (parent_.at(0)->GetProtocol() == MpcProtocol::kArithmeticConstant) {
//       auto arithmetic_wire_parent =
//           std::dynamic_pointer_cast<proto::ConstantArithmeticWire<T>>(parent_.at(0));

//       arithmetic_wire_value_parent = arithmetic_wire_parent->GetValues();
//     }

//     // std::cout << "arithmetic_wire_value_parent[0]: " <<
//     unsigned(arithmetic_wire_value_parent[0])
//     //           << std::endl;
//     //
//     //     digit-decompose the arithmetic value into Boolean bits
//     std::vector<DigitType> arithmetic_digit_value_output;
//     T digit_mask = (T(1) << digit_bit_size_) - 1;

//     // std::cout << "digit_mask: " << digit_mask << std::endl;

//     for (auto i = 0ull; i < number_of_digits_; i++) {
//       arithmetic_digit_value_output.emplace_back(
//           DigitType(arithmetic_wire_value_parent.at(0) >> i * digit_bit_size_) & digit_mask);

//       // for test
//       //   DigitType digit_decompose_part =
//       //       DigitType((arithmetic_wire_value_parent.at(0) >> i * digit_bit_size_) &
//       digit_mask);
//       //   std::cout << "digit_decompose_part: " << digit_decompose_part << std::endl;

//       auto arithmetic_digit_wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<DigitType>>(
//           arithmetic_gmw_digit_wires_.at(i));
//       arithmetic_digit_wire->GetMutableValues() =
//           std::vector<DigitType>(1, arithmetic_digit_value_output.at(i));

//       // std::cout << "arithmetic_digit_value_output.at(i): "
//       //           << unsigned(arithmetic_digit_value_output.at(i)) << std::endl;

//       //   std::cout << "arithmetic_digit_wire->GetMutableValues()[0]: "
//       //             << arithmetic_digit_wire->GetMutableValues()[0] << std::endl;

//       arithmetic_digit_wire->SetOnlineFinished();
//     }

//     // std::cout << "SetOnlineIsReady: " << std::endl;
//     SetOnlineIsReady();
//     GetRegister().IncrementEvaluatedGatesOnlineCounter();
//     // std::cout << "ArithmeticGmwValueDigitDecompositionGate EvaluateOnline finish" <<
//     std::endl;
//   }

//   const std::vector<motion::proto::arithmetic_gmw::SharePointer<DigitType>>
//   GetOutputAsArithmeticGmwShareVector() {
//     std::vector<motion::proto::arithmetic_gmw::SharePointer<DigitType>>
//         arithmetic_output_share_vector;
//     arithmetic_output_share_vector.reserve(number_of_digits_);

//     for (std::size_t i = 0; i < number_of_digits_; i++) {
//       auto arithmetic_output_share =
//           std::make_shared<motion::proto::arithmetic_gmw::Share<DigitType>>(
//               arithmetic_gmw_digit_wires_[i]);
//       assert(arithmetic_output_share);
//       // auto output_share = std::static_pointer_cast<motion::Share>(arithmetic_output_share);
//       // assert(output_share);
//       if (parent_.at(0)->IsPubliclyKnownWire()) {
//         arithmetic_output_share->SetAsPubliclyKnownShare();
//       }
//       arithmetic_output_share_vector.emplace_back(arithmetic_output_share);
//     }
//     return arithmetic_output_share_vector;
//   }

//   // // the output value is publicly known value after EvaluateOnline()
//   // const arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticGmwValue() {
//   //   auto arithmetic_output_wire =
//   //       std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(arithmetic_wires_.at(0));
//   //   assert(arithmetic_output_wire);
//   //   auto arithmetic_output_share =
//   //       std::make_shared<arithmetic_gmw::Share<T>>(arithmetic_output_wire);
//   //   return arithmetic_output_share;
//   // }

//   ArithmeticGmwValueDigitDecompositionGate() = delete;

//   ArithmeticGmwValueDigitDecompositionGate(Gate&) = delete;

//  private:
//   // wires to store the bits of after digit-decomposition
//   std::vector<motion::WirePointer> arithmetic_gmw_digit_wires_;

//   // // wires to store the arithmetic value
//   // std::vector<arithmetic_gmw::WirePointer<T>> arithmetic_wires_;

//   // std::int64_t output_owner_ = -1;
//   // std::vector<motion::ReusableFiberFuture<std::vector<std::uint8_t>>>
//   output_message_futures_;
//   // std::mutex m;

//   // arithmetic_gmw::WirePointer<T> parent_R_;
//   // arithmetic_gmw::WirePointer<T> parent_M_;
//   // std::size_t M_;

//   // motion::proto::arithmetic_gmw::SharePointer<T> arithmetic_share;

//   std::size_t num_of_simd_;

//   std::size_t number_of_bits_;
//   std::size_t number_of_digits_;
//   std::size_t digit_bit_size_;
//   // std::size_t number_of_simd_values_;
// };

// // added by Liang Zhao
// // convert Boolean value to arithmetic value
// template <typename T>
// class BooleanGmwValueToArithmeticGmwValueGate final : public motion::OneGate {
//  public:
//   BooleanGmwValueToArithmeticGmwValueGate(const motion::SharePointer& parent,
//                                           std::size_t output_owner = kAll)
//       : OneGate(parent->GetBackend()) {
//     // std::cout << "BooleanGmwValueToArithmeticGmwValueGate" << std::endl;
//     assert(parent);
//     // assert(parent_R);

//     if (parent->GetProtocol() != MpcProtocol::kBooleanGmw) {
//       auto sharing_type = to_string(parent->GetProtocol());
//       throw(std::runtime_error(
//           (fmt::format("BooleanGmwValueToArithmeticGmwValueGate expects an boolean share, "
//                        "got a share of type {}",
//                        sharing_type))));
//     }

//     parent_ = parent->GetWires();
//     number_of_wires_ = parent_.size();

//     // TODO should support SIMD now
//     num_of_simd_ = parent->GetNumberOfSimdValues();

//     // create boolean output wires
//     // constexpr auto number_of_wires{sizeof(T) * 8};
//     // number_of_wires_ = sizeof(T) * 8;
//     // std::cout << "number_of_wires: " << number_of_wires_ << std::endl;

//     requires_online_interaction_ = false;
//     gate_type_ = GateType::kNonInteractive;

//     // create the arithmetic output wires
//     arithmetic_wires_.emplace_back(
//         std::make_shared<motion::proto::arithmetic_gmw::Wire<T>>(backend_, num_of_simd_));
//     GetRegister().RegisterNextWire(arithmetic_wires_.at(0));

//     arithmetic_wires_.at(0)->SetAsPubliclyKnownWire();
//     for (std::size_t i = 0; i < number_of_wires_; i++) {
//       if (!(parent_[i]->IsPubliclyKnownWire())) {
//         arithmetic_wires_.at(0)->SetAsPubliclyUnknownWire();
//       }
//     }

//     // // create the boolean output wires
//     // boolean_wires_.reserve(number_of_wires_);
//     // for (size_t i = 0; i < number_of_wires_; i++) {
//     //   auto& w = boolean_wires_.emplace_back(std::static_pointer_cast<motion::Wire>(
//     //       std::make_shared<boolean_gmw::Wire>(backend_, num_of_simd_)));
//     //   GetRegister().RegisterNextWire(w);
//     // }

//     // // create the output gate to reconstruct the a
//     // auto arithmetic_parent_wire =
//     //     std::dynamic_pointer_cast<motion::proto::arithmetic_gmw::Wire<T>>(parent_.at(0));
//     // arithmetic_output_gate_ =
//     // std::make_shared<motion::proto::arithmetic_gmw::OutputGate<T>>(arithmetic_parent_wire);
//     // GetRegister().RegisterNextGate(arithmetic_output_gate_);

//     // register this gate
//     gate_id_ = GetRegister().NextGateId();

//     // register this gate with the parent_ wires
//     for (auto& wire : parent_) {
//       RegisterWaitingFor(wire->GetWireId());
//       wire->RegisterWaitingGate(gate_id_);
//     }

//     if constexpr (kDebug) {
//       auto gate_info = fmt::format("gate id {}", gate_id_);
//       GetLogger().LogDebug(fmt::format(
//           "Allocate an BooleanGmwValueToArithmeticGmwValueGate with following properties: {}",
//           gate_info));
//     }

//     // std::cout << "finish create BooleanGmwValueToArithmeticGmwValueGate" << std::endl;
//   }

//   // BooleanGmwValueToArithmeticGmwValueGate(const boolean_gmw::SharePointer<T>& parent,
//   std::size_t
//   // output_owner = kAll)
//   //     : BooleanGmwValueToArithmeticGmwValueGate(parent->GetWires(), output_owner) {
//   //   assert(parent);
//   // }

//   // BooleanGmwValueToArithmeticGmwValueGate(const motion::SharePointer& parent, std::size_t
//   // output_owner = kAll) {
//   //   assert(parent);

//   //   const arithmetic_gmw::SharePointer<T>& airthmetic_share_parent =
//   //       std::dynamic_pointer_cast<const arithmetic_gmw::Share<T>>(parent);
//   //   BooleanGmwValueToArithmeticGmwValueGate(airthmetic_share_parent, output_owner);
//   // }

//   ~BooleanGmwValueToArithmeticGmwValueGate() final = default;

//   void EvaluateSetup() final override {
//     SetSetupIsReady();
//     GetRegister().IncrementEvaluatedGatesSetupCounter();
//   }

//   void EvaluateOnline() final override {
//     // std::cout << "BooleanGmwValueToArithmeticGmwValueGate EvaluateOnline" << std::endl;

//     // setup needs to be done first
//     WaitSetup();
//     assert(setup_is_ready_);

//     // wait for the parent wires to obtain their values
//     for (const auto& wire : parent_) {
//       wire->GetIsReadyCondition().Wait();
//     }

//     // // wait for output gate to reconstruct a
//     // arithmetic_output_gate_->WaitOnline();
//     // const auto arithmetic_share = arithmetic_output_gate_->GetOutputAsArithmeticShare();
//     // const auto& output_wire = arithmetic_share->GetWires().at(0);
//     // const auto arithmetic_output_wire =
//     //     std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(output_wire);

//     // assign parent value to boolean_wire
//     // std::cout << "assign parent value to boolean_wire" << std::endl;
//     std::vector<BitVector<>> boolean_wire_value_parent;
//     boolean_wire_value_parent.reserve(number_of_wires_);

//     for (auto i = 0ull; i < number_of_wires_; ++i) {
//       if (parent_.at(i)->GetProtocol() == MpcProtocol::kBooleanGmw) {
//         auto boolean_wire_parent = std::dynamic_pointer_cast<boolean_gmw::Wire>(parent_.at(i));
//         boolean_wire_value_parent.emplace_back(boolean_wire_parent->GetValues());
//       } else if (parent_.at(i)->GetProtocol() == MpcProtocol::kBooleanConstant) {
//         auto boolean_wire_parent =
//             std::dynamic_pointer_cast<proto::ConstantBooleanWire>(parent_.at(i));
//         boolean_wire_value_parent.emplace_back(boolean_wire_parent->GetValues());
//       }
//     }

//     // calculate arithmetic value based on Boolean bits
//     // T arithmetic_output = 0;
//     std::vector<T> arithmetic_output_vector(num_of_simd_);
//     // std::cout << "boolean_wire_parent: " << arithmetic_wire_value_parent.at(0) << std::endl;
//     // std::cout << "boolean_output.at(i).Get(0): " << std::endl;
//     for (std::size_t j = 0; j < num_of_simd_; ++j)
//       for (auto i = 0ull; i < number_of_wires_; i++) {
//         if (boolean_wire_value_parent.at(i).Get(j)) {
//           arithmetic_output_vector[j] += T(1) << i;
//         }
//       }

//     // ]    std::vector<T> arithmetic_output_vector{arithmetic_output};
//     arithmetic_wires_.at(0)->GetMutableValues() = arithmetic_output_vector;

//     // std::cout << "boolean_output.at(i).Get(0): " << std::endl;
//     // for (auto i = 0ull; i < number_of_wires_; i++) {
//     //   std::cout << boolean_wire_value_parent.at(i).Get(0);
//     // }
//     // std::cout << std::endl;

//     // std::cout << "arithmetic_output: " << arithmetic_output << std::endl;

//     // std::cout << "SetOnlineIsReady: " << std::endl;
//     // SetOnlineIsReady();
//     arithmetic_wires_.at(0)->SetOnlineFinished();
//     // set online condition ready
//     {
//       std::scoped_lock lock(online_is_ready_condition_.GetMutex());
//       online_is_ready_ = true;
//     }

//     GetRegister().IncrementEvaluatedGatesOnlineCounter();
//     // std::cout << "Evaluate online finish: " << std::endl;
//   }

//   // // the output value is publicly known after EvaluateOnline()
//   // const motion::proto::boolean_gmw::SharePointer GetOutputAsBooleanGmwValue() {
//   //   auto boolean_output_share =
//   //   std::make_shared<motion::proto::boolean_gmw::Share>(boolean_wires_);
//   //   assert(boolean_output_share);
//   //   // auto output_share = std::static_pointer_cast<motion::Share>(boolean_output_share);
//   //   // assert(output_share);
//   //   return boolean_output_share;
//   // }

//   // the output value is publicly known value after EvaluateOnline()
//   const arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticGmwValue() {
//     auto arithmetic_output_wire =
//         std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(arithmetic_wires_.at(0));
//     assert(arithmetic_output_wire);
//     auto arithmetic_output_share =
//         std::make_shared<arithmetic_gmw::Share<T>>(arithmetic_output_wire);
//     return arithmetic_output_share;
//   }

//   BooleanGmwValueToArithmeticGmwValueGate() = delete;

//   BooleanGmwValueToArithmeticGmwValueGate(Gate&) = delete;

//  private:
//   // // indicates whether this party obtains the output
//   // bool is_my_output_ = false;

//   // // wires to store the bits of after bit-decomposition
//   // std::vector<motion::WirePointer> boolean_wires_;

//   // wires to store the arithmetic value
//   std::vector<arithmetic_gmw::WirePointer<T>> arithmetic_wires_;

//   // std::int64_t output_owner_ = -1;
//   // std::vector<motion::ReusableFiberFuture<std::vector<std::uint8_t>>>
//   output_message_futures_;
//   // std::mutex m;

//   // arithmetic_gmw::WirePointer<T> parent_R_;
//   // arithmetic_gmw::WirePointer<T> parent_M_;
//   // std::size_t M_;

//   // std::shared_ptr<motion::proto::arithmetic_gmw::OutputGate<T>> arithmetic_output_gate_;

//   // motion::proto::arithmetic_gmw::SharePointer<T> arithmetic_share;

//   std::size_t num_of_simd_;
//   std::size_t number_of_wires_;
// };

// // added by Liang Zhao
// // convert constant arithmetic share to arithmetic share
// template <typename T>
// class ArithmeticGmwConstantToArithmeticGmwValueGate final : public OneGate {
//  public:
//   ArithmeticGmwConstantToArithmeticGmwValueGate(const ConstantArithmeticWirePointer<T>& a)
//       : OneGate(a->GetBackend()) {
//     parent_ = {std::static_pointer_cast<Wire>(a)};
//     // std::cout << "ArithmeticGmwConstantToArithmeticGmwValueGate" << std::endl;

//     requires_online_interaction_ = false;
//     gate_type_ = GateType::kNonInteractive;

//     gate_id_ = GetRegister().NextGateId();

//     RegisterWaitingFor(parent_.at(0)->GetWireId());
//     parent_.at(0)->RegisterWaitingGate(gate_id_);

//     {
//       // reserve for output wires
//       auto w = std::make_shared<arithmetic_gmw::Wire<T>>(backend_, a->GetNumberOfSimdValues());
//       GetRegister().RegisterNextWire(w);
//       output_wires_ = {std::move(w)};

//       // assign for the output wires
//       auto input_wire = parent_.at(0);
//       auto constant_input_wire =
//           std::dynamic_pointer_cast<const ConstantArithmeticWire<T>>(input_wire);

//       auto arithmetic_output_wire =
//           std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
//       arithmetic_output_wire->GetMutableValues() = constant_input_wire->GetValues();
//       arithmetic_output_wire->SetAsPubliclyKnownWire();
//       // std::cout << "ArithmeticGmwConstantToArithmeticGmwValueGate,constant_input_wire: "
//       //           << constant_input_wire->GetValues()[0] << std::endl;
//     }

//     auto gate_info = fmt::format("uint{}_t type, gate id {}, parents: {}", sizeof(T) * 8,
//     gate_id_,
//                                  parent_.at(0)->GetWireId());
//     GetLogger().LogDebug(
//         fmt::format("Created an ArithmeticGmwConstantToArithmeticGmwValueGate with "
//                     "following properties: {}",
//                     gate_info));
//   }

//   ~ArithmeticGmwConstantToArithmeticGmwValueGate() final = default;

//   void EvaluateSetup() final override {
//     SetSetupIsReady();
//     GetRegister().IncrementEvaluatedGatesSetupCounter();
//   }

//   void EvaluateOnline() final override {
//     WaitSetup();
//     SetOnlineIsReady();
//     GetRegister().IncrementEvaluatedGatesOnlineCounter();
//   }

//   // perhaps, we should return a copy of the pointer and not move it for the
//   // case we need it multiple times
//   arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticGmwValue() {
//     auto arithmetic_output_wire =
//         std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
//     assert(arithmetic_output_wire);
//     auto result = std::make_shared<arithmetic_gmw::Share<T>>(arithmetic_output_wire);
//     result->SetAsPubliclyKnownShare();
//     return result;
//   }

//   ArithmeticGmwConstantToArithmeticGmwValueGate() = delete;

//   ArithmeticGmwConstantToArithmeticGmwValueGate(Gate&) = delete;
// };

// // added by Liang Zhao
// // convert constant arithmetic GMW share to boolean GMW value
// // when as_boolean_gmw_share = false, each party hold exactly the same value,
// // otherwise, only one party hold the value, the rest parties hold value zeros

// template <typename T>
// class ArithmeticGmwConstantToBooleanGmwValueGate final : public OneGate {
//  public:
//   ArithmeticGmwConstantToBooleanGmwValueGate(const ConstantArithmeticWirePointer<T>& a,
//                                              bool as_boolean_gmw_share = false)
//       : OneGate(a->GetBackend()) {
//     parent_ = {std::static_pointer_cast<Wire>(a)};
//     // std::cout << "ArithmeticGmwConstantToBooleanGmwValueGate" << std::endl;

//     as_boolean_gmw_share_ = as_boolean_gmw_share;

//     requires_online_interaction_ = false;
//     gate_type_ = GateType::kNonInteractive;

//     gate_id_ = GetRegister().NextGateId();

//     RegisterWaitingFor(parent_.at(0)->GetWireId());
//     parent_.at(0)->RegisterWaitingGate(gate_id_);

//     // assign for the output wires
//     auto input_wire = parent_.at(0);
//     auto constant_input_wire =
//         std::dynamic_pointer_cast<const ConstantArithmeticWire<T>>(input_wire);

//     // create output wires based on the type of the parent wires a and b
//     num_of_output_wires_ = sizeof(T) * 8;

//     // TODO should support SIMD yet
//     num_of_simd_ = parent_.at(0)->GetNumberOfSimdValues();

//     // std::cout<<"num_of_output_wires_: "<<num_of_output_wires_<<std::endl;

//     // reserve for output wires
//     output_wires_.reserve(num_of_output_wires_);
//     for (size_t i = 0; i < num_of_output_wires_; i++) {
//       auto& w = output_wires_.emplace_back(std::static_pointer_cast<motion::Wire>(
//           std::make_shared<boolean_gmw::Wire>(backend_, num_of_simd_)));
//       GetRegister().RegisterNextWire(w);
//       w->SetAsPubliclyKnownWire();
//     }

//     if (!as_boolean_gmw_share) {
//       std::vector<BitVector<>> boolean_output;
//       boolean_output = ToInput<T>(constant_input_wire->GetValues());
//       for (auto i = 0ull; i < num_of_output_wires_; i++) {
//         // boolean_output.emplace_back(1, ((constant_input_wire->GetValues().at(0) >> i) & 1)
//         == 1);
//         //   std::cout << boolean_output.at(i).Get(0);
//         auto boolean_output_wire =
//             std::dynamic_pointer_cast<boolean_gmw::Wire>(output_wires_.at(i));
//         boolean_output_wire->GetMutableValues() = boolean_output.at(i);
//         //   boolean_wire->SetOnlineFinished();
//       }
//     } else {
//       std::vector<BitVector<>> boolean_output;

//       const bool set_as_constant_arithmetic_value =
//           (parent_.at(0)->GetWireId() % GetCommunicationLayer().GetNumberOfParties()) ==
//           GetCommunicationLayer().GetMyId();

//       // only one party hold the value of the constant input
//       if (set_as_constant_arithmetic_value) {
//         boolean_output = ToInput<T>(constant_input_wire->GetValues());
//         for (auto i = 0ull; i < num_of_output_wires_; i++) {
//           // boolean_output.emplace_back(1, ((constant_input_wire->GetValues().at(0) >> i) & 1)
//           ==
//           // 1);
//           auto boolean_output_wire =
//               std::dynamic_pointer_cast<boolean_gmw::Wire>(output_wires_.at(i));
//           boolean_output_wire->GetMutableValues() = boolean_output.at(i);
//         }
//       }

//       // the rest parites hold the value of zeros
//       else {
//         for (auto i = 0ull; i < num_of_output_wires_; i++) {
//           boolean_output.emplace_back(num_of_simd_, false);
//           auto boolean_output_wire =
//               std::dynamic_pointer_cast<boolean_gmw::Wire>(output_wires_.at(i));
//           boolean_output_wire->GetMutableValues() = boolean_output.at(i);
//         }
//       }
//     }

//     auto gate_info = fmt::format("uint{}_t type, gate id {}, parents: {}", sizeof(T) * 8,
//     gate_id_,
//                                  parent_.at(0)->GetWireId());
//     GetLogger().LogDebug(
//         fmt::format("Created an ArithmeticGmwConstantToBooleanGmwValueGate with "
//                     "following properties: {}",
//                     gate_info));
//   }

//   ~ArithmeticGmwConstantToBooleanGmwValueGate() final = default;

//   void EvaluateSetup() final override {
//     SetSetupIsReady();
//     GetRegister().IncrementEvaluatedGatesSetupCounter();
//   }

//   void EvaluateOnline() final override {
//     WaitSetup();
//     SetOnlineIsReady();
//     GetRegister().IncrementEvaluatedGatesOnlineCounter();
//   }

//   // perhaps, we should return a copy of the pointer and not move it for the
//   // case we need it multiple times
//   boolean_gmw::SharePointer GetOutputAsBooleanGmwValue() {
//     // auto arithmetic_output_wire =
//     //     std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
//     // assert(arithmetic_output_wire);
//     auto result = std::make_shared<boolean_gmw::Share>(output_wires_);
//     result->SetAsPubliclyKnownShare();
//     return result;
//   }

//   ArithmeticGmwConstantToBooleanGmwValueGate() = delete;

//   ArithmeticGmwConstantToBooleanGmwValueGate(Gate&) = delete;

//  private:
//   std::size_t num_of_output_wires_ = 0;
//   std::size_t num_of_simd_ = 1;
//   bool as_boolean_gmw_share_ = false;
// };

// // added by Liang Zhao
// template <typename T, typename U>
// class ArithmeticGmwValueSplitGate final : public OneGate {
//  public:
//   ArithmeticGmwValueSplitGate(const arithmetic_gmw::WirePointer<T>& parent)
//       : OneGate(parent->GetBackend()) {
//     // std::cout << "ArithmeticGmwValueSplitGate" << std::endl;
//     parent_ = {std::static_pointer_cast<Wire>(parent)};

//     // assert(parent->IsPubliclyKnownWire());

//     // assert that not both parent are const
//     // TODO: parent separate gate for this probably rather rare case
//     // needs some mediocre implementation effort if implemented with parent deferred inputs
//     option

//     requires_online_interaction_ = false;
//     gate_type_ = GateType::kNonInteractive;

//     gate_id_ = GetRegister().NextGateId();

//     RegisterWaitingFor(parent_.at(0)->GetWireId());
//     parent_.at(0)->RegisterWaitingGate(gate_id_);

//     // reserve for output wires
//     {
//       auto arithmetic_output_wire_a =
//           std::make_shared<arithmetic_gmw::Wire<U>>(backend_, parent->GetNumberOfSimdValues());
//       GetRegister().RegisterNextWire(arithmetic_output_wire_a);
//       arithmetic_output_wires_a_ = {std::move(arithmetic_output_wire_a)};

//       auto arithmetic_output_wire_b =
//           std::make_shared<arithmetic_gmw::Wire<U>>(backend_, parent->GetNumberOfSimdValues());
//       GetRegister().RegisterNextWire(arithmetic_output_wire_b);
//       arithmetic_output_wires_b_ = {std::move(arithmetic_output_wire_b)};
//     }

//     if (parent->IsPubliclyKnownWire()) {
//       arithmetic_output_wires_a_.at(0)->SetAsPubliclyKnownWire();
//       arithmetic_output_wires_b_.at(0)->SetAsPubliclyKnownWire();
//     } else {
//       arithmetic_output_wires_a_.at(0)->SetAsPubliclyUnknownWire();
//       arithmetic_output_wires_b_.at(0)->SetAsPubliclyUnknownWire();
//     }

//     auto gate_info = fmt::format("uint{}_t type, gate id {}, parents: {}", sizeof(T) * 8,
//     gate_id_,
//                                  parent_.at(0)->GetWireId());
//     GetLogger().LogDebug(fmt::format(
//         "Created an ArithmeticGmwValueSplitGate with following properties: {}", gate_info));
//   }

//   ~ArithmeticGmwValueSplitGate() final = default;

//   void EvaluateSetup() final override {
//     SetSetupIsReady();
//     GetRegister().IncrementEvaluatedGatesSetupCounter();
//   }

//   void EvaluateOnline() final override {
//     WaitSetup();
//     assert(setup_is_ready_);

//     parent_.at(0)->GetIsReadyCondition().Wait();

//     auto input_wire = parent_.at(0);

//     auto arithmetic_input_wire =
//         std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(input_wire);

//     assert(arithmetic_input_wire);

//     std::vector<std::vector<U>> output_vector =
//         ValueSplitVectors<T, U>(arithmetic_input_wire->GetValues());

//     // assign modulo conversion result to output wires
//     auto arithmetic_output_wire_a =
//         std::dynamic_pointer_cast<arithmetic_gmw::Wire<U>>(arithmetic_output_wires_a_.at(0));
//     arithmetic_output_wire_a->GetMutableValues() = std::move(output_vector[0]);
//     auto arithmetic_output_wire_b =
//         std::dynamic_pointer_cast<arithmetic_gmw::Wire<U>>(arithmetic_output_wires_b_.at(0));
//     arithmetic_output_wire_b->GetMutableValues() = std::move(output_vector[1]);

//     GetLogger().LogDebug(fmt::format("Evaluated ArithmeticGmwValueSplitGate with id#{}",
//     gate_id_));

//     // SetOnlineIsReady();
//     arithmetic_output_wire_a->SetOnlineFinished();
//     arithmetic_output_wire_b->SetOnlineFinished();
//     {
//       std::scoped_lock lock(online_is_ready_condition_.GetMutex());
//       online_is_ready_ = true;
//     }
//     online_is_ready_condition_.NotifyAll();

//     GetRegister().IncrementEvaluatedGatesOnlineCounter();
//   }

//   arithmetic_gmw::SharePointer<U> GetOutputAsArithmeticGmwValueVectorA() {
//     auto arithmetic_output_wire_a =
//         std::dynamic_pointer_cast<arithmetic_gmw::Wire<U>>(arithmetic_output_wires_a_.at(0));
//     assert(arithmetic_output_wire_a);
//     auto arithmetic_output_share_a =
//         std::make_shared<arithmetic_gmw::Share<U>>(arithmetic_output_wire_a);
//     return arithmetic_output_share_a;
//   }

//   arithmetic_gmw::SharePointer<U> GetOutputAsArithmeticGmwValueVectorB() {
//     auto arithmetic_output_wire_b =
//         std::dynamic_pointer_cast<arithmetic_gmw::Wire<U>>(arithmetic_output_wires_b_.at(0));
//     assert(arithmetic_output_wire_b);
//     auto arithmetic_output_share_b =
//         std::make_shared<arithmetic_gmw::Share<U>>(arithmetic_output_wire_b);
//     return arithmetic_output_share_b;
//   }

//   ArithmeticGmwValueSplitGate() = delete;

//   ArithmeticGmwValueSplitGate(Gate&) = delete;

//  private:
//   std::vector<WirePointer> arithmetic_output_wires_a_;
//   std::vector<WirePointer> arithmetic_output_wires_b_;
// };

// // added by Liang Zhao
// // extend arithmetic share value from field T to U
// template <typename T, typename U>
// class ArithmeticGmwValueFieldConversionGate final : public OneGate {
//  public:
//   ArithmeticGmwValueFieldConversionGate(const arithmetic_gmw::WirePointer<T>& parent)
//       : OneGate(parent->GetBackend()) {
//     // std::cout << "ArithmeticGmwValueFieldConversionGate" << std::endl;
//     parent_ = {std::static_pointer_cast<Wire>(parent)};

//     // assert(parent->IsPubliclyKnownWire());

//     // assert that not both parent are const
//     // TODO: parent separate gate for this probably rather rare case
//     // needs some mediocre implementation effort if implemented with parent deferred inputs
//     option

//     requires_online_interaction_ = false;
//     gate_type_ = GateType::kNonInteractive;

//     gate_id_ = GetRegister().NextGateId();

//     RegisterWaitingFor(parent_.at(0)->GetWireId());
//     parent_.at(0)->RegisterWaitingGate(gate_id_);

//     // reserve for output wires
//     {
//       auto arithmetic_output_wire_a =
//           std::make_shared<arithmetic_gmw::Wire<U>>(backend_, parent->GetNumberOfSimdValues());
//       GetRegister().RegisterNextWire(arithmetic_output_wire_a);
//       arithmetic_output_wires_a_ = {std::move(arithmetic_output_wire_a)};
//     }

//     if (parent->IsPubliclyKnownWire()) {
//       arithmetic_output_wires_a_.at(0)->SetAsPubliclyKnownWire();
//     } else {
//       arithmetic_output_wires_a_.at(0)->SetAsPubliclyUnknownWire();
//     }

//     auto gate_info = fmt::format("uint{}_t type, gate id {}, parents: {}", sizeof(T) * 8,
//     gate_id_,
//                                  parent_.at(0)->GetWireId());
//     GetLogger().LogDebug(fmt::format(
//         "Created an ArithmeticGmwValueFieldConversionGate with following properties: {}",
//         gate_info));
//   }

//   ~ArithmeticGmwValueFieldConversionGate() final = default;

//   void EvaluateSetup() final override {
//     SetSetupIsReady();
//     GetRegister().IncrementEvaluatedGatesSetupCounter();
//   }

//   void EvaluateOnline() final override {
//     WaitSetup();
//     assert(setup_is_ready_);

//     parent_.at(0)->GetIsReadyCondition().Wait();

//     auto input_wire = parent_.at(0);

//     auto arithmetic_input_wire =
//         std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(input_wire);

//     assert(arithmetic_input_wire);

//     std::vector<U> output_vector =
//         ValueFieldConvertionVectors<T, U>(arithmetic_input_wire->GetValues());

//     auto arithmetic_output_wire_a =
//         std::dynamic_pointer_cast<arithmetic_gmw::Wire<U>>(arithmetic_output_wires_a_.at(0));
//     arithmetic_output_wire_a->GetMutableValues() = std::move(output_vector);

//     GetLogger().LogDebug(
//         fmt::format("Evaluated ArithmeticGmwValueFieldConversionGate with id#{}", gate_id_));

//     // SetOnlineIsReady();
//     arithmetic_output_wire_a->SetOnlineFinished();
//     {
//       std::scoped_lock lock(online_is_ready_condition_.GetMutex());
//       online_is_ready_ = true;
//     }
//     online_is_ready_condition_.NotifyAll();

//     GetRegister().IncrementEvaluatedGatesOnlineCounter();
//   }

//   arithmetic_gmw::SharePointer<U> GetOutputAsArithmeticGmwValue() {
//     auto arithmetic_output_wire_a =
//         std::dynamic_pointer_cast<arithmetic_gmw::Wire<U>>(arithmetic_output_wires_a_.at(0));
//     assert(arithmetic_output_wire_a);
//     auto arithmetic_output_share_a =
//         std::make_shared<arithmetic_gmw::Share<U>>(arithmetic_output_wire_a);
//     return arithmetic_output_share_a;
//   }

//   ArithmeticGmwValueFieldConversionGate() = delete;

//   ArithmeticGmwValueFieldConversionGate(Gate&) = delete;

//  private:
//   std::vector<WirePointer> arithmetic_output_wires_a_;
// };

// // added by Liang Zhao
// // generate the shared lookup table with input
// class SecretShareLookupTableGate final : public OneGate {
//  public:
//   SecretShareLookupTableGate(const motion::SharePointer& boolean_gmw_share_demux,
//                              const std::vector<std::vector<bool>>& lookup_table);

//   ~SecretShareLookupTableGate() final = default;

//   void EvaluateSetup() final override;

//   void EvaluateOnline() final override;

//   const motion::SharePointer GetOutputAsMixShare() const;

//   const motion::SharePointer GetOutputAsShare() const;

//   SecretShareLookupTableGate() = delete;

//   SecretShareLookupTableGate(const Gate&) = delete;

//  private:
//   // std::size_t mt_offset_;
//   // std::size_t mt_bitlen_;

//   // std::shared_ptr<motion::Share> d_, e_;
//   // std::shared_ptr<OutputGate> d_output_, e_output_;

//   std::size_t num_of_constant_output_wires_ = 0;
//   std::size_t num_of_gmw_output_wires_ = 0;
//   std::size_t num_of_output_wires_ = 0;
//   // std::size_t num_of_undetermined_output_wires_ = 0;
//   std::size_t num_of_simd_ = 0;
//   // std::vector<std::size_t> index_of_gmw_output_wires_require_interaction_;
//   // std::vector<std::size_t> index_of_gmw_wires_require_interaction_after_evaluation;
//   std::size_t num_of_rows_;
//   std::size_t table_entry_bit_size_;
//   std::vector<std::vector<bool>> lookup_table_;
// };

// added by Liang Zhao
// a ? b : c
// output the value in b or c based on the value of a
class BooleanValueSelectionGate final : public motion::ThreeGate {
 public:
  BooleanValueSelectionGate(const motion::SharePointer& parent_a,
                            const motion::SharePointer& parent_b,
                            const motion::SharePointer& parent_c, std::size_t output_owner = kAll)
      : ThreeGate(parent_a->GetBackend()) {
    //             std::cout << "BooleanValueSelectionGate" << std::endl;
    assert(parent_a);
    assert(parent_b);
    assert(parent_c);

    if (parent_a->GetProtocol() != MpcProtocol::kBooleanGmw) {
      auto sharing_type = to_string(parent_a->GetProtocol());
      throw(std::runtime_error(
          (fmt::format("BooleanValueSelectionGate expects an boolean share, got a share of type {}",
                       sharing_type))));
    }

    parent_a_ = parent_a->GetWires();
    parent_b_ = parent_b->GetWires();
    parent_c_ = parent_c->GetWires();
    number_of_wires_ = parent_a_.size();

    // TODO should support SIMD now
    num_of_simd_ = parent_a->GetNumberOfSimdValues();

    // requires_online_interaction_ = false;
    // gate_type_ = GateType::kNonInteractive;

    // create the boolean output wires
    output_wires_.reserve(number_of_wires_);
    for (std::size_t i = 0; i < number_of_wires_; i++) {
      // auto boolean_gmw_output_wire =
      //     std::make_shared<motion::proto::boolean_gmw::Wire>(backend_, num_of_simd_);
      // boolean_gmw_output_wire->GetMutableValues() = BitVector<>(num_of_simd_, false);
      // output_wires_.push_back(std::static_pointer_cast<motion::Wire>(boolean_gmw_output_wire));
      // GetRegister().RegisterNextWire(output_wires_.at(i));

      auto boolean_gmw_output_wire =
          GetRegister().template EmplaceWire<motion::proto::boolean_gmw::Wire>(backend_,
                                                                               num_of_simd_);
      output_wires_.push_back(boolean_gmw_output_wire);
      boolean_gmw_output_wire->GetMutableValues() = BitVector<>(num_of_simd_, false);
    }

    // // register this gate
    // gate_id_ = GetRegister().NextGateId();

    // // register this gate with the parent_a_ wires
    // for (auto& wire : parent_a_) {
    //   RegisterWaitingFor(wire->GetWireId());
    //   wire->RegisterWaitingGate(gate_id_);
    // }

    // for (auto& wire : parent_b_) {
    //   RegisterWaitingFor(wire->GetWireId());
    //   wire->RegisterWaitingGate(gate_id_);
    // }

    // for (auto& wire : parent_c_) {
    //   RegisterWaitingFor(wire->GetWireId());
    //   wire->RegisterWaitingGate(gate_id_);
    // }

    if constexpr (kDebug) {
      auto gate_info = fmt::format("gate id {}", gate_id_);
      GetLogger().LogDebug(fmt::format(
          "Allocate an BooleanValueSelectionGate with following properties: {}", gate_info));
    }

    // std::cout << "finish create BooleanValueSelectionGate" << std::endl;
  }

  // BooleanValueSelectionGate(const boolean_gmw::SharePointer<T>& parent_a, std::size_t
  // output_owner = kAll)
  //     : BooleanValueSelectionGate(parent_a->GetWires(), output_owner) {
  //   assert(parent_a);
  // }

  // BooleanValueSelectionGate(const motion::SharePointer& parent_a, std::size_t output_owner
  // = kAll) {
  //   assert(parent_a);

  //   const arithmetic_gmw::SharePointer<T>& airthmetic_share_parent =
  //       std::dynamic_pointer_cast<const arithmetic_gmw::Share<T>>(parent_a);
  //   BooleanValueSelectionGate(airthmetic_share_parent, output_owner);
  // }

  ~BooleanValueSelectionGate() final = default;

  void EvaluateSetup() final override {
    // SetSetupIsReady();
    // GetRegister().IncrementEvaluatedGatesSetupCounter();
  }

  void EvaluateOnline() final override {
    // std::cout << "BooleanValueSelectionGate EvaluateOnline" << std::endl;

    // // setup needs to be done first
    // WaitSetup();
    // assert(setup_is_ready_);

    // wait for the parent_a wires to obtain their values
    for (const auto& wire : parent_a_) {
      wire->GetIsReadyCondition().Wait();
    }

    for (const auto& wire : parent_b_) {
      wire->GetIsReadyCondition().Wait();
    }

    for (const auto& wire : parent_c_) {
      wire->GetIsReadyCondition().Wait();
    }

    // assign parent_a value to boolean_wire
    // std::cout << "assign parent_a value to boolean_wire" << std::endl;
    //            std::vector<BitVector<>> boolean_output_wire_value;
    //            boolean_output_wire_value.reserve(number_of_wires_);

    for (auto i = 0ull; i < number_of_wires_; ++i) {
      auto boolean_output_wire = std::dynamic_pointer_cast<boolean_gmw::Wire>(output_wires_.at(i));
      // boolean_output_wire->GetMutableValues() = BitVector<>(num_of_simd_, false);
      auto boolean_gmw_wire_parent_a =
          std::dynamic_pointer_cast<boolean_gmw::Wire>(parent_a_.at(i));

      for (std::size_t j = 0; j < num_of_simd_; ++j) {
        if (boolean_gmw_wire_parent_a->GetValues().Get(j)) {
          auto boolean_gmw_wire_parent_b =
              std::dynamic_pointer_cast<boolean_gmw::Wire>(parent_b_.at(i));
          boolean_output_wire->GetMutableValues().Set(boolean_gmw_wire_parent_b->GetValues().Get(j),
                                                      j);
        } else {
          auto boolean_gmw_wire_parent_c =
              std::dynamic_pointer_cast<boolean_gmw::Wire>(parent_c_.at(i));
          // boolean_output_wire->GetMutableValues() = boolean_gmw_wire_parent_c->GetValues();
          boolean_output_wire->GetMutableValues().Set(boolean_gmw_wire_parent_c->GetValues().Get(j),
                                                      j);
        }
      }
    }

    // SetOnlineIsReady();
    // GetRegister().IncrementEvaluatedGatesOnlineCounter();
    // std::cout << "Evaluate online finish: " << std::endl;
  }

  // the output value is publicly known value after EvaluateOnline()
  const boolean_gmw::SharePointer GetOutputAsBooleanShare() {
    //            auto boolean_output_wire =
    //                    std::dynamic_pointer_cast<boolean_gmw::Wire>(output_wires_);
    //            assert(boolean_output_wire);
    auto boolean_output_share = std::make_shared<boolean_gmw::Share>(output_wires_);
    return boolean_output_share;
  }

  BooleanValueSelectionGate() = delete;

  BooleanValueSelectionGate(Gate&) = delete;

 private:
  // // indicates whether this party obtains the output
  // bool is_my_output_ = false;

  // // wires to store the bits of after bit-decomposition
  // std::vector<motion::WirePointer> boolean_wires_;

  // wires to store the arithmetic value
  // std::vector<arithmetic_gmw::WirePointer<T>> arithmetic_wires_;

  // std::int64_t output_owner_ = -1;
  // std::vector<motion::ReusableFiberFuture<std::vector<std::uint8_t>>>
  // output_message_futures_;
  // std::mutex m;

  // arithmetic_gmw::WirePointer<T> parent_R_;
  // arithmetic_gmw::WirePointer<T> parent_M_;
  // std::size_t M_;

  // std::shared_ptr<motion::proto::arithmetic_gmw::OutputGate<T>> arithmetic_output_gate_;

  // motion::proto::arithmetic_gmw::SharePointer<T> arithmetic_share;

  std::size_t num_of_simd_;
  std::size_t number_of_wires_;
};

}  // namespace encrypto::motion::proto
