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

#include "conversion_gate.h"

#include <cassert>

#include "base/backend.h"
#include "share/bmr_share.h"
#include "share/boolean_gmw_share.h"
#include "utility/constants.h"
#include "wire/bmr_wire.h"
#include "wire/boolean_gmw_wire.h"

namespace MOTION::Gates::Conversion {

BMRToGMWGate::BMRToGMWGate(const Shares::SharePtr &parent) {
  parent_ = parent->GetWires();

  assert(parent_.size() > 0);
  assert(parent_.at(0)->GetBitLength() > 0);
  for ([[maybe_unused]] const auto &wire : parent_) assert(wire->GetProtocol() == MPCProtocol::BMR);

  backend_ = parent_.at(0)->GetBackend();

  requires_online_interaction_ = false;
  gate_type_ = GateType::NonInteractiveGate;
  gate_id_ = GetRegister()->NextGateId();

  for (auto &wire : parent_) {
    RegisterWaitingFor(wire->GetWireId());
    wire->RegisterWaitingGate(gate_id_);
  }

  output_wires_.resize(parent_.size());
  const ENCRYPTO::BitVector tmp_bv(parent->GetNumOfSIMDValues());
  for (auto &w : output_wires_) {
    w = std::make_shared<Wires::GMWWire>(tmp_bv, backend_);
    GetRegister()->RegisterNextWire(w);
  }

  if constexpr (MOTION_DEBUG) {
    auto gate_info = fmt::format("gate id {}, parent wires: ", gate_id_);
    for (const auto &wire : parent_) gate_info.append(fmt::format("{} ", wire->GetWireId()));
    gate_info.append(" output wires: ");
    for (const auto &wire : output_wires_) gate_info.append(fmt::format("{} ", wire->GetWireId()));
    GetLogger()->LogDebug(fmt::format(
        "Created a BMR to Boolean GMW conversion gate with following properties: {}", gate_info));
  }
}

void BMRToGMWGate::EvaluateSetup() { SetSetupIsReady(); }

void BMRToGMWGate::EvaluateOnline() {
  WaitSetup();
  if constexpr (MOTION_DEBUG) {
    auto ptr_backend = backend_.lock();
    assert(ptr_backend);
    ptr_backend->GetLogger()->LogDebug(fmt::format(
        "Start evaluating online phase of BMR to Boolean GMW Gate with id#{}", gate_id_));
  }

  for (auto i = 0ull; i < parent_.size(); ++i) {
    auto bmr_in{std::dynamic_pointer_cast<Wires::BMRWire>(parent_.at(i))};
    assert(bmr_in);

    auto gmw_out{std::dynamic_pointer_cast<Wires::GMWWire>(output_wires_.at(i))};
    assert(gmw_out);

    Helpers::WaitFor(*bmr_in->GetIsReadyCondition());
    const auto my_id{GetConfig()->GetMyId()};
    const auto num_parties{GetConfig()->GetNumOfParties()};
    auto &v{gmw_out->GetMutableValues()};

    // set current gmw shared bits on wire to permutation bits of parent BMR wire
    v = bmr_in->GetPermutationBits();

    // one party needs to XOR shared GMW bits with the public values of BMR wire
    // the party doing this is chosen based on the wire id for load balancing
    if ((gmw_out->GetWireId() % num_parties) == my_id) v ^= bmr_in->GetPublicValues();
  }

  GetRegister()->IncrementEvaluatedGatesCounter();

  SetOnlineIsReady();

  if constexpr (MOTION_DEBUG) {
    GetLogger()->LogDebug(fmt::format(
        "Finished evaluating online phase of BMR to Boolean GMW Gate with id#{}", gate_id_));
  }
}

const Shares::GMWSharePtr BMRToGMWGate::GetOutputAsGMWShare() const {
  auto result = std::make_shared<Shares::GMWShare>(output_wires_);
  assert(result);
  return result;
}

const Shares::SharePtr BMRToGMWGate::GetOutputAsShare() const {
  auto result = std::static_pointer_cast<Shares::Share>(GetOutputAsGMWShare());
  assert(result);
  return result;
}

}