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
#include "communication/bmr_message.h"
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
    GetLogger()->LogDebug(fmt::format(
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
    // the party doing this is chosen based on the wire id for the purpose of load balancing
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

GMWToBMRGate::GMWToBMRGate(const Shares::SharePtr &parent) {
  parent_ = parent->GetWires();
  const auto num_simd{parent->GetNumOfSIMDValues()};

  assert(parent_.size() > 0);
  assert(parent_.at(0)->GetBitLength() > 0);
  for ([[maybe_unused]] const auto &wire : parent_)
    assert(wire->GetProtocol() == MPCProtocol::BooleanGMW);

  backend_ = parent_.at(0)->GetBackend();

  requires_online_interaction_ = false;
  gate_type_ = GateType::NonInteractiveGate;
  gate_id_ = GetRegister()->NextGateId();

  for (auto &wire : parent_) {
    RegisterWaitingFor(wire->GetWireId());
    wire->RegisterWaitingGate(gate_id_);
  }

  output_wires_.resize(parent_.size());
  for (auto &w : output_wires_) {
    w = std::make_shared<Wires::BMRWire>(parent->GetNumOfSIMDValues(), backend_);
    GetRegister()->RegisterNextWire(w);
  }

  received_public_values_.resize(GetConfig()->GetNumOfParties());
  received_public_keys_.resize(GetConfig()->GetNumOfParties());

  assert(gate_id_ >= 0);
  const auto my_id{GetConfig()->GetMyId()};

  for (auto i = 0ull; i < GetConfig()->GetNumOfParties(); ++i) {
    if (my_id == i) continue;
    auto &data_storage =
        GetConfig()->GetCommunicationContext(static_cast<std::size_t>(i))->GetDataStorage();
    auto &bmr_data = data_storage->GetBMRData();

    auto [it_pub_vals, _] = bmr_data->input_public_values_.emplace(
        static_cast<std::size_t>(gate_id_),
        std::pair<std::size_t, std::promise<std::unique_ptr<ENCRYPTO::BitVector<>>>>());
    auto &bitlen_pub_values{std::get<0>(it_pub_vals->second)};
    bitlen_pub_values = num_simd * output_wires_.size();

    auto [it_pub_keys, __] = bmr_data->input_public_keys_.emplace(
        gate_id_, std::pair<std::size_t, std::promise<std::unique_ptr<ENCRYPTO::BitVector<>>>>());
    auto &bitlen_pub_keys = std::get<0>(it_pub_keys->second);
    bitlen_pub_keys = bitlen_pub_values * kappa;
  }

  if constexpr (MOTION_DEBUG) {
    auto gate_info = fmt::format("gate id {}, parent wires: ", gate_id_);
    for (const auto &wire : parent_) gate_info.append(fmt::format("{} ", wire->GetWireId()));
    gate_info.append(" output wires: ");
    for (const auto &wire : output_wires_) gate_info.append(fmt::format("{} ", wire->GetWireId()));
    GetLogger()->LogDebug(fmt::format(
        "Created a Boolean GMW to BMR conversion gate with following properties: {}", gate_info));
  }
}

void GMWToBMRGate::EvaluateSetup() {
  if constexpr (MOTION_DEBUG) {
    GetLogger()->LogDebug(fmt::format(
        "Start evaluating setup phase of Boolean GMW to BMR Gate with id#{}", gate_id_));
  }

  const auto my_id{GetConfig()->GetMyId()};
  const auto num_parties{GetConfig()->GetNumOfParties()};

  for (auto party_id = 0ull; party_id < num_parties; ++party_id) {
    if (party_id == my_id) continue;
    const auto &bmr_data{
        GetConfig()->GetCommunicationContext(party_id)->GetDataStorage()->GetBMRData()};

    received_public_values_.at(party_id) =
        bmr_data->input_public_values_.at(static_cast<std::size_t>(gate_id_)).second.get_future();
    received_public_keys_.at(party_id) =
        bmr_data->input_public_keys_.at(static_cast<std::size_t>(gate_id_)).second.get_future();
  }

  for (auto wire_i = 0ull; wire_i < output_wires_.size(); ++wire_i) {
    auto bmr_out = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(wire_i));
    assert(bmr_out);
    bmr_out->GenerateRandomPrivateKeys();
    bmr_out->GenerateRandomPermutationBits();
    bmr_out->SetSetupIsReady();
  }
  SetSetupIsReady();
  if constexpr (MOTION_DEBUG) {
    GetLogger()->LogDebug(fmt::format(
        "Finished evaluating setup phase of Boolean GMW to BMR Gate with id#{}", gate_id_));
  }
}

void GMWToBMRGate::EvaluateOnline() {
  WaitSetup();
  if constexpr (MOTION_DEBUG) {
    GetLogger()->LogDebug(fmt::format(
        "Start evaluating online phase of Boolean GMW to BMR Gate with id#{}", gate_id_));
  }

  auto ptr_backend = backend_.lock();
  assert(ptr_backend);

  const auto num_simd{output_wires_.at(0)->GetNumOfSIMDValues()};
  const auto my_id{GetConfig()->GetMyId()};
  const auto num_parties{GetConfig()->GetNumOfParties()};
  ENCRYPTO::BitVector<> buffer;

  // mask and publish inputs
  for (auto i = 0ull; i < output_wires_.size(); ++i) {
    auto gmw_in = std::dynamic_pointer_cast<Wires::GMWWire>(parent_.at(i));
    assert(gmw_in);
    auto bmr_out = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(i));
    assert(bmr_out);
    bmr_out->GetMutablePublicValues() = gmw_in->GetValues() ^ bmr_out->GetPermutationBits();
    buffer.Append(bmr_out->GetPublicValues());
  }
  const std::vector<std::uint8_t> payload_pub_vals(
      reinterpret_cast<const std::uint8_t *>(buffer.GetData().data()),
      reinterpret_cast<const std::uint8_t *>(buffer.GetData().data()) + buffer.GetData().size());
  for (auto i = 0ull; i < num_parties; ++i) {
    if (i == GetConfig()->GetMyId()) continue;
    ptr_backend->Send(i, Communication::BuildBMRInput0Message(gate_id_, payload_pub_vals));
  }

  // receive masked values if not my input
  for (auto party_id = 0ull; party_id < num_parties; ++party_id) {
    if (party_id == my_id) continue;
    buffer = std::move(*received_public_values_.at(party_id).get());
    for (auto i = 0ull; i < output_wires_.size(); ++i) {
      auto bmr_out = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(i));
      assert(bmr_out);
      bmr_out->GetMutablePublicValues() ^= buffer.Subset(i * num_simd, (i + 1) * num_simd);
    }
  }

  buffer.Clear();
  // rearrange keys corresponding to the public values into one buffer
  for (auto i = 0ull; i < output_wires_.size(); ++i) {
    auto wire = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(i));
    const auto &keys = wire->GetSecretKeys();
    const auto &keys_0 = std::get<0>(keys);
    const auto &keys_1 = std::get<1>(keys);
    for (auto j = 0ull; j < num_simd; ++j) {
      if (wire->GetPublicValues()[j])
        buffer.Append(keys_1.at(j));
      else
        buffer.Append(keys_0.at(j));
    }
  }

  // publish keys
  const std::vector<std::uint8_t> payload_pub_keys(
      reinterpret_cast<const std::uint8_t *>(buffer.GetData().data()),
      reinterpret_cast<const std::uint8_t *>(buffer.GetData().data()) + buffer.GetData().size());
  for (auto i = 0ull; i < num_parties; ++i) {
    if (i == GetConfig()->GetMyId()) continue;
    ptr_backend->Send(i, Communication::BuildBMRInput1Message(gate_id_, payload_pub_keys));
  }

  // parse published keys
  for (auto i = 0ull; i < num_parties; ++i) {
    if (i == GetConfig()->GetMyId()) {
      for (auto j = 0ull; j < output_wires_.size(); ++j) {
        auto wire = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(j));
        assert(wire);
        for (auto k = 0ull; k < num_simd; ++k) {
          if (wire->GetPublicValues()[k])
            wire->GetMutablePublicKeys().at(i).at(k) = std::get<1>(wire->GetSecretKeys()).at(k);
          else
            wire->GetMutablePublicKeys().at(i).at(k) = std::get<0>(wire->GetSecretKeys()).at(k);
        }
      }
    } else {
      buffer = std::move(*received_public_keys_.at(i).get());
      assert(num_simd > 0u);
      for (auto j = 0ull; j < output_wires_.size(); ++j) {
        auto wire = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(j));
        assert(wire);
        for (auto k = 0ull; k < num_simd; ++k) {
          wire->GetMutablePublicKeys().at(i).at(k) =
              buffer.Subset((j * num_simd + k) * kappa, (j * num_simd + k + 1) * kappa);
        }
      }
    }
  }

  GetRegister()->IncrementEvaluatedGatesCounter();
  SetOnlineIsReady();

  if constexpr (MOTION_DEBUG) {
    GetLogger()->LogDebug(fmt::format(
        "Finished evaluating online phase of Boolean GMW to BMR Gate with id#{}", gate_id_));
  }
}

const Shares::BMRSharePtr GMWToBMRGate::GetOutputAsBMRShare() const {
  auto result = std::make_shared<Shares::BMRShare>(output_wires_);
  assert(result);
  return result;
}

const Shares::SharePtr GMWToBMRGate::GetOutputAsShare() const {
  auto result = std::static_pointer_cast<Shares::Share>(GetOutputAsBMRShare());
  assert(result);
  return result;
}

}