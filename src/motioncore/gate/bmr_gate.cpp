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

#include "bmr_gate.h"

#include "base/backend.h"
#include "communication/bmr_message.h"
#include "crypto/oblivious_transfer/correlated_ot.h"
#include "crypto/oblivious_transfer/ot_provider.h"
#include "crypto/pseudo_random_generator.h"
#include "data_storage/bmr_data.h"
#include "data_storage/data_storage.h"
#include "utility/block.h"
#include "wire/bmr_wire.h"
#include "wire/boolean_gmw_wire.h"

namespace MOTION::Gates::BMR {

BMRInputGate::BMRInputGate(const std::vector<ENCRYPTO::BitVector<>> &input,
                           std::size_t input_owner_id, Backend &backend)
    : InputGate(backend), input_(input) {
  assert(!input_.empty());
  input_owner_id_ = input_owner_id;
  bits_ = input_.size() == 0 ? 0 : input_.at(0).GetSize();
  InitializationHelper();
}

BMRInputGate::BMRInputGate(std::vector<ENCRYPTO::BitVector<>> &&input, std::size_t input_owner_id,
                           Backend &backend)
    : InputGate(backend), input_(std::move(input)) {
  assert(!input_.empty());
  input_owner_id_ = input_owner_id;
  bits_ = input_.size() == 0 ? 0 : input_.at(0).GetSize();
  InitializationHelper();
}

void BMRInputGate::InitializationHelper() {
  if (static_cast<std::size_t>(input_owner_id_) >= GetConfig().GetNumOfParties()) {
    throw std::runtime_error(fmt::format("Invalid input owner: {} of {}", input_owner_id_,
                                         GetConfig().GetNumOfParties()));
  }

  gate_id_ = GetRegister().NextGateId();

  assert(input_.size() > 0u);           // assert >=1 wire
  assert(input_.at(0).GetSize() > 0u);  // assert >=1 SIMD bits
  // assert SIMD lengths of all wires are equal
  assert(ENCRYPTO::BitVector<>::EqualSizeDimensions(input_));

  output_wires_.reserve(input_.size());
  for (auto &v : input_)
    output_wires_.push_back(std::make_shared<Wires::BMRWire>(v.GetSize(), backend_));

  for (auto &w : output_wires_) GetRegister().RegisterNextWire(w);

  received_public_keys_.resize(GetConfig().GetNumOfParties());

  assert(input_owner_id_ >= 0);
  assert(gate_id_ >= 0);
  const auto my_id = GetConfig().GetMyId();

  // if this is someone else's input, prepare for receiving the *public values*
  // (if it is our's then we would compute it ourselves)
  if (my_id != static_cast<std::size_t>(input_owner_id_)) {
    auto &bmr_data = GetConfig()
                         .GetCommunicationContext(static_cast<std::size_t>(input_owner_id_))
                         ->GetDataStorage()
                         ->GetBMRData();
    received_public_values_ =
        bmr_data->RegisterForInputPublicValues(gate_id_, bits_ * input_.size());
  }

  // prepare for receiving the *public/active keys* of the other parties
  for (auto party_i = 0ull; party_i < GetConfig().GetNumOfParties(); ++party_i) {
    if (my_id == party_i) continue;
    auto &bmr_data = GetConfig().GetCommunicationContext(party_i)->GetDataStorage()->GetBMRData();
    received_public_keys_.at(party_i) =
        bmr_data->RegisterForInputPublicKeys(gate_id_, bits_ * input_.size() * kappa);
  }

  if constexpr (MOTION_DEBUG) {
    auto gate_info = fmt::format("gate id {}, input owner {}", gate_id_, input_owner_id_);
    GetLogger().LogDebug(
        fmt::format("Created a BMRInputGate with following properties: {}", gate_info));
  }
}

void BMRInputGate::EvaluateSetup() {
  auto &config = GetConfig();
  const auto my_id = config.GetMyId();

  // create keys etc. for all the wires
  for (auto i = 0ull; i < output_wires_.size(); ++i) {
    auto wire = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(i));
    assert(wire);
    // generate 2 keys for each bit
    wire->GenerateRandomPrivateKeys();

    // if this is our input, then only we generate a random permutation bit for each bit
    if (static_cast<std::size_t>(input_owner_id_) == my_id) {
      wire->GenerateRandomPermutationBits();
    }
    // otherwise we the permutation bits to 0 (this saves some communication)
    else {
      // create a bit vector of zeros
      wire->GetMutablePermutationBits() = ENCRYPTO::BitVector<>(wire->GetNumOfSIMDValues());
    }
    wire->SetSetupIsReady();

    if constexpr (MOTION_VERBOSE_DEBUG) {
      const auto &R = GetConfig().GetBMRRandomOffset();
      std::string keys_0, keys_1;
      for (const auto &key : wire->GetSecretKeys()) {
        assert(key.size() == kappa / 8);
        keys_0.append(key.as_string() + " ");
      }
      if (!keys_0.empty()) keys_0.erase(keys_0.size() - 1);
      for (const auto &key : wire->GetSecretKeys()) {
        assert(key.size() == kappa / 8);
        keys_1.append((key ^ R).as_string() + " ");
      }
      if (!keys_1.empty()) keys_1.erase(keys_1.size() - 1);

      GetLogger().LogTrace(
          fmt::format("Created a BMR wire #{} with real values {} permutation bits {}, keys 0 {}, "
                      "and keys 1 {}",
                      wire->GetWireId(), input_.at(i).AsString(),
                      wire->GetPermutationBits().AsString(), keys_0, keys_1));
    }
  }
  SetSetupIsReady();
  GetRegister().IncrementEvaluatedGateSetupsCounter();
}

void BMRInputGate::EvaluateOnline() {
  WaitSetup();

  const auto &R = GetConfig().GetBMRRandomOffset();
  const auto my_id = GetConfig().GetMyId();
  const auto num_parties = GetConfig().GetNumOfParties();
  const auto num_simd = output_wires_.at(0)->GetNumOfSIMDValues();
  const auto num_wires = output_wires_.size();
  const bool my_input = static_cast<std::size_t>(input_owner_id_) == my_id;
  ENCRYPTO::BitVector<> buffer;
  // XXX: ^ maybe we can already reserve enough space here since we call append
  // in a loop

  // if this is our input, set the public values by masking our real inputs
  // with the random permutation bits
  if (my_input) {
    for (auto i = 0ull; i < output_wires_.size(); ++i) {
      auto wire = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(i));
      assert(wire);
      wire->GetMutablePublicValues() = input_.at(i) ^ wire->GetPermutationBits();
      buffer.Append(wire->GetPublicValues());
    }
    const std::vector<std::uint8_t> payload(
        reinterpret_cast<const std::uint8_t *>(buffer.GetData().data()),
        reinterpret_cast<const std::uint8_t *>(buffer.GetData().data()) + buffer.GetData().size());
    for (auto i = 0ull; i < GetConfig().GetNumOfParties(); ++i) {
      if (i == GetConfig().GetMyId()) continue;
      backend_.Send(i, Communication::BuildBMRInput0Message(gate_id_, payload));
    }
  }
  // otherwise receive the public values from the party that provides the input
  else {
    buffer = received_public_values_.get();
    for (auto i = 0ull; i < output_wires_.size(); ++i) {
      auto wire = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(i));
      assert(wire);
      wire->GetMutablePublicValues() = buffer.Subset(i * bits_, (i + 1) * bits_);
    }
  }

  // the public values are now set for each bit
  // now we need to publish the corresponding keys

  buffer.Clear();
  // XXX: ^ maybe we can already reserve enough space here since we call append
  // in a loop

  // fill the buffer with the keys corresponding to the public values
  for (auto i = 0ull; i < num_wires; ++i) {
    auto wire = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(i));
    assert(wire);
    const auto &keys_0 = wire->GetSecretKeys();
    for (auto j = 0ull; j < wire->GetNumOfSIMDValues(); ++j) {
      if (wire->GetPublicValues()[j])
        buffer.Append(ENCRYPTO::BitVector<>((keys_0.at(j) ^ R).data(), kappa));
      else
        buffer.Append(ENCRYPTO::BitVector<>(keys_0.at(j).data(), kappa));
    }
  }

  // send the selected keys to all other parties
  const std::vector<std::uint8_t> payload(
      reinterpret_cast<const std::uint8_t *>(buffer.GetData().data()),
      reinterpret_cast<const std::uint8_t *>(buffer.GetData().data()) + buffer.GetData().size());
  for (auto party_i = 0ull; party_i < GetConfig().GetNumOfParties(); ++party_i) {
    if (party_i == my_id) continue;
    backend_.Send(party_i, Communication::BuildBMRInput1Message(gate_id_, payload));
  }

  auto pk_index = [num_parties](auto simd_i, auto party_i) {
    return simd_i * num_parties + party_i;
  };

  // receive the published keys from the other parties
  for (auto party_i = 0ull; party_i < num_parties; ++party_i) {
    if (party_i == my_id) {
      // XXX: we could move the correct secret key into the vector of public keys
      // since we should not need it anymore
      for (auto wire_j = 0ull; wire_j < num_wires; ++wire_j) {
        auto wire = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(wire_j));
        assert(wire);
        for (auto simd_k = 0ull; simd_k < num_simd; ++simd_k) {
          if (wire->GetPublicValues()[simd_k])
            wire->GetMutablePublicKeys().at(pk_index(simd_k, party_i)) =
                wire->GetSecretKeys().at(simd_k) ^ R;
          else
            wire->GetMutablePublicKeys().at(pk_index(simd_k, party_i)) =
                wire->GetSecretKeys().at(simd_k);
        }
      }
    } else {
      buffer = received_public_keys_.at(party_i).get();
      assert(bits_ > 0u);
      for (auto wire_j = 0ull; wire_j < num_wires; ++wire_j) {
        auto wire = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(wire_j));
        assert(wire);
        for (auto simd_k = 0ull; simd_k < num_simd; ++simd_k) {
          wire->GetMutablePublicKeys().at(pk_index(simd_k, party_i)) =
              ENCRYPTO::block128_t::make_from_memory(
                  buffer
                      .Subset((wire_j * bits_ + simd_k) * kappa,
                              (wire_j * bits_ + simd_k + 1) * kappa)
                      .GetData()
                      .data());
        }
      }
    }
  }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    std::string s(fmt::format("Evaluated a BMR input gate #{} and got as result: ", gate_id_));
    for (auto wire_i = 0ull; wire_i < num_wires; ++wire_i) {
      auto wire = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(wire_i));
      const auto &pks = wire->GetPublicKeys();
      std::string keys;
      for (auto party_j = 0ull; party_j < num_parties; ++party_j) {
        keys.append(std::to_string(party_j) + std::string(" "));
        for (auto simd_k = 0ull; simd_k < num_simd; ++simd_k) {
          keys.append(pks.at(pk_index(simd_k, party_j)).as_string() + " ");
        }
      }
      if (!keys.empty()) keys.erase(keys.size() - 1);
      s.append(fmt::format("wire #{} with public bits {} and public keys {}\n", wire->GetWireId(),
                           wire->GetPublicValues().AsString(), keys));
    }
    GetLogger().LogTrace(s);
  }
  SetOnlineIsReady();
  GetRegister().IncrementEvaluatedGatesCounter();
}

const Shares::BMRSharePtr BMRInputGate::GetOutputAsBMRShare() const {
  auto result = std::make_shared<Shares::BMRShare>(output_wires_);
  assert(result);
  return result;
}

const Shares::SharePtr BMRInputGate::GetOutputAsShare() const {
  auto result = std::static_pointer_cast<Shares::Share>(GetOutputAsBMRShare());
  assert(result);
  return result;
}

BMROutputGate::BMROutputGate(const Shares::SharePtr &parent, std::size_t output_owner)
    : OutputGate(parent->GetBackend()) {
  if (parent->GetWires().at(0)->GetProtocol() != MPCProtocol::BMR) {
    auto sharing_type = Helpers::Print::ToString(parent->GetWires().at(0)->GetProtocol());
    throw std::runtime_error(
        fmt::format("BMR output gate expects a BMR share, "
                    "got a share of type {}",
                    sharing_type));
  }

  if (parent->GetWires().size() == 0) {
    throw std::runtime_error("Trying to construct an output gate with no wires");
  }

  parent_ = parent->GetWires();

  output_owner_ = output_owner;
  output_.resize(parent_.size());
  requires_online_interaction_ = true;
  gate_type_ = GateType::InteractiveGate;

  if (output_owner >= GetConfig().GetNumOfParties() && output_owner != ALL) {
    throw std::runtime_error(
        fmt::format("Invalid output owner: {} of {}", output_owner, GetConfig().GetNumOfParties()));
  }

  // For BMR reconstruction, we need to recontruct the shared permutation bits
  // and xor them to the public values in order to get the real values.  Since
  // the permutation bits are shared in the same way as usual Boolean GMW
  // shares, we use a GMWOutputGate to perform the reconstruction.

  std::vector<Wires::WirePtr> dummy_wires(parent_.size());
  const ENCRYPTO::BitVector<> dummy_bv(parent_.at(0)->GetNumOfSIMDValues());

  for (auto &w : dummy_wires) {
    w = std::make_shared<Wires::GMWWire>(dummy_bv, backend_);
    GetRegister().RegisterNextWire(w);
  }

  gmw_out_share_ = std::make_shared<Shares::GMWShare>(dummy_wires);
  out_ = std::make_shared<MOTION::Gates::GMW::GMWOutputGate>(gmw_out_share_);
  GetRegister().RegisterNextGate(out_);

  gate_id_ = GetRegister().NextGateId();

  for (auto &wire : parent_) {
    RegisterWaitingFor(wire->GetWireId());  // mark this gate as waiting for @param wire
    wire->RegisterWaitingGate(gate_id_);    // register this gate in @param wire as waiting
  }

  const auto my_id = GetConfig().GetMyId();
  is_my_output_ = static_cast<std::size_t>(output_owner_) == my_id ||
                  static_cast<std::size_t>(output_owner_) == ALL;

  for (auto &bv : output_) {
    output_wires_.push_back(std::static_pointer_cast<MOTION::Wires::Wire>(
        std::make_shared<Wires::BMRWire>(bv, backend_)));
  }

  for (auto &wire : output_wires_) {
    GetRegister().RegisterNextWire(wire);
  }

  if constexpr (MOTION_DEBUG) {
    auto gate_info =
        fmt::format("bitlength {}, gate id {}, owner {}", output_.size(), gate_id_, output_owner_);
    GetLogger().LogDebug(
        fmt::format("Created a BMR OutputGate with following properties: {}", gate_info));
  }
}

void BMROutputGate::EvaluateSetup() {
  SetSetupIsReady();
  GetRegister().IncrementEvaluatedGateSetupsCounter();
}

void BMROutputGate::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);

  std::size_t i;

  if constexpr (MOTION_DEBUG) {
    GetLogger().LogDebug(
        fmt::format("Starting online phase evaluation for BMR OutputGate with id#{}", gate_id_));
  }

  auto &wires = gmw_out_share_->GetMutableWires();
  for (i = 0; i < wires.size(); ++i) {
    const auto bmr_wire = std::dynamic_pointer_cast<const Wires::BMRWire>(parent_.at(i));
    bmr_wire->GetIsReadyCondition()->Wait();
    auto gmw_wire = std::dynamic_pointer_cast<Wires::GMWWire>(wires.at(i));
    assert(bmr_wire);
    assert(gmw_wire);
    // take the permutation bits from the BMRWire and use them as GMW shares
    gmw_wire->GetMutableValues() = bmr_wire->GetPermutationBits();
    gmw_wire->SetOnlineFinished();
  }

  for (i = 0; i < output_wires_.size(); ++i) {
    const auto bmr_wire = std::dynamic_pointer_cast<const Wires::BMRWire>(parent_.at(i));
    auto gmw_wire = std::dynamic_pointer_cast<Wires::GMWWire>(out_->GetOutputWires().at(i));
    // wait until the GMWOutputGate is evaluated
    gmw_wire->GetIsReadyCondition()->Wait();
    assert(bmr_wire);
    assert(gmw_wire);
    assert(bmr_wire->GetPublicValues().GetSize() == gmw_wire->GetValues().GetSize());
    // compute the real values as XOR of the public values from the BMRWire
    // with the reconstructed permutation bits from the GMWWire
    output_.at(i) = bmr_wire->GetPublicValues() ^ gmw_wire->GetValues();
    auto wire = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(i));
    assert(wire);
    wire->GetMutablePublicValues() = output_.at(i);
  }

  if constexpr (MOTION_DEBUG) {
    GetLogger().LogDebug(
        fmt::format("Evaluated online phase of BMR OutputGate with id#{}", gate_id_));
  }

  SetOnlineIsReady();
  GetRegister().IncrementEvaluatedGatesCounter();
}

const Shares::BMRSharePtr BMROutputGate::GetOutputAsBMRShare() const {
  auto result = std::make_shared<Shares::BMRShare>(output_wires_);
  assert(result);
  return result;
}

const Shares::SharePtr BMROutputGate::GetOutputAsShare() const {
  auto result = std::static_pointer_cast<Shares::Share>(GetOutputAsBMRShare());
  assert(result);
  return result;
}

BMRXORGate::BMRXORGate(const Shares::SharePtr &a, const Shares::SharePtr &b)
    : TwoGate(a->GetBackend()) {
  parent_a_ = a->GetWires();
  parent_b_ = b->GetWires();

  assert(parent_a_.size() > 0);
  assert(parent_a_.size() == parent_b_.size());
  assert(parent_a_.at(0)->GetBitLength() > 0);
  assert(parent_a_.at(0)->GetProtocol() == parent_b_.at(0)->GetProtocol());
  assert(parent_a_.at(0)->GetProtocol() == MPCProtocol::BMR);

  requires_online_interaction_ = false;
  gate_type_ = GateType::NonInteractiveGate;

  gate_id_ = GetRegister().NextGateId();

  for (auto &wire : parent_a_) {
    RegisterWaitingFor(wire->GetWireId());
    wire->RegisterWaitingGate(gate_id_);
  }

  for (auto &wire : parent_b_) {
    RegisterWaitingFor(wire->GetWireId());
    wire->RegisterWaitingGate(gate_id_);
  }

  output_wires_.resize(parent_a_.size());
  const ENCRYPTO::BitVector tmp_bv(a->GetNumOfSIMDValues());
  for (auto &w : output_wires_) {
    w = std::make_shared<Wires::BMRWire>(tmp_bv, backend_);
    GetRegister().RegisterNextWire(w);
  }

  if constexpr (MOTION_DEBUG) {
    auto gate_info = fmt::format("gate id {}, parents: {}, {}", gate_id_,
                                 parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    GetLogger().LogDebug(
        fmt::format("Created a BMR XOR gate with following properties: {}", gate_info));
  }
}

void BMRXORGate::EvaluateSetup() {
  if constexpr (MOTION_DEBUG) {
    GetLogger().LogDebug(
        fmt::format("Start evaluating setup phase of BMR XOR Gate with id#{}", gate_id_));
  }

  for (auto i = 0ull; i < output_wires_.size(); ++i) {
    auto bmr_out = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(i));
    const auto bmr_a = std::dynamic_pointer_cast<const Wires::BMRWire>(parent_a_.at(i));
    const auto bmr_b = std::dynamic_pointer_cast<const Wires::BMRWire>(parent_b_.at(i));
    assert(bmr_out);
    assert(bmr_a);
    assert(bmr_b);
    bmr_a->GetSetupReadyCondition()->Wait();
    bmr_b->GetSetupReadyCondition()->Wait();

    // use freeXOR garbling
    bmr_out->GetMutablePermutationBits() =
        bmr_a->GetPermutationBits() ^ bmr_b->GetPermutationBits();
    bmr_out->GetMutableSecretKeys() = bmr_a->GetSecretKeys() ^ bmr_b->GetSecretKeys();
    bmr_out->SetSetupIsReady();
  }
  if constexpr (MOTION_DEBUG) {
    GetLogger().LogDebug(
        fmt::format("Finished evaluating setup phase of BMR XOR Gate with id#{}", gate_id_));
  }
  SetSetupIsReady();
  GetRegister().IncrementEvaluatedGateSetupsCounter();
}

void BMRXORGate::EvaluateOnline() {
  WaitSetup();
  if constexpr (MOTION_DEBUG) {
    GetLogger().LogDebug(
        fmt::format("Start evaluating online phase of BMR XOR Gate with id#{}", gate_id_));
  }

  for (auto i = 0ull; i < parent_a_.size(); ++i) {
    const auto wire_a = std::dynamic_pointer_cast<const Wires::BMRWire>(parent_a_.at(i));
    const auto wire_b = std::dynamic_pointer_cast<const Wires::BMRWire>(parent_b_.at(i));
    assert(wire_a);
    assert(wire_b);

    auto bmr_out = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(i));
    assert(bmr_out);

    wire_a->GetIsReadyCondition()->Wait();
    wire_b->GetIsReadyCondition()->Wait();

    // perform freeXOR evaluation
    bmr_out->GetMutablePublicKeys() = wire_a->GetPublicKeys() ^ wire_b->GetPublicKeys();
    bmr_out->GetMutablePublicValues() = wire_a->GetPublicValues() ^ wire_b->GetPublicValues();
  }

  if constexpr (MOTION_DEBUG) {
    GetLogger().LogDebug(
        fmt::format("Finished evaluating online phase of BMR XOR Gate with id#{}", gate_id_));
  }
  SetOnlineIsReady();
  GetRegister().IncrementEvaluatedGatesCounter();
}

const Shares::BMRSharePtr BMRXORGate::GetOutputAsBMRShare() const {
  auto result = std::make_shared<Shares::BMRShare>(output_wires_);
  assert(result);
  return result;
}

const Shares::SharePtr BMRXORGate::GetOutputAsShare() const {
  auto result = std::static_pointer_cast<Shares::Share>(GetOutputAsBMRShare());
  assert(result);
  return result;
}

BMRINVGate::BMRINVGate(const Shares::SharePtr &parent) : OneGate(parent->GetBackend()) {
  parent_ = parent->GetWires();

  assert(parent_.size() > 0);
  assert(parent_.at(0)->GetBitLength() > 0);
  for ([[maybe_unused]] const auto &wire : parent_) assert(wire->GetProtocol() == MPCProtocol::BMR);

  requires_online_interaction_ = false;
  gate_type_ = GateType::NonInteractiveGate;

  gate_id_ = GetRegister().NextGateId();

  for (auto &wire : parent_) {
    RegisterWaitingFor(wire->GetWireId());
    wire->RegisterWaitingGate(gate_id_);
  }

  output_wires_.resize(parent_.size());
  const ENCRYPTO::BitVector tmp_bv(parent->GetNumOfSIMDValues());
  for (auto &w : output_wires_) {
    w = std::make_shared<Wires::BMRWire>(tmp_bv, backend_);
    GetRegister().RegisterNextWire(w);
  }

  if constexpr (MOTION_DEBUG) {
    auto gate_info = fmt::format("gate id {}, parent wires: ", gate_id_);
    for (const auto &wire : parent_) gate_info.append(fmt::format("{} ", wire->GetWireId()));
    gate_info.append(" output wires: ");
    for (const auto &wire : output_wires_) gate_info.append(fmt::format("{} ", wire->GetWireId()));
    GetLogger().LogDebug(
        fmt::format("Created a BMR INV gate with following properties: {}", gate_info));
  }
}

void BMRINVGate::EvaluateSetup() {
  if constexpr (MOTION_DEBUG) {
    GetLogger().LogDebug(
        fmt::format("Start evaluating setup phase of BMR INV Gate with id#{}", gate_id_));
  }

  const auto my_id{GetConfig().GetMyId()};
  const auto num_parties{GetConfig().GetNumOfParties()};

  for (auto i = 0ull; i < output_wires_.size(); ++i) {
    auto bmr_out = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(i));
    const auto bmr_in = std::dynamic_pointer_cast<const Wires::BMRWire>(parent_.at(i));
    assert(bmr_out);
    assert(bmr_in);
    bmr_in->GetSetupReadyCondition()->Wait();

    bmr_out->GetMutablePermutationBits() = bmr_in->GetPermutationBits();

    // one party needs to invert its permutation bits
    // distribute this work among the parties
    if (bmr_out->GetWireId() % num_parties == my_id) bmr_out->GetMutablePermutationBits().Invert();

    // copy the secret keys to the new wire
    bmr_out->GetMutableSecretKeys() = bmr_in->GetSecretKeys();

    bmr_out->SetSetupIsReady();
  }
  if constexpr (MOTION_DEBUG) {
    GetLogger().LogDebug(
        fmt::format("Finished evaluating setup phase of BMR INV Gate with id#{}", gate_id_));
  }
  SetSetupIsReady();
  GetRegister().IncrementEvaluatedGateSetupsCounter();
}

void BMRINVGate::EvaluateOnline() {
  WaitSetup();
  if constexpr (MOTION_DEBUG) {
    GetLogger().LogDebug(
        fmt::format("Start evaluating online phase of BMR INV Gate with id#{}", gate_id_));
  }

  for (auto i = 0ull; i < parent_.size(); ++i) {
    const auto bmr_in = std::dynamic_pointer_cast<const Wires::BMRWire>(parent_.at(i));
    assert(bmr_in);

    auto bmr_out = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(i));
    assert(bmr_out);

    bmr_in->GetIsReadyCondition()->Wait();

    // just copy the public values and keys from the parent wire
    bmr_out->GetMutablePublicKeys() = bmr_in->GetPublicKeys();
    bmr_out->GetMutablePublicValues() = bmr_in->GetPublicValues();
  }

  if constexpr (MOTION_DEBUG) {
    GetLogger().LogDebug(
        fmt::format("Finished evaluating online phase of BMR INV Gate with id#{}", gate_id_));
  }
  SetOnlineIsReady();
  GetRegister().IncrementEvaluatedGatesCounter();
}

const Shares::BMRSharePtr BMRINVGate::GetOutputAsBMRShare() const {
  auto result = std::make_shared<Shares::BMRShare>(output_wires_);
  assert(result);
  return result;
}

const Shares::SharePtr BMRINVGate::GetOutputAsShare() const {
  auto result = std::static_pointer_cast<Shares::Share>(GetOutputAsBMRShare());
  assert(result);
  return result;
}

BMRANDGate::BMRANDGate(const Shares::SharePtr &a, const Shares::SharePtr &b)
    : TwoGate(a->GetBackend()) {
  parent_a_ = a->GetWires();
  parent_b_ = b->GetWires();

  assert(parent_a_.size() > 0);
  assert(parent_a_.size() == parent_b_.size());
  assert(parent_a_.at(0)->GetBitLength() > 0);
  assert(parent_a_.at(0)->GetProtocol() == parent_b_.at(0)->GetProtocol());
  assert(parent_a_.at(0)->GetProtocol() == MPCProtocol::BMR);

  requires_online_interaction_ = true;
  gate_type_ = GateType::InteractiveGate;

  gate_id_ = GetRegister().NextGateId();

  const auto num_simd{parent_a_.at(0)->GetNumOfSIMDValues()};
  const auto num_wires{parent_a_.size()};
  const auto batch_size_full{num_simd * 4};
  const auto batch_size_3{num_simd * 3};
  const auto my_id{GetConfig().GetMyId()};
  const auto num_parties{GetConfig().GetNumOfParties()};

  for (auto &wire : parent_a_) {
    RegisterWaitingFor(wire->GetWireId());
    wire->RegisterWaitingGate(gate_id_);
  }

  for (auto &wire : parent_b_) {
    RegisterWaitingFor(wire->GetWireId());
    wire->RegisterWaitingGate(gate_id_);
  }

  output_wires_.resize(num_wires);
  const ENCRYPTO::BitVector tmp_bv(num_simd);
  for (auto &w : output_wires_) {
    w = std::make_shared<Wires::BMRWire>(tmp_bv, backend_);
    GetRegister().RegisterNextWire(w);
  }

  s_ots_1_.resize(num_parties);
  for (auto &v : s_ots_1_) v.resize(num_wires);
  s_ots_kappa_.resize(num_parties);
  for (auto &v : s_ots_kappa_) v.resize(num_wires);
  r_ots_1_.resize(num_parties);
  for (auto &v : r_ots_1_) v.resize(num_wires);
  r_ots_kappa_.resize(num_parties);
  for (auto &v : r_ots_kappa_) v.resize(num_wires);
  for (auto wire_i = 0ull; wire_i < num_wires; ++wire_i) {
    for (auto pid = 0ull; pid < num_parties; ++pid) {
      if (pid == my_id) continue;
      s_ots_1_.at(pid).at(wire_i) = GetOTProvider(pid).RegisterSendXCOTBit(batch_size_3);
      s_ots_kappa_.at(pid).at(wire_i) = GetOTProvider(pid).RegisterSendFixedXCOT128(batch_size_3);
      r_ots_1_.at(pid).at(wire_i) = GetOTProvider(pid).RegisterReceiveXCOTBit(batch_size_3);
      r_ots_kappa_.at(pid).at(wire_i) =
          GetOTProvider(pid).RegisterReceiveFixedXCOT128(batch_size_3);
    }
  }

  garbled_rows_.resize(num_parties);
  for (auto &vv : garbled_rows_) {
    vv.resize(num_wires);
    for (auto &v : vv) {
      v.resize(batch_size_full);
    }
  }

  // store futures for the (partial) garbled tables we will receive during garbling
  received_garbled_rows_.resize(num_parties);
  for (auto party_id = 0ull; party_id < num_parties; ++party_id) {
    if (party_id == my_id) continue;
    auto &bmr_data = GetConfig().GetCommunicationContext(party_id)->GetDataStorage()->GetBMRData();
    received_garbled_rows_.at(party_id) =
        bmr_data->RegisterForGarbledRows(gate_id_, num_wires * batch_size_full * num_parties);
  }

  if constexpr (MOTION_DEBUG) {
    auto gate_info = fmt::format("gate id {}, parents: {}, {}", gate_id_,
                                 parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    GetLogger().LogDebug(
        fmt::format("Created a BMR AND gate with following properties: {}", gate_info));
  }
}

void BMRANDGate::GenerateRandomness() {
  const auto num_wires{output_wires_.size()};
  for (auto wire_i = 0ull; wire_i < num_wires; ++wire_i) {
    auto bmr_out{std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(wire_i))};
    assert(bmr_out);
    bmr_out->GenerateRandomPermutationBits();
    bmr_out->GenerateRandomPrivateKeys();
    if constexpr (MOTION_VERBOSE_DEBUG) {
      const auto my_id{GetConfig().GetMyId()};
      const auto num_simd{parent_a_.at(0)->GetNumOfSIMDValues()};
      for (auto simd_i = 0ull; simd_i < num_simd; ++simd_i) {
        const auto &key_0{bmr_out->GetSecretKeys().at(simd_i)};
        const auto &key_1{key_0 ^ GetConfig().GetBMRRandomOffset()};

        const auto bmr_a = std::dynamic_pointer_cast<const Wires::BMRWire>(parent_a_.at(wire_i));
        const auto bmr_b = std::dynamic_pointer_cast<const Wires::BMRWire>(parent_b_.at(wire_i));
        assert(bmr_a);
        assert(bmr_b);
        bmr_a->GetSetupReadyCondition()->Wait();
        bmr_b->GetSetupReadyCondition()->Wait();
        GetLogger().LogTrace(fmt::format(
            "Gate#{} (BMR AND gate) Party#{} wire_i {} simd_i {} perm_bits (a {} b {} out {}) key0 "
            "{} key 1 {}\n",
            gate_id_, my_id, wire_i, simd_i, bmr_a->GetPermutationBits().AsString(),
            bmr_b->GetPermutationBits().AsString(), bmr_out->GetPermutationBits().AsString(),
            key_0.as_string(), key_1.as_string()));
      }
    }
    bmr_out->SetSetupIsReady();
  }
}

void BMRANDGate::EvaluateSetup() {
  if constexpr (MOTION_DEBUG) {
    GetLogger().LogDebug(
        fmt::format("Start evaluating setup phase of BMR AND Gate with id#{}", gate_id_));
  }
  const auto &R{GetConfig().GetBMRRandomOffset()};
  const auto R_as_bv = ENCRYPTO::AlignedBitVector(R.data(), kappa);
  const auto num_wires{parent_a_.size()};
  const auto num_simd{parent_a_.at(0)->GetNumOfSIMDValues()};
  const auto my_id{GetConfig().GetMyId()};
  const auto num_parties{GetConfig().GetNumOfParties()};
  const auto batch_size_full{num_simd * 4};
  [[maybe_unused]] const auto batch_size_3{num_simd * 3};

  if constexpr (MOTION_VERBOSE_DEBUG) {
    GetLogger().LogTrace(
        fmt::format("Gate#{} (BMR AND gate) Party#{} R {}\n", gate_id_, my_id, R.as_string()));
  }

  // generate random keys and masking bits for the outgoing wires
  GenerateRandomness();

  // 1-bit OTs

  // structure: parties X wires X choice bits
  std::vector<std::vector<ENCRYPTO::BitVector<>>> choices(
      num_parties, std::vector<ENCRYPTO::BitVector<>>(num_wires));

  for (auto wire_i = 0ull; wire_i < num_wires; ++wire_i) {
    auto bmr_out{std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(wire_i))};
    const auto bmr_a{std::dynamic_pointer_cast<const Wires::BMRWire>(parent_a_.at(wire_i))};
    const auto bmr_b{std::dynamic_pointer_cast<const Wires::BMRWire>(parent_b_.at(wire_i))};
    assert(bmr_out);
    assert(bmr_a);
    assert(bmr_b);
    bmr_a->GetSetupReadyCondition()->Wait();
    bmr_b->GetSetupReadyCondition()->Wait();

    // XXX: Why are we doing three bit-COTs? One would be enough.

    // select one of the parties to invert the permutation bits
    const bool permutation{(bmr_out->GetWireId() % num_parties) == my_id};

    ENCRYPTO::BitVector<> a_bv, b_bv;
    // XXX: ^reserve memory here
    for (auto simd_i = 0ull; simd_i < num_simd; ++simd_i) {
      const bool a = bmr_a->GetPermutationBits()[simd_i];
      const bool b = bmr_b->GetPermutationBits()[simd_i];
      a_bv.Append(a);
      a_bv.Append(a);
      a_bv.Append(a != permutation);
      b_bv.Append(b);
      b_bv.Append(b != permutation);
      b_bv.Append(b);
    }  // for each simd

    for (auto party_id = 0ull; party_id < num_parties; ++party_id) {
      if (party_id == my_id) {
        choices.at(party_id).at(wire_i) = a_bv & b_bv;
        continue;
      }

      auto &r_ot_1{r_ots_1_.at(party_id).at(wire_i)};
      auto &s_ot_1{s_ots_1_.at(party_id).at(wire_i)};

      if constexpr (MOTION_VERBOSE_DEBUG) {
        GetLogger().LogTrace(fmt::format(
            "Gate#{} (BMR AND gate)  Party#{}-#{} bit-C-OTs wire_i {} perm_bits {} bits_a {} from "
            "{} bits_b {} from {} a&b {}\n",
            gate_id_, my_id, party_id, wire_i, bmr_out->GetPermutationBits().AsString(),
            a_bv.AsString(), bmr_a->GetPermutationBits().AsString(), b_bv.AsString(),
            bmr_b->GetPermutationBits().AsString(), choices.at(party_id).at(wire_i).AsString()));
      }
      // compute C-OTs for the real value, ie, b = (lambda_u ^ alpha) * (lambda_v ^ beta)

      r_ot_1->WaitSetup();
      s_ot_1->WaitSetup();

      r_ot_1->SetChoices(b_bv);
      r_ot_1->SendCorrections();

      s_ot_1->SetCorrelations(a_bv);
      s_ot_1->SendMessages();
    }  // for each party
  }    // for each wire

  // kappa-bit OTs

  for (auto wire_i = 0ull; wire_i < num_wires; ++wire_i) {
    auto bmr_out{std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(wire_i))};
    const auto bmr_a{std::dynamic_pointer_cast<const Wires::BMRWire>(parent_a_.at(wire_i))};
    const auto bmr_b{std::dynamic_pointer_cast<const Wires::BMRWire>(parent_b_.at(wire_i))};
    assert(bmr_out);
    assert(bmr_a);
    assert(bmr_b);
    for (auto party_id = 0ull; party_id < num_parties; ++party_id) {
      if (party_id == my_id) continue;
      auto &r_ot_1{r_ots_1_.at(party_id).at(wire_i)};
      auto &s_ot_1{s_ots_1_.at(party_id).at(wire_i)};

      assert(r_ot_1->ChoicesAreSet());
      r_ot_1->ComputeOutputs();
      const auto &r_bv = r_ot_1->GetOutputs();
      s_ot_1->ComputeOutputs();
      const auto &s_bv = s_ot_1->GetOutputs();

      choices.at(party_id).at(wire_i) = r_bv ^ s_bv;

      if constexpr (MOTION_VERBOSE_DEBUG) {
        const auto &r_bv_check = r_ot_1->GetChoices();
        const auto &s_bv_check = s_ot_1->GetCorrelations();
        GetLogger().LogTrace(fmt::format(
            "Gate#{} (BMR AND gate) Party#{}-#{} bit-C-OTs wire_i {} bits from C-OTs r {} s {} "
            "result {} (r {} s {})\n",
            gate_id_, GetConfig().GetMyId(), party_id, wire_i, r_bv.AsString(), s_bv.AsString(),
            choices.at(party_id).at(wire_i).AsString(), r_bv_check.AsString(),
            s_bv_check.AsString()));
      }
    }  // for each party
  }    // for each wire

  std::vector<ENCRYPTO::BitVector<>> aggregated_choices(num_wires);

  for (auto wire_i = 0ull; wire_i < num_wires; ++wire_i) {
    auto bmr_out{std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(wire_i))};
    assert(bmr_out);

    assert(choices.at(0).at(wire_i).GetSize() == batch_size_3);
    aggregated_choices.at(wire_i) = choices.at(0).at(wire_i);
    for (auto party_id = 1ull; party_id < num_parties; ++party_id) {
      assert(choices.at(party_id).at(wire_i).GetSize() == batch_size_3);
      aggregated_choices.at(wire_i) ^= choices.at(party_id).at(wire_i);
    }
    {
      ENCRYPTO::BitVector<> perm_bits_out;
      for (auto bit_i = 0ull; bit_i < bmr_out->GetPermutationBits().GetSize(); ++bit_i) {
        perm_bits_out.Append(bmr_out->GetPermutationBits()[bit_i]);
        perm_bits_out.Append(bmr_out->GetPermutationBits()[bit_i]);
        perm_bits_out.Append(bmr_out->GetPermutationBits()[bit_i]);
      }
      aggregated_choices.at(wire_i) ^= perm_bits_out;
    }

    for (auto party_id = 0ull; party_id < num_parties; ++party_id) {
      if (party_id == my_id) continue;
      // multiply individual parties' R's with the secret-shared real value XORed with
      // the permutation bit of the output wire, ie, R * (b ^ lambda_w)
      r_ots_kappa_.at(party_id).at(wire_i)->SetChoices(aggregated_choices.at(wire_i));
      r_ots_kappa_.at(party_id).at(wire_i)->SendCorrections();

      s_ots_kappa_.at(party_id).at(wire_i)->SetCorrelation(R);
      s_ots_kappa_.at(party_id).at(wire_i)->SendMessages();
    }
  }  // for each wire

  ENCRYPTO::PRG prg;
  prg.SetKey(GetConfig().GetFixedAESKey().GetData().data());

  // Compute garbled rows
  // First, set rows to PRG outputs XOR key

  for (auto wire_i = 0ull; wire_i < num_wires; ++wire_i) {
    auto bmr_out{std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(wire_i))};
    assert(bmr_out);
    const auto bmr_a{std::dynamic_pointer_cast<const Wires::BMRWire>(parent_a_.at(wire_i))};
    const auto bmr_b{std::dynamic_pointer_cast<const Wires::BMRWire>(parent_b_.at(wire_i))};
    assert(bmr_a);
    assert(bmr_b);

    for (auto simd_i = 0ull; simd_i < num_simd; ++simd_i) {
      const auto &key_a_0{bmr_a->GetSecretKeys().at(simd_i)};
      const auto &key_a_1{key_a_0 ^ R};
      const auto &key_b_0{bmr_b->GetSecretKeys().at(simd_i)};
      const auto &key_b_1{key_b_0 ^ R};

      for (auto party_i = 0ull; party_i < num_parties; ++party_i) {
        uint128_t plaintext{party_i};
        plaintext <<= 64;
        plaintext += static_cast<uint64_t>(bmr_out->GetWireId() + simd_i);

        ENCRYPTO::BitVector<> mask_a_0(prg.FixedKeyAES(key_a_0.data(), plaintext), kappa);
        ENCRYPTO::BitVector<> mask_a_1(prg.FixedKeyAES(key_a_1.data(), plaintext), kappa);
        ENCRYPTO::BitVector<> mask_b_0(prg.FixedKeyAES(key_b_0.data(), plaintext), kappa);
        ENCRYPTO::BitVector<> mask_b_1(prg.FixedKeyAES(key_b_1.data(), plaintext), kappa);

        if constexpr (MOTION_VERBOSE_DEBUG) {
          GetLogger().LogTrace(fmt::format(
              "Gate#{} (BMR AND gate) Party#{} keys: a0 {} ({}) a1 {} ({}) b0 {} ({}) b1 {} ({})\n",
              gate_id_, my_id, key_a_0.as_string(), mask_a_0.AsString(), key_a_1.as_string(),
              mask_a_1.AsString(), key_b_0.as_string(), mask_b_0.AsString(), key_b_1.as_string(),
              mask_b_1.AsString()));
        }

        // XXX: for transition
        const auto zero_block = ENCRYPTO::block128_t::make_zero();

        auto &garbled_row_00{garbled_rows_.at(party_i).at(wire_i).at(simd_i * 4)};
        auto &garbled_row_01{garbled_rows_.at(party_i).at(wire_i).at(simd_i * 4 + 1)};
        auto &garbled_row_10{garbled_rows_.at(party_i).at(wire_i).at(simd_i * 4 + 2)};
        auto &garbled_row_11{garbled_rows_.at(party_i).at(wire_i).at(simd_i * 4 + 3)};
        if (party_i == my_id) {
          const auto &key_w_0{bmr_out->GetSecretKeys().at(simd_i)};
          garbled_row_00 = zero_block ^ mask_a_0 ^ mask_b_0 ^ key_w_0;
          garbled_row_01 = zero_block ^ mask_a_0 ^ mask_b_1 ^ key_w_0;
          garbled_row_10 = zero_block ^ mask_a_1 ^ mask_b_0 ^ key_w_0;
          garbled_row_11 = zero_block ^ mask_a_1 ^ mask_b_1 ^ key_w_0 ^ R_as_bv;

          if constexpr (MOTION_VERBOSE_DEBUG) {
            GetLogger().LogTrace(
                fmt::format(
                    "Gate#{} (BMR AND gate) Party#{} (me {}) gr00 mask_a_0 {} XOR mask_b_0 {} XOR "
                    "key_w_0 {} = {}\n",
                    gate_id_, party_i, my_id, mask_a_0.AsString(), mask_b_0.AsString(),
                    key_w_0.as_string(), garbled_row_00.as_string()) +
                fmt::format(
                    "Gate#{} (BMR AND gate) Party#{} (me {}) gr01 mask_a_0 {} XOR mask_b_0 {} XOR "
                    "key_w_1 {} = {}\n",
                    gate_id_, party_i, my_id, mask_a_0.AsString(), mask_b_1.AsString(),
                    key_w_0.as_string(), garbled_row_01.as_string()) +
                fmt::format(
                    "Gate#{} (BMR AND gate) Party#{} (me {}) gr10 mask_a_0 {} XOR mask_b_0 {} XOR "
                    "key_w_0 {} = {}\n",
                    gate_id_, party_i, my_id, mask_a_1.AsString(), mask_b_0.AsString(),
                    key_w_0.as_string(), garbled_row_10.as_string()) +
                fmt::format(
                    "Gate#{} (BMR AND gate) Party#{} (me {}) gr11 mask_a_1 {} XOR mask_b_1 {} XOR "
                    "key_w_1 {} XOR R {} = {}\n",
                    gate_id_, party_i, my_id, mask_a_1.AsString(), mask_b_1.AsString(),
                    key_w_0.as_string(), R.as_string(), garbled_row_11.as_string()));
          }
        } else {
          garbled_row_00 = zero_block ^ mask_a_0 ^ mask_b_0;
          garbled_row_01 = zero_block ^ mask_a_0 ^ mask_b_1;
          garbled_row_10 = zero_block ^ mask_a_1 ^ mask_b_0;
          garbled_row_11 = zero_block ^ mask_a_1 ^ mask_b_1;
          if (MOTION_VERBOSE_DEBUG) {
            GetLogger().LogTrace(
                fmt::format("Gate#{} (BMR AND gate) Party#{} (me {}) gr00 mask_a_0 {} XOR mask_b_0 "
                            "{} = {}\n",
                            gate_id_, party_i, my_id, mask_a_0.AsString(), mask_b_0.AsString(),
                            garbled_row_00.as_string()) +
                fmt::format("Gate#{} (BMR AND gate) Party#{} (me {}) gr01 mask_a_0 {} XOR mask_b_1 "
                            "{} = {}\n",
                            gate_id_, party_i, my_id, mask_a_0.AsString(), mask_b_1.AsString(),
                            garbled_row_01.as_string()) +
                fmt::format("Gate#{} (BMR AND gate) Party#{} (me {}) gr10 mask_a_1 {} XOR mask_b_0 "
                            "{} = {}\n",
                            gate_id_, party_i, my_id, mask_a_1.AsString(), mask_b_0.AsString(),
                            garbled_row_10.as_string()) +
                fmt::format("Gate#{} (BMR AND gate) Party#{} (me {}) gr11 mask_a_1 {} XOR mask_b_1 "
                            "{} = {}\n",
                            gate_id_, party_i, my_id, mask_a_1.AsString(), mask_b_1.AsString(),
                            garbled_row_11.as_string()));
          }
        }

        std::array<ENCRYPTO::AlignedBitVector, 3> shared_R;
        const ENCRYPTO::AlignedBitVector zero_bv(kappa);

        if (party_i == my_id) {
          const auto R_as_bv = ENCRYPTO::AlignedBitVector(R.data(), kappa);
          shared_R.at(0) = aggregated_choices.at(wire_i)[simd_i * 3] ? R_as_bv : zero_bv;
          shared_R.at(1) = aggregated_choices.at(wire_i)[simd_i * 3 + 1] ? R_as_bv : zero_bv;
          shared_R.at(2) = aggregated_choices.at(wire_i)[simd_i * 3 + 2] ? R_as_bv : zero_bv;
        } else {
          shared_R.at(0) = shared_R.at(1) = shared_R.at(2) = zero_bv;
        }

        // R's from C-OTs
        if (party_i == my_id) {
          for (auto party_j = 0ull; party_j < num_parties; ++party_j) {
            if (party_j == my_id) continue;

            s_ots_kappa_.at(party_j).at(wire_i)->ComputeOutputs();
            const auto &s_out = s_ots_kappa_.at(party_j).at(wire_i)->GetOutputs();
            assert(s_out.size() == num_simd * 3);
            const auto R_00 = ENCRYPTO::BitVector(s_out[simd_i * 3].data(), kappa);
            const auto R_01 = ENCRYPTO::BitVector(s_out[simd_i * 3 + 1].data(), kappa);
            const auto R_10 = ENCRYPTO::BitVector(s_out[simd_i * 3 + 2].data(), kappa);

            shared_R.at(0) ^= R_00;
            shared_R.at(1) ^= R_01;
            shared_R.at(2) ^= R_10;

            if (MOTION_VERBOSE_DEBUG) {
              GetLogger().LogTrace(fmt::format(
                  "Gate#{} (BMR AND gate) Me#{}: Party#{} received R's \n00 ({}) \n01 ({}) \n10 "
                  "({})\n",
                  gate_id_, my_id, party_i, R_00.AsString(), R_01.AsString(), R_10.AsString()));
            }
          }
        } else {
          assert(r_ots_kappa_.at(party_i).at(wire_i)->ChoicesAreSet());
          r_ots_kappa_.at(party_i).at(wire_i)->ComputeOutputs();
          const auto &r_out = r_ots_kappa_.at(party_i).at(wire_i)->GetOutputs();
          assert(r_out.size() == num_simd * 3);
          const auto R_00 = ENCRYPTO::BitVector(r_out[simd_i * 3].data(), kappa);
          const auto R_01 = ENCRYPTO::BitVector(r_out[simd_i * 3 + 1].data(), kappa);
          const auto R_10 = ENCRYPTO::BitVector(r_out[simd_i * 3 + 2].data(), kappa);

          shared_R.at(0) ^= R_00;
          shared_R.at(1) ^= R_01;
          shared_R.at(2) ^= R_10;
        }

        if constexpr (MOTION_VERBOSE_DEBUG) {
          GetLogger().LogTrace(
              fmt::format("Gate#{} (BMR AND gate) Me#{}: Shared R's \n00 ({}) \n01 ({}) \n10 "
                          "({})\n",
                          gate_id_, my_id, party_i, shared_R.at(0).AsString(),
                          shared_R.at(1).AsString(), shared_R.at(2).AsString()));
        }
        garbled_row_00 ^= shared_R.at(0);
        garbled_row_01 ^= shared_R.at(1);
        garbled_row_10 ^= shared_R.at(2);
        garbled_row_11 ^= shared_R.at(0) ^ shared_R.at(1) ^ shared_R.at(2);
      }
    }  // for each simd
  }    // for each wire

  ENCRYPTO::block128_vector send_message_buffer(num_parties * num_wires * num_simd * 4);
  std::size_t buffer_index = 0;
  if constexpr (MOTION_VERBOSE_DEBUG) {
    std::string s{fmt::format("Me#{}: ", my_id)};
    assert(garbled_rows_.size() == num_parties);
    for (auto party_i = 0ull; party_i < num_parties; ++party_i) {
      s.append(fmt::format("\nParty #{}: ", party_i));
      assert(garbled_rows_.at(party_i).size() == num_wires);
      for (auto wire_j = 0ull; wire_j < num_wires; ++wire_j) {
        s.append(fmt::format(" Wire #{}: ", wire_j));
        assert(garbled_rows_.at(party_i).at(wire_j).size() == 4 * num_simd);
        for (auto k = 0ull; k < garbled_rows_.at(party_i).at(wire_j).size(); ++k) {
          s.append(fmt::format("\nSIMD #{}: ", k));
          send_message_buffer.at(buffer_index++) = garbled_rows_.at(party_i).at(wire_j).at(k);
          s.append(fmt::format(" garbled rows {} ",
                               garbled_rows_.at(party_i).at(wire_j).at(k).as_string()));
        }
      }
    }
    s.append("\n");
    GetLogger().LogTrace(s);
  } else {
    for (auto party_i = 0ull; party_i < garbled_rows_.size(); ++party_i) {
      for (auto wire_j = 0ull; wire_j < garbled_rows_.at(party_i).size(); ++wire_j) {
        for (auto k = 0ull; k < garbled_rows_.at(party_i).at(wire_j).size(); ++k) {
          send_message_buffer.at(buffer_index++) = garbled_rows_.at(party_i).at(wire_j).at(k);
        }
      }
    }
  }

  const std::vector<std::uint8_t> buffer_u8(
      reinterpret_cast<const std::uint8_t *>(send_message_buffer.data()),
      reinterpret_cast<const std::uint8_t *>(send_message_buffer.data()) +
          send_message_buffer.byte_size());

  for (auto party_id = 0ull; party_id < num_parties; ++party_id) {
    if (party_id == my_id) continue;
    backend_.Send(party_id,
                  Communication::BuildBMRANDMessage(static_cast<std::size_t>(gate_id_), buffer_u8));
  }

  {
    for (auto party_i = 0ull; party_i < num_parties; ++party_i) {
      if (party_i == my_id) continue;
      auto gr = received_garbled_rows_.at(party_i).get();
      for (auto party_j = 0ull; party_j < num_parties; ++party_j) {
        for (auto wire_i = 0ull; wire_i < num_wires; ++wire_i) {
          for (auto simd_i = 0ull; simd_i < num_simd; ++simd_i) {
            for (auto gr_i = 0; gr_i < 4; ++gr_i) {
              // party offset
              const std::size_t offset_p = party_j * (batch_size_full * num_wires);
              // wire offset
              const std::size_t offset_w = wire_i * batch_size_full;
              // simd_offset
              const std::size_t offset_s = simd_i * 4;
              // complete offset
              const std::size_t offset = offset_p + offset_w + offset_s + gr_i;
              garbled_rows_.at(party_j).at(wire_i).at(simd_i * 4 + gr_i) ^= gr.at(offset);
            }
          }
        }
      }
    }
  }

  // mark this gate as setup-ready to proceed with the online phase
  if constexpr (MOTION_DEBUG) {
    GetLogger().LogDebug(
        fmt::format("Finished evaluating setup phase of BMR AND Gate with id#{}", gate_id_));
  }
  SetSetupIsReady();
  GetRegister().IncrementEvaluatedGateSetupsCounter();
}

void BMRANDGate::EvaluateOnline() {
  WaitSetup();

  const auto num_parties = GetConfig().GetNumOfParties();
  const auto my_id = GetConfig().GetMyId();
  const auto num_wires = output_wires_.size();
  const auto num_simd = output_wires_.at(0)->GetNumOfSIMDValues();
  const auto &R = GetConfig().GetBMRRandomOffset();

  auto pk_index = [num_parties](auto simd_i, auto party_i) {
    return simd_i * num_parties + party_i;
  };

  if constexpr (MOTION_VERBOSE_DEBUG) {
    for (auto i = 0ull; i < garbled_rows_.size(); ++i) {
      for (auto j = 0ull; j < garbled_rows_.at(i).size(); ++j) {
        for (auto k = 0ull; k < garbled_rows_.at(i).at(j).size(); ++k) {
          GetLogger().LogTrace(fmt::format(
              "Party#{}: reconstructed gr for Party#{} Wire#{} SIMD#{}: {}\n",
              GetConfig().GetMyId(), i, j, k, garbled_rows_.at(i).at(j).at(k).as_string()));
        }
      }
    }
  }

  for (auto wire_i = 0ull; wire_i < num_wires; ++wire_i) {
    auto bmr_out = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(wire_i));
    assert(bmr_out);
    const auto wire_a = std::dynamic_pointer_cast<const Wires::BMRWire>(parent_a_.at(wire_i));
    const auto wire_b = std::dynamic_pointer_cast<const Wires::BMRWire>(parent_b_.at(wire_i));
    assert(wire_a);
    assert(wire_b);

    wire_a->GetIsReadyCondition()->Wait();
    wire_b->GetIsReadyCondition()->Wait();

    ENCRYPTO::PRG prg;
    prg.SetKey(GetConfig().GetFixedAESKey().GetData().data());

    for (auto simd_i = 0ull; simd_i < num_simd; ++simd_i) {
      auto masks = ENCRYPTO::block128_vector::make_zero(num_parties);
      [[maybe_unused]] std::string s;
      if constexpr (MOTION_VERBOSE_DEBUG) {
        s.append(
            fmt::format("Me#{}: wire#{} simd#{} result\n", GetConfig().GetMyId(), wire_i, simd_i));
        s.append(fmt::format("Public values a {} b {} ", wire_a->GetPublicValues().AsString(),
                             wire_b->GetPublicValues().AsString()));
      }
      for (auto party_i = 0ull; party_i < num_parties; ++party_i) {
        const auto &key_a = wire_a->GetPublicKeys().at(pk_index(simd_i, party_i));
        const auto &key_b = wire_b->GetPublicKeys().at(pk_index(simd_i, party_i));
        for (auto party_j = 0ull; party_j < num_parties; ++party_j) {
          uint128_t plaintext{party_j};
          plaintext <<= 64;
          plaintext += static_cast<uint64_t>(bmr_out->GetWireId() + simd_i);
          ENCRYPTO::block128_t mask_a;
          ENCRYPTO::block128_t mask_b;
          prg.FixedKeyAES(key_a.data(), plaintext, mask_a.data());
          prg.FixedKeyAES(key_b.data(), plaintext, mask_b.data());
          masks.at(party_j) ^= mask_a;
          masks.at(party_j) ^= mask_b;
          if constexpr (MOTION_VERBOSE_DEBUG) {
            s.append(fmt::format("\nParty#{} key for #{} key_a {} ({}) key_b {} ({})", party_i,
                                 party_j, key_a.as_string(), mask_a.as_string(), key_b.as_string(),
                                 mask_b.as_string()));
          }
        }
      }

      for (auto party_i = 0ull; party_i < num_parties; ++party_i) {
        const bool alpha = wire_a->GetPublicValues()[simd_i],
                   beta = wire_b->GetPublicValues()[simd_i];
        const std::size_t alpha_beta_offset =
            static_cast<std::size_t>(alpha) * 2 + static_cast<std::size_t>(beta);
        if constexpr (MOTION_VERBOSE_DEBUG) {
          s.append(fmt::format(
              "\nParty#{} output public keys = garbled row_(alpha = {} ,beta = {}, offset = {}) {} "
              "xor mask {} = ",
              party_i, alpha, beta, alpha_beta_offset,
              garbled_rows_.at(party_i).at(wire_i).at(4 * simd_i + alpha_beta_offset).as_string(),
              masks.at(party_i).as_string()));
        }
        bmr_out->GetMutablePublicKeys().at(pk_index(simd_i, party_i)) =
            garbled_rows_.at(party_i).at(wire_i).at(4 * simd_i + alpha_beta_offset) ^
            masks.at(party_i);
        if constexpr (MOTION_VERBOSE_DEBUG) {
          s.append(bmr_out->GetPublicKeys().at(pk_index(simd_i, party_i)).as_string());
        }
      }
      if constexpr (MOTION_VERBOSE_DEBUG) {
        s.append("\n");
        s.append(fmt::format("output skey0 {} skey1 {}\n",
                             bmr_out->GetSecretKeys().at(simd_i).as_string(),
                             (bmr_out->GetSecretKeys().at(simd_i) ^ R).as_string()));
        GetLogger().LogTrace(s);
      }
    }  // for each simd

    for (auto simd_i = 0ull; simd_i < num_simd; ++simd_i) {
      const bool neq = bmr_out->GetPublicKeys().at(pk_index(simd_i, my_id)) !=
                       bmr_out->GetSecretKeys().at(simd_i);
      if (neq)
        assert(bmr_out->GetPublicKeys().at(pk_index(simd_i, my_id)) ==
               (bmr_out->GetSecretKeys().at(simd_i) ^ R));
      bmr_out->GetMutablePublicValues().Set(neq, simd_i);
    }
    if constexpr (MOTION_VERBOSE_DEBUG) {
      GetLogger().LogTrace(fmt::format("Party#{} wire#{} public values result {}\n",
                                       GetConfig().GetMyId(), wire_i,
                                       bmr_out->GetPublicValues().AsString()));
    }
  }  // for each wire

  if constexpr (MOTION_VERBOSE_DEBUG) {
    GetLogger().LogTrace(fmt::format("Evaluated BMR AND Gate with id#{}", gate_id_));
  }
  SetOnlineIsReady();
  GetRegister().IncrementEvaluatedGatesCounter();
}

const Shares::BMRSharePtr BMRANDGate::GetOutputAsBMRShare() const {
  auto result = std::make_shared<Shares::BMRShare>(output_wires_);
  assert(result);
  return result;
}

const Shares::SharePtr BMRANDGate::GetOutputAsShare() const {
  auto result = std::static_pointer_cast<Shares::Share>(GetOutputAsBMRShare());
  assert(result);
  return result;
}
}  // namespace MOTION::Gates::BMR
