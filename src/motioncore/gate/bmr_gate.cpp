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
#include "crypto/oblivious_transfer/ot_provider.h"
#include "crypto/pseudo_random_generator.h"
#include "wire/bmr_wire.h"
#include "wire/boolean_gmw_wire.h"

namespace MOTION::Gates::BMR {

BMRInputGate::BMRInputGate(const std::vector<ENCRYPTO::BitVector<>> &input,
                           std::size_t input_owner_id, std::weak_ptr<Backend> backend)
    : input_(input) {
  assert(!input_.empty());
  input_owner_id_ = input_owner_id;
  bits_ = input_.size() == 0 ? 0 : input_.at(0).GetSize();
  backend_ = backend;
  InitializationHelper();
}

BMRInputGate::BMRInputGate(std::vector<ENCRYPTO::BitVector<>> &&input, std::size_t input_owner_id,
                           std::weak_ptr<Backend> backend)
    : input_(std::move(input)) {
  assert(!input_.empty());
  input_owner_id_ = input_owner_id;
  bits_ = input_.size() == 0 ? 0 : input_.at(0).GetSize();
  backend_ = backend;
  InitializationHelper();
}

void BMRInputGate::InitializationHelper() {
  if (static_cast<std::size_t>(input_owner_id_) >= GetConfig()->GetNumOfParties()) {
    throw std::runtime_error(fmt::format("Invalid input owner: {} of {}", input_owner_id_,
                                         GetConfig()->GetNumOfParties()));
  }

  gate_id_ = GetRegister()->NextGateId();

  assert(input_.size() > 0u);           // assert >=1 wire
  assert(input_.at(0).GetSize() > 0u);  // assert >=1 SIMD bits
  // assert SIMD lengths of all wires are equal
  assert(ENCRYPTO::BitVector<>::EqualSizeDimensions(input_));

  output_wires_.reserve(input_.size());
  for (auto &v : input_)
    output_wires_.push_back(std::make_shared<Wires::BMRWire>(v.GetSize(), backend_));

  for (auto &w : output_wires_) GetRegister()->RegisterNextWire(w);

  received_public_keys_.resize(GetConfig()->GetNumOfParties());

  assert(input_owner_id_ >= 0);
  assert(gate_id_ >= 0);
  const auto my_id = GetConfig()->GetMyId();

  if (my_id != static_cast<std::size_t>(input_owner_id_)) {
    auto &data_storage = GetConfig()
                             ->GetCommunicationContext(static_cast<std::size_t>(input_owner_id_))
                             ->GetDataStorage();
    auto &bmr_data = data_storage->GetBMRData();
    auto elem =
        bmr_data->input_public_values_
            .emplace(static_cast<std::size_t>(gate_id_),
                     std::pair<std::size_t, std::promise<std::unique_ptr<ENCRYPTO::BitVector<>>>>())
            .first;
    auto &bitlen = std::get<0>(elem->second);
    bitlen = bits_ * input_.size();
  }

  for (auto i = 0ull; i < GetConfig()->GetNumOfParties(); ++i) {
    if (my_id == i) continue;
    auto &data_storage = GetConfig()->GetCommunicationContext(i)->GetDataStorage();
    auto &bmr_data = data_storage->GetBMRData();

    auto elem =
        bmr_data->input_public_keys_
            .emplace(gate_id_,
                     std::pair<std::size_t, std::promise<std::unique_ptr<ENCRYPTO::BitVector<>>>>())
            .first;
    auto &bitlen = std::get<0>(elem->second);
    bitlen = bits_ * input_.size() * kappa;
  }

  if constexpr (MOTION_DEBUG) {
    auto gate_info = fmt::format("gate id {}, input owner {}", gate_id_, input_owner_id_);
    GetLogger()->LogDebug(
        fmt::format("Created a BMRInputGate with following properties: {}", gate_info));
  }
}

void BMRInputGate::EvaluateSetup() {
  const auto my_id = GetConfig()->GetMyId();
  if (my_id != static_cast<std::size_t>(input_owner_id_)) {
    received_public_values_ =
        GetConfig()
            ->GetCommunicationContext(static_cast<std::size_t>(input_owner_id_))
            ->GetDataStorage()
            ->GetBMRData()
            ->input_public_values_.at(static_cast<std::size_t>(gate_id_))
            .second.get_future();
  }

  for (auto i = 0ull; i < GetConfig()->GetNumOfParties(); ++i) {
    if (my_id == i) continue;
    received_public_keys_.at(i) = GetConfig()
                                      ->GetCommunicationContext(i)
                                      ->GetDataStorage()
                                      ->GetBMRData()
                                      ->input_public_keys_.at(static_cast<std::size_t>(gate_id_))
                                      .second.get_future();
  }

  for (auto i = 0ull; i < output_wires_.size(); ++i) {
    auto wire = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(i));
    assert(wire);
    // 2 private keys for each wire
    wire->GenerateRandomPrivateKeys();
    if (static_cast<std::size_t>(input_owner_id_) == my_id) {
      wire->GenerateRandomPermutationBits();
    } else {
      // zero-bit-vector
      wire->GetMutablePermutationBits() = ENCRYPTO::BitVector<>(wire->GetNumOfSIMDValues());
    }
    wire->SetSetupIsReady();
    if constexpr (MOTION_VERBOSE_DEBUG) {
      std::string keys_0, keys_1;
      for (const auto &key : std::get<0>(wire->GetSecretKeys())) {
        assert(key.GetSize() == kappa);
        keys_0.append(key.AsString() + " ");
      }
      if (!keys_0.empty()) keys_0.erase(keys_0.size() - 1);
      for (const auto &key : std::get<1>(wire->GetSecretKeys())) {
        assert(key.GetSize() == kappa);
        keys_1.append(key.AsString() + " ");
      }
      if (!keys_1.empty()) keys_1.erase(keys_1.size() - 1);

      GetLogger()->LogTrace(
          fmt::format("Created a BMR wire #{} with real values {} permutation bits {}, keys 0 {}, "
                      "and keys 1 {}",
                      wire->GetWireId(), input_.at(i).AsString(),
                      wire->GetPermutationBits().AsString(), keys_0, keys_1));
    }
  }
  SetSetupIsReady();
}

void BMRInputGate::EvaluateOnline() {
  WaitSetup();

  auto ptr_backend = backend_.lock();
  assert(ptr_backend);

  const auto my_id = GetConfig()->GetMyId();
  const bool my_input = static_cast<std::size_t>(input_owner_id_) == my_id;
  ENCRYPTO::BitVector<> buffer;
  if (my_input) {  // mask and publish inputs if my input
    for (auto i = 0ull; i < output_wires_.size(); ++i) {
      auto wire = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(i));
      assert(wire);
      wire->GetMutablePublicValues() = input_.at(i) ^ wire->GetPermutationBits();
      buffer.Append(wire->GetPublicValues());
    }
    const std::vector<std::uint8_t> payload(
        reinterpret_cast<const std::uint8_t *>(buffer.GetData().data()),
        reinterpret_cast<const std::uint8_t *>(buffer.GetData().data()) + buffer.GetData().size());
    for (auto i = 0ull; i < GetConfig()->GetNumOfParties(); ++i) {
      if (i == GetConfig()->GetMyId()) continue;
      ptr_backend->Send(i, Communication::BuildBMRInput0Message(gate_id_, payload));
    }
  } else {  // receive masked values if not my input
    buffer = std::move(*received_public_values_.get());
    for (auto i = 0ull; i < output_wires_.size(); ++i) {
      auto wire = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(i));
      assert(wire);
      wire->GetMutablePublicValues() = buffer.Subset(i * bits_, (i + 1) * bits_);
    }
  }

  buffer.Clear();
  // rearrange keys corresponding to the public values into one buffer
  for (auto i = 0ull; i < output_wires_.size(); ++i) {
    auto wire = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(i));
    const auto &keys = wire->GetSecretKeys();
    const auto &keys_0 = std::get<0>(keys);
    const auto &keys_1 = std::get<1>(keys);
    for (auto j = 0ull; j < wire->GetNumOfSIMDValues(); ++j) {
      if (wire->GetPublicValues()[j])
        buffer.Append(keys_1.at(j));
      else
        buffer.Append(keys_0.at(j));
    }
  }

  // publish keys
  const std::vector<std::uint8_t> payload(
      reinterpret_cast<const std::uint8_t *>(buffer.GetData().data()),
      reinterpret_cast<const std::uint8_t *>(buffer.GetData().data()) + buffer.GetData().size());
  for (auto i = 0ull; i < GetConfig()->GetNumOfParties(); ++i) {
    if (i == GetConfig()->GetMyId()) continue;
    ptr_backend->Send(i, Communication::BuildBMRInput1Message(gate_id_, payload));
  }

  // parse published keys
  for (auto i = 0ull; i < GetConfig()->GetNumOfParties(); ++i) {
    if (i == GetConfig()->GetMyId()) {
      for (auto j = 0ull; j < output_wires_.size(); ++j) {
        auto wire = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(j));
        assert(wire);
        for (auto k = 0ull; k < wire->GetNumOfSIMDValues(); ++k) {
          if (wire->GetPublicValues()[k])
            wire->GetMutablePublicKeys().at(i).at(k) = std::get<1>(wire->GetSecretKeys()).at(k);
          else
            wire->GetMutablePublicKeys().at(i).at(k) = std::get<0>(wire->GetSecretKeys()).at(k);
        }
      }
    } else {
      buffer = std::move(*received_public_keys_.at(i).get());
      assert(bits_ > 0u);
      for (auto j = 0ull; j < output_wires_.size(); ++j) {
        auto wire = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(j));
        assert(wire);
        for (auto k = 0ull; k < wire->GetNumOfSIMDValues(); ++k) {
          wire->GetMutablePublicKeys().at(i).at(k) =
              buffer.Subset((j * bits_ + k) * kappa, (j * bits_ + k + 1) * kappa);
        }
      }
    }
  }

  GetRegister()->IncrementEvaluatedGatesCounter();
  if constexpr (MOTION_VERBOSE_DEBUG) {
    std::string s(fmt::format("Evaluated a BMR input gate #{} and got as result: ", gate_id_));
    for (auto i = 0ull; i < output_wires_.size(); ++i) {
      auto wire = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(i));
      std::string keys;
      assert(MOTION::Helpers::Compare::Dimensions(wire->GetPublicKeys()));
      for (auto j = 0ull; j < GetConfig()->GetNumOfParties(); ++j) {
        keys.append(std::to_string(j) + std::string(" "));
        for (const auto &key : wire->GetPublicKeys().at(j)) {
          keys.append(key.AsString() + " ");
        }
      }
      if (!keys.empty()) keys.erase(keys.size() - 1);
      s.append(fmt::format("wire #{} with public bits {} and public keys {}\n", wire->GetWireId(),
                           wire->GetPublicValues().AsString(), keys));
    }
    GetLogger()->LogTrace(s);
  }
  SetOnlineIsReady();
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

BMROutputGate::BMROutputGate(const Shares::SharePtr &parent, std::size_t output_owner) {
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

  backend_ = parent_.at(0)->GetBackend();
  auto ptr_backend = backend_.lock();
  assert(ptr_backend);

  if (output_owner >= ptr_backend->GetConfig()->GetNumOfParties() && output_owner != ALL) {
    throw std::runtime_error(fmt::format("Invalid output owner: {} of {}", output_owner,
                                         ptr_backend->GetConfig()->GetNumOfParties()));
  }

  std::vector<Wires::WirePtr> dummy_wires(parent_.size());
  const ENCRYPTO::BitVector<> dummy_bv(parent_.at(0)->GetNumOfSIMDValues());

  for (auto &w : dummy_wires) {
    w = std::make_shared<Wires::GMWWire>(dummy_bv, backend_);
    ptr_backend->GetRegister()->RegisterNextWire(w);
  }

  gmw_out_share_ = std::make_shared<Shares::GMWShare>(dummy_wires);
  out_ = std::make_shared<MOTION::Gates::GMW::GMWOutputGate>(gmw_out_share_);
  GetRegister()->RegisterNextGate(out_);

  gate_id_ = ptr_backend->GetRegister()->NextGateId();

  for (auto &wire : parent_) {
    RegisterWaitingFor(wire->GetWireId());  // mark this gate as waiting for @param wire
    wire->RegisterWaitingGate(gate_id_);    // register this gate in @param wire as waiting
  }

  const auto my_id = ptr_backend->GetConfig()->GetMyId();
  is_my_output_ = static_cast<std::size_t>(output_owner_) == my_id ||
                  static_cast<std::size_t>(output_owner_) == ALL;

  for (auto &bv : output_) {
    output_wires_.push_back(std::static_pointer_cast<MOTION::Wires::Wire>(
        std::make_shared<Wires::BMRWire>(bv, ptr_backend)));
  }

  for (auto &wire : output_wires_) {
    ptr_backend->GetRegister()->RegisterNextWire(wire);
  }

  if constexpr (MOTION_DEBUG) {
    auto gate_info =
        fmt::format("bitlength {}, gate id {}, owner {}", output_.size(), gate_id_, output_owner_);
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Created a BMR OutputGate with following properties: {}", gate_info));
  }
}

void BMROutputGate::EvaluateSetup() { SetSetupIsReady(); }

void BMROutputGate::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);
  auto ptr_backend = backend_.lock();
  assert(ptr_backend);

  std::size_t i;

  if constexpr (MOTION_DEBUG) {
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Starting online phase evaluation for BMR OutputGate with id#{}", gate_id_));
  }

  auto &wires = gmw_out_share_->GetMutableWires();
  for (i = 0; i < wires.size(); ++i) {
    const auto bmr_wire = std::dynamic_pointer_cast<Wires::BMRWire>(parent_.at(i));
    MOTION::Helpers::WaitFor(*bmr_wire->GetIsReadyCondition());
    auto gmw_wire = std::dynamic_pointer_cast<Wires::GMWWire>(wires.at(i));
    assert(bmr_wire);
    assert(gmw_wire);
    gmw_wire->GetMutableValues() = bmr_wire->GetPermutationBits();
    gmw_wire->SetOnlineFinished();
  }

  for (i = 0; i < output_wires_.size(); ++i) {
    const auto bmr_wire = std::dynamic_pointer_cast<Wires::BMRWire>(parent_.at(i));
    auto gmw_wire = std::dynamic_pointer_cast<Wires::GMWWire>(out_->GetOutputWires().at(i));
    MOTION::Helpers::WaitFor(*gmw_wire->GetIsReadyCondition());
    assert(bmr_wire);
    assert(gmw_wire);
    assert(bmr_wire->GetPublicValues().GetSize() == gmw_wire->GetValues().GetSize());
    output_.at(i) = bmr_wire->GetPublicValues() ^ gmw_wire->GetValues();
    auto wire = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(i));
    assert(wire);
    wire->GetMutablePublicValues() = output_.at(i);
  }

  if constexpr (MOTION_DEBUG) {
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Evaluated online phase of BMR OutputGate with id#{}", gate_id_));
  }

  ptr_backend->GetRegister()->IncrementEvaluatedGatesCounter();
  SetOnlineIsReady();
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

BMRXORGate::BMRXORGate(const Shares::SharePtr &a, const Shares::SharePtr &b) {
  parent_a_ = a->GetWires();
  parent_b_ = b->GetWires();

  assert(parent_a_.size() > 0);
  assert(parent_a_.size() == parent_b_.size());
  assert(parent_a_.at(0)->GetBitLength() > 0);
  assert(parent_a_.at(0)->GetProtocol() == parent_b_.at(0)->GetProtocol());
  assert(parent_a_.at(0)->GetProtocol() == MPCProtocol::BMR);

  backend_ = parent_a_.at(0)->GetBackend();

  requires_online_interaction_ = false;
  gate_type_ = GateType::NonInteractiveGate;

  auto ptr_backend = backend_.lock();
  assert(ptr_backend);

  gate_id_ = ptr_backend->GetRegister()->NextGateId();

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
    ptr_backend->GetRegister()->RegisterNextWire(w);
  }

  if constexpr (MOTION_DEBUG) {
    auto gate_info = fmt::format("gate id {}, parents: {}, {}", gate_id_,
                                 parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Created a BMR XOR gate with following properties: {}", gate_info));
  }
}

void BMRXORGate::EvaluateSetup() {
  if constexpr (MOTION_DEBUG) {
    auto ptr_backend = backend_.lock();
    assert(ptr_backend);
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Start evaluating setup phase of BMR XOR Gate with id#{}", gate_id_));
  }

  for (auto i = 0ull; i < output_wires_.size(); ++i) {
    auto bmr_out = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(i));
    auto bmr_a = std::dynamic_pointer_cast<Wires::BMRWire>(parent_a_.at(i));
    auto bmr_b = std::dynamic_pointer_cast<Wires::BMRWire>(parent_b_.at(i));
    assert(bmr_out);
    assert(bmr_a);
    assert(bmr_b);
    MOTION::Helpers::WaitFor(*bmr_a->GetSetupReadyCondition());
    MOTION::Helpers::WaitFor(*bmr_b->GetSetupReadyCondition());
    bmr_out->GetMutablePermutationBits() =
        bmr_a->GetPermutationBits() ^ bmr_b->GetPermutationBits();
    const auto &R = GetConfig()->GetBMRRandomOffset();
    const auto &a0 = std::get<0>(bmr_a->GetSecretKeys());
    const auto &b0 = std::get<0>(bmr_b->GetSecretKeys());
    auto &out0 = std::get<0>(bmr_out->GetMutableSecretKeys());
    auto &out1 = std::get<1>(bmr_out->GetMutableSecretKeys());
    for (auto j = 0ull; j < bmr_out->GetNumOfSIMDValues(); ++j) {
      out0.at(j) = a0.at(j) ^ b0.at(j);
      out1.at(j) = out0.at(j) ^ R;
    }
    bmr_out->SetSetupIsReady();
  }
  SetSetupIsReady();
  if constexpr (MOTION_DEBUG) {
    auto ptr_backend = backend_.lock();
    assert(ptr_backend);
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Finished evaluating setup phase of BMR XOR Gate with id#{}", gate_id_));
  }
}

void BMRXORGate::EvaluateOnline() {
  WaitSetup();
  if constexpr (MOTION_DEBUG) {
    auto ptr_backend = backend_.lock();
    assert(ptr_backend);
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Start evaluating online phase of BMR XOR Gate with id#{}", gate_id_));
  }

  for (auto i = 0ull; i < parent_a_.size(); ++i) {
    auto wire_a = std::dynamic_pointer_cast<Wires::BMRWire>(parent_a_.at(i));
    auto wire_b = std::dynamic_pointer_cast<Wires::BMRWire>(parent_b_.at(i));
    assert(wire_a);
    assert(wire_b);

    auto bmr_out = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(i));
    assert(bmr_out);

    Helpers::WaitFor(*wire_a->GetIsReadyCondition());
    Helpers::WaitFor(*wire_b->GetIsReadyCondition());

    auto &out = bmr_out->GetMutablePublicKeys();
    const auto &a = wire_a->GetPublicKeys();
    const auto &b = wire_b->GetPublicKeys();

    for (auto k = 0ull; k < out.size(); ++k) {
      for (auto j = 0ull; j < out.at(k).size(); ++j) {
        out.at(k).at(j) = a.at(k).at(j) ^ b.at(k).at(j);
      }
    }
    bmr_out->GetMutablePublicValues() = wire_a->GetPublicValues() ^ wire_b->GetPublicValues();
  }

  auto ptr_backend = backend_.lock();
  assert(ptr_backend);

  ptr_backend->GetRegister()->IncrementEvaluatedGatesCounter();

  SetOnlineIsReady();

  if constexpr (MOTION_DEBUG) {
    auto ptr_backend = backend_.lock();
    assert(ptr_backend);
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Finished evaluating online phase of BMR XOR Gate with id#{}", gate_id_));
  }
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

BMRINVGate::BMRINVGate(const Shares::SharePtr &parent) {
  parent_ = parent->GetWires();

  assert(parent_.size() > 0);
  assert(parent_.at(0)->GetBitLength() > 0);
  for ([[maybe_unused]] const auto &wire : parent_) assert(wire->GetProtocol() == MPCProtocol::BMR);

  backend_ = parent_.at(0)->GetBackend();

  requires_online_interaction_ = false;
  gate_type_ = GateType::NonInteractiveGate;

  auto ptr_backend = backend_.lock();
  assert(ptr_backend);

  gate_id_ = ptr_backend->GetRegister()->NextGateId();

  for (auto &wire : parent_) {
    RegisterWaitingFor(wire->GetWireId());
    wire->RegisterWaitingGate(gate_id_);
  }

  output_wires_.resize(parent_.size());
  const ENCRYPTO::BitVector tmp_bv(parent->GetNumOfSIMDValues());
  for (auto &w : output_wires_) {
    w = std::make_shared<Wires::BMRWire>(tmp_bv, backend_);
    ptr_backend->GetRegister()->RegisterNextWire(w);
  }

  if constexpr (MOTION_DEBUG) {
    auto gate_info = fmt::format("gate id {}, parent wires: ", gate_id_);
    for (const auto &wire : parent_) gate_info.append(fmt::format("{} ", wire->GetWireId()));
    gate_info.append(" output wires: ");
    for (const auto &wire : output_wires_) gate_info.append(fmt::format("{} ", wire->GetWireId()));
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Created a BMR INV gate with following properties: {}", gate_info));
  }
}

void BMRINVGate::EvaluateSetup() {
  if constexpr (MOTION_DEBUG) {
    auto ptr_backend = backend_.lock();
    assert(ptr_backend);
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Start evaluating setup phase of BMR INV Gate with id#{}", gate_id_));
  }

  const auto my_id{GetConfig()->GetMyId()};
  const auto num_parties{GetConfig()->GetNumOfParties()};

  for (auto i = 0ull; i < output_wires_.size(); ++i) {
    auto bmr_out = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(i));
    auto bmr_in = std::dynamic_pointer_cast<Wires::BMRWire>(parent_.at(i));
    assert(bmr_out);
    assert(bmr_in);
    MOTION::Helpers::WaitFor(*bmr_in->GetSetupReadyCondition());

    bmr_out->GetMutablePermutationBits() = bmr_in->GetPermutationBits();

    if (bmr_out->GetWireId() % num_parties == my_id) bmr_out->GetMutablePermutationBits().Invert();

    const auto &in0 = std::get<0>(bmr_in->GetSecretKeys());
    const auto &in1 = std::get<1>(bmr_in->GetSecretKeys());

    auto &out0 = std::get<0>(bmr_out->GetMutableSecretKeys());
    auto &out1 = std::get<1>(bmr_out->GetMutableSecretKeys());

    for (auto j = 0ull; j < bmr_out->GetNumOfSIMDValues(); ++j) {
      out0.at(j) = in0.at(j);
      out1.at(j) = in1.at(j);
    }
    bmr_out->SetSetupIsReady();
  }
  SetSetupIsReady();
  if constexpr (MOTION_DEBUG) {
    auto ptr_backend = backend_.lock();
    assert(ptr_backend);
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Finished evaluating setup phase of BMR INV Gate with id#{}", gate_id_));
  }
}

void BMRINVGate::EvaluateOnline() {
  WaitSetup();
  if constexpr (MOTION_DEBUG) {
    auto ptr_backend = backend_.lock();
    assert(ptr_backend);
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Start evaluating online phase of BMR INV Gate with id#{}", gate_id_));
  }

  for (auto i = 0ull; i < parent_.size(); ++i) {
    auto bmr_in = std::dynamic_pointer_cast<Wires::BMRWire>(parent_.at(i));
    assert(bmr_in);

    auto bmr_out = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(i));
    assert(bmr_out);

    Helpers::WaitFor(*bmr_in->GetIsReadyCondition());

    for (auto j = 0ull; j < bmr_out->GetNumOfSIMDValues(); ++j) {
      for (auto k = 0ull; k < GetConfig()->GetNumOfParties(); ++k) {
        bmr_out->GetMutablePublicKeys().at(k).at(j) = (bmr_in->GetPublicKeys().at(k).at(j));
      }
      bmr_out->GetMutablePublicValues() = bmr_in->GetPublicValues();
    }
  }

  auto ptr_backend = backend_.lock();
  assert(ptr_backend);

  ptr_backend->GetRegister()->IncrementEvaluatedGatesCounter();

  SetOnlineIsReady();

  if constexpr (MOTION_DEBUG) {
    auto ptr_backend = backend_.lock();
    assert(ptr_backend);
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Finished evaluating online phase of BMR INV Gate with id#{}", gate_id_));
  }
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

BMRANDGate::BMRANDGate(const Shares::SharePtr &a, const Shares::SharePtr &b) {
  parent_a_ = a->GetWires();
  parent_b_ = b->GetWires();

  assert(parent_a_.size() > 0);
  assert(parent_a_.size() == parent_b_.size());
  assert(parent_a_.at(0)->GetBitLength() > 0);
  assert(parent_a_.at(0)->GetProtocol() == parent_b_.at(0)->GetProtocol());
  assert(parent_a_.at(0)->GetProtocol() == MPCProtocol::BMR);

  backend_ = parent_a_.at(0)->GetBackend();
  auto ptr_backend = backend_.lock();
  assert(ptr_backend);

  requires_online_interaction_ = true;
  gate_type_ = GateType::InteractiveGate;

  gate_id_ = ptr_backend->GetRegister()->NextGateId();

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
    ptr_backend->GetRegister()->RegisterNextWire(w);
  }

  s_ots_1_.resize(GetConfig()->GetNumOfParties());
  for (auto &v : s_ots_1_) v.resize(output_wires_.size());
  s_ots_kappa_.resize(GetConfig()->GetNumOfParties());
  for (auto &v : s_ots_kappa_) v.resize(output_wires_.size());
  r_ots_1_.resize(GetConfig()->GetNumOfParties());
  for (auto &v : r_ots_1_) v.resize(output_wires_.size());
  r_ots_kappa_.resize(GetConfig()->GetNumOfParties());
  for (auto &v : r_ots_kappa_) v.resize(output_wires_.size());

  constexpr auto XCOT{ENCRYPTO::ObliviousTransfer::OTProtocol::XCOT};
  const auto n_simd{parent_a_.at(0)->GetNumOfSIMDValues()};
  const auto batch_size_full{n_simd * 4};
  const auto batch_size_3{n_simd * 3};
  const auto my_id{GetConfig()->GetMyId()};
  const auto num_parties{GetConfig()->GetNumOfParties()};
  for (auto i = 0ull; i < output_wires_.size(); ++i) {
    for (auto pid = 0ull; pid < num_parties; ++pid) {
      if (pid == my_id) continue;
      s_ots_1_.at(pid).at(i) = GetOTProvider(pid)->RegisterSend(1, batch_size_3, XCOT);
      s_ots_kappa_.at(pid).at(i) = GetOTProvider(pid)->RegisterSend(kappa, batch_size_3, XCOT);
      r_ots_1_.at(pid).at(i) = GetOTProvider(pid)->RegisterReceive(1, batch_size_3, XCOT);
      r_ots_kappa_.at(pid).at(i) = GetOTProvider(pid)->RegisterReceive(kappa, batch_size_3, XCOT);
    }
  }

  garbled_rows_.resize(GetConfig()->GetNumOfParties());
  for (auto &vv : garbled_rows_) {
    vv.resize(output_wires_.size());
    for (auto &v : vv) {
      v.resize(batch_size_full);
      for (auto &bv : v) bv = ENCRYPTO::BitVector<>(kappa);
    }
  }
  received_garbled_rows_.resize(GetConfig()->GetNumOfParties());

  for (auto party_id = 0ull; party_id < GetConfig()->GetNumOfParties(); ++party_id) {
    if (party_id == GetConfig()->GetMyId()) continue;
    auto &data = GetConfig()->GetCommunicationContext(party_id)->GetDataStorage()->GetBMRData();
    auto elem =
        data->garbled_rows_
            .emplace(gate_id_,
                     std::pair<std::size_t, std::promise<std::unique_ptr<ENCRYPTO::BitVector<>>>>())
            .first;
    auto &bitlen = std::get<0>(elem->second);
    bitlen = output_wires_.size() * batch_size_full * kappa * num_parties;
  }

  if constexpr (MOTION_DEBUG) {
    auto gate_info = fmt::format("gate id {}, parents: {}, {}", gate_id_,
                                 parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Created a BMR AND gate with following properties: {}", gate_info));
  }
}

void BMRANDGate::GenerateRandomness() {
  const auto &R{GetConfig()->GetBMRRandomOffset()};
  const auto n_simd{parent_a_.at(0)->GetNumOfSIMDValues()};
  const auto my_id{GetConfig()->GetMyId()};
  for (auto wire_i = 0ull; wire_i < output_wires_.size(); ++wire_i) {
    auto bmr_out{std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(wire_i))};
    assert(bmr_out);
    bmr_out->GetMutablePermutationBits() = ENCRYPTO::BitVector<>::Random(n_simd);
    for (auto simd_i = 0ull; simd_i < n_simd; ++simd_i) {
      auto &key_0{std::get<0>(bmr_out->GetMutableSecretKeys()).at(simd_i)};
      auto &key_1{std::get<1>(bmr_out->GetMutableSecretKeys()).at(simd_i)};
      key_0 = ENCRYPTO::BitVector<>::Random(kappa);
      key_1 = key_0 ^ R;

      if constexpr (MOTION_VERBOSE_DEBUG) {
        auto bmr_a = std::dynamic_pointer_cast<Wires::BMRWire>(parent_a_.at(wire_i));
        auto bmr_b = std::dynamic_pointer_cast<Wires::BMRWire>(parent_b_.at(wire_i));
        assert(bmr_a);
        assert(bmr_b);
        MOTION::Helpers::WaitFor(*bmr_a->GetSetupReadyCondition());
        MOTION::Helpers::WaitFor(*bmr_b->GetSetupReadyCondition());
        auto ptr_backend{backend_.lock()};
        assert(ptr_backend);
        ptr_backend->GetLogger()->LogTrace(fmt::format(
            "Gate#{} (BMR AND gate) Party#{} wire_i {} simd_i {} perm_bits (a {} b {} out {}) key0 "
            "{} key 1 {}\n",
            gate_id_, my_id, wire_i, simd_i, bmr_a->GetPermutationBits().AsString(),
            bmr_b->GetPermutationBits().AsString(), bmr_out->GetPermutationBits().AsString(),
            key_0.AsString(), key_1.AsString()));
      }
    }
    bmr_out->SetSetupIsReady();
  }
}

void BMRANDGate::EvaluateSetup() {
  if constexpr (MOTION_DEBUG) {
    auto ptr_backend = backend_.lock();
    assert(ptr_backend);
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Start evaluating setup phase of BMR AND Gate with id#{}", gate_id_));
  }
  const auto &R{GetConfig()->GetBMRRandomOffset()};
  const auto n_simd{parent_a_.at(0)->GetNumOfSIMDValues()};
  const auto my_id{GetConfig()->GetMyId()};
  const auto num_parties{GetConfig()->GetNumOfParties()};
  const auto batch_size_full{n_simd * 4};
  const auto batch_size_3{n_simd * 3};

  for (auto party_id = 0ull; party_id < num_parties; ++party_id) {
    if (party_id == my_id) continue;
    auto &bmr_data = GetConfig()->GetCommunicationContext(party_id)->GetDataStorage()->GetBMRData();
    received_garbled_rows_.at(party_id) =
        bmr_data->garbled_rows_.at(static_cast<std::size_t>(gate_id_)).second.get_future();
  }

  std::vector<std::vector<std::vector<ENCRYPTO::BitVector<>>>> r_out(num_parties),
      s_out(num_parties);
  for (auto &v : r_out) v.resize(output_wires_.size());
  for (auto &v : s_out) v.resize(output_wires_.size());

  std::vector<std::vector<ENCRYPTO::BitVector<>>> choices(num_parties);
  for (auto &v : choices) v.resize(output_wires_.size());

  const std::vector<ENCRYPTO::BitVector<>> R_for_OTs(
      batch_size_3, ENCRYPTO::BitVector<>(R.GetData().data(), kappa));

  if constexpr (MOTION_VERBOSE_DEBUG) {
    auto ptr_backend{backend_.lock()};
    assert(ptr_backend);
    ptr_backend->GetLogger()->LogTrace(
        fmt::format("Gate#{} (BMR AND gate) Party#{} R {}\n", gate_id_, my_id, R.AsString()));
  }

  GenerateRandomness();

  for (auto wire_i = 0ull; wire_i < output_wires_.size(); ++wire_i) {
    auto bmr_out{std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(wire_i))};
    auto bmr_a{std::dynamic_pointer_cast<Wires::BMRWire>(parent_a_.at(wire_i))};
    auto bmr_b{std::dynamic_pointer_cast<Wires::BMRWire>(parent_b_.at(wire_i))};
    assert(bmr_out);
    assert(bmr_a);
    assert(bmr_b);
    MOTION::Helpers::WaitFor(*bmr_a->GetSetupReadyCondition());
    MOTION::Helpers::WaitFor(*bmr_b->GetSetupReadyCondition());
    const bool permutation{(bmr_out->GetWireId() % GetConfig()->GetNumOfParties()) ==
                           GetConfig()->GetMyId()};

    ENCRYPTO::BitVector<> a_bv, b_bv;
    for (auto simd_i = 0ull; simd_i < n_simd; ++simd_i) {
      const bool a = bmr_a->GetPermutationBits()[simd_i];
      const bool b = bmr_b->GetPermutationBits()[simd_i];
      a_bv.Append(a);
      a_bv.Append(a);
      a_bv.Append(a != permutation);
      b_bv.Append(b);
      b_bv.Append(b != permutation);
      b_bv.Append(b);
    }

    for (auto party_id = 0ull; party_id < num_parties; ++party_id) {
      if (party_id == my_id) {
        choices.at(party_id).at(wire_i) = a_bv & b_bv;
        continue;
      }

      auto &r_ot_1{r_ots_1_.at(party_id).at(wire_i)};
      auto &s_ot_1{s_ots_1_.at(party_id).at(wire_i)};
      std::vector<ENCRYPTO::BitVector<>> s_v;
      s_v.reserve(a_bv.GetSize());

      if constexpr (MOTION_VERBOSE_DEBUG) {
        auto ptr_backend{backend_.lock()};
        assert(ptr_backend);
        ptr_backend->GetLogger()->LogTrace(fmt::format(
            "Gate#{} (BMR AND gate)  Party#{}-#{} bit-C-OTs wire_i {} perm_bits {} bits_a {} from "
            "{} bits_b {} from {} a&b {}\n",
            gate_id_, my_id, party_id, wire_i, bmr_out->GetPermutationBits().AsString(),
            a_bv.AsString(), bmr_a->GetPermutationBits().AsString(), b_bv.AsString(),
            bmr_b->GetPermutationBits().AsString(), choices.at(party_id).at(wire_i).AsString()));
      }
      // compute C-OTs for the real value, ie, b = (lambda_u ^ alpha) * (lambda_v ^ beta)
      for (auto j = 0ull; j < a_bv.GetSize(); ++j) s_v.emplace_back(ENCRYPTO::BitVector<>(a_bv[j]));

      s_ot_1->WaitSetup();
      r_ot_1->WaitSetup();

      s_ot_1->SetInputs(s_v);
      r_ot_1->SetChoices(b_bv);

      s_ot_1->SendMessages();
      r_ot_1->SendCorrections();
    }
  }

  for (auto wire_i = 0ull; wire_i < output_wires_.size(); ++wire_i) {
    auto bmr_out{std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(wire_i))};
    auto bmr_a{std::dynamic_pointer_cast<Wires::BMRWire>(parent_a_.at(wire_i))};
    auto bmr_b{std::dynamic_pointer_cast<Wires::BMRWire>(parent_b_.at(wire_i))};
    assert(bmr_out);
    assert(bmr_a);
    assert(bmr_b);
    for (auto party_id = 0ull; party_id < num_parties; ++party_id) {
      if (party_id == my_id) continue;
      auto &r_ot_1{r_ots_1_.at(party_id).at(wire_i)};
      auto &s_ot_1{s_ots_1_.at(party_id).at(wire_i)};

      const auto &r = r_ot_1->GetOutputs();
      const auto &s = s_ot_1->GetOutputs();

      ENCRYPTO::BitVector<> r_bv, s_bv;
      for (auto i = 0ull; i < r.size(); ++i) {
        r_bv.Append(r.at(i)[0]);
        s_bv.Append(s.at(i).Subset(0, 1)[0]);
      }
      choices.at(party_id).at(wire_i) = r_bv ^ s_bv;

      if constexpr (MOTION_VERBOSE_DEBUG) {
        const auto &r_bv_check = r_ot_1->GetChoices();
        const auto &s_v_check = s_ot_1->GetInputs();
        ENCRYPTO::BitVector<> s_bv_check;
        for (auto i = 0ull; i < s_v_check.size(); ++i) s_bv_check.Append(s_v_check.at(i));
        auto ptr_backend{backend_.lock()};
        assert(ptr_backend);
        ptr_backend->GetLogger()->LogTrace(fmt::format(
            "Gate#{} (BMR AND gate) Party#{}-#{} bit-C-OTs wire_i {} bits from C-OTs r {} s {} "
            "result {} (r {} s {})\n",
            gate_id_, GetConfig()->GetMyId(), party_id, wire_i, r_bv.AsString(), s_bv.AsString(),
            choices.at(party_id).at(wire_i).AsString(), r_bv_check.AsString(),
            s_bv_check.AsString()));
      }
    }
  }

  ENCRYPTO::PRG prg;
  prg.SetKey(GetConfig()->GetFixedAESKey().GetData().data());

  std::vector<ENCRYPTO::BitVector<>> aggregated_choices(output_wires_.size());

  for (auto wire_i = 0ull; wire_i < output_wires_.size(); ++wire_i) {
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
      s_ots_kappa_.at(party_id).at(wire_i)->SetInputs(R_for_OTs);
      s_ots_kappa_.at(party_id).at(wire_i)->SendMessages();
      r_ots_kappa_.at(party_id).at(wire_i)->SetChoices(aggregated_choices.at(wire_i));
      r_ots_kappa_.at(party_id).at(wire_i)->SendCorrections();
    }
  }

  for (auto wire_i = 0ull; wire_i < output_wires_.size(); ++wire_i) {
    auto bmr_out{std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(wire_i))};
    assert(bmr_out);
    const auto bmr_a{std::dynamic_pointer_cast<Wires::BMRWire>(parent_a_.at(wire_i))};
    const auto bmr_b{std::dynamic_pointer_cast<Wires::BMRWire>(parent_b_.at(wire_i))};
    assert(bmr_a);
    assert(bmr_b);

    for (auto simd_i = 0ull; simd_i < n_simd; ++simd_i) {
      const auto &key_a_0{std::get<0>(bmr_a->GetSecretKeys()).at(simd_i)};
      const auto &key_a_1{std::get<1>(bmr_a->GetSecretKeys()).at(simd_i)};
      const auto &key_b_0{std::get<0>(bmr_b->GetSecretKeys()).at(simd_i)};
      const auto &key_b_1{std::get<1>(bmr_b->GetSecretKeys()).at(simd_i)};

      for (auto p_id_i = 0ull; p_id_i < num_parties; ++p_id_i) {
        uint128_t plaintext{p_id_i};
        plaintext <<= 64;
        plaintext += static_cast<uint64_t>(bmr_out->GetWireId() + simd_i);

        ENCRYPTO::BitVector<> mask_a_0(prg.FixedKeyAES(key_a_0.GetData().data(), plaintext), kappa);
        ENCRYPTO::BitVector<> mask_a_1(prg.FixedKeyAES(key_a_1.GetData().data(), plaintext), kappa);
        ENCRYPTO::BitVector<> mask_b_0(prg.FixedKeyAES(key_b_0.GetData().data(), plaintext), kappa);
        ENCRYPTO::BitVector<> mask_b_1(prg.FixedKeyAES(key_b_1.GetData().data(), plaintext), kappa);

        if constexpr (MOTION_VERBOSE_DEBUG) {
          auto ptr_backend{backend_.lock()};
          assert(ptr_backend);
          ptr_backend->GetLogger()->LogTrace(fmt::format(
              "Gate#{} (BMR AND gate) Party#{} keys: a0 {} ({}) a1 {} ({}) b0 {} ({}) b1 {} ({})\n",
              gate_id_, my_id, key_a_0.AsString(), mask_a_0.AsString(), key_a_1.AsString(),
              mask_a_1.AsString(), key_b_0.AsString(), mask_b_0.AsString(), key_b_1.AsString(),
              mask_b_1.AsString()));
        }

        auto &garbled_row_00{garbled_rows_.at(p_id_i).at(wire_i).at(simd_i * 4)};
        auto &garbled_row_01{garbled_rows_.at(p_id_i).at(wire_i).at(simd_i * 4 + 1)};
        auto &garbled_row_10{garbled_rows_.at(p_id_i).at(wire_i).at(simd_i * 4 + 2)};
        auto &garbled_row_11{garbled_rows_.at(p_id_i).at(wire_i).at(simd_i * 4 + 3)};
        if (p_id_i == GetConfig()->GetMyId()) {
          const auto &key_w_0{std::get<0>(bmr_out->GetSecretKeys()).at(simd_i)};
          garbled_row_00 = mask_a_0 ^ mask_b_0 ^ key_w_0;
          garbled_row_01 = mask_a_0 ^ mask_b_1 ^ key_w_0;
          garbled_row_10 = mask_a_1 ^ mask_b_0 ^ key_w_0;
          garbled_row_11 = mask_a_1 ^ mask_b_1 ^ key_w_0 ^ R;

          if constexpr (MOTION_VERBOSE_DEBUG) {
            auto ptr_backend{backend_.lock()};
            assert(ptr_backend);
            ptr_backend->GetLogger()->LogTrace(
                fmt::format(
                    "Gate#{} (BMR AND gate) Party#{} (me {}) gr00 mask_a_0 {} XOR mask_b_0 {} XOR "
                    "key_w_0 {} = {}\n",
                    gate_id_, p_id_i, my_id, mask_a_0.AsString(), mask_b_0.AsString(),
                    key_w_0.AsString(), garbled_row_00.AsString()) +
                fmt::format(
                    "Gate#{} (BMR AND gate) Party#{} (me {}) gr01 mask_a_0 {} XOR mask_b_0 {} XOR "
                    "key_w_1 {} = {}\n",
                    gate_id_, p_id_i, my_id, mask_a_0.AsString(), mask_b_1.AsString(),
                    key_w_0.AsString(), garbled_row_01.AsString()) +
                fmt::format(
                    "Gate#{} (BMR AND gate) Party#{} (me {}) gr10 mask_a_0 {} XOR mask_b_0 {} XOR "
                    "key_w_0 {} = {}\n",
                    gate_id_, p_id_i, my_id, mask_a_1.AsString(), mask_b_0.AsString(),
                    key_w_0.AsString(), garbled_row_10.AsString()) +
                fmt::format(
                    "Gate#{} (BMR AND gate) Party#{} (me {}) gr11 mask_a_1 {} XOR mask_b_1 {} XOR "
                    "key_w_1 {} XOR R {} = {}\n",
                    gate_id_, p_id_i, my_id, mask_a_1.AsString(), mask_b_1.AsString(),
                    key_w_0.AsString(), R.AsString(), garbled_row_11.AsString()));
          }
        } else {
          garbled_row_00 = mask_a_0 ^ mask_b_0;
          garbled_row_01 = mask_a_0 ^ mask_b_1;
          garbled_row_10 = mask_a_1 ^ mask_b_0;
          garbled_row_11 = mask_a_1 ^ mask_b_1;
          if (MOTION_VERBOSE_DEBUG) {
            auto ptr_backend{backend_.lock()};
            assert(ptr_backend);
            ptr_backend->GetLogger()->LogTrace(
                fmt::format("Gate#{} (BMR AND gate) Party#{} (me {}) gr00 mask_a_0 {} XOR mask_b_0 "
                            "{} = {}\n",
                            gate_id_, p_id_i, my_id, mask_a_0.AsString(), mask_b_0.AsString(),
                            garbled_row_00.AsString()) +
                fmt::format("Gate#{} (BMR AND gate) Party#{} (me {}) gr01 mask_a_0 {} XOR mask_b_1 "
                            "{} = {}\n",
                            gate_id_, p_id_i, my_id, mask_a_0.AsString(), mask_b_1.AsString(),
                            garbled_row_01.AsString()) +
                fmt::format("Gate#{} (BMR AND gate) Party#{} (me {}) gr10 mask_a_1 {} XOR mask_b_0 "
                            "{} = {}\n",
                            gate_id_, p_id_i, my_id, mask_a_1.AsString(), mask_b_0.AsString(),
                            garbled_row_10.AsString()) +
                fmt::format("Gate#{} (BMR AND gate) Party#{} (me {}) gr11 mask_a_1 {} XOR mask_b_1 "
                            "{} = {}\n",
                            gate_id_, p_id_i, my_id, mask_a_1.AsString(), mask_b_1.AsString(),
                            garbled_row_11.AsString()));
          }
        }

        std::array<ENCRYPTO::AlignedBitVector, 3> shared_R;
        const ENCRYPTO::AlignedBitVector zero_bv(kappa);

        if (p_id_i == my_id) {
          shared_R.at(0) = aggregated_choices.at(wire_i)[simd_i * 3] ? R : zero_bv;
          shared_R.at(1) = aggregated_choices.at(wire_i)[simd_i * 3 + 1] ? R : zero_bv;
          shared_R.at(2) = aggregated_choices.at(wire_i)[simd_i * 3 + 2] ? R : zero_bv;
        } else {
          shared_R.at(0) = shared_R.at(1) = shared_R.at(2) = zero_bv;
        }

        // R's from C-OTs
        if (p_id_i == my_id) {
          for (auto p_id_j = 0ull; p_id_j < num_parties; ++p_id_j) {
            if (p_id_j == my_id) continue;

            const auto &s_out = s_ots_kappa_.at(p_id_j).at(wire_i)->GetOutputs();
            const auto R_00 = s_out.at(simd_i * 3).Subset(0, kappa);
            const auto R_01 = s_out.at(simd_i * 3 + 1).Subset(0, kappa);
            const auto R_10 = s_out.at(simd_i * 3 + 2).Subset(0, kappa);

            shared_R.at(0) ^= R_00;
            shared_R.at(1) ^= R_01;
            shared_R.at(2) ^= R_10;

            if (MOTION_VERBOSE_DEBUG) {
              auto ptr_backend{backend_.lock()};
              assert(ptr_backend);
              ptr_backend->GetLogger()->LogTrace(fmt::format(
                  "Gate#{} (BMR AND gate) Me#{}: Party#{} received R's \n00 ({}) \n01 ({}) \n10 "
                  "({})\n",
                  gate_id_, my_id, p_id_i, R_00.AsString(), R_01.AsString(), R_10.AsString()));
            }
          }
        } else {
          const auto &r_out = r_ots_kappa_.at(p_id_i).at(wire_i)->GetOutputs();
          const auto &R_00{r_out.at(simd_i * 3)};
          const auto &R_01{r_out.at(simd_i * 3 + 1)};
          const auto &R_10{r_out.at(simd_i * 3 + 2)};

          shared_R.at(0) ^= R_00;
          shared_R.at(1) ^= R_01;
          shared_R.at(2) ^= R_10;
        }

        if constexpr (MOTION_VERBOSE_DEBUG) {
          auto ptr_backend{backend_.lock()};
          assert(ptr_backend);
          ptr_backend->GetLogger()->LogTrace(
              fmt::format("Gate#{} (BMR AND gate) Me#{}: Shared R's \n00 ({}) \n01 ({}) \n10 "
                          "({})\n",
                          gate_id_, my_id, p_id_i, shared_R.at(0).AsString(),
                          shared_R.at(1).AsString(), shared_R.at(2).AsString()));
        }
        garbled_row_00 ^= shared_R.at(0);
        garbled_row_01 ^= shared_R.at(1);
        garbled_row_10 ^= shared_R.at(2);
        garbled_row_11 ^= shared_R.at(0) ^ shared_R.at(1) ^ shared_R.at(2);
      }
    }
  }

  ENCRYPTO::BitVector<> buffer;
  if constexpr (MOTION_VERBOSE_DEBUG) {
    std::string s{fmt::format("Me#{}: ", my_id)};
    for (auto i = 0ull; i < garbled_rows_.size(); ++i) {
      s.append(fmt::format("\nParty #{}: ", i));
      for (auto j = 0ull; j < garbled_rows_.at(i).size(); ++j) {
        s.append(fmt::format(" Wire #{}: ", j));
        for (auto k = 0ull; k < garbled_rows_.at(i).at(j).size(); ++k) {
          s.append(fmt::format("\nSIMD #{}: ", k));
          buffer.Append(garbled_rows_.at(i).at(j).at(k));
          s.append(fmt::format(" garbled rows {} ", garbled_rows_.at(i).at(j).at(k).AsString()));
        }
      }
    }
    s.append("\n");
    auto ptr_backend{backend_.lock()};
    assert(ptr_backend);
    ptr_backend->GetLogger()->LogTrace(s);
  } else {
    for (auto i = 0ull; i < garbled_rows_.size(); ++i) {
      for (auto j = 0ull; j < garbled_rows_.at(i).size(); ++j) {
        for (auto k = 0ull; k < garbled_rows_.at(i).at(j).size(); ++k) {
          buffer.Append(garbled_rows_.at(i).at(j).at(k));
        }
      }
    }
  }
  const std::vector<std::uint8_t> buffer_u8(
      reinterpret_cast<const std::uint8_t *>(buffer.GetData().data()),
      reinterpret_cast<const std::uint8_t *>(buffer.GetData().data()) + buffer.GetData().size());

  for (auto party_id = 0ull; party_id < num_parties; ++party_id) {
    if (party_id == my_id) continue;
    auto ptr_backend = backend_.lock();
    assert(ptr_backend);
    ptr_backend->Send(
        party_id, Communication::BuildBMRANDMessage(static_cast<std::size_t>(gate_id_), buffer_u8));
  }

  {
    for (auto pid_i = 0ull; pid_i < num_parties; ++pid_i) {
      if (pid_i == GetConfig()->GetMyId()) continue;
      auto gr = received_garbled_rows_.at(pid_i).get();
      for (auto pid_j = 0ull; pid_j < num_parties; ++pid_j) {
        for (auto wire_i = 0ull; wire_i < output_wires_.size(); ++wire_i) {
          for (auto simd_i = 0ull; simd_i < n_simd; ++simd_i) {
            for (auto gr_i = 0; gr_i < 4; ++gr_i) {
              // party offset
              const std::size_t offset_p = pid_j * (batch_size_full * kappa * output_wires_.size());
              // wire offset
              const std::size_t offset_w = wire_i * batch_size_full * kappa;
              // simd_offset
              const std::size_t offset_s = simd_i * 4 * kappa;
              // complete offset
              const std::size_t offset = offset_p + offset_w + offset_s + gr_i * kappa;
              garbled_rows_.at(pid_j).at(wire_i).at(simd_i * 4 + gr_i) ^=
                  gr->Subset(offset, offset + kappa);
            }
          }
        }
      }
    }
  }

  // mark this gate as setup-ready to proceed with the online phase
  SetSetupIsReady();
  if constexpr (MOTION_DEBUG) {
    auto ptr_backend{backend_.lock()};
    assert(ptr_backend);
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Finished evaluating setup phase of BMR AND Gate with id#{}", gate_id_));
  }
}  // namespace MOTION::Gates::BMR

void BMRANDGate::EvaluateOnline() {
  WaitSetup();

  auto backend = backend_.lock();
  assert(backend);

  const auto num_parties = GetConfig()->GetNumOfParties();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    for (auto i = 0ull; i < garbled_rows_.size(); ++i) {
      for (auto j = 0ull; j < garbled_rows_.at(i).size(); ++j) {
        for (auto k = 0ull; k < garbled_rows_.at(i).at(j).size(); ++k) {
          backend->GetLogger()->LogTrace(fmt::format(
              "Party#{}: reconstructed gr for Party#{} Wire#{} SIMD#{}: {}\n",
              GetConfig()->GetMyId(), i, j, k, garbled_rows_.at(i).at(j).at(k).AsString()));
        }
      }
    }
  }

  for (auto wire_i = 0ull; wire_i < output_wires_.size(); ++wire_i) {
    auto bmr_out = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(wire_i));
    assert(bmr_out);
    auto wire_a = std::dynamic_pointer_cast<Wires::BMRWire>(parent_a_.at(wire_i));
    auto wire_b = std::dynamic_pointer_cast<Wires::BMRWire>(parent_b_.at(wire_i));
    assert(wire_a);
    assert(wire_b);

    Helpers::WaitFor(*wire_a->GetIsReadyCondition());
    Helpers::WaitFor(*wire_b->GetIsReadyCondition());

    ENCRYPTO::PRG prg;
    prg.SetKey(GetConfig()->GetFixedAESKey().GetData().data());

    for (auto simd_i = 0ull; simd_i < bmr_out->GetNumOfSIMDValues(); ++simd_i) {
      std::vector<ENCRYPTO::BitVector<>> masks(num_parties, ENCRYPTO::BitVector<>(kappa));
      [[maybe_unused]] std::string s;
      if constexpr (MOTION_VERBOSE_DEBUG) {
        s.append(
            fmt::format("Me#{}: wire#{} simd#{} result\n", GetConfig()->GetMyId(), wire_i, simd_i));
        s.append(fmt::format("Public values a {} b {} ", wire_a->GetPublicValues().AsString(),
                             wire_b->GetPublicValues().AsString()));
      }
      for (auto party_i = 0ull; party_i < num_parties; ++party_i) {
        const ENCRYPTO::BitVector<> &key_a = wire_a->GetPublicKeys().at(party_i).at(simd_i);
        const ENCRYPTO::BitVector<> &key_b = wire_b->GetPublicKeys().at(party_i).at(simd_i);
        for (auto party_j = 0ull; party_j < num_parties; ++party_j) {
          uint128_t plaintext{party_j};
          plaintext <<= 64;
          plaintext += static_cast<uint64_t>(bmr_out->GetWireId() + simd_i);
          ENCRYPTO::BitVector<> mask_a(prg.FixedKeyAES(key_a.GetData().data(), plaintext), kappa);
          ENCRYPTO::BitVector<> mask_b(prg.FixedKeyAES(key_b.GetData().data(), plaintext), kappa);
          masks.at(party_j) ^= mask_a;
          masks.at(party_j) ^= mask_b;
          if constexpr (MOTION_VERBOSE_DEBUG) {
            s.append(fmt::format("\nParty#{} key for #{} key_a {} ({}) key_b {} ({})", party_i,
                                 party_j, key_a.AsString(), mask_a.AsString(), key_b.AsString(),
                                 mask_b.AsString()));
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
              garbled_rows_.at(party_i).at(wire_i).at(4 * simd_i + alpha_beta_offset).AsString(),
              masks.at(party_i).AsString()));
        }
        bmr_out->GetMutablePublicKeys().at(party_i).at(simd_i) =
            garbled_rows_.at(party_i).at(wire_i).at(4 * simd_i + alpha_beta_offset) ^
            masks.at(party_i);
        if constexpr (MOTION_VERBOSE_DEBUG) {
          s.append(bmr_out->GetPublicKeys().at(party_i).at(simd_i).AsString());
        }
      }
      if constexpr (MOTION_VERBOSE_DEBUG) {
        s.append("\n");
        s.append(fmt::format("output skey0 {} skey1 {}\n",
                             std::get<0>(bmr_out->GetSecretKeys()).at(simd_i).AsString(),
                             std::get<1>(bmr_out->GetSecretKeys()).at(simd_i).AsString()));
        backend->GetLogger()->LogTrace(s);
      }
    }

    for (auto simd_i = 0ull; simd_i < bmr_out->GetNumOfSIMDValues(); ++simd_i) {
      const bool neq = bmr_out->GetMutablePublicKeys().at(GetConfig()->GetMyId()).at(simd_i) !=
                       std::get<0>(bmr_out->GetSecretKeys()).at(simd_i);
      if (neq)
        assert(bmr_out->GetMutablePublicKeys().at(GetConfig()->GetMyId()).at(simd_i) ==
               std::get<1>(bmr_out->GetSecretKeys()).at(simd_i));
      bmr_out->GetMutablePublicValues().Set(neq, simd_i);
    }
    if constexpr (MOTION_VERBOSE_DEBUG) {
      backend->GetLogger()->LogTrace(fmt::format("Party#{} wire#{} public values result {}\n",
                                                 GetConfig()->GetMyId(), wire_i,
                                                 bmr_out->GetPublicValues().AsString()));
    }
  }

  backend->GetRegister()->IncrementEvaluatedGatesCounter();
  SetOnlineIsReady();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    backend->GetLogger()->LogTrace(fmt::format("Evaluated BMR AND Gate with id#{}", gate_id_));
  }
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
}