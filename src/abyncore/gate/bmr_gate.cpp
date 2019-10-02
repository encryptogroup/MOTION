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
#include "wire/bmr_wire.h"
#include "wire/boolean_gmw_wire.h"

namespace ABYN::Gates::BMR {

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
  auto ptr_backend = backend_.lock();
  assert(ptr_backend);

  if (static_cast<std::size_t>(input_owner_id_) >= ptr_backend->GetConfig()->GetNumOfParties()) {
    throw std::runtime_error(fmt::format("Invalid input owner: {} of {}", input_owner_id_,
                                         ptr_backend->GetConfig()->GetNumOfParties()));
  }

  gate_id_ = ptr_backend->GetRegister()->NextGateId();

  assert(input_.size() > 0u);           // assert >=1 wire
  assert(input_.at(0).GetSize() > 0u);  // assert >=1 SIMD bits
  // assert SIMD lengths of all wires are equal
  assert(ENCRYPTO::BitVector<>::EqualSizeDimensions(input_));

  output_wires_.reserve(input_.size());
  for (auto &v : input_) {
    auto wire = std::make_shared<Wires::BMRWire>(v.GetSize(), backend_);
    output_wires_.push_back(std::static_pointer_cast<ABYN::Wires::Wire>(wire));
  }

  for (auto &w : output_wires_) {
    ptr_backend->GetRegister()->RegisterNextWire(w);
  }

  received_public_keys_.resize(ptr_backend->GetConfig()->GetNumOfParties());

  assert(input_owner_id_ >= 0);
  assert(gate_id_ >= 0);
  const auto my_id = ptr_backend->GetConfig()->GetMyId();

  if (my_id != static_cast<std::size_t>(input_owner_id_)) {
    auto &data_storage = ptr_backend->GetConfig()
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

  for (auto i = 0ull; i < ptr_backend->GetConfig()->GetNumOfParties(); ++i) {
    if (my_id == i) continue;
    auto &data_storage = ptr_backend->GetConfig()->GetCommunicationContext(i)->GetDataStorage();
    auto &bmr_data = data_storage->GetBMRData();

    auto elem =
        bmr_data->input_public_keys_
            .emplace(gate_id_,
                     std::pair<std::size_t, std::promise<std::unique_ptr<ENCRYPTO::BitVector<>>>>())
            .first;
    auto &bitlen = std::get<0>(elem->second);
    bitlen = bits_ * input_.size() * kappa;
  }

  if constexpr (ABYN_DEBUG) {
    auto gate_info = fmt::format("gate id {}, input owner {}", gate_id_, input_owner_id_);
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Created a BMRInputGate with following properties: {}", gate_info));
  }
}

void BMRInputGate::EvaluateSetup() {
  auto ptr_backend = backend_.lock();
  assert(ptr_backend);

  const auto my_id = ptr_backend->GetConfig()->GetMyId();
  if (my_id != static_cast<std::size_t>(input_owner_id_)) {
    received_public_values_ =
        ptr_backend->GetConfig()
            ->GetCommunicationContext(static_cast<std::size_t>(input_owner_id_))
            ->GetDataStorage()
            ->GetBMRData()
            ->input_public_values_.at(static_cast<std::size_t>(gate_id_))
            .second.get_future();
  }

  for (auto i = 0ull; i < ptr_backend->GetConfig()->GetNumOfParties(); ++i) {
    if (my_id == i) continue;
    received_public_keys_.at(i) = ptr_backend->GetConfig()
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
      wire->GetMutablePermutationBits() = ENCRYPTO::BitVector<>(wire->GetNumOfParallelValues());
    }
    wire->SetSetupIsReady();
    if constexpr (ABYN_VERBOSE_DEBUG) {
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

      ptr_backend->GetLogger()->LogTrace(
          fmt::format("Created a BMR wire #{} with real values {} permutation bits {}, keys 0 {}, "
                      "and keys 1 {}",
                      wire->GetWireId(), input_.at(i).AsString(),
                      wire->GetPermutationBits().AsString(), keys_0, keys_1));
    }
  }
  SetSetupIsReady();
}

void BMRInputGate::EvaluateOnline() {
  assert(setup_is_ready_);

  auto ptr_backend = backend_.lock();
  assert(ptr_backend);

  const auto my_id = ptr_backend->GetConfig()->GetMyId();
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
    for (auto i = 0ull; i < ptr_backend->GetConfig()->GetNumOfParties(); ++i) {
      if (i == ptr_backend->GetConfig()->GetMyId()) continue;
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
    for (auto j = 0ull; j < wire->GetNumOfParallelValues(); ++j) {
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
  for (auto i = 0ull; i < ptr_backend->GetConfig()->GetNumOfParties(); ++i) {
    if (i == ptr_backend->GetConfig()->GetMyId()) continue;
    ptr_backend->Send(i, Communication::BuildBMRInput1Message(gate_id_, payload));
  }

  // parse published keys
  for (auto i = 0ull; i < ptr_backend->GetConfig()->GetNumOfParties(); ++i) {
    if (i == ptr_backend->GetConfig()->GetMyId()) {
      for (auto j = 0ull; j < output_wires_.size(); ++j) {
        auto wire = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(j));
        assert(wire);
        for (auto k = 0ull; k < wire->GetNumOfParallelValues(); ++k) {
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
        for (auto k = 0ull; k < wire->GetNumOfParallelValues(); ++k) {
          wire->GetMutablePublicKeys().at(i).at(k) =
              buffer.Subset((j * bits_ + k) * kappa, (j * bits_ + k + 1) * kappa);
        }
      }
    }
  }

  ptr_backend->GetRegister()->IncrementEvaluatedGatesCounter();
  if constexpr (ABYN_VERBOSE_DEBUG) {
    std::string s(fmt::format("Evaluated a BMR input gate #{} and got as result: ", gate_id_));
    for (auto i = 0ull; i < output_wires_.size(); ++i) {
      auto wire = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(i));
      std::string keys;
      assert(ABYN::Helpers::Compare::Dimensions(wire->GetPublicKeys()));
      for (auto j = 0ull; j < ptr_backend->GetConfig()->GetNumOfParties(); ++j) {
        keys.append(std::to_string(j) + std::string(" "));
        for (const auto &key : wire->GetPublicKeys().at(j)) {
          keys.append(key.AsString() + " ");
        }
      }
      if (!keys.empty()) keys.erase(keys.size() - 1);
      s.append(fmt::format("wire #{} with public bits {} and public keys {}\n", wire->GetWireId(),
                           wire->GetPublicValues().AsString(), keys));
    }
    ptr_backend->GetLogger()->LogTrace(s);
  }
  SetOnlineIsReady();
}

const Shares::BMRSharePtr BMRInputGate::GetOutputAsBMRShare() {
  auto result = std::make_shared<Shares::BMRShare>(output_wires_);
  assert(result);
  return result;
}

BMROutputGate::BMROutputGate(const Shares::SharePtr &parent, std::size_t output_owner) {
  assert(!setup_is_ready_);
  assert(!online_is_ready_);
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
  const ENCRYPTO::BitVector<> dummy_bv(parent_.at(0)->GetNumOfParallelValues());

  for (auto &w : dummy_wires) {
    w = std::make_shared<Wires::GMWWire>(dummy_bv, backend_);
    ptr_backend->GetRegister()->RegisterNextWire(w);
  }

  gmw_out_share_ = std::make_shared<Shares::GMWShare>(dummy_wires);
  out_ = std::make_shared<ABYN::Gates::GMW::GMWOutputGate>(gmw_out_share_);
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
    output_wires_.push_back(std::static_pointer_cast<ABYN::Wires::Wire>(
        std::make_shared<Wires::BMRWire>(bv, ptr_backend)));
  }

  for (auto &wire : output_wires_) {
    ptr_backend->GetRegister()->RegisterNextWire(wire);
  }

  if constexpr (ABYN_DEBUG) {
    auto gate_info =
        fmt::format("bitlength {}, gate id {}, owner {}", output_.size(), gate_id_, output_owner_);
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Created a BMR OutputGate with following properties: {}", gate_info));
  }
}

void BMROutputGate::EvaluateSetup() { SetSetupIsReady(); }

void BMROutputGate::EvaluateOnline() {
  assert(!online_is_ready_);
  WaitSetup();
  assert(setup_is_ready_);
  auto ptr_backend = backend_.lock();
  assert(ptr_backend);

  std::size_t i;

  if constexpr (ABYN_DEBUG) {
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Starting online phase evaluation for BMR OutputGate with id#{}", gate_id_));
  }

  auto &wires = gmw_out_share_->GetMutableWires();
  for (i = 0; i < wires.size(); ++i) {
    const auto bmr_wire = std::dynamic_pointer_cast<Wires::BMRWire>(parent_.at(i));
    ABYN::Helpers::WaitFor(*bmr_wire->GetIsReadyCondition());
    auto gmw_wire = std::dynamic_pointer_cast<Wires::GMWWire>(wires.at(i));
    assert(bmr_wire);
    assert(gmw_wire);
    gmw_wire->GetMutableValues() = bmr_wire->GetPermutationBits();
    gmw_wire->SetOnlineFinished();
  }

  for (i = 0; i < output_wires_.size(); ++i) {
    const auto bmr_wire = std::dynamic_pointer_cast<Wires::BMRWire>(parent_.at(i));
    auto gmw_wire = std::dynamic_pointer_cast<Wires::GMWWire>(out_->GetOutputWires().at(i));
    ABYN::Helpers::WaitFor(*gmw_wire->GetIsReadyCondition());
    assert(bmr_wire);
    assert(gmw_wire);
    assert(bmr_wire->GetPublicValues().GetSize() == gmw_wire->GetValues().GetSize());
    output_.at(i) = bmr_wire->GetPublicValues() ^ gmw_wire->GetValues();
    auto wire = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(i));
    assert(wire);
    wire->GetMutablePublicValues() = output_.at(i);
  }

  if constexpr (ABYN_DEBUG) {
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
  const ENCRYPTO::BitVector tmp_bv(a->GetNumOfParallelValues());
  for (auto &w : output_wires_) {
    w = std::make_shared<Wires::BMRWire>(tmp_bv, backend_);
    ptr_backend->GetRegister()->RegisterNextWire(w);
  }

  if constexpr (ABYN_DEBUG) {
    auto gate_info = fmt::format("gate id {}, parents: {}, {}", gate_id_,
                                 parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Created a BMR XOR gate with following properties: {}", gate_info));
  }
}

void BMRXORGate::EvaluateSetup() {
  if constexpr (ABYN_DEBUG) {
    auto ptr_backend = backend_.lock();
    assert(ptr_backend);
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Starting setup phase evaluation for BMR XORGate with id#{}", gate_id_));
  }

  for (auto i = 0ull; i < output_wires_.size(); ++i) {
    auto bmr_out = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(i));
    auto bmr_a = std::dynamic_pointer_cast<Wires::BMRWire>(parent_a_.at(i));
    auto bmr_b = std::dynamic_pointer_cast<Wires::BMRWire>(parent_b_.at(i));
    assert(bmr_out);
    assert(bmr_a);
    assert(bmr_b);
    ABYN::Helpers::WaitFor(*bmr_a->GetSetupReadyCondition());
    ABYN::Helpers::WaitFor(*bmr_b->GetSetupReadyCondition());
    bmr_out->GetMutablePermutationBits() =
        bmr_a->GetPermutationBits() ^ bmr_b->GetPermutationBits();
    const auto &R = GetConfig()->GetBMRRandomOffset();
    const auto &a0 = std::get<0>(bmr_a->GetSecretKeys());
    const auto &b0 = std::get<0>(bmr_b->GetSecretKeys());
    auto &out0 = std::get<0>(bmr_out->GetMutableSecretKeys());
    auto &out1 = std::get<1>(bmr_out->GetMutableSecretKeys());
    for (auto j = 0ull; j < bmr_out->GetNumOfParallelValues(); ++j) {
      out0.at(j) = a0.at(j) ^ b0.at(j);
      out1.at(j) = out0.at(j) ^ R;
    }
    bmr_out->SetSetupIsReady();
  }
  SetSetupIsReady();
  if constexpr (ABYN_DEBUG) {
    auto ptr_backend = backend_.lock();
    assert(ptr_backend);
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Finished setup phase evaluation for BMR XORGate with id#{}", gate_id_));
  }
}

void BMRXORGate::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);
  assert(!online_is_ready_);
  if constexpr (ABYN_DEBUG) {
    auto ptr_backend = backend_.lock();
    assert(ptr_backend);
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Starting online phase evaluation for BMR XORGate with id#{}", gate_id_));
  }

  for (auto i = 0ull; i < parent_a_.size(); ++i) {
    auto wire_a = std::dynamic_pointer_cast<Wires::BMRWire>(parent_a_.at(i));
    auto wire_b = std::dynamic_pointer_cast<Wires::BMRWire>(parent_b_.at(i));

    assert(wire_a);
    assert(wire_b);

    auto bmr_wire = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(i));
    assert(bmr_wire);

    Helpers::WaitFor(*wire_a->GetIsReadyCondition());    Helpers::WaitFor(*wire_b->GetIsReadyCondition());

    for (auto j = 0ull; j < bmr_wire->GetNumOfParallelValues(); ++j) {
      for (auto k = 0ull; k < GetConfig()->GetNumOfParties(); ++k) {
        bmr_wire->GetMutablePublicKeys().at(k).at(j) =
            (wire_a->GetPublicKeys().at(k).at(j) ^ wire_b->GetPublicKeys().at(k).at(j));
      }
      bmr_wire->GetMutablePublicValues() = wire_a->GetPublicValues() ^ wire_b->GetPublicValues();
    }
  }

  auto ptr_backend = backend_.lock();
  assert(ptr_backend);

  ptr_backend->GetRegister()->IncrementEvaluatedGatesCounter();

  SetOnlineIsReady();

  if constexpr (ABYN_DEBUG) {
    auto ptr_backend = backend_.lock();
    assert(ptr_backend);
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Finished online phase evaluation for BMR XORGate with id#{}", gate_id_));
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

  const ENCRYPTO::BitVector<> dummy_bv(a->GetNumOfParallelValues());
  std::vector<Wires::WirePtr> dummy_wires_e(parent_a_.size()), dummy_wires_d(parent_a_.size());

  for (auto &w : dummy_wires_d) {
    w = std::make_shared<Wires::BMRWire>(dummy_bv, backend_);
    ptr_backend->GetRegister()->RegisterNextWire(w);
  }

  for (auto &w : dummy_wires_e) {
    w = std::make_shared<Wires::BMRWire>(dummy_bv, backend_);
    ptr_backend->GetRegister()->RegisterNextWire(w);
  }

  // d_ = std::make_shared<Shares::GMWShare>(dummy_wires_d);
  // e_ = std::make_shared<Shares::GMWShare>(dummy_wires_e);

  // d_out_ = std::make_shared<BMROutputGate>(d_);
  // e_out_ = std::make_shared<BMROutputGate>(e_);

  // GetRegister()->RegisterNextGate(d_out_);
  // GetRegister()->RegisterNextGate(e_out_);

  /* gate_id_ = ptr_backend->GetRegister()->NextGateId();

   for (auto &wire : parent_a_) {
     RegisterWaitingFor(wire->GetWireId());
     wire->RegisterWaitingGate(gate_id_);
   }

   for (auto &wire : parent_b_) {
     RegisterWaitingFor(wire->GetWireId());
     wire->RegisterWaitingGate(gate_id_);
   }

   output_wires_.resize(parent_a_.size());
   for (auto &w : output_wires_) {
     w = std::make_shared<Wires::GMWWire>(dummy_bv, backend_);
     ptr_backend->GetRegister()->RegisterNextWire(w);
   }

   auto backend = backend_.lock();
   assert(backend);

   auto &mt_provider = backend->GetMTProvider();
   mt_bitlen_ = parent_a_.size() * parent_a_.at(0)->GetNumOfParallelValues();
   mt_offset_ = mt_provider->RequestBinaryMTs(mt_bitlen_);
 */
  if constexpr (ABYN_DEBUG) {
    auto gate_info = fmt::format("gate id {}, parents: {}, {}", gate_id_,
                                 parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Created a BMR AND gate with following properties: {}", gate_info));
  }
}

void BMRANDGate::EvaluateSetup() {}

void BMRANDGate::EvaluateOnline() {
  for (auto &wire : parent_a_) {
    Helpers::WaitFor(*wire->GetIsReadyCondition());
  }

  for (auto &wire : parent_b_) {
    Helpers::WaitFor(*wire->GetIsReadyCondition());
  }

  auto backend = backend_.lock();
  assert(backend);

  // TODO

  SetOnlineIsReady();
  backend->GetRegister()->IncrementEvaluatedGatesCounter();

  if constexpr (ABYN_VERBOSE_DEBUG) {
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