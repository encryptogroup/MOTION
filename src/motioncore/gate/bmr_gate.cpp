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
#include "communication/communication_layer.h"
#include "crypto/bmr_provider.h"
#include "crypto/motion_base_provider.h"
#include "crypto/oblivious_transfer/ot_flavors.h"
#include "crypto/oblivious_transfer/ot_provider.h"
#include "crypto/pseudo_random_generator.h"
#include "data_storage/bmr_data.h"
#include "utility/block.h"
#include "wire/bmr_wire.h"
#include "wire/boolean_gmw_wire.h"

namespace MOTION::Gates::BMR {

BMRInputGate::BMRInputGate(std::size_t num_simd, std::size_t bit_size, std::size_t input_owner_id,
                           Backend &backend)
    : InputGate(backend), num_simd_(num_simd), bit_size_(bit_size) {
  input_future_ = input_promise_.get_future();
  assert(num_simd_ != 0);
  assert(bit_size_ != 0);
  input_owner_id_ = input_owner_id;
  InitializationHelper();
}

BMRInputGate::BMRInputGate(const std::vector<ENCRYPTO::BitVector<>> &input,
                           std::size_t input_owner_id, Backend &backend)
    : InputGate(backend) {
  input_future_ = input_promise_.get_future();
  assert(!input.empty());
  input_owner_id_ = input_owner_id;
  bit_size_ = input.size();
  num_simd_ = input.at(0).GetSize();
  input_promise_.set_value(input);
  InitializationHelper();
}

BMRInputGate::BMRInputGate(std::vector<ENCRYPTO::BitVector<>> &&input, std::size_t input_owner_id,
                           Backend &backend)
    : InputGate(backend) {
  input_future_ = input_promise_.get_future();
  assert(!input.empty());
  input_owner_id_ = input_owner_id;
  bit_size_ = input.size();
  num_simd_ = input.at(0).GetSize();
  input_promise_.set_value(std::move(input));
  InitializationHelper();
}

void BMRInputGate::InitializationHelper() {
  auto num_parties = get_communication_layer().get_num_parties();
  if (static_cast<std::size_t>(input_owner_id_) >= num_parties) {
    throw std::runtime_error(fmt::format("Invalid input owner: {} of {}", input_owner_id_,
                                         num_parties));
  }

  gate_id_ = GetRegister().NextGateId();

  output_wires_.reserve(bit_size_);
  for (std::size_t i = 0; i < bit_size_; ++i)
    output_wires_.emplace_back(std::make_shared<Wires::BMRWire>(num_simd_, backend_));

  for (auto &w : output_wires_) GetRegister().RegisterNextWire(w);

  const auto my_id = get_communication_layer().get_my_id();

  assert(input_owner_id_ >= 0);
  assert(gate_id_ >= 0);

  auto& bmr_provider = backend_.get_bmr_provider();

  // if this is someone else's input, prepare for receiving the *public values*
  // (if it is our's then we would compute it ourselves)
  if (my_id != static_cast<std::size_t>(input_owner_id_)) {
    received_public_values_ = bmr_provider.register_for_input_public_values(input_owner_id_, gate_id_, num_simd_ * bit_size_);
  }

  // prepare for receiving the *public/active keys* of the other parties
  received_public_keys_ = bmr_provider.register_for_input_keys(gate_id_, num_simd_ * bit_size_);

  if constexpr (MOTION_DEBUG) {
    auto gate_info = fmt::format("gate id {}, input owner {}", gate_id_, input_owner_id_);
    GetLogger().LogDebug(
        fmt::format("Created a BMRInputGate with following properties: {}", gate_info));
  }
}

void BMRInputGate::EvaluateSetup() {
  if constexpr (MOTION_DEBUG) {
    GetLogger().LogDebug(
        fmt::format("Start evaluating setup phase of BMR Input Gate with id#{}", gate_id_));
  }

  const auto my_id = get_communication_layer().get_my_id();

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
      const auto &R = backend_.get_bmr_provider().get_global_offset();
      std::string keys_0, keys_1;
      for (const auto &key : wire->GetSecretKeys()) {
        assert(key.size() * 8 == kappa);
        keys_0.append(key.as_string() + " ");
        keys_1.append((key ^ R).as_string() + " ");
      }
      if (!keys_0.empty()) keys_0.erase(keys_0.size() - 1);
      if (!keys_1.empty()) keys_1.erase(keys_1.size() - 1);

      GetLogger().LogTrace(
          fmt::format("Created a BMR wire #{} with permutation bits {}, keys 0 {}, "
                      "and keys 1 {}",
                      wire->GetWireId(), wire->GetPermutationBits().AsString(), keys_0, keys_1));
    }
  }
  if constexpr (MOTION_DEBUG) {
    GetLogger().LogDebug(
        fmt::format("Finished evaluating setup phase of BMR Input Gate with id#{}", gate_id_));
  }
  SetSetupIsReady();
  GetRegister().IncrementEvaluatedGatesSetupCounter();
}

void BMRInputGate::EvaluateOnline() {
  WaitSetup();

  if constexpr (MOTION_DEBUG) {
    GetLogger().LogDebug(
        fmt::format("Start evaluating online phase of BMR Input Gate with id#{}", gate_id_));
  }

  const auto &R = backend_.get_bmr_provider().get_global_offset();
  auto& comm_layer = get_communication_layer();
  const auto my_id = comm_layer.get_my_id();
  const auto num_parties = comm_layer.get_num_parties();
  const auto num_simd = output_wires_.at(0)->GetNumOfSIMDValues();
  const auto num_wires = output_wires_.size();
  const bool my_input = static_cast<std::size_t>(input_owner_id_) == my_id;
  ENCRYPTO::BitVector<> buffer;
  buffer.Reserve(MOTION::Helpers::Convert::BitsToBytes(bit_size_));

  // if this is our input, set the public values by masking our real inputs
  // with the random permutation bits
  if (my_input) {
    auto input = input_future_.get();
    assert(input.size() > 0u);           // assert >=1 wire
    assert(input.at(0).GetSize() > 0u);  // assert >=1 SIMD bits
    // assert SIMD lengths of all wires are equal
    assert(ENCRYPTO::BitVector<>::EqualSizeDimensions(input));

    for (auto i = 0ull; i < output_wires_.size(); ++i) {
      auto wire = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(i));
      assert(wire);
      wire->GetMutablePublicValues() = input.at(i) ^ wire->GetPermutationBits();
      buffer.Append(wire->GetPublicValues());
    }
    const std::vector<std::uint8_t> payload(
        reinterpret_cast<const std::uint8_t *>(buffer.GetData().data()),
        reinterpret_cast<const std::uint8_t *>(buffer.GetData().data()) + buffer.GetData().size());
    comm_layer.broadcast_message(Communication::BuildBMRInput0Message(gate_id_, payload));
  }
  // otherwise receive the public values from the party that provides the input
  else {
    buffer = received_public_values_.get();
    for (auto i = 0ull; i < output_wires_.size(); ++i) {
      auto wire = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(i));
      assert(wire);
      wire->GetMutablePublicValues() = buffer.Subset(i * num_simd_, (i + 1) * num_simd_);
    }
  }

  // the public values are now set for each bit
  // now we need to publish the corresponding keys

  // fill the buffer with our keys corresponding to the public values
  ENCRYPTO::block128_vector my_keys_buffer(num_wires * num_simd);
  for (auto wire_i = 0ull; wire_i < num_wires; ++wire_i) {
    const auto wire = std::dynamic_pointer_cast<const Wires::BMRWire>(output_wires_.at(wire_i));
    assert(wire);
    const auto &keys = wire->GetSecretKeys();
    // copy the "0 keys" into the buffer
    std::copy(std::begin(keys), std::end(keys), std::begin(my_keys_buffer) + wire_i * num_simd);
    const auto &public_values = wire->GetPublicValues();
    for (auto simd_j = 0ull; simd_j < num_simd; ++simd_j) {
      // xor the offset on a key if the corresponding public value is 1
      if (public_values[simd_j]) {
        my_keys_buffer.at(wire_i * num_simd + simd_j) ^= R;
      }
    }
  }

  // send the selected keys to all other parties
  const std::vector<std::uint8_t> payload(
      reinterpret_cast<const std::uint8_t *>(my_keys_buffer.data()),
      reinterpret_cast<const std::uint8_t *>(my_keys_buffer.data()) + my_keys_buffer.byte_size());
  comm_layer.broadcast_message(Communication::BuildBMRInput1Message(gate_id_, payload));

  // index function for the public/active keys stored in the wires
  const auto pk_index = [num_parties](auto simd_i, auto party_i) {
    return simd_i * num_parties + party_i;
  };

  // receive the published keys from the other parties
  // and construct the active super keys for the output wires
  for (auto party_i = 0ull; party_i < num_parties; ++party_i) {
    if (party_i == my_id) {
      // our case: we can copy the keys we have already prepared above in
      // my_keys_buffer to the right positions
      for (auto wire_j = 0ull; wire_j < num_wires; ++wire_j) {
        auto wire = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(wire_j));
        assert(wire);
        auto &public_keys = wire->GetMutablePublicKeys();
        for (auto simd_k = 0ull; simd_k < num_simd; ++simd_k) {
          public_keys.at(pk_index(simd_k, my_id)) = my_keys_buffer.at(wire_j * num_simd + simd_k);
        }
      }
    } else {
      // other party: we copy the received keys to the right position
      auto received_keys_buffer = received_public_keys_.at(party_i).get();
      assert(received_keys_buffer.size() == num_wires * num_simd);
      for (auto wire_j = 0ull; wire_j < num_wires; ++wire_j) {
        auto wire = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(wire_j));
        assert(wire);
        auto &public_keys = wire->GetMutablePublicKeys();
        for (auto simd_k = 0ull; simd_k < num_simd; ++simd_k) {
          public_keys.at(pk_index(simd_k, party_i)) =
              received_keys_buffer.at(wire_j * num_simd + simd_k);
        }
      }
    }
  }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    std::string s(fmt::format("Evaluated a BMR input gate #{} and got as result: ", gate_id_));
    for (auto wire_i = 0ull; wire_i < num_wires; ++wire_i) {
      auto wire = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(wire_i));
      const auto &public_keys = wire->GetPublicKeys();
      std::string keys;
      for (auto party_j = 0ull; party_j < num_parties; ++party_j) {
        keys.append(std::to_string(party_j) + std::string(" "));
        for (auto simd_k = 0ull; simd_k < num_simd; ++simd_k) {
          keys.append(public_keys.at(pk_index(simd_k, party_j)).as_string() + " ");
        }
      }
      if (!keys.empty()) keys.erase(keys.size() - 1);
      s.append(fmt::format("wire #{} with public bits {} and public keys {}\n", wire->GetWireId(),
                           wire->GetPublicValues().AsString(), keys));
    }
    GetLogger().LogTrace(s);
  }
  if constexpr (MOTION_DEBUG) {
    GetLogger().LogDebug(
        fmt::format("Finished evaluating online phase of BMR Input Gate with id#{}", gate_id_));
  }

  for (auto &wire : output_wires_) {
    const auto bmr_wire = std::dynamic_pointer_cast<const Wires::BMRWire>(wire);
    assert(bmr_wire);
    assert(!bmr_wire->GetPermutationBits().Empty());
  }

  assert(!online_is_ready_);
  SetOnlineIsReady();
  GetRegister().IncrementEvaluatedGatesOnlineCounter();
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

  if (parent->GetWires().empty()) {
    throw std::runtime_error("Trying to construct an output gate with no wires");
  }

  parent_ = parent->GetWires();

  output_owner_ = output_owner;
  output_.resize(parent_.size());
  requires_online_interaction_ = true;
  gate_type_ = GateType::Interactive;

  auto& comm_layer = get_communication_layer();
  const auto my_id = comm_layer.get_my_id();
  const auto num_parties = comm_layer.get_num_parties();

  if (output_owner >= num_parties && output_owner != ALL) {
    throw std::runtime_error(
        fmt::format("Invalid output owner: {} of {}", output_owner, num_parties));
  }

  // For BMR reconstruction, we need to recontruct the shared permutation bits
  // and xor them to the public values in order to get the real values.  Since
  // the permutation bits are shared in the same way as usual Boolean GMW
  // shares, we use a GMWOutputGate to perform the reconstruction.

  std::vector<Wires::WirePtr> gmw_wires(parent_.size());
  const ENCRYPTO::BitVector<> dummy_bv(parent_.at(0)->GetNumOfSIMDValues());
  assert(!dummy_bv.Empty());

  for (auto &w : gmw_wires) {
    w = std::make_shared<Wires::GMWWire>(dummy_bv, backend_);
    GetRegister().RegisterNextWire(w);
  }

  gmw_out_share_ = std::make_shared<Shares::GMWShare>(gmw_wires);
  out_ = std::make_shared<MOTION::Gates::GMW::GMWOutputGate>(gmw_out_share_, output_owner_);
  GetRegister().RegisterNextGate(out_);

  gate_id_ = GetRegister().NextGateId();

  for (auto &wire : parent_) {
    RegisterWaitingFor(wire->GetWireId());  // mark this gate as waiting for @param wire
    wire->RegisterWaitingGate(gate_id_);    // register this gate in @param wire as waiting
  }

  is_my_output_ = static_cast<std::size_t>(output_owner_) == my_id ||
                  static_cast<std::size_t>(output_owner_) == ALL;

  assert(!output_.empty());
  for (auto &bv : output_) {
    output_wires_.push_back(std::static_pointer_cast<MOTION::Wires::Wire>(
        std::make_shared<Wires::BMRWire>(bv, backend_)));
  }

  for (auto &wire : output_wires_) GetRegister().RegisterNextWire(wire);

  if constexpr (MOTION_DEBUG) {
    auto gate_info =
        fmt::format("bitlength {}, gate id {}, owner {}", output_.size(), gate_id_, output_owner_);
    GetLogger().LogDebug(
        fmt::format("Created a BMR OutputGate with following properties: {}", gate_info));
  }
}

void BMROutputGate::EvaluateSetup() {
  SetSetupIsReady();
  GetRegister().IncrementEvaluatedGatesSetupCounter();
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
    bmr_wire->GetIsReadyCondition().Wait();
    bmr_wire->GetSetupReadyCondition()->Wait();
    auto gmw_wire = std::dynamic_pointer_cast<Wires::GMWWire>(wires.at(i));
    assert(bmr_wire);
    assert(gmw_wire);
    assert(!bmr_wire->GetPermutationBits().Empty());
    // take the permutation bits from the BMRWire and use them as GMW shares
    gmw_wire->GetMutableValues() = bmr_wire->GetPermutationBits();
    gmw_wire->SetOnlineFinished();
  }

  if (is_my_output_) {
    for (i = 0; i < output_wires_.size(); ++i) {
      const auto in_wire = std::dynamic_pointer_cast<const Wires::BMRWire>(parent_.at(i));
      auto gmw_wire = std::dynamic_pointer_cast<Wires::GMWWire>(out_->GetOutputWires().at(i));
      // wait until the GMWOutputGate is evaluated
      assert(in_wire);
      assert(gmw_wire);
      gmw_wire->GetIsReadyCondition().Wait();
      assert(in_wire->GetPublicValues().GetSize() == gmw_wire->GetValues().GetSize());
      // compute the real values as XOR of the public values from the BMRWire
      // with the reconstructed permutation bits from the GMWWire
      output_.at(i) = in_wire->GetPublicValues() ^ gmw_wire->GetValues();
      auto out_wire = std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(i));
      assert(out_wire);
      out_wire->GetMutablePublicValues() = output_.at(i);
    }
  }

  if constexpr (MOTION_DEBUG) {
    GetLogger().LogDebug(
        fmt::format("Evaluated online phase of BMR OutputGate with id#{}", gate_id_));
  }

  SetOnlineIsReady();
  GetRegister().IncrementEvaluatedGatesOnlineCounter();
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
  gate_type_ = GateType::NonInteractive;

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
  GetRegister().IncrementEvaluatedGatesSetupCounter();
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

    wire_a->GetIsReadyCondition().Wait();
    wire_b->GetIsReadyCondition().Wait();

    // perform freeXOR evaluation
    bmr_out->GetMutablePublicKeys() = wire_a->GetPublicKeys() ^ wire_b->GetPublicKeys();
    bmr_out->GetMutablePublicValues() = wire_a->GetPublicValues() ^ wire_b->GetPublicValues();
  }

  if constexpr (MOTION_DEBUG) {
    GetLogger().LogDebug(
        fmt::format("Finished evaluating online phase of BMR XOR Gate with id#{}", gate_id_));
  }

  for (auto &wire : output_wires_) {
    const auto bmr_wire = std::dynamic_pointer_cast<const Wires::BMRWire>(wire);
    assert(bmr_wire);
    assert(!bmr_wire->GetPermutationBits().Empty());
  }

  assert(!online_is_ready_);

  SetOnlineIsReady();
  GetRegister().IncrementEvaluatedGatesOnlineCounter();
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
  gate_type_ = GateType::NonInteractive;

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

  auto& comm_layer = get_communication_layer();
  const auto my_id = comm_layer.get_my_id();
  const auto num_parties = comm_layer.get_num_parties();

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
  GetRegister().IncrementEvaluatedGatesSetupCounter();
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

    bmr_in->GetIsReadyCondition().Wait();

    // just copy the public values and keys from the parent wire
    bmr_out->GetMutablePublicKeys() = bmr_in->GetPublicKeys();
    bmr_out->GetMutablePublicValues() = bmr_in->GetPublicValues();
  }

  if constexpr (MOTION_DEBUG) {
    GetLogger().LogDebug(
        fmt::format("Finished evaluating online phase of BMR INV Gate with id#{}", gate_id_));
  }

  for (auto &wire : output_wires_) {
    const auto bmr_wire = std::dynamic_pointer_cast<const Wires::BMRWire>(wire);
    assert(bmr_wire);
    assert(!bmr_wire->GetPermutationBits().Empty());
  }

  assert(!online_is_ready_);

  SetOnlineIsReady();
  GetRegister().IncrementEvaluatedGatesOnlineCounter();
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
  gate_type_ = GateType::Interactive;

  gate_id_ = GetRegister().NextGateId();

  auto& comm_layer = get_communication_layer();
  const auto my_id = comm_layer.get_my_id();
  const auto num_parties = comm_layer.get_num_parties();
  const auto num_simd{parent_a_.at(0)->GetNumOfSIMDValues()};
  const auto num_wires{parent_a_.size()};
  const auto size_of_all_garbled_tables = num_wires * num_simd * 4 * num_parties;

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
    for (auto party_j = 0ull; party_j < num_parties; ++party_j) {
      if (party_j == my_id) continue;
      // we need 1 bit C-OT and ...
      s_ots_1_.at(party_j).at(wire_i) = GetOTProvider(party_j).RegisterSendXCOTBit(num_simd);
      r_ots_1_.at(party_j).at(wire_i) = GetOTProvider(party_j).RegisterReceiveXCOTBit(num_simd);
      // ... 3 string C-OTs per gate (in each direction)
      s_ots_kappa_.at(party_j).at(wire_i) =
          GetOTProvider(party_j).RegisterSendFixedXCOT128(3 * num_simd);
      r_ots_kappa_.at(party_j).at(wire_i) =
          GetOTProvider(party_j).RegisterReceiveFixedXCOT128(3 * num_simd);
    }
  }

  // allocate enough space for num_wires * num_simd garbled tables
  garbled_tables_.resize(size_of_all_garbled_tables);

  // store futures for the (partial) garbled tables we will receive during garbling
  received_garbled_rows_ = backend_.get_bmr_provider().register_for_garbled_rows(gate_id_, size_of_all_garbled_tables);

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
      const auto my_id = get_communication_layer().get_my_id();
      const auto num_simd{parent_a_.at(0)->GetNumOfSIMDValues()};
      for (auto simd_i = 0ull; simd_i < num_simd; ++simd_i) {
        const auto &key_0{bmr_out->GetSecretKeys().at(simd_i)};
        const auto &key_1{key_0 ^ backend_.get_bmr_provider().get_global_offset()};

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
  const auto &R{backend_.get_bmr_provider().get_global_offset()};
  const auto num_wires{parent_a_.size()};
  const auto num_simd{parent_a_.at(0)->GetNumOfSIMDValues()};
  auto& comm_layer = get_communication_layer();
  const auto my_id = comm_layer.get_my_id();
  const auto num_parties = comm_layer.get_num_parties();
  [[maybe_unused]] const auto batch_size_3{num_simd * 3};

  // index function for the buffer of garbled tables
  const auto gt_index = [num_simd, num_parties](auto wire_i, auto simd_i, auto row_i,
                                                auto party_i) {
    return wire_i * num_simd * 4 * num_parties + simd_i * (4 * num_parties) + row_i * num_parties +
           party_i;
  };

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

    const ENCRYPTO::BitVector<> &a_perm_bits = bmr_a->GetPermutationBits();
    const ENCRYPTO::BitVector<> &b_perm_bits = bmr_b->GetPermutationBits();

    for (auto party_i = 0ull; party_i < num_parties; ++party_i) {
      if (party_i == my_id) {
        choices.at(party_i).at(wire_i) = a_perm_bits & b_perm_bits;
        continue;
      }

      auto &r_ot_1{r_ots_1_.at(party_i).at(wire_i)};
      auto &s_ot_1{s_ots_1_.at(party_i).at(wire_i)};

      if constexpr (MOTION_VERBOSE_DEBUG) {
        GetLogger().LogTrace(fmt::format(
            "Gate#{} (BMR AND gate)  Party#{}-#{} bit-C-OTs wire_i {} perm_bits {} bits_a {} "
            "bits_b {} a&b {}\n",
            gate_id_, my_id, party_i, wire_i, bmr_out->GetPermutationBits().AsString(),
            bmr_a->GetPermutationBits().AsString(), bmr_b->GetPermutationBits().AsString(),
            choices.at(party_i).at(wire_i).AsString()));
      }
      // compute C-OTs for the real value, ie, b = (lambda_u ^ alpha) * (lambda_v ^ beta)

      r_ot_1->WaitSetup();
      s_ot_1->WaitSetup();

      r_ot_1->SetChoices(b_perm_bits);
      r_ot_1->SendCorrections();

      s_ot_1->SetCorrelations(a_perm_bits);
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
    for (auto party_i = 0ull; party_i < num_parties; ++party_i) {
      if (party_i == my_id) continue;
      auto &r_ot_1{r_ots_1_.at(party_i).at(wire_i)};
      auto &s_ot_1{s_ots_1_.at(party_i).at(wire_i)};

      assert(r_ot_1->ChoicesAreSet());
      r_ot_1->ComputeOutputs();
      const auto &r_bv = r_ot_1->GetOutputs();
      s_ot_1->ComputeOutputs();
      const auto &s_bv = s_ot_1->GetOutputs();

      choices.at(party_i).at(wire_i) = r_bv ^ s_bv;

      if constexpr (MOTION_VERBOSE_DEBUG) {
        const auto &r_bv_check = r_ot_1->GetChoices();
        const auto &s_bv_check = s_ot_1->GetCorrelations();
        GetLogger().LogTrace(fmt::format(
            "Gate#{} (BMR AND gate) Party#{}-#{} bit-C-OTs wire_i {} bits from C-OTs r {} s {} "
            "result {} (r {} s {})\n",
            gate_id_, my_id, party_i, wire_i, r_bv.AsString(), s_bv.AsString(),
            choices.at(party_i).at(wire_i).AsString(), r_bv_check.AsString(),
            s_bv_check.AsString()));
      }
    }  // for each party
  }    // for each wire

  // choices contain now shares of \lambda_{uv}^i

  std::vector<ENCRYPTO::BitVector<>> aggregated_choices(num_wires);

  for (auto wire_i = 0ull; wire_i < num_wires; ++wire_i) {
    auto bmr_out{std::dynamic_pointer_cast<Wires::BMRWire>(output_wires_.at(wire_i))};
    const auto bmr_a{std::dynamic_pointer_cast<const Wires::BMRWire>(parent_a_.at(wire_i))};
    const auto bmr_b{std::dynamic_pointer_cast<const Wires::BMRWire>(parent_b_.at(wire_i))};
    assert(bmr_out);
    assert(bmr_a);
    assert(bmr_b);

    const auto &out_perm_bits = bmr_out->GetPermutationBits();
    const auto &a_perm_bits = bmr_a->GetPermutationBits();
    const auto &b_perm_bits = bmr_b->GetPermutationBits();

    assert(choices.at(0).at(wire_i).GetSize() == num_simd);
    auto &agg_choices_fw = aggregated_choices.at(wire_i);
    agg_choices_fw = ENCRYPTO::BitVector<>(3 * num_simd, false);
    for (auto bit_i = 0ull; bit_i < num_simd; ++bit_i) {
      bool bit_val = out_perm_bits.Get(bit_i);  // \lambda_w^i
      for (auto party_i = 0ull; party_i < num_parties; ++party_i) {
        bit_val ^= choices.at(party_i).at(wire_i).Get(bit_i);  // \lambda_uv^i
      }
      agg_choices_fw.Set(bit_val, bit_i * 3);
      agg_choices_fw.Set(bit_val ^ a_perm_bits[bit_i], bit_i * 3 + 1);
      agg_choices_fw.Set(bit_val ^ b_perm_bits[bit_i], bit_i * 3 + 2);
    }

    for (auto party_i = 0ull; party_i < num_parties; ++party_i) {
      if (party_i == my_id) continue;
      // multiply individual parties' R's with the secret-shared real value XORed with
      // the permutation bit of the output wire, ie, R * (b ^ lambda_w)
      r_ots_kappa_.at(party_i).at(wire_i)->SetChoices(aggregated_choices.at(wire_i));
      r_ots_kappa_.at(party_i).at(wire_i)->SendCorrections();

      s_ots_kappa_.at(party_i).at(wire_i)->SetCorrelation(R);
      s_ots_kappa_.at(party_i).at(wire_i)->SendMessages();
    }
  }  // for each wire

  ENCRYPTO::PRG prg;
  prg.SetKey(get_motion_base_provider().get_aes_fixed_key().data());

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
        uint128_t tweak{party_i};
        tweak <<= 64;
        tweak += static_cast<uint64_t>(bmr_out->GetWireId() + simd_i);

        ENCRYPTO::block128_t mask_a_0;
        ENCRYPTO::block128_t mask_a_1;
        ENCRYPTO::block128_t mask_b_0;
        ENCRYPTO::block128_t mask_b_1;
        prg.FixedKeyAES(key_a_0.data(), tweak, mask_a_0.data());
        prg.FixedKeyAES(key_a_1.data(), tweak, mask_a_1.data());
        prg.FixedKeyAES(key_b_0.data(), tweak, mask_b_0.data());
        prg.FixedKeyAES(key_b_1.data(), tweak, mask_b_1.data());

        if constexpr (MOTION_VERBOSE_DEBUG) {
          GetLogger().LogTrace(fmt::format(
              "Gate#{} (BMR AND gate) Party#{} keys: a0 {} ({}) a1 {} ({}) b0 {} ({}) b1 {} ({})\n",
              gate_id_, my_id, key_a_0.as_string(), mask_a_0.as_string(), key_a_1.as_string(),
              mask_a_1.as_string(), key_b_0.as_string(), mask_b_0.as_string(), key_b_1.as_string(),
              mask_b_1.as_string()));
        }

        auto &garbled_row_00{garbled_tables_.at(gt_index(wire_i, simd_i, 0, party_i))};
        auto &garbled_row_01{garbled_tables_.at(gt_index(wire_i, simd_i, 1, party_i))};
        auto &garbled_row_10{garbled_tables_.at(gt_index(wire_i, simd_i, 2, party_i))};
        auto &garbled_row_11{garbled_tables_.at(gt_index(wire_i, simd_i, 3, party_i))};
        if (party_i == my_id) {
          const auto &key_w_0{bmr_out->GetSecretKeys().at(simd_i)};
          garbled_row_00 = mask_a_0 ^ mask_b_0 ^ key_w_0;
          garbled_row_01 = mask_a_0 ^ mask_b_1 ^ key_w_0;
          garbled_row_10 = mask_a_1 ^ mask_b_0 ^ key_w_0;
          garbled_row_11 = mask_a_1 ^ mask_b_1 ^ key_w_0 ^ R;

          if constexpr (MOTION_VERBOSE_DEBUG) {
            GetLogger().LogTrace(
                fmt::format(
                    "Gate#{} (BMR AND gate) Party#{} (me {}) gr00 mask_a_0 {} XOR mask_b_0 {} XOR "
                    "key_w_0 {} = {}\n",
                    gate_id_, party_i, my_id, mask_a_0.as_string(), mask_b_0.as_string(),
                    key_w_0.as_string(), garbled_row_00.as_string()) +
                fmt::format(
                    "Gate#{} (BMR AND gate) Party#{} (me {}) gr01 mask_a_0 {} XOR mask_b_0 {} XOR "
                    "key_w_1 {} = {}\n",
                    gate_id_, party_i, my_id, mask_a_0.as_string(), mask_b_1.as_string(),
                    key_w_0.as_string(), garbled_row_01.as_string()) +
                fmt::format(
                    "Gate#{} (BMR AND gate) Party#{} (me {}) gr10 mask_a_0 {} XOR mask_b_0 {} XOR "
                    "key_w_0 {} = {}\n",
                    gate_id_, party_i, my_id, mask_a_1.as_string(), mask_b_0.as_string(),
                    key_w_0.as_string(), garbled_row_10.as_string()) +
                fmt::format(
                    "Gate#{} (BMR AND gate) Party#{} (me {}) gr11 mask_a_1 {} XOR mask_b_1 {} XOR "
                    "key_w_1 {} XOR R {} = {}\n",
                    gate_id_, party_i, my_id, mask_a_1.as_string(), mask_b_1.as_string(),
                    key_w_0.as_string(), R.as_string(), garbled_row_11.as_string()));
          }
        } else {
          garbled_row_00 = mask_a_0 ^ mask_b_0;
          garbled_row_01 = mask_a_0 ^ mask_b_1;
          garbled_row_10 = mask_a_1 ^ mask_b_0;
          garbled_row_11 = mask_a_1 ^ mask_b_1;
          if (MOTION_VERBOSE_DEBUG) {
            GetLogger().LogTrace(
                fmt::format("Gate#{} (BMR AND gate) Party#{} (me {}) gr00 mask_a_0 {} XOR mask_b_0 "
                            "{} = {}\n",
                            gate_id_, party_i, my_id, mask_a_0.as_string(), mask_b_0.as_string(),
                            garbled_row_00.as_string()) +
                fmt::format("Gate#{} (BMR AND gate) Party#{} (me {}) gr01 mask_a_0 {} XOR mask_b_1 "
                            "{} = {}\n",
                            gate_id_, party_i, my_id, mask_a_0.as_string(), mask_b_1.as_string(),
                            garbled_row_01.as_string()) +
                fmt::format("Gate#{} (BMR AND gate) Party#{} (me {}) gr10 mask_a_1 {} XOR mask_b_0 "
                            "{} = {}\n",
                            gate_id_, party_i, my_id, mask_a_1.as_string(), mask_b_0.as_string(),
                            garbled_row_10.as_string()) +
                fmt::format("Gate#{} (BMR AND gate) Party#{} (me {}) gr11 mask_a_1 {} XOR mask_b_1 "
                            "{} = {}\n",
                            gate_id_, party_i, my_id, mask_a_1.as_string(), mask_b_1.as_string(),
                            garbled_row_11.as_string()));
          }
        }

        std::array<ENCRYPTO::block128_t, 3> shared_R;
        const auto zero_block = ENCRYPTO::block128_t::make_zero();

        if (party_i == my_id) {
          shared_R.at(0) = aggregated_choices.at(wire_i)[simd_i * 3] ? R : zero_block;
          shared_R.at(1) = aggregated_choices.at(wire_i)[simd_i * 3 + 1] ? R : zero_block;
          shared_R.at(2) = aggregated_choices.at(wire_i)[simd_i * 3 + 2] ? R : zero_block;
        } else {
          shared_R.at(0) = shared_R.at(1) = shared_R.at(2) = zero_block;
        }

        // R's from C-OTs
        if (party_i == my_id) {
          for (auto party_j = 0ull; party_j < num_parties; ++party_j) {
            if (party_j == my_id) continue;

            s_ots_kappa_.at(party_j).at(wire_i)->ComputeOutputs();
            const auto &s_out = s_ots_kappa_.at(party_j).at(wire_i)->GetOutputs();
            assert(s_out.size() == num_simd * 3);
            const auto R_00 = s_out[simd_i * 3];
            const auto R_01 = s_out[simd_i * 3 + 1];
            const auto R_10 = s_out[simd_i * 3 + 2];

            shared_R.at(0) ^= R_00;
            shared_R.at(1) ^= R_01;
            shared_R.at(2) ^= R_10;

            if (MOTION_VERBOSE_DEBUG) {
              GetLogger().LogTrace(fmt::format(
                  "Gate#{} (BMR AND gate) Me#{}: Party#{} received R's \n00 ({}) \n01 ({}) \n10 "
                  "({})\n",
                  gate_id_, my_id, party_i, R_00.as_string(), R_01.as_string(), R_10.as_string()));
            }
          }
        } else {
          assert(r_ots_kappa_.at(party_i).at(wire_i)->ChoicesAreSet());
          r_ots_kappa_.at(party_i).at(wire_i)->ComputeOutputs();
          const auto &r_out = r_ots_kappa_.at(party_i).at(wire_i)->GetOutputs();
          assert(r_out.size() == num_simd * 3);
          const auto R_00 = r_out[simd_i * 3];
          const auto R_01 = r_out[simd_i * 3 + 1];
          const auto R_10 = r_out[simd_i * 3 + 2];

          shared_R.at(0) ^= R_00;
          shared_R.at(1) ^= R_01;
          shared_R.at(2) ^= R_10;
        }

        if constexpr (MOTION_VERBOSE_DEBUG) {
          GetLogger().LogTrace(
              fmt::format("Gate#{} (BMR AND gate) Me#{}: Shared R's \n00 ({}) \n01 ({}) \n10 "
                          "({})\n",
                          gate_id_, my_id, party_i, shared_R.at(0).as_string(),
                          shared_R.at(1).as_string(), shared_R.at(2).as_string()));
        }
        garbled_row_00 ^= shared_R.at(0);
        garbled_row_01 ^= shared_R.at(1);
        garbled_row_10 ^= shared_R.at(2);
        garbled_row_11 ^= shared_R.at(0) ^ shared_R.at(1) ^ shared_R.at(2);
      }  // for each party
    }    // for each simd
  }      // for each wire

  if constexpr (MOTION_VERBOSE_DEBUG) {
    std::string s{fmt::format("Me#{}: ", my_id)};
    assert(garbled_tables_.size() == num_wires * num_simd * 4 * num_parties);
    for (auto wire_j = 0ull; wire_j < num_wires; ++wire_j) {
      s.append(fmt::format(" Wire #{}: ", wire_j));
      for (auto simd_k = 0ull; simd_k < num_simd; ++simd_k) {
        s.append(fmt::format("\nSIMD #{}: ", simd_k));
        for (auto row_l = 0ull; row_l < 4; ++row_l) {
          s.append(fmt::format("\nRow #{}: ", row_l));
          for (auto party_i = 0ull; party_i < num_parties; ++party_i) {
            s.append(fmt::format("\nParty #{}: ", party_i));
            s.append(fmt::format(
                " garbled rows {} ",
                garbled_tables_.at(gt_index(wire_j, simd_k, row_l, party_i)).as_string()));
          }
        }
      }
    }
    s.append("\n");
    GetLogger().LogTrace(s);
  }

  // send out our partial garbled tables
  const std::vector<std::uint8_t> send_message_buffer(
      reinterpret_cast<const std::uint8_t *>(garbled_tables_.data()),
      reinterpret_cast<const std::uint8_t *>(garbled_tables_.data()) + garbled_tables_.byte_size());
  comm_layer.broadcast_message(Communication::BuildBMRANDMessage(static_cast<std::size_t>(gate_id_),
                                                             send_message_buffer));

  // finalize garbled tables
  for (auto party_i = 0ull; party_i < num_parties; ++party_i) {
    if (party_i == my_id) continue;
    const auto received_message = received_garbled_rows_.at(party_i).get();
    assert(received_message.size() == garbled_tables_.size());
    garbled_tables_ ^= received_message;
  }

  // mark this gate as setup-ready to proceed with the online phase
  if constexpr (MOTION_DEBUG) {
    GetLogger().LogDebug(
        fmt::format("Finished evaluating setup phase of BMR AND Gate with id#{}", gate_id_));
  }
  SetSetupIsReady();
  GetRegister().IncrementEvaluatedGatesSetupCounter();
}

void BMRANDGate::EvaluateOnline() {
  WaitSetup();

  if constexpr (MOTION_DEBUG) {
    GetLogger().LogDebug(
        fmt::format("Start evaluating online phase of BMR AND Gate with id#{}", gate_id_));
  }

  auto& comm_layer = get_communication_layer();
  const auto my_id = comm_layer.get_my_id();
  const auto num_parties = comm_layer.get_num_parties();
  const auto num_wires = output_wires_.size();
  const auto num_simd = output_wires_.at(0)->GetNumOfSIMDValues();
  const auto &R = backend_.get_bmr_provider().get_global_offset();

  // index function for the public/active keys stored in the wires
  const auto pk_index = [num_parties](auto simd_i, auto party_i) {
    return simd_i * num_parties + party_i;
  };

  // index function for the buffer of garbled tables
  const auto gt_index = [num_simd, num_parties](auto wire_i, auto simd_i, auto row_i,
                                                auto party_i) {
    return wire_i * num_simd * 4 * num_parties + simd_i * (4 * num_parties) + row_i * num_parties +
           party_i;
  };

  if constexpr (MOTION_VERBOSE_DEBUG) {
    for (auto wire_i = 0ull; wire_i < num_wires; ++wire_i) {
      for (auto simd_j = 0ull; simd_j < num_simd; ++simd_j) {
        for (auto row_l = 0ull; row_l < 4; ++row_l) {
          for (auto party_i = 0ull; party_i < num_parties; ++party_i) {
            GetLogger().LogTrace(fmt::format(
                "Party#{}: reconstructed gr for Party#{} Wire#{} SIMD#{} Row#{}: {}\n", my_id,
                party_i, wire_i, simd_j, row_l,
                garbled_tables_.at(gt_index(wire_i, simd_j, row_l, party_i)).as_string()));
          }
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

    wire_a->GetIsReadyCondition().Wait();
    wire_b->GetIsReadyCondition().Wait();

    ENCRYPTO::PRG prg;
    prg.SetKey(get_motion_base_provider().get_aes_fixed_key().data());

    for (auto simd_i = 0ull; simd_i < num_simd; ++simd_i) {
      auto masks = ENCRYPTO::block128_vector::make_zero(num_parties);
      [[maybe_unused]] std::string s;
      if constexpr (MOTION_VERBOSE_DEBUG) {
        s.append(
            fmt::format("Me#{}: wire#{} simd#{} result\n", my_id, wire_i, simd_i));
        s.append(fmt::format("Public values a {} b {} ", wire_a->GetPublicValues().AsString(),
                             wire_b->GetPublicValues().AsString()));
      }
      for (auto party_i = 0ull; party_i < num_parties; ++party_i) {
        const auto &key_a = wire_a->GetPublicKeys().at(pk_index(simd_i, party_i));
        const auto &key_b = wire_b->GetPublicKeys().at(pk_index(simd_i, party_i));
        for (auto party_j = 0ull; party_j < num_parties; ++party_j) {
          uint128_t tweak{party_j};
          tweak <<= 64;
          tweak += static_cast<uint64_t>(bmr_out->GetWireId() + simd_i);
          ENCRYPTO::block128_t mask_a;
          ENCRYPTO::block128_t mask_b;
          prg.FixedKeyAES(key_a.data(), tweak, mask_a.data());
          prg.FixedKeyAES(key_b.data(), tweak, mask_b.data());
          masks.at(party_j) ^= mask_a;
          masks.at(party_j) ^= mask_b;
          if constexpr (MOTION_VERBOSE_DEBUG) {
            s.append(fmt::format("\nParty#{} key for #{} key_a {} ({}) key_b {} ({})", party_i,
                                 party_j, key_a.as_string(), mask_a.as_string(), key_b.as_string(),
                                 mask_b.as_string()));
          }
        }
      }

      // compute index of the correct row in the garbled table
      const bool alpha = wire_a->GetPublicValues()[simd_i],
                 beta = wire_b->GetPublicValues()[simd_i];
      const std::size_t row_index =
          static_cast<std::size_t>(alpha) * 2 + static_cast<std::size_t>(beta);

      // decrypt that row of the garbled table
      for (auto party_i = 0ull; party_i < num_parties; ++party_i) {
        if constexpr (MOTION_VERBOSE_DEBUG) {
          s.append(fmt::format(
              "\nParty#{} output public keys = garbled row_(alpha = {} ,beta = {}, offset = {}) {} "
              "xor mask {} = ",
              party_i, alpha, beta, row_index,
              garbled_tables_.at(gt_index(wire_i, simd_i, row_index, party_i)).as_string(),
              masks.at(party_i).as_string()));
        }
        bmr_out->GetMutablePublicKeys().at(pk_index(simd_i, party_i)) =
            garbled_tables_.at(gt_index(wire_i, simd_i, row_index, party_i)) ^ masks.at(party_i);
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

    // figure out the public value of the outputs
    for (auto simd_i = 0ull; simd_i < num_simd; ++simd_i) {
      // check if our part of the output super key is different to our "0 key"
      const bool neq = bmr_out->GetPublicKeys().at(pk_index(simd_i, my_id)) !=
                       bmr_out->GetSecretKeys().at(simd_i);
      if (neq) {
        // then it should be equal to the "1 key" which is the "0 key" xored with the global offset
        assert(bmr_out->GetPublicKeys().at(pk_index(simd_i, my_id)) ==
               (bmr_out->GetSecretKeys().at(simd_i) ^ R));
      }
      bmr_out->GetMutablePublicValues().Set(neq, simd_i);
    }
    if constexpr (MOTION_VERBOSE_DEBUG) {
      GetLogger().LogTrace(fmt::format("Party#{} wire#{} public values result {}\n",
                                       my_id, wire_i,
                                       bmr_out->GetPublicValues().AsString()));
    }
  }  // for each wire

  if constexpr (MOTION_VERBOSE_DEBUG) {
    GetLogger().LogTrace(fmt::format("Evaluated BMR AND Gate with id#{}", gate_id_));
  }

  for (auto &wire : output_wires_) {
    const auto bmr_wire = std::dynamic_pointer_cast<const Wires::BMRWire>(wire);
    assert(bmr_wire);
    assert(!bmr_wire->GetPermutationBits().Empty());
  }

  assert(!online_is_ready_);

  SetOnlineIsReady();
  GetRegister().IncrementEvaluatedGatesOnlineCounter();
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
