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
#include "bmr_provider.h"
#include "bmr_wire.h"

#include <span>

#include "base/backend.h"
#include "base/motion_base_provider.h"
#include "communication/communication_layer.h"
#include "communication/message.h"
#include "oblivious_transfer/ot_flavors.h"
#include "primitives/aes/aesni_primitives.h"
#include "primitives/pseudo_random_generator.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "utility/block.h"

namespace encrypto::motion::proto::bmr {

InputGate::InputGate(std::size_t number_of_simd, std::size_t bit_size, std::size_t input_owner_id,
                     Backend& backend)
    : InputGate::Base(backend), number_of_simd_(number_of_simd), bit_size_(bit_size) {
  input_future_ = input_promise_.get_future();
  assert(number_of_simd_ != 0);
  assert(bit_size_ != 0);
  input_owner_id_ = input_owner_id;
  InitializationHelper();
}

InputGate::InputGate(std::span<const motion::BitVector<>> input, std::size_t input_owner_id,
                     Backend& backend)
    : InputGate::Base(backend) {
  input_future_ = input_promise_.get_future();
  assert(!input.empty());
  input_owner_id_ = input_owner_id;
  bit_size_ = input.size();
  number_of_simd_ = input[0].GetSize();
  input_promise_.set_value(std::vector(input.begin(), input.end()));
  InitializationHelper();
}

InputGate::InputGate(std::vector<motion::BitVector<>>&& input, std::size_t input_owner_id,
                     Backend& backend)
    : InputGate::Base(backend) {
  input_future_ = input_promise_.get_future();
  assert(!input.empty());
  input_owner_id_ = input_owner_id;
  bit_size_ = input.size();
  number_of_simd_ = input.at(0).GetSize();
  input_promise_.set_value(std::move(input));
  InitializationHelper();
}

void InputGate::InitializationHelper() {
  auto number_of_parties = GetCommunicationLayer().GetNumberOfParties();
  if (static_cast<std::size_t>(input_owner_id_) >= number_of_parties) {
    throw std::runtime_error(
        fmt::format("Invalid input owner: {} of {}", input_owner_id_, number_of_parties));
  }

  output_wires_.reserve(bit_size_);
  for (std::size_t i = 0; i < bit_size_; ++i) {
    output_wires_.emplace_back(
        GetRegister().template EmplaceWire<bmr::Wire>(backend_, number_of_simd_));
  }

  const auto my_id = GetCommunicationLayer().GetMyId();

  assert(input_owner_id_ >= 0);
  assert(gate_id_ >= 0);

  auto& bmr_provider = backend_.GetBmrProvider();

  // if this is someone else's input, prepare for receiving the *public values*
  // (if it is our's then we would compute it ourselves)
  if (my_id != static_cast<std::size_t>(input_owner_id_)) {
    received_public_values_ = bmr_provider.RegisterForInputPublicValues(input_owner_id_, gate_id_);
  }

  // prepare for receiving the *public/active keys* of the other parties
  received_public_keys_ = bmr_provider.RegisterForInputKeys(gate_id_);

  if constexpr (kDebug) {
    auto gate_info = fmt::format("gate id {}, input owner {}", gate_id_, input_owner_id_);
    GetLogger().LogDebug(
        fmt::format("Created a bmr::InputGate with following properties: {}", gate_info));
  }
}

void InputGate::EvaluateSetup() {
  if constexpr (kDebug) {
    GetLogger().LogDebug(
        fmt::format("Start evaluating setup phase of bmr::InputGate with id#{}", gate_id_));
  }

  const auto my_id = GetCommunicationLayer().GetMyId();

  // create keys etc. for all the wires
  for (auto i = 0ull; i < output_wires_.size(); ++i) {
    auto wire = std::dynamic_pointer_cast<bmr::Wire>(output_wires_.at(i));
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
      wire->GetMutablePermutationBits() = motion::BitVector<>(wire->GetNumberOfSimdValues());
    }
    wire->SetSetupIsReady();

    if constexpr (kVerboseDebug) {
      const auto& R = backend_.GetBmrProvider().GetGlobalOffset();
      std::string keys_0, keys_1;
      for (const auto& key : wire->GetSecretKeys()) {
        assert(key.size() * 8 == kKappa);
        keys_0.append(key.AsString() + " ");
        keys_1.append((key ^ R).AsString() + " ");
      }
      if (!keys_0.empty()) keys_0.erase(keys_0.size() - 1);
      if (!keys_1.empty()) keys_1.erase(keys_1.size() - 1);

      GetLogger().LogTrace(
          fmt::format("Created a BMR wire #{} with permutation bits {}, keys 0 {}, "
                      "and keys 1 {}",
                      wire->GetWireId(), wire->GetPermutationBits().AsString(), keys_0, keys_1));
    }
  }
  if constexpr (kDebug) {
    GetLogger().LogDebug(
        fmt::format("Finished evaluating setup phase of bmr::InputGate with id#{}", gate_id_));
  }
}

void InputGate::EvaluateOnline() {
  WaitSetup();

  if constexpr (kDebug) {
    GetLogger().LogDebug(
        fmt::format("Start evaluating online phase of bmr::InputGate with id#{}", gate_id_));
  }

  const auto& R = backend_.GetBmrProvider().GetGlobalOffset();
  auto& communication_layer = GetCommunicationLayer();
  const auto my_id = communication_layer.GetMyId();
  const auto number_of_parties = communication_layer.GetNumberOfParties();
  const auto number_of_simd = output_wires_.at(0)->GetNumberOfSimdValues();
  const auto number_of_wires = output_wires_.size();
  const bool my_input = static_cast<std::size_t>(input_owner_id_) == my_id;

  // if this is our input, set the public values by masking our real inputs
  // with the random permutation bits
  if (my_input) {
    motion::BitVector<> buffer;
    buffer.Reserve(bit_size_);
    std::vector<BitVector<>> input{input_future_.get()};

    for (std::size_t i = 0; i < output_wires_.size(); ++i) {
      auto wire = std::dynamic_pointer_cast<bmr::Wire>(output_wires_[i]);
      assert(wire);
      wire->GetMutablePublicValues() = input[i] ^ wire->GetPermutationBits();
      buffer.Append(wire->GetPublicValues());
    }
    std::span payload(reinterpret_cast<const std::uint8_t*>(buffer.GetData().data()),
                      buffer.GetData().size());
    auto msg{
        communication::BuildMessage(communication::MessageType::kBmrInputGate0, gate_id_, payload)};
    communication_layer.BroadcastMessage(msg.Release());
  }
  // otherwise receive the public values from the party that provides the input
  else {
    std::vector<std::uint8_t> public_values_message{received_public_values_.get()};
    auto pointer{const_cast<std::uint8_t*>(
        communication::GetMessage(public_values_message.data())->payload()->data())};
    BitSpan public_values_span(pointer, output_wires_.size() * number_of_simd_);
    for (auto i = 0ull; i < output_wires_.size(); ++i) {
      auto wire = std::dynamic_pointer_cast<bmr::Wire>(output_wires_.at(i));
      assert(wire);
      wire->GetMutablePublicValues() =
          public_values_span.Subset(i * number_of_simd_, (i + 1) * number_of_simd_);
    }
  }

  // the public values are now set for each bit
  // now we need to publish the corresponding keys

  // fill the buffer with our keys corresponding to the public values
  motion::Block128Vector my_keys_buffer(number_of_wires * number_of_simd);
  for (auto wire_i = 0ull; wire_i < number_of_wires; ++wire_i) {
    const auto wire = std::dynamic_pointer_cast<const bmr::Wire>(output_wires_.at(wire_i));
    assert(wire);
    const auto& keys = wire->GetSecretKeys();
    // copy the "0 keys" into the buffer
    std::copy(std::begin(keys), std::end(keys),
              std::begin(my_keys_buffer) + wire_i * number_of_simd);
    const auto& public_values = wire->GetPublicValues();
    for (auto simd_j = 0ull; simd_j < number_of_simd; ++simd_j) {
      // xor the offset on a key if the corresponding public value is 1
      if (public_values[simd_j]) {
        my_keys_buffer.at(wire_i * number_of_simd + simd_j) ^= R;
      }
    }
  }

  // send the selected keys to all other parties
  std::span payload(reinterpret_cast<const std::uint8_t*>(my_keys_buffer.data()),
                    my_keys_buffer.ByteSize());
  auto msg{
      communication::BuildMessage(communication::MessageType::kBmrInputGate1, gate_id_, payload)};
  communication_layer.BroadcastMessage(msg.Release());

  // index function for the public/active keys stored in the wires
  const auto PublicKeyIndex = [number_of_parties](auto simd_i, auto party_i) {
    return simd_i * number_of_parties + party_i;
  };

  // receive the published keys from the other parties
  // and construct the active super keys for the output wires
  for (auto party_i = 0ull; party_i < number_of_parties; ++party_i) {
    if (party_i == my_id) {
      // our case: we can copy the keys we have already prepared above in
      // my_keys_buffer to the right positions
      for (auto wire_j = 0ull; wire_j < number_of_wires; ++wire_j) {
        auto wire = std::dynamic_pointer_cast<bmr::Wire>(output_wires_.at(wire_j));
        assert(wire);
        auto& public_keys = wire->GetMutablePublicKeys();
        for (auto simd_k = 0ull; simd_k < number_of_simd; ++simd_k) {
          public_keys[PublicKeyIndex(simd_k, my_id)] =
              my_keys_buffer[wire_j * number_of_simd + simd_k];
        }
      }
    } else {
      assert(received_public_keys_.size() == number_of_parties - 1);
      // other party: we copy the received keys to the right position
      std::size_t party_i_remapped{party_i > my_id ? party_i - 1 : party_i};
      std::vector<std::uint8_t> received_keys_message{
          received_public_keys_[party_i_remapped].get()};
      const std::uint8_t* received_keys_pointer{
          communication::GetMessage(received_keys_message.data())->payload()->data()};
      assert(communication::GetMessage(received_keys_message.data())->payload()->size() ==
             number_of_wires * number_of_simd * kKappa / 8);

      for (auto wire_j = 0ull; wire_j < number_of_wires; ++wire_j) {
        auto wire = std::dynamic_pointer_cast<bmr::Wire>(output_wires_.at(wire_j));
        assert(wire);
        auto& public_keys = wire->GetMutablePublicKeys();
        for (auto simd_k = 0ull; simd_k < number_of_simd; ++simd_k) {
          auto pub_key_ptr{public_keys[PublicKeyIndex(simd_k, party_i)].data()};
          std::copy_n(reinterpret_cast<const std::byte*>(received_keys_pointer) +
                          Block128::size() * (wire_j * number_of_simd + simd_k),
                      Block128::size(), pub_key_ptr);
        }
      }
    }
  }

  if constexpr (kVerboseDebug) {
    std::string s(fmt::format("Evaluated a BMR input gate #{} and got as result: ", gate_id_));
    for (auto wire_i = 0ull; wire_i < number_of_wires; ++wire_i) {
      auto wire = std::dynamic_pointer_cast<bmr::Wire>(output_wires_.at(wire_i));
      const auto& public_keys = wire->GetPublicKeys();
      std::string keys;
      for (auto party_j = 0ull; party_j < number_of_parties; ++party_j) {
        keys.append(std::to_string(party_j) + std::string(" "));
        for (auto simd_k = 0ull; simd_k < number_of_simd; ++simd_k) {
          keys.append(public_keys.at(PublicKeyIndex(simd_k, party_j)).AsString() + " ");
        }
      }
      if (!keys.empty()) keys.erase(keys.size() - 1);
      s.append(fmt::format("wire #{} with public bits {} and public keys {}\n", wire->GetWireId(),
                           wire->GetPublicValues().AsString(), keys));
    }
    GetLogger().LogTrace(s);
  }
  if constexpr (kDebug) {
    GetLogger().LogDebug(
        fmt::format("Finished evaluating online phase of bmr::InputGate with id#{}", gate_id_));
  }

  for (auto& wire : output_wires_) {
    const auto bmr_wire = std::dynamic_pointer_cast<const bmr::Wire>(wire);
    assert(bmr_wire);
    assert(!bmr_wire->GetPermutationBits().Empty());
  }

  assert(!online_is_ready_);
}

const bmr::SharePointer InputGate::GetOutputAsBmrShare() const {
  auto result = std::make_shared<bmr::Share>(output_wires_);
  assert(result);
  return result;
}

const motion::SharePointer InputGate::GetOutputAsShare() const {
  auto result = std::static_pointer_cast<bmr::Share>(GetOutputAsBmrShare());
  assert(result);
  return result;
}

OutputGate::OutputGate(const motion::SharePointer& parent, std::size_t output_owner)
    : OutputGate::Base(parent->GetBackend()) {
  if (parent->GetWires().at(0)->GetProtocol() != MpcProtocol::kBmr) {
    auto sharing_type = to_string(parent->GetWires().at(0)->GetProtocol());
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
  output_wires_.resize(parent_.size());

  auto& communication_layer = GetCommunicationLayer();
  const auto my_id = communication_layer.GetMyId();
  const auto number_of_parties = communication_layer.GetNumberOfParties();

  if (output_owner >= number_of_parties && output_owner != kAll) {
    throw std::runtime_error(
        fmt::format("Invalid output owner: {} of {}", output_owner, number_of_parties));
  }

  // For BMR reconstruction, we need to recontruct the shared permutation bits
  // and xor them to the public values in order to get the real values.  Since
  // the permutation bits are shared in the same way as usual Boolean GMW
  // shares, we use a boolean_gmw::OutputGate to perform the reconstruction.

  std::vector<motion::WirePointer> gmw_wires(parent_.size());
  const motion::BitVector<> dummy_bitvector(parent_.at(0)->GetNumberOfSimdValues());
  assert(!dummy_bitvector.Empty());

  for (auto& w : gmw_wires) {
    w = GetRegister().EmplaceWire<boolean_gmw::Wire>(dummy_bitvector, backend_);
  }

  gmw_output_share_ = std::make_shared<boolean_gmw::Share>(gmw_wires);
  output_gate_ =
      GetRegister().EmplaceGate<boolean_gmw::OutputGate>(gmw_output_share_, output_owner_);

  is_my_output_ = static_cast<std::size_t>(output_owner_) == my_id ||
                  static_cast<std::size_t>(output_owner_) == kAll;

  const std::size_t number_of_simd{parent_[0]->GetNumberOfSimdValues()};
  assert(!output_.empty());
  for (auto& wire : output_wires_) {
    wire = GetRegister().EmplaceWire<bmr::Wire>(backend_, number_of_simd);
  }

  if constexpr (kDebug) {
    auto gate_info =
        fmt::format("bitlength {}, gate id {}, owner {}", output_.size(), gate_id_, output_owner_);
    GetLogger().LogDebug(
        fmt::format("Created a BMR OutputGate with following properties: {}", gate_info));
  }
}

void OutputGate::EvaluateSetup() {}

void OutputGate::EvaluateOnline() {
  // nothing to setup, no need to wait/check
  std::size_t i;

  if constexpr (kDebug) {
    GetLogger().LogDebug(
        fmt::format("Starting online phase evaluation for BMR OutputGate with id#{}", gate_id_));
  }

  auto& wires = gmw_output_share_->GetMutableWires();
  for (i = 0; i < wires.size(); ++i) {
    const auto bmr_wire = std::dynamic_pointer_cast<const bmr::Wire>(parent_.at(i));
    bmr_wire->GetIsReadyCondition().Wait();
    bmr_wire->GetSetupReadyCondition()->Wait();
    auto gmw_wire = std::dynamic_pointer_cast<boolean_gmw::Wire>(wires.at(i));
    assert(bmr_wire);
    assert(gmw_wire);
    assert(!bmr_wire->GetPermutationBits().Empty());
    // take the permutation bits from the bmr::Wire and use them as GMW shares
    gmw_wire->GetMutableValues() = bmr_wire->GetPermutationBits();
    gmw_wire->SetOnlineFinished();
  }

  if (is_my_output_) {
    for (i = 0; i < output_wires_.size(); ++i) {
      const auto input_wire = std::dynamic_pointer_cast<const bmr::Wire>(parent_.at(i));
      auto gmw_wire =
          std::dynamic_pointer_cast<boolean_gmw::Wire>(output_gate_->GetOutputWires().at(i));
      // wait until the boolean_gmw::OutputGate is evaluated
      assert(input_wire);
      assert(gmw_wire);
      gmw_wire->GetIsReadyCondition().Wait();
      assert(input_wire->GetPublicValues().GetSize() == gmw_wire->GetValues().GetSize());
      // compute the real values as XOR of the public values from the bmr::Wire
      // with the reconstructed permutation bits from the boolean_gmw::Wire
      output_.at(i) = input_wire->GetPublicValues() ^ gmw_wire->GetValues();
      auto output_wire = std::dynamic_pointer_cast<bmr::Wire>(output_wires_.at(i));
      assert(output_wire);
      output_wire->GetMutablePublicValues() = output_.at(i);
    }
  }

  if constexpr (kDebug) {
    GetLogger().LogDebug(
        fmt::format("Evaluated online phase of BMR OutputGate with id#{}", gate_id_));
  }
}

const bmr::SharePointer OutputGate::GetOutputAsBmrShare() const {
  auto result = std::make_shared<bmr::Share>(output_wires_);
  assert(result);
  return result;
}

const motion::SharePointer OutputGate::GetOutputAsShare() const {
  auto result = std::static_pointer_cast<bmr::Share>(GetOutputAsBmrShare());
  assert(result);
  return result;
}

XorGate::XorGate(const motion::SharePointer& a, const motion::SharePointer& b)
    : TwoGate(a->GetBackend()) {
  parent_a_ = a->GetWires();
  parent_b_ = b->GetWires();

  assert(parent_a_.size() > 0);
  assert(parent_a_.size() == parent_b_.size());
  assert(parent_a_.at(0)->GetBitLength() > 0);
  assert(parent_a_.at(0)->GetProtocol() == parent_b_.at(0)->GetProtocol());
  assert(parent_a_.at(0)->GetProtocol() == MpcProtocol::kBmr);

  output_wires_.resize(parent_a_.size());
  const motion::BitVector tmp_bv(a->GetNumberOfSimdValues());
  for (auto& w : output_wires_) {
    w = GetRegister().EmplaceWire<bmr::Wire>(tmp_bv, backend_);
  }

  if constexpr (kDebug) {
    auto gate_info = fmt::format("gate id {}, parents: {}, {}", gate_id_,
                                 parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    GetLogger().LogDebug(
        fmt::format("Created a BMR XOR gate with following properties: {}", gate_info));
  }
}

void XorGate::EvaluateSetup() {
  if constexpr (kDebug) {
    GetLogger().LogDebug(
        fmt::format("Start evaluating setup phase of BMR XOR Gate with id#{}", gate_id_));
  }

  for (auto i = 0ull; i < output_wires_.size(); ++i) {
    auto bmr_output = std::dynamic_pointer_cast<bmr::Wire>(output_wires_.at(i));
    const auto bmr_a = std::dynamic_pointer_cast<const bmr::Wire>(parent_a_.at(i));
    const auto bmr_b = std::dynamic_pointer_cast<const bmr::Wire>(parent_b_.at(i));
    assert(bmr_output);
    assert(bmr_a);
    assert(bmr_b);
    bmr_a->GetSetupReadyCondition()->Wait();
    bmr_b->GetSetupReadyCondition()->Wait();

    // use freeXOR garbling
    bmr_output->GetMutablePermutationBits() =
        bmr_a->GetPermutationBits() ^ bmr_b->GetPermutationBits();
    bmr_output->GetMutableSecretKeys() = bmr_a->GetSecretKeys() ^ bmr_b->GetSecretKeys();
    bmr_output->SetSetupIsReady();
  }
  if constexpr (kDebug) {
    GetLogger().LogDebug(
        fmt::format("Finished evaluating setup phase of BMR XOR Gate with id#{}", gate_id_));
  }
}

void XorGate::EvaluateOnline() {
  WaitSetup();
  if constexpr (kDebug) {
    GetLogger().LogDebug(
        fmt::format("Start evaluating online phase of BMR XOR Gate with id#{}", gate_id_));
  }

  for (auto i = 0ull; i < parent_a_.size(); ++i) {
    const auto wire_a = std::dynamic_pointer_cast<const bmr::Wire>(parent_a_.at(i));
    const auto wire_b = std::dynamic_pointer_cast<const bmr::Wire>(parent_b_.at(i));
    assert(wire_a);
    assert(wire_b);

    auto bmr_output = std::dynamic_pointer_cast<bmr::Wire>(output_wires_.at(i));
    assert(bmr_output);

    wire_a->GetIsReadyCondition().Wait();
    wire_b->GetIsReadyCondition().Wait();

    // perform freeXOR evaluation
    bmr_output->GetMutablePublicKeys() = wire_a->GetPublicKeys() ^ wire_b->GetPublicKeys();
    bmr_output->GetMutablePublicValues() = wire_a->GetPublicValues() ^ wire_b->GetPublicValues();
  }

  if constexpr (kDebug) {
    GetLogger().LogDebug(
        fmt::format("Finished evaluating online phase of BMR XOR Gate with id#{}", gate_id_));
  }

  for (auto& wire : output_wires_) {
    const auto bmr_wire = std::dynamic_pointer_cast<const bmr::Wire>(wire);
    assert(bmr_wire);
    assert(!bmr_wire->GetPermutationBits().Empty());
  }

  assert(!online_is_ready_);
}

const bmr::SharePointer XorGate::GetOutputAsBmrShare() const {
  auto result = std::make_shared<bmr::Share>(output_wires_);
  assert(result);
  return result;
}

const motion::SharePointer XorGate::GetOutputAsShare() const {
  auto result = std::static_pointer_cast<bmr::Share>(GetOutputAsBmrShare());
  assert(result);
  return result;
}

InvGate::InvGate(const motion::SharePointer& parent) : OneGate(parent->GetBackend()) {
  parent_ = parent->GetWires();

  assert(parent_.size() > 0);
  assert(parent_.at(0)->GetBitLength() > 0);
  for ([[maybe_unused]] const auto& wire : parent_)
    assert(wire->GetProtocol() == MpcProtocol::kBmr);

  output_wires_.resize(parent_.size());
  const motion::BitVector tmp_bv(parent->GetNumberOfSimdValues());
  for (auto& w : output_wires_) {
    w = GetRegister().EmplaceWire<bmr::Wire>(tmp_bv, backend_);
  }

  if constexpr (kDebug) {
    auto gate_info = fmt::format("gate id {}, parent wires: ", gate_id_);
    for (const auto& wire : parent_) gate_info.append(fmt::format("{} ", wire->GetWireId()));
    gate_info.append(" output wires: ");
    for (const auto& wire : output_wires_) gate_info.append(fmt::format("{} ", wire->GetWireId()));
    GetLogger().LogDebug(
        fmt::format("Created a BMR INV gate with following properties: {}", gate_info));
  }
}

void InvGate::EvaluateSetup() {
  if constexpr (kDebug) {
    GetLogger().LogDebug(
        fmt::format("Start evaluating setup phase of BMR INV Gate with id#{}", gate_id_));
  }

  auto& communication_layer = GetCommunicationLayer();
  const auto my_id = communication_layer.GetMyId();
  const auto number_of_parties = communication_layer.GetNumberOfParties();

  for (auto i = 0ull; i < output_wires_.size(); ++i) {
    auto bmr_output = std::dynamic_pointer_cast<bmr::Wire>(output_wires_.at(i));
    const auto bmr_input = std::dynamic_pointer_cast<const bmr::Wire>(parent_.at(i));
    assert(bmr_output);
    assert(bmr_input);
    bmr_input->GetSetupReadyCondition()->Wait();

    bmr_output->GetMutablePermutationBits() = bmr_input->GetPermutationBits();

    // one party needs to invert its permutation bits
    // distribute this work among the parties
    if (bmr_output->GetWireId() % number_of_parties == my_id)
      bmr_output->GetMutablePermutationBits().Invert();

    // copy the secret keys to the new wire
    bmr_output->GetMutableSecretKeys() = bmr_input->GetSecretKeys();

    bmr_output->SetSetupIsReady();
  }
  if constexpr (kDebug) {
    GetLogger().LogDebug(
        fmt::format("Finished evaluating setup phase of BMR INV Gate with id#{}", gate_id_));
  }
}

void InvGate::EvaluateOnline() {
  WaitSetup();
  if constexpr (kDebug) {
    GetLogger().LogDebug(
        fmt::format("Start evaluating online phase of BMR INV Gate with id#{}", gate_id_));
  }

  for (auto i = 0ull; i < parent_.size(); ++i) {
    const auto bmr_input = std::dynamic_pointer_cast<const bmr::Wire>(parent_.at(i));
    assert(bmr_input);

    auto bmr_output = std::dynamic_pointer_cast<bmr::Wire>(output_wires_.at(i));
    assert(bmr_output);

    bmr_input->GetIsReadyCondition().Wait();

    // just copy the public values and keys from the parent wire
    bmr_output->GetMutablePublicKeys() = bmr_input->GetPublicKeys();
    bmr_output->GetMutablePublicValues() = bmr_input->GetPublicValues();
  }

  if constexpr (kDebug) {
    GetLogger().LogDebug(
        fmt::format("Finished evaluating online phase of BMR INV Gate with id#{}", gate_id_));
  }

  for (auto& wire : output_wires_) {
    const auto bmr_wire = std::dynamic_pointer_cast<const bmr::Wire>(wire);
    assert(bmr_wire);
    assert(!bmr_wire->GetPermutationBits().Empty());
  }

  assert(!online_is_ready_);
}

const bmr::SharePointer InvGate::GetOutputAsBmrShare() const {
  auto result = std::make_shared<bmr::Share>(output_wires_);
  assert(result);
  return result;
}

const motion::SharePointer InvGate::GetOutputAsShare() const {
  auto result = std::static_pointer_cast<bmr::Share>(GetOutputAsBmrShare());
  assert(result);
  return result;
}

AndGate::AndGate(const motion::SharePointer& a, const motion::SharePointer& b)
    : TwoGate(a->GetBackend()) {
  parent_a_ = a->GetWires();
  parent_b_ = b->GetWires();

  assert(parent_a_.size() > 0);
  assert(parent_a_.size() == parent_b_.size());
  assert(parent_a_.at(0)->GetBitLength() > 0);
  assert(parent_a_.at(0)->GetProtocol() == parent_b_.at(0)->GetProtocol());
  assert(parent_a_.at(0)->GetProtocol() == MpcProtocol::kBmr);

  auto& communication_layer = GetCommunicationLayer();
  const auto my_id = communication_layer.GetMyId();
  const auto number_of_parties = communication_layer.GetNumberOfParties();
  const auto number_of_simd{parent_a_.at(0)->GetNumberOfSimdValues()};
  const auto number_of_wires{parent_a_.size()};
  const auto size_of_all_garbled_tables = number_of_wires * number_of_simd * 4 * number_of_parties;

  output_wires_.resize(number_of_wires);
  const motion::BitVector tmp_bv(number_of_simd);
  for (auto& w : output_wires_) {
    w = GetRegister().template EmplaceWire<bmr::Wire>(tmp_bv, backend_);
  }

  sender_ots_1_.resize(number_of_parties);
  for (auto& v : sender_ots_1_) v.resize(number_of_wires);
  sender_ots_kappa_.resize(number_of_parties);
  for (auto& v : sender_ots_kappa_) v.resize(number_of_wires);
  receiver_ots_1_.resize(number_of_parties);
  for (auto& v : receiver_ots_1_) v.resize(number_of_wires);
  receiver_ots_kappa_.resize(number_of_parties);
  for (auto& v : receiver_ots_kappa_) v.resize(number_of_wires);
  for (auto wire_i = 0ull; wire_i < number_of_wires; ++wire_i) {
    for (auto party_j = 0ull; party_j < number_of_parties; ++party_j) {
      if (party_j == my_id) continue;
      // we need 1 bit C-OT and ...
      sender_ots_1_.at(party_j).at(wire_i) =
          GetOtProvider(party_j).RegisterSendXcOtBit(number_of_simd);
      receiver_ots_1_.at(party_j).at(wire_i) =
          GetOtProvider(party_j).RegisterReceiveXcOtBit(number_of_simd);
      // ... 3 string C-OTs per gate (in each direction)
      sender_ots_kappa_.at(party_j).at(wire_i) =
          GetOtProvider(party_j).RegisterSendFixedXcOt128(3 * number_of_simd);
      receiver_ots_kappa_.at(party_j).at(wire_i) =
          GetOtProvider(party_j).RegisterReceiveFixedXcOt128(3 * number_of_simd);
    }
  }

  // allocate enough space for number_of_wires * number_of_simd garbled tables
  garbled_tables_.resize(size_of_all_garbled_tables);
  garbled_tables_.SetToZero();

  // store futures for the (partial) garbled tables we will receive during garbling
  received_garbled_rows_ = backend_.GetBmrProvider().RegisterForGarbledRows(gate_id_);

  if constexpr (kDebug) {
    auto gate_info = fmt::format("gate id {}, parents: {}, {}", gate_id_,
                                 parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    GetLogger().LogDebug(
        fmt::format("Created a BMR AND gate with following properties: {}", gate_info));
  }
}

AndGate::~AndGate() = default;

void AndGate::GenerateRandomness() {
  const auto number_of_wires{output_wires_.size()};
  for (auto wire_i = 0ull; wire_i < number_of_wires; ++wire_i) {
    auto bmr_output{std::dynamic_pointer_cast<bmr::Wire>(output_wires_.at(wire_i))};
    assert(bmr_output);
    bmr_output->GenerateRandomPermutationBits();
    bmr_output->GenerateRandomPrivateKeys();
    if constexpr (kVerboseDebug) {
      const auto my_id = GetCommunicationLayer().GetMyId();
      const auto number_of_simd{parent_a_.at(0)->GetNumberOfSimdValues()};
      for (auto simd_i = 0ull; simd_i < number_of_simd; ++simd_i) {
        const auto& key_0{bmr_output->GetSecretKeys().at(simd_i)};
        const auto& key_1{key_0 ^ backend_.GetBmrProvider().GetGlobalOffset()};

        const auto bmr_a = std::dynamic_pointer_cast<const bmr::Wire>(parent_a_.at(wire_i));
        const auto bmr_b = std::dynamic_pointer_cast<const bmr::Wire>(parent_b_.at(wire_i));
        assert(bmr_a);
        assert(bmr_b);
        bmr_a->GetSetupReadyCondition()->Wait();
        bmr_b->GetSetupReadyCondition()->Wait();
        GetLogger().LogTrace(fmt::format(
            "Gate#{} (BMR AND gate) Party#{} wire_i {} simd_i {} perm_bits (a {} b {} out {}) key0 "
            "{} key 1 {}\n",
            gate_id_, my_id, wire_i, simd_i, bmr_a->GetPermutationBits().AsString(),
            bmr_b->GetPermutationBits().AsString(), bmr_output->GetPermutationBits().AsString(),
            key_0.AsString(), key_1.AsString()));
      }
    }
    bmr_output->SetSetupIsReady();
  }
}

void AndGate::EvaluateSetup() {
  if constexpr (kDebug) {
    GetLogger().LogDebug(
        fmt::format("Start evaluating setup phase of BMR AND Gate with id#{}", gate_id_));
  }
  const auto& R{backend_.GetBmrProvider().GetGlobalOffset()};
  const auto number_of_wires{parent_a_.size()};
  const auto number_of_simd{parent_a_.at(0)->GetNumberOfSimdValues()};
  auto& communication_layer = GetCommunicationLayer();
  const auto my_id = communication_layer.GetMyId();
  const auto number_of_parties = communication_layer.GetNumberOfParties();
  [[maybe_unused]] const auto batch_size_3{number_of_simd * 3};

  // index function for the buffer of garbled tables
  const auto GetGarbledTableIndex = [number_of_simd, number_of_parties](auto wire_i, auto simd_i,
                                                                        auto row_i, auto party_i) {
    return wire_i * number_of_simd * 4 * number_of_parties + simd_i * (4 * number_of_parties) +
           row_i * number_of_parties + party_i;
  };

  if constexpr (kVerboseDebug) {
    GetLogger().LogTrace(
        fmt::format("Gate#{} (BMR AND gate) Party#{} R {}\n", gate_id_, my_id, R.AsString()));
  }

  // generate random keys and masking bits for the outgoing wires
  GenerateRandomness();

  // 1-bit OTs

  // structure: parties X wires X choice bits
  std::vector<std::vector<motion::BitVector<>>> choices(
      number_of_parties, std::vector<motion::BitVector<>>(number_of_wires));

  for (auto wire_i = 0ull; wire_i < number_of_wires; ++wire_i) {
    auto bmr_output{std::dynamic_pointer_cast<bmr::Wire>(output_wires_.at(wire_i))};
    const auto bmr_a{std::dynamic_pointer_cast<const bmr::Wire>(parent_a_.at(wire_i))};
    const auto bmr_b{std::dynamic_pointer_cast<const bmr::Wire>(parent_b_.at(wire_i))};
    assert(bmr_output);
    assert(bmr_a);
    assert(bmr_b);
    bmr_a->GetSetupReadyCondition()->Wait();
    bmr_b->GetSetupReadyCondition()->Wait();

    const motion::BitVector<>& a_permutation_bits = bmr_a->GetPermutationBits();
    const motion::BitVector<>& b_permutation_bits = bmr_b->GetPermutationBits();

    for (auto party_i = 0ull; party_i < number_of_parties; ++party_i) {
      if (party_i == my_id) {
        choices.at(party_i).at(wire_i) = a_permutation_bits & b_permutation_bits;
        continue;
      }

      auto& receiver_ot_1{receiver_ots_1_.at(party_i).at(wire_i)};
      auto& sender_ot_1{sender_ots_1_.at(party_i).at(wire_i)};

      if constexpr (kVerboseDebug) {
        GetLogger().LogTrace(fmt::format(
            "Gate#{} (BMR AND gate)  Party#{}-#{} bit-C-OTs wire_i {} perm_bits {} bits_a {} "
            "bits_b {} a&b {}\n",
            gate_id_, my_id, party_i, wire_i, bmr_output->GetPermutationBits().AsString(),
            bmr_a->GetPermutationBits().AsString(), bmr_b->GetPermutationBits().AsString(),
            choices.at(party_i).at(wire_i).AsString()));
      }
      // compute C-OTs for the real value, ie, b = (lambda_u ^ alpha) * (lambda_v ^ beta)

      receiver_ot_1->WaitSetup();
      sender_ot_1->WaitSetup();

      receiver_ot_1->SetChoices(b_permutation_bits);
      receiver_ot_1->SendCorrections();

      sender_ot_1->SetCorrelations(a_permutation_bits);
      sender_ot_1->SendMessages();
    }  // for each party
  }    // for each wire

  // kKappa-bit OTs

  for (auto wire_i = 0ull; wire_i < number_of_wires; ++wire_i) {
    auto bmr_output{std::dynamic_pointer_cast<bmr::Wire>(output_wires_.at(wire_i))};
    const auto bmr_a{std::dynamic_pointer_cast<const bmr::Wire>(parent_a_.at(wire_i))};
    const auto bmr_b{std::dynamic_pointer_cast<const bmr::Wire>(parent_b_.at(wire_i))};
    assert(bmr_output);
    assert(bmr_a);
    assert(bmr_b);
    for (auto party_i = 0ull; party_i < number_of_parties; ++party_i) {
      if (party_i == my_id) continue;
      auto& receiver_ot_1{receiver_ots_1_.at(party_i).at(wire_i)};
      auto& sender_ot_1{sender_ots_1_.at(party_i).at(wire_i)};

      assert(receiver_ot_1->AreChoicesSet());
      receiver_ot_1->ComputeOutputs();
      const auto& receiver_bitvector = receiver_ot_1->GetOutputs();
      sender_ot_1->ComputeOutputs();
      const auto& sender_bitvector = sender_ot_1->GetOutputs();

      choices.at(party_i).at(wire_i) = receiver_bitvector ^ sender_bitvector;

      if constexpr (kVerboseDebug) {
        const auto& receiver_bitvector_check = receiver_ot_1->GetChoices();
        const auto& sender_bitvector_check = sender_ot_1->GetCorrelations();
        GetLogger().LogTrace(fmt::format(
            "Gate#{} (BMR AND gate) Party#{}-#{} bit-C-OTs wire_i {} bits from C-OTs r {} s {} "
            "result {} (r {} s {})\n",
            gate_id_, my_id, party_i, wire_i, receiver_bitvector.AsString(),
            sender_bitvector.AsString(), choices.at(party_i).at(wire_i).AsString(),
            receiver_bitvector_check.AsString(), sender_bitvector_check.AsString()));
      }
    }  // for each party
  }    // for each wire

  // choices contain now shares of \lambda_{uv}^i

  std::vector<motion::BitVector<>> aggregated_choices(number_of_wires);

  for (auto wire_i = 0ull; wire_i < number_of_wires; ++wire_i) {
    auto bmr_output{std::dynamic_pointer_cast<bmr::Wire>(output_wires_.at(wire_i))};
    const auto bmr_a{std::dynamic_pointer_cast<const bmr::Wire>(parent_a_.at(wire_i))};
    const auto bmr_b{std::dynamic_pointer_cast<const bmr::Wire>(parent_b_.at(wire_i))};
    assert(bmr_output);
    assert(bmr_a);
    assert(bmr_b);

    const auto& out_permutation_bits = bmr_output->GetPermutationBits();
    const auto& a_permutation_bits = bmr_a->GetPermutationBits();
    const auto& b_permutation_bits = bmr_b->GetPermutationBits();

    assert(choices.at(0).at(wire_i).GetSize() == number_of_simd);
    auto& aggregated_choices_fw = aggregated_choices.at(wire_i);
    aggregated_choices_fw = motion::BitVector<>(3 * number_of_simd, false);
    for (auto bit_i = 0ull; bit_i < number_of_simd; ++bit_i) {
      bool bit_value = out_permutation_bits.Get(bit_i);  // \lambda_w^i
      for (auto party_i = 0ull; party_i < number_of_parties; ++party_i) {
        bit_value ^= choices.at(party_i).at(wire_i).Get(bit_i);  // \lambda_uv^i
      }
      aggregated_choices_fw.Set(bit_value, bit_i * 3);
      aggregated_choices_fw.Set(bit_value ^ a_permutation_bits[bit_i], bit_i * 3 + 1);
      aggregated_choices_fw.Set(bit_value ^ b_permutation_bits[bit_i], bit_i * 3 + 2);
    }

    for (auto party_i = 0ull; party_i < number_of_parties; ++party_i) {
      if (party_i == my_id) continue;
      // multiply individual parties' R's with the secret-shared real value XORed with
      // the permutation bit of the output wire, ie, R * (b ^ lambda_w)
      receiver_ots_kappa_.at(party_i).at(wire_i)->SetChoices(aggregated_choices.at(wire_i));
      receiver_ots_kappa_.at(party_i).at(wire_i)->SendCorrections();

      sender_ots_kappa_.at(party_i).at(wire_i)->SetCorrelation(R);
      sender_ots_kappa_.at(party_i).at(wire_i)->SendMessages();
    }
  }  // for each wire

  // AES key expansion
  motion::primitives::Prg prg;
  prg.SetKey(GetBaseProvider().GetAesFixedKey().data());
  const auto aes_round_keys = prg.GetRoundKeys();

  // Compute garbled rows
  // First, set rows to PRG outputs XOR key
  for (auto wire_i = 0ull; wire_i < number_of_wires; ++wire_i) {
    auto bmr_output{std::dynamic_pointer_cast<bmr::Wire>(output_wires_.at(wire_i))};
    assert(bmr_output);
    const auto bmr_a{std::dynamic_pointer_cast<const bmr::Wire>(parent_a_.at(wire_i))};
    const auto bmr_b{std::dynamic_pointer_cast<const bmr::Wire>(parent_b_.at(wire_i))};
    assert(bmr_a);
    assert(bmr_b);

    for (auto simd_i = 0ull; simd_i < number_of_simd; ++simd_i) {
      const auto& key_a_0{bmr_a->GetSecretKeys().at(simd_i)};
      const auto& key_a_1{key_a_0 ^ R};
      const auto& key_b_0{bmr_b->GetSecretKeys().at(simd_i)};
      const auto& key_b_1{key_b_0 ^ R};

      // TODO: fix gate id computation
      const auto gate_id = static_cast<uint64_t>(bmr_output->GetWireId() + simd_i);

      AesniBmrDkc(aes_round_keys, key_a_0.data(), key_b_0.data(), gate_id, number_of_parties,
                  &garbled_tables_[GetGarbledTableIndex(wire_i, simd_i, 0, 0)]);
      AesniBmrDkc(aes_round_keys, key_a_0.data(), key_b_1.data(), gate_id, number_of_parties,
                  &garbled_tables_[GetGarbledTableIndex(wire_i, simd_i, 1, 0)]);
      AesniBmrDkc(aes_round_keys, key_a_1.data(), key_b_0.data(), gate_id, number_of_parties,
                  &garbled_tables_[GetGarbledTableIndex(wire_i, simd_i, 2, 0)]);
      AesniBmrDkc(aes_round_keys, key_a_1.data(), key_b_1.data(), gate_id, number_of_parties,
                  &garbled_tables_[GetGarbledTableIndex(wire_i, simd_i, 3, 0)]);

      const auto& key_w_0 = bmr_output->GetSecretKeys()[simd_i];
      garbled_tables_[GetGarbledTableIndex(wire_i, simd_i, 0, my_id)] ^= key_w_0;
      garbled_tables_[GetGarbledTableIndex(wire_i, simd_i, 1, my_id)] ^= key_w_0;
      garbled_tables_[GetGarbledTableIndex(wire_i, simd_i, 2, my_id)] ^= key_w_0;
      garbled_tables_[GetGarbledTableIndex(wire_i, simd_i, 3, my_id)] ^= key_w_0 ^ R;

      for (auto party_i = 0ull; party_i < number_of_parties; ++party_i) {
        std::array<motion::Block128, 3> shared_R;
        const auto zero_block = motion::Block128::MakeZero();

        if (party_i == my_id) {
          shared_R.at(0) = aggregated_choices.at(wire_i)[simd_i * 3] ? R : zero_block;
          shared_R.at(1) = aggregated_choices.at(wire_i)[simd_i * 3 + 1] ? R : zero_block;
          shared_R.at(2) = aggregated_choices.at(wire_i)[simd_i * 3 + 2] ? R : zero_block;
        } else {
          shared_R.at(0) = shared_R.at(1) = shared_R.at(2) = zero_block;
        }

        // R's from C-OTs
        if (party_i == my_id) {
          for (auto party_j = 0ull; party_j < number_of_parties; ++party_j) {
            if (party_j == my_id) continue;

            sender_ots_kappa_.at(party_j).at(wire_i)->ComputeOutputs();
            const auto& sender_output = sender_ots_kappa_.at(party_j).at(wire_i)->GetOutputs();
            assert(sender_output.size() == number_of_simd * 3);
            const auto R00 = sender_output[simd_i * 3];
            const auto R01 = sender_output[simd_i * 3 + 1];
            const auto R10 = sender_output[simd_i * 3 + 2];

            shared_R.at(0) ^= R00;
            shared_R.at(1) ^= R01;
            shared_R.at(2) ^= R10;

            if (kVerboseDebug) {
              GetLogger().LogTrace(fmt::format(
                  "Gate#{} (BMR AND gate) Me#{}: Party#{} received R's \n00 ({}) \n01 ({}) \n10 "
                  "({})\n",
                  gate_id_, my_id, party_i, R00.AsString(), R01.AsString(), R10.AsString()));
            }
          }
        } else {
          assert(receiver_ots_kappa_.at(party_i).at(wire_i)->AreChoicesSet());
          receiver_ots_kappa_.at(party_i).at(wire_i)->ComputeOutputs();
          const auto& receiver_output = receiver_ots_kappa_.at(party_i).at(wire_i)->GetOutputs();
          assert(receiver_output.size() == number_of_simd * 3);
          const auto R00 = receiver_output[simd_i * 3];
          const auto R01 = receiver_output[simd_i * 3 + 1];
          const auto R10 = receiver_output[simd_i * 3 + 2];

          shared_R.at(0) ^= R00;
          shared_R.at(1) ^= R01;
          shared_R.at(2) ^= R10;
        }

        if constexpr (kVerboseDebug) {
          GetLogger().LogTrace(
              fmt::format("Gate#{} (BMR AND gate) Me#{}: Shared R's \n00 ({}) \n01 ({}) \n10 "
                          "({})\n",
                          gate_id_, my_id, party_i, shared_R.at(0).AsString(),
                          shared_R.at(1).AsString(), shared_R.at(2).AsString()));
        }

        garbled_tables_[GetGarbledTableIndex(wire_i, simd_i, 0, party_i)] ^= shared_R[0];
        garbled_tables_[GetGarbledTableIndex(wire_i, simd_i, 1, party_i)] ^= shared_R[1];
        garbled_tables_[GetGarbledTableIndex(wire_i, simd_i, 2, party_i)] ^= shared_R[2];
        garbled_tables_[GetGarbledTableIndex(wire_i, simd_i, 3, party_i)] ^=
            shared_R[0] ^ shared_R[1] ^ shared_R[2];
      }  // for each party
    }    // for each simd
  }      // for each wire

  if constexpr (kVerboseDebug) {
    std::string s{fmt::format("Me#{}: ", my_id)};
    assert(garbled_tables_.size() == number_of_wires * number_of_simd * 4 * number_of_parties);
    for (auto wire_j = 0ull; wire_j < number_of_wires; ++wire_j) {
      s.append(fmt::format(" Wire #{}: ", wire_j));
      for (auto simd_k = 0ull; simd_k < number_of_simd; ++simd_k) {
        s.append(fmt::format("\nSIMD #{}: ", simd_k));
        for (auto row_l = 0ull; row_l < 4; ++row_l) {
          s.append(fmt::format("\nRow #{}: ", row_l));
          for (auto party_i = 0ull; party_i < number_of_parties; ++party_i) {
            s.append(fmt::format("\nParty #{}: ", party_i));
            s.append(
                fmt::format(" garbled rows {} ",
                            garbled_tables_.at(GetGarbledTableIndex(wire_j, simd_k, row_l, party_i))
                                .AsString()));
          }
        }
      }
    }
    s.append("\n");
    GetLogger().LogTrace(s);
  }

  // send out our partial garbled tables
  std::span send_message_buffer(reinterpret_cast<const std::uint8_t*>(garbled_tables_.data()),
                                garbled_tables_.ByteSize());
  auto msg{communication::BuildMessage(communication::MessageType::kBmrAndGate, gate_id_,
                                       send_message_buffer)};
  communication_layer.BroadcastMessage(msg.Release());

  // finalize garbled tables
  for (auto party_i = 0ull; party_i < number_of_parties; ++party_i) {
    if (party_i == my_id) continue;
    auto remapped_party_i{party_i > my_id ? party_i - 1 : party_i};
    std::vector<std::uint8_t> garbled_rows_message = received_garbled_rows_[remapped_party_i].get();
    auto pointer{reinterpret_cast<const std::byte*>(
        communication::GetMessage(garbled_rows_message.data())->payload()->data())};
    assert(communication::GetMessage(garbled_rows_message.data())->payload()->size() ==
           garbled_tables_.size() * kKappa / 8);
    std::transform(pointer, pointer + garbled_tables_.size() * Block128::size(),
                   garbled_tables_[0].data(), garbled_tables_[0].data(), std::bit_xor<std::byte>());
  }

  // mark this gate as setup-ready to proceed with the online phase
  if constexpr (kDebug) {
    GetLogger().LogDebug(
        fmt::format("Finished evaluating setup phase of BMR AND Gate with id#{}", gate_id_));
  }
}

void AndGate::EvaluateOnline() {
  WaitSetup();

  if constexpr (kDebug) {
    GetLogger().LogDebug(
        fmt::format("Start evaluating online phase of BMR AND Gate with id#{}", gate_id_));
  }

  auto& communication_layer = GetCommunicationLayer();
  const auto my_id = communication_layer.GetMyId();
  const auto number_of_parties = communication_layer.GetNumberOfParties();
  const auto number_of_wires = output_wires_.size();
  const auto number_of_simd = output_wires_.at(0)->GetNumberOfSimdValues();
  const auto& R = backend_.GetBmrProvider().GetGlobalOffset();

  // index function for the public/active keys stored in the wires
  const auto PublicKeyIndex = [number_of_parties](auto simd_i, auto party_i) {
    return simd_i * number_of_parties + party_i;
  };

  // index function for the buffer of garbled tables
  const auto GetGarbledTableIndex = [number_of_simd, number_of_parties](auto wire_i, auto simd_i,
                                                                        auto row_i, auto party_i) {
    return wire_i * number_of_simd * 4 * number_of_parties + simd_i * (4 * number_of_parties) +
           row_i * number_of_parties + party_i;
  };

  if constexpr (kVerboseDebug) {
    for (auto wire_i = 0ull; wire_i < number_of_wires; ++wire_i) {
      for (auto simd_j = 0ull; simd_j < number_of_simd; ++simd_j) {
        for (auto row_l = 0ull; row_l < 4; ++row_l) {
          for (auto party_i = 0ull; party_i < number_of_parties; ++party_i) {
            GetLogger().LogTrace(
                fmt::format("Party#{}: reconstructed gr for Party#{} Wire#{} SIMD#{} Row#{}: {}\n",
                            my_id, party_i, wire_i, simd_j, row_l,
                            garbled_tables_.at(GetGarbledTableIndex(wire_i, simd_j, row_l, party_i))
                                .AsString()));
          }
        }
      }
    }
  }

  // AES key expansion
  motion::primitives::Prg prg;
  prg.SetKey(GetBaseProvider().GetAesFixedKey().data());
  const auto aes_round_keys = prg.GetRoundKeys();

  for (auto wire_i = 0ull; wire_i < number_of_wires; ++wire_i) {
    auto bmr_output = std::dynamic_pointer_cast<bmr::Wire>(output_wires_.at(wire_i));
    assert(bmr_output);
    const auto wire_a = std::dynamic_pointer_cast<const bmr::Wire>(parent_a_.at(wire_i));
    const auto wire_b = std::dynamic_pointer_cast<const bmr::Wire>(parent_b_.at(wire_i));
    assert(wire_a);
    assert(wire_b);

    wire_a->GetIsReadyCondition().Wait();
    wire_b->GetIsReadyCondition().Wait();

    for (auto simd_i = 0ull; simd_i < number_of_simd; ++simd_i) {
      // TODO: fix gate id computation
      const auto gate_id = static_cast<uint64_t>(bmr_output->GetWireId() + simd_i);

      // compute index of the correct row in the garbled table
      const bool alpha = wire_a->GetPublicValues()[simd_i],
                 beta = wire_b->GetPublicValues()[simd_i];
      const std::size_t row_index =
          static_cast<std::size_t>(alpha) * 2 + static_cast<std::size_t>(beta);

      // decrypt that row of the garbled table
      for (auto party_i = 0ull; party_i < number_of_parties; ++party_i) {
        const auto& key_a = wire_a->GetPublicKeys().at(PublicKeyIndex(simd_i, party_i));
        const auto& key_b = wire_b->GetPublicKeys().at(PublicKeyIndex(simd_i, party_i));
        AesniBmrDkc(aes_round_keys, key_a.data(), key_b.data(), gate_id, number_of_parties,
                    &garbled_tables_[GetGarbledTableIndex(wire_i, simd_i, row_index, 0)]);
      }

      // copy decrypted public keys to outgoing wire
      std::copy(
          std::begin(garbled_tables_) + GetGarbledTableIndex(wire_i, simd_i, row_index, 0),
          std::begin(garbled_tables_) + GetGarbledTableIndex(wire_i, simd_i, row_index + 1, 0),
          std::begin(bmr_output->GetMutablePublicKeys()) + PublicKeyIndex(simd_i, 0));

      if constexpr (kVerboseDebug) {
        std::string s;
        s.append(fmt::format("Me#{}: wire#{} simd#{} result\n", my_id, wire_i, simd_i));
        s.append(fmt::format("Public values a {} b {} ", wire_a->GetPublicValues().AsString(),
                             wire_b->GetPublicValues().AsString()));
        s.append("\n");
        s.append(fmt::format("output skey0 {} skey1 {}\n",
                             bmr_output->GetSecretKeys().at(simd_i).AsString(),
                             (bmr_output->GetSecretKeys().at(simd_i) ^ R).AsString()));
        GetLogger().LogTrace(s);
      }
    }  // for each simd

    // figure out the public value of the outputs
    for (auto simd_i = 0ull; simd_i < number_of_simd; ++simd_i) {
      // check if our part of the output super key is different to our "0 key"
      const bool different_to_0_key = bmr_output->GetPublicKeys().at(PublicKeyIndex(
                                          simd_i, my_id)) != bmr_output->GetSecretKeys().at(simd_i);
      if (different_to_0_key) {
        // then it should be equal to the "1 key" which is the "0 key" xored with the global offset
        assert(bmr_output->GetPublicKeys().at(PublicKeyIndex(simd_i, my_id)) ==
               (bmr_output->GetSecretKeys().at(simd_i) ^ R));
      }
      bmr_output->GetMutablePublicValues().Set(different_to_0_key, simd_i);
    }
    if constexpr (kVerboseDebug) {
      GetLogger().LogTrace(fmt::format("Party#{} wire#{} public values result {}\n", my_id, wire_i,
                                       bmr_output->GetPublicValues().AsString()));
    }
  }  // for each wire

  if constexpr (kVerboseDebug) {
    GetLogger().LogTrace(fmt::format("Evaluated BMR AND Gate with id#{}", gate_id_));
  }

  if constexpr (kDebug) {
    for (auto& wire : output_wires_) {
      const auto bmr_wire = std::dynamic_pointer_cast<const bmr::Wire>(wire);
      assert(bmr_wire);
      assert(!bmr_wire->GetPermutationBits().Empty());
    }
  }

  assert(!online_is_ready_);
}

const bmr::SharePointer AndGate::GetOutputAsBmrShare() const {
  auto result = std::make_shared<bmr::Share>(output_wires_);
  assert(result);
  return result;
}

const motion::SharePointer AndGate::GetOutputAsShare() const {
  auto result = std::static_pointer_cast<bmr::Share>(GetOutputAsBmrShare());
  assert(result);
  return result;
}

}  // namespace encrypto::motion::proto::bmr
