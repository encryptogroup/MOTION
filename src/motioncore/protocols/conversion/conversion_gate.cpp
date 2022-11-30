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
#include "communication/communication_layer.h"
#include "communication/message.h"
#include "protocols/bmr/bmr_gate.h"
#include "protocols/bmr/bmr_provider.h"
#include "protocols/bmr/bmr_share.h"
#include "protocols/bmr/bmr_wire.h"
#include "protocols/boolean_gmw/boolean_gmw_share.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "secure_type/secure_unsigned_integer.h"
#include "utility/bit_vector.h"
#include "utility/constants.h"
#include "utility/fiber_condition.h"

// added by Liang Zhao
#include "protocols/garbled_circuit/garbled_circuit_constants.h"
#include "protocols/garbled_circuit/garbled_circuit_gate.h"
#include "protocols/garbled_circuit/garbled_circuit_provider.h"
#include "protocols/garbled_circuit/garbled_circuit_share.h"
#include "protocols/garbled_circuit/garbled_circuit_wire.h"

namespace encrypto::motion {

BmrToBooleanGmwGate::BmrToBooleanGmwGate(const SharePointer& parent)
    : OneGate(parent->GetBackend()) {
  parent_ = parent->GetWires();

  assert(parent_.size() > 0);
  assert(parent_.at(0)->GetBitLength() > 0);
  for ([[maybe_unused]] const auto& wire : parent_)
    assert(wire->GetProtocol() == MpcProtocol::kBmr);

  // create output wires
  auto number_of_wires = parent_.size();
  output_wires_.reserve(number_of_wires);

  for (size_t i = 0; i < number_of_wires; ++i) {
    output_wires_.emplace_back(GetRegister().EmplaceWire<proto::boolean_gmw::Wire>(
        backend_, parent->GetNumberOfSimdValues()));
  }

  if constexpr (kDebug) {
    auto gate_info = fmt::format("gate id {}, parent wires: ", gate_id_);
    for (const auto& wire : parent_) gate_info.append(fmt::format("{} ", wire->GetWireId()));
    gate_info.append(" output wires: ");
    for (const auto& wire : output_wires_) gate_info.append(fmt::format("{} ", wire->GetWireId()));
    GetLogger().LogDebug(fmt::format(
        "Created a BMR to Boolean GMW conversion gate with following properties: {}", gate_info));
  }
}

void BmrToBooleanGmwGate::EvaluateSetup() {}

void BmrToBooleanGmwGate::EvaluateOnline() {
  // nothing to setup, no need to wait/check
  if constexpr (kDebug) {
    GetLogger().LogDebug(fmt::format(
        "Start evaluating online phase of BMR to Boolean GMW Gate with id#{}", gate_id_));
  }

  for (auto i = 0ull; i < parent_.size(); ++i) {
    auto bmr_input{std::dynamic_pointer_cast<const proto::bmr::Wire>(parent_.at(i))};
    assert(bmr_input);

    auto gmw_output{std::dynamic_pointer_cast<proto::boolean_gmw::Wire>(output_wires_.at(i))};
    assert(gmw_output);

    bmr_input->GetIsReadyCondition().Wait();
    const auto& communication_layer = GetCommunicationLayer();
    const auto my_id = communication_layer.GetMyId();
    const auto number_of_parties = communication_layer.GetNumberOfParties();
    auto& v{gmw_output->GetMutableValues()};

    // set current gmw shared bits on wire to permutation bits of parent BMR wire
    v = bmr_input->GetPermutationBits();

    // one party needs to XOR shared GMW bits with the public values of BMR wire
    // the party doing this is chosen based on the wire id for the purpose of load balancing
    if ((gmw_output->GetWireId() % number_of_parties) == my_id) v ^= bmr_input->GetPublicValues();
  }

  if constexpr (kDebug) {
    GetLogger().LogDebug(fmt::format(
        "Finished evaluating online phase of BMR to Boolean GMW Gate with id#{}", gate_id_));
  }
}

const proto::boolean_gmw::SharePointer BmrToBooleanGmwGate::GetOutputAsGmwShare() const {
  auto result = std::make_shared<proto::boolean_gmw::Share>(output_wires_);
  assert(result);
  return result;
}

const SharePointer BmrToBooleanGmwGate::GetOutputAsShare() const {
  auto result = std::static_pointer_cast<Share>(GetOutputAsGmwShare());
  assert(result);
  return result;
}

BooleanGmwToBmrGate::BooleanGmwToBmrGate(const SharePointer& parent)
    : OneGate(parent->GetBackend()) {
  parent_ = parent->GetWires();

  assert(parent_.size() > 0);
  assert(parent_.at(0)->GetBitLength() > 0);
  for ([[maybe_unused]] const auto& wire : parent_)
    assert(wire->GetProtocol() == MpcProtocol::kBooleanGmw);

  output_wires_.resize(parent_.size());
  for (auto& w : output_wires_) {
    w = GetRegister().EmplaceWire<proto::bmr::Wire>(backend_, parent_[0]->GetNumberOfSimdValues());
  }

  assert(gate_id_ >= 0);

  auto& bmr_provider = backend_.GetBmrProvider();
  received_public_keys_ = bmr_provider.RegisterForInputKeys(gate_id_);
  received_public_values_ = bmr_provider.RegisterForInputPublicValues(gate_id_);

  if constexpr (kDebug) {
    auto gate_info = fmt::format("gate id {}, parent wires: ", gate_id_);
    for (const auto& wire : parent_) gate_info.append(fmt::format("{} ", wire->GetWireId()));
    gate_info.append(" output wires: ");
    for (const auto& wire : output_wires_) gate_info.append(fmt::format("{} ", wire->GetWireId()));
    GetLogger().LogDebug(fmt::format(
        "Created a Boolean GMW to BMR conversion gate with following properties: {}", gate_info));
  }
}

void BooleanGmwToBmrGate::EvaluateSetup() {
  if constexpr (kDebug) {
    GetLogger().LogDebug(fmt::format(
        "Start evaluating setup phase of Boolean GMW to BMR Gate with id#{}", gate_id_));
  }

  for (auto wire_i = 0ull; wire_i < output_wires_.size(); ++wire_i) {
    auto bmr_output = std::dynamic_pointer_cast<proto::bmr::Wire>(output_wires_.at(wire_i));
    assert(bmr_output);
    bmr_output->GenerateRandomPrivateKeys();
    bmr_output->GenerateRandomPermutationBits();
    bmr_output->SetSetupIsReady();
  }
  if constexpr (kDebug) {
    GetLogger().LogDebug(fmt::format(
        "Finished evaluating setup phase of Boolean GMW to BMR Gate with id#{}", gate_id_));
  }
}

void BooleanGmwToBmrGate::EvaluateOnline() {
  WaitSetup();
  if constexpr (kDebug) {
    GetLogger().LogDebug(fmt::format(
        "Start evaluating online phase of Boolean GMW to BMR Gate with id#{}", gate_id_));
  }

  const auto number_of_simd{output_wires_.at(0)->GetNumberOfSimdValues()};
  const auto number_of_wires{output_wires_.size()};
  auto& communication_layer = GetCommunicationLayer();
  const auto my_id = communication_layer.GetMyId();
  const auto number_of_parties = communication_layer.GetNumberOfParties();
  const auto& R = backend_.GetBmrProvider().GetGlobalOffset();
  BitVector<> buffer;

  // mask and publish inputs
  for (std::size_t i = 0; i < output_wires_.size(); ++i) {
    auto gmw_input = std::dynamic_pointer_cast<const proto::boolean_gmw::Wire>(parent_.at(i));
    assert(gmw_input);
    auto bmr_output = std::dynamic_pointer_cast<proto::bmr::Wire>(output_wires_.at(i));
    assert(bmr_output);
    gmw_input->GetIsReadyCondition().Wait();
    bmr_output->GetMutablePublicValues() =
        gmw_input->GetValues() ^ bmr_output->GetPermutationBits();
    buffer.Append(bmr_output->GetPublicValues());
  }

  std::span payload_pub_vals(reinterpret_cast<const std::uint8_t*>(buffer.GetData().data()),
                             buffer.GetData().size());
  auto msg_pub_vals{communication::BuildMessage(communication::MessageType::kBmrInputGate0,
                                                gate_id_, payload_pub_vals)};
  communication_layer.BroadcastMessage(msg_pub_vals.Release());

  // receive masked values if not my input
  for (std::size_t party_id = 0; party_id < number_of_parties; ++party_id) {
    if (party_id == my_id) continue;
    auto public_values_message{
        received_public_values_[party_id > my_id ? party_id - 1 : party_id].get()};
    auto pointer{const_cast<std::uint8_t*>(
        communication::GetMessage(public_values_message.data())->payload()->data())};
    BitSpan public_values_span(pointer, number_of_wires * number_of_simd);
    for (std::size_t i = 0; i < number_of_wires; ++i) {
      auto bmr_output = std::dynamic_pointer_cast<proto::bmr::Wire>(output_wires_[i]);
      assert(bmr_output);
      bmr_output->GetMutablePublicValues() ^=
          public_values_span.Subset(i * number_of_simd, (i + 1) * number_of_simd);
    }
  }

  // rearrange keys corresponding to the public values into one buffer
  Block128Vector my_keys_buffer(number_of_wires * number_of_simd);
  for (std::size_t wire_i = 0; wire_i < number_of_wires; ++wire_i) {
    const auto wire = std::dynamic_pointer_cast<const proto::bmr::Wire>(output_wires_[wire_i]);
    assert(wire);
    const auto& keys = wire->GetSecretKeys();
    // copy the "0 keys" into the buffer
    std::copy(std::begin(keys), std::end(keys),
              std::begin(my_keys_buffer) + wire_i * number_of_simd);
    const auto& public_values = wire->GetPublicValues();
    for (std::size_t simd_j = 0; simd_j < number_of_simd; ++simd_j) {
      // xor the offset on a key if the corresponding public value is 1
      if (public_values[simd_j]) {
        my_keys_buffer.at(wire_i * number_of_simd + simd_j) ^= R;
      }
    }
  }

  // send the selected keys to all other parties
  std::span my_keys_payload(reinterpret_cast<const std::uint8_t*>(my_keys_buffer.data()),
                            my_keys_buffer.ByteSize());
  auto my_keys_msg{communication::BuildMessage(communication::MessageType::kBmrInputGate1, gate_id_,
                                               my_keys_payload)};
  communication_layer.BroadcastMessage(my_keys_msg.Release());

  // index function for the public/active keys stored in the wires
  const auto public_key_index = [number_of_parties](auto simd_i, auto party_i) {
    return simd_i * number_of_parties + party_i;
  };

  // receive the published keys from the other parties
  // and construct the active super keys for the output wires
  for (auto party_i = 0ull; party_i < number_of_parties; ++party_i) {
    if (party_i == my_id) {
      // our case: we can copy the keys we have already prepared above in
      // my_keys_buffer to the right positions
      for (auto wire_j = 0ull; wire_j < number_of_wires; ++wire_j) {
        auto wire = std::dynamic_pointer_cast<proto::bmr::Wire>(output_wires_.at(wire_j));
        assert(wire);
        auto& public_keys = wire->GetMutablePublicKeys();
        for (auto simd_k = 0ull; simd_k < number_of_simd; ++simd_k) {
          public_keys.at(public_key_index(simd_k, my_id)) =
              my_keys_buffer.at(wire_j * number_of_simd + simd_k);
        }
      }
    } else {
      // other party: we copy the received keys to the right position
      auto received_keys_buffer =
          received_public_keys_.at(party_i > my_id ? party_i - 1 : party_i).get();
      const std::uint8_t* pointer{
          communication::GetMessage(received_keys_buffer.data())->payload()->data()};
      for (auto wire_j = 0ull; wire_j < number_of_wires; ++wire_j) {
        auto wire = std::dynamic_pointer_cast<proto::bmr::Wire>(output_wires_.at(wire_j));
        assert(wire);
        auto& public_keys = wire->GetMutablePublicKeys();
        for (auto simd_k = 0ull; simd_k < number_of_simd; ++simd_k) {
          std::copy_n(reinterpret_cast<const std::byte*>(pointer) +
                          Block128::size() * (wire_j * number_of_simd + simd_k),
                      Block128::size(), public_keys[public_key_index(simd_k, party_i)].data());
        }
      }
    }
  }

  if constexpr (kDebug) {
    GetLogger().LogDebug(fmt::format(
        "Finished evaluating online phase of Boolean GMW to BMR Gate with id#{}", gate_id_));
  }
}

const proto::bmr::SharePointer BooleanGmwToBmrGate::GetOutputAsBmrShare() const {
  auto result = std::make_shared<proto::bmr::Share>(output_wires_);
  assert(result);
  return result;
}

const SharePointer BooleanGmwToBmrGate::GetOutputAsShare() const {
  auto result = std::static_pointer_cast<Share>(GetOutputAsBmrShare());
  assert(result);
  return result;
}

ArithmeticGmwToBmrGate::ArithmeticGmwToBmrGate(const SharePointer& parent)
    : OneGate(parent->GetBackend()) {
  parent_ = parent->GetWires();

  assert(parent_.size() == 1);
  assert(parent_[0]->GetBitLength() > 0);
  for ([[maybe_unused]] const auto& wire : parent_)
    assert(wire->GetProtocol() == MpcProtocol::kArithmeticGmw);

  // ArithmeticGmwToBmrGate does not own its output wires, since these are the output wires of the
  // last BMR addition circuit. Thus, Gate::SetOnlineReady should not mark the output wires
  // online-ready.
  own_output_wires_ = false;

  assert(gate_id_ >= 0);
  const auto& communication_layer = GetCommunicationLayer();
  const auto my_id = communication_layer.GetMyId();
  const auto number_of_parties = communication_layer.GetNumberOfParties();
  const auto bitlength{parent_[0]->GetBitLength()};
  const auto number_of_simd{parent_[0]->GetNumberOfSimdValues()};

  std::vector<SecureUnsignedInteger> shares;
  shares.reserve(number_of_parties);
  // each party re-shares its arithmetic GMW share in BMR
  for (std::size_t party_id = 0; party_id < number_of_parties; ++party_id) {
    const auto input_gate = GetRegister().EmplaceGate<proto::bmr::InputGate>(
        number_of_simd, bitlength, party_id, backend_);
    // the party owning the share takes the input promise to assign its input when the parent wires
    // are online-ready
    if (party_id == my_id) input_promise_ = &input_gate->GetInputPromise();

    shares.emplace_back(ShareWrapper(input_gate->GetOutputAsShare()));
  }

  // securely compute the sum of the arithmetic GMW shares to get a valid BMR share
  auto result{shares[0]};
  for (auto share_i = 1ull; share_i < shares.size(); ++share_i) result += shares[share_i];

  // the sum of the shares is a valid BMR share, which output wires are the output wires of the
  // AGMW to BMR conversion gate
  output_wires_ = result.Get()->GetWires();

  if constexpr (kDebug) {
    auto gate_info = fmt::format("gate id {}, parent wires: ", gate_id_);
    for (const auto& wire : parent_) gate_info.append(fmt::format("{} ", wire->GetWireId()));
    gate_info.append(" output wires: ");
    for (const auto& wire : output_wires_) gate_info.append(fmt::format("{} ", wire->GetWireId()));
    GetLogger().LogDebug(
        fmt::format("Created a Arithmetic GMW to BMR conversion gate with following properties: {}",
                    gate_info));
  }
}

void ArithmeticGmwToBmrGate::EvaluateSetup() {}

void ArithmeticGmwToBmrGate::EvaluateOnline() {
  // nothing to setup, no need to wait/check
  if constexpr (kDebug) {
    GetLogger().LogDebug(fmt::format(
        "Start evaluating online phase of Boolean GMW to BMR Gate with id#{}", gate_id_));
  }

  const auto bitlength = parent_[0]->GetBitLength();
  parent_[0]->GetIsReadyCondition().Wait();

  switch (bitlength) {
    case 8: {
      auto w{std::dynamic_pointer_cast<proto::arithmetic_gmw::Wire<std::uint8_t>>(parent_[0])};
      assert(w);
      input_promise_->set_value(ToInput(w->GetValues()));
      break;
    }
    case 16: {
      auto w{std::dynamic_pointer_cast<proto::arithmetic_gmw::Wire<std::uint16_t>>(parent_[0])};
      assert(w);
      input_promise_->set_value(ToInput(w->GetValues()));
      break;
    }
    case 32: {
      auto w{std::dynamic_pointer_cast<proto::arithmetic_gmw::Wire<std::uint32_t>>(parent_[0])};
      assert(w);
      input_promise_->set_value(ToInput(w->GetValues()));
      break;
    }
    case 64: {
      auto w{std::dynamic_pointer_cast<proto::arithmetic_gmw::Wire<std::uint64_t>>(parent_[0])};
      assert(w);
      input_promise_->set_value(ToInput(w->GetValues()));
      break;
    }

      // added by Liang Zhao
    case 128: {
      auto w{std::dynamic_pointer_cast<proto::arithmetic_gmw::Wire<__uint128_t>>(parent_[0])};
      assert(w);
      input_promise_->set_value(ToInput(w->GetValues()));
      break;
    }

    default:
      throw std::logic_error(fmt::format("Illegal bitlength: {}", bitlength));
  }

  if constexpr (kDebug) {
    GetLogger().LogDebug(fmt::format(
        "Finished evaluating online phase of Boolean GMW to BMR Gate with id#{}", gate_id_));
  }
}

const proto::bmr::SharePointer ArithmeticGmwToBmrGate::GetOutputAsBmrShare() const {
  auto result = std::make_shared<proto::bmr::Share>(output_wires_);
  assert(result);
  return result;
}

const SharePointer ArithmeticGmwToBmrGate::GetOutputAsShare() const {
  auto result = std::static_pointer_cast<Share>(GetOutputAsBmrShare());
  assert(result);
  return result;
}

// added by Liang Zhao
BooleanGmwToGCGate::BooleanGmwToGCGate(const SharePointer& parent) : OneGate(parent->GetBackend()) {
  is_garbler_ = backend_.GetCommunicationLayer().GetMyId() ==
                static_cast<std::size_t>(GarbledCircuitRole::kGarbler);
  is_evaluator_ = !is_garbler_;

  parent_ = parent->GetWires();

  assert(parent_.size() > 0);
  assert(parent_.at(0)->GetBitLength() > 0);
  for ([[maybe_unused]] const auto& wire : parent_)
    assert(wire->GetProtocol() == MpcProtocol::kBooleanGmw);

  output_wires_.resize(parent_.size());
  // for (auto& w : output_wires_) {
  //   w = GetRegister().EmplaceWire<proto::garbled_circuit::Wire>(backend_,
  //   parent_[0]->GetNumberOfSimdValues());
  // }
  number_of_simd_ = parent_[0]->GetNumberOfSimdValues();
  number_of_wires_ = parent_.size();
  my_id_ = GetCommunicationLayer().GetMyId();
  bitlength_ = parent_[0]->GetBitLength();

  std::size_t garbler_id = static_cast<std::size_t>(GarbledCircuitRole::kGarbler);
  std::size_t evaluator_id = static_cast<std::size_t>(GarbledCircuitRole::kEvaluator);

  std::vector<ShareWrapper> garbles_gc_shares;
  garbles_gc_shares.reserve(2);

  std::vector<ShareWrapper> evaluators_gc_shares;
  evaluators_gc_shares.reserve(2);

  // std::cout << "before secret sharing boolean Gmw" << std::endl;

  // // the garbler secret share his Boolean Gmw share
  // auto garbler_input_gate = GetRegister().EmplaceGate<proto::garbled_circuit::InputGateGarbler>(
  //     garbler_id, number_of_wires_, number_of_simd_, parent->GetBackend());

  // std::cout << "after secret sharing boolean Gmw" << std::endl;

  // // the evaluator secret share his Boolean Gmw share
  // auto evaluator_input_gate =
  // GetRegister().EmplaceGate<proto::garbled_circuit::InputGateEvaluator>(
  //     evaluator_id, number_of_wires_, number_of_simd_, parent->GetBackend());

  auto garbler_input_gate = GetGarbledCircuitProvider().MakeInputGate(
      garbler_id, number_of_wires_, number_of_simd_, parent->GetBackend());

  auto evaluator_input_gate = GetGarbledCircuitProvider().MakeInputGate(
      evaluator_id, number_of_wires_, number_of_simd_, parent->GetBackend());

  if (is_garbler_) {
    garblers_input_promise_ = &garbler_input_gate->GetInputPromise();
    garbles_gc_shares.emplace_back(garbler_input_gate->GetOutputAsGarbledCircuitShare());
    garbles_gc_shares.emplace_back(evaluator_input_gate->GetOutputAsGarbledCircuitShare());

    output_wires_ = (garbles_gc_shares[0] ^ garbles_gc_shares[1])->GetWires();
    // output_wires_ = (garbles_gc_shares[0])->GetWires();

  } else {
    evaluators_input_promise_ = &evaluator_input_gate->GetInputPromise();
    evaluators_gc_shares.emplace_back(garbler_input_gate->GetOutputAsGarbledCircuitShare());
    evaluators_gc_shares.emplace_back(evaluator_input_gate->GetOutputAsGarbledCircuitShare());
    output_wires_ = (evaluators_gc_shares[0] ^ evaluators_gc_shares[1])->GetWires();
    // output_wires_ = (evaluators_gc_shares[0])->GetWires();
  }

  assert(gate_id_ >= 0);
}

void BooleanGmwToGCGate::EvaluateSetup() {}

void BooleanGmwToGCGate::EvaluateOnline() {
  std::cout << "BooleanGmwToGCGate::EvaluateOnline" << std::endl;

  // wait for parents Boolean Gmw wires to be ready
  for (auto i = 0ull; i < parent_.size(); ++i) {
    auto boolean_gmw_wire{std::dynamic_pointer_cast<const proto::boolean_gmw::Wire>(parent_.at(i))};
    assert(boolean_gmw_wire);
    boolean_gmw_wire->GetIsReadyCondition().Wait();
  }

  std::cout << "wait for parents Boolean Gmw wires to be ready" << std::endl;

  // std::shared_ptr<motion::Share> boolean_gmw_share_parent =
  //     std::make_shared<proto::boolean_gmw::Share>(parent_);

  // auto boolean_gmw_share{
  //     std::dynamic_pointer_cast<const proto::boolean_gmw::Share>(boolean_gmw_share_parent)};

  std::vector<BitVector<>> boolean_gmw_share_bitvector;
  boolean_gmw_share_bitvector.reserve(number_of_wires_);
  for (auto& wire : parent_) {
    auto gmw_wire = std::dynamic_pointer_cast<proto::boolean_gmw::Wire>(wire);
    assert(gmw_wire);
    boolean_gmw_share_bitvector.emplace_back(gmw_wire->GetValues());

    std::cout<<"gmw_wire->GetValues(): "<<gmw_wire->GetValues()<<std::endl;
  }

  std::cout << "000" << std::endl;

  if (is_garbler_) {
    garblers_input_promise_->set_value(boolean_gmw_share_bitvector);
  }

  else {
    evaluators_input_promise_->set_value(boolean_gmw_share_bitvector);
  }


}

const proto::garbled_circuit::SharePointer BooleanGmwToGCGate::GetOutputAsGCShare() const {
  auto result = std::make_shared<proto::garbled_circuit::Share>(output_wires_);
  assert(result);
  return result;
}

const SharePointer BooleanGmwToGCGate::GetOutputAsShare() const {
  auto result = std::static_pointer_cast<Share>(GetOutputAsGCShare());
  assert(result);
  return result;
}

// TODO: improve BooleanGmwToGCGate
// // added by Liang Zhao
// BooleanGmwToGCGate::BooleanGmwToGCGate(const SharePointer& parent) :
// OneGate(parent->GetBackend()) {
//   is_garbler_ = backend_.GetCommunicationLayer().GetMyId() ==
//                 static_cast<std::size_t>(GarbledCircuitRole::kGarbler);
//   is_evaluator_ = !is_garbler_;

//   parent_ = parent->GetWires();

//   assert(parent_.size() > 0);
//   assert(parent_.at(0)->GetBitLength() > 0);
//   for ([[maybe_unused]] const auto& wire : parent_)
//     assert(wire->GetProtocol() == MpcProtocol::kBooleanGmw);

//   output_wires_.resize(parent_.size());
//   // for (auto& w : output_wires_) {
//   //   w = GetRegister().EmplaceWire<proto::garbled_circuit::Wire>(backend_,
//   //   parent_[0]->GetNumberOfSimdValues());
//   // }
//   number_of_simd_ = parent_[0]->GetNumberOfSimdValues();
//   number_of_wires_ = parent_.size();

//   for (auto& wire : output_wires_) {
//     wire =
//         std::make_shared<encrypto::motion::proto::garbled_circuit::Wire>(backend_,
//         number_of_simd_);
//   }

//   assert(gate_id_ >= 0);
// }

// void BooleanGmwToGCGate::EvaluateSetup() {
//   // the garbler samples key_0 randomly
//   if (is_garbler_) {
//     for (auto& wire : output_wires_) {
//       auto gc_wire =
//           std::dynamic_pointer_cast<encrypto::motion::proto::garbled_circuit::Wire>(wire);
//       assert(gc_wire);
//       gc_wire->GetMutableKeys() = Block128Vector::MakeRandom(number_of_simd_);
//       // set the bits at positions where we will store the r vector to 0

//       // commented by Liang Zhao
//       // ? why set to zero at these positions
//       // ? for each key, its size is kKappa/2

//       for (auto& key : gc_wire->GetMutableKeys()) {
//         BitSpan key_span(key.data(), kKappa);
//         key_span.Set(false, 0);
//         key_span.Set(false, encrypto::motion::proto::garbled_circuit::kGarbledRowBitSize);
//       }

//       gc_wire->SetSetupIsReady();
//     }
//   }
// }

// void BooleanGmwToGCGate::EvaluateOnline() {
//   // as OT sender, the garbler has input: (key_0 xor x_0^B dot R, key_0 xor (1-x_0^B) dot R)
//   if (is_garbler_) {
//     if constexpr (kDebug) {
//       if (!ots_for_evaluators_inputs_) {
//         throw std::logic_error("OT object must be instantiated for evaluator's input gates");
//       }
//     }
//     auto& provider{
//         dynamic_cast<encrypto::motion::proto::garbled_circuit::ThreeHalvesGarblerProvider&>(
//             GetGarbledCircuitProvider())};

//     // get the global R
//     const Block128& offset = provider.GetOffset();

//     // prepare the OT inputs: (key_0 xor x_0^B dot R, key_0 xor (1-x_0^B) dot R)
//     auto zero = Block128::MakeZero();

//     // send the labels corresponding to the inputs to the evaluator
//     // std::vector<BitVector<>> inputs{input_promise_future_->second.get()};
//     std::vector<std::uint8_t> input_labels(Block128::kBlockSize * number_of_wires_ *
//                                            number_of_simd_);

//     for (std::size_t wire_i = 0; wire_i < number_of_wires_; ++wire_i) {
//       // get the Boolean GMW wire value x_0^B
//       auto boolean_gmw_wire_value =
//           std::dynamic_pointer_cast<encrypto::motion::proto::boolean_gmw::Wire>(parent_[wire_i])
//               ->GetValues();

//       auto gc_wire{std::dynamic_pointer_cast<encrypto::motion::proto::garbled_circuit::Wire>(
//           output_wires_[wire_i])};
//       assert(gc_wire);

//       // key_0 xor x_0^B dot R
//       for (std::size_t simd_j = 0; simd_j < number_of_simd_; ++simd_j) {
//         // const Block128& offset_or_zero = inputs[wire_i][simd_j] ? offset : zero;
//         const Block128& offset_or_zero = boolean_gmw_wire_value[simd_j] ? offset : zero;
//         const auto lhs_data{std::assume_aligned<Block128::kBlockSize>(
//             reinterpret_cast<const std::uint8_t* __restrict__>(offset_or_zero.data()))};
//         const auto rhs_data{std::assume_aligned<Block128::kBlockSize>(
//             reinterpret_cast<const std::uint8_t*
//             __restrict__>(gc_wire->GetKeys()[simd_j].data()))};
//         auto output_data{reinterpret_cast<std::uint8_t* __restrict__>(
//             input_labels.data() + Block128::kBlockSize * (number_of_simd_ * wire_i + simd_j))};
//         std::transform(lhs_data, lhs_data + Block128::kBlockSize, rhs_data, output_data,
//                        [](const std::uint8_t& lhs, const std::uint8_t& rhs) { return lhs ^ rhs;
//                        });
//       }

//       // key_0 xor (1-x_0^B) dot R

//     }

//     // a pair of labels for each wire and simd value
//     Block128Vector labels(2 * number_of_wires_ * number_of_simd_);
//     for (std::size_t wire_i = 0; wire_i < number_of_wires_; ++wire_i) {
//       auto gc_wire{std::dynamic_pointer_cast<encrypto::motion::proto::garbled_circuit::Wire>(
//           output_wires_[wire_i])};
//       for (std::size_t simd_j = 0; simd_j < number_of_simd_; ++simd_j) {
//         labels[2 * (wire_i * number_of_simd_ + simd_j)] = gc_wire->GetKeys()[simd_j];
//         labels[2 * (wire_i * number_of_simd_ + simd_j) + 1] = gc_wire->GetKeys()[simd_j] ^
//         offset;
//       }
//     }
//     ots_for_evaluators_inputs_->WaitSetup();
//     ots_for_evaluators_inputs_->SetInputs(std::move(labels));
//     ots_for_evaluators_inputs_->SendMessages();
//   }

//   // as OT receiver, the evaluator has choice bit x_1^B
//   else {
//   }
// }

}  // namespace encrypto::motion
