// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko, Lennart Braun
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

#include "boolean_gmw_gate.h"
#include "boolean_gmw_wire.h"

#include <fmt/format.h>
#include <span>

#include "base/backend.h"
#include "base/register.h"
#include "communication/communication_layer.h"
#include "communication/message.h"
#include "communication/message_manager.h"
#include "multiplication_triple/mt_provider.h"
#include "primitives/sharing_randomness_generator.h"
#include "utility/helpers.h"

namespace encrypto::motion::proto::boolean_gmw {

std::vector<uint8_t> ToByteVector(std::vector<BitVector<>> values) {
  std::vector<uint8_t> result;
  result.reserve(values.size() * values[0].GetData().size());
  for(BitVector<> const& bit_vector : values) {
    std::span s{reinterpret_cast<const std::uint8_t*>(bit_vector.GetData().data()), 
                bit_vector.GetData().size()}; 
    std::copy(s.begin(), s.end(), std::back_inserter(result));
  }
  return result;
}

void AssignSpan(std::vector<BitVector<>>& values, 
                std::span<const uint8_t> s) {
  size_t number_of_simd_values = values.size();
  auto it = s.begin();
  auto const end_it = s.end();
  for(size_t i = 0u; i != number_of_simd_values; ++i) {
    for(std::byte& b : values[i].GetMutableData()) {
      assert(it != end_it);
      b = std::byte(*it);
      ++it;
    }
  }
  assert(it == end_it);
}

void XorAssignSpan(std::vector<BitVector<>>& values, 
                   std::span<const uint8_t> s) {
  size_t number_of_simd_values = values.size();
  auto it = s.begin();
  auto const end_it = s.end();
  for(size_t i = 0u; i != number_of_simd_values; ++i) {
    for(std::byte& b : values[i].GetMutableData()) {
      assert(it != end_it);
      b ^= std::byte(*it);
      ++it;
    }
  }
  assert(it == end_it);
}

InputGate::InputGate(std::span<const BitVector<>> input, std::size_t party_id, Backend& backend)
    : InputGate::Base(backend), input_(std::vector(input.begin(), input.end())) {
  input_owner_id_ = party_id;
  bits_ = input_.size() == 0 ? 0 : input_.at(0).GetSize();
  InitializationHelper();
}

InputGate::InputGate(std::vector<BitVector<>>&& input, std::size_t party_id, Backend& backend)
    : InputGate::Base(backend), input_(std::move(input)) {
  input_owner_id_ = party_id;
  bits_ = input_.size() == 0 ? 0 : input_.at(0).GetSize();
  InitializationHelper();
}

void InputGate::InitializationHelper() {
  auto& communication_layer = GetCommunicationLayer();
  auto& _register = GetRegister();

  if (static_cast<std::size_t>(input_owner_id_) >= communication_layer.GetNumberOfParties()) {
    throw std::runtime_error(fmt::format("Invalid input owner: {} of {}", input_owner_id_,
                                         communication_layer.GetNumberOfParties()));
  }

  gate_id_ = _register.NextGateId();

  assert(input_.size() > 0u);           // assert >=1 wire
  assert(input_.at(0).GetSize() > 0u);  // assert >=1 SIMD bits
  // assert SIMD lengths of all wires are equal
  assert(BitVector<>::IsEqualSizeDimensions(input_));

  boolean_sharing_id_ = _register.NextBooleanGmwSharingId(input_.size() * bits_);

  if constexpr (kVerboseDebug) {
    GetLogger().LogTrace(fmt::format("Created a BooleanGmwInputGate with global id {}", gate_id_));
  }

  output_wires_.reserve(input_.size());
  for (auto& v : input_) {
    output_wires_.push_back(GetRegister().EmplaceWire<boolean_gmw::Wire>(v, backend_));
  }

  if constexpr (kDebug) {
    auto gate_info = fmt::format("gate id {},", gate_id_);
    GetLogger().LogDebug(
        fmt::format("Created a BooleanGmwInputGate with following properties: {}", gate_info));
  }
}

void InputGate::SetAndCommit(std::vector<BitVector<>> input) {
  input_ = std::move(input);
  for (size_t i = 0u; i != input.size(); ++i) {
    auto my_wire = std::dynamic_pointer_cast<boolean_gmw::Wire>(output_wires_[i]);
    assert(my_wire);
    my_wire->GetMutableValues() = input_[i];
  }
}

void InputGate::EvaluateSetup() {}

void InputGate::EvaluateOnline() {
  // nothing to setup, no need to wait/check
  GetBaseProvider().WaitForSetup();

  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto number_of_parties = communication_layer.GetNumberOfParties();

  std::vector<BitVector<>> result(input_.size());
  auto sharing_id = boolean_sharing_id_;
  for (auto i = 0ull; i < result.size(); ++i) {
    if (static_cast<std::size_t>(input_owner_id_) == my_id) {
      result.at(i) = input_.at(i);
      auto log_string = std::string("");
      for (auto party_id = 0u; party_id < number_of_parties; ++party_id) {
        if (party_id == my_id) {
          continue;
        }
        auto& randomness_generator = GetBaseProvider().GetMyRandomnessGenerator(party_id);
        auto randomness = randomness_generator.GetBits(sharing_id, bits_);

        if constexpr (kVerboseDebug) {
          log_string.append(fmt::format("id#{}:{} ", party_id, randomness.AsString()));
        }

        result.at(i) ^= randomness;
      }
      sharing_id += bits_;

      if constexpr (kVerboseDebug) {
        auto s = fmt::format(
            "My (id#{}) Boolean input sharing for gate#{}, my input: {}, my "
            "share: {}, expected shares of other parties: {}",
            input_owner_id_, gate_id_, input_.at(i).AsString(), result.at(i).AsString(),
            log_string);
        GetLogger().LogTrace(s);
      }
    } else {
      auto& randomness_generator = GetBaseProvider().GetTheirRandomnessGenerator(input_owner_id_);
      result.at(i) = randomness_generator.GetBits(sharing_id, bits_);

      if constexpr (kVerboseDebug) {
        auto s = fmt::format(
            "Boolean input sharing (gate#{}) of Party's#{} input, got a "
            "share {} from the seed",
            gate_id_, input_owner_id_, result.at(i).AsString());
        GetLogger().LogTrace(s);
      }
      sharing_id += bits_;
    }
  }
  for (auto i = 0ull; i < output_wires_.size(); ++i) {
    auto my_wire = std::dynamic_pointer_cast<boolean_gmw::Wire>(output_wires_.at(i));
    assert(my_wire);
    auto buf = result.at(i);
    my_wire->GetMutableValues() = buf;
  }
  if constexpr (kVerboseDebug) {
    GetLogger().LogTrace(fmt::format("Evaluated Boolean InputGate with id#{}", gate_id_));
  }
}

const boolean_gmw::SharePointer InputGate::GetOutputAsGmwShare() {
  auto result = std::make_shared<boolean_gmw::Share>(output_wires_);
  assert(result);
  return result;
}

OutputGate::OutputGate(const motion::SharePointer& parent, std::size_t output_owner)
    : OutputGate::Base(parent->GetBackend()) {
  if (parent->GetWires().size() == 0) {
    throw std::runtime_error("Trying to construct an output gate with no wires");
  }

  if (parent->GetWires().at(0)->GetProtocol() != MpcProtocol::kBooleanGmw) {
    auto sharing_type = to_string(parent->GetWires().at(0)->GetProtocol());
    throw std::runtime_error(
        fmt::format("Boolean output gate expects an Boolean share, "
                    "got a share of type {}",
                    sharing_type));
  }

  parent_ = parent->GetWires();

  // values we need repeatedly
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto number_of_parties = communication_layer.GetNumberOfParties();
  auto number_of_wires = parent_.size();

  if (output_owner >= number_of_parties && output_owner != kAll) {
    throw std::runtime_error(
        fmt::format("Invalid output owner: {} of {}", output_owner, number_of_parties));
  }

  output_owner_ = output_owner;
  requires_online_interaction_ = true;
  gate_type_ = GateType::kInteractive;
  gate_id_ = GetRegister().NextGateId();
  is_my_output_ = static_cast<std::size_t>(output_owner_) == my_id ||
                  static_cast<std::size_t>(output_owner_) == kAll;

  // create output wires
  output_wires_.reserve(number_of_wires);
  for (size_t i = 0; i < number_of_wires; ++i) {
    output_wires_.emplace_back(GetRegister().EmplaceWire<boolean_gmw::Wire>(
        backend_, parent_.at(0)->GetNumberOfSimdValues()));
  }

  // Tell the DataStorages that we want to receive OutputMessages from the
  // other parties.
  if (is_my_output_) {
    output_message_futures_ = GetCommunicationLayer().GetMessageManager().RegisterReceiveAll(
        communication::MessageType::kOutputMessage, gate_id_);
  }

  if constexpr (kDebug) {
    auto gate_info =
        fmt::format("bitlength {}, gate id {}, owner {}", number_of_wires, gate_id_, output_owner_);

    GetLogger().LogDebug(
        fmt::format("Created a BooleanGMW OutputGate with following properties: {}", gate_info));
  }
}

void OutputGate::EvaluateSetup() {}

void OutputGate::EvaluateOnline() {
  // nothing to setup, no need to wait/check
  // data we need repeatedly
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto number_of_parties = communication_layer.GetNumberOfParties();
  const auto number_of_wires = parent_.size();

  std::vector<BitVector<>> output;
  output.reserve(number_of_wires);
  for (std::size_t i = 0; i < number_of_wires; ++i) {
    // wait for parent wire to obtain a value
    auto gmw_wire = std::dynamic_pointer_cast<boolean_gmw::Wire>(parent_.at(i));
    assert(gmw_wire);
    gmw_wire->GetIsReadyCondition().Wait();
    assert(!gmw_wire->GetValues().GetData().empty());
    // initialize output with local share
    output.emplace_back(gmw_wire->GetValues());
  }

  const std::size_t bit_size = output.at(0).GetSize();

  // we need to send shares
  if (!is_my_output_ || output_owner_ == kAll) {
    // prepare payloads
    BitVector<> buffer;
    buffer.Reserve(bit_size * number_of_wires);
    for (auto& o : output) buffer.Append(o);
    // we need to send shares to one other party:
    if (!is_my_output_) {
      std::span s(reinterpret_cast<const std::uint8_t*>(buffer.GetData().data()),
                  buffer.GetData().size());
      auto msg{
          communication::BuildMessage(communication::MessageType::kOutputMessage, gate_id_, s)};
      communication_layer.SendMessage(output_owner_, msg.Release());
    }
    // we need to send shares to all other parties:
    else if (output_owner_ == kAll) {
      std::span s(reinterpret_cast<const std::uint8_t*>(buffer.GetData().data()),
                  buffer.GetData().size());
      auto msg{
          communication::BuildMessage(communication::MessageType::kOutputMessage, gate_id_, s)};
      communication_layer.BroadcastMessage(msg.Release());
    }
  }

  // we receive shares from other parties
  if (is_my_output_) {
    // collect shares from all parties
    std::vector<std::vector<BitVector<>>> shared_outputs(number_of_parties);
    for (std::size_t i = 0; i < number_of_parties; ++i) {
      if (i == my_id) {
        shared_outputs.at(i) = output;
        continue;
      }
      // we need space for a BitVector per wire
      shared_outputs.at(i).reserve(number_of_wires);

      // Retrieve the received messsage or wait until it has arrived.
      const auto output_message = output_message_futures_[i > my_id ? i - 1 : i].get();
      auto message = communication::GetMessage(output_message.data());
      BitSpan bit_span(const_cast<std::uint8_t*>(message->payload()->data()),
                       bit_size * number_of_wires);

      // handle each wire
      for (std::size_t j = 0; j < number_of_wires; ++j) {
        // copy the subset to a bit vector
        auto subset_bv = bit_span.Subset(j * bit_size, (j + 1) * bit_size);
        // steal the data
        auto byte_vector = std::move(subset_bv.GetMutableData());
        // ... and construct a new BitVector
        shared_outputs.at(i).emplace_back(std::move(byte_vector),
                                          parent_.at(0)->GetNumberOfSimdValues());
      }
      assert(shared_outputs.at(i).size() == number_of_wires);
    }

    // reconstruct the shared value
    if constexpr (kVerboseDebug) {
      // we need to copy since we have to keep shared_outputs for the debug output below
      output = BitVector<>::XorBitVectors(shared_outputs);
    } else {
      // we can move
      output = BitVector<>::XorBitVectors(std::move(shared_outputs));
    }

    // set the value of the output wires
    for (std::size_t i = 0; i < output_wires_.size(); ++i) {
      auto wire = std::dynamic_pointer_cast<boolean_gmw::Wire>(output_wires_.at(i));
      assert(wire);
      wire->GetMutableValues() = output.at(i);
    }

    if constexpr (kVerboseDebug) {
      std::string shares{""};
      for (std::size_t party_id = 0; party_id < number_of_parties; ++party_id) {
        shares.append(
            fmt::format("id#{}:{} ", party_id, shared_outputs.at(party_id).at(0).AsString()));
      }

      GetLogger().LogTrace(
          fmt::format("Received output shares: {} from other parties, "
                      "reconstructed result is {}",
                      shares, output.at(0).AsString()));
    }
  }

  // we are done with this gate
  if constexpr (kDebug) {
    GetLogger().LogDebug(fmt::format("Evaluated Boolean OutputGate with id#{}", gate_id_));
  }
}

const boolean_gmw::SharePointer OutputGate::GetOutputAsGmwShare() const {
  auto result = std::make_shared<boolean_gmw::Share>(output_wires_);
  assert(result);
  return result;
}

const motion::SharePointer OutputGate::GetOutputAsShare() const {
  auto result = std::static_pointer_cast<motion::Share>(GetOutputAsGmwShare());
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

  requires_online_interaction_ = false;
  gate_type_ = GateType::kNonInteractive;

  auto& _register = GetRegister();
  gate_id_ = _register.NextGateId();

  auto number_of_wires = parent_a_.size();

  // create output wires
  output_wires_.reserve(number_of_wires);
  for (size_t i = 0; i < number_of_wires; ++i) {
    output_wires_.emplace_back(
        GetRegister().EmplaceWire<boolean_gmw::Wire>(backend_, a->GetNumberOfSimdValues()));
  }

  if constexpr (kDebug) {
    auto gate_info = fmt::format("gate id {}, parents: {}, {}", gate_id_,
                                 parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    GetLogger().LogDebug(
        fmt::format("Created a BooleanGMW XOR gate with following properties: {}", gate_info));
  }
}

void XorGate::EvaluateSetup() {}

void XorGate::EvaluateOnline() {
  // nothing to setup, no need to wait/check
  for (auto& wire : parent_a_) {
    wire->GetIsReadyCondition().Wait();
  }

  for (auto& wire : parent_b_) {
    wire->GetIsReadyCondition().Wait();
  }

  for (auto i = 0ull; i < parent_a_.size(); ++i) {
    auto wire_a = std::dynamic_pointer_cast<const boolean_gmw::Wire>(parent_a_.at(i));
    auto wire_b = std::dynamic_pointer_cast<const boolean_gmw::Wire>(parent_b_.at(i));

    assert(wire_a);
    assert(wire_b);

    auto output = wire_a->GetValues() ^ wire_b->GetValues();

    auto gmw_wire = std::dynamic_pointer_cast<boolean_gmw::Wire>(output_wires_.at(i));
    assert(gmw_wire);
    gmw_wire->GetMutableValues() = std::move(output);
    assert(gmw_wire->GetValues().GetSize() == parent_a_.at(0)->GetNumberOfSimdValues());
  }

  // we are done with this gate
  if constexpr (kVerboseDebug) {
    GetLogger().LogTrace(fmt::format("Evaluated BooleanGMW XOR Gate with id#{}", gate_id_));
  }
}

const boolean_gmw::SharePointer XorGate::GetOutputAsGmwShare() const {
  auto result = std::make_shared<boolean_gmw::Share>(output_wires_);
  assert(result);
  return result;
}

const motion::SharePointer XorGate::GetOutputAsShare() const {
  auto result = std::static_pointer_cast<motion::Share>(GetOutputAsGmwShare());
  assert(result);
  return result;
}

InvGate::InvGate(const motion::SharePointer& parent) : OneGate(parent->GetBackend()) {
  parent_ = parent->GetWires();

  assert(parent_.size() > 0);
  assert(parent_.at(0)->GetBitLength() > 0);

  requires_online_interaction_ = false;
  gate_type_ = GateType::kNonInteractive;

  auto& _register = GetRegister();
  gate_id_ = _register.NextGateId();

  auto number_of_wires = parent_.size();

  // create output wires
  output_wires_.reserve(number_of_wires);
  for (size_t i = 0; i < number_of_wires; ++i) {
    output_wires_.emplace_back(
        GetRegister().EmplaceWire<boolean_gmw::Wire>(backend_, parent->GetNumberOfSimdValues()));
  }

  if constexpr (kDebug) {
    auto gate_info = fmt::format("gate id {}, parent wires: ", gate_id_);
    for (const auto& wire : parent_) gate_info.append(fmt::format("{} ", wire->GetWireId()));
    gate_info.append(" output wires: ");
    for (const auto& wire : output_wires_) gate_info.append(fmt::format("{} ", wire->GetWireId()));
    GetLogger().LogDebug(
        fmt::format("Created a BooleanGMW INV gate with following properties: {}", gate_info));
  }
}

void InvGate::EvaluateSetup() {}

void InvGate::EvaluateOnline() {
  // nothing to setup, no need to wait/check
  for (auto i = 0ull; i < parent_.size(); ++i) {
    auto wire = std::dynamic_pointer_cast<const boolean_gmw::Wire>(parent_.at(i));
    assert(wire);
    wire->GetIsReadyCondition().Wait();
    auto gmw_wire = std::dynamic_pointer_cast<boolean_gmw::Wire>(output_wires_.at(i));
    assert(gmw_wire);
    const bool invert = (wire->GetWireId() % GetCommunicationLayer().GetNumberOfParties()) ==
                        GetCommunicationLayer().GetMyId();
    gmw_wire->GetMutableValues() = invert ? ~wire->GetValues() : wire->GetValues();
  }

  if constexpr (kVerboseDebug) {
    GetLogger().LogTrace(fmt::format("Evaluated BooleanGMW INV Gate with id#{}", gate_id_));
  }
}

const boolean_gmw::SharePointer InvGate::GetOutputAsGmwShare() const {
  auto result = std::make_shared<boolean_gmw::Share>(output_wires_);
  assert(result);
  return result;
}

const motion::SharePointer InvGate::GetOutputAsShare() const {
  auto result = std::static_pointer_cast<motion::Share>(GetOutputAsGmwShare());
  assert(result);
  return result;
}

AndGate::AndGate(const motion::SharePointer& a, const motion::SharePointer& b)
    : TwoGate(a->GetBackend()) {
  parent_a_ = a->GetWires();
  parent_b_ = b->GetWires();

  assert(parent_a_.size() > 0);
  assert(parent_a_.size() == parent_b_.size());
  assert(parent_a_[0]->GetBitLength() > 0);

  auto number_of_wires = parent_a_.size();
  auto number_of_simd_values = a->GetNumberOfSimdValues();
  requires_online_interaction_ = true;
  gate_type_ = GateType::kInteractive;
  gate_id_ = GetRegister().NextGateId();
  
  auto& message_manager = GetCommunicationLayer().GetMessageManager();
  
  d_futures_ = message_manager.RegisterReceiveAll(
                 communication::MessageType::kBooleanGmwDMultiplyGate, gate_id_);
      
  e_futures_ = message_manager.RegisterReceiveAll(
                 communication::MessageType::kBooleanGmwEMultiplyGate, gate_id_);

  // create output wires
  output_wires_.reserve(number_of_wires);
  for (size_t i = 0u; i < number_of_wires; ++i) {
    output_wires_.emplace_back(
        GetRegister().EmplaceWire<boolean_gmw::Wire>(backend_, number_of_simd_values));
  }

  auto& mt_provider = backend_.GetMtProvider();
  mt_bitlen_ = parent_a_.size() * parent_a_[0]->GetNumberOfSimdValues();
  mt_offset_ = mt_provider->RequestBinaryMts(mt_bitlen_);

  if constexpr (kDebug) {
    auto gate_info = fmt::format("gate id {}, parents: {}, {}", gate_id_,
                                 parent_a_[0]->GetWireId(), parent_b_[0]->GetWireId());
    GetLogger().LogDebug(
        fmt::format("Created a BooleanGMW AND gate with following properties: {}", gate_info));
  }
}

void AndGate::EvaluateSetup() {}

#include <string>
#include <iostream>
#include <mutex>
std::mutex str_m;
using namespace std::string_literals;
using std::to_string;
void printValue(std::string str) {
    std::lock_guard guard{str_m};
    std::cout << str << std::endl;
}

void AndGate::EvaluateOnline() {
  using communication::MessageType::kBooleanGmwDMultiplyGate;
  using communication::MessageType::kBooleanGmwEMultiplyGate;
  // nothing to setup, no need to wait/check
  for (auto& wire : parent_a_) {
    wire->GetIsReadyCondition().Wait();
  }

  for (auto& wire : parent_b_) {
    wire->GetIsReadyCondition().Wait();
  }
  
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto number_of_parties = communication_layer.GetNumberOfParties();

  auto& mt_provider = GetMtProvider();
  mt_provider.WaitFinished();
  const auto& mts = mt_provider.GetBinaryAll();
  size_t number_of_wires = parent_a_.size();
  size_t number_of_simd_values = parent_a_[0]->GetNumberOfSimdValues();
  
  std::vector<BitVector<>> d_values(number_of_wires), e_values(number_of_wires);
  for (size_t i = 0u; i != number_of_wires; ++i) {
    const auto x = std::dynamic_pointer_cast<const boolean_gmw::Wire>(parent_a_[i]);
    const auto y = std::dynamic_pointer_cast<const boolean_gmw::Wire>(parent_b_[i]);
    assert(x);
    assert(x->GetNumberOfSimdValues() == number_of_simd_values);
    assert(y);
    assert(y->GetNumberOfSimdValues() == number_of_simd_values);
    d_values[i] = mts.a.Subset(mt_offset_ + i * number_of_simd_values,
                               mt_offset_ + (i + 1) * number_of_simd_values);
    d_values[i] ^= x->GetValues();
    
    e_values[i] = mts.b.Subset(mt_offset_ + i * number_of_simd_values,
                               mt_offset_ + (i + 1) * number_of_simd_values);
    e_values[i] ^= y->GetValues();
  }

  communication_layer.BroadcastMessage(
    communication::BuildMessage(kBooleanGmwDMultiplyGate, gate_id_, ToByteVector(d_values)).Release());
  
  communication_layer.BroadcastMessage(
    communication::BuildMessage(kBooleanGmwEMultiplyGate, gate_id_, ToByteVector(e_values)).Release());
  
  // collect shares from all parties
  for(size_t i = 0u; i != number_of_parties - 1; ++i) {
    auto message = d_futures_[i].get();
    auto payload = communication::GetMessage(message.data())->payload();
    XorAssignSpan(d_values, {payload->Data(), payload->size()});
  }

  // collect shares from all parties
  for (size_t i = 0u; i != number_of_parties - 1; ++i) {
    auto message = e_futures_[i].get();
    auto payload = communication::GetMessage(message.data())->payload();
    XorAssignSpan(e_values, {payload->Data(), payload->size()});
  }
  
  assert(d_values.size() > 0u);
  assert(d_values.size() == e_values.size());

  for (size_t i = 0u; i != d_values.size(); ++i) {
    const auto x_i_w = std::dynamic_pointer_cast<const boolean_gmw::Wire>(parent_a_[i]);
    const auto y_i_w = std::dynamic_pointer_cast<const boolean_gmw::Wire>(parent_b_[i]);
    assert(x_i_w);
    assert(y_i_w);
    assert(x_i_w->GetNumberOfSimdValues() == number_of_simd_values);
    assert(y_i_w->GetNumberOfSimdValues() == number_of_simd_values);

    auto output = std::dynamic_pointer_cast<boolean_gmw::Wire>(output_wires_[i]);
    assert(output);
    output->GetMutableValues() =
        mts.c.Subset(mt_offset_ + i * number_of_simd_values,
                     mt_offset_ + (i + 1) * number_of_simd_values);

    const auto& d = d_values[i];
    const auto& x_i = x_i_w->GetValues();
    const auto& e = e_values[i];
    const auto& y_i = y_i_w->GetValues();

    if (my_id == (gate_id_ % number_of_parties)) {
      output->GetMutableValues() ^= (d & y_i) ^ (e & x_i) ^ (e & d);
    } else {
      output->GetMutableValues() ^= (d & y_i) ^ (e & x_i);
    }
  }

  if constexpr (kVerboseDebug) {
    GetLogger().LogTrace(fmt::format("Evaluated BooleanGMW AND Gate with id#{}", gate_id_));
  }
}

const boolean_gmw::SharePointer AndGate::GetOutputAsGmwShare() const {
  auto result = std::make_shared<boolean_gmw::Share>(output_wires_);
  assert(result);
  return result;
}

const motion::SharePointer AndGate::GetOutputAsShare() const {
  auto result = std::static_pointer_cast<motion::Share>(GetOutputAsGmwShare());
  assert(result);
  return result;
}

MuxGate::MuxGate(const motion::SharePointer& a, const motion::SharePointer& b,
                 const motion::SharePointer& c)
    : ThreeGate(a->GetBackend()) {
  parent_a_ = a->GetWires();
  parent_b_ = b->GetWires();
  parent_c_ = c->GetWires();

  assert(parent_a_.size() > 0);
  assert(parent_a_.size() == parent_b_.size());
  assert(parent_c_.size() == 1);
  assert(parent_a_.at(0)->GetBitLength() > 0);

  requires_online_interaction_ = true;
  gate_type_ = GateType::kInteractive;

  auto& _register = GetRegister();
  gate_id_ = _register.NextGateId();

  auto number_of_wires = parent_a_.size();
  auto number_of_simd_values = a->GetNumberOfSimdValues();

  // create output wires
  // (EvaluateOnline expects the output wires already having buffers)
  output_wires_.reserve(number_of_wires);
  BitVector dummy_bv(number_of_simd_values);
  for (size_t i = 0; i < number_of_wires; ++i) {
    output_wires_.emplace_back(GetRegister().EmplaceWire<boolean_gmw::Wire>(dummy_bv, backend_));
  }

  const auto& communication_layer = GetCommunicationLayer();
  const auto number_of_parties = communication_layer.GetNumberOfParties();
  const auto my_id = communication_layer.GetMyId();
  const auto number_of_bits = parent_a_.size();

  ot_sender_.resize(number_of_parties);
  ot_receiver_.resize(number_of_parties);

  for (std::size_t i = 0; i < number_of_parties; ++i) {
    if (i == my_id) continue;
    ot_sender_.at(i) = GetOtProvider(i).RegisterSendXcOt(number_of_simd_values, number_of_bits);
    ot_receiver_.at(i) =
        GetOtProvider(i).RegisterReceiveXcOt(number_of_simd_values, number_of_bits);
  }

  if constexpr (kDebug) {
    auto gate_info =
        fmt::format("gate id {}, parents: {}, {}, {}", gate_id_, parent_a_.at(0)->GetWireId(),
                    parent_b_.at(0)->GetWireId(), parent_c_.at(0)->GetWireId());
    GetLogger().LogDebug(
        fmt::format("Created a BooleanGMW MUX gate with following properties: {}", gate_info));
  }
}

void MuxGate::EvaluateSetup() {}

void MuxGate::EvaluateOnline() {
  // nothing to setup, no need to wait/check
  for (auto& wire : parent_a_) {
    wire->GetIsReadyCondition().Wait();
  }

  for (auto& wire : parent_b_) {
    wire->GetIsReadyCondition().Wait();
  }

  for (auto& wire : parent_c_) {
    wire->GetIsReadyCondition().Wait();
  }

  const auto number_of_bits = parent_a_.size();
  const auto number_of_simd = parent_a_.at(0)->GetNumberOfSimdValues();
  const auto& communication_layer = GetCommunicationLayer();
  const auto number_of_parties = communication_layer.GetNumberOfParties();
  const auto my_id = communication_layer.GetMyId();

  std::vector<BitVector<>> xored_vector;
  xored_vector.reserve(number_of_bits);
  for (auto simd_i = 0ull; simd_i < number_of_simd; ++simd_i) {
    BitVector<> a, b;
    a.Reserve(number_of_bits);
    b.Reserve(number_of_bits);
    for (auto bit_i = 0ull; bit_i < number_of_bits; ++bit_i) {
      auto wire_a = std::dynamic_pointer_cast<const boolean_gmw::Wire>(parent_a_.at(bit_i));
      auto wire_b = std::dynamic_pointer_cast<const boolean_gmw::Wire>(parent_b_.at(bit_i));
      assert(wire_a);
      assert(wire_b);
      a.Append(wire_a->GetValues()[simd_i]);
      b.Append(wire_b->GetValues()[simd_i]);
    }
    xored_vector.emplace_back(a ^ b);
  }
  auto gmw_wire_selection_bits =
      std::dynamic_pointer_cast<const boolean_gmw::Wire>(parent_c_.at(0));
  assert(gmw_wire_selection_bits);
  const auto& selection_bits = gmw_wire_selection_bits->GetValues();
  for (auto other_pid = 0ull; other_pid < number_of_parties; ++other_pid) {
    if (other_pid == my_id) continue;

    ot_receiver_.at(other_pid)->SetChoices(selection_bits);
    ot_receiver_.at(other_pid)->SendCorrections();

    ot_sender_.at(other_pid)->SetCorrelations(xored_vector);
    ot_sender_.at(other_pid)->SendMessages();
  }

  for (auto simd_i = 0ull; simd_i < number_of_simd; ++simd_i)
    if (!selection_bits[simd_i]) xored_vector.at(simd_i).Set(false);

  for (auto other_pid = 0ull; other_pid < number_of_parties; ++other_pid) {
    if (other_pid == my_id) continue;
    ot_receiver_.at(other_pid)->ComputeOutputs();
    const auto ot_r = ot_receiver_.at(other_pid)->GetOutputs();
    ot_sender_.at(other_pid)->ComputeOutputs();
    const auto ot_s = ot_sender_.at(other_pid)->GetOutputs();
    for (auto simd_i = 0ull; simd_i < number_of_simd; ++simd_i) {
      xored_vector.at(simd_i) ^= ot_r[simd_i];
      BitSpan bs(const_cast<std::byte*>(ot_s[simd_i].GetData().data()), number_of_bits);
      xored_vector.at(simd_i) ^= bs;
    }
  }

  for (auto simd_i = 0ull; simd_i < number_of_simd; ++simd_i) {
    for (auto bit_i = 0ull; bit_i < number_of_bits; ++bit_i) {
      auto wire_output = std::dynamic_pointer_cast<boolean_gmw::Wire>(output_wires_.at(bit_i));
      assert(wire_output);
      wire_output->GetMutableValues().Set(xored_vector.at(simd_i)[bit_i], simd_i);
    }
  }

  for (auto bit_i = 0ull; bit_i < number_of_bits; ++bit_i) {
    auto wire_output = std::dynamic_pointer_cast<boolean_gmw::Wire>(output_wires_.at(bit_i));
    assert(wire_output);
    auto& output = wire_output->GetMutableValues();

    auto wire_b = std::dynamic_pointer_cast<const boolean_gmw::Wire>(parent_b_.at(bit_i));
    assert(wire_b);
    output ^= wire_b->GetValues();
  }

  if constexpr (kVerboseDebug) {
    GetLogger().LogTrace(fmt::format("Evaluated BooleanGMW AND Gate with id#{}", gate_id_));
  }
}

const boolean_gmw::SharePointer MuxGate::GetOutputAsGmwShare() const {
  auto result = std::make_shared<boolean_gmw::Share>(output_wires_);
  assert(result);
  return result;
}

const motion::SharePointer MuxGate::GetOutputAsShare() const {
  auto result = std::static_pointer_cast<motion::Share>(GetOutputAsGmwShare());
  assert(result);
  return result;
}

}  // namespace encrypto::motion::proto::boolean_gmw
