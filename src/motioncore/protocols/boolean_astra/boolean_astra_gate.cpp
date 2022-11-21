// MIT License
//
// Copyright (c) 2022 Oliver Schick
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

#include <algorithm>
#include <functional>
#include <mutex>
#include <type_traits>

#include "boolean_astra_gate.h"
#include "boolean_astra_share.h"
#include "boolean_astra_wire.h"
#include "communication/message_manager.h"
#include "primitives/sharing_randomness_generator.h"
#include "protocols/boolean_gmw/boolean_gmw_gate.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "utility/helpers.h"

#include <string>
#include <iostream>

using namespace std::string_literals;
std::mutex pm;

void printValue(std::string s) {
  std::lock_guard guard(pm);
  std::cout << s << std::endl;
}

namespace encrypto::motion::proto::boolean_astra {
using std::to_string;

template<typename Allocator>
std::span<const std::uint8_t> ToByteSpan(BitVector<Allocator> const& bit_vector) {
  constexpr size_t kBitVectorInternalSize = 
    sizeof(typename std::decay_t<decltype(bit_vector.GetData())>::value_type);
    
  return std::span<const std::uint8_t>(
           reinterpret_cast<const std::uint8_t*>(bit_vector.GetData().data()),
           bit_vector.GetData().size() * kBitVectorInternalSize);
}

void AssignToValues(std::vector<boolean_astra::Wire::value_type>& values, 
                    std::span<const std::uint8_t> s) {
  size_t simd_values = values.size();
  auto it = s.begin();
  auto const end_it = s.end();
  for(size_t i = 0u; i != simd_values; ++i) {
    BitVector<>& bit_vector = values[i].value;
    for(std::byte& b : bit_vector.GetMutableData()) {
      assert(it != end_it);
      b = std::byte(*it);
      ++it;
    }
  }
  assert(it == end_it);
}

void XorAssignToValues(std::vector<boolean_astra::Wire::value_type>& values, 
                       std::span<const std::uint8_t> s) {
  size_t simd_values = values.size();
  auto it = s.begin();
  auto const end_it = s.end();
  for(size_t i = 0u; i != simd_values; ++i) {
    BitVector<>& bit_vector = values[i].value;
    for(std::byte& b : bit_vector.GetMutableData()) {
      assert(it != end_it);
      b ^= std::byte(*it);
      ++it;
    }
  }
  assert(it == end_it);
}

auto BuildValuesMessage(std::vector<boolean_astra::Wire::value_type> const& values,
                        int64_t gate_id,
                        communication::MessageType message_type) {
  size_t simd_values = values.size();
  std::vector<uint8_t> payload;
  //In most cases the SIMD values will be of equal bitsize
  payload.reserve(values.size() * values[0].value.GetData().size());
  for(size_t i = 0u; i != simd_values; ++i) {
      std::span<const std::uint8_t> s = ToByteSpan(values[i].value);
      std::copy(s.begin(), s.end(), std::back_inserter(payload));
  }
  return communication::BuildMessage(message_type, gate_id, std::move(payload));
}

void SendValues(std::vector<boolean_astra::Wire::value_type> const& values,
                size_t target_id,
                int64_t gate_id,
                communication::CommunicationLayer& communication_layer, 
                communication::MessageType message_type) {
    auto message = BuildValuesMessage(values, gate_id, message_type);
    communication_layer.SendMessage(target_id, message.Release());
}

void BroadcastValues(std::vector<boolean_astra::Wire::value_type> const& values,
                     int64_t gate_id,
                     communication::CommunicationLayer& communication_layer, 
                     communication::MessageType message_type) {
    auto message = BuildValuesMessage(values, gate_id, message_type);
    communication_layer.BroadcastMessage(message.Release());
}

std::vector<boolean_astra::Wire::value_type> GetZeroWireData(const boolean_astra::WirePointer& parent) {
  size_t simd_values = parent->GetNumberOfSimdValues();
  
  std::vector<boolean_astra::Wire::value_type> result;
  result.reserve(simd_values);
  
  for (auto const& data : parent->GetValues()) {
    size_t bit_vector_size = data.value.GetSize();
    assert(bit_vector_size > 0);
    result.emplace_back(BitVector<>(bit_vector_size, false), BitVector<>(bit_vector_size, false));
  }
  assert(result.size() == simd_values);
  
  return result;
}
    
void InputGate::SetAndCommit(std::vector<BitVector<>> input) {
  auto out_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[0]);
  assert(out_wire);
  auto& values = out_wire->GetMutableValues();
  size_t simd_values = values.size();
  assert(input.size() == simd_values);
  
  for(auto i = 0u; i != simd_values; ++i) {
    //values could be set to lambda at this point, so we XOR the new input instead of setting it
    values[i].value ^= std::move(input[i]);
  }
}

InputGate::InputGate(std::vector<BitVector<>> input, std::size_t input_owner, Backend& backend)
: Base(backend) {
  input_owner_id_ = input_owner;
  gate_id_ = GetRegister().NextGateId();
  requires_online_interaction_ = true;

  auto my_id = static_cast<std::int64_t>(GetCommunicationLayer().GetMyId());

  size_t simd_values = input.size();
  std::shared_ptr<boolean_astra::Wire> w;
  std::vector<boolean_astra::Wire::value_type> d;
  d.reserve(simd_values);
  for (auto&& bit_vector : input) {
    size_t bit_vector_size = bit_vector.GetSize();
    assert(bit_vector_size > 0);
    if(my_id == static_cast<std::int64_t>(input_owner)) {
      d.emplace_back(std::move(bit_vector), BitVector<>(bit_vector_size, false));
    }
    else {
      d.emplace_back(BitVector<>(bit_vector_size, false), BitVector<>(bit_vector_size, false));
    }
  }
  w = GetRegister().template EmplaceWire<boolean_astra::Wire>(backend_, std::move(d));

  output_wires_ = {std::move(w)};

  if (my_id != input_owner_id_) {
    input_future_ = GetCommunicationLayer().GetMessageManager().RegisterReceive(
        input_owner_id_, communication::MessageType::kBooleanAstraInputGate, gate_id_);
  }

  if constexpr (kDebug) {
    auto gate_info = fmt::format("gate id {}, owner {}", gate_id_, input_owner_id_);
    GetLogger().LogDebug(
        fmt::format("Allocate an boolean_astra::InputGate with following properties: {}", gate_info));
  }
}

void InputGate::EvaluateSetup() {
  //Wait for base provider to finish its setup, since we use its SharingRandomnessGenerators
  GetBaseProvider().WaitForSetup();
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto number_of_parties = communication_layer.GetNumberOfParties();
  GetBaseProvider().WaitForSetup();

  auto out_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[0]);
  assert(out_wire);
  auto& values = out_wire->GetMutableValues();
  size_t simd_values = values.size();

  if(my_id == static_cast<std::size_t>(input_owner_id_) ) {
    //Generate lambda = lambda_1 + ... + lambda_n, with lambda_i belonging to party i
    for(auto i = 0u; i != number_of_parties; ++i) {
      auto& rng_i = GetBaseProvider().GetMyRandomnessGenerator(i);
      for(auto j = 0u; j != simd_values; ++j) {
        //Generate lambda_i, using the RNG shared with party i (they will generate the same lambda_i)
        //and XOR lambda_i to the resulting lambda.
        BitVector<> lambda_i = rng_i.GetBits(gate_id_, values[j].lambda_i.GetSize());
        values[j].value ^= lambda_i;
        //If we generated our lambda_i, we assign it to the wire data.
        if(i == my_id) {
          values[j].lambda_i = std::move(lambda_i);
        }
      }
    }
  }
  else {
    //Generate lambda_i, with i = my_id
    auto& rng = GetBaseProvider().GetTheirRandomnessGenerator(input_owner_id_);
    for(auto i = 0u; i != simd_values; ++i) {
      values[i].lambda_i = rng.GetBits(gate_id_, values[i].value.GetSize());
    }
  }
  
  out_wire->SetSetupIsReady();
}

void InputGate::EvaluateOnline() {
  using communication::MessageType::kBooleanAstraInputGate;
  WaitSetup();
  assert(setup_is_ready_);

  auto out_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[0]);
  assert(out_wire);
  auto& values = out_wire->GetMutableValues();

  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  
  if (my_id == static_cast<std::size_t>(input_owner_id_)) {
    //Send the input ^ lambda to all other parties
    BroadcastValues(values, gate_id_, communication_layer, kBooleanAstraInputGate);
  }
  else {
    //Receive input ^ lambda from input owner
    auto input_message = input_future_.get();
    auto payload = communication::GetMessage(input_message.data())->payload();
    AssignToValues(values, {payload->Data(), payload->size()});
  }

  if constexpr (kDebug) {
    GetLogger().LogDebug(fmt::format("Evaluated boolean_astra::InputGate with id#{}", gate_id_));
  }
}

boolean_astra::SharePointer InputGate::GetOutputAsBooleanAstraShare() {
  auto wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[0]);
  assert(wire);
  return std::make_shared<boolean_astra::Share>(wire);
}

OutputGate::OutputGate(const boolean_astra::WirePointer& parent, std::size_t output_owner)
: Base( (assert(parent), parent->GetBackend()) ) {
  if (parent->GetProtocol() != MpcProtocol::kBooleanAstra) {
    auto sharing_type = to_string(parent->GetProtocol());
    throw(
        std::runtime_error((fmt::format("BooleanAstra output gate expects a BooleanAstra share, "
                                        "got a share of type {}",
                                        sharing_type))));
  }
  auto my_id = static_cast<std::int64_t>(GetCommunicationLayer().GetMyId());

  parent_ = {parent};
  output_owner_ = output_owner;
  requires_online_interaction_ = true;
  gate_type_ = GateType::kInteractive;
  gate_id_ = GetRegister().NextGateId();
  
  //If we receive the output, we register ourselves to receive messages from all other parties
  if (output_owner_ == my_id || output_owner_ == kAll) {
    output_futures_ = GetCommunicationLayer().GetMessageManager().RegisterReceiveAll(
        communication::MessageType::kBooleanAstraOutputGate, gate_id_);
  }
  
  auto w = GetRegister().template EmplaceWire<boolean_astra::Wire>(backend_, GetZeroWireData(parent));
  output_wires_ = {std::move(w)};
}

void OutputGate::EvaluateSetup() {}

void OutputGate::EvaluateOnline() {
  using communication::MessageType::kBooleanAstraOutputGate;
  WaitSetup();
  assert(setup_is_ready_);

  auto out_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[0]);
  assert(out_wire);
  auto in_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_[0]);
  assert(in_wire);

  auto& out_values = out_wire->GetMutableValues();
  auto const& in_values = in_wire->GetValues();
  assert(in_values.size() == out_values.size());
  size_t simd_values = in_values.size();

  auto& communication_layer = GetCommunicationLayer();
  auto my_id = static_cast<std::int64_t>(communication_layer.GetMyId());
  auto number_of_parties = communication_layer.GetNumberOfParties();
  
  // wait for parent wire to obtain a value
  parent_[0]->GetIsReadyCondition().Wait();
  for(auto i = 0u; i != simd_values; ++i) {
    out_values[i].value = in_values[i].value ^ in_values[i].lambda_i;
  }
  
  //If we are not the only one to receive the output, 
  //we need to send our lambda_i to at least one other party
  if(output_owner_ != my_id) {
    //Send message
    if(output_owner_ == kAll) {
      BroadcastValues(out_values, gate_id_, communication_layer, kBooleanAstraOutputGate);
    }
    else {
      SendValues(out_values, output_owner_, gate_id_, communication_layer, kBooleanAstraOutputGate);
    }
  }
  
  //If we receive the output, then we will receive messages from all other parties
  if(output_owner_ == my_id || output_owner_ == kAll) {
    for (size_t i = 0u; i != number_of_parties - 1; ++i) {
      //Receive input ^ lambda from input owner
      auto output_message = output_futures_[i].get();
      auto payload = communication::GetMessage(output_message.data())->payload();
      XorAssignToValues(out_values, {payload->Data(), payload->size()});
    }
  }

  if constexpr (kDebug) {
    GetLogger().LogDebug(fmt::format("Evaluated boolean_astra::OutputGate with id#{}", gate_id_));
  }
}

boolean_astra::SharePointer OutputGate::GetOutputAsBooleanAstraShare() {
  auto wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[0]);
  assert(wire);
  return std::make_shared<boolean_astra::Share>(wire);
}


XorGate::XorGate(const boolean_astra::WirePointer& a, const boolean_astra::WirePointer& b)
    : TwoGate( (assert(a && b), a->GetBackend()) ) {
  size_t simd_values = a->GetNumberOfSimdValues();
  assert(simd_values == b->GetNumberOfSimdValues());
  assert(std::equal(a->GetValues().begin(), a->GetValues().end(), b->GetValues().begin(), 
                    [](auto const& d_a, auto const& d_b){
                      return d_a.value.GetSize() == d_b.value.GetSize() &&
                             d_a.lambda_i.GetSize() == d_b.lambda_i.GetSize();
                    }));
  parent_a_ = {a};
  parent_b_ = {b};

  requires_online_interaction_ = false;
  gate_type_ = GateType::kNonInteractive;
  gate_id_ = GetRegister().NextGateId();

  auto w = GetRegister().template EmplaceWire<boolean_astra::Wire>(backend_, GetZeroWireData(a));
  output_wires_ = {std::move(w)};

  if constexpr (kDebug) {
    auto gate_info =
        fmt::format("gate id {}, parents: {}, {}", gate_id_,
                    parent_a_[0]->GetWireId(), parent_b_[0]->GetWireId());
    GetLogger().LogDebug(
        fmt::format("Created a boolean_astra::XorGate with following properties: {}", gate_info));
  }
}

void XorGate::EvaluateSetup() {
  auto out_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[0]);
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_a_[0]);
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_b_[0]);
  assert(b_wire);

  auto& out_values = out_wire->GetMutableValues();
  auto const& a_values = a_wire->GetMutableValues();
  auto const& b_values = b_wire->GetMutableValues();
  size_t simd_values = out_values.size();
  
  a_wire->GetSetupReadyCondition()->Wait();
  b_wire->GetSetupReadyCondition()->Wait();
  
  for(auto i = 0u; i != simd_values; ++i) {
    out_values[i].lambda_i = a_values[i].lambda_i ^ b_values[i].lambda_i;
  }
  
  out_wire->SetSetupIsReady();
}

void XorGate::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);
  auto out_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[0]);
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_a_[0]);
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_b_[0]);
  assert(b_wire);

  auto& out_values = out_wire->GetMutableValues();
  auto const& a_values = a_wire->GetMutableValues();
  auto const& b_values = b_wire->GetMutableValues();
  size_t simd_values = out_values.size();
  
  parent_a_[0]->GetIsReadyCondition().Wait();
  parent_b_[0]->GetIsReadyCondition().Wait();
  
  for(auto i = 0u; i != simd_values; ++i) {
    out_values[i].value = a_values[i].value ^ b_values[i].value;
  }

  if constexpr (kDebug) {
    GetLogger().LogDebug(fmt::format("Evaluated boolean_astra::XorGate with id#{}", gate_id_));
  }
}

boolean_astra::SharePointer XorGate::GetOutputAsBooleanAstraShare() {
  auto wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[0]);
  assert(wire);
  return std::make_shared<boolean_astra::Share>(wire);
}

//TODO: Replace the following three helper functions with the Encapsulating Gate class
void FullyEvaluateGate(GatePointer gate) {
  gate->EvaluateSetup();
  gate->SetSetupIsReady();
  gate->EvaluateOnline();
  gate->SetOnlineIsReady();
}

void AddFullEvaluationJob(Backend& backend, GatePointer gate) {
  backend.AddCustomSetupJob([gate = std::move(gate)]() mutable {
    FullyEvaluateGate(std::move(gate));
  });
}

//Method that adds a job, waits for delayed_wire to execute its setup phase,
//then sets the input of the input gate according to the value stored in lambda_i
//of delayed_wire and then fully evaluates the input gate.
void AddDelayedInputJob(Backend& backend, 
                        boolean_astra::WirePointer delayed_wire, 
                        std::shared_ptr<boolean_gmw::InputGate> input_gate) {
  backend.AddCustomSetupJob(
    [delayed_wire = std::move(delayed_wire), input_gate = std::move(input_gate)] {
      delayed_wire->GetSetupReadyCondition()->Wait();
        
      size_t simd_values = delayed_wire->GetNumberOfSimdValues();
      auto const& delayed_values = delayed_wire->GetValues();
      std::vector<BitVector<>> lambda_input;
      lambda_input.reserve(simd_values);
      for(auto i = 0u; i != simd_values; ++i) {
        lambda_input.emplace_back(delayed_values[i].lambda_i);
      }
      input_gate->SetAndCommit(std::move(lambda_input));
      FullyEvaluateGate(std::move(input_gate));
    });
}

GatePointer AddLambdaAbJob(
  Backend& backend, size_t number_of_parties, size_t my_id, 
  boolean_astra::WirePointer a_wire, boolean_astra::WirePointer b_wire) {
      
  assert(a_wire);
  assert(b_wire);
  size_t simd_values = a_wire->GetNumberOfSimdValues();
  assert(simd_values == b_wire->GetNumberOfSimdValues());
  std::vector<std::shared_ptr<boolean_gmw::InputGate>> inputs_a;
  std::vector<std::shared_ptr<boolean_gmw::InputGate>> inputs_b;
  inputs_a.reserve(number_of_parties);
  inputs_b.reserve(number_of_parties);
  std::vector<BitVector<>> zero_input_data;
  zero_input_data.reserve(simd_values);
  for(size_t i = 0u; i != simd_values; ++i) {
    assert(a_wire->GetValues()[i].lambda_i.GetSize() == b_wire->GetValues()[i].lambda_i.GetSize());
    zero_input_data.emplace_back(a_wire->GetValues()[i].lambda_i.GetSize(), false);
  }
  
  for(auto party_id = 0u; party_id != number_of_parties; ++party_id) {
    //Add job that waits for own wires to become ready and sets input
    auto input_a = std::make_shared<boolean_gmw::InputGate>(zero_input_data, party_id, backend);
    auto input_b = std::make_shared<boolean_gmw::InputGate>(zero_input_data, party_id, backend);
    if(party_id == my_id) {
      AddDelayedInputJob(backend, a_wire, input_a);
      AddDelayedInputJob(backend, b_wire, input_b);
    }
    else {
      AddFullEvaluationJob(backend, input_a);
      AddFullEvaluationJob(backend, input_b);
    }
    //place the input gates into temparary vectors for further use
    inputs_a.emplace_back(std::move(input_a));
    inputs_b.emplace_back(std::move(input_b));
  }
  assert(inputs_a.size() == inputs_b.size());
  //We added an evaluation job for all input gates at this point
  
  auto sum_lambdas = [&](const GatePointer& a, const GatePointer& b) {
    //All parameter gates have already an evaluation job added at this point
    auto a_sum_share = std::make_shared<boolean_gmw::Share>(std::move(a->GetOutputWires()));
    auto b_in_share = std::make_shared<boolean_gmw::Share>(std::move(b->GetOutputWires()));
    auto result = std::make_shared<boolean_gmw::XorGate>(a_sum_share, b_in_share);
    //Add an evaluation job for the newly created AdditionGate
    AddFullEvaluationJob(backend, result);
    return result;
  };
  
  assert(inputs_a.size() >= 2);
  //Sum all lambdas using inner arithmetic gmw
  GatePointer lambda_a = std::accumulate(inputs_a.begin() + 2, inputs_a.end(), sum_lambdas(inputs_a[0], inputs_a[1]), sum_lambdas);
  GatePointer lambda_b = std::accumulate(inputs_b.begin() + 2, inputs_b.end(), sum_lambdas(inputs_b[0], inputs_b[1]), sum_lambdas);
  
  //Multiply both sums
  auto a_sum_share = std::make_shared<boolean_gmw::Share>(lambda_a->GetOutputWires());
  auto b_sum_share = std::make_shared<boolean_gmw::Share>(lambda_b->GetOutputWires());
  GatePointer lambda_ab = std::make_shared<boolean_gmw::AndGate>(a_sum_share, b_sum_share);
  AddFullEvaluationJob(backend, lambda_ab);
  return lambda_ab;
}

AndGate::AndGate(const boolean_astra::WirePointer& a, const boolean_astra::WirePointer& b)
    : TwoGate(a->GetBackend()) {
  assert(std::equal(a->GetValues().begin(), a->GetValues().end(), b->GetValues().begin(), 
                    [](auto const& d_a, auto const& d_b){
                      return d_a.value.GetSize() == d_b.value.GetSize() &&
                             d_a.lambda_i.GetSize() == d_b.lambda_i.GetSize();
                    }));
  using communication::MessageType::kBooleanAstraOnlineAndGate;
  size_t simd_values = a->GetNumberOfSimdValues();
  assert(simd_values == b->GetNumberOfSimdValues());
  parent_a_ = {a};
  parent_b_ = {b};

  requires_online_interaction_ = true;
  gate_type_ = GateType::kInteractive;
  gate_id_ = GetRegister().NextGateId();

  auto w = GetRegister().template EmplaceWire<boolean_astra::Wire>(backend_, GetZeroWireData(a));
  output_wires_ = {std::move(w)};
  
  auto& communication_layer = GetCommunicationLayer();
  std::size_t my_id = communication_layer.GetMyId();
  auto& message_manager = communication_layer.GetMessageManager();
  auto number_of_parties = communication_layer.GetNumberOfParties();
  
  //P0 is the only party that receives all shares of all other parties during online multiplication
  if(my_id == 0) {
    multiply_futures_online_ = 
      message_manager.RegisterReceiveAll(kBooleanAstraOnlineAndGate, gate_id_);
  }
  else {
    multiply_futures_online_.emplace_back(
      message_manager.RegisterReceive(0, kBooleanAstraOnlineAndGate, gate_id_));
  }
  
  lambda_ab_gate_ = AddLambdaAbJob(backend_, number_of_parties, my_id, a, b);

  if constexpr (kDebug) {
    auto gate_info =
        fmt::format("gate id {}, parents: {}, {}", gate_id_,
                    parent_a_[0]->GetWireId(), parent_b_[0]->GetWireId());
    GetLogger().LogDebug(fmt::format(
        "Created a boolean_astra::MultiplicationGate with following properties: {}", gate_info));
  }
}

void AndGate::EvaluateSetup() {
  //Wait for base provider to finish its setup, since we use its SharingRandomnessGenerators
  GetBaseProvider().WaitForSetup();
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto out_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[0]);
  assert(out_wire);

  auto& out_values = out_wire->GetMutableValues();
  size_t simd_values = out_values.size();
  
  //Generate and store lambda_zi
  auto& rng = GetBaseProvider().GetMyRandomnessGenerator(my_id);
  for(auto i = 0u; i != simd_values; ++i) {
    out_values[i].lambda_i = rng.GetBits(gate_id_, out_values[i].lambda_i.GetSize());
  }
  
  auto const& lambda_ab_wires = lambda_ab_gate_->GetOutputWires();
  std::vector<BitVector<>> lambda_ab_values;
  lambda_ab_values.reserve(lambda_ab_wires.size());
  for(auto const& w : lambda_ab_wires) {
    w->GetIsReadyCondition().Wait();
    auto lambda_ab_wire = std::dynamic_pointer_cast<boolean_gmw::Wire>(w);
    lambda_ab_values.emplace_back(std::move(lambda_ab_wire->GetMutableValues()));
  }
  assert(lambda_ab_values.size() == simd_values);
  
  //We store our share of lambda_ab into out_values and XOR lambda_zi with it
  for(auto i = 0u; i != simd_values; ++i) {
    out_values[i].value = out_values[i].lambda_i ^ lambda_ab_values[i];
  }
  
  out_wire->SetSetupIsReady();
}

void AndGate::EvaluateOnline() {
  constexpr int64_t kLeadPartyId = 0;
  using communication::MessageType::kBooleanAstraOnlineAndGate;
  WaitSetup();
  assert(setup_is_ready_);
  parent_a_[0]->GetIsReadyCondition().Wait();
  parent_b_[0]->GetIsReadyCondition().Wait();
      
  auto& communication_layer = GetCommunicationLayer();
  auto number_of_parties = communication_layer.GetNumberOfParties();
  auto my_id = communication_layer.GetMyId();
  auto out_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[0]);
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_a_[0]);
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_b_[0]);
  assert(b_wire);
  auto& out_values = out_wire->GetMutableValues();
  auto const& a_values = a_wire->GetMutableValues();
  auto const& b_values = b_wire->GetMutableValues();
  size_t simd_values = out_values.size();
  
  for(auto i = 0u; i != simd_values; ++i) {
    //lambda_ab ^ lambda_zi was already calculated in the setup phase 
    if(my_id == kLeadPartyId) {
      out_values[i].value ^= a_values[i].value & b_values[i].value;
    }
    out_values[i].value ^= (a_values[i].value & b_values[i].lambda_i) ^
                           (b_values[i].value & a_values[i].lambda_i);
  }
  
  //All parties (except P0) send their share to P0 and receive the sum of all shares from P0
  if(my_id != kLeadPartyId) {
    SendValues(out_values, kLeadPartyId, gate_id_, communication_layer, kBooleanAstraOnlineAndGate);
    //We receive only from 1 party, so the futures index is always 0
    auto message = multiply_futures_online_[0].get();
    auto payload = communication::GetMessage(message.data())->payload();
    AssignToValues(out_values, {payload->Data(), payload->size()});
  }
  
  //P0 receives all shares, sums them up and sends result back to everyone
  if(my_id == kLeadPartyId) {
    for(auto party_id = 0u; party_id != number_of_parties - 1; ++party_id) {
      auto message = multiply_futures_online_[party_id].get();
      const auto payload = communication::GetMessage(message.data())->payload();
      XorAssignToValues(out_values, {payload->Data(), payload->size()});
    }
    BroadcastValues(out_values, gate_id_, communication_layer, kBooleanAstraOnlineAndGate);
  }
}

boolean_astra::SharePointer AndGate::GetOutputAsBooleanAstraShare() {
  auto wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[0]);
  assert(wire);
  return std::make_shared<boolean_astra::Share>(wire);
}

BooleanDotProductGate::BooleanDotProductGate(std::vector<motion::WirePointer> vector_a,
                                             std::vector<motion::WirePointer> vector_b)
    : Base((assert(vector_a.size() > 0), assert(vector_a.size() == vector_b.size()),
            vector_a[0]->GetBackend())) {
  using communication::MessageType::kBooleanAstraOnlineDotProductGate;
  auto elements_in_vector = vector_a.size();
  auto number_of_simd_values = vector_a[0]->GetNumberOfSimdValues();
  
  assert(vector_a.size() == elements_in_vector);
  assert(vector_b.size() == elements_in_vector);
  assert(std::all_of(vector_a.begin(), vector_a.end(), 
                     [&](motion::WirePointer& wp){ 
                       return wp->GetNumberOfSimdValues() == number_of_simd_values; 
                     }));
  assert(std::all_of(vector_b.begin(), vector_b.end(), 
                     [&](motion::WirePointer& wp){ 
                       return wp->GetNumberOfSimdValues() == number_of_simd_values; 
                     }));

  requires_online_interaction_ = true;
  gate_type_ = GateType::kInteractive;
  gate_id_ = GetRegister().NextGateId();
  auto parent = std::dynamic_pointer_cast<boolean_astra::Wire>(vector_a[0]);
  assert(parent);
  auto w = GetRegister().template EmplaceWire<boolean_astra::Wire>(backend_, GetZeroWireData(parent));
  output_wires_ = {std::move(w)};
  
  parent_a_ = std::move(vector_a);
  parent_b_ = std::move(vector_b);

  auto& communication_layer = GetCommunicationLayer();
  std::size_t my_id = communication_layer.GetMyId();
  auto& message_manager = communication_layer.GetMessageManager();
  auto number_of_parties = communication_layer.GetNumberOfParties();
  
  //P0 is the only party that receives all shares of all other parties during online dot product
  if(my_id == 0) {
    dot_product_futures_online_ = 
      message_manager.RegisterReceiveAll(kBooleanAstraOnlineDotProductGate, gate_id_);
  }
  else {
    dot_product_futures_online_.emplace_back(
      message_manager.RegisterReceive(0, kBooleanAstraOnlineDotProductGate, gate_id_));
  }
  
  lambda_abk_gates_.reserve(elements_in_vector);
  for(size_t k = 0u; k != elements_in_vector; ++k) {
    auto a = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_a_[k]);
    auto b = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_b_[k]);
    lambda_abk_gates_.emplace_back(
      AddLambdaAbJob(backend_, number_of_parties, my_id, std::move(a), std::move(b)));
  }
}

void BooleanDotProductGate::EvaluateSetup() {
  //Wait for base provider to finish its setup, since we use its SharingRandomnessGenerators
  GetBaseProvider().WaitForSetup();
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto elements_in_vector = parent_a_.size();
  auto out_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[0]);
  assert(out_wire);

  auto& out_values = out_wire->GetMutableValues();
  size_t simd_values = out_values.size();
  
  //Generate and store lambda_zi
  auto& rng = GetBaseProvider().GetMyRandomnessGenerator(my_id);
  for(size_t i = 0u; i != simd_values; ++i) {
    out_values[i].lambda_i = rng.GetBits(gate_id_, out_values[i].value.GetSize());
  }
  
  for(size_t k = 0u; k != elements_in_vector; ++k) {
    auto const& lambda_abk_wires = lambda_abk_gates_[k]->GetOutputWires();
    std::vector<BitVector<>> lambda_abk_values;
    lambda_abk_values.reserve(lambda_abk_wires.size());
    for(auto const& w : lambda_abk_wires) {
      w->GetIsReadyCondition().Wait();
      auto lambda_abk_wire = std::dynamic_pointer_cast<boolean_gmw::Wire>(w);
      lambda_abk_values.emplace_back(std::move(lambda_abk_wire->GetMutableValues()));
    }
    assert(lambda_abk_values.size() == simd_values);
  
    //We store the sum over all k of lambda_abk_values
    //We don't XOR lambda_zi yet
    for(size_t i = 0u; i != simd_values; ++i) {
      out_values[i].value ^= lambda_abk_values[i];
    }
  }
  out_wire->SetSetupIsReady();
}

void BooleanDotProductGate::EvaluateOnline() {
  using communication::MessageType::kBooleanAstraOnlineDotProductGate;
  constexpr int64_t kLeadPartyId = 0;
  WaitSetup();
  assert(setup_is_ready_);
  auto elements_in_vector = parent_a_.size();
  auto& communication_layer = GetCommunicationLayer();
  auto number_of_parties = communication_layer.GetNumberOfParties();
  auto my_id = communication_layer.GetMyId();
  auto out_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[0]);
  assert(out_wire);
  auto& out_values = out_wire->GetMutableValues();
  size_t simd_values = out_values.size();

  for(size_t k = 0u; k != elements_in_vector; ++k) {
    parent_a_[k]->GetIsReadyCondition().Wait();
    parent_b_[k]->GetIsReadyCondition().Wait();
    auto a_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_a_[k]);
    assert(a_wire);
    auto b_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(parent_b_[k]);
    assert(b_wire);
    auto const& a_values = a_wire->GetMutableValues();
    auto const& b_values = b_wire->GetMutableValues();
  
    for(size_t i = 0u; i != simd_values; ++i) {
      if(my_id == kLeadPartyId) {
        out_values[i].value ^= a_values[i].value & b_values[i].value;
      }
      out_values[i].value ^= (a_values[i].value & b_values[i].lambda_i) ^
                             (b_values[i].value & a_values[i].lambda_i);
    }
  }
  
  //now we can XOR lambda_zi, since we calculated the XOR over all k
  for(size_t i = 0u; i != simd_values; ++i) {
    out_values[i].value ^= out_values[i].lambda_i;
  }
  
  //All parties (except P0) send their share to P0 and receive the sum of all shares from P0
  if(my_id != kLeadPartyId) {
    SendValues(out_values, kLeadPartyId, gate_id_, communication_layer, kBooleanAstraOnlineDotProductGate);
    auto message = dot_product_futures_online_[0].get();
    //We receive only from 1 party, so the futures index is always 0
    const auto payload = communication::GetMessage(message.data())->payload();
    AssignToValues(out_values, {payload->Data(), payload->size()});
  }
  
  //P0 receives all shares, sums them up and sends result back to everyone
  if(my_id == kLeadPartyId) {
    for(auto party_id = 0u; party_id != number_of_parties - 1; ++party_id) {
      auto message = dot_product_futures_online_[party_id].get();
      const auto payload = communication::GetMessage(message.data())->payload();
      XorAssignToValues(out_values, {payload->Data(), payload->size()});
    }
    BroadcastValues(out_values, gate_id_, communication_layer, kBooleanAstraOnlineDotProductGate);
  }
}

boolean_astra::SharePointer BooleanDotProductGate::GetOutputAsBooleanAstraShare() {
  auto wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[0]);
  assert(wire);
  return std::make_shared<boolean_astra::Share>(wire);
}

}  // namespace encrypto::motion::proto::boolean_astra
