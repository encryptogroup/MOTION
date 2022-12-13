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
#include <map>

#include "boolean_astra_gate.h"
#include "boolean_astra_share.h"
#include "boolean_astra_wire.h"
#include "protocols/share_wrapper.h"
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

std::vector<boolean_astra::Wire::value_type> GetZeroWireData(boolean_astra::WirePointer const& parent) {
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

boolean_gmw::SharePointer AddLambdaSumJob(
  Backend& backend, size_t number_of_parties, size_t my_id, 
  boolean_astra::WirePointer wire) {
      
  assert(wire);
  size_t simd_values = wire->GetNumberOfSimdValues();
  std::vector<std::shared_ptr<boolean_gmw::InputGate>> inputs;
  inputs.reserve(number_of_parties);
  std::vector<BitVector<>> zero_input_data;
  zero_input_data.reserve(simd_values);
  for(size_t i = 0u; i != simd_values; ++i) {
    zero_input_data.emplace_back(wire->GetValues()[i].lambda_i.GetSize(), false);
  }
  
  for(size_t party_id = 0; party_id != number_of_parties; ++party_id) {
    //Add job that waits for own wires to become ready and sets input
    auto input_gate = std::make_shared<boolean_gmw::InputGate>(zero_input_data, party_id, backend);
    if(party_id == my_id) {
      AddDelayedInputJob(backend, wire, input_gate);
    }
    else {
      AddFullEvaluationJob(backend, input_gate);
    }
    inputs.emplace_back(std::move(input_gate));
  }
  assert(inputs.size() == number_of_parties);
  
  auto sum_lambdas = [&](const GatePointer& a, const GatePointer& b) {
    //All parameter gates have already an evaluation job added at this point
    auto a_sum_share = std::make_shared<boolean_gmw::Share>(std::move(a->GetOutputWires()));
    auto b_in_share = std::make_shared<boolean_gmw::Share>(std::move(b->GetOutputWires()));
    auto result = std::make_shared<boolean_gmw::XorGate>(a_sum_share, b_in_share);
    //Add an evaluation job for the newly created AdditionGate
    AddFullEvaluationJob(backend, result);
    return result;
  };
  //Sum all lambdas using inner boolean gmw
  assert(inputs.size() >= 2);
  GatePointer sum_gate = std::accumulate(inputs.begin() + 2, inputs.end(), sum_lambdas(inputs[0], inputs[1]), sum_lambdas);
  return std::make_shared<boolean_gmw::Share>(std::move(sum_gate->GetOutputWires()));
}

GatePointer AddLambdaAbJob(
  Backend& backend, size_t number_of_parties, size_t my_id, 
  boolean_astra::WirePointer a_wire, boolean_astra::WirePointer b_wire) {
      
  assert(a_wire);
  assert(b_wire);
  size_t simd_values = a_wire->GetNumberOfSimdValues();
  assert(simd_values == b_wire->GetNumberOfSimdValues());
  
  //Multiply both sums
  auto a_sum_share = AddLambdaSumJob(backend, number_of_parties, my_id, a_wire);
  auto b_sum_share = AddLambdaSumJob(backend, number_of_parties, my_id, b_wire);
  GatePointer lambda_ab = std::make_shared<boolean_gmw::AndGate>(a_sum_share, b_sum_share);
  AddFullEvaluationJob(backend, lambda_ab);
  return lambda_ab;
}

size_t NextPowerOf2(size_t number) {
  size_t shift = 1;
  for(size_t i = 0; i != sizeof(size_t) / 2; ++i, ++shift) {
    number |= number >> shift;
  }
  return number + 1;
}

std::vector<GatePointer> IntermediaryLambdaJob(
  Backend& backend, size_t number_of_parties, size_t my_id, 
  std::vector<boolean_astra::WirePointer> const& wires) {
  size_t const arity = wires.size();
  assert(arity >= 2);
  //The lambda_products vector must be initialized with a size of 0.
  std::vector<GatePointer> lambda_products;
  //We need space for every possible <arity>-bit number,
  //except for the numbers having less than one set bit.
  lambda_products.reserve((1 << arity) - arity - 1);
  std::vector<boolean_gmw::SharePointer> lambda_factors;
  //We need space for every possible <arity>-bit number,
  //that have exactly one set bit.
  lambda_factors.reserve(arity);
  //We create a bidirectional association between a number and a lambda product,
  //s.t. the product of all lambda_factors, where there is a 1 in the 
  //binary representation of the number is associated with it.
  //The indexing of the bits in the number goes from lsb to msb.
  //E.g. [00101]_2 shall be associated with lambda_factors[0] * lambda_factors[2]
  std::map<size_t, GatePointer> key_lambda_map;
  std::map<GatePointer, size_t> lambda_key_map;
  
  auto multiply_factors = 
    [&](size_t index1, size_t index2) {
      auto& lf1 = lambda_factors[index1];
      auto& lf2 = lambda_factors[index2];
      auto product = std::make_shared<boolean_gmw::AndGate>(lf1, lf2);
      AddFullEvaluationJob(backend, product);
      lambda_products.emplace_back(product);
      //Create bidirectional association between product key and product
      size_t product_key = (1 << index1) | (1 << index2);
      key_lambda_map.emplace(std::make_pair(product_key, product));
      lambda_key_map.emplace(std::make_pair(product, product_key));
    };
  
  auto multiply_product_factor = 
    [&](size_t index_lambda_product, size_t index_lambda_factor) {
      auto& lp = lambda_products[index_lambda_product];
      auto& lf = lambda_factors[index_lambda_factor];
      auto lp_share = std::make_shared<boolean_gmw::Share>(lp->GetOutputWires());
      auto product = std::make_shared<boolean_gmw::AndGate>(lp_share, lf);
      AddFullEvaluationJob(backend, product);
      lambda_products.emplace_back(product);
      //Create bidirectional association between product key and product
      size_t lambda_product_key = lambda_key_map.at(lp);
      size_t new_product_key = lambda_product_key | (1 << index_lambda_factor);
      key_lambda_map.emplace(std::make_pair(new_product_key, product));
      lambda_key_map.emplace(std::make_pair(product, new_product_key));
    };
  
  lambda_factors.reserve(arity);
  for(size_t i = 0; i != arity; ++i) {
    lambda_factors.emplace_back(AddLambdaSumJob(backend, number_of_parties, my_id, wires[i]));
  }
  
  for(size_t factor_idx = 1; factor_idx != arity; ++factor_idx) {
    //The lambda_products vector will be extended during the loop,
    //therefor we need to store the size at the start of the loop.
    size_t products_size = lambda_products.size();
    
    //We multiply the current lambda_factor with every lambda_product of the 
    //previous iteration and add their product to the lambda_products vector.
    for(size_t product_idx = 0; product_idx != products_size; ++product_idx) {
      multiply_product_factor(product_idx, factor_idx);
    }
    //We multiply the current lambda_factor with every previous lambda_factors
    for(size_t previous_idx = 0; previous_idx != factor_idx; ++previous_idx) {
      multiply_factors(previous_idx, factor_idx);
    }
  }
  
  assert(lambda_products.size() == key_lambda_map.size());
  std::vector<GatePointer> result(1 << arity);
  result[0] = nullptr;
  size_t n = 0;
  for(size_t i = 1; i != result.size(); ++i) {
    if(i == (1u << n)) {
      assert(!key_lambda_map.contains(i));
      result[i] = nullptr;
      ++n;
    } else {
      assert(key_lambda_map.contains(i));
      result[i] = std::move(key_lambda_map.at(i));
    }
  }
  return result;
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

AndNGate::AndNGate(std::vector<boolean_astra::WirePointer> as)
    : Base( (assert(as.size() > 0), as[0]->GetBackend()) ) {
  using communication::MessageType::kBooleanAstraOnlineAndNGate;

  requires_online_interaction_ = true;
  gate_type_ = GateType::kInteractive;
  gate_id_ = GetRegister().NextGateId();

  auto w = GetRegister().template EmplaceWire<boolean_astra::Wire>(backend_, GetZeroWireData(as[0]));
  output_wires_ = {std::move(w)};
  parents_ = std::move(as);
  
  auto& communication_layer = GetCommunicationLayer();
  std::size_t my_id = communication_layer.GetMyId();
  auto& message_manager = communication_layer.GetMessageManager();
  auto number_of_parties = communication_layer.GetNumberOfParties();
  
  //P0 is the only party that receives all shares of all other parties during online multiplication
  if(my_id == 0) {
    multiply_n_futures_online_ = 
      message_manager.RegisterReceiveAll(kBooleanAstraOnlineAndNGate, gate_id_);
  }
  else {
    multiply_n_futures_online_.emplace_back(
      message_manager.RegisterReceive(0, kBooleanAstraOnlineAndNGate, gate_id_));
  }
  
  intermediary_lambdas_ = IntermediaryLambdaJob(backend_, number_of_parties, my_id, parents_);
}

void AndNGate::EvaluateSetup() {
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
  
  for(auto const& l : intermediary_lambdas_) {
    if(l != nullptr) {
      auto const& l_wires = l->GetOutputWires();
    
      for(auto const& w : l_wires) {
        w->GetIsReadyCondition().Wait();
      }
    }
  }
  
  out_wire->SetSetupIsReady();
}

void AndNGate::EvaluateOnline() {
  constexpr int64_t kLeadPartyId = 0;
  using communication::MessageType::kBooleanAstraOnlineAndNGate;
  WaitSetup();
  assert(setup_is_ready_);
  for(auto const& p : parents_) {
    p->GetIsReadyCondition().Wait();
  }
      
  auto& communication_layer = GetCommunicationLayer();
  auto number_of_parties = communication_layer.GetNumberOfParties();
  auto my_id = communication_layer.GetMyId();
  auto out_wire = std::dynamic_pointer_cast<boolean_astra::Wire>(output_wires_[0]);
  assert(out_wire);
  std::vector<boolean_astra::WirePointer> a_wires;
  a_wires.reserve(a_wires.size());
  for(size_t i = 0; i != parents_.size(); ++i) {
    auto w = std::dynamic_pointer_cast<boolean_astra::Wire>(parents_[i]);
    assert(w);
    a_wires.emplace_back(std::move(w));
  }
  auto& out_values = out_wire->GetMutableValues();
  size_t simd_values = out_values.size();
  
  //TODO: if runtime/memory tradeoff desired: Replace calculate_product with lookup table of intermediary products
  auto calculate_ms_product = [&](size_t factors_key, size_t simd_idx) {
    //Initialize result as the neutral element of multiplication
    BitVector<> result(out_values[simd_idx].value.GetSize(), true);
    //1s encode lambdas in the product, therefore we negate it, so that 1s encode ms in the product
    size_t neg_factors_key = ~factors_key;
    for(size_t i = 0; i != a_wires.size(); ++i, neg_factors_key >>= 1) {
      if(0x1 == (neg_factors_key & 0x1)) {
        auto w = std::dynamic_pointer_cast<boolean_astra::Wire>(a_wires[i]);
        assert(w);
        result &= w->GetValues()[simd_idx].value;
      }
    }
    
    return result;
  };
  auto get_intermediary_lambda_p = [&](size_t factors_key, size_t simd_idx) {
    assert(factors_key != 0);
    auto w = std::dynamic_pointer_cast<boolean_gmw::Wire>(
               intermediary_lambdas_[factors_key]->GetOutputWires()[simd_idx]);
    assert(w);
    return std::addressof(w->GetValues());
  };
  
  for(size_t i = 0; i != simd_values; ++i) {
    size_t n = 0;
    assert(intermediary_lambdas_.size() > 1);
    for(size_t j = (my_id == kLeadPartyId ? 0 : 1); j != intermediary_lambdas_.size(); ++j) {
      if(j == 0) {
        out_values[i].value ^= calculate_ms_product(j, i);
      } else {
        BitVector<> const* intermediary_lambda_p = nullptr;
        if(j == (1u << n)) {
          intermediary_lambda_p = std::addressof(a_wires[n]->GetValues()[i].lambda_i);
          ++n;
        } else {
          intermediary_lambda_p = get_intermediary_lambda_p(j, i);
        }
        assert(intermediary_lambda_p != nullptr);
        out_values[i].value ^= calculate_ms_product(j, i) & *intermediary_lambda_p;
      }
    }
    out_values[i].value ^= out_values[i].lambda_i;
  }
  
  //All parties (except P0) send their share to P0 and receive the sum of all shares from P0
  if(my_id != kLeadPartyId) {
    SendValues(out_values, kLeadPartyId, gate_id_, communication_layer, kBooleanAstraOnlineAndNGate);
    //We receive only from 1 party, so the futures index is always 0
    auto message = multiply_n_futures_online_[0].get();
    auto payload = communication::GetMessage(message.data())->payload();
    AssignToValues(out_values, {payload->Data(), payload->size()});
  }
  
  //P0 receives all shares, sums them up and sends result back to everyone
  if(my_id == kLeadPartyId) {
    for(auto party_id = 0u; party_id != number_of_parties - 1; ++party_id) {
      auto message = multiply_n_futures_online_[party_id].get();
      const auto payload = communication::GetMessage(message.data())->payload();
      XorAssignToValues(out_values, {payload->Data(), payload->size()});
    }
    BroadcastValues(out_values, gate_id_, communication_layer, kBooleanAstraOnlineAndNGate);
  }
}

boolean_astra::SharePointer AndNGate::GetOutputAsBooleanAstraShare() {
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
