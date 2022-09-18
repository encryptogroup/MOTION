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

#include "astra_gate.h"
#include "astra_share.h"
#include "astra_wire.h"
#include "communication/message_manager.h"
#include "primitives/sharing_randomness_generator.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_gate.h"
#include "utility/helpers.h"

#include <string>
#include <iostream>

namespace encrypto::motion::proto::astra {
    
template<typename T>
void InputGate<T>::SetAndCommit(std::vector<T> input) {
  auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_[0]);
  assert(out_wire);
  auto& values = out_wire->GetMutableValues();
  size_t simd_values = values.size();
  assert(input.size() == simd_values);
  
  for(auto i = 0u; i != simd_values; ++i) {
    //values could be set to -lambda at this point, so we add the new input instead of setting it
    values[i].value += std::move(input[i]);
  }
}

template <typename T>
InputGate<T>::InputGate(std::vector<T> input, std::size_t input_owner, Backend& backend)
: Base(backend) {
  input_owner_id_ = input_owner;
  gate_id_ = GetRegister().NextGateId();
  requires_online_interaction_ = true;

  auto my_id = static_cast<std::int64_t>(GetCommunicationLayer().GetMyId());

  std::shared_ptr<astra::Wire<T>> w;
  std::vector<typename astra::Wire<T>::value_type> d;
  d.reserve(input.size());
  for (auto&& e : input) {
    d.emplace_back(my_id == static_cast<std::int64_t>(input_owner) ? std::move(e) : 0, 0);
  }
  w = GetRegister().template EmplaceWire<astra::Wire<T>>(backend_, std::move(d));

  output_wires_ = {std::move(w)};

  if (my_id != input_owner_id_) {
    input_future_ = GetCommunicationLayer().GetMessageManager().RegisterReceive(
        input_owner_id_, communication::MessageType::kAstraInputGate, gate_id_);
  }

  if constexpr (kDebug) {
    auto gate_info = fmt::format("uint{}_t type, gate id {}, owner {}", sizeof(T) * 8, gate_id_,
                                 input_owner_id_);
    GetLogger().LogDebug(
        fmt::format("Allocate an astra::InputGate with following properties: {}", gate_info));
  }
}

template <typename T>
void InputGate<T>::EvaluateSetup() {
  //Wait for base provider to finish its setup, since we use its SharingRandomnessGenerators
  GetBaseProvider().WaitForSetup();
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto number_of_parties = communication_layer.GetNumberOfParties();
  GetBaseProvider().WaitForSetup();

  auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_[0]);
  assert(out_wire);
  auto& values = out_wire->GetMutableValues();
  size_t simd_values = values.size();

  if(my_id == static_cast<std::size_t>(input_owner_id_) ) {
    //Generate lambda = lambda_1 + ... + lambda_n, with lambda_i belonging to party i,
    std::vector<T> simd_lambda(simd_values);
    for(auto i = 0u; i != number_of_parties; ++i) {
      //Generate lambda_i, using the RNG shared with party i (they will generate the same lambda_i),
      std::vector<T> simd_lambda_i = GetBaseProvider().GetMyRandomnessGenerator(i).GetUnsigned<T>(gate_id_, simd_values);
      assert(simd_lambda_i.size() == simd_values);
      //Add lambda_i to the resulting lambda (looping over all SIMD values).
      std::transform(simd_lambda.begin(), simd_lambda.end(), simd_lambda_i.begin(), simd_lambda.begin(), std::plus<>{});
      if(i == my_id) {
        //If we generated our lambda_i, we assign it to the wire data.
        for(auto i = 0u; i != simd_values; ++i) 
          values[i].lambda_i = simd_lambda_i[i];
      }
    }

    for(auto i = 0u; i != simd_values; ++i) {
      values[i].value -= simd_lambda[i];
    }
  }
  else {
    //Generate lambda_i, with i = my_id
    std::vector<T> simd_lambda_i = GetBaseProvider().GetTheirRandomnessGenerator(input_owner_id_).GetUnsigned<T>(gate_id_, simd_values);
    for(auto i = 0u; i != simd_values; ++i) {
      values[i].lambda_i = simd_lambda_i[i];
    }
  }
  
  out_wire->SetSetupIsReady();
}

template <typename T>
void InputGate<T>::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);

  auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_[0]);
  assert(out_wire);
  auto& values = out_wire->GetMutableValues();
  size_t simd_values = values.size();

  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  
  if (my_id == static_cast<std::size_t>(input_owner_id_)) {
    //Send the input - lambda to all other parties
    std::vector<T> buffer(simd_values);
    for(unsigned i = 0; i != simd_values; ++i) {
      //lambda was already substracted in EvaluateSetup()
      buffer[i] = values[i].value;
    }
    auto payload = ToByteVector<T>(buffer);
    auto message = communication::BuildMessage(communication::MessageType::kAstraInputGate, gate_id_, payload);
    communication_layer.BroadcastMessage(message.Release());
  }
  else {
    //Receive input - lambda from input owner
    auto input_message = input_future_.get();
    auto payload = communication::GetMessage(input_message.data())->payload();
    auto buffer = FromByteVector<T>({payload->Data(), payload->size()});
    assert(buffer.size() == simd_values);
    for (auto i = 0u; i != simd_values; ++i) {
      values[i].value = std::move(buffer[i]);
    }
  }

  if constexpr (kDebug) {
    GetLogger().LogDebug(fmt::format("Evaluated astra::InputGate with id#{}", gate_id_));
  }
}

template <typename T>
astra::SharePointer<T> InputGate<T>::GetOutputAsAstraShare() {
  auto wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(wire);
  return std::make_shared<astra::Share<T>>(wire);
}

template class InputGate<std::uint8_t>;
template class InputGate<std::uint16_t>;
template class InputGate<std::uint32_t>;
template class InputGate<std::uint64_t>;
template class InputGate<__uint128_t>;

template <typename T>
OutputGate<T>::OutputGate(const astra::WirePointer<T>& parent, std::size_t output_owner)
: Base( (assert(parent), parent->GetBackend()) ) {
  if (parent->GetProtocol() != MpcProtocol::kAstra) {
    auto sharing_type = to_string(parent->GetProtocol());
    throw(
        std::runtime_error((fmt::format("Astra output gate expects an astra share, "
                                        "got a share of type {}",
                                        sharing_type))));
  }
  auto my_id{static_cast<std::int64_t>(GetCommunicationLayer().GetMyId())};

  parent_ = {parent};
  output_owner_ = output_owner;
  requires_online_interaction_ = true;
  gate_type_ = GateType::kInteractive;
  gate_id_ = GetRegister().NextGateId();
  
  //If we receive the output, we register ourselves to receive messages from all other parties
  if (output_owner_ == my_id || output_owner_ == kAll) {
    output_futures_ = GetCommunicationLayer().GetMessageManager().RegisterReceiveAll(
        communication::MessageType::kAstraOutputGate, gate_id_);
  }

  size_t simd_values = parent->GetNumberOfSimdValues();
  std::vector<typename astra::Wire<T>::value_type> v(simd_values);
  auto w = GetRegister().template EmplaceWire<astra::Wire<T>>(backend_, std::move(v));
  output_wires_ = {std::move(w)};
}

template <typename T>
void OutputGate<T>::EvaluateSetup() {}

template <typename T>
void OutputGate<T>::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);

  auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(out_wire);
  auto in_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_.at(0));
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
    out_values[i].value = in_values[i].value + in_values[i].lambda_i;
  }
  
  //If we are not the only one to receive the output, 
  //we need to send our lambda_i to at least one other party
  if(output_owner_ != my_id) {
    std::vector<T> output(simd_values);
    for (auto i = 0u; i != simd_values; ++i) {
      output[i] = in_values[i].lambda_i;
    }
    auto payload = ToByteVector<T>(output);
    auto message = communication::BuildMessage(communication::MessageType::kAstraOutputGate, 
                                               gate_id_, payload);
    if(output_owner_ == kAll) {
      communication_layer.BroadcastMessage(message.Release());
    }
    else {
      communication_layer.SendMessage(output_owner_, message.Release());
    }
  }
  
  //If we receive the output, then we will receive messages from all other parties
  if(output_owner_ == my_id || output_owner_ == kAll) {
    for (auto i = 0u; i != number_of_parties - 1; ++i) {
      auto output_message = output_futures_[i].get();
      auto payload = communication::GetMessage(output_message.data())->payload();
      auto received_values = FromByteVector<T>({payload->Data(), payload->size()});
      assert(received_values.size() == simd_values);
      //Reconstruct the outputs by adding all shares of all other parties
      for(auto i = 0u; i != simd_values; ++i) {
        out_values[i].value += received_values[i];
      }
    }
  }

  if constexpr (kDebug) {
    GetLogger().LogDebug(fmt::format("Evaluated astra::OutputGate with id#{}", gate_id_));
  }
}

template <typename T>
astra::SharePointer<T> OutputGate<T>::GetOutputAsAstraShare() {
  auto wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(wire);
  return std::make_shared<astra::Share<T>>(wire);
}

template class OutputGate<std::uint8_t>;
template class OutputGate<std::uint16_t>;
template class OutputGate<std::uint32_t>;
template class OutputGate<std::uint64_t>;
template class OutputGate<__uint128_t>;


template <typename T>
AdditionGate<T>::AdditionGate(const astra::WirePointer<T>& a, const astra::WirePointer<T>& b)
    : TwoGate( (assert(a && b), a->GetBackend()) ) {
  size_t simd_values = a->GetNumberOfSimdValues();
  assert(simd_values == b->GetNumberOfSimdValues());
  parent_a_ = {a};
  parent_b_ = {b};

  requires_online_interaction_ = false;
  gate_type_ = GateType::kNonInteractive;
  gate_id_ = GetRegister().NextGateId();

  std::vector<typename astra::Wire<T>::value_type> v(simd_values);
  auto w = GetRegister().template EmplaceWire<astra::Wire<T>>(backend_, std::move(v));
  output_wires_ = {std::move(w)};

  if constexpr (kDebug) {
    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                    parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    GetLogger().LogDebug(
        fmt::format("Created an astra::AdditionGate with following properties: {}", gate_info));
  }
}

template <typename T>
void AdditionGate<T>::EvaluateSetup() {
  auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_[0]);
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_a_[0]);
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_b_[0]);
  assert(b_wire);

  auto& out_values = out_wire->GetMutableValues();
  auto const& a_values = a_wire->GetMutableValues();
  auto const& b_values = b_wire->GetMutableValues();
  size_t simd_values = out_values.size();
  
  a_wire->GetSetupReadyCondition()->Wait();
  b_wire->GetSetupReadyCondition()->Wait();
  
  for(auto i = 0u; i != simd_values; ++i) {
    out_values[i].lambda_i = a_values[i].lambda_i + b_values[i].lambda_i;
  }
  
  out_wire->SetSetupIsReady();
}

template <typename T>
void AdditionGate<T>::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);
  auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_[0]);
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_a_[0]);
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_b_[0]);
  assert(b_wire);

  auto& out_values = out_wire->GetMutableValues();
  auto const& a_values = a_wire->GetMutableValues();
  auto const& b_values = b_wire->GetMutableValues();
  size_t simd_values = out_values.size();
  
  parent_a_[0]->GetIsReadyCondition().Wait();
  parent_b_[0]->GetIsReadyCondition().Wait();
  
  for(auto i = 0u; i != simd_values; ++i) {
    out_values[i].value = a_values[i].value + b_values[i].value;
  }

  if constexpr (kDebug) {
    GetLogger().LogDebug(fmt::format("Evaluated astra::AdditionGate with id#{}", gate_id_));
  }
}

template <typename T>
astra::SharePointer<T> AdditionGate<T>::GetOutputAsAstraShare() {
  auto wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(wire);
  return std::make_shared<astra::Share<T>>(wire);
}

template class AdditionGate<std::uint8_t>;
template class AdditionGate<std::uint16_t>;
template class AdditionGate<std::uint32_t>;
template class AdditionGate<std::uint64_t>;
template class AdditionGate<__uint128_t>;

template <typename T>
SubtractionGate<T>::SubtractionGate(const astra::WirePointer<T>& a, const astra::WirePointer<T>& b)
    : TwoGate( (assert(a && b), a->GetBackend()) ) {
  size_t simd_values = a->GetNumberOfSimdValues();
  assert(simd_values == b->GetNumberOfSimdValues());
  parent_a_ = {a};
  parent_b_ = {b};

  requires_online_interaction_ = false;
  gate_type_ = GateType::kNonInteractive;
  gate_id_ = GetRegister().NextGateId();

  std::vector<typename astra::Wire<T>::value_type> v(simd_values);
  auto w = GetRegister().template EmplaceWire<astra::Wire<T>>(backend_, std::move(v));
  output_wires_ = {std::move(w)};

  if constexpr (kDebug) {
    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                    parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    GetLogger().LogDebug(
        fmt::format("Created an astra::SubtractionGate with following properties: {}", gate_info));
  }
}

template <typename T>
void SubtractionGate<T>::EvaluateSetup() {
  auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_[0]);
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_a_[0]);
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_b_[0]);
  assert(b_wire);

  auto& out_values = out_wire->GetMutableValues();
  auto const& a_values = a_wire->GetMutableValues();
  auto const& b_values = b_wire->GetMutableValues();
  size_t simd_values = out_values.size();
  
  a_wire->GetSetupReadyCondition()->Wait();
  b_wire->GetSetupReadyCondition()->Wait();
  
  for(auto i = 0u; i != simd_values; ++i) {
    out_values[i].lambda_i = a_values[i].lambda_i - b_values[i].lambda_i;
  }

  out_wire->SetSetupIsReady();
}

template <typename T>
void SubtractionGate<T>::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);
  auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_[0]);
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_a_[0]);
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_b_[0]);
  assert(b_wire);

  auto& out_values = out_wire->GetMutableValues();
  auto const& a_values = a_wire->GetMutableValues();
  auto const& b_values = b_wire->GetMutableValues();
  size_t simd_values = out_values.size();
  
  parent_a_[0]->GetIsReadyCondition().Wait();
  parent_b_[0]->GetIsReadyCondition().Wait();
  
  for(auto i = 0u; i != simd_values; ++i) {
    out_values[i].value = a_values[i].value - b_values[i].value;
  }

  if constexpr (kDebug) {
    GetLogger().LogDebug(fmt::format("Evaluated astra::SubtractionGate with id#{}", gate_id_));
  }
}

template <typename T>
astra::SharePointer<T> SubtractionGate<T>::GetOutputAsAstraShare() {
  auto wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(wire);
  return std::make_shared<astra::Share<T>>(wire);
}

template class SubtractionGate<std::uint8_t>;
template class SubtractionGate<std::uint16_t>;
template class SubtractionGate<std::uint32_t>;
template class SubtractionGate<std::uint64_t>;
template class SubtractionGate<__uint128_t>;

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
template <typename T>
void AddDelayedInputJob(Backend& backend, 
                        astra::WirePointer<T> delayed_wire, 
                        std::shared_ptr<arithmetic_gmw::InputGate<T>> input_gate) {
  backend.AddCustomSetupJob(
    [delayed_wire = std::move(delayed_wire), input_gate = std::move(input_gate)] {
      delayed_wire->GetSetupReadyCondition()->Wait();
        
      size_t simd_values = delayed_wire->GetNumberOfSimdValues();
      auto const& delayed_values = delayed_wire->GetMutableValues();
      std::vector<T> lambda_input(simd_values);
      for(auto i = 0u; i != simd_values; ++i) {
        lambda_input[i] = delayed_values[i].lambda_i;
      }
      input_gate->SetAndCommit(std::move(lambda_input));
      FullyEvaluateGate(std::move(input_gate));
    });
}

template<typename T>
arithmetic_gmw::WirePointer<T> AddLambdaAbJob(
  Backend& backend, size_t number_of_parties, size_t my_id, 
  astra::WirePointer<T> a_wire, astra::WirePointer<T> b_wire) {
      
  assert(a_wire);
  assert(b_wire);
  size_t simd_values = a_wire->GetNumberOfSimdValues();
  assert(simd_values == b_wire->GetNumberOfSimdValues());
  std::vector<std::shared_ptr<arithmetic_gmw::InputGate<T>>> inputs_a;
  std::vector<std::shared_ptr<arithmetic_gmw::InputGate<T>>> inputs_b;
  
  for(auto party_id = 0u; party_id != number_of_parties; ++party_id) {  
    //Add job that waits for own wires to become ready and sets input
    auto input_a = std::make_shared<arithmetic_gmw::InputGate<T>>(simd_values, party_id, backend);
    auto input_b = std::make_shared<arithmetic_gmw::InputGate<T>>(simd_values, party_id, backend);
    if(party_id == my_id) {
      AddDelayedInputJob(backend, a_wire, input_a);
      AddDelayedInputJob(backend, b_wire, input_b);
    }
    else {
      AddFullEvaluationJob(backend, input_a);
      AddFullEvaluationJob(backend, input_b);
    }
    assert(std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(input_a->GetOutputWires()[0])->GetValues().size() == simd_values);
    assert(std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(input_b->GetOutputWires()[0])->GetValues().size() == simd_values);
    //place the input gates into temparary vectors for further use
    inputs_a.emplace_back(std::move(input_a));
    inputs_b.emplace_back(std::move(input_b));
  }
  assert(inputs_a.size() == inputs_b.size());
  //We added an evaluation job for all input gates at this point
  
  auto sum_lambdas = [&](const GatePointer& a, const GatePointer& b) {
    //All parameter gates have already an evaluation job added at this point
    auto a_sum_wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(a->GetOutputWires()[0]);
    assert(a_sum_wire);
    auto b_in_wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(b->GetOutputWires()[0]);
    assert(b_in_wire);
    auto result = std::make_shared<arithmetic_gmw::AdditionGate<T>>(a_sum_wire, b_in_wire);
    //Add an evaluation job for the newly created AdditionGate
    AddFullEvaluationJob(backend, result);
    return result;
  };
  
  assert(inputs_a.size() >= 2);
  //Sum all lambdas using inner arithmetic gmw
  GatePointer lambda_a = std::accumulate(inputs_a.begin() + 2, inputs_a.end(), sum_lambdas(inputs_a[0], inputs_a[1]), sum_lambdas);
  GatePointer lambda_b = std::accumulate(inputs_b.begin() + 2, inputs_b.end(), sum_lambdas(inputs_b[0], inputs_b[1]), sum_lambdas);
  
  //Multiply both sums
  auto a_sum_wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(lambda_a->GetOutputWires()[0]);
  assert(a_sum_wire);
  auto b_sum_wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(lambda_b->GetOutputWires()[0]);
  assert(b_sum_wire);
  GatePointer lambda_ab = std::make_shared<arithmetic_gmw::MultiplicationGate<T>>(a_sum_wire, b_sum_wire);
  AddFullEvaluationJob(backend, lambda_ab);
  auto lambda_ab_wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(lambda_ab->GetOutputWires()[0]);
  assert(lambda_ab_wire);
  return lambda_ab_wire;
}

template <typename T>
MultiplicationGate<T>::MultiplicationGate(const astra::WirePointer<T>& a,
                                          const astra::WirePointer<T>& b)
    : TwoGate(a->GetBackend()) {
  size_t simd_values = a->GetNumberOfSimdValues();
  assert(simd_values == b->GetNumberOfSimdValues());
  parent_a_ = {a};
  parent_b_ = {b};

  requires_online_interaction_ = true;
  gate_type_ = GateType::kInteractive;
  gate_id_ = GetRegister().NextGateId();

  std::vector<typename astra::Wire<T>::value_type> v(simd_values);
  auto w = GetRegister().template EmplaceWire<astra::Wire<T>>(backend_, std::move(v));
  output_wires_ = {std::move(w)};
  
  auto& communication_layer = GetCommunicationLayer();
  std::size_t my_id = communication_layer.GetMyId();
  auto& message_manager = communication_layer.GetMessageManager();
  auto number_of_parties = communication_layer.GetNumberOfParties();
  
  //P0 is the only party that receives all shares of all other parties during online multiplication
  if(my_id == 0) {
    multiply_futures_online_ = 
      message_manager.RegisterReceiveAll(
        communication::MessageType::kAstraOnlineMultiplyGate, gate_id_);
  }
  else {
    multiply_futures_online_.emplace_back(
      message_manager.RegisterReceive(
        0, communication::MessageType::kAstraOnlineMultiplyGate, gate_id_));
  }
  
  lambda_ab_wire_ = AddLambdaAbJob(backend_, number_of_parties, my_id, a, b);

  if constexpr (kDebug) {
    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                    parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    GetLogger().LogDebug(fmt::format(
        "Created an astra::MultiplicationGate with following properties: {}", gate_info));
  }
}

template <typename T>
void MultiplicationGate<T>::EvaluateSetup() {
  //Wait for base provider to finish its setup, since we use its SharingRandomnessGenerators
  GetBaseProvider().WaitForSetup();
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_[0]);
  assert(out_wire);

  auto& out_values = out_wire->GetMutableValues();
  size_t simd_values = out_values.size();
  
  //Generate and store lambda_zi
  auto& rng = GetBaseProvider().GetMyRandomnessGenerator(my_id);
  std::vector<T> lambda_zi = rng.template GetUnsigned<T>(gate_id_, simd_values);
  for(auto i = 0u; i != simd_values; ++i) {
    out_values[i].lambda_i = lambda_zi[i];
  }

  lambda_ab_wire_->GetIsReadyCondition().Wait();

  const auto& lambda_ab_values = lambda_ab_wire_->GetValues();
  assert(lambda_ab_values.size() == simd_values);
  
  //We store our share of lambda_ab into out_values and subtract lambda_zi from it
  for(auto i = 0u; i != simd_values; ++i) {
    out_values[i].value = lambda_ab_values[i] - lambda_zi[i];
  }
  
  out_wire->SetSetupIsReady();
}

template <typename T>
void MultiplicationGate<T>::EvaluateOnline() {
  constexpr int kLeadPartyId = 0;
  WaitSetup();
  assert(setup_is_ready_);
  parent_a_[0]->GetIsReadyCondition().Wait();
  parent_b_[0]->GetIsReadyCondition().Wait();
      
  auto& communication_layer = GetCommunicationLayer();
  auto number_of_parties = communication_layer.GetNumberOfParties();
  auto my_id = communication_layer.GetMyId();
  auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_[0]);
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_a_[0]);
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_b_[0]);
  assert(b_wire);
  auto& out_values = out_wire->GetMutableValues();
  auto const& a_values = a_wire->GetMutableValues();
  auto const& b_values = b_wire->GetMutableValues();
  size_t simd_values = out_values.size();
  
  for(auto i = 0u; i != simd_values; ++i) {
    //lambda_ab - lambda_zi was already calculated in the setup phase 
    //out_values[i].value == lambda_abi - lambda_zi
    if(my_id == kLeadPartyId) {
      out_values[i].value += a_values[i].value * b_values[i].value;
    }
    //out_values[i].value == v*ma*mb + lambda_abi - lambda_zi (v = 1, if ID = 0, else v = 0)
    out_values[i].value += a_values[i].value * b_values[i].lambda_i 
                           + b_values[i].value * a_values[i].lambda_i;
    //out_values[i].value == v*ma*mb + ma*lambda_bi + mb * lambda_ai + lambda_abi - lambda_zi
  }
  
  //All parties (except P0) send their share to P0 and receive the sum of all shares from P0
  if(my_id != kLeadPartyId) {
    //Transform out_values into sendable form
    std::vector<T> message_values;
    message_values.reserve(out_values.size());
    for (auto i = 0u; i != simd_values; ++i) {
      message_values.emplace_back(out_values[i].value);
    }
    assert(message_values.size() == simd_values);
    //Send own share to P0
    {
      auto payload = ToByteVector<T>(message_values);
      auto message = communication::BuildMessage(
                       communication::MessageType::kAstraOnlineMultiplyGate, gate_id_, payload);
      communication_layer.SendMessage(kLeadPartyId, message.Release());
    }
    //Receive sum of all shares from P0
    {
      //We receive only from 1 party, so the futures index is always 0
      const auto message = multiply_futures_online_[0].get();
      const auto payload = communication::GetMessage(message.data())->payload();
      auto received_values = FromByteVector<T>({payload->Data(), payload->size()});
      assert(received_values.size() == simd_values);
      for(auto i = 0u; i != simd_values; ++i) {
        out_values[i].value = received_values[i];
      }
    }
  }
  
  //P0 receives all shares, sums them up and sends result back to everyone
  if(my_id == kLeadPartyId) {
    for(auto party_id = 0u; party_id != number_of_parties - 1; ++party_id) {
      const auto message = multiply_futures_online_[party_id].get();
      const auto payload = communication::GetMessage(message.data())->payload();
      auto received_values = FromByteVector<T>({payload->Data(), payload->size()});
      assert(received_values.size() == simd_values);
      //We sum all of the values we get from the other parties
      for (auto i = 0u; i != simd_values; ++i) {
        out_values[i].value += received_values[i];
      }
    }
    
    //Transform out_values into sendable form
    std::vector<T> message_values;
    message_values.reserve(out_values.size());
    for (auto i = 0u; i != simd_values; ++i) {
      message_values.emplace_back(out_values[i].value);
    }
    assert(message_values.size() == simd_values);
    auto payload = ToByteVector<T>(message_values);
    auto message = communication::BuildMessage(
                     communication::MessageType::kAstraOnlineMultiplyGate, gate_id_, payload);
    communication_layer.BroadcastMessage(message.Release());
  }
}

template <typename T>
astra::SharePointer<T> MultiplicationGate<T>::GetOutputAsAstraShare() {
  auto wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(wire);
  return std::make_shared<astra::Share<T>>(wire);
}

template class MultiplicationGate<std::uint8_t>;
template class MultiplicationGate<std::uint16_t>;
template class MultiplicationGate<std::uint32_t>;
template class MultiplicationGate<std::uint64_t>;
//template class MultiplicationGate<__uint128_t>;   //Not supported, because ArithmeticGmw does not support it

template <typename T>
DotProductGate<T>::DotProductGate(std::vector<motion::WirePointer> vector_a,
                                  std::vector<motion::WirePointer> vector_b)
    : Base((assert(vector_a.size() > 0), assert(vector_a.size() == vector_b.size()),
            vector_a[0]->GetBackend())) {

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
  
  parent_a_ = std::move(vector_a);
  parent_b_ = std::move(vector_b);

  requires_online_interaction_ = true;
  gate_type_ = GateType::kInteractive;
  gate_id_ = GetRegister().NextGateId();

  std::vector<typename astra::Wire<T>::value_type> v(number_of_simd_values);
  auto w = GetRegister().template EmplaceWire<astra::Wire<T>>(backend_, std::move(v));
  output_wires_ = {std::move(w)};

  auto& communication_layer = GetCommunicationLayer();
  std::size_t my_id = communication_layer.GetMyId();
  auto& message_manager = communication_layer.GetMessageManager();
  auto number_of_parties = communication_layer.GetNumberOfParties();
  
  //P0 is the only party that receives all shares of all other parties during online dot product
  if(my_id == 0) {
    dot_product_futures_online_ = 
      message_manager.RegisterReceiveAll(
        communication::MessageType::kAstraOnlineDotProductGate, gate_id_);
  }
  else {
    dot_product_futures_online_.emplace_back(
      message_manager.RegisterReceive(
        0, communication::MessageType::kAstraOnlineDotProductGate, gate_id_));
  }
  
  lambda_abk_wires_.reserve(elements_in_vector);
  for(auto k = 0u; k != elements_in_vector; ++k) {
    auto a = std::dynamic_pointer_cast<astra::Wire<T>>(parent_a_[k]);
    auto b = std::dynamic_pointer_cast<astra::Wire<T>>(parent_b_[k]);
    lambda_abk_wires_.emplace_back(
      AddLambdaAbJob(backend_, number_of_parties, my_id, std::move(a), std::move(b)));
  }
  
}

template <typename T>
void DotProductGate<T>::EvaluateSetup() {
  //Wait for base provider to finish its setup, since we use its SharingRandomnessGenerators
  GetBaseProvider().WaitForSetup();
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto elements_in_vector = parent_a_.size();
  auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_[0]);
  assert(out_wire);

  auto& out_values = out_wire->GetMutableValues();
  size_t simd_values = out_values.size();
  
  //Generate and store lambda_zi
  auto& rng = GetBaseProvider().GetMyRandomnessGenerator(my_id);
  std::vector<T> lambda_zi = rng.template GetUnsigned<T>(gate_id_, simd_values);
  for(auto i = 0u; i != simd_values; ++i) {
    out_values[i].lambda_i = lambda_zi[i];
  }
  
  for(auto k = 0u; k != elements_in_vector; ++k) {
    auto& lambda_abk_wire = lambda_abk_wires_[k];
    lambda_abk_wire->GetIsReadyCondition().Wait();
    const auto& lambda_abk_values = lambda_abk_wire->GetValues();
    assert(lambda_abk_values.size() == simd_values);
  
    //We store the sum over all k of lambda_abk_values
    //We don't subtract lambda_zi yet
    for(auto i = 0u; i != simd_values; ++i) {
      out_values[i].value += lambda_abk_values[i];
    }
  }
  
  out_wire->SetSetupIsReady();
}

template <typename T>
void DotProductGate<T>::EvaluateOnline() {
  constexpr int kLeadPartyId = 0;
  WaitSetup();
  assert(setup_is_ready_);
  auto elements_in_vector = parent_a_.size();
  auto& communication_layer = GetCommunicationLayer();
  auto number_of_parties = communication_layer.GetNumberOfParties();
  auto my_id = communication_layer.GetMyId();
  auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_[0]);
  assert(out_wire);
  auto& out_values = out_wire->GetMutableValues();
  size_t simd_values = out_values.size();

  for(auto k = 0u; k != elements_in_vector; ++k) {
    parent_a_[k]->GetIsReadyCondition().Wait();
    parent_b_[k]->GetIsReadyCondition().Wait();
    auto a_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_a_[k]);
    assert(a_wire);
    auto b_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_b_[k]);
    assert(b_wire);
    auto const& a_values = a_wire->GetMutableValues();
    auto const& b_values = b_wire->GetMutableValues();
  
    for(auto i = 0u; i != simd_values; ++i) {
      if(my_id == kLeadPartyId) {
        out_values[i].value += a_values[i].value * b_values[i].value;
      }
      out_values[i].value += a_values[i].value * b_values[i].lambda_i 
                           + b_values[i].value * a_values[i].lambda_i;
    }
  }
  //now we can subtract lambda_zi, since we calculated the sum over all k
  for(auto i = 0u; i != simd_values; ++i) {
    out_values[i].value -= out_values[i].lambda_i;
  }
  
  //All parties (except P0) send their share to P0 and receive the sum of all shares from P0
  if(my_id != kLeadPartyId) {
    //Transform out_values into sendable form
    std::vector<T> message_values;
    message_values.reserve(out_values.size());
    for (auto i = 0u; i != simd_values; ++i) {
      message_values.emplace_back(out_values[i].value);
    }
    assert(message_values.size() == simd_values);
    //Send own share to P0
    {
      auto payload = ToByteVector<T>(message_values);
      auto message = communication::BuildMessage(
                       communication::MessageType::kAstraOnlineDotProductGate, gate_id_, payload);
      communication_layer.SendMessage(kLeadPartyId, message.Release());
    }
    //Receive sum of all shares from P0
    {
      //We receive only from 1 party, so the futures index is always 0
      const auto message = dot_product_futures_online_[0].get();
      const auto payload = communication::GetMessage(message.data())->payload();
      auto received_values = FromByteVector<T>({payload->Data(), payload->size()});
      assert(received_values.size() == simd_values);
      for(auto i = 0u; i != simd_values; ++i) {
        out_values[i].value = received_values[i];
      }
    }
  }
  
  //P0 receives all shares, sums them up and sends the result back to everyone
  if(my_id == kLeadPartyId) {
    for(auto party_id = 0u; party_id != number_of_parties - 1; ++party_id) {
      const auto message = dot_product_futures_online_[party_id].get();
      const auto payload = communication::GetMessage(message.data())->payload();
      auto received_values = FromByteVector<T>({payload->Data(), payload->size()});
      assert(received_values.size() == simd_values);
      //We sum all of the values we get from the other parties
      for (auto i = 0u; i != simd_values; ++i) {
        out_values[i].value += received_values[i];
      }
    }
    
    //Transform out_values into sendable form
    std::vector<T> message_values;
    message_values.reserve(out_values.size());
    for (auto i = 0u; i != simd_values; ++i) {
      message_values.emplace_back(out_values[i].value);
    }
    assert(message_values.size() == simd_values);
    auto payload = ToByteVector<T>(message_values);
    auto message = communication::BuildMessage(
                     communication::MessageType::kAstraOnlineDotProductGate, gate_id_, payload);
    communication_layer.BroadcastMessage(message.Release());
  }
}
template <typename T>
astra::SharePointer<T> DotProductGate<T>::GetOutputAsAstraShare() {
  auto wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(wire);
  return std::make_shared<astra::Share<T>>(wire);
}

template class DotProductGate<std::uint8_t>;
template class DotProductGate<std::uint16_t>;
template class DotProductGate<std::uint32_t>;
template class DotProductGate<std::uint64_t>;
//template class DotProductGate<__uint128_t>;

}  // namespace encrypto::motion::proto::astra
