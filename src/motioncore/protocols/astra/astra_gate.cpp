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

#include <type_traits>


#include "astra_gate.h"
#include "astra_provider.h"
#include "astra_share.h"
#include "astra_wire.h"
#include "communication/astra_message.h"
#include "primitives/sharing_randomness_generator.h"
#include "utility/helpers.h"

//********************************************************************************************
#include <mutex>

#define BOOST_STACKTRACE_USE_ADDR2LINE
#include <boost/stacktrace.hpp>

std::mutex m;

void printState(std::size_t gate_id, std::size_t party_id, std::string msg) {
    std::lock_guard<std::mutex> lock{m};
    //std::cout << boost::stacktrace::stacktrace() << std::endl;
    std::cout << "(gate=" << gate_id << ", party=" << party_id << "): " << msg << std::endl;
}
//********************************************************************************************

namespace encrypto::motion::proto::astra {
    
//Simple randomness generation for testing purposes
constexpr std::size_t kKey_0_1 = 0;
constexpr std::size_t kKey_1_0 = 1;
constexpr std::size_t kKey_0_2 = 2;
constexpr std::size_t kKey_2_0 = 3;
constexpr std::size_t kKey_1_2 = 4;
constexpr std::size_t kKey_2_1 = 5;
constexpr std::size_t kKeyP_0 = 6;
constexpr std::size_t kKeyP_1 = 7;
constexpr std::size_t kKeyP_2 = 8;

uint64_t GetRandomValue(std::size_t key_id) {
    static std::mt19937_64 mt_64[9] = { std::mt19937_64{0}, std::mt19937_64{0}, std::mt19937_64{1}, 
                                        std::mt19937_64{1}, std::mt19937_64{2}, std::mt19937_64{2}, 
                                        std::mt19937_64{3}, std::mt19937_64{3}, std::mt19937_64{3} };
    std::lock_guard<std::mutex> lock{m};
    static std::uniform_int_distribution<uint64_t> 
      ui(std::numeric_limits<std::size_t>::min(), std::numeric_limits<std::size_t>::max());
    return ui(mt_64[key_id]);
}
    
template<typename T>
InputGate<T>::InputGate(const T& input, std::size_t input_owner, Backend& backend) 
: Base(backend) {
  input_owner_id_ = input_owner;
  gate_id_ = GetRegister().NextGateId();
  requires_online_interaction_ = true;
  
  auto my_id = GetCommunicationLayer().GetMyId();

  auto w = std::make_shared<astra::Wire<T>>(backend_, (my_id == input_owner ? input : 0), 0, 0);
  GetRegister().RegisterNextWire(w);
  output_wires_ = {std::move(w)};
  
  auto gate_info =
      fmt::format("uint{}_t type, gate id {}, owner {}", sizeof(T) * 8, gate_id_, input_owner_id_);
  GetLogger().LogDebug(fmt::format(
      "Allocate an astra::InputGate with following properties: {}", gate_info));
}

template<typename T>
void InputGate<T>::EvaluateSetup() {
  GetBaseProvider().WaitForSetup();
  input_future_ = backend_.GetAstraProvider().RegisterReceivingGate(gate_id_);
  auto my_id = GetCommunicationLayer().GetMyId();
  
  auto my_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(my_wire);
  auto& lambdas = my_wire->GetMutableLambdas();
  switch(input_owner_id_) {
    case 0:
      switch(my_id) {
        case 0: {
          auto& rng1 = GetBaseProvider().GetMyRandomnessGenerator(1);
          auto& rng2 = GetBaseProvider().GetMyRandomnessGenerator(2);
          lambdas[0] = rng1.template GetUnsigned<T>(gate_id_);
          lambdas[1] = rng2.template GetUnsigned<T>(gate_id_);
          break;
        }
        case 1: {
          auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
          lambdas[0] = rng0.template GetUnsigned<T>(gate_id_);
          break;
        }
        case 2: {
          auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
          lambdas[1] = rng0.template GetUnsigned<T>(gate_id_);
          break;
        }
      }
      break;
    case 1:
      switch(my_id) {
        case 0: {
          auto& rng1 = GetBaseProvider().GetMyRandomnessGenerator(1);
          auto& rng_global = GetBaseProvider().GetGlobalRandomnessGenerator();
          lambdas[0] = rng1.template GetUnsigned<T>(gate_id_);
          lambdas[1] = rng_global.template GetUnsigned<T>(gate_id_);
          break;
        }
        case 1: {
          auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
          auto& rng_global = GetBaseProvider().GetGlobalRandomnessGenerator();
          lambdas[0] = rng0.template GetUnsigned<T>(gate_id_);
          lambdas[1] = rng_global.template GetUnsigned<T>(gate_id_);
          break;
        }
        case 2: {
          auto& rng_global = GetBaseProvider().GetGlobalRandomnessGenerator();
          lambdas[1] = rng_global.template GetUnsigned<T>(gate_id_);
          break;
        }
      }
      break;
    case 2:
      switch(my_id) {
        case 0: {
          auto& rng_global = GetBaseProvider().GetGlobalRandomnessGenerator();
          auto& rng2 = GetBaseProvider().GetMyRandomnessGenerator(2);
          lambdas[0] = rng_global.template GetUnsigned<T>(gate_id_);
          lambdas[1] = rng2.template GetUnsigned<T>(gate_id_);
          break;
        }
        case 1: {
          auto& rng_global = GetBaseProvider().GetGlobalRandomnessGenerator();
          lambdas[0] = rng_global.template GetUnsigned<T>(gate_id_);
          break;
        }
        case 2: {
          auto& rng_global = GetBaseProvider().GetGlobalRandomnessGenerator();
          auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
          lambdas[0] = rng_global.template GetUnsigned<T>(gate_id_);
          lambdas[1] = rng0.template GetUnsigned<T>(gate_id_);
          break;
        }
      }
      break;    
  }
  SetSetupIsReady();
  GetRegister().IncrementEvaluatedGatesSetupCounter();
}

template<typename T>
void InputGate<T>::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);
  
  auto my_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(my_wire);
  auto& value = my_wire->GetMutableValue();
  
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  
  if(static_cast<std::size_t>(input_owner_id_) == my_id) {
    auto const& lambdas = my_wire->GetMutableLambdas();
    T lambda_x = lambdas[0] + lambdas[1];
    value += lambda_x;
    
    auto payload = ToByteVector(std::vector<T>{value});
    auto message = communication::BuildAstraInputMessage(gate_id_, payload);
    communication_layer.BroadcastMessage(std::move(message)); 
  }
  else if(my_id != 0) {
    value = FromByteVector<T>(input_future_.get())[0];
  }
  backend_.GetAstraProvider().UnregisterReceivingGate(gate_id_);
  
  GetLogger().LogDebug(fmt::format("Evaluated astra::InputGate with id#{}", gate_id_));
  SetOnlineIsReady();
  GetRegister().IncrementEvaluatedGatesOnlineCounter();
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

  
//TODO: Implement sending output only to one party
template<typename T>
OutputGate<T>::OutputGate(const astra::WirePointer<T>& parent, std::size_t output_owner)
: Base(parent->GetBackend()) {
  assert(parent);
  
  if (parent->GetProtocol() != MpcProtocol::kAstra) {
    auto sharing_type = to_string(parent->GetProtocol());
    throw(
        std::runtime_error((fmt::format("Astra output gate expects an astra share, "
                                        "got a share of type {}",
                                        sharing_type))));
  }
  
  parent_ = {parent};
  output_owner_ = output_owner;
  requires_online_interaction_ = true;
  gate_type_ = GateType::kInteractive;
  gate_id_ = GetRegister().NextGateId();
  
  RegisterWaitingFor(parent_.at(0)->GetWireId());
  parent_.at(0)->RegisterWaitingGate(gate_id_);
  
  auto w = std::make_shared<astra::Wire<T>>(backend_, 0, 0, 0);
  GetRegister().RegisterNextWire(w);
  output_wires_ = {std::move(w)};
}

template <typename T>
OutputGate<T>::OutputGate(const astra::SharePointer<T>& parent, std::size_t output_owner)
    : OutputGate((assert(parent), parent->GetAstraWire()), output_owner) {}

template <typename T>
OutputGate<T>::OutputGate(const motion::SharePointer& parent, std::size_t output_owner)
    : OutputGate(std::dynamic_pointer_cast<astra::Share<T>>(parent), output_owner) {}

template<typename T>
void OutputGate<T>::EvaluateSetup() {
  output_future_ = backend_.GetAstraProvider().RegisterReceivingGate(gate_id_);
  SetSetupIsReady();
  GetRegister().IncrementEvaluatedGatesSetupCounter();
}

template<typename T>
void OutputGate<T>::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);
  parent_.at(0)->GetIsReadyCondition().Wait();
  
  auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(out_wire);
  auto my_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_.at(0));
  assert(my_wire);
  
  auto& out_value = out_wire->GetMutableValue();
  auto const& lambdas = my_wire->GetMutableLambdas();
  auto const& value = my_wire->GetMutableValue();
  
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();

  switch(my_id) {
    case 0: {
      auto payload = ToByteVector(std::vector<T>{lambdas[0]});
      auto message = communication::BuildAstraOutputMessage(gate_id_, payload);
      communication_layer.SendMessage(2, std::move(message));
        
      auto received_value = FromByteVector<T>(output_future_.get())[0];
      out_value = received_value - lambdas[0] - lambdas[1];
      break;
    }
    case 1: {
      auto payload = ToByteVector(std::vector<T>{value});
      auto message = communication::BuildAstraOutputMessage(gate_id_, payload);
      communication_layer.SendMessage(0, std::move(message));
        
      auto received_lambda = FromByteVector<T>(output_future_.get())[0];
      out_value = value - lambdas[0] - received_lambda;
      break;
    }
    case 2: {
      auto payload = ToByteVector(std::vector<T>{lambdas[1]});
      auto message = communication::BuildAstraOutputMessage(gate_id_, payload);
      communication_layer.SendMessage(1, std::move(message));
        
      auto received_lambda = FromByteVector<T>(output_future_.get())[0];
      out_value = value - received_lambda - lambdas[1];
      break;
    }
    default: {
      //suppress warning
      (void) out_value;
      assert(false);
    }
  }
  
  backend_.GetAstraProvider().UnregisterReceivingGate(gate_id_);
  
  GetLogger().LogDebug(fmt::format("Evaluated astra::OutputGate with id#{}", gate_id_));
  
  SetOnlineIsReady();
  GetRegister().IncrementEvaluatedGatesOnlineCounter();
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

template<typename T>
AdditionGate<T>::AdditionGate(const astra::WirePointer<T>& a, const astra::WirePointer<T>& b)
: TwoGate(a->GetBackend()) {
  parent_a_ = {a};
  parent_b_ = {b};
  
  requires_online_interaction_ = false;
  gate_type_ = GateType::kNonInteractive;
  gate_id_ = GetRegister().NextGateId();
  
  RegisterWaitingFor(parent_a_.at(0)->GetWireId());
  parent_a_.at(0)->RegisterWaitingGate(gate_id_);
  RegisterWaitingFor(parent_b_.at(0)->GetWireId());
  parent_b_.at(0)->RegisterWaitingGate(gate_id_);
  
  auto w = std::make_shared<astra::Wire<T>>(backend_, 0, 0, 0);
  GetRegister().RegisterNextWire(w);
  output_wires_ = {std::move(w)};

  auto gate_info =
      fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                  parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
  GetLogger().LogDebug(fmt::format(
      "Created an astra::AdditionGate with following properties: {}", gate_info));
}

template<typename T>
void AdditionGate<T>::EvaluateSetup() {
  //Setup Phase is moved to online phase, as we have to wait for our input gates
  SetSetupIsReady();
  GetRegister().IncrementEvaluatedGatesSetupCounter();
}

template<typename T>
void AdditionGate<T>::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);
  parent_a_.at(0)->GetIsReadyCondition().Wait();
  parent_b_.at(0)->GetIsReadyCondition().Wait();
  
  auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_a_.at(0));
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_b_.at(0));
  assert(b_wire);
  
  auto& out_value = out_wire->GetMutableValue();
  auto& out_lambdas = out_wire->GetMutableLambdas();
  auto const& a_value = a_wire->GetMutableValue();
  auto const& a_lambdas = a_wire->GetMutableLambdas();
  auto const& b_value = b_wire->GetMutableValue();
  auto const& b_lambdas = b_wire->GetMutableLambdas();
  
  auto my_id = GetCommunicationLayer().GetMyId();
  
  //Setup Phase according to paper
  switch(my_id) {
    case 0: {
      out_lambdas[0] = a_lambdas[0] + b_lambdas[0];
      out_lambdas[1] = a_lambdas[1] + b_lambdas[1];
      break;
    }
    case 1: {
      out_lambdas[0] = a_lambdas[0] + b_lambdas[0];
      break;
    }
    case 2: {
      out_lambdas[1] = a_lambdas[1] + b_lambdas[1];
      break;
    }
  }
  
  //Online Phase according to paper
  if(my_id != 0) {
    out_value = a_value + b_value;
  }
  
  GetLogger().LogDebug(fmt::format("Evaluated astra::AdditionGate with id#{}", gate_id_));
  SetOnlineIsReady();
  GetRegister().IncrementEvaluatedGatesOnlineCounter();
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

template<typename T>
SubtractionGate<T>::SubtractionGate(const astra::WirePointer<T>& a, const astra::WirePointer<T>& b)
: TwoGate(a->GetBackend()) {
  parent_a_ = {a};
  parent_b_ = {b};
  
  requires_online_interaction_ = false;
  gate_type_ = GateType::kNonInteractive;
  gate_id_ = GetRegister().NextGateId();
  
  RegisterWaitingFor(parent_a_.at(0)->GetWireId());
  parent_a_.at(0)->RegisterWaitingGate(gate_id_);
  RegisterWaitingFor(parent_b_.at(0)->GetWireId());
  parent_b_.at(0)->RegisterWaitingGate(gate_id_);
  
  auto w = std::make_shared<astra::Wire<T>>(backend_, 0, 0, 0);
  GetRegister().RegisterNextWire(w);
  output_wires_ = {std::move(w)};

  auto gate_info =
      fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                  parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
  GetLogger().LogDebug(fmt::format(
      "Created an astra::Subtraction with following properties: {}", gate_info));
}

template<typename T>
void SubtractionGate<T>::EvaluateSetup() {
  //Setup Phase is moved to online phase, as we have to wait for our input gates
  SetSetupIsReady();
  GetRegister().IncrementEvaluatedGatesSetupCounter();
}

template<typename T>
void SubtractionGate<T>::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);
  parent_a_.at(0)->GetIsReadyCondition().Wait();
  parent_b_.at(0)->GetIsReadyCondition().Wait();
  
  auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_a_.at(0));
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_b_.at(0));
  assert(b_wire);
  
  auto& out_value = out_wire->GetMutableValue();
  auto& out_lambdas = out_wire->GetMutableLambdas();
  auto const& a_value = a_wire->GetMutableValue();
  auto const& a_lambdas = a_wire->GetMutableLambdas();
  auto const& b_value = b_wire->GetMutableValue();
  auto const& b_lambdas = b_wire->GetMutableLambdas();
  
  auto my_id = GetCommunicationLayer().GetMyId();
  
  //Setup Phase according to paper
  switch(my_id) {
    case 0: {
      out_lambdas[0] = a_lambdas[0] - b_lambdas[0];
      out_lambdas[1] = a_lambdas[1] - b_lambdas[1];
      break;
    }
    case 1: {
      out_lambdas[0] = a_lambdas[0] - b_lambdas[0];
      break;
    }
    case 2: {
      out_lambdas[1] = a_lambdas[1] - b_lambdas[1];
      break;
    }
  }

  if(my_id != 0) {
    out_value = a_value - b_value;
  }
  
  GetLogger().LogDebug(fmt::format("Evaluated astra::SubtractionGate with id#{}", gate_id_));
  SetOnlineIsReady();
  GetRegister().IncrementEvaluatedGatesOnlineCounter();
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

template<typename T>
MultiplicationGate<T>::MultiplicationGate(const astra::WirePointer<T>& a, const astra::WirePointer<T>& b)
: TwoGate(a->GetBackend()) {
  parent_a_ = {a};
  parent_b_ = {b};
  
  requires_online_interaction_ = true;
  gate_type_ = GateType::kInteractive;
  gate_id_ = GetRegister().NextGateId();
  
  RegisterWaitingFor(parent_a_.at(0)->GetWireId());
  parent_a_.at(0)->RegisterWaitingGate(gate_id_);
  RegisterWaitingFor(parent_b_.at(0)->GetWireId());
  parent_b_.at(0)->RegisterWaitingGate(gate_id_);
  
  auto w = std::make_shared<astra::Wire<T>>(backend_, 0, 0, 0);
  GetRegister().RegisterNextWire(w);
  output_wires_ = {std::move(w)};
  
  multiply_future_ = backend_.GetAstraProvider().RegisterReceivingGate(gate_id_);

  auto gate_info =
      fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                  parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
  GetLogger().LogDebug(fmt::format(
      "Created an astra::MultiplicationGate with following properties: {}", gate_info));
}

template<typename T>
void MultiplicationGate<T>::EvaluateSetup() {
  switch(my_id) {
    case 0: {
      auto& rng1 = GetBaseProvider().GetMyRandomnessGenerator(1);
      auto& rng2 = GetBaseProvider().GetMyRandomnessGenerator(2);
      out_lambdas[0] = rng1.template GetUnsigned<T>(gate_id_);
      out_lambdas[1] = rng2.template GetUnsigned<T>(gate_id_);
        
      auto a_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_a_.at(0));
      assert(a_wire);
      auto b_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_b_.at(0));
      assert(b_wire);
          
      auto const& a_lambdas = a_wire->GetMutableLambdas();
      auto const& b_lambdas = b_wire->GetMutableLambdas();
          
      T gamma_ab_1 = rng1.template GetUnsigned<T>(gate_id_);
      T lambda_a = a_lambdas[0] + a_lambdas[1];
      T lambda_b = b_lambdas[0] + b_lambdas[1];
      T gamma_ab = lambda_a * lambda_b;
      T gamma_ab_2 = gamma_ab - gamma_ab_1;
          
      auto payload = ToByteVector(std::vector<T>{gamma_ab_2});
      auto message = communication::BuildAstraSetupMultiplyMessage(gate_id_, payload);
      communication_layer.SendMessage(2, std::move(message));
      break;
    }
    case 1: {
      auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
      out_lambdas[0] = rng0.template GetUnsigned<T>(gate_id_);
      //We store gamma_ab_1 in the free out_lambda space
      out_lambdas[1] = rng0.template GetUnsigned<T>(gate_id_);
      break;
    }
    case 2: {
      auto& rng0 = GetBaseProvider().GetTheirRandomnessGenerator(0);
      out_lambdas[1] = rng0.template GetUnsigned<T>(gate_id_);
      //We store gamma_ab_2 in the free out_lambda space
      out_lambdas[0] = FromByteVector<T>(multiply_future_.get())[0];
      break;
    }
  }
  SetSetupIsReady();
  GetRegister().IncrementEvaluatedGatesSetupCounter();
}

template<typename T>
void MultiplicationGate<T>::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);
  parent_a_.at(0)->GetIsReadyCondition().Wait();
  parent_b_.at(0)->GetIsReadyCondition().Wait();  
  
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(out_wire);
  auto a_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_a_.at(0));
  assert(a_wire);
  auto b_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_b_.at(0));
  assert(b_wire);
  
  auto& out_value = out_wire->GetMutableValue();
  auto const& a_value = a_wire->GetMutableValue();
  auto const& b_value = b_wire->GetMutableValue();
    
  auto& out_lambdas = out_wire->GetMutableLambdas();
  auto const& a_lambdas = a_wire->GetMutableLambdas();
  auto const& b_lambdas = b_wire->GetMutableLambdas();
  
  printState(gate_id_, my_id, 
             std::string("Mul Setup Start: a_value=")
             + std::to_string((uint64_t) a_wire->GetMutableValue())
             + std::string(", a_lambda1=")
             + std::to_string((uint64_t) a_wire->GetMutableLambdas()[0])
             + std::string(", a_lambda2=")
             + std::to_string((uint64_t) a_wire->GetMutableLambdas()[1])
             + std::string(", b_value=")
             + std::to_string((uint64_t) b_wire->GetMutableValue())
             + std::string(", b_lambda1=")
             + std::to_string((uint64_t) b_wire->GetMutableLambdas()[0])
             + std::string(", b_lambda2=")
             + std::to_string((uint64_t) b_wire->GetMutableLambdas()[1]));
  
  //Online phase according to paper
  if(my_id != 0) {
    switch(my_id) {
      case 1: {
        out_value = -(a_value * b_lambdas[0]) - b_value * a_lambdas[0] + out_lambdas[0] + out_lambdas[1];
        
        auto payload = ToByteVector(std::vector<T>{out_value});
        auto message = communication::BuildAstraOnlineMultiplyMessage(gate_id_, payload);
        communication_layer.SendMessage(2, std::move(message));
        
        out_value += FromByteVector<T>(multiply_future_.get())[0];
        break;
      }
      case 2: {
        out_value = a_value * b_value - a_value * b_lambdas[1] - b_value * a_lambdas[1] + out_lambdas[1] + out_lambdas[0];
        
        auto payload = ToByteVector(std::vector<T>{out_value});
        auto message = communication::BuildAstraOnlineMultiplyMessage(gate_id_, payload);
        communication_layer.SendMessage(1, std::move(message));
        
        out_value += FromByteVector<T>(multiply_future_.get())[0];
        break;
      }
    }
  }
  
  GetLogger().LogDebug(fmt::format("Evaluated astra::MultiplicationGate with id#{}", gate_id_));
  SetOnlineIsReady();
  GetRegister().IncrementEvaluatedGatesOnlineCounter();
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
template class MultiplicationGate<__uint128_t>;

template<typename T>
DotProductGate<T>::DotProductGate(const std::vector<motion::WirePointer>& vector_a, const std::vector<motion::WirePointer>& vector_b)
: Base(vector_a.at(0)->GetBackend()) {
  parent_a_ = vector_a;
  parent_b_ = vector_b;
  
  assert(parent_a_.size() > 0);
  assert(parent_a_.size() == parent_b_.size());
  
  requires_online_interaction_ = true;
  gate_type_ = GateType::kInteractive;
  gate_id_ = GetRegister().NextGateId();
  
  for(auto&& pa : parent_a_) {
    RegisterWaitingFor(pa->GetWireId());
    pa->RegisterWaitingGate(gate_id_);
  }
  
  for(auto&& pb : parent_b_) {
    RegisterWaitingFor(pb->GetWireId());
    pb->RegisterWaitingGate(gate_id_);
  }
  
  auto w = std::make_shared<astra::Wire<T>>(backend_, 0, 0, 0);
  GetRegister().RegisterNextWire(w);
  output_wires_ = {std::move(w)};
  
  dot_product_future_ = backend_.GetAstraProvider().RegisterReceivingGate(gate_id_);
}

template<typename T>
void DotProductGate<T>::EvaluateSetup() {
  auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
  assert(out_wire);
  auto& out_lambdas = out_wire->GetMutableLambdas();
  
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  
  switch(my_id) {
      case 0:
        out_lambdas[0] = GetRandomValue(kKey_0_1);
        out_lambdas[1] = GetRandomValue(kKey_0_2);
        {
          T gamma_ab_1 = GetRandomValue(kKey_0_1);
          T gamma_ab{0};
          //Compute gamma_ab
          for(std::size_t i = 0; i != parent_a_.size(); ++i) {
            auto a_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_a_.at(i));
            assert(a_wire);
            auto b_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_b_.at(i));
            assert(b_wire);
            
            auto const& a_lambdas = a_wire->GetMutableLambdas();
            auto const& b_lambdas = b_wire->GetMutableLambdas();
            
            T lambda_a = a_lambdas[0] + a_lambdas[1];
            T lambda_b = b_lambdas[0] + b_lambdas[1];
            gamma_ab += lambda_a * lambda_b;
          }
          T gamma_ab_2 = gamma_ab - gamma_ab_1;
          
          auto payload = ToByteVector(std::vector<T>{gamma_ab_2});
          auto message = communication::BuildAstraSetupDotProductMessage(gate_id_, payload);
          communication_layer.SendMessage(2, std::move(message));
        }
        break;
      case 1:
        out_lambdas[0] = GetRandomValue(kKey_1_0);
        //We store gamma_ab_1 in the free out_lambda space
        out_lambdas[1] = GetRandomValue(kKey_1_0);
        break;
      case 2:
        out_lambdas[1] = GetRandomValue(kKey_2_0);
        //We store gamma_ab_2 in the free out_lambda space
        out_lambdas[0] = FromByteVector<T>(dot_product_future_.get())[0];
        break;
  }
  SetSetupIsReady();
  GetRegister().IncrementEvaluatedGatesSetupCounter();
}

template<typename T>
void DotProductGate<T>::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);
  parent_a_.at(0)->GetIsReadyCondition().Wait();
  parent_b_.at(0)->GetIsReadyCondition().Wait();
  
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  
  if(my_id != 0) {
    
    auto out_wire = std::dynamic_pointer_cast<astra::Wire<T>>(output_wires_.at(0));
    assert(out_wire);
  
    auto& out_value = out_wire->GetMutableValue();
    auto& out_lambdas = out_wire->GetMutableLambdas();
    
    out_value = 0;
    for(std::size_t i = 0; i != parent_a_.size(); ++i) {
      auto a_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_a_.at(i));
      assert(a_wire);
      auto b_wire = std::dynamic_pointer_cast<astra::Wire<T>>(parent_b_.at(i));
      assert(b_wire);
      auto const& a_value = a_wire->GetMutableValue();
      auto const& b_value = b_wire->GetMutableValue();
      auto const& a_lambdas = a_wire->GetMutableLambdas();
      auto const& b_lambdas = b_wire->GetMutableLambdas();
      
      switch(my_id) {
        case 1:
          out_value += -(a_value * b_lambdas[0]) - b_value * a_lambdas[0];
          break;
        case 2:
          out_value += a_value * b_value - a_value * b_lambdas[1] - b_value * a_lambdas[1];
          break;
      }
    }
    
    switch(my_id) {
      case 1: 
        {
          out_value += out_lambdas[0] + out_lambdas[1];
          
          auto payload = ToByteVector(std::vector<T>{out_value});
          auto message = communication::BuildAstraOnlineDotProductMessage(gate_id_, payload);
          communication_layer.SendMessage(2, std::move(message));
          
          out_value += FromByteVector<T>(dot_product_future_.get())[0];
        }
        break;
      case 2:
        {
          out_value += out_lambdas[1] + out_lambdas[0];
          
          auto payload = ToByteVector(std::vector<T>{out_value});
          auto message = communication::BuildAstraOnlineDotProductMessage(gate_id_, payload);
          communication_layer.SendMessage(1, std::move(message));
        
          out_value += FromByteVector<T>(dot_product_future_.get())[0];
        }
        break;
    }
  }
  
  GetLogger().LogDebug(fmt::format("Evaluated astra::DotProductGate with id#{}", gate_id_));
  SetOnlineIsReady();
  GetRegister().IncrementEvaluatedGatesOnlineCounter();
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
template class DotProductGate<__uint128_t>;
  
} //namespace encrypto::motion::proto::astra
