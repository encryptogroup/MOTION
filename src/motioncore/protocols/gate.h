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

#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <unordered_set>
#include <vector>

#include "utility/fiber_condition.h"
#include "utility/typedefs.h"

namespace encrypto::motion::communication {

class CommunicationLayer;

}  // namespace encrypto::motion::communication

namespace encrypto::motion {

class BaseProvider;
class OtProvider;
class Wire;
using WirePointer = std::shared_ptr<Wire>;
class Backend;
class Register;
class Configuration;
class Logger;
class MtProvider;
class SbProvider;
class SpProvider;

//
//  inputs are not defined in the Gate class but only in the child classes
//
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- one abstract output
//

class Gate {
 public:
  virtual ~Gate() = default;

  virtual void EvaluateSetup() = 0;

  virtual void EvaluateOnline() = 0;

  const std::vector<WirePointer>& GetOutputWires() const { return output_wires_; }

  void Clear();

  void RegisterWaitingFor(std::size_t wire_id);

  void SignalDependencyIsReady();

  bool AreDependenciesReady() { return wire_dependencies_.size() == number_of_ready_dependencies_; }

  void SetSetupIsReady();

  void SetOnlineIsReady();

  void WaitSetup() const;

  void WaitOnline() const;

  bool SetupIsReady() const { return setup_is_ready_; }

  std::int64_t GetId() const { return gate_id_; }

  Gate(Gate&) = delete;

 protected:
  std::vector<WirePointer> output_wires_;
  Backend& backend_;
  std::int64_t gate_id_ = -1;
  std::unordered_set<std::size_t> wire_dependencies_;

  GateType gate_type_ = GateType::kInvalid;
  std::atomic<bool> setup_is_ready_ = false;
  std::atomic<bool> online_is_ready_ = false;
  std::atomic<bool> requires_online_interaction_ = false;

  std::atomic<bool> added_to_active_queue_ = false;

  FiberCondition setup_is_ready_condition_;
  FiberCondition online_is_ready_condition_;

  std::atomic<std::size_t> number_of_ready_dependencies_ = 0;

  Gate(Backend& backend);

  Register& GetRegister();
  Configuration& GetConfiguration();
  Logger& GetLogger();
  BaseProvider& GetBaseProvider();
  MtProvider& GetMtProvider();
  SpProvider& GetSpProvider();
  SbProvider& GetSbProvider();
  communication::CommunicationLayer& GetCommunicationLayer();
  OtProvider& GetOtProvider(const std::size_t i);
  bool own_output_wires_{true};

 private:
  void IfReadyAddToProcessingQueue();

  std::mutex mutex_;
};

using GatePointer = std::shared_ptr<Gate>;

//
//     | <- one abstract input
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- one abstract output
//

class OneGate : public Gate {
 public:
  ~OneGate() override = default;

  OneGate(OneGate&) = delete;

 protected:
  std::vector<WirePointer> parent_;

  OneGate(Backend& backend) : Gate(backend) {}
};

//
//     | <- one abstract (perhaps !SharePointer) input
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- SharePointer output
//

class InputGate : public OneGate {
 public:
 protected:
  ~InputGate() override = default;

  InputGate(Backend& backend) : OneGate(backend) { gate_type_ = GateType::kInput; }

  InputGate(InputGate&) = delete;

  std::int64_t input_owner_id_ = -1;
};

using InputGatePointer = std::shared_ptr<InputGate>;

//
//     | <- one SharePointer input
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- abstract output
//

class OutputGate : public OneGate {
 public:
  ~OutputGate() override = default;

  OutputGate(OutputGate&) = delete;

  OutputGate(Backend& backend) : OneGate(backend) { gate_type_ = GateType::kInteractive; }

 protected:
  std::int64_t output_owner_ = -1;
};

using OutputGatePointer = std::shared_ptr<OutputGate>;

//
//   |    | <- two SharePointers input
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- SharePointer output
//

class TwoGate : public Gate {
 protected:
  std::vector<WirePointer> parent_a_;
  std::vector<WirePointer> parent_b_;

  TwoGate(Backend& backend) : Gate(backend) {}

 public:
  ~TwoGate() override = default;
};

//
//  |  |  | <- three SharePointers input
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- SharePointer output
//

class ThreeGate : public Gate {
 protected:
  std::vector<WirePointer> parent_a_;
  std::vector<WirePointer> parent_b_;
  std::vector<WirePointer> parent_c_;

  ThreeGate(Backend& backend) : Gate(backend) {}

 public:
  ~ThreeGate() override = default;
};

//
//  | |... |  <- n SharePointers input
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- SharePointer output
//

class NInputGate : public Gate {
 protected:
  std::vector<WirePointer> parents_;

  NInputGate(Backend& backend) : Gate(backend) {}

 public:
  ~NInputGate() override = default;
};

}  // namespace encrypto::motion
