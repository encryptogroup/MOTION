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

#include "utility/typedefs.h"

namespace ENCRYPTO {
class Condition;
}

namespace ABYN::Wires {
class Wire;
using WirePtr = std::shared_ptr<Wire>;
}  // namespace ABYN::Wires

namespace ABYN {
class Backend;
class Register;
class Configuration;
class Logger;
class MTProvider;
}  // namespace ABYN

namespace ABYN::Gates::Interfaces {

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

  const std::vector<Wires::WirePtr> &GetOutputWires() const { return output_wires_; }

  void Clear();

  void RegisterWaitingFor(std::size_t wire_id);

  void SignalDependencyIsReady();

  bool AreDependenciesReady() { return wire_dependencies_.size() == num_ready_dependencies_; }

  void SetSetupIsReady() { setup_is_ready_ = true; }

  void SetOnlineIsReady();

  void WaitOnline();

  bool SetupIsReady() { return setup_is_ready_; }

  std::int64_t GetID() const { return gate_id_; }

  Gate(Gate &) = delete;

 protected:
  std::vector<Wires::WirePtr> output_wires_;
  std::weak_ptr<Backend> backend_;
  std::int64_t gate_id_ = -1;
  std::unordered_set<std::size_t> wire_dependencies_;

  GateType gate_type_ = InvalidGate;
  bool setup_is_ready_ = false;
  bool online_is_ready_ = false;
  bool requires_online_interaction_ = false;

  bool added_to_active_queue = false;

  std::shared_ptr<ENCRYPTO::Condition> online_is_ready_cond_;

  std::atomic<std::size_t> num_ready_dependencies_ = 0;

  Gate();

  std::shared_ptr<Register> GetRegister();
  std::shared_ptr<Configuration> GetConfig();
  std::shared_ptr<Logger> GetLogger();
  std::shared_ptr<MTProvider> GetMTProvider();

 private:
  void IfReadyAddToProcessingQueue();

  std::mutex mutex_;
};

using GatePtr = std::shared_ptr<Gate>;

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

  OneGate(OneGate &) = delete;

 protected:
  std::vector<Wires::WirePtr> parent_;

  OneGate() = default;
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

  InputGate() { gate_type_ = GateType::InputGate; }

  InputGate(InputGate &) = delete;

  std::int64_t input_owner_id_ = -1;
};

using InputGatePtr = std::shared_ptr<InputGate>;

//
//     | <- one SharePtr input
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

  OutputGate(OutputGate &) = delete;

  OutputGate() { gate_type_ = GateType::InteractiveGate; }

 protected:
  std::int64_t output_owner_ = -1;
};

using OutputGatePtr = std::shared_ptr<OutputGate>;

//
//   |    | <- two SharePtrs input
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- SharePointer output
//

class TwoGate : public Gate {
 protected:
  std::vector<Wires::WirePtr> parent_a_;
  std::vector<Wires::WirePtr> parent_b_;

  TwoGate() = default;

 public:
  ~TwoGate() override = default;
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

class nInputGate : public Gate {
 protected:
  std::vector<Wires::WirePtr> parents_;

  nInputGate() = default;

 public:
  ~nInputGate() override = default;
};

}  // namespace ABYN::Gates::Interfaces

namespace ABYN::Gates {
// alias
using Gate = ABYN::Gates::Interfaces::Gate;
}