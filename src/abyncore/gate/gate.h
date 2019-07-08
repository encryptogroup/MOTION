#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <unordered_set>
#include <vector>

#include "utility/typedefs.h"

namespace ABYN::Wires{
class Wire;
using WirePtr = std::shared_ptr<Wire>;
}

namespace ABYN{
class Backend;
class Register;
class Configuration;
class Logger;
}

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

  bool AreDependenciesReady() { return wire_dependencies_.size() == num_ready_dependencies; }

  void SetSetupIsReady() { setup_is_ready_ = true; }

  void SetOnlineIsReady();

  bool &SetupIsReady() { return setup_is_ready_; }

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

  std::atomic<std::size_t> num_ready_dependencies = 0;

  Gate() = default;

  std::shared_ptr<Register> GetRegister();
  std::shared_ptr<Configuration> GetConfig();
  std::shared_ptr<Logger> GetLogger();

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

  std::int64_t input_owner_ = -1;
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