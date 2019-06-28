#pragma once

#include <unordered_set>
#include <vector>

#include "base/register.h"
#include "wire/wire.h"

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

  void RegisterWaitingFor(std::size_t wire_id) {
    std::scoped_lock lock(mutex_);
    wire_dependencies_.insert(wire_id);
  }

  void UnregisterWaitingFor(std::size_t wire_id) {
    std::scoped_lock lock(mutex_);
    if (wire_dependencies_.size() > 0 &&
        wire_dependencies_.find(wire_id) != wire_dependencies_.end()) {
      wire_dependencies_.erase(wire_id);
    }
    IfReadyAddToProcessingQueue();
  }

  bool DependenciesAreReady() { return wire_dependencies_.size() == 0; }

  void SetSetupIsReady() { setup_is_ready_ = true; }

  void SetOnlineIsReady() {
    online_is_ready_ = true;
    for (auto &wire : output_wires_) {
      assert(wire);
      wire->SetOnlineFinished();
    }
  }

  bool &SetupIsReady() { return setup_is_ready_; }

  std::int64_t GetID() const { return gate_id_; }

  Gate(Gate &) = delete;

 protected:
  std::vector<Wires::WirePtr> output_wires_;
  std::weak_ptr<Register> register_;
  std::int64_t gate_id_ = -1;
  std::unordered_set<std::size_t> wire_dependencies_;

  GateType gate_type_ = InvalidGate;
  bool setup_is_ready_ = false;
  bool online_is_ready_ = false;
  bool requires_online_interaction_ = false;

  bool added_to_active_queue = false;

  Gate() = default;

 private:
  void IfReadyAddToProcessingQueue() {
    if (DependenciesAreReady() && !added_to_active_queue) {
      auto shared_ptr_reg = register_.lock();
      assert(shared_ptr_reg);
      shared_ptr_reg->AddToActiveQueue(gate_id_);
      added_to_active_queue = true;
    }
  }

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