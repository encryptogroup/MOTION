#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <queue>

#include "flatbuffers/flatbuffers.h"

namespace ABYN {

// >> forward declarations

class Logger;
using LoggerPtr = std::shared_ptr<Logger>;

class Configuration;
using ConfigurationPtr = std::shared_ptr<Configuration>;

namespace Gates {
namespace Interfaces {
class Gate;
}  // namespace Interfaces
using Gate = Interfaces::Gate;
using GatePtr = std::shared_ptr<Gate>;
}  // namespace Gates

namespace Wires {
class Wire;
using WirePtr = std::shared_ptr<Wire>;
}  // namespace Wires

namespace Communication {
class Handler;
using HandlerPtr = std::shared_ptr<Handler>;
}  // namespace Communication

// forward declarations <<

class Register {
 public:
  Register() = delete;

  Register(const Register &) = delete;

  Register(ConfigurationPtr &config);

  ~Register();

  std::size_t NextGateId() noexcept;

  std::size_t NextWireId() noexcept;

  std::size_t NextArithmeticSharingId(std::size_t num_of_parallel_values);

  std::size_t NextBooleanGMWSharingId(std::size_t num_of_parallel_values);

  const LoggerPtr &GetLogger() const noexcept;

  const ConfigurationPtr &GetConfig() const noexcept;

  void RegisterCommunicationHandlers(
      std::vector<Communication::HandlerPtr> &communication_handlers);

  void Send(std::size_t party_id, flatbuffers::FlatBufferBuilder &message);

  void RegisterNextGate(Gates::GatePtr gate);

  void RegisterNextInputGate(Gates::GatePtr gate);

  const Gates::GatePtr &GetGate(std::size_t gate_id) const { return gates_.at(gate_id); }
  const auto &GetInputGates() const { return input_gates_; }

  auto &GetGates() const { return gates_; }

  void UnregisterGate(std::size_t gate_id) { gates_.at(gate_id) = nullptr; }

  void RegisterNextWire(Wires::WirePtr wire) { wires_.push_back(wire); }

  Wires::WirePtr GetWire(std::size_t wire_id) const { return wires_.at(wire_id); }

  void UnregisterWire(std::size_t wire_id) { wires_.at(wire_id) = nullptr; }

  void AddToActiveQueue(std::size_t gate_id);

  std::int64_t GetNextGateFromOnlineQueue();

  void IncrementEvaluatedGatesCounter() { evaluated_gates++; }

  std::size_t GetNumOfEvaluatedGates() { return evaluated_gates; }

  std::size_t GetTotalNumOfGates() { return global_gate_id_; }

 private:
  // don't need atomic here, since only the master thread has access to these
  std::size_t global_gate_id_ = 0, global_wire_id_ = 0, global_arithmetic_gmw_sharing_id_ = 0,
              global_boolean_gmw_sharing_id_ = 0;

  std::atomic<std::size_t> evaluated_gates = 0;

  ConfigurationPtr config_;
  LoggerPtr logger_;

  std::queue<std::size_t> active_gates_;
  std::mutex active_queue_mutex_;

  std::vector<Gates::GatePtr> input_gates_;
  std::vector<Gates::GatePtr> gates_;

  std::vector<Wires::WirePtr> wires_;

  std::vector<std::weak_ptr<Communication::Handler>> communication_handlers_;
};

using RegisterPtr = std::shared_ptr<Register>;
}  // namespace ABYN
