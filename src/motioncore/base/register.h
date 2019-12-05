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

#pragma once

#include <utility/condition.h>
#include <atomic>
#include <memory>
#include <mutex>
#include <queue>

#include <flatbuffers/flatbuffers.h>

namespace ENCRYPTO {
struct AlgorithmDescription;
}

namespace MOTION {

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

  void Send(std::size_t party_id, flatbuffers::FlatBufferBuilder &&message);

  void RegisterNextGate(Gates::GatePtr gate);

  void RegisterNextInputGate(Gates::GatePtr gate);

  const Gates::GatePtr &GetGate(std::size_t gate_id) const {
    return gates_.at(gate_id - gate_id_offset_);
  }

  const auto &GetInputGates() const { return input_gates_; }

  auto &GetGates() const { return gates_; }

  void UnregisterGate(std::size_t gate_id) { gates_.at(gate_id) = nullptr; }

  void RegisterNextWire(Wires::WirePtr wire) { wires_.push_back(wire); }

  Wires::WirePtr GetWire(std::size_t wire_id) const { return wires_.at(wire_id - wire_id_offset_); }

  void UnregisterWire(std::size_t wire_id) { wires_.at(wire_id) = nullptr; }

  void AddToActiveQueue(std::size_t gate_id);

  void ClearActiveQueue();

  std::int64_t GetNextGateFromActiveQueue();

  void IncrementEvaluatedGateSetupsCounter();

  void IncrementEvaluatedGatesCounter();

  std::size_t GetNumOfEvaluatedGateSetups() const { return evaluated_gate_setups_; }

  std::size_t GetNumOfEvaluatedGates() const { return evaluated_gates_; }

  std::size_t GetTotalNumOfGates() const { return global_gate_id_ - gate_id_offset_; }

  void Reset();

  void Clear();

  std::shared_ptr<ENCRYPTO::Condition> GetGatesSetupDoneCondition() {
    return gates_setup_done_condition_;
  };

  std::shared_ptr<ENCRYPTO::Condition> GetGatesOnlineDoneCondition() {
    return gates_online_done_condition_;
  };

  /// \brief Tries to insert an AlgorithmDescription object read from a file into cached_algos_
  /// \param path absolute path to the corresponding file
  /// \param algo_description AlgorithmDescription object corresponding to the parsed file
  /// \returns true if the insertion was successful and false if the object is already in the cache
  bool AddCachedAlgorithmDescription(
      std::string path, const std::shared_ptr<ENCRYPTO::AlgorithmDescription> &algo_description);

  /// \brief Gets cached AlgorithmDescription object read from a file and placed into cached_algos_
  /// \return shared_ptr to the algorithm description or to nullptr if not in the hash table
  std::shared_ptr<ENCRYPTO::AlgorithmDescription> GetCachedAlgorithmDescription(
      const std::string &path);

 private:
  // don't need atomic here, since only the master thread has access to these
  std::size_t global_gate_id_ = 0, global_wire_id_ = 0;
  std::size_t global_arithmetic_gmw_sharing_id_ = 0, global_boolean_gmw_sharing_id_ = 0;
  std::size_t gate_id_offset_ = 0, wire_id_offset_ = 0;

  std::atomic<std::size_t> evaluated_gates_ = 0;
  std::atomic<std::size_t> evaluated_gate_setups_ = 0;
  // flags which should be changed to true as soon as the counters above reach
  // gates_.size(); need to be protected using the mutexes from the conditions below
  bool gates_setup_done_flag_ = false;
  bool gates_online_done_flag_ = false;
  // conditions which enable waiting for the above flags to change to true
  std::shared_ptr<ENCRYPTO::Condition> gates_setup_done_condition_;
  std::shared_ptr<ENCRYPTO::Condition> gates_online_done_condition_;

  ConfigurationPtr config_;
  LoggerPtr logger_;

  std::queue<std::size_t> active_gates_;
  std::mutex active_queue_mutex_;

  std::vector<Gates::GatePtr> input_gates_;
  std::vector<Gates::GatePtr> gates_;

  std::vector<Wires::WirePtr> wires_;

  std::vector<std::weak_ptr<Communication::Handler>> communication_handlers_;
  std::mutex comm_handler_mutex_;

  std::unordered_map<std::string, std::shared_ptr<ENCRYPTO::AlgorithmDescription>> cached_algos_;
  std::mutex cached_algos_mutex_;
};

using RegisterPtr = std::shared_ptr<Register>;
}  // namespace MOTION
