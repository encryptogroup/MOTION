// MIT License
//
// Copyright (c) 2019-2022 Oleksandr Tkachenko, Lennart Braun, Arianne Roselina Prananto
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
#include <queue>
#include <unordered_map>

namespace encrypto::motion {

struct AlgorithmDescription;
class Backend;
class FiberCondition;
class Gate;
using GatePointer = std::shared_ptr<Gate>;
class Wire;
using WirePointer = std::shared_ptr<Wire>;

// >> forward declarations

class Logger;

// forward declarations <<

class Register {
 public:
  Register(std::shared_ptr<Logger> logger);

  ~Register();

  std::shared_ptr<Logger> GetLogger() { return logger_; }

  std::size_t NextGateId() noexcept;

  std::size_t NextWireId() noexcept;

  std::size_t NextArithmeticSharingId(std::size_t number_of_parallel_values);

  std::size_t NextBooleanGmwSharingId(std::size_t number_of_parallel_values);

  template <typename T, typename... Args>
  std::shared_ptr<T> EmplaceGate(Args&&... args) {
    auto gate = std::make_shared<T>(std::forward<Args&&>(args)...);
    RegisterGate(gate);
    return gate;
  }

  void RegisterGate(const GatePointer& gate);

  template <typename T, typename... Args>
  std::shared_ptr<T> EmplaceWire(Args&&... args) {
    auto wire = std::make_shared<T>(std::forward<Args&&>(args)...);
    RegisterWire(wire);
    return wire;
  }

  void RegisterWire(const WirePointer& wire) { wires_.push_back(wire); }

  const GatePointer& GetGate(std::size_t gate_id) const {
    return gates_.at(gate_id - gate_id_offset_);
  }

  auto& GetGates() const { return gates_; }

  WirePointer GetWire(std::size_t wire_id) const { return wires_.at(wire_id - wire_id_offset_); }

  void IncrementEvaluatedGatesSetupCounter();

  void IncrementEvaluatedGatesOnlineCounter();

  void CheckSetupCondition();

  void CheckOnlineCondition();

  std::size_t GetNumberOfGatesSetup() const { return gates_setup_; }

  std::size_t GetNumberOfGatesOnline() const { return gates_online_; }

  std::size_t GetNumberOfEvaluatedGatesSetup() const { return evaluated_gates_setup_; }

  std::size_t GetNumberOfEvaluatedGatesOnline() const { return evaluated_gates_online_; }

  std::size_t GetTotalNumberOfGates() const { return global_gate_id_ - gate_id_offset_; }
  
  std::size_t GetGateIdOffset() const { return gate_id_offset_; }

  void Reset();

  void Clear();

  std::shared_ptr<FiberCondition> GetGatesSetupDoneCondition() {
    return gates_setup_done_condition_;
  };

  std::shared_ptr<FiberCondition> GetGatesOnlineDoneCondition() {
    return gates_online_done_condition_;
  };

  /// \brief Tries to insert an AlgorithmDescription object read from a file into cached_algos_
  /// \param path absolute path to the corresponding file
  /// \param algorithm_description AlgorithmDescription object corresponding to the parsed file
  /// \returns true if the insertion was successful and false if the object is already in the cache
  bool AddCachedAlgorithmDescription(
      std::string path, const std::shared_ptr<AlgorithmDescription>& algorithm_description);

  /// \brief Gets cached AlgorithmDescription object read from a file and placed into cached_algos_
  /// \return shared_ptr to the algorithm description or to nullptr if not in the hash table
  std::shared_ptr<AlgorithmDescription> GetCachedAlgorithmDescription(const std::string& path);

 private:
  std::shared_ptr<Logger> logger_;

  // don't need atomic here, since only the master thread has access to these
  std::size_t global_gate_id_ = 0, global_wire_id_ = 0;
  std::size_t global_arithmetic_gmw_sharing_id_ = 0, global_boolean_gmw_sharing_id_ = 0;
  std::size_t gate_id_offset_ = 0, wire_id_offset_ = 0;

  std::atomic<std::size_t> gates_setup_ = 0;
  std::atomic<std::size_t> gates_online_ = 0;

  std::atomic<std::size_t> evaluated_gates_setup_ = 0;
  std::atomic<std::size_t> evaluated_gates_online_ = 0;
  // flags which should be changed to true as soon as the counters above reach
  // gates_.size(); need to be protected using the mutexes from the conditions below
  bool gates_setup_done_flag_ = false;
  bool gates_online_done_flag_ = false;
  // conditions which enable waiting for the above flags to change to true
  std::shared_ptr<FiberCondition> gates_setup_done_condition_;
  std::shared_ptr<FiberCondition> gates_online_done_condition_;

  std::vector<GatePointer> gates_;

  std::vector<WirePointer> wires_;

  std::unordered_map<std::string, std::shared_ptr<AlgorithmDescription>> cached_algos_;
  std::mutex cached_algos_mutex_;
};

using RegisterPointer = std::shared_ptr<Register>;

}  // namespace encrypto::motion
