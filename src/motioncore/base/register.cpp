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

#include "register.h"

#include <iostream>

#include <fmt/format.h>

#include "configuration.h"
#include "protocols/gate.h"
#include "protocols/wire.h"
#include "utility/constants.h"
#include "utility/fiber_condition.h"
#include "utility/logger.h"

namespace encrypto::motion {

Register::Register(std::shared_ptr<Logger> logger) : logger_(std::move(logger)) {
  gates_setup_done_condition_ =
      std::make_shared<FiberCondition>([this]() { return gates_setup_done_flag_; });
  gates_online_done_condition_ =
      std::make_shared<FiberCondition>([this]() { return gates_online_done_flag_; });
}

Register::~Register() {
  gates_.clear();
  wires_.clear();
}

std::size_t Register::NextGateId() noexcept {
  // TODO the return value is old global_gate_id, not the increased one. Check if that is intended.
  return global_gate_id_++;
}

std::size_t Register::NextWireId() noexcept {
  // TODO the return value is old global_wire_id, not the increased one. Check if that is intended.
  return global_wire_id_++;
}

std::size_t Register::NextArithmeticSharingId(std::size_t number_of_parallel_values) {
  assert(number_of_parallel_values != 0);
  auto old_id = global_arithmetic_gmw_sharing_id_;
  global_arithmetic_gmw_sharing_id_ += number_of_parallel_values;
  return old_id;
}

std::size_t Register::NextBooleanGmwSharingId(std::size_t number_of_parallel_values) {
  assert(number_of_parallel_values != 0);
  auto old_id = global_boolean_gmw_sharing_id_;
  global_boolean_gmw_sharing_id_ += number_of_parallel_values;
  return old_id;
}

void Register::RegisterGate(const GatePointer& gate) {
  assert(gate != nullptr);
  if (gate->NeedsSetup()) {
    gates_setup_++;
  }
  if (gate->NeedsOnline()) {
    gates_online_++;
  }
  gates_.push_back(gate);
}

void Register::IncrementEvaluatedGatesSetupCounter() {
  ++evaluated_gates_setup_;
  CheckSetupCondition();
}

void Register::IncrementEvaluatedGatesOnlineCounter() {
  ++evaluated_gates_online_;
  CheckOnlineCondition();
}

void Register::CheckSetupCondition() {
  if (evaluated_gates_setup_ == gates_setup_) {
    {
      std::scoped_lock lock(gates_setup_done_condition_->GetMutex());
      gates_setup_done_flag_ = true;
    }
    gates_setup_done_condition_->NotifyAll();
  }
}

void Register::CheckOnlineCondition() {
  if (evaluated_gates_online_ == gates_online_) {
    {
      std::scoped_lock lock(gates_online_done_condition_->GetMutex());
      gates_online_done_flag_ = true;
    }
    gates_online_done_condition_->NotifyAll();
  }
}

void Register::Reset() {
  if (evaluated_gates_setup_ != gates_setup_ || evaluated_gates_online_ != gates_online_) {
    throw(std::runtime_error("Register::Reset evaluated_gates_ != gates_.size()"));
  }

  assert(evaluated_gates_setup_ == gates_setup_);
  assert(evaluated_gates_online_ == gates_online_);
  if (!gates_.empty()) {
    gate_id_offset_ = global_gate_id_;
  }

  if (!wires_.empty()) {
    wire_id_offset_ = global_wire_id_;
  }

  wires_.clear();
  gates_.clear();

  evaluated_gates_setup_ = 0;
  evaluated_gates_online_ = 0;
  gates_setup_done_flag_ = false;
  gates_online_done_flag_ = false;
  
  
}

void Register::Clear() {
  if (evaluated_gates_setup_ != gates_setup_ || evaluated_gates_online_ != gates_online_) {
    throw(std::runtime_error("Register::Reset evaluated_gates_ != gates_.size()"));
  }
  assert(evaluated_gates_setup_ == gates_setup_);
  assert(evaluated_gates_online_ == gates_online_);
  for (auto& gate : gates_) {
    gate->Clear();
  }

  for (auto& wire : wires_) {
    wire->Clear();
  }

  evaluated_gates_setup_ = 0;
  evaluated_gates_online_ = 0;
  gates_setup_done_flag_ = false;
  gates_online_done_flag_ = false;
}

bool Register::AddCachedAlgorithmDescription(
    std::string path, const std::shared_ptr<AlgorithmDescription>& algorithm_description) {
  std::scoped_lock lock(cached_algos_mutex_);
  const auto [iterator, success] = cached_algos_.try_emplace(path, algorithm_description);
  return success;
}

std::shared_ptr<AlgorithmDescription> Register::GetCachedAlgorithmDescription(
    const std::string& path) {
  std::scoped_lock lock(cached_algos_mutex_);
  const auto iterator = cached_algos_.find(path);
  if (iterator == cached_algos_.end()) {
    return nullptr;
  } else {
    return iterator->second;
  }
}

}  // namespace encrypto::motion
