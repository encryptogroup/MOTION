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

#include "register.h"

#include <iostream>

#include "fmt/format.h"

#include "communication/handler.h"
#include "configuration.h"
#include "gate/gate.h"
#include "utility/condition.h"
#include "utility/logger.h"
#include "wire/wire.h"

namespace MOTION {

Register::Register(ConfigurationPtr &config) : config_(config) {
  logger_ =
      std::make_shared<MOTION::Logger>(config_->GetMyId(), config_->GetLoggingSeverityLevel());
  logger_->SetEnabled(config_->GetLoggingEnabled());

  evaluated_gates_condition_ =
      std::make_shared<ENCRYPTO::Condition>([this]() { return evaluated_gates_ == gates_.size(); });
}

Register::~Register() {
  input_gates_.clear();
  gates_.clear();
  wires_.clear();
}

std::size_t Register::NextGateId() noexcept { return global_gate_id_++; }

std::size_t Register::NextWireId() noexcept { return global_wire_id_++; }

std::size_t Register::NextArithmeticSharingId(std::size_t num_of_parallel_values) {
  assert(num_of_parallel_values != 0);
  auto old_id = global_arithmetic_gmw_sharing_id_;
  global_arithmetic_gmw_sharing_id_ += num_of_parallel_values;
  return old_id;
}

std::size_t Register::NextBooleanGMWSharingId(std::size_t num_of_parallel_values) {
  assert(num_of_parallel_values != 0);
  auto old_id = global_boolean_gmw_sharing_id_;
  global_boolean_gmw_sharing_id_ += num_of_parallel_values;
  return old_id;
}

const LoggerPtr &Register::GetLogger() const noexcept { return logger_; }

const ConfigurationPtr &Register::GetConfig() const noexcept { return config_; }

void Register::RegisterCommunicationHandlers(
    std::vector<MOTION::Communication::HandlerPtr> &communication_handlers) {
  for (auto i = 0ull; i < communication_handlers.size(); ++i) {
    communication_handlers_.push_back(communication_handlers.at(i));
  }
}

void Register::Send(std::size_t party_id, flatbuffers::FlatBufferBuilder &&message) {
  if (party_id == config_->GetMyId()) {
    throw(std::runtime_error("Trying to send message to myself"));
  }
  std::scoped_lock lock(comm_handler_mutex_);
  if (auto shared_ptr_comm_handler = communication_handlers_.at(party_id).lock()) {
    shared_ptr_comm_handler->SendMessage(std::move(message));
  } else {
    throw(std::runtime_error("Trying to use a destroyed communication handler"));
  }
}

void Register::RegisterNextGate(MOTION::Gates::GatePtr gate) {
  assert(gate != nullptr);
  gates_.push_back(gate);
}

void Register::RegisterNextInputGate(MOTION::Gates::GatePtr gate) {
  RegisterNextGate(gate);
  assert(gate != nullptr);
  input_gates_.push_back(gate);
}

void Register::AddToActiveQueue(std::size_t gate_id) {
  std::scoped_lock lock(active_queue_mutex_);
  active_gates_.push(gate_id);
  logger_->LogTrace(fmt::format("Added gate #{} to the active queue", gate_id));
  // std::cerr << fmt::format("Party#{} added gate #{} to the active queue\n", config_->GetMyId(),
  //                        gate_id);
}

std::int64_t Register::GetNextGateFromActiveQueue() {
  std::scoped_lock lock(active_queue_mutex_);
  if (active_gates_.empty()) {
    return -1;
  } else {
    const auto gate_id = active_gates_.front();
    assert(gate_id < static_cast<std::size_t>(std::numeric_limits<std::int64_t>::max()));
    active_gates_.pop();
    return static_cast<std::int64_t>(gate_id);
  }
}

void Register::IncrementEvaluatedGatesCounter() {
  {
    std::scoped_lock lock(evaluated_gates_condition_->GetMutex());
    ++evaluated_gates_;
  }
  evaluated_gates_condition_->NotifyAll();
}

void Register::Reset() {
  if (evaluated_gates_ != gates_.size()) {
    throw(std::runtime_error("Register::Reset evaluated_gates_ != gates_.size()"));
  }

  assert(active_gates_.empty());
  assert(evaluated_gates_ == gates_.size());
  if (!gates_.empty()) {
    gate_id_offset_ = global_gate_id_;
  }

  if (!wires_.empty()) {
    wire_id_offset_ = global_wire_id_;
  }

  wires_.clear();
  gates_.clear();
  input_gates_.clear();

  {
    std::scoped_lock(evaluated_gates_condition_->GetMutex());
    evaluated_gates_ = 0;
  }

  for (auto i = 0ull; i < communication_handlers_.size(); ++i) {
    if (GetConfig()->GetMyId() == i) {
      continue;
    }
    auto handler_ptr = communication_handlers_.at(i).lock();
    assert(handler_ptr);
    handler_ptr->Reset();
  }
}

void Register::Clear() {
  if (evaluated_gates_ != gates_.size()) {
    throw(std::runtime_error("Register::Reset evaluated_gates_ != gates_.size()"));
  }
  assert(active_gates_.empty());
  assert(evaluated_gates_ == gates_.size());
  for (auto &gate : gates_) {
    gate->Clear();
  }

  for (auto &wire : wires_) {
    wire->Clear();
  }

  {
    std::scoped_lock(evaluated_gates_condition_->GetMutex());
    evaluated_gates_ = 0;
  }

  for (auto i = 0ull; i < communication_handlers_.size(); ++i) {
    if (GetConfig()->GetMyId() == i) {
      continue;
    }
    auto handler_ptr = communication_handlers_.at(i).lock();
    assert(handler_ptr);
    handler_ptr->Clear();
  }
}

bool Register::AddCachedAlgorithmDescription(
    std::string path, const std::shared_ptr<ENCRYPTO::AlgorithmDescription> &algo_description) {
  std::scoped_lock lock(cached_algos_mutex_);
  const auto [it, success] = cached_algos_.try_emplace(path, algo_description);
  return success;
}

std::shared_ptr<ENCRYPTO::AlgorithmDescription> Register::GetCachedAlgorithmDescription(
    const std::string &path) {
  std::scoped_lock lock(cached_algos_mutex_);
  const auto it = cached_algos_.find(path);
  if (it == cached_algos_.end()) {
    return nullptr;
  } else {
    return it->second;
  }
}

}  // namespace MOTION
