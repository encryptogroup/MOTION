#include "wire.h"

#include "fmt/format.h"

#include "base/backend.h"
#include "base/register.h"
#include "gate/gate.h"
#include "utility/condition.h"

namespace ABYN::Wires {

std::size_t Wire::GetNumOfParallelValues() const { return num_of_parallel_values_; }

Wire::Wire() {
  is_done_condition_ = std::make_shared<ENCRYPTO::Condition>([this]() { return IsReady(); });
}

Wire::~Wire() { assert(wire_id_ >= 0); }

void Wire::RegisterWaitingGate(std::size_t gate_id) {
  std::scoped_lock lock(mutex_);
  waiting_gate_ids_.insert(gate_id);
}

void Wire::SetOnlineFinished() {
  assert(wire_id_ >= 0);
  if (is_done_) {
    throw(std::runtime_error(
        fmt::format("Marking wire #{} as \"online phase ready\" twice", wire_id_)));
  }
  {
    std::scoped_lock lock(is_done_condition_->GetMutex());
    is_done_ = true;
  }
  is_done_condition_->NotifyAll();

  for (auto gate_id : waiting_gate_ids_) {
    Wire::SignalReadyToDependency(gate_id, backend_);
  }
}

const bool &Wire::IsReady() const noexcept {
  if (is_constant_) {
    return is_constant_;
  } else {
    return is_done_;
  }
}

std::string Wire::PrintIds(const std::vector<std::shared_ptr<Wires::Wire>> &wires) {
  std::string result;
  for (auto &w : wires) {
    result.append(fmt::format("{} ", w->GetWireId()));
  }
  result.erase(result.end() - 1);
  return std::move(result);
}

void Wire::SignalReadyToDependency(std::size_t gate_id, std::weak_ptr<Backend> backend) {
  auto ptr_backend = backend.lock();
  assert(ptr_backend);
  auto gate = ptr_backend->GetGate(gate_id);
  assert(gate != nullptr);
  gate->SignalDependencyIsReady();
}

void Wire::InitializationHelper() {
  auto ptr_backend = backend_.lock();
  assert(ptr_backend);
  wire_id_ = ptr_backend->GetRegister()->NextWireId();
}

}