#include "wire.h"

#include "fmt/format.h"

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
  auto shared_ptr_reg = register_.lock();
  assert(shared_ptr_reg);
  for (auto gate_id : waiting_gate_ids_) {
    Wire::UnregisterWireIdFromGate(gate_id, static_cast<std::size_t>(wire_id_), shared_ptr_reg);
  }
  waiting_gate_ids_.clear();
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

void Wire::UnregisterWireIdFromGate(std::size_t gate_id, std::size_t wire_id,
                                    std::weak_ptr<ABYN::Register> reg) {
  auto shared_ptr_reg = reg.lock();
  assert(shared_ptr_reg);
  auto gate = shared_ptr_reg->GetGate(gate_id);
  assert(gate != nullptr);
  gate->UnregisterWaitingFor(wire_id);
}

void Wire::InitializationHelper() {
  auto shared_ptr_reg = register_.lock();
  assert(shared_ptr_reg);
  wire_id_ = shared_ptr_reg->NextWireId();
}

}