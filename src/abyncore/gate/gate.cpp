#include "gate.h"

#include "wire/wire.h"

#include "base/backend.h"
#include "base/register.h"

namespace ABYN::Gates::Interfaces {

void Gate::RegisterWaitingFor(std::size_t wire_id) {
  std::scoped_lock lock(mutex_);
  wire_dependencies_.insert(wire_id);
}

void Gate::SignalDependencyIsReady() {
  num_ready_dependencies++;
  IfReadyAddToProcessingQueue();
}

void Gate::SetOnlineIsReady() {
  online_is_ready_ = true;
  for (auto &wire : output_wires_) {
    assert(wire);
    wire->SetOnlineFinished();
  }
}

void Gate::IfReadyAddToProcessingQueue() {
  if (AreDependenciesReady() && !added_to_active_queue) {
    auto ptr_backend = backend_.lock();
    assert(ptr_backend);
    ptr_backend->GetRegister()->AddToActiveQueue(gate_id_);
    added_to_active_queue = true;
  }
}

void Gate::Clear() {
  setup_is_ready_ = false;
  online_is_ready_ = false;
  added_to_active_queue = false;
  num_ready_dependencies = 0;

  for (auto &wire : output_wires_) {
    wire->Clear();
  }
}

std::shared_ptr<Register> Gate::GetRegister() {
  auto ptr_backend = backend_.lock();
  assert(ptr_backend);
  return ptr_backend->GetRegister();
}

std::shared_ptr<Configuration> Gate::GetConfig() {
  auto ptr_backend = backend_.lock();
  assert(ptr_backend);
  return ptr_backend->GetConfig();
}

std::shared_ptr<Logger> Gate::GetLogger() {
  auto ptr_backend = backend_.lock();
  assert(ptr_backend);
  return ptr_backend->GetLogger();
}

}