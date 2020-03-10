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

#include "gate.h"

#include "base/backend.h"
#include "base/register.h"
#include "crypto/oblivious_transfer/ot_provider.h"
#include "utility/condition.h"
#include "utility/fiber_condition.h"
#include "wire/wire.h"

namespace MOTION::Gates::Interfaces {

void Gate::RegisterWaitingFor(std::size_t wire_id) {
  std::scoped_lock lock(mutex_);
  wire_dependencies_.insert(wire_id);
}

void Gate::SignalDependencyIsReady() {
  num_ready_dependencies_++;
  IfReadyAddToProcessingQueue();
}

void Gate::SetSetupIsReady() {
  {
    std::scoped_lock lock(setup_is_ready_cond_.GetMutex());
    setup_is_ready_ = true;
  }
  setup_is_ready_cond_.NotifyAll();
}

void Gate::SetOnlineIsReady() {
  if(own_output_wires_) {
    for (auto& wire : output_wires_) {
      assert(wire);
      wire->SetOnlineFinished();
    }
  }
  {
    std::scoped_lock lock(online_is_ready_cond_.GetMutex());
    online_is_ready_ = true;
  }
  online_is_ready_cond_.NotifyAll();
}

void Gate::WaitSetup() const { setup_is_ready_cond_.Wait(); }

void Gate::WaitOnline() const { online_is_ready_cond_.Wait(); }

void Gate::IfReadyAddToProcessingQueue() {
  std::scoped_lock lock(mutex_);
  if (AreDependenciesReady() && !added_to_active_queue) {
    GetRegister().AddToActiveQueue(gate_id_);
    added_to_active_queue = true;
  }
}

void Gate::Clear() {
  setup_is_ready_ = false;
  online_is_ready_ = false;
  added_to_active_queue = false;
  num_ready_dependencies_ = 0;
}

Gate::Gate(Backend& backend)
    : backend_(backend),
      setup_is_ready_cond_([this] { return setup_is_ready_.load(); }),
      online_is_ready_cond_([this] { return online_is_ready_.load(); }) {}

Register& Gate::GetRegister() { return *backend_.GetRegister(); }

Configuration& Gate::GetConfig() { return *backend_.GetConfig(); }

Logger& Gate::GetLogger() { return *backend_.GetLogger(); }

MTProvider& Gate::GetMTProvider() { return *backend_.GetMTProvider(); }

SPProvider& Gate::GetSPProvider() { return *backend_.GetSPProvider(); }

SBProvider& Gate::GetSBProvider() { return *backend_.GetSBProvider(); }

ENCRYPTO::ObliviousTransfer::OTProvider& Gate::GetOTProvider(const std::size_t i) {
  return backend_.GetOTProvider(i);
}

}  // namespace MOTION::Gates::Interfaces
