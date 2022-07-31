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
#include "wire.h"

#include "base/backend.h"
#include "base/register.h"
#include "oblivious_transfer/1_out_of_n/kk13_ot_provider.h"
#include "oblivious_transfer/ot_provider.h"
#include "utility/condition.h"
#include "utility/fiber_condition.h"

namespace encrypto::motion {

void Gate::SetSetupIsReady() {
  {
    std::scoped_lock lock(setup_is_ready_condition_.GetMutex());
    setup_is_ready_ = true;
  }
  setup_is_ready_condition_.NotifyAll();
}

void Gate::SetOnlineIsReady() {
  if (own_output_wires_) {
    for (auto& wire : output_wires_) {
      assert(wire);
      wire->SetOnlineFinished();
    }
  }
  {
    std::scoped_lock lock(online_is_ready_condition_.GetMutex());
    online_is_ready_ = true;
  }
  online_is_ready_condition_.NotifyAll();
}

void Gate::WaitSetup() const { setup_is_ready_condition_.Wait(); }

void Gate::WaitOnline() const { online_is_ready_condition_.Wait(); }

void Gate::Clear() {
  setup_is_ready_ = false;
  online_is_ready_ = false;
}

Gate::Gate(Backend& backend)
    : backend_(backend),
      gate_id_(backend.GetRegister()->NextGateId()),
      setup_is_ready_condition_([this] { return setup_is_ready_.load(); }),
      online_is_ready_condition_([this] { return online_is_ready_.load(); }) {}

communication::CommunicationLayer& Gate::GetCommunicationLayer() {
  return backend_.GetCommunicationLayer();
}

Register& Gate::GetRegister() { return *backend_.GetRegister(); }

Configuration& Gate::GetConfiguration() { return *backend_.GetConfiguration(); }

Logger& Gate::GetLogger() { return *backend_.GetLogger(); }

BaseProvider& Gate::GetBaseProvider() { return backend_.GetBaseProvider(); }

MtProvider& Gate::GetMtProvider() { return backend_.GetMtProvider(); }

SpProvider& Gate::GetSpProvider() { return backend_.GetSpProvider(); }

SbProvider& Gate::GetSbProvider() { return backend_.GetSbProvider(); }

OtProvider& Gate::GetOtProvider(const std::size_t i) { return backend_.GetOtProvider(i); }

proto::garbled_circuit::Provider& Gate::GetGarbledCircuitProvider() {
  return backend_.GetGarbledCircuitProvider();
}

Kk13OtProvider& Gate::GetKk13OtProvider(const std::size_t i) {
  return backend_.GetKk13OtProvider(i);
}

}  // namespace encrypto::motion
