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

#include "wire.h"
#include "gate.h"

#include <fmt/format.h>

#include "base/backend.h"
#include "base/register.h"
#include "utility/fiber_condition.h"

namespace encrypto::motion {

std::size_t Wire::GetNumberOfSimdValues() const { return number_of_simd_; }

Wire::Wire(Backend& backend, std::size_t number_of_simd)
    : backend_(backend),
      number_of_simd_(number_of_simd),
      is_done_condition_([this]() { return IsReady().load(); }) {
  InitializationHelper();
}

Wire::~Wire() { assert(wire_id_ >= 0); }

void Wire::SetOnlineFinished() {
  assert(wire_id_ >= 0);
  {
    std::scoped_lock lock(is_done_condition_.GetMutex());
    if (is_done_) {
      throw(std::runtime_error(
          fmt::format("Marking wire #{} as \"online phase ready\" twice", wire_id_)));
    }
    is_done_ = true;
  }
  is_done_condition_.NotifyAll();
}

const std::atomic<bool>& Wire::IsReady() const noexcept { return is_done_; }

std::string Wire::PrintIds(const std::vector<std::shared_ptr<Wire>>& wires) {
  std::string result;
  for (auto& w : wires) {
    result.append(fmt::format("{} ", w->GetWireId()));
  }
  result.erase(result.end() - 1);
  return result;
}

void Wire::InitializationHelper() { wire_id_ = backend_.GetRegister()->NextWireId(); }

}  // namespace encrypto::motion
