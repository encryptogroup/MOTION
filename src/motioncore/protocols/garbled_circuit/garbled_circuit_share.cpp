// MIT License
//
// Copyright (c) 2021-2022 Oleksandr Tkachenko
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

#include "garbled_circuit_share.h"
#include "garbled_circuit_wire.h"

#include "base/backend.h"

namespace encrypto::motion::proto::garbled_circuit {

MpcProtocol Share::GetProtocol() const noexcept {
  if constexpr (kDebug) {
    for ([[maybe_unused]] const auto& wire : wires_)
      assert(wire->GetProtocol() == MpcProtocol::kGarbledCircuit);
  }
  return MpcProtocol::kGarbledCircuit;
}

CircuitType Share::GetCircuitType() const noexcept {
  if constexpr (kDebug) {
    for ([[maybe_unused]] const auto& wire : wires_)
      assert(wire->GetCircuitType() == CircuitType::kBoolean);
  }
  return CircuitType::kBoolean;
}

Share::Share(std::span<const motion::WirePointer> wires) : BooleanShare(wires[0]->GetBackend()) {
  if constexpr (kDebug) {
    for (auto& wire : wires) {
      if (wire->GetProtocol() != MpcProtocol::kGarbledCircuit) {
        throw std::runtime_error(
            "Trying to create a Garbled Circuit share from wires "
            "of different sharing type");
      }
    }
  }

  wires_.assign(wires.begin(), wires.end());

  if constexpr (kDebug) {
    assert(wires_.size() > 0);
    const auto gmw_wire = std::dynamic_pointer_cast<const garbled_circuit::Wire>(wires_.at(0));
    assert(gmw_wire);

    // maybe_unused due to assert which is optimized away in Release
    [[maybe_unused]] const auto number_of_simd = gmw_wire->GetNumberOfSimdValues();

    // check that all wires have same simd width
    for (std::size_t i = 1; i < wires_.size(); ++i) {
      const auto wire_next = std::dynamic_pointer_cast<const garbled_circuit::Wire>(wires_.at(i));
      assert(wire_next);
      assert(number_of_simd == wire_next->GetNumberOfSimdValues());
    }
  }
}

Share::Share(std::vector<motion::WirePointer>&& wires) : Share(wires) {}

std::size_t Share::GetNumberOfSimdValues() const noexcept {
  const auto gc_wire = std::dynamic_pointer_cast<const garbled_circuit::Wire>(wires_.at(0));
  assert(gc_wire);
  return gc_wire->GetNumberOfSimdValues();
}

std::vector<std::shared_ptr<motion::Share>> Share::Split() const noexcept {
  std::vector<motion::SharePointer> v;
  v.reserve(wires_.size());
  for (const auto& w : wires_) {
    const std::vector<motion::WirePointer> w_v = {std::static_pointer_cast<motion::Wire>(w)};
    v.emplace_back(std::make_shared<Share>(w_v));
  }
  return v;
}

std::shared_ptr<motion::Share> Share::GetWire(std::size_t i) const {
  if (i >= wires_.size()) {
    throw std::out_of_range(
        fmt::format("Trying to access wire #{} out of {} wires", i, wires_.size()));
  }
  std::vector<motion::WirePointer> result = {std::static_pointer_cast<motion::Wire>(wires_[i])};
  return std::make_shared<Share>(result);
}

}  // namespace encrypto::motion::proto::garbled_circuit
