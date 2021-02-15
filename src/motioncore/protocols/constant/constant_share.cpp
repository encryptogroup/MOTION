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

#include "constant_share.h"

namespace encrypto::motion::proto {

MpcProtocol ConstantBooleanShare::GetProtocol() const noexcept {
  if constexpr (kDebug) {
    for ([[maybe_unused]] const auto& wire : wires_)
      assert(wire->GetProtocol() == MpcProtocol::kBooleanConstant);
  }
  return MpcProtocol::kBooleanConstant;
}

CircuitType ConstantBooleanShare::GetCircuitType() const noexcept {
  if constexpr (kDebug) {
    for ([[maybe_unused]] const auto& wire : wires_)
      assert(wire->GetCircuitType() == CircuitType::kBoolean);
  }
  return CircuitType::kBoolean;
}

ConstantBooleanShare::ConstantBooleanShare(const std::vector<WirePointer>& wires)
    : BooleanShare(wires.at(0)->GetBackend()) {
  if (wires.size() == 0) {
    throw(std::runtime_error("Trying to create a constant Boolean share without wires"));
  }
  for (auto& wire : wires) {
    if (wire->GetProtocol() != MpcProtocol::kBooleanConstant) {
      throw(
          std::runtime_error("Trying to create a constant Boolean share from wires "
                             "of different sharing type"));
    }
  }

  wires_ = wires;
  if constexpr (kDebug) {
    assert(wires_.size() > 0);
    const auto constant_boolean_wire =
        std::dynamic_pointer_cast<const ConstantBooleanWire>(wires_.at(0));
    assert(constant_boolean_wire);

    // maybe_unused due to assert which is optimized away in Release
    [[maybe_unused]] const auto number_of_simd = constant_boolean_wire->GetNumberOfSimdValues();

    // check that all wires have same simd width
    for (auto i = 1ull; i < wires_.size(); ++i) {
      const auto constant_boolean_wire_next =
          std::dynamic_pointer_cast<const ConstantBooleanWire>(wires_.at(i));
      assert(constant_boolean_wire_next);
      assert(number_of_simd == constant_boolean_wire_next->GetNumberOfSimdValues());
    }
  }
}

ConstantBooleanShare::ConstantBooleanShare(std::vector<WirePointer>&& wires)
    : ConstantBooleanShare(wires) {}

std::size_t ConstantBooleanShare::GetNumberOfSimdValues() const noexcept {
  const auto constant_boolean_wire =
      std::dynamic_pointer_cast<const ConstantBooleanWire>(wires_.at(0));
  assert(constant_boolean_wire);
  return constant_boolean_wire->GetNumberOfSimdValues();
}

std::vector<std::shared_ptr<Share>> ConstantBooleanShare::Split() const noexcept {
  std::vector<SharePointer> v;
  v.reserve(wires_.size());
  for (const auto& w : wires_) {
    const std::vector<WirePointer> w_v = {std::static_pointer_cast<Wire>(w)};
    v.emplace_back(std::make_shared<ConstantBooleanShare>(w_v));
  }
  return v;
}

std::shared_ptr<motion::Share> ConstantBooleanShare::GetWire(std::size_t i) const {
  if (i >= wires_.size()) {
    throw std::out_of_range(
        fmt::format("Trying to access wire #{} out of {} wires", i, wires_.size()));
  }
  std::vector<motion::WirePointer> result = {std::static_pointer_cast<motion::Wire>(wires_[i])};
  return std::make_shared<ConstantBooleanShare>(result);
}

}  // namespace encrypto::motion::proto
