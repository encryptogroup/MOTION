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

namespace MOTION::Shares {

MPCProtocol ConstantBooleanShare::GetProtocol() const noexcept {
  if constexpr (MOTION_DEBUG) {
    for ([[maybe_unused]] const auto &wire : wires_)
      assert(wire->GetProtocol() == MPCProtocol::BooleanConstant);
  }
  return MPCProtocol::BooleanConstant;
}

CircuitType ConstantBooleanShare::GetCircuitType() const noexcept {
  if constexpr (MOTION_DEBUG) {
    for ([[maybe_unused]] const auto &wire : wires_)
      assert(wire->GetCircuitType() == CircuitType::Boolean);
  }
  return CircuitType::Boolean;
}

ConstantBooleanShare::ConstantBooleanShare(const std::vector<MOTION::Wires::WirePtr> &wires)
    : BooleanShare(wires.at(0)->GetBackend()) {
  if (wires.size() == 0) {
    throw(std::runtime_error("Trying to create a constant Boolean share without wires"));
  }
  for (auto &wire : wires) {
    if (wire->GetProtocol() != MPCProtocol::BooleanConstant) {
      throw(
          std::runtime_error("Trying to create a constant Boolean share from wires "
                             "of different sharing type"));
    }
  }

  wires_ = wires;
  if constexpr (MOTION_DEBUG) {
    assert(wires_.size() > 0);
    const auto const_bool_wire =
        std::dynamic_pointer_cast<const Wires::ConstantBooleanWire>(wires_.at(0));
    assert(const_bool_wire);

    // maybe_unused due to assert which is optimized away in Release
    [[maybe_unused]] const auto num_simd = const_bool_wire->GetNumOfSIMDValues();

    // check that all wires have same simd width
    for (auto i = 1ull; i < wires_.size(); ++i) {
      const auto const_bool_wire_next =
          std::dynamic_pointer_cast<const Wires::ConstantBooleanWire>(wires_.at(i));
      assert(const_bool_wire_next);
      assert(num_simd == const_bool_wire_next->GetNumOfSIMDValues());
    }
  }
  bits_ = wires.at(0)->GetBitLength();
}

ConstantBooleanShare::ConstantBooleanShare(std::vector<MOTION::Wires::WirePtr> &&wires)
    : ConstantBooleanShare(wires) {}

std::size_t ConstantBooleanShare::GetNumOfSIMDValues() const noexcept {
  const auto const_bool_wire =
      std::dynamic_pointer_cast<const Wires::ConstantBooleanWire>(wires_.at(0));
  assert(const_bool_wire);
  return const_bool_wire->GetNumOfSIMDValues();
}

std::vector<std::shared_ptr<Share>> ConstantBooleanShare::Split() const noexcept {
  std::vector<SharePtr> v;
  v.reserve(wires_.size());
  for (const auto &w : wires_) {
    const std::vector<Wires::WirePtr> w_v = {std::static_pointer_cast<MOTION::Wires::Wire>(w)};
    v.emplace_back(std::make_shared<ConstantBooleanShare>(w_v));
  }
  return v;
}
}