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

#include "boolean_gmw_share.h"
#include "boolean_gmw_wire.h"

#include <cassert>
#include <functional>
#include <memory>
#include <vector>

#include "base/backend.h"
#include "utility/bit_vector.h"
#include "utility/config.h"
#include "utility/typedefs.h"

namespace encrypto::motion::proto::boolean_gmw {

MpcProtocol Share::GetProtocol() const noexcept {
  if constexpr (kDebug) {
    for ([[maybe_unused]] const auto& wire : wires_)
      assert(wire->GetProtocol() == MpcProtocol::kBooleanGmw);
  }
  return MpcProtocol::kBooleanGmw;
}

CircuitType Share::GetCircuitType() const noexcept {
  if constexpr (kDebug) {
    for ([[maybe_unused]] const auto& wire : wires_)
      assert(wire->GetCircuitType() == CircuitType::kBoolean);
  }
  return CircuitType::kBoolean;
}

Share::Share(const std::vector<motion::WirePointer>& wires)
    : BooleanShare(wires.at(0)->GetBackend()) {
  if (wires.size() == 0) {
    throw(std::runtime_error("Trying to create a Boolean GMW share without wires"));
  }
  for (auto& wire : wires) {
    if (wire->GetProtocol() != MpcProtocol::kBooleanGmw) {
      throw(
          std::runtime_error("Trying to create a Boolean GMW share from wires "
                             "of different sharing type"));
    }
  }

  wires_ = wires;
  if constexpr (kDebug) {
    assert(wires_.size() > 0);
    const auto gmw_wire = std::dynamic_pointer_cast<const boolean_gmw::Wire>(wires_.at(0));
    assert(gmw_wire);

    // maybe_unused due to assert which is optimized away in Release
    [[maybe_unused]] const auto number_of_simd = gmw_wire->GetNumberOfSimdValues();

    // check that all wires have same simd width
    for (auto i = 1ull; i < wires_.size(); ++i) {
      const auto gmw_wire_next = std::dynamic_pointer_cast<const boolean_gmw::Wire>(wires_.at(i));
      assert(gmw_wire_next);
      assert(number_of_simd == gmw_wire_next->GetNumberOfSimdValues());
    }
  }
}

Share::Share(std::vector<motion::WirePointer>&& wires) : Share(wires) {}

std::size_t Share::GetNumberOfSimdValues() const noexcept {
  const auto gmw_wire = std::dynamic_pointer_cast<const boolean_gmw::Wire>(wires_.at(0));
  assert(gmw_wire);
  return gmw_wire->GetNumberOfSimdValues();
}

std::vector<std::reference_wrapper<const BitVector<>> > Share::GetValues() const {
  std::vector<std::reference_wrapper<const BitVector<>> > result;
  result.reserve(wires_.size());
  for (const auto& wire : wires_) {
    const auto gmw_wire = std::dynamic_pointer_cast<const boolean_gmw::Wire>(wire);
    assert(gmw_wire);
    result.emplace_back(gmw_wire->GetValues());
  }
  return result;
}

std::vector<std::reference_wrapper<BitVector<>> > Share::GetMutableValues() {
  std::vector<std::reference_wrapper<BitVector<>> > result;
  result.reserve(wires_.size());
  for (auto& wire : wires_) {
    auto gmw_wire = std::dynamic_pointer_cast<boolean_gmw::Wire>(wire);
    assert(gmw_wire);
    result.emplace_back(gmw_wire->GetMutableValues());
  }
  return result;
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

}  // namespace encrypto::motion::proto::boolean_gmw
