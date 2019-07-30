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

#include <cassert>

#include "utility/config.h"
#include "wire/boolean_gmw_wire.h"

#include "base/backend.h"
#include "gate/boolean_gmw_gate.h"
#include "utility/typedefs.h"

namespace ABYN::Shares {

MPCProtocol GMWShare::GetSharingType() const noexcept { return BooleanGMW; }

GMWShare::GMWShare(const std::vector<ABYN::Wires::WirePtr> &wires) {
  if (wires.size() == 0) {
    throw(std::runtime_error("Trying to create a Boolean GMW share without wires"));
  }
  for (auto &wire : wires) {
    if (wire->GetProtocol() != ABYN::MPCProtocol::BooleanGMW) {
      throw(
          std::runtime_error("Trying to create a Boolean GMW share from wires "
                             "of different sharing type"));
    }
  }

  wires_ = wires;
  if constexpr (ABYN_DEBUG) {
    assert(wires_.size() > 0);
    auto gmw_wire = std::dynamic_pointer_cast<Wires::GMWWire>(wires_.at(0));
    assert(gmw_wire);

    // maybe_unused due to assert which is optimized away in Release
    [[maybe_unused]] auto size = gmw_wire->GetValuesOnWire().GetSize();

    for (auto i = 0ull; i < wires_.size(); ++i) {
      auto gmw_wire_next = std::dynamic_pointer_cast<Wires::GMWWire>(wires_.at(0));
      assert(gmw_wire_next);
      assert(size == gmw_wire_next->GetValuesOnWire().GetSize());
    }
  }
  backend_ = wires.at(0)->GetBackend();
  bits_ = wires.at(0)->GetBitLength();
}

std::size_t GMWShare::GetNumOfParallelValues() const noexcept {
  auto gmw_wire = std::dynamic_pointer_cast<Wires::GMWWire>(wires_.at(0));
  assert(gmw_wire);
  return gmw_wire->GetValuesOnWire().GetSize();
}

}