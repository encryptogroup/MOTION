#include "boolean_gmw_share.h"

#include <cassert>

#include "utility/config.h"
#include "wire/boolean_gmw_wire.h"

namespace ABYN::Shares {

GMWShare::GMWShare(const std::vector<ABYN::Wires::WirePtr> &wires) {
  if (wires.size() == 0) {
    throw(std::runtime_error("Trying to create a Boolean GMW share without wires"));
  }
  for (auto &wire : wires) {
    if (wire->GetProtocol() != ABYN::Protocol::BooleanGMW) {
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
  register_ = wires.at(0)->GetRegister();
  bits_ = wires.at(0)->GetBitLength();
}

std::size_t GMWShare::GetNumOfParallelValues() {
  auto gmw_wire = std::dynamic_pointer_cast<Wires::GMWWire>(wires_.at(0));
  assert(gmw_wire);
  return gmw_wire->GetValuesOnWire().GetSize();
}

}