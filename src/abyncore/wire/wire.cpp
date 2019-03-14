#include "wire.h"

#include "gate/gate.h"

namespace ABYN::Wires {
  void Wire::UnregisterWireIdFromGate(size_t gate_id, size_t wire_id, CorePtr &core) {
    auto gate = core->GetGate(gate_id);
    assert(gate != nullptr);
    gate->UnregisterWaitingFor(wire_id);
  }
}