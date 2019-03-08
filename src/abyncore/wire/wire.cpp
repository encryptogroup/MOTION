#include "wire.h"

#include "gate/gate.h"

namespace ABYN::Wires {
  void Wire::UnregisterWireIdFromGate(size_t gate_id, size_t wire_id, ABYNCorePtr &core) {
    core->GetGate(gate_id)->UnregisterWaitingFor(wire_id);
  }
}