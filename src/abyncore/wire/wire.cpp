#include "wire.h"

#include "gate/gate.h"

namespace ABYN::Wires {
void Wire::UnregisterWireIdFromGate(std::size_t gate_id, std::size_t wire_id,
                                    std::weak_ptr<ABYN::Register> reg) {
  auto shared_ptr_reg = reg.lock();
  assert(shared_ptr_reg);
  auto gate = shared_ptr_reg->GetGate(gate_id);
  assert(gate != nullptr);
  gate->UnregisterWaitingFor(wire_id);
}
}