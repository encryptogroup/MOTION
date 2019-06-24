#pragma once

#include "flatbuffers/flatbuffers.h"

namespace ABYN::Communication {
flatbuffers::FlatBufferBuilder BuildOutputMessage(std::size_t gate_id,
                                                  std::vector<std::uint8_t> wire_payload);
flatbuffers::FlatBufferBuilder BuildOutputMessage(
    std::size_t gate_id, std::vector<std::vector<std::uint8_t>> wire_payload);
}  // namespace ABYN::Communication
