#pragma once

#include "flatbuffers/flatbuffers.h"
#include "utility/constants.h"

namespace ABYN::Communication {
flatbuffers::FlatBufferBuilder BuildHelloMessage(
    uint16_t source_id = 0, uint16_t destination_id = 0, uint16_t num_of_parties = 0,
    const std::vector<uint8_t> *input_sharing_seed = nullptr, bool online_after_setup = false,
    float ABYN_version = ABYN_VERSION);
}  // namespace ABYN::Communication
