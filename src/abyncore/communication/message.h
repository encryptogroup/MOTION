#pragma once

#include "flatbuffers/flatbuffers.h"

#include "fbs_headers/message_generated.h"

namespace ABYN::Communication {
flatbuffers::FlatBufferBuilder BuildMessage(MessageType message_type,
                                                   const std::vector<uint8_t> *payload);
flatbuffers::FlatBufferBuilder BuildMessage(MessageType message_type, const uint8_t *payload,
                                                   std::size_t size);
}  // namespace ABYN::Communication
