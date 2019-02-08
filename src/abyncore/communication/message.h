#ifndef MESSAGE_H
#define MESSAGE_H

#include "message_generated.h"
#include "utility/typedefs.h"

namespace ABYN::Communication {
  static flatbuffers::FlatBufferBuilder BuildMessage(MessageType message_type,
                                                     const std::vector<uint8_t> *payload) {
    auto allocation_size = payload ? payload->size() + 20 : 1024;
    flatbuffers::FlatBufferBuilder builder(allocation_size);
    CreateMessageDirect(builder, message_type, payload);
    return std::move(builder);
  }

  static flatbuffers::FlatBufferBuilder BuildMessage(MessageType message_type,
                                                     const uint8_t *payload,
                                                     size_t size) {
      auto allocation_size = size + 20;
      flatbuffers::FlatBufferBuilder builder(allocation_size);
      std::vector<u8> payload_vector(payload, payload + size);
      CreateMessageDirect(builder, message_type, &payload_vector);
      return std::move(builder);
  }
}

#endif //MESSAGE_H
