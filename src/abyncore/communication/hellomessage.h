#ifndef HELLOMESSAGE_H
#define HELLOMESSAGE_H

#include "hello_message_generated.h"
#include "utility/typedefs.h"

namespace ABYN::Communication {
  static flatbuffers::FlatBufferBuilder BuildHelloMessage(uint64_t source_id = 0,
                                                          uint64_t destination_id = 0,
                                                          float ABYN_version = 0.0f,
                                                          uint64_t num_of_parties = 0,
                                                          const std::vector<uint8_t> *input_sharing_seed = nullptr,
                                                          bool online_after_setup = false) {
    flatbuffers::FlatBufferBuilder builder(1024);
    CreateHelloMessageDirect(builder,
                             source_id,
                             destination_id,
                             ABYN_version,
                             num_of_parties,
                             input_sharing_seed,
                             online_after_setup);
    return std::move(builder);
  }
}

#endif //HELLOMESSAGE_H
