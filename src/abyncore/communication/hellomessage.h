#ifndef HELLOMESSAGE_H
#define HELLOMESSAGE_H

#include "message.h"
#include "hello_message_generated.h"
#include "utility/typedefs.h"
#include "utility/constants.h"

namespace ABYN::Communication {
  static flatbuffers::FlatBufferBuilder BuildHelloMessage(uint16_t source_id = 0,
                                                          uint16_t destination_id = 0,
                                                          uint16_t num_of_parties = 0,
                                                          const std::vector<uint8_t> *input_sharing_seed = nullptr,
                                                          bool online_after_setup = false,
                                                          float ABYN_version = ABYN_VERSION) {
    flatbuffers::FlatBufferBuilder builder_hello_message(64);
    CreateHelloMessageDirect(builder_hello_message,
                             source_id,
                             destination_id,
                             num_of_parties,
                             input_sharing_seed,
                             online_after_setup,
                             ABYN_version);

    return std::move(BuildMessage(
        MessageType_HelloMessage, builder_hello_message.GetBufferPointer(), builder_hello_message.GetSize()));
  }
}

#endif //HELLOMESSAGE_H
