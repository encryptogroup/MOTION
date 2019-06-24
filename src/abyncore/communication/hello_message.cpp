#include "hello_message.h"

#include "fbs_headers/hello_message_generated.h"
#include "message.h"
#include "utility/typedefs.h"

namespace ABYN::Communication {
flatbuffers::FlatBufferBuilder BuildHelloMessage(uint16_t source_id, uint16_t destination_id,
                                                 uint16_t num_of_parties,
                                                 const std::vector<uint8_t> *input_sharing_seed,
                                                 bool online_after_setup, float ABYN_version) {
  flatbuffers::FlatBufferBuilder builder_hello_message(256);
  auto hello_message_root =
      CreateHelloMessageDirect(builder_hello_message, source_id, destination_id, num_of_parties,
                               input_sharing_seed, online_after_setup, ABYN_version);
  FinishHelloMessageBuffer(builder_hello_message, hello_message_root);

  return std::move(BuildMessage(MessageType_HelloMessage, builder_hello_message.GetBufferPointer(),
                                builder_hello_message.GetSize()));
}
}