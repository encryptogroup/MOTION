#include "output_message.h"

#include "fbs_headers/output_message_generated.h"
#include "utility/constants.h"
#include "utility/typedefs.h"

#include "message.h"

namespace ABYN::Communication {
flatbuffers::FlatBufferBuilder BuildOutputMessage(std::size_t gate_id,
                                                  std::vector<std::uint8_t> wire_payload) {
  flatbuffers::FlatBufferBuilder builder_output_message(64);
  auto wire = CreateOutputWireDirect(builder_output_message, &wire_payload);
  std::vector<flatbuffers::Offset<OutputWire>> wires{wire};

  auto output_message_root =
      CreateOutputMessageDirect(builder_output_message, static_cast<uint64_t>(gate_id), &wires);
  FinishOutputMessageBuffer(builder_output_message, output_message_root);

  return std::move(BuildMessage(MessageType_OutputMessage,
                                builder_output_message.GetBufferPointer(),
                                builder_output_message.GetSize()));
}

flatbuffers::FlatBufferBuilder BuildOutputMessage(
    std::size_t gate_id, std::vector<std::vector<std::uint8_t>> wire_payload) {
  flatbuffers::FlatBufferBuilder builder_output_message(64);
  std::vector<flatbuffers::Offset<OutputWire>> wires;
  for (auto i = 0ull; i < wire_payload.size(); ++i) {
    wires.push_back(CreateOutputWireDirect(builder_output_message, &wire_payload.at(i)));
  }
  auto output_message_root =
      CreateOutputMessageDirect(builder_output_message, static_cast<uint64_t>(gate_id), &wires);
  FinishOutputMessageBuffer(builder_output_message, output_message_root);

  return std::move(BuildMessage(MessageType_OutputMessage,
                                builder_output_message.GetBufferPointer(),
                                builder_output_message.GetSize()));
}
}  // namespace ABYN::Communication
