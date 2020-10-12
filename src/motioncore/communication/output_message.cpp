// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko
// Cryptography and Privacy Engineering Group (ENCRYPTO)
// TU Darmstadt, Germany
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "output_message.h"

#include "fbs_headers/output_message_generated.h"
#include "utility/constants.h"
#include "utility/typedefs.h"

#include "message.h"

namespace encrypto::motion::communication {

flatbuffers::FlatBufferBuilder BuildOutputMessage(std::size_t gate_id,
                                                  std::vector<std::uint8_t> wire_payload) {
  flatbuffers::FlatBufferBuilder builder_output_message(64);
  auto wire = CreateOutputWireDirect(builder_output_message, &wire_payload);
  std::vector<flatbuffers::Offset<OutputWire>> wires{wire};

  auto output_message_root =
      CreateOutputMessageDirect(builder_output_message, static_cast<uint64_t>(gate_id), &wires);
  FinishOutputMessageBuffer(builder_output_message, output_message_root);

  return BuildMessage(MessageType::kOutputMessage, builder_output_message.GetBufferPointer(),
                      builder_output_message.GetSize());
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

  return BuildMessage(MessageType::kOutputMessage, builder_output_message.GetBufferPointer(),
                      builder_output_message.GetSize());
}

}  // namespace encrypto::motion::communication
