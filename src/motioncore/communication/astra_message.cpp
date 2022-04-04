// MIT License
//
// Copyright (c) 2022 Oliver Schick
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

#include "astra_message.h"

#include "fbs_headers/astra_message_generated.h"
#include "utility/constants.h"

#include "message.h"

namespace encrypto::motion::communication {
    
flatbuffers::FlatBufferBuilder BuilAstraMessage(const std::size_t id,
                                               const std::vector<std::uint8_t>& payload,
                                               const MessageType t) {
  flatbuffers::FlatBufferBuilder builder_astra_message(128);
  auto output_message_root =
      CreateAstraMessageDirect(builder_astra_message, id, &payload);
  FinishAstraMessageBuffer(builder_astra_message, output_message_root);

  return BuildMessage(t, builder_astra_message.GetBufferPointer(), builder_astra_message.GetSize());
}

flatbuffers::FlatBufferBuilder BuildAstraInputMessage(const std::size_t id,
                                                      const std::vector<std::uint8_t>& payload) {
  return BuilAstraMessage(id, payload, MessageType::kAstraInputGate);
}

flatbuffers::FlatBufferBuilder BuildAstraOutputMessage(const std::size_t id,
                                                       const std::vector<std::uint8_t>& payload) {
  return BuilAstraMessage(id, payload, MessageType::kAstraOutputGate);
}

flatbuffers::FlatBufferBuilder BuildAstraSetupMultiplyMessage(const std::size_t id,
                                                              const std::vector<std::uint8_t>& payload) {
  return BuilAstraMessage(id, payload, MessageType::kAstraSetupMultiplyGate);                                                               
}

flatbuffers::FlatBufferBuilder BuildAstraOnlineMultiplyMessage(const std::size_t id,
                                                              const std::vector<std::uint8_t>& payload) {
  return BuilAstraMessage(id, payload, MessageType::kAstraOnlineMultiplyGate);     
}

flatbuffers::FlatBufferBuilder BuildAstraSetupDotProductMessage(const std::size_t id,
                                                                const std::vector<std::uint8_t>& payload) {
  return BuilAstraMessage(id, payload, MessageType::kAstraSetupDotProductGate);                                                               
}

flatbuffers::FlatBufferBuilder BuildAstraOnlineDotProductMessage(const std::size_t id,
                                                                 const std::vector<std::uint8_t>& payload) {
  return BuilAstraMessage(id, payload, MessageType::kAstraOnlineDotProductGate);                                                              
}

}  // namespace encrypto::motion::communication