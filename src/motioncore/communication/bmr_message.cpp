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

#include "bmr_message.h"

#include "fbs_headers/bmr_message_generated.h"
#include "utility/constants.h"

#include "message.h"

namespace encrypto::motion::communication {

flatbuffers::FlatBufferBuilder BuildBmrMessage(const std::size_t id,
                                               const std::vector<std::uint8_t>& payload,
                                               const MessageType t) {
  flatbuffers::FlatBufferBuilder builder_bmr_message(64);
  auto output_message_root =
      CreateBmrMessageDirect(builder_bmr_message, static_cast<uint64_t>(id), &payload);
  FinishBmrMessageBuffer(builder_bmr_message, output_message_root);

  return BuildMessage(t, builder_bmr_message.GetBufferPointer(), builder_bmr_message.GetSize());
}

flatbuffers::FlatBufferBuilder BuildBmrInput0Message(const std::size_t id,
                                                     const std::vector<std::uint8_t>& payload) {
  return BuildBmrMessage(id, payload, MessageType::kBmrInputGate0);
}

flatbuffers::FlatBufferBuilder BuildBmrInput0Message(const std::size_t id,
                                                     std::vector<std::uint8_t>&& payload) {
  return BuildBmrMessage(id, std::move(payload), MessageType::kBmrInputGate0);
}

flatbuffers::FlatBufferBuilder BuildBmrInput1Message(const std::size_t id,
                                                     const std::vector<std::uint8_t>& payload) {
  return BuildBmrMessage(id, payload, MessageType::kBmrInputGate1);
}

flatbuffers::FlatBufferBuilder BuildBmrInput1Message(const std::size_t id,
                                                     std::vector<std::uint8_t>&& payload) {
  return BuildBmrMessage(id, std::move(payload), MessageType::kBmrInputGate1);
}

flatbuffers::FlatBufferBuilder BuildBmrAndMessage(const std::size_t id,
                                                  const std::vector<std::uint8_t>& payload) {
  return BuildBmrMessage(id, payload, MessageType::kBmrAndGate);
}

flatbuffers::FlatBufferBuilder BuildBmrAndMessage(const std::size_t id,
                                                  std::vector<std::uint8_t>&& payload) {
  return BuildBmrMessage(id, std::move(payload), MessageType::kBmrAndGate);
}

}  // namespace encrypto::motion::communication
