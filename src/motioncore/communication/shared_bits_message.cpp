// MIT License
//
// Copyright (c) 2019 Lennart Braun
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

#include "shared_bits_message.h"
#include <flatbuffers/flatbuffers.h>
#include "fbs_headers/message_generated.h"
#include "fbs_headers/shared_bits_message_generated.h"
#include "message.h"

namespace encrypto::motion::communication {

flatbuffers::FlatBufferBuilder BuildSharedBitsMaskMessage(const std::vector<std::uint8_t>& buffer) {
  flatbuffers::FlatBufferBuilder builder(buffer.size());
  auto root = CreateSharedBitsMessageDirect(builder, &buffer);
  FinishSharedBitsMessageBuffer(builder, root);
  return BuildMessage(MessageType::kSharedBitsMask, builder.GetBufferPointer(), builder.GetSize());
}

flatbuffers::FlatBufferBuilder BuildSharedBitsReconstructMessage(
    const std::vector<std::uint8_t>& buffer) {
  flatbuffers::FlatBufferBuilder builder(buffer.size());
  auto root = CreateSharedBitsMessageDirect(builder, &buffer);
  FinishSharedBitsMessageBuffer(builder, root);
  return BuildMessage(MessageType::kSharedBitsReconstruct, builder.GetBufferPointer(),
                      builder.GetSize());
}

}  // namespace encrypto::motion::communication
