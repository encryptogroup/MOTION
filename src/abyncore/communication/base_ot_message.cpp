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

#include "message.h"

#include "fbs_headers/base_ot_generated.h"
#include "utility/typedefs.h"

namespace ABYN::Communication {
flatbuffers::FlatBufferBuilder BuildBaseROTMessageReceiver(std::uint8_t *buffer, std::size_t size,
                                                           std::size_t ot_id) {
  flatbuffers::FlatBufferBuilder builder(size + 32);
  std::vector<std::uint8_t> v_buffer(buffer, buffer + size);
  auto root = CreateBaseROTMessageDirect(builder, ot_id, &v_buffer);
  FinishBaseROTMessageBuffer(builder, root);
  return BuildMessage(MessageType_BaseROTMessageReceiver, builder.GetBufferPointer(),
                      builder.GetSize());
}

flatbuffers::FlatBufferBuilder BuildBaseROTMessageSender(std::uint8_t *buffer, std::size_t size,
                                                         std::size_t ot_id) {
  flatbuffers::FlatBufferBuilder builder(size + 32);
  std::vector<std::uint8_t> v_buffer(buffer, buffer + size);
  auto root = CreateBaseROTMessageDirect(builder, ot_id, &v_buffer);
  FinishBaseROTMessageBuffer(builder, root);
  return BuildMessage(MessageType_BaseROTMessageSender, builder.GetBufferPointer(),
                      builder.GetSize());
}
}  // namespace ABYN::Communication