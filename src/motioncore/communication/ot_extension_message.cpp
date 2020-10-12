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

#include "fbs_headers/ot_extension_generated.h"

namespace encrypto::motion::communication {

flatbuffers::FlatBufferBuilder BuildOtExtensionMessageSender(const std::byte* buffer,
                                                             const std::size_t size,
                                                             const std::size_t i) {
  flatbuffers::FlatBufferBuilder builder(size + 32);
  std::vector<std::uint8_t> v_buffer(reinterpret_cast<const std::uint8_t*>(buffer),
                                     reinterpret_cast<const std::uint8_t*>(buffer) + size);
  auto root = CreateOtExtensionMessageDirect(builder, i, &v_buffer);
  FinishOtExtensionMessageBuffer(builder, root);
  return BuildMessage(MessageType::kOtExtensionSender, builder.GetBufferPointer(),
                      builder.GetSize());
}

flatbuffers::FlatBufferBuilder BuildOtExtensionMessageReceiverMasks(const std::byte* buffer,
                                                                    const std::size_t size,
                                                                    const std::size_t i) {
  flatbuffers::FlatBufferBuilder builder(size + 32);
  std::vector<std::uint8_t> v_buffer(reinterpret_cast<const std::uint8_t*>(buffer),
                                     reinterpret_cast<const std::uint8_t*>(buffer) + size);
  auto root = CreateOtExtensionMessageDirect(builder, i, &v_buffer);
  FinishOtExtensionMessageBuffer(builder, root);
  return BuildMessage(MessageType::kOtExtensionReceiverMasks, builder.GetBufferPointer(),
                      builder.GetSize());
}

flatbuffers::FlatBufferBuilder BuildOtExtensionMessageReceiverCorrections(const std::byte* buffer,
                                                                          const std::size_t size,
                                                                          const std::size_t i) {
  flatbuffers::FlatBufferBuilder builder(size + 32);
  std::vector<std::uint8_t> v_buffer(reinterpret_cast<const std::uint8_t*>(buffer),
                                     reinterpret_cast<const std::uint8_t*>(buffer) + size);
  auto root = CreateOtExtensionMessageDirect(builder, i, &v_buffer);
  FinishOtExtensionMessageBuffer(builder, root);
  return BuildMessage(MessageType::kOtExtensionReceiverCorrections, builder.GetBufferPointer(),
                      builder.GetSize());
}

}  // namespace encrypto::motion::communication
