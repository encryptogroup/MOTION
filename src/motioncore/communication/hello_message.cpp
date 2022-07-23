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

#include "hello_message.h"

#include "fbs_headers/hello_message_generated.h"
#include "message.h"
#include "utility/typedefs.h"

namespace encrypto::motion::communication {

flatbuffers::FlatBufferBuilder BuildHelloMessage(
    uint16_t source_id, uint16_t destination_id, uint16_t number_of_parties,
    const std::vector<uint8_t>* input_sharing_seed, const std::vector<uint8_t>* global_sharing_seed,
    const std::vector<uint8_t>* fixed_key_aes_seed, bool online_after_setup,
    std::uint16_t motion_version_major, std::uint16_t motion_version_minor,
    std::uint16_t motion_version_patch) {
  flatbuffers::FlatBufferBuilder builder_hello_message(256);
  auto hello_message_root = CreateHelloMessageDirect(
      builder_hello_message, source_id, destination_id, number_of_parties, input_sharing_seed,
      global_sharing_seed, fixed_key_aes_seed, online_after_setup, motion_version_major,
      motion_version_minor, motion_version_patch);
  FinishHelloMessageBuffer(builder_hello_message, hello_message_root);

  return BuildMessage(
      MessageType::kHelloMessage,
      std::span(builder_hello_message.GetBufferPointer(), builder_hello_message.GetSize()));
}

}  // namespace encrypto::motion::communication
