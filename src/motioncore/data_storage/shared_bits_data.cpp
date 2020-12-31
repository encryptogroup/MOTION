// MIT License
//
// Copyright (c) 2019 Lennart Braun
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

#include "shared_bits_data.h"
#include <cassert>

namespace encrypto::motion {

ReusableFuture<std::vector<std::uint8_t>> SharedBitsData::RegisterForMaskMessage(
    size_t expected_size) {
  assert(expected_size > 0);
  mask_message_expected_size = expected_size;
  return mask_message_promise.get_future();
}

ReusableFuture<std::vector<std::uint8_t>> SharedBitsData::RegisterForReconstructMessage(
    size_t expected_size) {
  assert(expected_size > 0);
  reconstruct_message_expected_size = expected_size;
  return reconstruct_message_promise.get_future();
}

void SharedBitsData::MessageReceived(const SharedBitsMessageType type, const std::uint8_t* message,
                                     const std::size_t size) {
  if (type == SharedBitsMessageType::kMaskMessage) {
    if (size != mask_message_expected_size) {
      // TODO: log and drop
      return;
    }
    std::vector<std::uint8_t> buffer(message, message + size);
    mask_message_promise.set_value(std::move(buffer));
  } else if (type == SharedBitsMessageType::kReconstructMessage) {
    if (size != reconstruct_message_expected_size) {
      // TODO: log and drop
      return;
    }
    std::vector<std::uint8_t> buffer(message, message + size);
    reconstruct_message_promise.set_value(std::move(buffer));
  }
}

}  // namespace encrypto::motion
