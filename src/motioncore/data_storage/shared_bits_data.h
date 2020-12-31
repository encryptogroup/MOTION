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

#pragma once

#include <cstdint>
#include <vector>
#include "utility/reusable_future.h"

namespace encrypto::motion {

enum SharedBitsMessageType : std::uint8_t { kMaskMessage = 2, kReconstructMessage = 1 };

struct SharedBitsData {
  void MessageReceived(const SharedBitsMessageType type, const std::uint8_t* message,
                       const std::size_t size);
  void Clear();

  // register to receive the masked value during squaring
  ReusableFuture<std::vector<std::uint8_t>> RegisterForMaskMessage(size_t expected_size);

  // register to receive the reconstruction messages for a^2
  ReusableFuture<std::vector<std::uint8_t>> RegisterForReconstructMessage(size_t expected_size);

  ReusablePromise<std::vector<std::uint8_t>> mask_message_promise;
  std::size_t mask_message_expected_size = 0;
  ReusablePromise<std::vector<std::uint8_t>> reconstruct_message_promise;
  std::size_t reconstruct_message_expected_size = 0;
};

}  // namespace encrypto::motion
