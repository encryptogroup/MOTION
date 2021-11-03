// MIT License
//
// Copyright (c) 2018 Lennart Braun
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

#include <array>
#include <vector>

#include "utility/bit_vector.h"
#include "utility/fiber_waitable.h"

namespace encrypto::motion {

class Ot {
 public:
  virtual ~Ot() = default;
  virtual void Send(const std::vector<std::vector<std::byte>>&) = 0;
  virtual std::vector<std::byte> Receive(size_t) = 0;
};

class RandomOt : public FiberOnlineWaitable {
 public:
  virtual ~RandomOt() = default;

  /**
   * Send/receive parts of the random OT protocol (batch version).
   */
  virtual std::vector<std::pair<std::vector<std::byte>, std::vector<std::byte>>> Send(size_t) = 0;
  virtual std::vector<std::vector<std::byte>> Receive(const BitVector<>&) = 0;
};

}  // namespace encrypto::motion
