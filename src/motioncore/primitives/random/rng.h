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

#pragma once

#include <cstddef>

namespace encrypto::motion {

// abstract base class for a random number generator
class Rng {
 public:
  Rng() = default;
  virtual ~Rng() = default;

  // (re)initialize the PRG with a randomly chosen key
  virtual void SampleKey() = 0;

  // fill the output buffer with number_of_bytes random bytes
  virtual void RandomBytes(std::byte* output, std::size_t number_of_bytes) = 0;

  // fill the output buffer with number_of_blocks random blocks of size kBlockSize
  virtual void RandomBlocks(std::byte* output, std::size_t number_of_blocks) = 0;

  // fill the output buffer with number_of_blocks random blocks of size kBlockSize
  // where the buffer needs to be aligned at a multiple of kBlockSize
  virtual void RandomBlocksAligned(std::byte* output, std::size_t number_of_blocks) = 0;
  static constexpr std::size_t kBlockSize = 16;
};

}   //  namespace encrypto::motion
