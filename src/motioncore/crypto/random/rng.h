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

// abstract base class for a random number generator
class RNG {
 public:
  RNG() = default;
  virtual ~RNG() = default;

  // (re)initialize the PRG with a randomly chosen key
  virtual void sample_key() = 0;

  // fill the output buffer with num_bytes random bytes
  virtual void random_bytes(std::byte* output, std::size_t num_bytes) = 0;

  // fill the output buffer with num_blocks random blocks of size block_size
  virtual void random_blocks(std::byte* output, std::size_t num_blocks) = 0;

  // fill the output buffer with num_blocks random blocks of size block_size
  // where the buffer needs to be aligned at a multiple of block_size
  virtual void random_blocks_aligned(std::byte* output, std::size_t num_blocks) = 0;
  static constexpr std::size_t block_size = 16;
};
