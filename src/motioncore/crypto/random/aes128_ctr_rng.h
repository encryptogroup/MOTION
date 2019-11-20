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
#include <memory>
#include "rng.h"

// RNG implemented using AES128 in CTR mode
class AES128_CTR_RNG : public RNG {
 public:
  AES128_CTR_RNG();
  virtual ~AES128_CTR_RNG();

  // delete copy/move constructors/assignment operators
  AES128_CTR_RNG(const AES128_CTR_RNG&) = delete;
  AES128_CTR_RNG(AES128_CTR_RNG&&) = delete;
  AES128_CTR_RNG& operator=(const AES128_CTR_RNG&) = delete;
  AES128_CTR_RNG& operator=(AES128_CTR_RNG&&) = delete;


  // (re)initialize the PRG with a randomly chosen key
  virtual void sample_key();

  // fill the output buffer with num_bytes random bytes
  virtual void random_bytes(std::byte* output, std::size_t num_bytes);

  // fill the output buffer with num_blocks random blocks of size block_size
  virtual void random_blocks(std::byte* output, std::size_t num_blocks);

  // fill the output buffer with num_blocks random blocks of size block_size
  // where the buffer needs to be aligned at a multiple of block_size
  virtual void random_blocks_aligned(std::byte* output, std::size_t num_blocks);

  static AES128_CTR_RNG& get_thread_instance() { return thread_instance_; }

  static constexpr std::size_t block_size = 16;
 private:
  struct AES128_CTR_RNG_State;
  std::unique_ptr<AES128_CTR_RNG_State> state_;
  static thread_local AES128_CTR_RNG thread_instance_;
};
