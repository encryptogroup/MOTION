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

namespace encrypto::motion {

// RNG implemented using AES128 in CTR mode
class Aes128CtrRng : public Rng {
 public:
  Aes128CtrRng();
  virtual ~Aes128CtrRng();

  // delete copy/move constructors/assignment operators
  Aes128CtrRng(const Aes128CtrRng&) = delete;
  Aes128CtrRng(Aes128CtrRng&&) = delete;
  Aes128CtrRng& operator=(const Aes128CtrRng&) = delete;
  Aes128CtrRng& operator=(Aes128CtrRng&&) = delete;

  // (re)initialize the PRG with a randomly chosen key
  virtual void SampleKey() override;

  // fill the output buffer with number_of_bytes random bytes
  virtual void RandomBytes(std::byte* output, std::size_t number_of_bytes) override;

  // fill the output buffer with number_of_blocks random blocks of size kBlockSize
  virtual void RandomBlocks(std::byte* output, std::size_t number_of_blocks) override;

  // fill the output buffer with number_of_blocks random blocks of size kBlockSize
  // where the buffer needs to be aligned at a multiple of kBlockSize
  virtual void RandomBlocksAligned(std::byte* output, std::size_t number_of_blocks) override;

  static Aes128CtrRng& GetThreadInstance() { return thread_instance_; }

  static constexpr std::size_t kBlockSize = 16;

 private:
  struct Aes128CtrRngState;
  std::unique_ptr<Aes128CtrRngState> state_;
  static thread_local Aes128CtrRng thread_instance_;
};

}   //  namespace encrypto::motion
