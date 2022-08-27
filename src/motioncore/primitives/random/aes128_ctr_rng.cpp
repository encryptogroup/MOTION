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

#include "aes128_ctr_rng.h"

#include <array>
#include <fstream>
#include <openssl/rand.h>

#include "primitives/aes/aesni_primitives.h"

namespace encrypto::motion {

thread_local Aes128CtrRng Aes128CtrRng::thread_instance_;

struct Aes128CtrRng::Aes128CtrRngState {
  alignas(kAesBlockSize) std::array<std::byte, kAesRoundKeysSize128> round_keys;
  std::uint64_t counter;
};

Aes128CtrRng::Aes128CtrRng() : state_(std::make_unique<Aes128CtrRngState>()) { SampleKey(); }

Aes128CtrRng::~Aes128CtrRng() = default;

void Aes128CtrRng::SampleKey() {
  int random =
      RAND_bytes(reinterpret_cast<unsigned char*>(state_->round_keys.data()), kAesBlockSize);
  if (random != 1) {
    throw std::runtime_error("RAND_bytes in Aes128CtrRng::SampleKey failed");
  }

  // execute key schedule
  AesniKeyExpansion128(state_->round_keys.data());

  // reset counter
  state_->counter = 0;
}

void Aes128CtrRng::RandomBlocksAligned(std::byte* output, std::size_t number_of_blocks) {
  std::byte* aligned_output = reinterpret_cast<std::byte*>(__builtin_assume_aligned(output, 16));
  AesniCtrStreamBlocks128(state_->round_keys.data(), &state_->counter, aligned_output,
                          number_of_blocks);
}

void Aes128CtrRng::RandomBlocks(std::byte* output, std::size_t number_of_blocks) {
  AesniCtrStreamBlocks128Unaligned(state_->round_keys.data(), &state_->counter, output,
                                   number_of_blocks);
}

void Aes128CtrRng::RandomBytes(std::byte* output, std::size_t number_of_bytes) {
  std::size_t number_of_blocks = number_of_bytes / kAesBlockSize;
  std::size_t remaining_bytes = number_of_bytes % kAesBlockSize;
  RandomBlocks(output, number_of_blocks);
  std::array<std::byte, kAesBlockSize> extra_block;
  AesniCtrStreamSingleBlock128Unaligned(state_->round_keys.data(), &state_->counter,
                                        extra_block.data());
  std::copy(std::begin(extra_block), std::begin(extra_block) + remaining_bytes,
            output + number_of_bytes - remaining_bytes);
}

}  //  namespace encrypto::motion
