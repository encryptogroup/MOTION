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

#include <fstream>
#include "aes128_ctr_rng.h"
#include "crypto/aes/aesni_primitives.h"

thread_local AES128_CTR_RNG AES128_CTR_RNG::thread_instance_;

struct AES128_CTR_RNG::AES128_CTR_RNG_State {
  alignas(aes_block_size) std::array<std::byte, aes_round_keys_size_128> round_keys;
  std::uint64_t counter;
};

AES128_CTR_RNG::AES128_CTR_RNG() : state_(std::make_unique<AES128_CTR_RNG_State>()) {
  sample_key();
}

AES128_CTR_RNG::~AES128_CTR_RNG() = default;

void AES128_CTR_RNG::sample_key() {
  // read key from /dev/urandom
  std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
  if (!urandom) {
    throw std::runtime_error("Failed to open /dev/urandom");
  }
  urandom.read(reinterpret_cast<char*>(state_->round_keys.data()),
               static_cast<std::streamsize>(aes_block_size));
  if (!urandom) {
    throw std::runtime_error("Failed to read from /dev/urandom");
  }
  urandom.close();

  // execute key schedule
  aesni_key_expansion_128(state_->round_keys.data());

  // reset counter
  state_->counter = 0;
}

void AES128_CTR_RNG::random_blocks_aligned(std::byte* output, std::size_t num_blocks) {
  std::byte* aligned_output = reinterpret_cast<std::byte*>(__builtin_assume_aligned(output, 16));
  aesni_ctr_stream_blocks_128(state_->round_keys.data(), &state_->counter, aligned_output,
                              num_blocks);
}

void AES128_CTR_RNG::random_blocks(std::byte* output, std::size_t num_blocks) {
  aesni_ctr_stream_blocks_128_unaligned(state_->round_keys.data(), &state_->counter, output,
                                        num_blocks);
}

void AES128_CTR_RNG::random_bytes(std::byte* output, std::size_t num_bytes) {
  std::size_t num_blocks = num_bytes / aes_block_size;
  std::size_t remaining_bytes = num_bytes & aes_block_size;
  random_blocks(output, num_blocks);
  std::array<std::byte, aes_block_size> extra_block;
  aesni_ctr_stream_single_block_128_unaligned(state_->round_keys.data(), &state_->counter,
                                              extra_block.data());
  std::copy(std::begin(extra_block), std::begin(extra_block) + remaining_bytes,
            output + num_bytes - remaining_bytes);
}
