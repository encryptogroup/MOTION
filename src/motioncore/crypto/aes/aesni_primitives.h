// MIT License
//
// Copyright (c) 2018-2019 Lennart Braun
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
#include <cstdint>

constexpr std::size_t aes_key_size_128 = 16;
constexpr std::size_t aes_block_size = 16;
constexpr std::size_t aes_round_keys_size_128 = 176;
constexpr std::size_t aes_num_round_keys_128 = 11;

// expand the round_keys with the assumptions:
// * first round key == aes key is already placed at the start of the buffer
// * round_keys is 16B aligned
void aesni_key_expansion_128(void* round_keys);

// generate num_blocks of random bytes using AES in counter mode
// * round_keys and output are 16B aligned
void aesni_ctr_stream_blocks_128(const void* round_keys, std::uint64_t* counter, void* output,
                                 std::size_t num_blocks);
