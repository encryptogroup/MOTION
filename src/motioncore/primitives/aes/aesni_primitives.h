// MIT License
//
// Copyright (c) 2018-2020 Lennart Braun
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

constexpr std::size_t kAesKeySize128 = 16;
constexpr std::size_t kAesBlockSize = 16;
constexpr std::size_t kAesRoundKeysSize128 = 176;
constexpr std::size_t kAesNumRoundKeys128 = 11;

// expand the round_keys with the assumptions:
// * first round key == aes key is already placed at the start of the buffer
// * round_keys is 16B aligned
void AesniKeyExpansion128(void* round_keys);

// generate number_of_blocks of random bytes using AES in counter mode
// * round_keys and output are 16B aligned
void AesniCtrStreamBlocks128(const void* round_keys, std::uint64_t* counter, void* output,
                             std::size_t number_of_blocks);

// generate number_of_blocks of random bytes using AES in counter mode
// * round_keys are 16B aligned
void AesniCtrStreamBlocks128Unaligned(const void* round_keys, std::uint64_t* counter, void* output,
                                      std::size_t number_of_blocks);

// generate a single block of random bytes using AES in counter mode
// * round_keys are 16B aligned
void AesniCtrStreamSingleBlock128Unaligned(const void* round_keys, std::uint64_t* counter,
                                           void* output);

// Compute the fixed-key contruction TMMO^\pi from Guo et al.
// (https://eprint.iacr.org/2019/074) on four input blocks inplace.
//
// TMMO^\pi(x, i) = \pi(\pi(x) ^ i) ^ \pi(x)
//
// * round_keys and output are 16B aligned
void AesniTmmoBatch4(const void* round_keys, void* input, __uint128_t tweak);

// Compute the fixed-key contruction TMMO^\pi from Guo et al.
// (https://eprint.iacr.org/2019/074) on six input blocks inplace as described in
//
// TMMO^\pi(x, i) = \pi(\pi(x) ^ i) ^ \pi(x)
//
// * round_keys and output are 16B-bit aligned
// TODO tests
void AesniTmmoBatch6(const void* round_keys, void* input, __uint128_t tweak);

// Compute the fixed-key contruction TMMO^\pi from Guo et al.
// (https://eprint.iacr.org/2019/074) on six input blocks inplace as described in
//
// TMMO^\pi(x, i) = \pi(\pi(x) ^ i) ^ \pi(x)
//
// * round_keys and output are 16B-bit aligned
// TODO tests
void AesniTmmoBatch3(const void* round_keys, void* input, __uint128_t tweak);

// Compute the fixed-key contruction MMO^\pi from Guo et al.
// (https://eprint.iacr.org/2019/074).
//
// MMO^\pi(x) = \pi(x) ^ x
//
// * round_keys are 16B aligned
void AesniMmoSingle(const void* round_keys, void* input);

// Compute the dual-key cipher A2/D1 by Bellare et al.
// (https://eprint.iacr.org/2013/426).
//
// Computes `number_of_parties` invocation of the DKC:
//    E^\pi(A, B, T, _) = \pi(K) ^ K
// where
// - \pi is AES with the expanded key from `round_keys`
// - K = 4A + 2B + T and with multiplication in GF(2^128)
// - T = gate_id || party_id
// - `party_id` ranges from 0 to number_of_parties - 1
// The output is xored into `output`.
void AesniBmrDkc(const void* round_keys, const void* key_a, const void* key_b,
                 std::uint64_t gate_id, std::size_t number_of_parties, void* output);
