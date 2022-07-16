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

#include "aesni_primitives.h"
#include <immintrin.h>
#include <algorithm>
#include <array>

template <int round_constant>
static __m128i AesKeyExpand(__m128i xmm1) {
  // aeskeygenassist xmm3, xmm1, \rcon
  __m128i xmm3 = _mm_aeskeygenassist_si128(xmm1, round_constant);
  // pshufd xmm3, xmm3, 0xff
  xmm3 = _mm_shuffle_epi32(xmm3, 0xff);
  // movdqa xmm2, xmm1
  __m128i xmm2 = xmm1;
  // pslldq xmm2, 4
  xmm2 = _mm_slli_si128(xmm2, 4);
  // pxor xmm1, xmm2
  xmm1 = _mm_xor_si128(xmm1, xmm2);
  // pslldq xmm2, 4
  xmm2 = _mm_slli_si128(xmm2, 4);
  // pxor xmm1, xmm2
  xmm1 = _mm_xor_si128(xmm1, xmm2);
  // pslldq xmm2, 4
  xmm2 = _mm_slli_si128(xmm2, 4);
  // pxor xmm1, xmm2
  xmm1 = _mm_xor_si128(xmm1, xmm2);
  // pxor xmm1, xmm3
  xmm1 = _mm_xor_si128(xmm1, xmm3);
  return xmm1;
}

// expand the round_keys
// assume first round key == aes key is already placed at the start of the buffer
void AesniKeyExpansion128(void* round_keys_input) {
  __m128i* round_keys =
      reinterpret_cast<__m128i*>(__builtin_assume_aligned(round_keys_input, kAesBlockSize));
  // movdqa xmm1, [rsi]
  // movdqa [rdi], xmm1
  round_keys[1] = AesKeyExpand<0x01>(round_keys[0]);
  // AesKeyExpand 0x01
  // movdqa 0x10[rdi], xmm1
  round_keys[2] = AesKeyExpand<0x02>(round_keys[1]);
  // AesKeyExpand 0x02
  // movdqa 0x20[rdi], xmm1
  round_keys[3] = AesKeyExpand<0x04>(round_keys[2]);
  // AesKeyExpand 0x04
  // movdqa 0x30[rdi], xmm1
  round_keys[4] = AesKeyExpand<0x08>(round_keys[3]);
  // AesKeyExpand 0x08
  // movdqa 0x40[rdi], xmm1
  round_keys[5] = AesKeyExpand<0x10>(round_keys[4]);
  // AesKeyExpand 0x10
  // movdqa 0x50[rdi], xmm1
  round_keys[6] = AesKeyExpand<0x20>(round_keys[5]);
  // AesKeyExpand 0x20
  // movdqa 0x60[rdi], xmm1
  round_keys[7] = AesKeyExpand<0x40>(round_keys[6]);
  // AesKeyExpand 0x40
  // movdqa 0x70[rdi], xmm1
  round_keys[8] = AesKeyExpand<0x80>(round_keys[7]);
  // AesKeyExpand 0x80
  // movdqa 0x80[rdi], xmm1
  round_keys[9] = AesKeyExpand<0x1b>(round_keys[8]);
  // AesKeyExpand 0x1b
  // movdqa 0x90[rdi], xmm1
  round_keys[10] = AesKeyExpand<0x36>(round_keys[9]);
  // AesKeyExpand 0x36
  // movdqa 0xa0[rdi], xmm1
}

void AesniCtrStreamBlocks128(const void* round_keys_input, std::uint64_t* counter_input_pointer,
                             void* output_input_pointer, std::size_t number_of_blocks) {
  alignas(16) std::array<__m128i, kAesNumRoundKeys128> round_keys;
  alignas(16) std::array<__m128i, 4> wb;
  auto counter = *counter_input_pointer;

  // we assume the output buffer is aligned
  auto output =
      reinterpret_cast<__m128i*>(__builtin_assume_aligned(output_input_pointer, kAesBlockSize));

  // copy the round keys onto the stack
  // -> compiler will put them into registers
  std::copy(reinterpret_cast<__m128i*>(__builtin_assume_aligned(round_keys_input, kAesBlockSize)),
            reinterpret_cast<__m128i*>(__builtin_assume_aligned(round_keys_input, kAesBlockSize)) +
                kAesNumRoundKeys128,
            round_keys.data());

  // do as many blocks as possible in 4er batches
  // since the aesenc instructions have a latency of 4
  auto batch_blocks = number_of_blocks & (~0b11);
  for (size_t i = 0; i < batch_blocks; i += 4) {
    for (std::size_t j = 0; j < 4; ++j) wb[j] = _mm_set_epi64x(0, counter + j);
    for (std::size_t j = 0; j < 4; ++j) wb[j] = _mm_xor_si128(wb[j], round_keys[0]);
    for (std::size_t j = 0; j < 4; ++j) wb[j] = _mm_aesenc_si128(wb[j], round_keys[1]);
    for (std::size_t j = 0; j < 4; ++j) wb[j] = _mm_aesenc_si128(wb[j], round_keys[2]);
    for (std::size_t j = 0; j < 4; ++j) wb[j] = _mm_aesenc_si128(wb[j], round_keys[3]);
    for (std::size_t j = 0; j < 4; ++j) wb[j] = _mm_aesenc_si128(wb[j], round_keys[4]);
    for (std::size_t j = 0; j < 4; ++j) wb[j] = _mm_aesenc_si128(wb[j], round_keys[5]);
    for (std::size_t j = 0; j < 4; ++j) wb[j] = _mm_aesenc_si128(wb[j], round_keys[6]);
    for (std::size_t j = 0; j < 4; ++j) wb[j] = _mm_aesenc_si128(wb[j], round_keys[7]);
    for (std::size_t j = 0; j < 4; ++j) wb[j] = _mm_aesenc_si128(wb[j], round_keys[8]);
    for (std::size_t j = 0; j < 4; ++j) wb[j] = _mm_aesenc_si128(wb[j], round_keys[9]);
    for (std::size_t j = 0; j < 4; ++j) wb[j] = _mm_aesenclast_si128(wb[j], round_keys[10]);
    for (std::size_t j = 0; j < 4; ++j) output[i + j] = wb[j];
    counter += 4;
  }

  // do the remaining blocks
  for (size_t i = batch_blocks; i < number_of_blocks; ++i) {
    wb[0] = _mm_set_epi64x(0, counter);
    wb[0] = _mm_xor_si128(wb[0], round_keys[0]);
    wb[0] = _mm_aesenc_si128(wb[0], round_keys[1]);
    wb[0] = _mm_aesenc_si128(wb[0], round_keys[2]);
    wb[0] = _mm_aesenc_si128(wb[0], round_keys[3]);
    wb[0] = _mm_aesenc_si128(wb[0], round_keys[4]);
    wb[0] = _mm_aesenc_si128(wb[0], round_keys[5]);
    wb[0] = _mm_aesenc_si128(wb[0], round_keys[6]);
    wb[0] = _mm_aesenc_si128(wb[0], round_keys[7]);
    wb[0] = _mm_aesenc_si128(wb[0], round_keys[8]);
    wb[0] = _mm_aesenc_si128(wb[0], round_keys[9]);
    wb[0] = _mm_aesenclast_si128(wb[0], round_keys[10]);
    output[i] = wb[0];
    ++counter;
  }

  // write the new counter back
  *counter_input_pointer = counter;
}

void AesniCtrStreamBlocks128Unaligned(const void* round_keys_input,
                                      std::uint64_t* counter_input_pointer,
                                      void* output_input_pointer, std::size_t number_of_blocks) {
  // almost the same code as in `AesniCtrStreamBlocks128`

  alignas(16) std::array<__m128i, kAesNumRoundKeys128> round_keys;
  alignas(16) std::array<__m128i, 4> wb;
  auto counter = *counter_input_pointer;

  // DIFFERENCE: we no longer assume that the output buffer is aligned
  auto output = reinterpret_cast<__m128i*>(output_input_pointer);

  // copy the round keys onto the stack
  // -> compiler will put them into registers
  std::copy(reinterpret_cast<__m128i*>(__builtin_assume_aligned(round_keys_input, kAesBlockSize)),
            reinterpret_cast<__m128i*>(__builtin_assume_aligned(round_keys_input, kAesBlockSize)) +
                kAesNumRoundKeys128,
            round_keys.data());

  // do as many blocks as possible in batches of 4
  // since the aesenc instructions have a latency of 4
  auto batch_blocks = number_of_blocks & (~0b11);
  for (size_t i = 0; i < batch_blocks; i += 4) {
    for (std::size_t j = 0; j < 4; ++j) wb[j] = _mm_set_epi64x(0, counter + j);
    for (std::size_t j = 0; j < 4; ++j) wb[j] = _mm_xor_si128(wb[j], round_keys[0]);
    for (std::size_t j = 0; j < 4; ++j) wb[j] = _mm_aesenc_si128(wb[j], round_keys[1]);
    for (std::size_t j = 0; j < 4; ++j) wb[j] = _mm_aesenc_si128(wb[j], round_keys[2]);
    for (std::size_t j = 0; j < 4; ++j) wb[j] = _mm_aesenc_si128(wb[j], round_keys[3]);
    for (std::size_t j = 0; j < 4; ++j) wb[j] = _mm_aesenc_si128(wb[j], round_keys[4]);
    for (std::size_t j = 0; j < 4; ++j) wb[j] = _mm_aesenc_si128(wb[j], round_keys[5]);
    for (std::size_t j = 0; j < 4; ++j) wb[j] = _mm_aesenc_si128(wb[j], round_keys[6]);
    for (std::size_t j = 0; j < 4; ++j) wb[j] = _mm_aesenc_si128(wb[j], round_keys[7]);
    for (std::size_t j = 0; j < 4; ++j) wb[j] = _mm_aesenc_si128(wb[j], round_keys[8]);
    for (std::size_t j = 0; j < 4; ++j) wb[j] = _mm_aesenc_si128(wb[j], round_keys[9]);
    for (std::size_t j = 0; j < 4; ++j) wb[j] = _mm_aesenclast_si128(wb[j], round_keys[10]);
    // DIFFERENCE: we need to use an explicit unaligned store here
    for (std::size_t j = 0; j < 4; ++j) _mm_storeu_si128(&output[i + j], wb[j]);
    counter += 4;
  }

  // do the remaining blocks
  for (size_t i = batch_blocks; i < number_of_blocks; ++i) {
    wb[0] = _mm_set_epi64x(0, counter);
    wb[0] = _mm_xor_si128(wb[0], round_keys[0]);
    wb[0] = _mm_aesenc_si128(wb[0], round_keys[1]);
    wb[0] = _mm_aesenc_si128(wb[0], round_keys[2]);
    wb[0] = _mm_aesenc_si128(wb[0], round_keys[3]);
    wb[0] = _mm_aesenc_si128(wb[0], round_keys[4]);
    wb[0] = _mm_aesenc_si128(wb[0], round_keys[5]);
    wb[0] = _mm_aesenc_si128(wb[0], round_keys[6]);
    wb[0] = _mm_aesenc_si128(wb[0], round_keys[7]);
    wb[0] = _mm_aesenc_si128(wb[0], round_keys[8]);
    wb[0] = _mm_aesenc_si128(wb[0], round_keys[9]);
    wb[0] = _mm_aesenclast_si128(wb[0], round_keys[10]);
    // DIFFERENCE: we need to use an explicit unaligned store here
    _mm_storeu_si128(&output[i], wb[0]);
    ++counter;
  }

  // write the new counter back
  *counter_input_pointer = counter;
}

void AesniCtrStreamSingleBlock128Unaligned(const void* round_keys_input, std::uint64_t* counter,
                                           void* output) {
  auto round_keys =
      reinterpret_cast<__m128i*>(__builtin_assume_aligned(round_keys_input, kAesBlockSize));
  auto output_pointer = reinterpret_cast<__m128i*>(output);
  __m128i wb;
  wb = _mm_set_epi64x(0, (*counter)++);
  wb = _mm_xor_si128(wb, round_keys[0]);
  wb = _mm_aesenc_si128(wb, round_keys[1]);
  wb = _mm_aesenc_si128(wb, round_keys[2]);
  wb = _mm_aesenc_si128(wb, round_keys[3]);
  wb = _mm_aesenc_si128(wb, round_keys[4]);
  wb = _mm_aesenc_si128(wb, round_keys[5]);
  wb = _mm_aesenc_si128(wb, round_keys[6]);
  wb = _mm_aesenc_si128(wb, round_keys[7]);
  wb = _mm_aesenc_si128(wb, round_keys[8]);
  wb = _mm_aesenc_si128(wb, round_keys[9]);
  wb = _mm_aesenclast_si128(wb, round_keys[10]);
  _mm_storeu_si128(output_pointer, wb);
}

void AesniTmmoBatch4(const void* round_keys_input, void* input, __uint128_t tweak) {
  alignas(16) std::array<__m128i, kAesNumRoundKeys128> round_keys;
  alignas(16) std::array<__m128i, 4> wb_1;
  alignas(16) std::array<__m128i, 4> wb_2;

  // copy the round keys onto the stack
  // -> compiler will put them into registers
  std::copy(reinterpret_cast<__m128i*>(__builtin_assume_aligned(round_keys_input, kAesBlockSize)),
            reinterpret_cast<__m128i*>(__builtin_assume_aligned(round_keys_input, kAesBlockSize)) +
                kAesNumRoundKeys128,
            round_keys.data());
  auto input_pointer = reinterpret_cast<__m128i*>(input);
  auto tweak_pointer = reinterpret_cast<__m128i*>(&tweak);

  // compute wb_1 <- \pi(x)
  for (std::size_t j = 0; j < 4; ++j) wb_1[j] = _mm_xor_si128(input_pointer[j], round_keys[0]);
  for (std::size_t j = 0; j < 4; ++j) wb_1[j] = _mm_aesenc_si128(wb_1[j], round_keys[1]);
  for (std::size_t j = 0; j < 4; ++j) wb_1[j] = _mm_aesenc_si128(wb_1[j], round_keys[2]);
  for (std::size_t j = 0; j < 4; ++j) wb_1[j] = _mm_aesenc_si128(wb_1[j], round_keys[3]);
  for (std::size_t j = 0; j < 4; ++j) wb_1[j] = _mm_aesenc_si128(wb_1[j], round_keys[4]);
  for (std::size_t j = 0; j < 4; ++j) wb_1[j] = _mm_aesenc_si128(wb_1[j], round_keys[5]);
  for (std::size_t j = 0; j < 4; ++j) wb_1[j] = _mm_aesenc_si128(wb_1[j], round_keys[6]);
  for (std::size_t j = 0; j < 4; ++j) wb_1[j] = _mm_aesenc_si128(wb_1[j], round_keys[7]);
  for (std::size_t j = 0; j < 4; ++j) wb_1[j] = _mm_aesenc_si128(wb_1[j], round_keys[8]);
  for (std::size_t j = 0; j < 4; ++j) wb_1[j] = _mm_aesenc_si128(wb_1[j], round_keys[9]);
  for (std::size_t j = 0; j < 4; ++j) wb_1[j] = _mm_aesenclast_si128(wb_1[j], round_keys[10]);

  // compute wb_2 <- \pi(\pi(x) ^ i)
  for (std::size_t j = 0; j < 4; ++j) wb_2[j] = _mm_xor_si128(wb_1[j], *tweak_pointer);
  for (std::size_t j = 0; j < 4; ++j) wb_2[j] = _mm_xor_si128(wb_2[j], round_keys[0]);
  for (std::size_t j = 0; j < 4; ++j) wb_2[j] = _mm_aesenc_si128(wb_2[j], round_keys[1]);
  for (std::size_t j = 0; j < 4; ++j) wb_2[j] = _mm_aesenc_si128(wb_2[j], round_keys[2]);
  for (std::size_t j = 0; j < 4; ++j) wb_2[j] = _mm_aesenc_si128(wb_2[j], round_keys[3]);
  for (std::size_t j = 0; j < 4; ++j) wb_2[j] = _mm_aesenc_si128(wb_2[j], round_keys[4]);
  for (std::size_t j = 0; j < 4; ++j) wb_2[j] = _mm_aesenc_si128(wb_2[j], round_keys[5]);
  for (std::size_t j = 0; j < 4; ++j) wb_2[j] = _mm_aesenc_si128(wb_2[j], round_keys[6]);
  for (std::size_t j = 0; j < 4; ++j) wb_2[j] = _mm_aesenc_si128(wb_2[j], round_keys[7]);
  for (std::size_t j = 0; j < 4; ++j) wb_2[j] = _mm_aesenc_si128(wb_2[j], round_keys[8]);
  for (std::size_t j = 0; j < 4; ++j) wb_2[j] = _mm_aesenc_si128(wb_2[j], round_keys[9]);
  for (std::size_t j = 0; j < 4; ++j) wb_2[j] = _mm_aesenclast_si128(wb_2[j], round_keys[10]);

  // store \pi(\pi(x) ^ i) ^ \pi(x)
  for (std::size_t j = 0; j < 4; ++j) input_pointer[j] = _mm_xor_si128(wb_2[j], wb_1[j]);
}

void AesniTmmoBatch6(const void* round_keys_input, void* input, __uint128_t tweak) {
  alignas(16) std::array<__m128i, kAesNumRoundKeys128> round_keys;
  alignas(16) std::array<__m128i, 6> wb_1;
  alignas(16) std::array<__m128i, 6> wb_2;

  // copy the round keys onto the stack
  // -> compiler will put them into registers
  std::copy(reinterpret_cast<__m128i*>(__builtin_assume_aligned(round_keys_input, kAesBlockSize)),
            reinterpret_cast<__m128i*>(__builtin_assume_aligned(round_keys_input, kAesBlockSize)) +
                kAesNumRoundKeys128,
            round_keys.data());
  auto input_pointer = reinterpret_cast<__m128i*>(input);
  auto tweak_pointer = reinterpret_cast<__m128i*>(&tweak);

  // compute wb_1 <- \pi(x)
  for (std::size_t j = 0; j < 6; ++j) wb_1[j] = _mm_xor_si128(input_pointer[j], round_keys[0]);
  for (std::size_t j = 0; j < 6; ++j) wb_1[j] = _mm_aesenc_si128(wb_1[j], round_keys[1]);
  for (std::size_t j = 0; j < 6; ++j) wb_1[j] = _mm_aesenc_si128(wb_1[j], round_keys[2]);
  for (std::size_t j = 0; j < 6; ++j) wb_1[j] = _mm_aesenc_si128(wb_1[j], round_keys[3]);
  for (std::size_t j = 0; j < 6; ++j) wb_1[j] = _mm_aesenc_si128(wb_1[j], round_keys[4]);
  for (std::size_t j = 0; j < 6; ++j) wb_1[j] = _mm_aesenc_si128(wb_1[j], round_keys[5]);
  for (std::size_t j = 0; j < 6; ++j) wb_1[j] = _mm_aesenc_si128(wb_1[j], round_keys[6]);
  for (std::size_t j = 0; j < 6; ++j) wb_1[j] = _mm_aesenc_si128(wb_1[j], round_keys[7]);
  for (std::size_t j = 0; j < 6; ++j) wb_1[j] = _mm_aesenc_si128(wb_1[j], round_keys[8]);
  for (std::size_t j = 0; j < 6; ++j) wb_1[j] = _mm_aesenc_si128(wb_1[j], round_keys[9]);
  for (std::size_t j = 0; j < 6; ++j) wb_1[j] = _mm_aesenclast_si128(wb_1[j], round_keys[10]);

  // compute wb_2 <- \pi(\pi(x) ^ i)
  tweak *= 3;
  tweak -= 3;
  wb_2[0] = _mm_xor_si128(wb_1[0], *tweak_pointer);
  wb_2[1] = _mm_xor_si128(wb_1[1], *tweak_pointer);
  ++tweak;
  wb_2[2] = _mm_xor_si128(wb_1[2], *tweak_pointer);
  wb_2[3] = _mm_xor_si128(wb_1[3], *tweak_pointer);
  ++tweak;
  wb_2[4] = _mm_xor_si128(wb_1[4], *tweak_pointer);
  wb_2[5] = _mm_xor_si128(wb_1[5], *tweak_pointer);
  for (std::size_t j = 0; j < 6; ++j) wb_2[j] = _mm_xor_si128(wb_2[j], round_keys[0]);
  for (std::size_t j = 0; j < 6; ++j) wb_2[j] = _mm_aesenc_si128(wb_2[j], round_keys[1]);
  for (std::size_t j = 0; j < 6; ++j) wb_2[j] = _mm_aesenc_si128(wb_2[j], round_keys[2]);
  for (std::size_t j = 0; j < 6; ++j) wb_2[j] = _mm_aesenc_si128(wb_2[j], round_keys[3]);
  for (std::size_t j = 0; j < 6; ++j) wb_2[j] = _mm_aesenc_si128(wb_2[j], round_keys[4]);
  for (std::size_t j = 0; j < 6; ++j) wb_2[j] = _mm_aesenc_si128(wb_2[j], round_keys[5]);
  for (std::size_t j = 0; j < 6; ++j) wb_2[j] = _mm_aesenc_si128(wb_2[j], round_keys[6]);
  for (std::size_t j = 0; j < 6; ++j) wb_2[j] = _mm_aesenc_si128(wb_2[j], round_keys[7]);
  for (std::size_t j = 0; j < 6; ++j) wb_2[j] = _mm_aesenc_si128(wb_2[j], round_keys[8]);
  for (std::size_t j = 0; j < 6; ++j) wb_2[j] = _mm_aesenc_si128(wb_2[j], round_keys[9]);
  for (std::size_t j = 0; j < 6; ++j) wb_2[j] = _mm_aesenclast_si128(wb_2[j], round_keys[10]);

  // store \pi(\pi(x) ^ i) ^ \pi(x)
  for (std::size_t j = 0; j < 6; ++j) input_pointer[j] = _mm_xor_si128(wb_2[j], wb_1[j]);
}

void AesniTmmoBatch3(const void* round_keys_input, void* input, __uint128_t tweak) {
  alignas(16) std::array<__m128i, kAesNumRoundKeys128> round_keys;
  alignas(16) std::array<__m128i, 3> wb_1;
  alignas(16) std::array<__m128i, 3> wb_2;

  // copy the round keys onto the stack
  // -> compiler will put them into registers
  std::copy(reinterpret_cast<__m128i*>(__builtin_assume_aligned(round_keys_input, kAesBlockSize)),
            reinterpret_cast<__m128i*>(__builtin_assume_aligned(round_keys_input, kAesBlockSize)) +
                kAesNumRoundKeys128,
            round_keys.data());
  auto input_pointer = reinterpret_cast<__m128i*>(input);
  auto tweak_pointer = reinterpret_cast<__m128i*>(&tweak);

  // compute wb_1 <- \pi(x)
  for (std::size_t j = 0; j < 3; ++j) wb_1[j] = _mm_xor_si128(input_pointer[j], round_keys[0]);
  for (std::size_t j = 0; j < 3; ++j) wb_1[j] = _mm_aesenc_si128(wb_1[j], round_keys[1]);
  for (std::size_t j = 0; j < 3; ++j) wb_1[j] = _mm_aesenc_si128(wb_1[j], round_keys[2]);
  for (std::size_t j = 0; j < 3; ++j) wb_1[j] = _mm_aesenc_si128(wb_1[j], round_keys[3]);
  for (std::size_t j = 0; j < 3; ++j) wb_1[j] = _mm_aesenc_si128(wb_1[j], round_keys[4]);
  for (std::size_t j = 0; j < 3; ++j) wb_1[j] = _mm_aesenc_si128(wb_1[j], round_keys[5]);
  for (std::size_t j = 0; j < 3; ++j) wb_1[j] = _mm_aesenc_si128(wb_1[j], round_keys[6]);
  for (std::size_t j = 0; j < 3; ++j) wb_1[j] = _mm_aesenc_si128(wb_1[j], round_keys[7]);
  for (std::size_t j = 0; j < 3; ++j) wb_1[j] = _mm_aesenc_si128(wb_1[j], round_keys[8]);
  for (std::size_t j = 0; j < 3; ++j) wb_1[j] = _mm_aesenc_si128(wb_1[j], round_keys[9]);
  for (std::size_t j = 0; j < 3; ++j) wb_1[j] = _mm_aesenclast_si128(wb_1[j], round_keys[10]);

  // compute wb_2 <- \pi(\pi(x) ^ i)
  tweak *= 3;
  tweak -= 3;
  wb_2[0] = _mm_xor_si128(wb_1[0], *tweak_pointer);
  ++tweak;
  wb_2[1] = _mm_xor_si128(wb_1[1], *tweak_pointer);
  ++tweak;
  wb_2[2] = _mm_xor_si128(wb_1[2], *tweak_pointer);
  for (std::size_t j = 0; j < 3; ++j) wb_2[j] = _mm_xor_si128(wb_2[j], round_keys[0]);
  for (std::size_t j = 0; j < 3; ++j) wb_2[j] = _mm_aesenc_si128(wb_2[j], round_keys[1]);
  for (std::size_t j = 0; j < 3; ++j) wb_2[j] = _mm_aesenc_si128(wb_2[j], round_keys[2]);
  for (std::size_t j = 0; j < 3; ++j) wb_2[j] = _mm_aesenc_si128(wb_2[j], round_keys[3]);
  for (std::size_t j = 0; j < 3; ++j) wb_2[j] = _mm_aesenc_si128(wb_2[j], round_keys[4]);
  for (std::size_t j = 0; j < 3; ++j) wb_2[j] = _mm_aesenc_si128(wb_2[j], round_keys[5]);
  for (std::size_t j = 0; j < 3; ++j) wb_2[j] = _mm_aesenc_si128(wb_2[j], round_keys[6]);
  for (std::size_t j = 0; j < 3; ++j) wb_2[j] = _mm_aesenc_si128(wb_2[j], round_keys[7]);
  for (std::size_t j = 0; j < 3; ++j) wb_2[j] = _mm_aesenc_si128(wb_2[j], round_keys[8]);
  for (std::size_t j = 0; j < 3; ++j) wb_2[j] = _mm_aesenc_si128(wb_2[j], round_keys[9]);
  for (std::size_t j = 0; j < 3; ++j) wb_2[j] = _mm_aesenclast_si128(wb_2[j], round_keys[10]);

  // store \pi(\pi(x) ^ i) ^ \pi(x)
  for (std::size_t j = 0; j < 3; ++j) input_pointer[j] = _mm_xor_si128(wb_2[j], wb_1[j]);
}

void AesniMmoSingle(const void* round_keys_input, void* input) {
  alignas(16) __m128i input_block;
  alignas(16) __m128i wb_1;
  auto input_pointer = reinterpret_cast<__m128i*>(input);
  auto round_keys =
      reinterpret_cast<__m128i*>(__builtin_assume_aligned(round_keys_input, kAesBlockSize));

  // load x
  input_block = *input_pointer;
  // compute wb_1 <- \pi(x)
  wb_1 = _mm_xor_si128(input_block, round_keys[0]);
  wb_1 = _mm_aesenc_si128(wb_1, round_keys[1]);
  wb_1 = _mm_aesenc_si128(wb_1, round_keys[2]);
  wb_1 = _mm_aesenc_si128(wb_1, round_keys[3]);
  wb_1 = _mm_aesenc_si128(wb_1, round_keys[4]);
  wb_1 = _mm_aesenc_si128(wb_1, round_keys[5]);
  wb_1 = _mm_aesenc_si128(wb_1, round_keys[6]);
  wb_1 = _mm_aesenc_si128(wb_1, round_keys[7]);
  wb_1 = _mm_aesenc_si128(wb_1, round_keys[8]);
  wb_1 = _mm_aesenc_si128(wb_1, round_keys[9]);
  wb_1 = _mm_aesenclast_si128(wb_1, round_keys[10]);
  // store \pi(x) ^ x
  *input_pointer = _mm_xor_si128(wb_1, input_block);
}

static __m128i AesniMixKeys(__m128i key_a, __m128i key_b) {
  const __m128i modulus = _mm_set_epi32(0, 0, 0, 0x87);
  const __m128i msb_mask = _mm_set_epi32(0x80000000, 0, 0, 0);
  __m128i mixed_keys = key_a;
  int msb_zero = _mm_testz_si128(mixed_keys, msb_mask);
  mixed_keys <<= 1;
  if (!msb_zero) {
    mixed_keys ^= modulus;
  }
  mixed_keys ^= key_b;
  msb_zero = _mm_testz_si128(mixed_keys, msb_mask);
  mixed_keys <<= 1;
  if (!msb_zero) {
    mixed_keys ^= modulus;
  }
  return mixed_keys;
}

static __m128i AesniXorEncrypt(const __m128i* round_keys, __m128i in) {
  __m128i wb;
  wb = _mm_xor_si128(in, round_keys[0]);
  wb = _mm_aesenc_si128(wb, round_keys[1]);
  wb = _mm_aesenc_si128(wb, round_keys[2]);
  wb = _mm_aesenc_si128(wb, round_keys[3]);
  wb = _mm_aesenc_si128(wb, round_keys[4]);
  wb = _mm_aesenc_si128(wb, round_keys[5]);
  wb = _mm_aesenc_si128(wb, round_keys[6]);
  wb = _mm_aesenc_si128(wb, round_keys[7]);
  wb = _mm_aesenc_si128(wb, round_keys[8]);
  wb = _mm_aesenc_si128(wb, round_keys[9]);
  wb = _mm_aesenclast_si128(wb, round_keys[10]);
  return wb ^ in;
}

void AesniBmrDkc(const void* round_keys_input, const void* key_a, const void* key_b,
                 std::uint64_t gate_id, std::size_t number_of_parties, void* output_input_pointer) {
  auto key_a_pointer =
      reinterpret_cast<const __m128i*>(__builtin_assume_aligned(key_a, kAesBlockSize));
  auto key_b_pointer =
      reinterpret_cast<const __m128i*>(__builtin_assume_aligned(key_b, kAesBlockSize));
  auto round_keys =
      reinterpret_cast<const __m128i*>(__builtin_assume_aligned(round_keys_input, kAesBlockSize));
  auto out =
      reinterpret_cast<__m128i*>(__builtin_assume_aligned(output_input_pointer, kAesBlockSize));
  __m128i mixed_keys = AesniMixKeys(*key_a_pointer, *key_b_pointer);
  for (std::size_t party_id = 0; party_id < number_of_parties; ++party_id) {
    __m128i tmp = mixed_keys ^ _mm_set_epi64x(gate_id, party_id);
    out[party_id] ^= AesniXorEncrypt(round_keys, tmp);
  }
}
