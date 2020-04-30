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

#include <immintrin.h>
#include <algorithm>
#include <array>
#include "aesni_primitives.h"

template <int round_constant>
static __m128i aes_key_expand(__m128i xmm1) {
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
void aesni_key_expansion_128(void* round_keys_in) {
  __m128i* round_keys =
      reinterpret_cast<__m128i*>(__builtin_assume_aligned(round_keys_in, aes_block_size));
  // movdqa xmm1, [rsi]
  // movdqa [rdi], xmm1
  round_keys[1] = aes_key_expand<0x01>(round_keys[0]);
  // aes_key_expand 0x01
  // movdqa 0x10[rdi], xmm1
  round_keys[2] = aes_key_expand<0x02>(round_keys[1]);
  // aes_key_expand 0x02
  // movdqa 0x20[rdi], xmm1
  round_keys[3] = aes_key_expand<0x04>(round_keys[2]);
  // aes_key_expand 0x04
  // movdqa 0x30[rdi], xmm1
  round_keys[4] = aes_key_expand<0x08>(round_keys[3]);
  // aes_key_expand 0x08
  // movdqa 0x40[rdi], xmm1
  round_keys[5] = aes_key_expand<0x10>(round_keys[4]);
  // aes_key_expand 0x10
  // movdqa 0x50[rdi], xmm1
  round_keys[6] = aes_key_expand<0x20>(round_keys[5]);
  // aes_key_expand 0x20
  // movdqa 0x60[rdi], xmm1
  round_keys[7] = aes_key_expand<0x40>(round_keys[6]);
  // aes_key_expand 0x40
  // movdqa 0x70[rdi], xmm1
  round_keys[8] = aes_key_expand<0x80>(round_keys[7]);
  // aes_key_expand 0x80
  // movdqa 0x80[rdi], xmm1
  round_keys[9] = aes_key_expand<0x1b>(round_keys[8]);
  // aes_key_expand 0x1b
  // movdqa 0x90[rdi], xmm1
  round_keys[10] = aes_key_expand<0x36>(round_keys[9]);
  // aes_key_expand 0x36
  // movdqa 0xa0[rdi], xmm1
}

void aesni_ctr_stream_blocks_128(const void* round_keys_in, std::uint64_t* counter_in,
                                 void* output_in, std::size_t num_blocks) {
  alignas(16) std::array<__m128i, aes_num_round_keys_128> round_keys;
  alignas(16) std::array<__m128i, 4> wb;
  auto wb_as_uint64s = reinterpret_cast<std::uint64_t*>(wb.data());
  auto counter = *counter_in;

  // we assume the output buffer is aligned
  auto output = reinterpret_cast<__m128i*>(__builtin_assume_aligned(output_in, aes_block_size));

  // copy the round keys onto the stack
  // -> compiler will put them into registers
  std::copy(reinterpret_cast<__m128i*>(__builtin_assume_aligned(round_keys_in, aes_block_size)),
            reinterpret_cast<__m128i*>(__builtin_assume_aligned(round_keys_in, aes_block_size)) +
                aes_num_round_keys_128,
            round_keys.data());

  // do as many blocks as possible in 4er batches
  // since the aesenc instructions have a latency of 4
  auto batch_blocks = num_blocks & (~0b11);
  for (size_t i = 0; i < batch_blocks; i += 4) {
    std::fill(reinterpret_cast<std::byte*>(wb.data()), reinterpret_cast<std::byte*>(wb.data() + 4),
              std::byte(0x00));
    for (std::size_t j = 0; j < 4; ++j) wb_as_uint64s[2 * j] = counter + j;
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
  for (size_t i = batch_blocks; i < num_blocks; ++i) {
    wb_as_uint64s[0] = counter;
    wb_as_uint64s[1] = 0;
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
  *counter_in = counter;
}

void aesni_ctr_stream_blocks_128_unaligned(const void* round_keys_in, std::uint64_t* counter_in,
                                 void* output_in, std::size_t num_blocks) {
  // almost the same code as in `aesni_ctr_stream_blocks_128_unaligned`

  alignas(16) std::array<__m128i, aes_num_round_keys_128> round_keys;
  alignas(16) std::array<__m128i, 4> wb;
  auto wb_as_uint64s = reinterpret_cast<std::uint64_t*>(wb.data());
  auto counter = *counter_in;

  // DIFFERENCE: we no longer assume that the output buffer is aligned
  auto output = reinterpret_cast<__m128i*>(output_in);

  // copy the round keys onto the stack
  // -> compiler will put them into registers
  std::copy(reinterpret_cast<__m128i*>(__builtin_assume_aligned(round_keys_in, aes_block_size)),
            reinterpret_cast<__m128i*>(__builtin_assume_aligned(round_keys_in, aes_block_size)) +
                aes_num_round_keys_128,
            round_keys.data());

  // do as many blocks as possible in 4er batches
  // since the aesenc instructions have a latency of 4
  auto batch_blocks = num_blocks & (~0b11);
  for (size_t i = 0; i < batch_blocks; i += 4) {
    std::fill(reinterpret_cast<std::byte*>(wb.data()), reinterpret_cast<std::byte*>(wb.data() + 4),
              std::byte(0x00));
    for (std::size_t j = 0; j < 4; ++j) wb_as_uint64s[2 * j] = counter + j;
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
  for (size_t i = batch_blocks; i < num_blocks; ++i) {
    wb_as_uint64s[0] = counter;
    wb_as_uint64s[1] = 0;
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
  *counter_in = counter;
}

void aesni_ctr_stream_single_block_128_unaligned(const void* round_keys_in, std::uint64_t* counter,
                                                 void* output) {
  auto round_keys =
      reinterpret_cast<__m128i*>(__builtin_assume_aligned(round_keys_in, aes_block_size));
  auto output_ptr = reinterpret_cast<__m128i*>(output);
  __m128i wb;
  auto wb_as_uint64s = reinterpret_cast<std::uint64_t*>(&wb);
  wb_as_uint64s[0] = (*counter)++;
  wb_as_uint64s[1] = 0;
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
  _mm_storeu_si128(output_ptr, wb);
}

void aesni_tmmo_batch_4(const void* round_keys_in, void* input, __uint128_t tweak) {
  alignas(16) std::array<__m128i, aes_num_round_keys_128> round_keys;
  alignas(16) std::array<__m128i, 4> wb_1;
  alignas(16) std::array<__m128i, 4> wb_2;

  // copy the round keys onto the stack
  // -> compiler will put them into registers
  std::copy(reinterpret_cast<__m128i*>(__builtin_assume_aligned(round_keys_in, aes_block_size)),
            reinterpret_cast<__m128i*>(__builtin_assume_aligned(round_keys_in, aes_block_size)) +
                aes_num_round_keys_128,
            round_keys.data());
  auto input_ptr = reinterpret_cast<__m128i*>(input);
  auto tweak_ptr = reinterpret_cast<__m128i*>(&tweak);

  // compute wb_1 <- \pi(x)
  for (std::size_t j = 0; j < 4; ++j) wb_1[j] = _mm_xor_si128(input_ptr[j], round_keys[0]);
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
  for (std::size_t j = 0; j < 4; ++j) wb_2[j] = _mm_xor_si128(wb_1[j], *tweak_ptr);
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
  for (std::size_t j = 0; j < 4; ++j) input_ptr[j] = _mm_xor_si128(wb_2[j], wb_1[j]);
}

void aesni_mmo_single(const void* round_keys_in, void* input) {
  alignas(16) __m128i input_block;
  alignas(16) __m128i wb_1;
  auto input_ptr = reinterpret_cast<__m128i*>(input);
  auto round_keys = reinterpret_cast<__m128i*>(__builtin_assume_aligned(round_keys_in, aes_block_size));

  // load x
  input_block = *input_ptr;
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
  *input_ptr = _mm_xor_si128(wb_1, input_block);
}

static __m128i aesni_mix_keys(__m128i key_a, __m128i key_b) {
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

static __m128i aesni_xor_encrypt(const __m128i* round_keys, __m128i in) {
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

void aesni_bmr_dkc(const void* round_keys_in, const void* key_a, const void* key_b,
                   std::uint64_t gate_id, std::size_t num_parties, void* output_in) {
  auto key_a_ptr =
      reinterpret_cast<const __m128i*>(__builtin_assume_aligned(key_a, aes_block_size));
  auto key_b_ptr =
      reinterpret_cast<const __m128i*>(__builtin_assume_aligned(key_b, aes_block_size));
  auto round_keys =
      reinterpret_cast<const __m128i*>(__builtin_assume_aligned(round_keys_in, aes_block_size));
  auto out = reinterpret_cast<__m128i*>(__builtin_assume_aligned(output_in, aes_block_size));
  __m128i mixed_keys = aesni_mix_keys(*key_a_ptr, *key_b_ptr);
  for (std::size_t party_id = 0; party_id < num_parties; ++party_id) {
    __m128i tmp = mixed_keys ^ _mm_set_epi64x(gate_id, party_id);
    out[party_id] ^= aesni_xor_encrypt(round_keys, tmp);
  }
}
