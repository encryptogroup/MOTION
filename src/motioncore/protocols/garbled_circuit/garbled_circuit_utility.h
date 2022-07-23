// MIT License
//
// Copyright (c) 2021-2022 Oleksandr Tkachenko
// Cryptography and Privacy Engineering Group (ENCRYPTO)
// TU Darmstadt, Germany
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

#include <array>

#include "primitives/random/openssl_rng.h"
#include "utility/bit_vector.h"

namespace encrypto::motion::proto::garbled_circuit {

/// @param p_a permutation bit from the left input wire, i.e., wire A
/// @param p_b permutation bit from the right input wire, i.e., wire B
/// @param random_choice randomly samples an R$ from range [0, 3]
static std::byte SampleWireMapping(bool p_a, bool p_b, std::size_t random_choice) {
  static constexpr std::byte compressed_R_a{std::byte(0b01101100)};
  static constexpr std::byte compressed_R_b{std::byte(0b10110100)};
  // Randomly sample R from span with precomputed choices.
  // The parity matrix R_p is not in the subspace S hence it is not easy to compress,
  // but it is public information, so the evaluator xors it on top of the decoded result
  // themselves
  static constexpr std::array compressed_R_span = {std::byte(0), std::byte(0b01010101),
                                                   std::byte(0b10101010), std::byte(0b11111111)};

  std::byte selected_R{compressed_R_span[static_cast<std::size_t>(random_choice) % 4]};
  std::byte selected_R_a = p_a ? std::byte(0) : compressed_R_a;
  std::byte selected_R_b = p_b ? std::byte(0) : compressed_R_b;

  return selected_R ^ selected_R_a ^ selected_R_b;
}

static constexpr std::array<std::array<std::byte, 4>, 256> GenerateLutForDecoding() {
  // S1 = | 1 1 | 1 0 |
  //      | 1 0 | 0 1 |
  constexpr std::byte S1{std::byte(0b10010111)};
  // S2 = | 1 0 | 0 1 |
  //      | 0 1 | 1 1 |
  constexpr std::byte S2{std::byte(0b11101001)};
  constexpr std::array two_row_lut = {std::byte(0), S1, S2, S1 ^ S2};
  constexpr std::size_t array_size{256};

  std::array<std::array<std::byte, 4>, array_size> lut;
  for (std::size_t i = 0; i < array_size; ++i) {
    lut[i] = std::array<std::byte, 4>{two_row_lut[i & 3], two_row_lut[(i >> 2) & 3],
                                      two_row_lut[(i >> 4) & 3], two_row_lut[(i >> 6) & 3]};
  }
  return lut;
}

// Don't apply R_p in this function
static inline std::byte DecodeCompressedWireMapping(bool choose_S1, bool choose_S2) {
  // S1 = | 1 1 | 1 0 |
  //      | 1 0 | 0 1 |
  constexpr std::byte S1{std::byte(0b10010111)};
  // S2 = | 1 0 | 0 1 |
  //      | 0 1 | 1 1 |
  constexpr std::byte S2{std::byte(0b11101001)};
  constexpr std::array two_row_lut = {std::byte(0), S1, S2, S1 ^ S2};
  auto index{static_cast<std::size_t>((choose_S1 ? 1 : 0) + (choose_S2 ? 2 : 0))};
  return two_row_lut[index];
}

}  // namespace encrypto::motion::proto::garbled_circuit