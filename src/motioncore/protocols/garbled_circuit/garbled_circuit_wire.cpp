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

#include "garbled_circuit_wire.h"

#include "base/backend.h"
#include "base/register.h"

namespace encrypto::motion::proto::garbled_circuit {

Wire::Wire(Backend& backend, size_t number_of_simd) : BooleanWire(backend, number_of_simd) {}

Wire::Wire(Block128Vector&& wire_labels, Backend& backend)
    : BooleanWire(backend, wire_labels.size()), wire_labels_(std::move(wire_labels)) {}

Wire::Wire(const Block128Vector& wire_labels, Backend& backend)
    : BooleanWire(backend, wire_labels.size()), wire_labels_(wire_labels) {}

BitVector<> Wire::CopyPermutationBits() const {
  return encrypto::motion::proto::garbled_circuit::CopyPermutationBits(wire_labels_);
}

BitVector<> CopyPermutationBits(const Block128Vector& keys) {
  // copy MSB of each key buffer to the output buffer
  BitVector<> permutation_bits;
  permutation_bits.Resize(keys.size(), true);
  std::size_t simd_i = 0;
  constexpr std::byte msb_mask{0b10000000};
  while ((keys.size() - simd_i) >= 8) {
    // Copy 8 next permutation bits in-place
    permutation_bits.GetMutableData()[simd_i / 8] |=
        (keys[simd_i].data()[Block128::kBlockSize - 1] >> 7) ^
        ((keys[simd_i + 1].data()[Block128::kBlockSize - 1] & msb_mask) >> 6) ^
        ((keys[simd_i + 2].data()[Block128::kBlockSize - 1] & msb_mask) >> 5) ^
        ((keys[simd_i + 3].data()[Block128::kBlockSize - 1] & msb_mask) >> 4) ^
        ((keys[simd_i + 4].data()[Block128::kBlockSize - 1] & msb_mask) >> 3) ^
        ((keys[simd_i + 5].data()[Block128::kBlockSize - 1] & msb_mask) >> 2) ^
        ((keys[simd_i + 6].data()[Block128::kBlockSize - 1] & msb_mask) >> 1) ^
        ((keys[simd_i + 7].data()[Block128::kBlockSize - 1] & msb_mask));
    simd_i += 8;
  }

  for (; simd_i < keys.size(); ++simd_i) {
    std::size_t bit_remainder{simd_i % 8};
    std::size_t shift{7 - bit_remainder};
    permutation_bits.GetMutableData()[simd_i / 8] |=
        ((keys[simd_i].data()[Block128::kBlockSize - 1] & msb_mask) >> shift);
  }
  return permutation_bits;
}

}  // namespace encrypto::motion::proto::garbled_circuit
