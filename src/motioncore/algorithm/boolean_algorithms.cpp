// MIT License
//
// Copyright (c) 2021 Oleksandr Tkachenko
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

#include "boolean_algorithms.h"

#include <algorithm>
#include <cassert>
#include <cmath>

#include "protocols/share.h"

namespace encrypto::motion::algorithm {

std::pair<ShareWrapper, ShareWrapper> FullAdder(const ShareWrapper& a, const ShareWrapper& b,
                                                const ShareWrapper& carry) {
  for (auto& s [[maybe_unused]] : {a, b, carry}) assert(s->GetBitLength() == 1);
  auto a_xor_b{a ^ b};
  auto sum{a_xor_b ^ carry};
  // equivalent to carry_out = (a & b) | (a & carry) | (b & carry)
  auto carry_out{(a_xor_b & (b ^ carry)) ^ b};

  return std::pair(std::move(sum), std::move(carry_out));
}

ShareWrapper AdderChain(const ShareWrapper& bit_string_0, const ShareWrapper& bit_string_1,
                        const ShareWrapper& carry_in) {
  std::vector<ShareWrapper> bits_0{bit_string_0.Split()};
  std::vector<ShareWrapper> bits_1{bit_string_1.Split()};
  return AdderChain(bits_0, bits_1, carry_in);
}

ShareWrapper AdderChain(std::span<const ShareWrapper> bits_0, std::span<const ShareWrapper> bits_1,
                        const ShareWrapper& carry_in) {
  if (!bits_0.empty()) assert(bits_0[0]->GetCircuitType() == CircuitType::kBoolean);
  if (!bits_1.empty()) assert(bits_1[0]->GetCircuitType() == CircuitType::kBoolean);
  assert(!bits_0.empty() || !bits_1.empty());

  // inlining seems to be causing constexpr retrieval of size which yields the extent and not the
  // actual runtime size, i.e., max std::size
  // not sure how to avoid it in a more elegant way...
  std::size_t bits_0_length = bits_0.size(), bits_1_length = bits_1.size();
  auto [min_length, max_length] = std::minmax(bits_0_length, bits_1_length);

  // allocate wires
  std::vector<ShareWrapper> result_wires(max_length + 1);

  // compute the output wires using full adders for bit strings of equal size
  ShareWrapper carry{carry_in};
  std::size_t i = 0;
  for (; i < min_length; ++i) {
    std::tie(result_wires[i], carry) = FullAdder(bits_0[i], bits_1[i], carry);
  }

  // if shares are of unequal size, compute the remaining part using only the longer share
  std::span<const ShareWrapper> long_share{bits_0.size() > bits_1.size() ? bits_0 : bits_1};

  for (; i < max_length; ++i) {
    result_wires[i] = long_share[i] ^ carry;
    carry = long_share[i] & carry;
  }

  // save the carry bit for the case of an overflow
  result_wires.back() = carry;

  // concatenate wires into a single share
  return ShareWrapper::Concatenate(result_wires);
}

ShareWrapper HammingWeight(const ShareWrapper& bit_string) {
  std::vector<ShareWrapper> bits{bit_string.Split()};
  return HammingWeight(bits);
}

ShareWrapper HammingWeight(std::span<const ShareWrapper> bits) {
  if (bits.size() == 0) {
    return ShareWrapper(nullptr);
  } else if (bits.size() == 1) {
    // HW(bit) = bit
    return bits[0];
  } else if (bits.size() == 2) {
    // return {sum (0th pos.), carry (1st pos.)}
    return ShareWrapper::Concatenate({bits[0] ^ bits[1], bits[0] & bits[1]});
  } else if (bits.size() == 3) {
    // use full adder
    // FullAdder returns
    auto [sum, carry] = FullAdder(bits[0], bits[1], bits[2]);
    return ShareWrapper::Concatenate({sum, carry});
  } else {  // bits.size() > 3
    // split the input bit string into three parts: v, u and i
    // length of v is the largest possible power of two - 1, e.g., 3, 7, 15, etc
    // length of u is total length - length of v - 1
    // length of i is always 1
    size_t length_v{static_cast<std::size_t>(std::pow(2, std::floor(log2(bits.size())))) - 1};
    size_t length_u{bits.size() - length_v - 1};

    auto v{bits.first(length_v)};
    auto u{bits.subspan(length_v, length_u)};
    ShareWrapper i{bits.back()};

    return AdderChain(HammingWeight(v), HammingWeight(u), i);
  }
}

}  // namespace encrypto::motion::algorithm