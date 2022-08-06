
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

#pragma once

#include "protocols/share_wrapper.h"

namespace encrypto::motion::algorithm {

/// \brief computes the binary full adder gate, i.e., adds the 3 input bits.
/// \param bit_0 first input bit
/// \param bit_1 second input bit
/// \param carry input carry bit (useful in adder chains, see AdderChain)
/// \returns the sum of the inputs and the carry out bit, which indicates the overflow, i.e., at
/// least two input bits are equal to one.
/// \asserts that the function arguments are not ill-formed, e.g., of arithmetic type or contain
/// multiple bits.
std::pair<ShareWrapper, ShareWrapper> FullAdder(const ShareWrapper& bit_0,
                                                const ShareWrapper& bit_1,
                                                const ShareWrapper& carry);

/// \brief
ShareWrapper AdderChain(const ShareWrapper& bit_string_0, const ShareWrapper& bit_string_1,
                        const ShareWrapper& carry_in);

ShareWrapper AdderChain(std::span<const ShareWrapper> bits_0, std::span<const ShareWrapper> bits_1,
                        const ShareWrapper& carry_in);

ShareWrapper HammingWeight(const ShareWrapper& bit_string);

ShareWrapper HammingWeight(std::span<const ShareWrapper> bits);

}  // namespace encrypto::motion::algorithm