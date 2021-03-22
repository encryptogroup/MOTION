// MIT License
//
// Copyright (c) 2021 Arianne Roselina Prananto
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

#include <vector>

/**
 * This general function runs the iterative implementation of the given vector input and the
 * operation. As a graphic example, given the vector input = | a | b | c | d | e |. The calculation
 * will be shown as,
 *
 * a    b  c    d  e
 *  \  /    \  /  /
 *   ab      cd  e      Depth = 1
 *     \    /  /
 *      abcd  e         Depth = 2
 *        \  /
 *       abcde          Depth = 3
 */

template <typename T, typename BinaryOperation>
T LowDepthReduce(std::vector<T> input, BinaryOperation operation) {
  for (std::size_t i = 1; i < input.size(); i *= 2) {
    for (std::size_t j = 0; (j + i) < input.size(); j += i * 2)
      input[j] = operation(input[j], input[j + i]);
  }
  return input[0];
}
