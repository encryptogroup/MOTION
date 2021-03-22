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

#include <gtest/gtest.h>
#include <random>
#include "algorithm/low_depth_reduce.h"

/**
 * Struct with a function that calculates the depth of the operation, after the given inputs are
 * operated.
 */
template <typename T>
struct CalculateDepth {
  T operator()(const T& left, const T& right) const { return std::max(left, right) + 1; }
};

/**
 * Class to set up the tests.
 */
class LowDepthReduceTest : public ::testing::TestWithParam<int> {
 public:
  void SetUp() override {
    // Generate a random vector of integer values
    std::mt19937 gen1(1);                              // Generate randomness seeded with 1
    std::uniform_int_distribution<> distrib1(1, 100);  // Random between 1 and 100
    for (std::size_t i = 0; i < size; i++) integer_values.push_back(distrib1(gen1));

    // Generate a random vector of boolean
    std::mt19937_64 gen2(1);                    // Generate pseudo-randomness seeded with 1
    std::bernoulli_distribution distrib2(0.5);  // Random between true or false
    for (std::size_t i = 0; i < size; i++) boolean_values.push_back(distrib2(gen2));
  }

 protected:
  int size = GetParam();
  std::vector<std::uint32_t> integer_values;
  std::vector<bool> boolean_values;
};

/**
 * This test-function calculates the total depth of the operation and compares it with the expected
 * depth. The expected depth is defined as the ceiling of the logarithm to the basis 2 of the total
 * leaves, which in this case is 'size'. The real depth itself will be calculated by defining a
 * vector that contains only zeros with 'size' as the length. Using the function operator() in
 * 'CalculateDepth' struct and given the vector = | 0 | 0 | 0 | 0 | 0 | with size = 5, the
 * calculation will be shown as the following,
 *
 * 0   0 0  0  0
 *  \ /  \ /  /
 *   1    1  0
 *    \  /  /
 *     2   0
 *      \ /
 *       3
 */

TEST_P(LowDepthReduceTest, OperationDepth) {
  std::vector<std::uint32_t> input(size, 0);
  int expected_depth = static_cast<std::size_t>(std::ceil(std::log2(size)));
  int result_depth = LowDepthReduce(input, CalculateDepth<std::uint32_t>());
  ASSERT_EQ(result_depth, expected_depth);
}

TEST_P(LowDepthReduceTest, BitwiseXor) {
  int expected_xor = integer_values[0];
  for (std::size_t i = 1; i < integer_values.size(); i++) expected_xor ^= integer_values[i];
  int result_xor = LowDepthReduce(integer_values, std::bit_xor<>());
  ASSERT_EQ(result_xor, expected_xor);
}

TEST_P(LowDepthReduceTest, BitwiseOr) {
  int expected_or = integer_values[0];
  for (std::size_t i = 1; i < integer_values.size(); i++) expected_or |= integer_values[i];
  int result_or = LowDepthReduce(integer_values, std::bit_or<>());
  ASSERT_EQ(result_or, expected_or);
}

TEST_P(LowDepthReduceTest, BitwiseAnd) {
  int expected_and = boolean_values[0];
  for (std::size_t i = 1; i < boolean_values.size(); i++) expected_and &= boolean_values[i];
  int result_and = LowDepthReduce(boolean_values, std::bit_and<>());
  ASSERT_EQ(result_and, expected_and);
}

TEST_P(LowDepthReduceTest, BitwiseMul) {
  int expected_mul = integer_values[0];
  for (std::size_t i = 1; i < integer_values.size(); i++) expected_mul *= integer_values[i];
  int result_mul = LowDepthReduce(integer_values, std::multiplies<>());
  ASSERT_EQ(result_mul, expected_mul);
}

TEST_P(LowDepthReduceTest, BitwiseAdd) {
  int expected_add = integer_values[0];
  for (std::size_t i = 1; i < integer_values.size(); i++) expected_add += integer_values[i];
  int result_add = LowDepthReduce(integer_values, std::plus<>());
  ASSERT_EQ(result_add, expected_add);
}

INSTANTIATE_TEST_SUITE_P(LowDepthReduceTestParameters, LowDepthReduceTest,
                         testing::Values(1, 2, 3, 4, 7, 8, 16, 17, 23, 32, 53, 64, 100,
                                         999999));  // Different sizes for the vector inputs
