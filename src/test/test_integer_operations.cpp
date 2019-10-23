// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko
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

#include <fstream>
#include <random>

#include <gtest/gtest.h>

#include "algorithm/algorithm_description.h"
#include "secure_type/secure_unsigned_integer.h"
#include "utility/config.h"

#include "test_constants.h"

namespace {
TEST(AlgorithmDescription, FromBristolFormat__int_add8_size) {
  auto int_add8 = ENCRYPTO::AlgorithmDescription::FromBristol(
      std::string(MOTION::MOTION_ROOT_DIR) + "/circuits/int/int_add8_size.bristol");
  EXPECT_EQ(int_add8.n_gates_, 34);
  EXPECT_EQ(int_add8.gates_.size(), 34);
  EXPECT_EQ(int_add8.n_output_wires_, 8);
  EXPECT_EQ(int_add8.n_input_wires_parent_a_, 8);
  ASSERT_NO_THROW([&int_add8]() { EXPECT_EQ(*int_add8.n_input_wires_parent_b_, 8); });
  EXPECT_EQ(int_add8.n_wires_, 50);

  const auto& gate0 = int_add8.gates_.at(0);
  EXPECT_EQ(gate0.parent_a_, 0);
  ASSERT_NO_THROW([&gate0]() { EXPECT_EQ(*gate0.parent_b_, 8); });
  EXPECT_EQ(gate0.output_wire_, 42);
  EXPECT_EQ(gate0.type_, ENCRYPTO::PrimitiveOperationType::XOR);
  EXPECT_EQ(gate0.selection_bit_.has_value(), false);

  const auto& gate1 = int_add8.gates_.at(1);
  EXPECT_EQ(gate1.parent_a_, 0);
  ASSERT_NO_THROW([&gate1]() { EXPECT_EQ(*gate1.parent_b_, 8); });
  EXPECT_EQ(gate1.output_wire_, 16);
  EXPECT_EQ(gate1.type_, ENCRYPTO::PrimitiveOperationType::AND);
  EXPECT_EQ(gate1.selection_bit_.has_value(), false);

  const auto& gate32 = int_add8.gates_.at(32);
  EXPECT_EQ(gate32.parent_a_, 15);
  ASSERT_NO_THROW([&gate32]() { EXPECT_EQ(*gate32.parent_b_, 40); });
  EXPECT_EQ(gate32.output_wire_, 41);
  EXPECT_EQ(gate32.type_, ENCRYPTO::PrimitiveOperationType::XOR);
  EXPECT_EQ(gate32.selection_bit_.has_value(), false);

  const auto& gate33 = int_add8.gates_.at(33);
  EXPECT_EQ(gate33.parent_a_, 7);
  ASSERT_NO_THROW([&gate33]() { EXPECT_EQ(*gate33.parent_b_, 41); });
  EXPECT_EQ(gate33.output_wire_, 49);
  EXPECT_EQ(gate33.type_, ENCRYPTO::PrimitiveOperationType::XOR);
  EXPECT_EQ(gate33.selection_bit_.has_value(), false);
}

TEST(AlgorithmDescription, FromBristolFormat) {
  auto int_add8 = ENCRYPTO::AlgorithmDescription::FromBristol(
      std::string(MOTION::MOTION_ROOT_DIR) + "/circuits/int/int_add8_size.bristol");
}
}  // namespace
