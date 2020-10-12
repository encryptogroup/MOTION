// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko, Lennart Braun
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

#include <cassert>
#include <optional>
#include <vector>

#include "utility/typedefs.h"

namespace encrypto::motion {

struct PrimitiveOperation {
  PrimitiveOperationType type{PrimitiveOperationType::kInvalid};
  std::size_t parent_a{0};
  std::optional<std::size_t> parent_b{std::nullopt};
  std::optional<std::size_t> selection_bit{std::nullopt};
  std::size_t output_wire{0};
};

struct AlgorithmDescription {
  AlgorithmDescription() = default;

  static AlgorithmDescription FromBristol(const std::string& path);

  static AlgorithmDescription FromBristol(std::string&& path);

  static AlgorithmDescription FromBristol(std::ifstream& stream);

  static AlgorithmDescription FromBristolFashion(const std::string& path);

  static AlgorithmDescription FromBristolFashion(std::string&& path);

  static AlgorithmDescription FromBristolFashion(std::ifstream& stream);

  static AlgorithmDescription FromAby(const std::string& path);

  static AlgorithmDescription FromAby(std::string&& path);

  static AlgorithmDescription FromAby(std::ifstream& stream);

  std::size_t number_of_output_wires{0}, number_of_input_wires_parent_a{0}, number_of_wires{0},
      number_of_gates{0};
  std::optional<std::size_t> number_of_input_wires_parent_b{std::nullopt};
  std::vector<PrimitiveOperation> gates;
};

}  // namespace encrypto::motion
