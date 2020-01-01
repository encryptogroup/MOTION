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

#pragma once

#include <cassert>
#include <optional>
#include <vector>

#include "utility/typedefs.h"

namespace ENCRYPTO {

struct PrimitiveOperation {
  PrimitiveOperationType type_{INVALID_PrimitiveOperationType};
  std::size_t parent_a_{0};
  std::optional<std::size_t> parent_b_{std::nullopt};
  std::optional<std::size_t> selection_bit_{std::nullopt};
  std::size_t output_wire_{0};
};

struct AlgorithmDescription {
  AlgorithmDescription() = default;

  static AlgorithmDescription FromBristol(const std::string& path);

  static AlgorithmDescription FromBristol(std::string&& path);

  static AlgorithmDescription FromBristol(std::ifstream& stream);

  static AlgorithmDescription FromABY(const std::string& path);

  static AlgorithmDescription FromABY(std::string&& path);

  static AlgorithmDescription FromABY(std::ifstream& stream);

  std::size_t n_output_wires_{0}, n_input_wires_parent_a_{0}, n_wires_{0}, n_gates_{0};
  std::optional<std::size_t> n_input_wires_parent_b_{std::nullopt};
  std::vector<PrimitiveOperation> gates_;
};

}