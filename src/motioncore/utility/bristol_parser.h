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

#include <cassert>
#include <optional>
#include <vector>

namespace ENCRYPTO {

enum PrimitiveOperationType : std::uint8_t {
  XOR = 0,  // for Boolean circuit only
  AND = 1,  // for Boolean circuit only
  MUX = 2,  // for Boolean circuit only
  INV = 3,  // for Boolean circuit only
  ADD = 4,  // for arithmetic circuit only
  MUL = 5,  // for arithmetic circuit only
  INVALID = 6
};

struct PrimitiveOperation {
  PrimitiveOperationType type_{INVALID};
  std::size_t parent_a_{0};
  std::optional<std::size_t> parent_b_{std::nullopt};
  std::optional<std::size_t> selection_bit_{std::nullopt};
  std::size_t output_wire_{0};
};

struct AlgorithmDescription {
  AlgorithmDescription() = default;

  static AlgorithmDescription FromBristol(std::ifstream& stream);

  std::size_t n_output_wires_{0}, n_input_wires_parent_a_{0}, total_n_wires_{0}, n_gates_{0};
  std::optional<std::size_t> n_input_wires_parent_b_{std::nullopt};
  std::vector<PrimitiveOperation> gates_;
};

}