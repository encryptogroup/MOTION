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

#include <span>
#include <vector>

#include "protocols/gate.h"

// namespace encrypto::motion::proto::boolean_gmw

namespace encrypto::motion {

class Share;
using SharePointer = std::shared_ptr<Share>;

class ShareWrapper;

/// \brief yields a share that constitutes a concatenation of the parent in terms of their SIMD
/// values, e.g., if 3 parents contain 1, 3, and 2 SIMD values, respectively, the output will
/// contain 1 share with 6 SIMD values and the same number of wires as parents. The output SIMD
/// values will be ordered as
/// [parent_0[simd_0], parent_1[simd_0, simd_1, simd_2], parent_2[simd_0, simd_1]].
///
/// \throws invalid_argument if the parent have inconsistent number of wires.
class SimdifyGate final : public OneGate {
 public:
  SimdifyGate(std::span<SharePointer> parents);

  ~SimdifyGate() = default;

  void EvaluateSetup() override;

  void EvaluateOnline() override;

  SharePointer GetOutputAsShare();

  SimdifyGate() = delete;

  SimdifyGate(const Gate&) = delete;

 private:
  const std::size_t number_of_input_shares_;
  std::size_t output_number_of_simd_values_{0};
};

}  // namespace encrypto::motion