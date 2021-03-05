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

namespace encrypto::motion {

class Share;
using SharePointer = std::shared_ptr<Share>;

class ShareWrapper;

/// \brief obtains a subset of SIMD values of a share at provided position ids.
/// Repeated position ids are allowed, meaning that the number of SIMD values of the output share
/// may be greater than the number of SIMD values of the parent share. Each of the position ids must
/// be smaller than the number of SIMD values of the parent share.
class SubsetGate final : public OneGate {
 public:
  SubsetGate(const SharePointer& parent, std::span<const std::size_t> position_ids);

  SubsetGate(const SharePointer& parent, std::vector<std::size_t>&& position_ids);

  ~SubsetGate() = default;

  void EvaluateSetup() override;

  void EvaluateOnline() override;

  const SharePointer GetOutputAsShare();

  SubsetGate() = delete;

  SubsetGate(const Gate&) = delete;

 private:
  const std::vector<std::size_t> position_ids_;
};

}  // namespace encrypto::motion