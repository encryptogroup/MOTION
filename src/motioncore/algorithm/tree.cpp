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

#include "share/share_wrapper.h"
#include "utility/helpers.h"

namespace ENCRYPTO::Algorithm {
MOTION::Shares::ShareWrapper FullANDTree(const MOTION::Shares::ShareWrapper& s) {
  assert(MOTION::Helpers::IsPowerOfTwo(s->GetBitLength()));
  auto result = s;
  while (result->GetBitLength() != 1) {
    const auto split{result.Split()};
    const auto left{MOTION::Shares::ShareWrapper::Join(std::vector<MOTION::Shares::ShareWrapper>(
        split.begin(), split.begin() + split.size() / 2))};
    const auto right{MOTION::Shares::ShareWrapper::Join(
        std::vector<MOTION::Shares::ShareWrapper>(split.begin() + split.size() / 2, split.end()))};
    result = left & right;
  }
  return result;
}

MOTION::Shares::ShareWrapper FullANDTree(const std::vector<MOTION::Shares::ShareWrapper>& v) {
  assert(MOTION::Helpers::IsPowerOfTwo(v.size()));
  const auto s = MOTION::Shares::ShareWrapper::Join(v);
  return FullANDTree(s);
}
}