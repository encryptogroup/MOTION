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

#include "share.h"

namespace MOTION::Shares {

class GMWShare final : public BooleanShare {
 public:
  GMWShare(const std::vector<MOTION::Wires::WirePtr> &wires);

  const std::vector<Wires::WirePtr> &GetWires() const noexcept final { return wires_; }

  std::vector<Wires::WirePtr> &GetMutableWires() noexcept final { return wires_; }

  std::size_t GetNumOfSIMDValues() const noexcept final;

  MPCProtocol GetSharingType() const noexcept final;

  std::size_t GetBitLength() const noexcept final { return wires_.size(); }
};

using GMWSharePtr = std::shared_ptr<GMWShare>;

}