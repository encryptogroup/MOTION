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

#include <functional>
#include <vector>
#include "protocols/share.h"
#include "utility/bit_vector.h"

namespace encrypto::motion::proto::boolean_gmw {

class Share final : public BooleanShare {
 public:
  Share(const std::vector<motion::WirePointer>& wires);

  Share(std::vector<motion::WirePointer>&& wires);

  const std::vector<motion::WirePointer>& GetWires() const noexcept final { return wires_; }

  std::vector<motion::WirePointer>& GetMutableWires() noexcept final { return wires_; }

  std::size_t GetNumberOfSimdValues() const noexcept final;

  MpcProtocol GetProtocol() const noexcept final;

  CircuitType GetCircuitType() const noexcept final;

  std::size_t GetBitLength() const noexcept final { return wires_.size(); }

  std::vector<std::reference_wrapper<const BitVector<>>> GetValues() const;

  std::vector<std::reference_wrapper<BitVector<>>> GetMutableValues();

  std::vector<std::shared_ptr<motion::Share>> Split() const noexcept final;

  std::shared_ptr<motion::Share> GetWire(std::size_t i) const final;
};

using SharePointer = std::shared_ptr<Share>;

}  // namespace encrypto::motion::proto::boolean_gmw
