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

#include "wire.h"

#include "utility/bit_vector.h"

namespace MOTION {
class Backend;
}

namespace MOTION::Wires {

class GMWWire : public BooleanWire {
 public:
  GMWWire(ENCRYPTO::BitVector<> &&values, Backend &backend, bool is_constant = false);

  GMWWire(const ENCRYPTO::BitVector<> &values, Backend &backend, bool is_constant = false);

  GMWWire(bool value, Backend &backend, bool is_constant = false);

  ~GMWWire() final = default;

  MPCProtocol GetProtocol() const final { return MPCProtocol::BooleanGMW; }

  GMWWire() = delete;

  GMWWire(GMWWire &) = delete;

  std::size_t GetBitLength() const final { return 1; }

  const ENCRYPTO::BitVector<> &GetValues() const { return values_; }

  ENCRYPTO::BitVector<> &GetMutableValues() { return values_; }

 private:
  ENCRYPTO::BitVector<> values_;
};

using GMWWirePtr = std::shared_ptr<GMWWire>;

}  // namespace MOTION::Wires
