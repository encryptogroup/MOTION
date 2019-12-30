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

#include "utility/bit_vector.h"
#include "wire.h"

namespace MOTION::Wires {
template <typename T>
class ConstantArithmeticWire : public Wire {
 public:
  ConstantArithmeticWire(Backend &backend, std::size_t num_simd) : Wire(backend, num_simd) {}

  ConstantArithmeticWire(std::vector<T> &&values, Backend &backend)
      : Wire(backend, values.size()), values_(std::move(values)) {}

  ConstantArithmeticWire(const std::vector<T> &values, Backend &backend)
      : Wire(backend, values.size()), values_(values) {}

  ConstantArithmeticWire(T t, Backend &backend) : Wire(backend, 1), values_({t}) {}

  ~ConstantArithmeticWire() final = default;

  MPCProtocol GetProtocol() const final { return MPCProtocol::ArithmeticConstant; }

  CircuitType GetCircuitType() const final { return CircuitType::ArithmeticCircuitType; }

  const std::vector<T> &GetValues() const { return values_; }

  std::vector<T> &GetMutableValues() { return values_; }

  std::size_t GetBitLength() const final { return sizeof(T) * 8; }

  bool IsConstant() const noexcept final { return true; }

 private:
  std::vector<T> values_;
};

template <typename T>
using ConstantArithmeticWirePtr = std::shared_ptr<ConstantArithmeticWire<T>>;

class ConstantBooleanWire : public BooleanWire {
 public:
  ConstantBooleanWire(size_t num_simd, Backend &backend);

  ConstantBooleanWire(ENCRYPTO::BitVector<> &&values, Backend &backend);

  ConstantBooleanWire(const ENCRYPTO::BitVector<> &values, Backend &backend);

  ConstantBooleanWire(bool value, Backend &backend);

  ~ConstantBooleanWire() final = default;

  MPCProtocol GetProtocol() const final { return MPCProtocol::BooleanConstant; }

  ConstantBooleanWire() = delete;

  ConstantBooleanWire(ConstantBooleanWire &) = delete;

  std::size_t GetBitLength() const final { return 1; }

  const ENCRYPTO::BitVector<> &GetValues() const { return values_; }

  ENCRYPTO::BitVector<> &GetMutableValues() { return values_; }

  bool IsConstant() const noexcept final { return true; }

 private:
  ENCRYPTO::BitVector<> values_;
};

using ConstantBooleanWirePtr = std::shared_ptr<ConstantBooleanWire>;

}  // namespace MOTION::Wires