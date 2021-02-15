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

#include "protocols/wire.h"
#include "utility/bit_vector.h"

namespace encrypto::motion::proto {

template <typename T>
class ConstantArithmeticWire final : public Wire {
 public:
  using value_type = T;

  ConstantArithmeticWire(Backend& backend, std::size_t number_of_simd)
      : Wire(backend, number_of_simd) {}

  ConstantArithmeticWire(std::vector<T>&& values, Backend& backend)
      : Wire(backend, values.size()), values_(std::move(values)) {}

  ConstantArithmeticWire(const std::vector<T>& values, Backend& backend)
      : Wire(backend, values.size()), values_(values) {}

  ConstantArithmeticWire(T t, Backend& backend) : Wire(backend, 1), values_({t}) {}

  ~ConstantArithmeticWire() final = default;

  MpcProtocol GetProtocol() const final { return MpcProtocol::kArithmeticConstant; }

  CircuitType GetCircuitType() const final { return CircuitType::kArithmetic; }

  const std::vector<T>& GetValues() const { return values_; }

  std::vector<T>& GetMutableValues() { return values_; }

  std::size_t GetBitLength() const final { return sizeof(T) * 8; }

  bool IsConstant() const noexcept final { return true; }

 private:
  std::vector<T> values_;
};

template <typename T>
using ConstantArithmeticWirePointer = std::shared_ptr<ConstantArithmeticWire<T>>;

class ConstantBooleanWire final : public BooleanWire {
 public:
  ConstantBooleanWire(Backend& backend, std::size_t number_of_simd);

  ConstantBooleanWire(BitVector<>&& values, Backend& backend);

  ConstantBooleanWire(const BitVector<>& values, Backend& backend);

  ConstantBooleanWire(bool value, Backend& backend);

  ~ConstantBooleanWire() final = default;

  MpcProtocol GetProtocol() const final { return MpcProtocol::kBooleanConstant; }

  ConstantBooleanWire() = delete;

  ConstantBooleanWire(ConstantBooleanWire&) = delete;

  std::size_t GetBitLength() const final { return 1; }

  const BitVector<>& GetValues() const { return values_; }

  BitVector<>& GetMutableValues() { return values_; }

  bool IsConstant() const noexcept final { return true; }

 private:
  BitVector<> values_;
};

using ConstantBooleanWirePointer = std::shared_ptr<ConstantBooleanWire>;

}  // namespace encrypto::motion::proto
