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

namespace MOTION::Wires {

// Allow only unsigned integers for Arithmetic wires.
template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class ArithmeticWire : public Wire {
 public:
  ArithmeticWire(std::vector<T> &&values, Backend &backend, bool is_constant = false)
      : Wire(backend) {
    is_constant_ = is_constant;
    values_ = std::move(values);
    n_simd_ = values_.size();
    InitializationHelper();
  }

  ArithmeticWire(const std::vector<T> &values, Backend &backend, bool is_constant = false)
      : Wire(backend) {
    is_constant_ = is_constant;
    values_ = values;
    n_simd_ = values_.size();
    InitializationHelper();
  }

  ArithmeticWire(T t, Backend &backend, bool is_constant = false) : Wire(backend) {
    is_constant_ = is_constant;
    values_.push_back(t);
    n_simd_ = 1;
    InitializationHelper();
  }

  ~ArithmeticWire() final = default;

  MPCProtocol GetProtocol() const final { return MPCProtocol::ArithmeticGMW; }

  CircuitType GetCircuitType() const final { return CircuitType::ArithmeticCircuitType; }

  const std::vector<T> &GetValues() const { return values_; }

  std::vector<T> &GetMutableValues() { return values_; }

  std::size_t GetBitLength() const final { return sizeof(T) * 8; }

 private:
  std::vector<T> values_;
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
using ArithmeticWirePtr = std::shared_ptr<ArithmeticWire<T>>;

}  // namespace MOTION::Wires
