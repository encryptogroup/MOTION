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

namespace encrypto::motion::proto::arithmetic_gmw {

// Allow only unsigned integers for Arithmetic wires.
template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class Wire final : public motion::Wire {
  using Base = motion::Wire;

 public:
  using value_type = T;

  Wire(Backend& backend, std::size_t number_of_simd) : Base(backend, number_of_simd) {}

  Wire(std::vector<T>&& values, Backend& backend)
      : Base(backend, values.size()), values_(std::move(values)) {}

  Wire(const std::vector<T>& values, Backend& backend)
      : Base(backend, values.size()), values_(values) {}

  Wire(T t, Backend& backend) : Base(backend, 1), values_({t}) {}

  ~Wire() final = default;

  MpcProtocol GetProtocol() const final { return MpcProtocol::kArithmeticGmw; }

  CircuitType GetCircuitType() const final { return CircuitType::kArithmetic; }

  const std::vector<T>& GetValues() const { return values_; }

  std::vector<T>& GetMutableValues() { return values_; }

  std::size_t GetBitLength() const final { return sizeof(T) * 8; }

  bool IsConstant() const noexcept final { return false; }

 private:
  std::vector<T> values_;
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
using WirePointer = std::shared_ptr<Wire<T>>;

}  // namespace encrypto::motion::proto::arithmetic_gmw
