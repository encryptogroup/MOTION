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

// added by Liang Zhao
#include "utility/meta.hpp"

namespace encrypto::motion::proto::arithmetic_gmw {

// Allow only unsigned integers for Arithmetic wires.
template <typename T>
class Wire final : public motion::Wire {
  using Base = motion::Wire;

 public:
  using value_type = T;

  Wire(Backend& backend, std::size_t number_of_simd);

  Wire(std::vector<T>&& values, Backend& backend);

  Wire(const std::vector<T>& values, Backend& backend);

  Wire(T t, Backend& backend);

  ~Wire() final = default;

  MpcProtocol GetProtocol() const final { return MpcProtocol::kArithmeticGmw; }

  CircuitType GetCircuitType() const final { return CircuitType::kArithmetic; }

  const std::vector<T>& GetValues() const { return values_; }

  std::vector<T>& GetMutableValues() { return values_; }

  // commented out by Liang Zhao
  // std::size_t GetBitLength() const final { return sizeof(T) * 8; }

  // added by Liang Zhao
  std::size_t GetBitLength() const final {
    T t = 0;
    std::size_t bit_length = encrypto::motion::GetBitSizeOfTypeT<T>(t) * 8;
    return bit_length;
  }

  bool IsConstant() const noexcept final { return false; }

 private:
  std::vector<T> values_;
};

template <typename T>
using WirePointer = std::shared_ptr<Wire<T>>;

}  // namespace encrypto::motion::proto::arithmetic_gmw
