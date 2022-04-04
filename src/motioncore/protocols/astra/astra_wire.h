// MIT License
//
// Copyright (c) 2022 Oliver Schick
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

#pragma once

#include "protocols/wire.h"

namespace encrypto::motion::proto::astra {
    
template<typename T>
class Wire final : public motion::Wire {
  using Base = motion::Wire;
 public:
 
 Wire() = default;
 
  Wire(Backend& backend, const T& value, const T& lambda_x_0, const T& lambda_x_1);
  
  ~Wire() = default;
  
  MpcProtocol GetProtocol() const final { return MpcProtocol::kAstra; }
  
  CircuitType GetCircuitType() const final { return CircuitType::kArithmetic; }

  virtual bool IsConstant() const noexcept final { return false; };
  
  virtual std::size_t GetBitLength() const final { return sizeof(T) * CHAR_BIT; };
  
  const T& GetValue() const { return value_; }
  
  T& GetMutableValue() { return value_; }
  
  std::array<T, 2>& GetMutableLambdas() { return lambda_x_i_; }
  
 //private:
  T value_;
  std::array<T, 2> lambda_x_i_;
};

template<typename T>
using WirePointer = std::shared_ptr<astra::Wire<T>>;
    
} // namespace encrypto::motion::proto::astra