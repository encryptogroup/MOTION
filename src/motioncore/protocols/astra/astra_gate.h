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

#include "base/backend.h"
#include "base/register.h"
#include "communication/communication_layer.h"
#include "communication/message.h"
#include "protocols/astra/astra_wire.h"

namespace encrypto::motion::proto::astra { 
    
constexpr std::size_t kAll = std::numeric_limits<std::int64_t>::max(); 

template <typename T>
class InputGate final : public motion::InputGate {
  using Base = motion::InputGate;

 public:
  InputGate(std::vector<T> input, std::size_t input_owner, Backend& backend);

  ~InputGate() final = default;

  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
  astra::SharePointer<T> GetOutputAsAstraShare();
  
 private:
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> input_future_;
};

template <typename T>
class OutputGate final : public motion::OutputGate {
  using Base = motion::OutputGate;

 public:
  OutputGate(const astra::SharePointer<T>& parent, std::size_t output_owner);
  OutputGate(const astra::WirePointer<T>& parent, std::size_t output_owner = kAll);
  OutputGate(const motion::SharePointer& parent, std::size_t output_owner);

  ~OutputGate() final = default;

  void EvaluateSetup() final override;
  void EvaluateOnline() final override;

  bool NeedsSetup() const override { return false; }
  
  astra::SharePointer<T> GetOutputAsAstraShare();
  
 private:
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> output_future_;
};

template<typename T>
class AdditionGate final : public TwoGate {
  using Base = motion::TwoGate;
 
 public:
  AdditionGate(const astra::WirePointer<T>& a, const astra::WirePointer<T>& b);
  
  ~AdditionGate() final = default;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
  astra::SharePointer<T> GetOutputAsAstraShare();
};

template<typename T>
class SubtractionGate final : public TwoGate {
  using Base = motion::TwoGate;
 
 public:
  SubtractionGate(const astra::WirePointer<T>& a, const astra::WirePointer<T>& b);
  
  ~SubtractionGate() final = default;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
  astra::SharePointer<T> GetOutputAsAstraShare();
};

template<typename T>
class MultiplicationGate final : public TwoGate {
  using Base = motion::TwoGate;
 
 public:
  MultiplicationGate(const astra::WirePointer<T>& a, const astra::WirePointer<T>& b);
  
  ~MultiplicationGate() final = default;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
  astra::SharePointer<T> GetOutputAsAstraShare();
  
 private:
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> multiply_future_setup_;
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> multiply_future_online_;
};

template<typename T>
class DotProductGate final : public TwoGate {
  using Base = motion::TwoGate;
 public:
  DotProductGate(std::vector<motion::WirePointer> vector_a, std::vector<motion::WirePointer> vector_b);

  ~DotProductGate() final = default;

  DotProductGate(DotProductGate&) = delete;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
  astra::SharePointer<T> GetOutputAsAstraShare();
  
 private:
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> dot_product_future_setup_;
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> dot_product_future_online_;
};

    
} //namespace encrypto::motion::proto::astra