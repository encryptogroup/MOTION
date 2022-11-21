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
#include "boolean_astra_wire.h"
#include "boolean_astra_share.h"
#include "utility/bit_vector.h"
#include "protocols/boolean_gmw/boolean_gmw_gate.h"

namespace encrypto::motion::proto::boolean_astra {
    
constexpr std::size_t kAll = std::numeric_limits<std::int64_t>::max(); 

class InputGate final : public motion::InputGate {
  using Base = motion::InputGate;

 public:
  InputGate(std::vector<BitVector<>> input, std::size_t input_owner, Backend& backend);

  ~InputGate() final = default;

  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
  //Sets input values after construction but before evaluating the gate.
  //The input can only be set once, before EvaluateOnline() was called and only 
  //if all input values were set to 0 during construction.
  void SetAndCommit(std::vector<BitVector<>> input);
  
  boolean_astra::SharePointer GetOutputAsBooleanAstraShare();
  
 private:
  motion::ReusableFiberFuture<std::vector<std::uint8_t>> input_future_;
};

class OutputGate final : public motion::OutputGate {
  using Base = motion::OutputGate;

 public:
  OutputGate(const boolean_astra::WirePointer& parent, std::size_t output_owner = kAll);
  OutputGate(const boolean_astra::SharePointer& parent, std::size_t output_owner = kAll)
  : OutputGate((assert(parent), parent->GetBooleanAstraWire()), output_owner) {}
  OutputGate(const motion::SharePointer& parent, std::size_t output_owner = kAll)
  : OutputGate(std::dynamic_pointer_cast<boolean_astra::Share>(parent), output_owner) {}

  ~OutputGate() final = default;

  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
  boolean_astra::SharePointer GetOutputAsBooleanAstraShare();
  
 private:
  std::vector<motion::ReusableFiberFuture<std::vector<std::uint8_t>>> output_futures_;
};

class XorGate final : public motion::TwoGate {
  using Base = motion::TwoGate;
 
 public:
  XorGate(const boolean_astra::WirePointer& a, const boolean_astra::WirePointer& b);
  
  ~XorGate() final = default;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
  boolean_astra::SharePointer GetOutputAsBooleanAstraShare();
};

class AndGate final : public motion::TwoGate {
  using Base = motion::TwoGate;
 
 public:
  AndGate(const boolean_astra::WirePointer& a, const boolean_astra::WirePointer& b);
  
  ~AndGate() final = default;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
  boolean_astra::SharePointer GetOutputAsBooleanAstraShare();
  
 private:
  std::vector<motion::ReusableFiberFuture<std::vector<std::uint8_t>>> multiply_futures_online_;
  GatePointer lambda_ab_gate_ = nullptr;
};

class BooleanDotProductGate final : public motion::TwoGate {
  using Base = motion::TwoGate;
 public:
  BooleanDotProductGate(std::vector<motion::WirePointer> vector_a, 
                        std::vector<motion::WirePointer> vector_b);

  ~BooleanDotProductGate() final = default;

  BooleanDotProductGate(BooleanDotProductGate&) = delete;
  
  void EvaluateSetup() final override;
  void EvaluateOnline() final override;
  
  boolean_astra::SharePointer GetOutputAsBooleanAstraShare();
  
 private:
  std::vector<motion::ReusableFiberFuture<std::vector<std::uint8_t>>> dot_product_futures_online_;
  std::vector<GatePointer> lambda_abk_gates_;
};

} //namespace encrypto::motion::proto::boolean_astra