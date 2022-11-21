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
#include "utility/bit_vector.h"

namespace encrypto::motion::proto::boolean_astra {
    
class Wire final : public motion::BooleanWire {
  using Base = motion::BooleanWire;
 public:
  struct Data {
    Data() : value{}, lambda_i{} {}
    Data(BitVector<> v, BitVector<> l_i) : value{v}, lambda_i{l_i} {}
    BitVector<> value;
    BitVector<> lambda_i;
  };

  using value_type = Data;
 
  Wire() = default;
 
  Wire(Backend& backend, std::vector<Data> values);
  
  Wire(Backend& backend, std::size_t number_of_simd);
  
  ~Wire() = default;
  
  MpcProtocol GetProtocol() const final { return MpcProtocol::kBooleanAstra; }

  virtual bool IsConstant() const noexcept final { return false; };
  
  virtual std::size_t GetBitLength() const final { return 1; };
  
  const std::vector<Data>& GetValues() const { return values_; }
  
  std::vector<Data>& GetMutableValues() { return values_; }

  void SetSetupIsReady() {
    {
      std::scoped_lock lock(setup_ready_condition_->GetMutex());
      setup_ready_ = true;
    }
    setup_ready_condition_->NotifyAll();
  }

  const auto& GetSetupReadyCondition() const { return setup_ready_condition_; }
  
 private:
  std::vector<Data> values_;

  std::atomic<bool> setup_ready_{false};
  std::unique_ptr<FiberCondition> setup_ready_condition_;
};

using WirePointer = std::shared_ptr<boolean_astra::Wire>;
    
} // namespace encrypto::motion::proto::boolean_astra