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
#include "astra_data.h"

namespace encrypto::motion::proto::astra {
    
template<typename T>
class Wire final : public motion::Wire {
  using Base = motion::Wire;
 public:
  using value_type = Data<T>;
 
 Wire() = default;
 
  Wire(Backend& backend, std::vector<Data<T>> values);
  Wire(Backend& backend, std::size_t number_of_simd);
  
  ~Wire() = default;
  
  MpcProtocol GetProtocol() const final { return MpcProtocol::kAstra; }
  
  CircuitType GetCircuitType() const final { return CircuitType::kArithmetic; }

  virtual bool IsConstant() const noexcept final { return false; };
  
  virtual std::size_t GetBitLength() const final { return sizeof(T) * CHAR_BIT; };
  
  const std::vector<Data<T>>& GetValues() const { return values_; }
  
  std::vector<Data<T>>& GetMutableValues() { return values_; }

  void SetSetupIsReady() {
    {
      std::scoped_lock lock(setup_ready_condition_->GetMutex());
      setup_ready_ = true;
    }
    setup_ready_condition_->NotifyAll();
  }

  const auto& GetSetupReadyCondition() const { return setup_ready_condition_; }
  
 private:
  std::vector<Data<T>> values_;

  std::atomic<bool> setup_ready_{false};
  std::unique_ptr<FiberCondition> setup_ready_condition_;
};

template<typename T>
using WirePointer = std::shared_ptr<astra::Wire<T>>;
    
} // namespace encrypto::motion::proto::astra