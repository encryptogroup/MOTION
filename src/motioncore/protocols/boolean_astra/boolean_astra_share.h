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

#include "boolean_astra_wire.h"
#include "protocols/share.h"


namespace encrypto::motion::proto::boolean_astra {
    
class Share final : public motion::BooleanShare {
  using Base = motion::BooleanShare;

 public:
  Share(const motion::WirePointer& wire);
  
  Share(const boolean_astra::WirePointer& wire);
  
  Share(const std::vector<boolean_astra::WirePointer>& wires);
  
  Share(const std::vector<motion::WirePointer>& wires);

  ~Share() override = default;

  std::size_t GetNumberOfSimdValues() const noexcept final;

  MpcProtocol GetProtocol() const noexcept final;

  CircuitType GetCircuitType() const noexcept final;

  const boolean_astra::WirePointer GetBooleanAstraWire() {
    assert(wires_.size() == 1);
    auto wire = std::dynamic_pointer_cast<boolean_astra::Wire>(wires_[0]);
    assert(wire);
    return wire;
  }

  const std::vector<motion::WirePointer>& GetWires() const noexcept final { return wires_; }

  std::vector<motion::WirePointer>& GetMutableWires() noexcept final { return wires_; }

  bool Finished();

  std::size_t GetBitLength() const noexcept final { return wires_.size(); }

  std::vector<motion::SharePointer> Split() const noexcept final;

  motion::SharePointer GetWire(std::size_t i) const override;

  Share(Share&) = delete;

 private:
  Share() = default;
};

using SharePointer = std::shared_ptr<boolean_astra::Share>;

}  // namespace encrypto::motion::proto::boolean_astra