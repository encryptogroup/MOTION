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

#include "astra_wire.h"
#include "protocols/share.h"


namespace encrypto::motion::proto::astra {
    
template <typename T>
class Share final : public motion::Share {
  using Base = motion::Share;

 public:
  Share(const motion::WirePointer& wire);
  Share(const astra::WirePointer<T>& wire);
  Share(const std::vector<astra::WirePointer<T>>& wires);
  Share(const std::vector<motion::WirePointer>& wires);

  ~Share() override = default;

  std::size_t GetNumberOfSimdValues() const noexcept final;

  MpcProtocol GetProtocol() const noexcept final;

  CircuitType GetCircuitType() const noexcept final;

  const astra::WirePointer<T> GetAstraWire() {
    auto wire = std::dynamic_pointer_cast<astra::Wire<T>>(wires_.at(0));
    assert(wire);
    return wire;
  }

  const std::vector<motion::WirePointer>& GetWires() const noexcept final { return wires_; }

  std::vector<motion::WirePointer>& GetMutableWires() noexcept final { return wires_; }

  bool Finished();

  std::size_t GetBitLength() const noexcept final { return sizeof(T) * CHAR_BIT; }

  std::vector<std::shared_ptr<Base>> Split() const noexcept final;

  std::shared_ptr<Base> GetWire(std::size_t i) const override;

  Share(Share&) = delete;

 private:
  Share() = default;
};

template <typename T>
using SharePointer = std::shared_ptr<Share<T>>;

}  // namespace encrypto::motion::proto::astra