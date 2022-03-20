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

#include "arithmetic_gmw_wire.h"
#include "protocols/share.h"

namespace encrypto::motion::proto::arithmetic_gmw {
/*
 * Allow only unsigned integers for Arithmetic shares.
 */
template <typename T>
class Share final : public motion::Share {
  using Base = motion::Share;

 public:
  Share(const motion::WirePointer& wire);
  Share(const arithmetic_gmw::WirePointer<T>& wire);
  Share(const std::vector<arithmetic_gmw::WirePointer<T>>& wires);
  Share(const std::vector<motion::WirePointer>& wires);
  Share(const std::vector<T>& input, Backend& backend);
  Share(const T input, Backend& backend);

  //  std::shared_ptr<Share> operator+(const std::shared_ptr<Share> &other) {}

  ~Share() override = default;

  std::size_t GetNumberOfSimdValues() const noexcept final;

  MpcProtocol GetProtocol() const noexcept final;

  CircuitType GetCircuitType() const noexcept final;

  const arithmetic_gmw::WirePointer<T> GetArithmeticWire() {
    auto wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(wires_.at(0));
    assert(wire);
    return wire;
  }

  const std::vector<motion::WirePointer>& GetWires() const noexcept final { return wires_; }

  std::vector<motion::WirePointer>& GetMutableWires() noexcept final { return wires_; }

  const std::vector<T>& GetValue() const;

  std::size_t GetBitLength() const noexcept final { return sizeof(T) * 8; }

  std::vector<std::shared_ptr<Base>> Split() const noexcept final;

  std::shared_ptr<Base> GetWire(std::size_t i) const override;

  Share(Share&) = delete;

 private:
  Share() = default;
};

template <typename T>
using SharePointer = std::shared_ptr<Share<T>>;

}  // namespace encrypto::motion::proto::arithmetic_gmw
