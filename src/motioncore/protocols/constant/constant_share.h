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

#include "constant_wire.h"

#include "protocols/share.h"

namespace encrypto::motion::proto {

/*
 * Allow only unsigned integers for Arithmetic shares.
 */
template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class ConstantArithmeticShare : public motion::Share {
 public:
  ConstantArithmeticShare(const WirePointer& wire) : motion::Share(wire->GetBackend()) {
    wires_ = {wire};
    if (!wires_.at(0)) {
      throw(std::runtime_error("Something went wrong with creating a constant arithmetic share"));
    }

    if constexpr (kDebug) ConstructorConsistencyCheck();
  }

  ConstantArithmeticShare(const ConstantArithmeticWirePointer<T>& wire)
      : motion::Share(wire->GetBackend()) {
    wires_ = {std::static_pointer_cast<Wire>(wire)};

    if constexpr (kDebug) ConstructorConsistencyCheck();
  }

  ConstantArithmeticShare(const std::vector<ConstantArithmeticWirePointer<T>>& wires)
      : motion::Share(wires.at(0)->GetBackend()) {
    for (auto i = 0ull; i < wires.size(); ++i) {
      wires_.emplace_back(wires.at(i));
    }

    if (wires.empty()) {
      throw(std::runtime_error("Trying to create a constant arithmetic share without wires"));
    } else if (wires.size() > 1) {
      throw(
          std::runtime_error(fmt::format("Cannot create a constant arithmetic share "
                                         "from more than 1 wire; got {} wires",
                                         wires.size())));
    }

    if constexpr (kDebug) ConstructorConsistencyCheck();
  }

  ConstantArithmeticShare(const std::vector<WirePointer>& wires)
      : motion::Share(wires.at(0)->GetBackend()) {
    if (wires.size() == 0) {
      throw(std::runtime_error("Trying to create an arithmetic share without wires"));
    }
    if (wires.size() > 1) {
      throw(
          std::runtime_error(fmt::format("Cannot create an arithmetic share "
                                         "from more than 1 wire; got {} wires",
                                         wires.size())));
    }
    wires_ = {wires.at(0)};
    if (!wires_.at(0)) {
      throw(std::runtime_error("Something went wrong with creating an arithmetic share"));
    }
  }

  ConstantArithmeticShare(const std::vector<T>& input, Backend& backend) : motion::Share(backend) {
    wires_ = {std::make_shared<ConstantArithmeticWirePointer<T>>(input, backend)};
  }

  ConstantArithmeticShare(const T input, Backend& backend) : motion::Share(backend) {
    wires_ = {std::make_shared<ConstantArithmeticWirePointer<T>>(input, backend)};
  }

  ~ConstantArithmeticShare() override = default;

  std::size_t GetNumberOfSimdValues() const noexcept final {
    return wires_.at(0)->GetNumberOfSimdValues();
  };

  MpcProtocol GetProtocol() const noexcept final {
    assert(wires_.at(0)->GetProtocol() == MpcProtocol::kArithmeticConstant);
    return wires_.at(0)->GetProtocol();
  }

  CircuitType GetCircuitType() const noexcept final {
    assert(wires_.at(0)->GetCircuitType() == CircuitType::kArithmetic);
    return wires_.at(0)->GetCircuitType();
  }

  const ConstantArithmeticWirePointer<T> GetConstantArithmeticWire() const {
    auto wire = std::dynamic_pointer_cast<ConstantArithmeticWirePointer<T>>(wires_.at(0));
    assert(wire);
    return wire;
  }

  const std::vector<WirePointer>& GetWires() const noexcept final { return wires_; }

  std::vector<WirePointer>& GetMutableWires() noexcept final { return wires_; }

  const std::vector<T>& GetValue() const {
    auto wire = std::dynamic_pointer_cast<ConstantArithmeticWirePointer<T>>(wires_.at(0));
    assert(wire);
    return wire->GetRawSharedValues();
  }

  std::size_t GetBitLength() const noexcept final { return sizeof(T) * 8; }

  std::vector<std::shared_ptr<motion::Share>> Split() const noexcept final {
    std::vector<std::shared_ptr<motion::Share>> v;
    v.reserve(wires_.size());
    for (const auto& w : wires_) {
      const std::vector<WirePointer> w_v = {std::static_pointer_cast<Wire>(w)};
      v.emplace_back(std::make_shared<ConstantArithmeticShare<T>>(w_v));
    }
    return v;
  }

  std::shared_ptr<motion::Share> GetWire(std::size_t i) const override {
    if (i >= wires_.size()) {
      throw std::out_of_range(
          fmt::format("Trying to access wire #{} out of {} wires", i, wires_.size()));
    }
    std::vector<motion::WirePointer> result = {std::static_pointer_cast<motion::Wire>(wires_[i])};
    return std::make_shared<ConstantArithmeticShare<T>>(result);
  };

  ConstantArithmeticShare(ConstantArithmeticShare&) = delete;

 private:
  ConstantArithmeticShare() = default;

  void ConstructorConsistencyCheck() const {
    assert(wires_.size() == 1);
    auto arithmetic_wire =
        std::dynamic_pointer_cast<ConstantArithmeticWirePointer<T>>(wires_.at(0));
    assert(arithmetic_wire);
    assert(arithmetic_wire->IsConstant());
    assert(arithmetic_wire->GetProtocol() == MpcProtocol::kArithmeticConstant);
    assert(arithmetic_wire->GetCircuitType() == CircuitType::kArithmetic);
  };
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
using ConstantArithmeticSharePointer = std::shared_ptr<ConstantArithmeticShare<T>>;

class ConstantBooleanShare final : public BooleanShare {
 public:
  ConstantBooleanShare(const std::vector<WirePointer>& wires);

  ConstantBooleanShare(std::vector<WirePointer>&& wires);

  const std::vector<WirePointer>& GetWires() const noexcept final { return wires_; }

  std::vector<WirePointer>& GetMutableWires() noexcept final { return wires_; }

  std::size_t GetNumberOfSimdValues() const noexcept final;

  MpcProtocol GetProtocol() const noexcept final;

  CircuitType GetCircuitType() const noexcept final;

  std::size_t GetBitLength() const noexcept final { return wires_.size(); }

  std::vector<std::shared_ptr<motion::Share>> Split() const noexcept final;

  std::shared_ptr<motion::Share> GetWire(std::size_t i) const final;
};

using ConstantBooleanSharePointer = std::shared_ptr<ConstantBooleanShare>;

}  // namespace encrypto::motion::proto
