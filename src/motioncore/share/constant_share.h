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

#include "share.h"
#include "wire/constant_wire.h"

namespace MOTION::Shares {

/*
 * Allow only unsigned integers for Arithmetic shares.
 */
template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class ConstantArithmeticShare : public Share {
 public:
  ConstantArithmeticShare(const Wires::WirePtr &wire) : Share(wire->GetBackend()) {
    wires_ = {wire};
    if (!wires_.at(0)) {
      throw(std::runtime_error("Something went wrong with creating a constant arithmetic share"));
    }

    if constexpr (MOTION_DEBUG) ConstructorConsistencyCheck();
  }

  ConstantArithmeticShare(const Wires::ConstantArithmeticWirePtr<T> &wire)
      : Share(wire->GetBackend()) {
    wires_ = {std::static_pointer_cast<Wires::Wire>(wire)};

    if constexpr (MOTION_DEBUG) ConstructorConsistencyCheck();
  }

  ConstantArithmeticShare(const std::vector<Wires::ConstantArithmeticWirePtr<T>> &wires)
      : Share(wires.at(0)->GetBackend()) {
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

    if constexpr (MOTION_DEBUG) ConstructorConsistencyCheck();
  }

  ConstantArithmeticShare(const std::vector<Wires::WirePtr> &wires)
      : Share(wires.at(0)->GetBackend()) {
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

  ConstantArithmeticShare(const std::vector<T> &input, Backend &backend) : Share(backend) {
    wires_ = {std::make_shared<Wires::ConstantArithmeticWirePtr<T>>(input, backend)};
  }

  ConstantArithmeticShare(const T input, Backend &backend) : Share(backend) {
    wires_ = {std::make_shared<Wires::ConstantArithmeticWirePtr<T>>(input, backend)};
  }

  ~ConstantArithmeticShare() override = default;

  std::size_t GetNumOfSIMDValues() const noexcept final {
    return wires_.at(0)->GetNumOfSIMDValues();
  };

  MPCProtocol GetProtocol() const noexcept final {
    assert(wires_.at(0)->GetProtocol() == MPCProtocol::ArithmeticConstant);
    return wires_.at(0)->GetProtocol();
  }

  CircuitType GetCircuitType() const noexcept final {
    assert(wires_.at(0)->GetCircuitType() == CircuitType::Arithmetic);
    return wires_.at(0)->GetCircuitType();
  }

  const Wires::ConstantArithmeticWirePtr<T> GetConstantArithmeticWire() const {
    auto wire = std::dynamic_pointer_cast<Wires::ConstantArithmeticWirePtr<T>>(wires_.at(0));
    assert(wire);
    return wire;
  }

  const std::vector<Wires::WirePtr> &GetWires() const noexcept final { return wires_; }

  std::vector<Wires::WirePtr> &GetMutableWires() noexcept final { return wires_; }

  const bool &Finished() { return wires_.at(0)->IsReady(); }

  const std::vector<T> &GetValue() const {
    auto wire = std::dynamic_pointer_cast<Wires::ConstantArithmeticWirePtr<T>>(wires_.at(0));
    assert(wire);
    return wire->GetRawSharedValues();
  }

  std::size_t GetBitLength() const noexcept final { return sizeof(T) * 8; }

  std::vector<std::shared_ptr<Shares::Share>> Split() const noexcept final {
    std::vector<std::shared_ptr<Shares::Share>> v;
    v.reserve(wires_.size());
    for (const auto &w : wires_) {
      const std::vector<Wires::WirePtr> w_v = {std::static_pointer_cast<MOTION::Wires::Wire>(w)};
      v.emplace_back(std::make_shared<ConstantArithmeticShare<T>>(w_v));
    }
    return v;
  }

  ConstantArithmeticShare(ConstantArithmeticShare &) = delete;

 private:
  ConstantArithmeticShare() = default;

  void ConstructorConsistencyCheck() const {
    assert(wires_.size() == 1);
    auto arithmetic_wire =
        std::dynamic_pointer_cast<Wires::ConstantArithmeticWirePtr<T>>(wires_.at(0));
    assert(arithmetic_wire);
    assert(arithmetic_wire->IsConstant());
    assert(arithmetic_wire->GetProtocol() == MPCProtocol::ArithmeticConstant);
    assert(arithmetic_wire->GetCircuitType() == CircuitType::Arithmetic);
  };
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
using ConstantArithmeticSharePtr = std::shared_ptr<ConstantArithmeticShare<T>>;

class ConstantBooleanShare : public BooleanShare {
 public:
  ConstantBooleanShare(const std::vector<MOTION::Wires::WirePtr> &wires);

  ConstantBooleanShare(std::vector<MOTION::Wires::WirePtr> &&wires);

  const std::vector<Wires::WirePtr> &GetWires() const noexcept final { return wires_; }

  std::vector<Wires::WirePtr> &GetMutableWires() noexcept final { return wires_; }

  std::size_t GetNumOfSIMDValues() const noexcept final;

  MPCProtocol GetProtocol() const noexcept final;

  CircuitType GetCircuitType() const noexcept final;

  std::size_t GetBitLength() const noexcept final { return wires_.size(); }

  std::vector<std::shared_ptr<Share>> Split() const noexcept final;
};

using ConstantBooleanSharePtr = std::shared_ptr<ConstantBooleanShare>;

}