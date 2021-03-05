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

#include <fmt/format.h>

#include "arithmetic_gmw_wire.h"
#include "protocols/share.h"

namespace encrypto::motion::proto::arithmetic_gmw {
/*
 * Allow only unsigned integers for Arithmetic shares.
 */
template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class Share final : public motion::Share {
  using Base = motion::Share;

 public:
  Share(const motion::WirePointer& wire) : Base(wire->GetBackend()) {
    wires_ = {wire};
    if (!wires_.at(0)) {
      throw(std::runtime_error("Something went wrong with creating an arithmetic share"));
    }
  }

  Share(const arithmetic_gmw::WirePointer<T>& wire) : Base(wire->GetBackend()) {
    wires_ = {std::static_pointer_cast<motion::Wire>(wire)};
  }

  Share(const std::vector<arithmetic_gmw::WirePointer<T>>& wires)
      : Base(wires.at(0)->GetBackend()) {
    for (auto i = 0ull; i < wires.size(); ++i) {
      wires_.emplace_back(wires.at(i));
    }
    if (wires.size() == 0) {
      throw(std::runtime_error("Trying to create an arithmetic share without wires"));
    }
    if (wires.size() > 1) {
      throw(
          std::runtime_error(fmt::format("Cannot create an arithmetic share "
                                         "from more than 1 wire; got {} wires",
                                         wires.size())));
    }
  }

  Share(const std::vector<motion::WirePointer>& wires) : Base(wires.at(0)->GetBackend()) {
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

  Share(const std::vector<T>& input, Backend& backend) : Base(backend) {
    wires_ = {std::make_shared<arithmetic_gmw::Wire<T>>(input, backend)};
  }

  Share(const T input, Backend& backend) : Base(backend) {
    wires_ = {std::make_shared<arithmetic_gmw::Wire<T>>(input, backend)};
  }

  //  std::shared_ptr<Share> operator+(const std::shared_ptr<Share> &other) {}

  ~Share() override = default;

  std::size_t GetNumberOfSimdValues() const noexcept final {
    return wires_.at(0)->GetNumberOfSimdValues();
  };

  MpcProtocol GetProtocol() const noexcept final {
    assert(wires_.at(0)->GetProtocol() == MpcProtocol::kArithmeticGmw);
    return wires_.at(0)->GetProtocol();
  }

  CircuitType GetCircuitType() const noexcept final {
    assert(wires_.at(0)->GetCircuitType() == CircuitType::kArithmetic);
    return wires_.at(0)->GetCircuitType();
  }

  const arithmetic_gmw::WirePointer<T> GetArithmeticWire() {
    auto wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(wires_.at(0));
    assert(wire);
    return wire;
  }

  const std::vector<motion::WirePointer>& GetWires() const noexcept final { return wires_; }

  std::vector<motion::WirePointer>& GetMutableWires() noexcept final { return wires_; }

  const bool& Finished() { return wires_.at(0)->IsReady(); }

  const std::vector<T>& GetValue() const {
    auto wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(wires_.at(0));
    assert(wire);
    return wire->GetRawSharedValues();
  }

  std::size_t GetBitLength() const noexcept final { return sizeof(T) * 8; }

  std::vector<std::shared_ptr<Base>> Split() const noexcept final {
    std::vector<std::shared_ptr<Base>> v;
    v.reserve(wires_.size());
    for (const auto& w : wires_) {
      const std::vector<motion::WirePointer> w_v = {std::static_pointer_cast<motion::Wire>(w)};
      v.emplace_back(std::make_shared<Share<T>>(w_v));
    }
    return v;
  }

  std::shared_ptr<Base> GetWire(std::size_t i) const override {
    if (i >= wires_.size()) {
      throw std::out_of_range(
          fmt::format("Trying to access wire #{} out of {} wires", i, wires_.size()));
    }
    std::vector<motion::WirePointer> result = {std::static_pointer_cast<motion::Wire>(wires_[i])};
    return std::make_shared<Share<T>>(result);
  }

  Share(Share&) = delete;

 private:
  Share() = default;
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
using SharePointer = std::shared_ptr<Share<T>>;

}  // namespace encrypto::motion::proto::arithmetic_gmw
