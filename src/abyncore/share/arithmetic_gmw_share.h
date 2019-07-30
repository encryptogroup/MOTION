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

#include "wire/arithmetic_gmw_wire.h"

namespace ABYN::Shares {
/*
 * Allow only unsigned integers for Arithmetic shares.
 */
template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class ArithmeticShare : public Share {
 public:
  ArithmeticShare(const Wires::WirePtr &wire) {
    wires_ = {std::dynamic_pointer_cast<ArithmeticShare<T>>(wire)};
    if (!wires_.at(0)) {
      throw(std::runtime_error("Something went wrong with creating an arithmetic share"));
    }
    backend_ = wires_.at(0)->GetBackend();
  }

  ArithmeticShare(Wires::ArithmeticWirePtr<T> &wire) : wires_({wire}) {
    wires_ = {wire};
    assert(wire);
    backend_ = wires_.at(0)->GetBackend();
  }

  ArithmeticShare(std::vector<Wires::ArithmeticWirePtr<T>> &wires) : wires_(wires) {
    if (wires.size() == 0) {
      throw(std::runtime_error("Trying to create an arithmetic share without wires"));
    }
    if (wires.size() > 1) {
      throw(
          std::runtime_error(fmt::format("Cannot create an arithmetic share "
                                         "from more than 1 wire; got {} wires",
                                         wires.size())));
    }
    backend_ = wires_.at(0)->GetBackend();
  }

  ArithmeticShare(std::vector<Wires::WirePtr> &wires) {
    if (wires.size() == 0) {
      throw(std::runtime_error("Trying to create an arithmetic share without wires"));
    }
    if (wires.size() > 1) {
      throw(
          std::runtime_error(fmt::format("Cannot create an arithmetic share "
                                         "from more than 1 wire; got {} wires",
                                         wires.size())));
    }
    wires_ = {std::dynamic_pointer_cast<ArithmeticShare<T>>(wires.at(0))};
    if (!wires_.at(0)) {
      throw(std::runtime_error("Something went wrong with creating an arithmetic share"));
    }
    backend_ = wires_.at(0)->GetRegister();
  }

  ArithmeticShare(std::vector<T> &input, const std::weak_ptr<Backend> &backend) {
    backend_ = backend;
    wires_ = {std::make_shared<Wires::ArithmeticWire<T>>(input, backend)};
  }

  ArithmeticShare(T input, const std::weak_ptr<Backend> &backend) {
    backend_ = backend;
    wires_ = {std::make_shared<Wires::ArithmeticWire<T>>(input, backend)};
  }

  std::shared_ptr<ArithmeticShare> operator+(const std::shared_ptr<ArithmeticShare> &other) {}

  ~ArithmeticShare() override = default;

  std::size_t GetNumOfParallelValues() const noexcept final {
    return wires_.at(0)->GetNumOfParallelValues();
  };

  MPCProtocol GetSharingType() const noexcept final { return wires_.at(0)->GetProtocol(); }

  const Wires::ArithmeticWirePtr<T> &GetArithmeticWire() { return wires_.at(0); }

  const std::vector<Wires::WirePtr> GetWires() const final {
    std::vector<Wires::WirePtr> result{std::static_pointer_cast<Wires::Wire>(wires_.at(0))};
    return std::move(result);
  }

  const bool &Finished() { return wires_.at(0)->IsReady(); }

  const std::vector<T> &GetValue() const { return wires_->GetRawSharedValues(); }

  std::size_t GetBitLength() const noexcept final { return sizeof(T) * 8; }

  std::shared_ptr<Share> Clone() final {
    // TODO
    return std::static_pointer_cast<Share>(std::make_shared<ArithmeticShare<T>>(wires_));
  }

  std::shared_ptr<ArithmeticShare> NonVirtualClone() {
    return std::make_shared<ArithmeticShare>(wires_);
  }

  ArithmeticShare(ArithmeticShare &) = delete;

 protected:
  std::vector<Wires::ArithmeticWirePtr<T>> wires_;

 private:
  ArithmeticShare() = default;
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
using ArithmeticSharePtr = std::shared_ptr<ArithmeticShare<T>>;

/*
 * Allow only unsigned integers for Arithmetic shares.
 */
template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class ArithmeticConstantShare : public Share {
 public:
  ArithmeticConstantShare(T input, const std::weak_ptr<Backend> &backend) : values_({input}) {
    backend_ = backend;
  }

  ArithmeticConstantShare(std::vector<T> &input, const std::weak_ptr<Backend> &backend)
      : values_(input) {
    backend_ = backend;
  }

  ArithmeticConstantShare(std::vector<T> &&input, const std::weak_ptr<Backend> &backend)
      : values_(std::move(input)) {
    backend_ = backend;
  }

  ~ArithmeticConstantShare() override = default;

  std::size_t GetNumOfParallelValues() const noexcept final { return values_.size(); };

  MPCProtocol GetSharingType() const noexcept final { return ArithmeticGMW; }

  const std::vector<T> &GetValue() const { return values_; }

  std::shared_ptr<Share> Clone() final {
    // TODO
    return std::static_pointer_cast<Share>(
        std::make_shared<ArithmeticConstantShare>(values_, backend_));
  };

  ArithmeticConstantShare() = delete;

  ArithmeticConstantShare(ArithmeticConstantShare &) = delete;

  std::size_t GetBitLength() const noexcept final { return sizeof(T) * 8; }

 protected:
  std::vector<T> values_;

 private:
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
using ArithmeticConstantSharePtr = std::shared_ptr<ArithmeticConstantShare<T>>;
}