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

#include "arithmetic_gmw_share.h"

#include <fmt/format.h>

namespace encrypto::motion::proto::arithmetic_gmw {

template <typename T>
Share<T>::Share(const motion::WirePointer& wire) : Base(wire->GetBackend()) {
  wires_ = {wire};
  if (!wires_.at(0)) {
    throw(std::runtime_error("Something went wrong with creating an arithmetic share"));
  }
}

template <typename T>
Share<T>::Share(const arithmetic_gmw::WirePointer<T>& wire) : Base(wire->GetBackend()) {
  wires_ = {std::static_pointer_cast<motion::Wire>(wire)};
}

template <typename T>
Share<T>::Share(const std::vector<arithmetic_gmw::WirePointer<T>>& wires)
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

template <typename T>
Share<T>::Share(const std::vector<motion::WirePointer>& wires) : Base(wires.at(0)->GetBackend()) {
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

template <typename T>
Share<T>::Share(const std::vector<T>& input, Backend& backend) : Base(backend) {
  wires_ = {std::make_shared<arithmetic_gmw::Wire<T>>(input, backend)};
}

template <typename T>
Share<T>::Share(const T input, Backend& backend) : Base(backend) {
  wires_ = {std::make_shared<arithmetic_gmw::Wire<T>>(input, backend)};
}

template <typename T>
std::size_t Share<T>::GetNumberOfSimdValues() const noexcept {
  return wires_.at(0)->GetNumberOfSimdValues();
}

template <typename T>
MpcProtocol Share<T>::GetProtocol() const noexcept {
  assert(wires_.at(0)->GetProtocol() == MpcProtocol::kArithmeticGmw);
  return wires_.at(0)->GetProtocol();
}

template <typename T>
CircuitType Share<T>::GetCircuitType() const noexcept {
  assert(wires_.at(0)->GetCircuitType() == CircuitType::kArithmetic);
  return wires_.at(0)->GetCircuitType();
}

template <typename T>
const std::vector<T>& Share<T>::GetValue() const {
  auto wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(wires_.at(0));
  assert(wire);
  return wire->GetValues();
}

template <typename T>
std::vector<std::shared_ptr<motion::Share>> Share<T>::Split() const noexcept {
  std::vector<std::shared_ptr<Base>> v;
  v.reserve(wires_.size());
  for (const auto& w : wires_) {
    const std::vector<motion::WirePointer> w_v = {std::static_pointer_cast<motion::Wire>(w)};
    v.emplace_back(std::make_shared<Share<T>>(w_v));
  }
  return v;
}

template <typename T>
std::shared_ptr<motion::Share> Share<T>::GetWire(std::size_t i) const {
  if (i >= wires_.size()) {
    throw std::out_of_range(
        fmt::format("Trying to access wire #{} out of {} wires", i, wires_.size()));
  }
  std::vector<motion::WirePointer> result = {std::static_pointer_cast<motion::Wire>(wires_[i])};
  return std::make_shared<Share<T>>(result);
}

template class Share<std::uint8_t>;
template class Share<std::uint16_t>;
template class Share<std::uint32_t>;
template class Share<std::uint64_t>;
template class Share<__uint128_t>;

}  // namespace encrypto::motion::proto::arithmetic_gmw
