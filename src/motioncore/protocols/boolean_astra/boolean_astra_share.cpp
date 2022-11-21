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

#include "boolean_astra_share.h"


namespace encrypto::motion::proto::boolean_astra {

Share::Share(const motion::WirePointer& wire) : Base(wire->GetBackend()) {
  wires_ = {wire};
  if (!wires_[0]) {
    throw(std::runtime_error("Something went wrong with creating a boolean astra share"));
  }
}

Share::Share(const boolean_astra::WirePointer& wire) : Base(wire->GetBackend()) {
  wires_ = {std::static_pointer_cast<motion::Wire>(wire)};
}

Share::Share(const std::vector<boolean_astra::WirePointer>& wires)
    : Base(wires[0]->GetBackend()) {
  for (auto i = 0ull; i < wires.size(); ++i) {
    wires_.emplace_back(wires[i]);
  }
  if (wires.size() == 0) {
    throw(std::runtime_error("Trying to create an astra share without wires"));
  }
  if (wires.size() > 1) {
    throw(
        std::runtime_error(fmt::format("Cannot create a boolean astra share "
                                       "from more than 1 wire; got {} wires",
                                       wires.size())));
  }
}

Share::Share(const std::vector<motion::WirePointer>& wires) : Base(wires[0]->GetBackend()) {
  if (wires.size() == 0) {
    throw(std::runtime_error("Trying to create a boolean astra share without wires"));
  }
  if (wires.size() > 1) {
    throw(
        std::runtime_error(fmt::format("Cannot create a boolean astra share "
                                       "from more than 1 wire; got {} wires",
                                       wires.size())));
  }
  wires_ = {wires[0]};
  if (!wires_[0]) {
    throw(std::runtime_error("Something went wrong with creating an astra share"));
  }
}

std::size_t Share::GetNumberOfSimdValues() const noexcept {
  return wires_[0]->GetNumberOfSimdValues();
}

MpcProtocol Share::GetProtocol() const noexcept {
  assert(wires_[0]->GetProtocol() == MpcProtocol::kBooleanAstra);
  return wires_[0]->GetProtocol();
}

CircuitType Share::GetCircuitType() const noexcept {
  assert(wires_[0]->GetCircuitType() == CircuitType::kBoolean);
  return wires_[0]->GetCircuitType();
}

bool Share::Finished() {
  return wires_[0]->IsReady();
}

std::vector<std::shared_ptr<motion::Share>> Share::Split() const noexcept {
  std::vector<motion::SharePointer> v;
  v.reserve(wires_.size());
  for (const auto& w : wires_) {
    const std::vector<motion::WirePointer> w_v = {std::static_pointer_cast<motion::Wire>(w)};
    v.emplace_back(std::make_shared<Share>(w_v));
  }
  return v;
}

std::shared_ptr<motion::Share> Share::GetWire(std::size_t i) const {
  if (i >= wires_.size()) {
    throw std::out_of_range(
        fmt::format("Trying to access wire #{} out of {} wires", i, wires_.size()));
  }
  std::vector<motion::WirePointer> result = {std::static_pointer_cast<motion::Wire>(wires_[i])};
  return std::make_shared<Share>(result);
}

}  // namespace encrypto::motion::proto::boolean_astra
