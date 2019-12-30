// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko, Lennart Braun
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

#include "constant_gate.h"
#include "share/constant_share.h"
#include "wire/constant_wire.h"

namespace MOTION::Gates {

ConstantBooleanInputGate::ConstantBooleanInputGate(std::vector<ENCRYPTO::BitVector<>>&& v,
                                                   Backend& backend)
    : Gate(backend) {
  assert(output_wires_.empty());
  output_wires_.reserve(v.size());
  for (std::size_t i = 0; i < v.size(); ++i) {
    output_wires_.emplace_back(
        std::make_shared<MOTION::Wires::ConstantBooleanWire>(std::move(v[i]), backend));
  }
  InitializationHelper();
}

ConstantBooleanInputGate::ConstantBooleanInputGate(const std::vector<ENCRYPTO::BitVector<>>& v,
                                                   Backend& backend)
    : Gate(backend) {
  assert(output_wires_.empty());
  output_wires_.reserve(v.size());
  for (std::size_t i = 0; i < v.size(); ++i) {
    output_wires_.emplace_back(std::make_shared<MOTION::Wires::ConstantBooleanWire>(v[i], backend));
  }
  InitializationHelper();
}

void ConstantBooleanInputGate::InitializationHelper() {
  gate_id_ = GetRegister().NextGateId();
  if constexpr (MOTION::MOTION_VERBOSE_DEBUG) {
    GetLogger().LogTrace(
        fmt::format("Created a ConstantBooleanInputGate with global id {}", gate_id_));
  }

  for (auto& w : output_wires_) GetRegister().RegisterNextWire(w);

  auto gate_info = fmt::format("gate id {}", gate_id_);
  GetLogger().LogDebug(
      fmt::format("Allocated a ConstantBooleanInputGate with following properties: {}", gate_info));
}

MOTION::Shares::SharePtr ConstantBooleanInputGate::GetOutputAsShare() const {
  return std::make_shared<Shares::ConstantBooleanShare>(output_wires_);
}

namespace Arithmetic {

template <typename T>
ConstantArithmeticInputGate<T>::ConstantArithmeticInputGate(const std::vector<T>& v,
                                                            Backend& backend)
    : Gate(backend) {
  assert(output_wires_.empty());
  output_wires_.emplace_back(
      std::make_shared<MOTION::Wires::ConstantArithmeticWire<T>>(v, backend));
  InitializationHelper();
}

template <typename T>
ConstantArithmeticInputGate<T>::ConstantArithmeticInputGate(std::vector<T>&& v, Backend& backend)
    : Gate(backend) {
  assert(output_wires_.empty());
  output_wires_.emplace_back(
      std::make_shared<MOTION::Wires::ConstantArithmeticWire<T>>(std::move(v), backend));
  InitializationHelper();
}

template <typename T>
MOTION::Shares::SharePtr ConstantArithmeticInputGate<T>::GetOutputAsShare() const {
  return std::make_shared<Shares::ConstantArithmeticShare<T>>(output_wires_);
}

template class ConstantArithmeticInputGate<std::uint8_t>;
template class ConstantArithmeticInputGate<std::uint16_t>;
template class ConstantArithmeticInputGate<std::uint32_t>;
template class ConstantArithmeticInputGate<std::uint64_t>;
}  // namespace Arithmetic

}