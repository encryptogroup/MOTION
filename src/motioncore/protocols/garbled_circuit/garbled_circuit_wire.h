// MIT License
//
// Copyright (c) 2021-2022 Oleksandr Tkachenko
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

#include <span>

#include "protocols/wire.h"
#include "utility/bit_vector.h"
#include "utility/block.h"
#include "utility/fiber_waitable.h"

namespace encrypto::motion {

class Backend;

}  // namespace encrypto::motion

namespace encrypto::motion::proto::garbled_circuit {

class Wire final : public BooleanWire, public FiberSetupWaitable {
 public:
  Wire(Backend& backend, size_t number_of_simd);

  explicit Wire(Block128Vector&& values, Backend& backend);

  explicit Wire(const Block128Vector& values, Backend& backend);

  ~Wire() final = default;

  MpcProtocol GetProtocol() const final { return MpcProtocol::kGarbledCircuit; }

  Wire() = delete;

  Wire(Wire&) = delete;

  std::size_t GetBitLength() const final { return 1; }

  const Block128Vector& GetKeys() const noexcept { return wire_labels_; }

  Block128Vector& GetMutableKeys() noexcept { return wire_labels_; }

  BitVector<> CopyPermutationBits() const;

  bool IsConstant() const noexcept final { return false; }

 private:
  /// Generated wire labels of the garbler or evaluated/obtained wire labels of the evaluator.
  Block128Vector wire_labels_;
};

using WirePointer = std::shared_ptr<Wire>;

BitVector<> CopyPermutationBits(const Block128Vector& keys);

}  // namespace encrypto::motion::proto::garbled_circuit