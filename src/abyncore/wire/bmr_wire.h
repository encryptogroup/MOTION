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

#include "wire.h"

#include "utility/bit_vector.h"

namespace ABYN::Wires {

class BMRWire : BooleanWire {
 public:
  BMRWire(const std::size_t bitlen, const std::size_t n_simd, std::weak_ptr<Backend> backend,
          bool is_constant = false);

  BMRWire(ENCRYPTO::BitVector<> &&values, std::weak_ptr<Backend> backend, bool is_constant = false);

  BMRWire(const ENCRYPTO::BitVector<> &values, std::weak_ptr<Backend> backend,
          bool is_constant = false);

  BMRWire(bool value, std::weak_ptr<Backend> backend, bool is_constant = false);

  ~BMRWire() final = default;

  MPCProtocol GetProtocol() const final { return MPCProtocol::BMR; }

  BMRWire() = delete;

  BMRWire(BMRWire &) = delete;

  std::size_t GetBitLength() const final { return 1; }

  const ENCRYPTO::BitVector<> &GetPublicValuesOnWire() const { return public_values_; }

  ENCRYPTO::BitVector<> &GetPublicMutableValuesOnWire() { return public_values_; }

  const ENCRYPTO::BitVector<> &GetPermutationBitsOnWire() const { return shared_permutation_bits_; }

  ENCRYPTO::BitVector<> &GetMutablePermutationBitsOnWire() { return shared_permutation_bits_; }

  const auto &GetKeysOnWire() const { return keys_; }

  auto &GetMutableKeysOnWire() { return keys_; }

 private:
  void InitializationHelperBMR();

  ENCRYPTO::BitVector<> public_values_, shared_permutation_bits_;
  std::vector<ENCRYPTO::BitVector<>> keys_;
};

using BMRWirePtr = std::shared_ptr<BMRWire>;
}  // namespace ABYN::Wires
