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

#include "bmr_wire.h"

#include "base/backend.h"
#include "utility/condition.h"

namespace MOTION::Wires {
BMRWire::BMRWire(const std::size_t n_simd, std::weak_ptr<Backend> backend, bool is_constant) {
  backend_ = backend;
  is_constant_ = is_constant;
  n_simd_ = n_simd;
  InitializationHelper();
  InitializationHelperBMR();
}

BMRWire::BMRWire(ENCRYPTO::BitVector<> &&values, std::weak_ptr<Backend> backend, bool is_constant) {
  public_values_ = std::move(values);
  backend_ = backend;
  is_constant_ = is_constant;
  n_simd_ = public_values_.GetSize();
  InitializationHelper();
  InitializationHelperBMR();
}

BMRWire::BMRWire(const ENCRYPTO::BitVector<> &values, std::weak_ptr<Backend> backend,
                 bool is_constant) {
  public_values_ = values;
  backend_ = backend;
  is_constant_ = is_constant;
  n_simd_ = public_values_.GetSize();
  InitializationHelper();
  InitializationHelperBMR();
}

BMRWire::BMRWire(bool value, std::weak_ptr<Backend> backend, bool is_constant) {
  public_values_.Append(value);
  backend_ = backend;
  is_constant_ = is_constant;
  n_simd_ = 1;
  InitializationHelper();
  InitializationHelperBMR();
}

void BMRWire::InitializationHelperBMR() {
  const auto backend = GetBackend().lock();
  assert(backend);
  const auto num_parties = backend->GetConfig()->GetNumOfParties();
  std::get<0>(secret_keys_).resize(n_simd_);
  std::get<1>(secret_keys_).resize(n_simd_);
  public_keys_.resize(num_parties);
  for (auto i = 0ull; i < public_keys_.size(); ++i) public_keys_.at(i).resize(n_simd_);

  setup_ready_cond_ =
      std::make_unique<ENCRYPTO::Condition>([this]() { return setup_ready_.load(); });
}

void BMRWire::GenerateRandomPrivateKeys() {
  for (auto &key : std::get<0>(secret_keys_)) {
    key = ENCRYPTO::BitVector<>::Random(kappa);
  }
  for (auto &key : std::get<1>(secret_keys_)) {
    key = ENCRYPTO::BitVector<>::Random(kappa);
  }
}

void BMRWire::GenerateRandomPermutationBits() {
  shared_permutation_bits_ = ENCRYPTO::BitVector<>::Random(n_simd_);
}
}