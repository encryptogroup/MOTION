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
#include "utility/fiber_condition.h"

namespace MOTION::Wires {

BMRWire::BMRWire(const std::size_t n_simd, Backend& backend, bool is_constant)
    : BooleanWire(backend, n_simd, is_constant), secret_0_keys_(n_simd) {
  InitializationHelperBMR();
}

BMRWire::BMRWire(ENCRYPTO::BitVector<>&& values, Backend& backend, bool is_constant)
    : BooleanWire(backend, values.GetSize(), is_constant),
      public_values_(std::move(values)),
      secret_0_keys_(values.GetSize()) {
  InitializationHelperBMR();
}

BMRWire::BMRWire(const ENCRYPTO::BitVector<>& values, Backend& backend, bool is_constant)
    : BooleanWire(backend, values.GetSize(), is_constant),
      public_values_(values),
      secret_0_keys_(values.GetSize()) {
  InitializationHelperBMR();
}

BMRWire::BMRWire(bool value, Backend& backend, bool is_constant)
    : BooleanWire(backend, 1, is_constant), public_values_(value), secret_0_keys_(1) {
  InitializationHelperBMR();
}

void BMRWire::InitializationHelperBMR() {
  const auto num_parties = backend_.GetConfig()->GetNumOfParties();
  public_keys_.resize(num_parties);
  for (auto i = 0ull; i < public_keys_.size(); ++i) public_keys_.at(i).resize(n_simd_);

  setup_ready_cond_ =
      std::make_unique<ENCRYPTO::FiberCondition>([this]() { return setup_ready_.load(); });
}

void BMRWire::GenerateRandomPrivateKeys() {
  const auto& R{backend_.GetConfig()->GetBMRRandomOffset()};
  const auto R_as_bv = ENCRYPTO::AlignedBitVector(R.data(), kappa);
  secret_0_keys_.set_to_random();
}

void BMRWire::GenerateRandomPermutationBits() {
  shared_permutation_bits_ = ENCRYPTO::BitVector<>::Random(n_simd_);
}
}  // namespace MOTION::Wires
