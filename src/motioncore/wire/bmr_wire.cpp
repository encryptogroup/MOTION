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

BMRWire::BMRWire(const std::size_t n_simd, Backend& backend)
    : BooleanWire(backend, n_simd), secret_0_keys_(n_simd) {
  InitializationHelperBMR();
}

BMRWire::BMRWire(ENCRYPTO::BitVector<>&& values, Backend& backend)
    : BooleanWire(backend, values.GetSize()),
      public_values_(std::move(values)),
      secret_0_keys_(values.GetSize()) {
  InitializationHelperBMR();
}

BMRWire::BMRWire(const ENCRYPTO::BitVector<>& values, Backend& backend)
    : BooleanWire(backend, values.GetSize()),
      public_values_(values),
      secret_0_keys_(values.GetSize()) {
  InitializationHelperBMR();
}

BMRWire::BMRWire(bool value, Backend& backend)
    : BooleanWire(backend, 1), public_values_(value), secret_0_keys_(1) {
  InitializationHelperBMR();
}

void BMRWire::InitializationHelperBMR() {
  const auto num_parties = backend_.get_communication_layer().get_num_parties();
  public_keys_.resize(n_simd_ * num_parties);

  setup_ready_cond_ =
      std::make_unique<ENCRYPTO::FiberCondition>([this]() { return setup_ready_.load(); });
}

void BMRWire::GenerateRandomPrivateKeys() { secret_0_keys_.set_to_random(); }

void BMRWire::GenerateRandomPermutationBits() {
  shared_permutation_bits_ = ENCRYPTO::BitVector<>::Random(n_simd_);
}
}  // namespace MOTION::Wires
