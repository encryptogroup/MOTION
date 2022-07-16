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

namespace encrypto::motion::proto::bmr {

Wire::Wire(Backend& backend, std::size_t number_of_simd)
    : BooleanWire(backend, number_of_simd), secret_0_keys_(number_of_simd) {
  InitializationHelperBmr();
}

Wire::Wire(BitVector<>&& values, Backend& backend)
    : BooleanWire(backend, values.GetSize()),
      public_values_(std::move(values)),
      secret_0_keys_(values.GetSize()) {
  InitializationHelperBmr();
}

Wire::Wire(const BitVector<>& values, Backend& backend)
    : BooleanWire(backend, values.GetSize()),
      public_values_(values),
      secret_0_keys_(values.GetSize()) {
  InitializationHelperBmr();
}

Wire::Wire(bool value, Backend& backend)
    : BooleanWire(backend, 1), public_values_(value), secret_0_keys_(1) {
  InitializationHelperBmr();
}

void Wire::InitializationHelperBmr() {
  const auto number_of_parties = backend_.GetCommunicationLayer().GetNumberOfParties();
  public_keys_.resize(number_of_simd_ * number_of_parties);

  setup_ready_cond_ = std::make_unique<FiberCondition>([this]() { return setup_ready_.load(); });
}

void Wire::GenerateRandomPrivateKeys() { secret_0_keys_.SetToRandom(); }

void Wire::GenerateRandomPermutationBits() {
  shared_permutation_bits_ = BitVector<>::SecureRandom(number_of_simd_);
}

}  // namespace encrypto::motion::proto::bmr
