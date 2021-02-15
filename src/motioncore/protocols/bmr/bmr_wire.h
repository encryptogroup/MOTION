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

#include "protocols/wire.h"
#include "utility/bit_vector.h"
#include "utility/block.h"
#include "utility/fiber_condition.h"

namespace encrypto::motion::proto::bmr {

class Wire final : public BooleanWire {
 public:
  Wire(Backend& backend, std::size_t number_of_simd);

  explicit Wire(BitVector<>&& values, Backend& backend);

  explicit Wire(const BitVector<>& values, Backend& backend);

  explicit Wire(bool value, Backend& backend);

  ~Wire() final = default;

  MpcProtocol GetProtocol() const final { return MpcProtocol::kBmr; }

  Wire() = delete;

  Wire(Wire&) = delete;

  std::size_t GetBitLength() const final { return 1; }

  const BitVector<>& GetPublicValues() const { return public_values_; }

  BitVector<>& GetMutablePublicValues() { return public_values_; }

  const BitVector<>& GetPermutationBits() const { return shared_permutation_bits_; }

  BitVector<>& GetMutablePermutationBits() { return shared_permutation_bits_; }

  const auto& GetSecretKeys() const { return secret_0_keys_; }

  auto& GetMutableSecretKeys() { return secret_0_keys_; }

  const auto& GetPublicKeys() const { return public_keys_; }

  auto& GetMutablePublicKeys() { return public_keys_; }

  void GenerateRandomPrivateKeys();

  void GenerateRandomPermutationBits();

  void SetSetupIsReady() {
    {
      std::scoped_lock lock(setup_ready_cond_->GetMutex());
      setup_ready_ = true;
    }
    setup_ready_cond_->NotifyAll();
  }

  const auto& GetSetupReadyCondition() const { return setup_ready_cond_; }

  bool IsConstant() const noexcept final { return false; }

 protected:
  void DynamicClear() final { setup_ready_ = false; }

 private:
  void InitializationHelperBmr();

  // Store the cleartext values in public_values_ if this wire is an output wire.
  BitVector<> public_values_;
  BitVector<> shared_permutation_bits_;

  // Store one of the secret keys since we have the global offset for free XOR.
  // Structure for n simd values: (k_1 || k_2 || ... || k_n).
  Block128Vector secret_0_keys_;

  // Buffer for the super keys corresponding to each simd value.
  // Structure for n simd values and m parties: (K_1 || K_2 || ... || K_n), where K is constructed
  // by concatenating each of m parties' public keys, i.e., K = (k_1 || k_2 || ... || k_m).
  Block128Vector public_keys_;

  std::atomic<bool> setup_ready_{false};
  std::unique_ptr<FiberCondition> setup_ready_cond_;
};

using WirePointer = std::shared_ptr<Wire>;

}  // namespace encrypto::motion::proto::bmr
