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

#include <boost/fiber/mutex.hpp>
#include <limits>
#include <thread>
#include <vector>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>

#if (OPENSSL_VERSION_NUMBER < 0x1010000fL)
static auto& EVP_MD_CTX_new = EVP_MD_CTX_create;
static auto& EVP_MD_CTX_free = EVP_MD_CTX_destroy;
#endif

#include <fmt/format.h>

#include "pseudo_random_generator.h"
#include "utility/bit_vector.h"
#include "utility/constants.h"
#include "utility/fiber_condition.h"
#include "utility/typedefs.h"

namespace encrypto::motion {

class FiberCondition;

}  // namespace encrypto::motion

namespace encrypto::motion::primitives {

class SharingRandomnessGenerator {
 public:
  constexpr static std::size_t kMasterSeedByteLength = 32;

  SharingRandomnessGenerator(std::size_t party_id);

  void Initialize(const unsigned char seed[SharingRandomnessGenerator::kMasterSeedByteLength]);

  ~SharingRandomnessGenerator() = default;

  std::vector<std::uint8_t> GetSeed();

  bool& IsInitialized() { return initialized_; }

  std::unique_ptr<FiberCondition>& GetInitializedCondition() noexcept {
    return initialized_condition_;
  }

  SharingRandomnessGenerator(SharingRandomnessGenerator&) = delete;

  SharingRandomnessGenerator() = delete;

  template <typename T>
  T GetUnsigned(const std::size_t gate_id);

  template <typename T>
  std::vector<T> GetUnsigned(std::size_t gate_id, std::size_t number_of_gates);

  BitVector<> GetBits(std::size_t gate_id, std::size_t number_of_bits);

  void ClearBitPool();

  void ResetBitPool();

 private:
  static constexpr std::size_t kCounterOffset =
      AES_BLOCK_SIZE / 2;  /// Byte length of the AES-CTR nonce
  std::int64_t party_id_ = -1;

  /// AES context, created only once and reused further
  using EvpCipherCtxPointer = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
  static constexpr auto MakeCipherCtx = []() {
    return EvpCipherCtxPointer(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
  };
  EvpCipherCtxPointer context_arithmetic_, context_boolean_;

  std::uint8_t master_seed_[SharingRandomnessGenerator::kMasterSeedByteLength] = {0};
  std::uint8_t raw_key_arithmetic_[kAesKeySize] = {0};
  std::uint8_t raw_key_boolean_[kAesKeySize] = {0};  /// AES key in raw std::uint8_t format
  std::uint8_t aes_ctr_nonce_arithmetic_[AES_BLOCK_SIZE / 2] = {0};
  std::uint8_t aes_ctr_nonce_boolean_[AES_BLOCK_SIZE / 2] = {0};  /// Raw AES CTR nonce that is used
  /// in the left part of IV

  primitives::Prg prg_a, prg_b;

  enum KeyType : unsigned int {
    kArithmeticGmwKey = 0,
    kArithmeticGmwNonce = 1,
    kBooleanGmwKey = 2,
    kBooleanGmwNonce = 3,
    kInvalidKeyType = 4
  };

  // use a seed to generate randomness for a new key
  std::vector<std::uint8_t> HashKey(const std::uint8_t seed[kAesKeySize], const KeyType key_type);

  bool initialized_ = false;

  BitVector<> random_bits_;

  std::size_t random_bits_offset_ = 0;
  std::size_t random_bits_used_ = 0;

  boost::fibers::mutex random_bits_mutex_;

  std::unique_ptr<FiberCondition> initialized_condition_;
};
}  // namespace encrypto::motion::primitives
