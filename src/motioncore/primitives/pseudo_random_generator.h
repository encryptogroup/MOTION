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

#include <cstddef>
#include <memory>
#include <vector>

#include <openssl/aes.h>
#include <openssl/evp.h>

#include "aes/aesni_primitives.h"
#include "utility/helpers.h"

using uint128_t = __uint128_t;

namespace encrypto::motion::primitives {

class Prg {
 public:
  Prg() = default;

  void SetKey(const std::uint8_t* key);

  void SetKey(const std::byte* key);

  bool ContainsKey() { return contains_key_; }

  const void* GetRoundKeys() const { return round_keys_.data(); }

  std::size_t SetOffset(std::size_t new_offset) {
    std::swap(offset_, new_offset);
    return new_offset;
  }

  std::vector<std::byte> Encrypt(const std::size_t bytes);

  std::vector<std::byte> Encrypt(const std::byte* input, const std::size_t bytes);

  std::vector<std::byte> FixedKeyAes(const std::byte* x, const std::uint64_t i,
                                     const std::size_t num = 1);

  std::vector<std::byte> FixedKeyAes(const std::byte* x, const uint128_t i);
  void Mmo(std::byte* input);

  // Implementation of TMMO^\pi
  // of https://eprint.iacr.org/2019/074
  // with input x and tweak i
  // input and output have to point into a buffer with AES_BLOCK_SIZE bytes
  void FixedKeyAes(const std::byte* input, const uint128_t tweak, std::byte* output);

  ~Prg() = default;

 private:
  alignas(16) std::array<std::byte, kAesRoundKeysSize128> round_keys_;
  using EvpCipherCtxPointer = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
  static constexpr auto MakeCipherCtx = []() {
    return EvpCipherCtxPointer(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
  };

  EvpCipherCtxPointer ctx_ = MakeCipherCtx();

  std::array<std::uint8_t, AES_BLOCK_SIZE> key_;
  bool contains_key_{false};
  std::size_t offset_{0};
};

}  // namespace encrypto::motion::primitives
