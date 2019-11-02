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

#include <memory>
#include <vector>

#include <openssl/aes.h>
#include <openssl/evp.h>

#include "utility/helpers.h"

using uint128_t = __uint128_t;

namespace ENCRYPTO {

class PRG {
 public:
  PRG() = default;

  void SetKey(const std::uint8_t *key);

  void SetKey(const std::byte *key);

  std::size_t SetOffset(std::size_t new_offset) {
    std::swap(offset_, new_offset);
    return new_offset;
  }

  std::vector<std::byte> Encrypt(const std::size_t bytes);

  std::vector<std::byte> Encrypt(const std::byte *input, const std::size_t bytes);

  std::vector<std::byte> FixedKeyAES(const std::byte *x, const std::uint64_t i,
                                     const std::size_t num = 1);

  std::vector<std::byte> FixedKeyAES(const std::byte *x, const uint128_t i);

  ~PRG() = default;

 private:
  using EVP_CIPHER_CTX_PTR = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
  static constexpr auto MakeCipherCtx = []() {
    return EVP_CIPHER_CTX_PTR(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
  };

  EVP_CIPHER_CTX_PTR ctx_ = MakeCipherCtx();

  std::array<std::uint8_t *, AES_BLOCK_SIZE> key_;

  std::size_t offset_{0};
};
}