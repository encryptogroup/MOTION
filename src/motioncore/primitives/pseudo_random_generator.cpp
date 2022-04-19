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

#include "pseudo_random_generator.h"

#include <cstdint>

#include "aes/aesni_primitives.h"

namespace encrypto::motion::primitives {

void Prg::SetKey(const std::uint8_t* key) {
  offset_ = 0;
  std::copy(key, key + AES_BLOCK_SIZE, reinterpret_cast<std::uint8_t*>(key_.data()));
  if (1 != EVP_EncryptInit_ex(ctx_.get(), EVP_aes_128_ecb(), NULL,
                              reinterpret_cast<const unsigned char*>(key_.data()), nullptr)) {
    throw std::runtime_error("Could not re-initialize EVP context");
  }
  std::copy(key, key + kAesKeySize128, reinterpret_cast<std::uint8_t*>(round_keys_.data()));
  AesniKeyExpansion128(round_keys_.data());
  contains_key_ = true;
}

void Prg::SetKey(const std::byte* key) { SetKey(reinterpret_cast<const std::uint8_t*>(key)); }

std::vector<std::byte> Prg::Encrypt(const std::size_t bytes) {
  const unsigned int remainder = (bytes & 15u) > 0 ? 1 : 0;
  const std::size_t number_of_blocks = (bytes / 16) + remainder + 1;
  const std::size_t byte_length = number_of_blocks * AES_BLOCK_SIZE;
  int length = static_cast<int>(bytes);

  // Asserting that conversion of (possibly larger) unsigned to signed integral value is safe here.
  assert(length > 0 && "assigning bytes to int should yield a positive value");
  assert(static_cast<std::size_t>(length) == bytes &&
         "converting length back to std::size_t should yield a value equal to bytes");

  std::vector<std::byte> output(byte_length), input(byte_length, std::byte(0));

  for (auto i = 0ull; i < input.size() / AES_BLOCK_SIZE; ++i) {
    *reinterpret_cast<uint64_t*>(input.data() + i * AES_BLOCK_SIZE) = i + offset_;
  }

  if (1 != EVP_EncryptUpdate(ctx_.get(), reinterpret_cast<std::uint8_t*>(output.data()), &length,
                             reinterpret_cast<std::uint8_t*>(input.data()),
                             number_of_blocks * AES_BLOCK_SIZE)) {
    throw std::runtime_error("Could not EVP_EncryptUpdate");
  }

  return output;
}

std::vector<std::byte> Prg::Encrypt(const std::byte* input, const std::size_t bytes) {
  const unsigned int remainder = (bytes & 15u) > 0 ? 1 : 0;
  const std::size_t number_of_blocks = (bytes / 16) + remainder;
  int length = bytes;

  // Asserting that conversion of (possibly larger) unsigned to signed integral value is safe here.
  assert(length > 0 && "assigning bytes to int should yield a positive value");
  assert(static_cast<std::size_t>(length) == bytes &&
         "converting length back to std::size_t should yield a value equal to bytes");

  const std::size_t byte_length = number_of_blocks * AES_BLOCK_SIZE;
  std::vector<std::byte> output(byte_length);

  if (1 != EVP_EncryptUpdate(ctx_.get(), reinterpret_cast<std::uint8_t*>(output.data()), &length,
                             reinterpret_cast<const std::uint8_t*>(input),
                             number_of_blocks * AES_BLOCK_SIZE)) {
    throw std::runtime_error("Could not EVP_EncryptUpdate");
  }

  return output;
}

std::vector<std::byte> Prg::FixedKeyAes(const std::byte* x, const std::uint64_t i,
                                        const std::size_t number) {
  auto aes_x = Encrypt(x, number * AES_BLOCK_SIZE);

  std::size_t j;

  for (j = 0; j < number; ++j) {
    reinterpret_cast<uint64_t*>(aes_x.data())[2 * j] ^= i + j;
  }

  auto output = Encrypt(aes_x.data(), number * AES_BLOCK_SIZE);

  for (j = 0; j < number; ++j) {
    reinterpret_cast<uint128_t*>(output.data())[j] ^=
        reinterpret_cast<const uint128_t*>(aes_x.data())[j];
    reinterpret_cast<uint64_t*>(output.data())[2 * j] ^= i + j;
  }

  return output;
}

std::vector<std::byte> Prg::FixedKeyAes(const std::byte* x, const uint128_t i) {
  auto aes_x = Encrypt(x, AES_BLOCK_SIZE);

  *reinterpret_cast<uint128_t*>(aes_x.data()) ^= i;

  auto output = Encrypt(aes_x.data(), AES_BLOCK_SIZE);

  *reinterpret_cast<uint128_t*>(output.data()) ^=
      *reinterpret_cast<const uint128_t*>(aes_x.data()) ^ i;

  return output;
}

static void EncryptBlock(EVP_CIPHER_CTX* ctx, const std::byte* in, std::byte* output) {
  int outl;
  if (1 != EVP_EncryptUpdate(ctx, reinterpret_cast<std::uint8_t*>(output), &outl,
                             reinterpret_cast<const std::uint8_t*>(in), AES_BLOCK_SIZE)) {
    throw std::runtime_error("Could not EVP_EncryptUpdate");
  }
}

void Prg::FixedKeyAes(const std::byte* input, const uint128_t tweak, std::byte* output) {
  // TODO: enforce buffer alignment, do byte-wise xor (-> better compiler optimization)
  std::array<std::byte, AES_BLOCK_SIZE> tmp1;
  std::array<std::byte, AES_BLOCK_SIZE> tmp2;
  EncryptBlock(ctx_.get(), input, tmp1.data());         // compute \pi(x) ...
  std::copy(std::begin(tmp1), std::end(tmp1), output);  // ... and save it in the output
  *reinterpret_cast<uint128_t*>(tmp1.data()) ^= tweak;  // compute \pi(x) ^ i
  EncryptBlock(ctx_.get(), tmp1.data(), tmp2.data());   // compute \pi(\pi(x) ^ i)
  // compute \pi(\pi(x) ^ i) ^ \pi(x):
  *reinterpret_cast<uint128_t*>(output) ^= *reinterpret_cast<const uint128_t*>(tmp2.data());
}

void Prg::Mmo(std::byte* input) { AesniMmoSingle(round_keys_.data(), input); }

}  // namespace encrypto::motion::primitives
