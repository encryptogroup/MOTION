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

#include "sharing_randomness_generator.h"
#include "blake2b.h"

#include <openssl/aes.h>

#include "utility/helpers.h"

namespace encrypto::motion::primitives {

SharingRandomnessGenerator::SharingRandomnessGenerator(std::size_t party_id)
    : party_id_(party_id), context_arithmetic_(MakeCipherCtx()), context_boolean_(MakeCipherCtx()) {
  if (!context_arithmetic_ || !context_boolean_) {
    throw(std::runtime_error(fmt::format("Could not initialize EVP context")));
  }
  initialized_condition_ = std::make_unique<FiberCondition>([this]() { return initialized_; });
}

void SharingRandomnessGenerator::Initialize(
    const std::uint8_t seed[SharingRandomnessGenerator::kMasterSeedByteLength]) {
  std::copy(seed, seed + kMasterSeedByteLength, std::begin(master_seed_));

  {
    auto digest = HashKey(master_seed_, KeyType::kArithmeticGmwKey);
    std::copy(digest.data(), digest.data() + kAesKeySize, raw_key_arithmetic_);
  }
  {
    auto digest = HashKey(master_seed_, KeyType::kArithmeticGmwNonce);
    std::copy(digest.data(), digest.data() + AES_BLOCK_SIZE / 2, aes_ctr_nonce_arithmetic_);
  }
  {
    auto digest = HashKey(master_seed_, KeyType::kBooleanGmwKey);
    std::copy(digest.data(), digest.data() + kAesKeySize, raw_key_boolean_);
  }
  {
    auto digest = HashKey(master_seed_, KeyType::kBooleanGmwNonce);
    std::copy(digest.data(), digest.data() + AES_BLOCK_SIZE / 2, aes_ctr_nonce_boolean_);
  }

  prg_a.SetKey(raw_key_arithmetic_);
  prg_b.SetKey(raw_key_boolean_);

  {
    std::scoped_lock lock(initialized_condition_->GetMutex());
    initialized_ = true;
  }
  initialized_condition_->NotifyAll();
}

BitVector<> SharingRandomnessGenerator::GetBits(const std::size_t gate_id,
                                                const std::size_t number_of_bits) {
  std::scoped_lock lock(random_bits_mutex_);

  if (number_of_bits == 0) {
    return {};  // return an empty vector if number_of_gates is zero
  }

  while (!initialized_) {
    initialized_condition_->Wait();
  }

  constexpr std::size_t kBitsInCiphertext = AES_BLOCK_SIZE * 8;
  constexpr std::size_t kCipherTextsInBatch = 100;
  // initialization for the encryption is costly, so perform random bit generation in a batch
  constexpr std::size_t kBitsInBatch = kBitsInCiphertext * kCipherTextsInBatch;
  constexpr std::size_t kBytesInBatch = kBitsInBatch / 8;

  while (random_bits_.GetSize() < (gate_id - random_bits_offset_ + number_of_bits)) {
    std::vector<std::byte> input(kBytesInBatch + AES_BLOCK_SIZE),
        output(kBytesInBatch + AES_BLOCK_SIZE);
    for (auto offset = random_bits_.GetSize() / kAesBlockSize; offset < kCipherTextsInBatch;
         ++offset) {
      auto pointer = reinterpret_cast<std::uint8_t*>(input.data()) + offset * kAesBlockSize;
      // copy nonce
      std::copy(std::begin(aes_ctr_nonce_boolean_), std::end(aes_ctr_nonce_boolean_), pointer);
      // copy counter value
      *reinterpret_cast<uint64_t*>(pointer + kAesBlockSize / 2) = offset;
    }

    // encrypt as in CTR mode, but without sequentially incrementing the counter
    // after each encryption
    std::vector<std::byte> output_bytes =
        prg_b.Encrypt(input.data(), kCipherTextsInBatch * AES_BLOCK_SIZE);

    for (auto i = 0ull; i < kBytesInBatch; ++i) {
      output_bytes.push_back(std::byte(output.at(i)));
    }
    auto randomness = BitVector(std::move(output_bytes), kBitsInBatch);
    random_bits_.Append(randomness);
  }

  const auto requested = gate_id - random_bits_offset_ + number_of_bits;
  if (requested > random_bits_used_) {
    random_bits_used_ = requested;
  }

  assert(gate_id >= random_bits_offset_);
  return random_bits_.Subset(gate_id - random_bits_offset_,
                             gate_id + number_of_bits - random_bits_offset_);
}

std::vector<std::uint8_t> SharingRandomnessGenerator::HashKey(
    const std::uint8_t seed[kMasterSeedByteLength], const KeyType key_type) {
  std::vector<std::uint8_t> seed_padded(seed, seed + kMasterSeedByteLength);
  std::uint32_t key_type32 = key_type;
  const uint8_t* key_type_pointer = reinterpret_cast<const std::uint8_t*>(&key_type32);
  seed_padded.insert(seed_padded.begin(), key_type_pointer, key_type_pointer + sizeof(key_type32));
  EVP_MD_CTX* md_context = EVP_MD_CTX_new();
  std::uint8_t digest[EVP_MAX_MD_SIZE];
  unsigned int md_length;

#if (OPENSSL_VERSION_NUMBER < 0x1010000fL)
  EVP_DigestInit_ex(md_context, EVP_sha512(), NULL);
#else
  EVP_DigestInit_ex(md_context, EVP_blake2b512(), NULL);
#endif

  EVP_DigestUpdate(md_context, seed_padded.data(), seed_padded.size());
  EVP_DigestFinal_ex(md_context, digest, &md_length);
  EVP_MD_CTX_free(md_context);

  return std::vector<std::uint8_t>(digest, digest + kAesKeySize);
}

std::vector<std::uint8_t> SharingRandomnessGenerator::GetSeed() {
  return std::vector<std::uint8_t>(master_seed_, master_seed_ + sizeof(master_seed_));
}

void SharingRandomnessGenerator::ClearBitPool() { random_bits_ = BitVector<>(); }

void SharingRandomnessGenerator::ResetBitPool() {
  if (random_bits_used_ == random_bits_.GetSize()) {
    random_bits_.Clear();
  } else {
    random_bits_ = random_bits_.Subset(random_bits_used_, random_bits_.GetSize() - 1);
  }
  random_bits_offset_ += random_bits_used_;
  random_bits_used_ = 0;
}

template <typename T>
T SharingRandomnessGenerator::GetUnsigned(std::size_t gate_id) {
  initialized_condition_->Wait();

  std::byte input[AES_BLOCK_SIZE];

  std::copy(std::begin(aes_ctr_nonce_arithmetic_), std::end(aes_ctr_nonce_arithmetic_),
            reinterpret_cast<std::uint8_t*>(input));
  std::copy(reinterpret_cast<const std::byte*>(&gate_id),
            reinterpret_cast<const std::byte*>(&gate_id) + sizeof(gate_id),
            input + SharingRandomnessGenerator::kCounterOffset);

  auto output = prg_a.Encrypt(input, AES_BLOCK_SIZE);

  // combine resulting randomness xored with the gate_id, which is the actual
  // input to AES-CTR
  __uint128_t result = reinterpret_cast<std::uint64_t*>(output.data())[0],
              modulus = std::numeric_limits<T>::max();
  result <<= 64;
  result ^= reinterpret_cast<std::uint64_t*>(output.data())[1] ^ gate_id;
  result %= modulus;

  return static_cast<T>(result);  // static-cast the result to the smaller
                                  // ring
}

template std::uint8_t SharingRandomnessGenerator::GetUnsigned(std::size_t gate_id);
template std::uint16_t SharingRandomnessGenerator::GetUnsigned(std::size_t gate_id);
template std::uint32_t SharingRandomnessGenerator::GetUnsigned(std::size_t gate_id);
template std::uint64_t SharingRandomnessGenerator::GetUnsigned(std::size_t gate_id);
template uint128_t SharingRandomnessGenerator::GetUnsigned(std::size_t gate_id);

template <typename T>
std::vector<T> SharingRandomnessGenerator::GetUnsigned(std::size_t gate_id,
                                                       std::size_t number_of_gates) {
  if (number_of_gates == 0) {
    return {};  // return an empty vector if number_of_gates is zero
  }

  initialized_condition_->Wait();

  // Pre-initialize output vector
  std::vector<T> results;
  results.reserve(number_of_gates);

  auto size_in_bytes = AES_BLOCK_SIZE * (number_of_gates);
  std::vector<std::byte> input(size_in_bytes + AES_BLOCK_SIZE);

  auto gate_id_copy = gate_id;
  for (auto i = 0u; i < number_of_gates; ++i, ++gate_id_copy) {
    std::copy(std::begin(aes_ctr_nonce_arithmetic_), std::end(aes_ctr_nonce_arithmetic_),
              reinterpret_cast<std::uint8_t*>(input.data()) + i * AES_BLOCK_SIZE);
    std::copy(reinterpret_cast<std::byte*>(&gate_id_copy),
              reinterpret_cast<std::byte*>(&gate_id_copy) + sizeof(gate_id_copy),
              input.data() + i * AES_BLOCK_SIZE + SharingRandomnessGenerator::kCounterOffset);
  }

  auto output = prg_a.Encrypt(input.data(), number_of_gates * AES_BLOCK_SIZE);
  __uint128_t modulus = std::numeric_limits<T>::max(), single_result;
  // combine resulting randomness xored with the gate_id, which is the actual
  // input to AES-CTR
  for (auto i = 0u; i < number_of_gates; ++i) {
    single_result = reinterpret_cast<std::uint64_t*>(output.data())[i * 2];
    single_result <<= 64;
    single_result ^= reinterpret_cast<std::uint64_t*>(output.data())[i * 2 + 1] ^ gate_id++;
    single_result %= modulus;
    results.push_back(static_cast<T>(single_result));  // static-cast the result to the smaller ring
  }

  return results;
}

template std::vector<std::uint8_t> SharingRandomnessGenerator::GetUnsigned(
    std::size_t gate_id, std::size_t number_of_gates);
template std::vector<std::uint16_t> SharingRandomnessGenerator::GetUnsigned(
    std::size_t gate_id, std::size_t number_of_gates);
template std::vector<std::uint32_t> SharingRandomnessGenerator::GetUnsigned(
    std::size_t gate_id, std::size_t number_of_gates);
template std::vector<std::uint64_t> SharingRandomnessGenerator::GetUnsigned(
    std::size_t gate_id, std::size_t number_of_gates);
template std::vector<uint128_t> SharingRandomnessGenerator::GetUnsigned(
    std::size_t gate_id, std::size_t number_of_gates);

}  // namespace encrypto::motion::primitives
