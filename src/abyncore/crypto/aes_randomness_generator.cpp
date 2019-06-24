#include "aes_randomness_generator.h"

namespace ABYN::Crypto {

void AESRandomnessGenerator::Initialize(
    std::uint8_t seed[AESRandomnessGenerator::MASTER_SEED_BYTE_LENGTH]) {
  std::copy(seed, seed + MASTER_SEED_BYTE_LENGTH, std::begin(master_seed_));

  {
    auto digest = HashKey(master_seed_, KeyType::ArithmeticGMWKey);
    std::copy(digest.data(), digest.data() + AES_KEY_SIZE, raw_key_arithmetic_);
  }
  {
    auto digest = HashKey(master_seed_, KeyType::ArithmeticGMWNonce);
    std::copy(digest.data(), digest.data() + AES_BLOCK_SIZE / 2, aes_ctr_nonce_arithmetic_);
  }
  {
    auto digest = HashKey(master_seed_, KeyType::BooleanGMWKey);
    std::copy(digest.data(), digest.data() + AES_KEY_SIZE, raw_key_boolean_);
  }
  {
    auto digest = HashKey(master_seed_, KeyType::BooleanGMWNonce);
    std::copy(digest.data(), digest.data() + AES_BLOCK_SIZE / 2, aes_ctr_nonce_boolean_);
  }
  initialized_ = true;
}

ENCRYPTO::BitVector AESRandomnessGenerator::GetBits(std::size_t gate_id, std::size_t num_of_gates) {
  if (num_of_gates == 0) {
    return {};  // return an empty vector if num_of_gates is zero
  }

  Helpers::WaitFor(initialized_);

  const size_t BITS_IN_CIPHERTEXT = AES_BLOCK_SIZE * 8;

  std::vector<std::uint8_t> input(AES_BLOCK_SIZE), output(AES_BLOCK_SIZE * 2);
  std::vector<std::byte> output_bytes;
  std::copy(std::begin(aes_ctr_nonce_boolean_), std::end(aes_ctr_nonce_boolean_), input.data());
  while (random_bits.GetSize() < (gate_id + num_of_gates)) {
    auto counter_pointer = input.data() + AESRandomnessGenerator::COUNTER_OFFSET;
    auto counter_value = random_bits.GetSize() / BITS_IN_CIPHERTEXT;
    *reinterpret_cast<std::uint64_t *>(counter_pointer) = counter_value;

    // encrypt as in CTR mode, but without sequentially incrementing the counter
    // after each encryption
    int output_length = Encrypt(ctx_boolean_.get(), input.data(), output.data(), 1);

    if (static_cast<std::size_t>(output_length) < AES_BLOCK_SIZE ||
        static_cast<std::size_t>(output_length) > 2 * AES_BLOCK_SIZE) {
      throw(std::runtime_error(fmt::format("AES encryption output has length {}, expected {}",
                                           output_length, 2 * AES_BLOCK_SIZE)));
    }

    for (auto i = 0ull; i < AES_BLOCK_SIZE; ++i) {
      output_bytes.push_back(std::byte(output.at(i)));
    }
    random_bits.Append(ENCRYPTO::BitVector(output_bytes, BITS_IN_CIPHERTEXT));
  }

  return std::move(random_bits.Subset(gate_id, gate_id + num_of_gates));
}

int AESRandomnessGenerator::Encrypt(evp_cipher_ctx_st *ctx, std::uint8_t *input,
                                    std::uint8_t *output, std::size_t num_of_blocks) {
  int output_length, len;

  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, raw_key_arithmetic_, nullptr)) {
    throw(std::runtime_error(fmt::format("Could not re-initialize EVP context")));
  }

  if (1 != EVP_EncryptUpdate(ctx, output, &len, input, AES_BLOCK_SIZE * num_of_blocks)) {
    throw(std::runtime_error(fmt::format("Could not EVP_EncryptUpdate")));
  }

  output_length = len;

  if (1 != EVP_EncryptFinal_ex(ctx, output + len, &len)) {
    throw(std::runtime_error(fmt::format("Could not finalize EVP-AES encryption")));
  }

  output_length += len;
  return output_length;
}

std::vector<std::uint8_t> AESRandomnessGenerator::HashKey(
    const std::uint8_t seed[MASTER_SEED_BYTE_LENGTH], KeyType key_type) {
  std::vector<std::uint8_t> seed_padded(seed, seed + MASTER_SEED_BYTE_LENGTH);
  std::uint32_t key_type32 = key_type;
  const uint8_t *key_type_ptr = reinterpret_cast<const std::uint8_t *>(&key_type32);
  seed_padded.insert(seed_padded.begin(), key_type_ptr, key_type_ptr + sizeof(key_type32));
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  std::uint8_t digest[EVP_MAX_MD_SIZE];
  unsigned int md_len;

#if (OPENSSL_VERSION_NUMBER < 0x1010000fL)
  EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL);
#else
  EVP_DigestInit_ex(mdctx, EVP_blake2b512(), NULL);
#endif

  EVP_DigestUpdate(mdctx, seed_padded.data(), seed_padded.size());
  EVP_DigestFinal_ex(mdctx, digest, &md_len);
  EVP_MD_CTX_free(mdctx);

  return std::vector<std::uint8_t>(digest, digest + AES_KEY_SIZE);
}

std::vector<std::uint8_t> AESRandomnessGenerator::GetSeed() {
  return std::vector<std::uint8_t>(master_seed_, master_seed_ + sizeof(master_seed_));
}
}