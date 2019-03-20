#include "aes_randomness_generator.h"
#include <openssl/evp.h>

namespace ABYN::Crypto {

  void AESRandomnessGenerator::Initialize(u8 key[AES_KEY_SIZE], u8 iv[AES_BLOCK_SIZE / 2]) {
    std::copy(key, key + AES_KEY_SIZE, std::begin(raw_key_));
    std::copy(iv, iv + AES_BLOCK_SIZE / 2, std::begin(aes_ctr_nonce_));
    if (!(ctx_ = EVP_CIPHER_CTX_new())) {
      throw (std::runtime_error(fmt::format("Could not initialize EVP context")));
    }

    if (!(ctx_boolean_ = EVP_CIPHER_CTX_new())) {
      throw (std::runtime_error(fmt::format("Could not initialize EVP context")));
    }

    auto boolean_key = HashKey(key);
    std::copy(boolean_key.data(), boolean_key.data() + AES_KEY_SIZE, raw_key_boolean);

    initialized_ = true;
  };

  std::vector<u8> AESRandomnessGenerator::GetBits(std::size_t gate_id, std::size_t num_of_gates) {
    if (num_of_gates == 0) {
      return {}; //return an empty vector if num_of_gates is zero
    }

    Helpers::WaitFor(initialized_);

    const size_t BITS_IN_CIPHERTEXT = AES_BLOCK_SIZE * 8;

    std::vector<u8> input(AES_BLOCK_SIZE), output(AES_BLOCK_SIZE * 2);
    std::copy(std::begin(aes_ctr_nonce_boolean_), std::end(aes_ctr_nonce_boolean_), input.data());
    while (random_bits_counter < (gate_id + num_of_gates)) {
      auto counter_pointer = input.data() + AESRandomnessGenerator::COUNTER_OFFSET;
      auto counter_value = random_bits_counter / BITS_IN_CIPHERTEXT;
      *reinterpret_cast<u64 *>(counter_pointer) = counter_value;

      //encrypt as in CTR mode, but without sequentially incrementing the counter after each encryption
      int output_length = Encrypt(ctx_boolean_, input.data(), output.data(), 1);

      if (static_cast<std::size_t>(output_length) < AES_BLOCK_SIZE ||
          static_cast<std::size_t>(output_length) > 2 * AES_BLOCK_SIZE) {
        throw (std::runtime_error(
            fmt::format("AES encryption output has length {}, expected {}",
                        output_length, 2 * AES_BLOCK_SIZE)
        ));
      }
      random_bits.insert(random_bits.end(), output.begin(), output.begin() + AES_BLOCK_SIZE);
      random_bits_counter += BITS_IN_CIPHERTEXT;
    }

    std::vector<u8> result(Helpers::Convert::BitsToBytes(num_of_gates));
    CBitVector helper;

    helper.AttachBuf(random_bits.data(), random_bits.size());
    helper.GetBits(result.data(), gate_id, num_of_gates);
    helper.DetachBuf();

    return std::move(result);
  }

  int AESRandomnessGenerator::Encrypt(evp_cipher_ctx_st * ctx, u8 *input, u8 *output, std::size_t num_of_blocks) {
    int output_length, len;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, raw_key_, nullptr)) {
      throw (std::runtime_error(fmt::format("Could not re-initialize EVP context")));
    }

    if (1 != EVP_EncryptUpdate(ctx, output, &len, input, AES_BLOCK_SIZE * num_of_blocks)) {
      throw (std::runtime_error(fmt::format("Could not EVP_EncryptUpdate")));
    }

    output_length = len;

    if (1 != EVP_EncryptFinal_ex(ctx, output + len, &len)) {
      throw (std::runtime_error(fmt::format("Could not finalize EVP-AES encryption")));
    }

    output_length += len;
    return output_length;
  }

  std::vector<u8> AESRandomnessGenerator::HashKey(const u8 old_key[AES_KEY_SIZE]){
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    u8 new_key[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, old_key, AES_KEY_SIZE);
    EVP_DigestFinal_ex(mdctx, new_key, &md_len);
    EVP_MD_CTX_free(mdctx);

    return std::vector<u8>(new_key, new_key + AES_KEY_SIZE);
  }

  std::vector<u8> AESRandomnessGenerator::GetSeed() {
    std::vector<u8> seed(raw_key_, raw_key_ + sizeof(raw_key_));
    seed.insert(seed.end(), aes_ctr_nonce_, aes_ctr_nonce_ + sizeof(aes_ctr_nonce_));
    return std::move(seed);
  }
}