#include "aesrandomnessgenerator.h"

namespace ABYN::Crypto {

  void AESRandomnessGenerator::Initialize(u8 key[AES_KEY_SIZE], u8 iv[AES_BLOCK_SIZE / 2]) {
    std::copy(key, key + AES_KEY_SIZE, std::begin(raw_key_));
    std::copy(iv, iv + AES_BLOCK_SIZE / 2, std::begin(aes_ctr_nonce_));
    if (!(ctx_ = EVP_CIPHER_CTX_new())) {
      throw (std::runtime_error(fmt::format("Could not initialize EVP context")));
    }
    initialized_ = true;
  };

  int AESRandomnessGenerator::Encrypt(u8 *input, u8 *output, size_t num_of_blocks) {
    int output_length;

    if (1 != EVP_EncryptInit_ex(ctx_, EVP_aes_128_ecb(), NULL, raw_key_, nullptr)) {
      throw (std::runtime_error(fmt::format("Could not re-initialize EVP context")));
    }

    if (1 != EVP_EncryptUpdate(ctx_, output, &output_length, input, AES_BLOCK_SIZE * num_of_blocks)) {
      throw (std::runtime_error(fmt::format("Could not EVP_EncryptUpdate")));
    }

    if (1 != EVP_EncryptFinal_ex(ctx_, output + output_length, &output_length)) {
      throw (std::runtime_error(fmt::format("Could not finalize EVP-AES encryption")));
    }
    return output_length;
  }

  std::vector<u8> AESRandomnessGenerator::GetSeed() {
    std::vector<u8> seed(raw_key_, raw_key_ + sizeof(raw_key_));
    seed.insert(seed.end(), aes_ctr_nonce_, aes_ctr_nonce_ + sizeof(aes_ctr_nonce_));
    return std::move(seed);
  }
}