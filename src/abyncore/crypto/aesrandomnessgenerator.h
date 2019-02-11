#ifndef RANDOMNESSGENERATOR_H
#define RANDOMNESSGENERATOR_H

#include <vector>
#include <limits>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/conf.h>
#include <openssl/err.h>

#include "utility/constants.h"
#include "utility/typedefs.h"

namespace ABYN::Crypto {

    class AESRandomnessGenerator {
    public:
      AESRandomnessGenerator(size_t party_id) : party_id_(party_id) {};

      void Initialize(unsigned char key[AES_KEY_SIZE], unsigned char iv[AES_BLOCK_SIZE / 2]);

      ~AESRandomnessGenerator() { if (initialized_) EVP_CIPHER_CTX_free(ctx_); };

      template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
      T GetUnsigned(size_t gate_id);

      template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
      std::vector<T> GetUnsigned(size_t gate_id, size_t num_of_gates);

      std::vector<u8> GetSeed();

    private:
      const size_t COUNTER_OFFSET = AES_BLOCK_SIZE / 2;/// Byte length of the AES-CTR nonce
      size_t party_id_ = -1;

      EVP_CIPHER_CTX *ctx_ = nullptr;                  /// AES context, created only once and reused further
      u8 raw_key_[AES_KEY_SIZE] = {0};                 /// AES key in raw u8 format
      u8 aes_ctr_nonce_[AES_BLOCK_SIZE / 2] = {0};     /// Raw AES CTR nonce that is used in the left part of IV

      AESRandomnessGenerator(AESRandomnessGenerator &) = delete;

      AESRandomnessGenerator() = delete;

      ///
      /// \brief Encrypt a sequence of bytes using 128-bit AES-ECB to further manually compute AES-CTR
      /// which hopefully improves the efficiency of the automated OpenSSL routine for AES-CTR,
      /// where counter is incremented after each encryption.
      ///
      int Encrypt(u8 *input, u8 *output, size_t num_of_blocks);

      bool initialized_ = false;
    };
  }

#endif //RANDOMNESSGENERATOR_H
