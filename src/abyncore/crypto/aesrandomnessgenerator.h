#ifndef RANDOMNESSGENERATOR_H
#define RANDOMNESSGENERATOR_H

#include <vector>
#include <limits>
#include <thread>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/conf.h>
#include <openssl/err.h>

#include <fmt/format.h>

#include "utility/helpers.h"
#include "utility/constants.h"
#include "utility/typedefs.h"

namespace ABYN::Crypto {

  class AESRandomnessGenerator {
  public:
    AESRandomnessGenerator(size_t party_id) : party_id_(party_id) {};

    void Initialize(unsigned char key[AES_KEY_SIZE], unsigned char iv[AES_BLOCK_SIZE / 2]);

    ~AESRandomnessGenerator() { if (initialized_) EVP_CIPHER_CTX_free(ctx_); };

    std::vector<u8> GetSeed();

    bool &IsInitialized() { return initialized_; };

  private:
    static const size_t COUNTER_OFFSET = AES_BLOCK_SIZE / 2;/// Byte length of the AES-CTR nonce
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

  public:
    //---------------------------------------------- Template funtions ----------------------------------------------

    template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    T GetUnsigned(size_t gate_id) {

      while (!initialized_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }

      u8 output[AES_BLOCK_SIZE], input[AES_BLOCK_SIZE];

      std::copy(std::begin(aes_ctr_nonce_), std::end(aes_ctr_nonce_), input);
      std::copy(reinterpret_cast<u8 *>(&gate_id),
                reinterpret_cast<u8 *>(&gate_id) + sizeof(gate_id),
                input + AESRandomnessGenerator::COUNTER_OFFSET);

      //encrypt as in CTR mode, but without incrementing the counter after each encryption
      int output_length = Encrypt(input, output, 1);

      if (output_length != AES_BLOCK_SIZE) {
        throw (std::runtime_error(
            fmt::format("AES encryption output has length {}, expected {}",
                        output_length, AES_BLOCK_SIZE)
        ));
      }

      //combine resulting randomness xored with the gate_id, which is the actual input to AES-CTR
      __uint128_t result = reinterpret_cast<u64 *>(output)[0], mod = std::numeric_limits<T>::max();
      result <<= 64;
      result ^= reinterpret_cast<u64 *>(output)[1] ^ gate_id;
      result %= mod;

      return static_cast<T>(result); //static-cast the result to the smaller ring
    };

    template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    std::vector<T> GetUnsigned(size_t gate_id, size_t num_of_gates) {
      if (num_of_gates == 0) {
        return {}; //return an empty vector if num_of_gates is zero
      }

      Helpers::WaitFor(initialized_);

      //Pre-initialize output vector
      std::vector<T> results;
      results.reserve(num_of_gates);

      auto size_in_bytes = AES_BLOCK_SIZE * (num_of_gates);
      std::vector<u8> output(size_in_bytes + AES_BLOCK_SIZE), input(size_in_bytes + AES_BLOCK_SIZE);

      auto gate_id_copy = gate_id;
      for (auto i = 0u; i < num_of_gates; ++i, ++gate_id_copy) {
        std::copy(std::begin(aes_ctr_nonce_),
                  std::end(aes_ctr_nonce_),
                  input.data() + i * AES_BLOCK_SIZE);
        std::copy(reinterpret_cast<u8 *>(&gate_id_copy),
                  reinterpret_cast<u8 *>(&gate_id_copy) + sizeof(gate_id_copy),
                  input.data() + i * AES_BLOCK_SIZE + AESRandomnessGenerator::COUNTER_OFFSET);
      }

      //encrypt as in CTR mode, but without incrementing the counter after each encryption
      int output_length = Encrypt(input.data(), output.data(), num_of_gates);
      assert(output_length >= 0);

      if (static_cast<size_t>(output_length) != size_in_bytes) {
        throw (std::runtime_error(
            fmt::format("AES encryption output has length {}, expected {}",
                        output_length, size_in_bytes)
        ));
      }

      __uint128_t mod = std::numeric_limits<T>::max(), single_result;
      //combine resulting randomness xored with the gate_id, which is the actual input to AES-CTR
      for (auto i = 0u; i < num_of_gates; ++i) {
        single_result = reinterpret_cast<u64 *>(output.data())[i * 2];
        single_result <<= 64;
        single_result ^= reinterpret_cast<u64 *>(output.data())[i * 2 + 1] ^ gate_id++;
        single_result %= mod;
        results.push_back(static_cast<T>(single_result)); //static-cast the result to the smaller ring
      }

      return std::move(results);
    };
  };
}

#endif //RANDOMNESSGENERATOR_H
