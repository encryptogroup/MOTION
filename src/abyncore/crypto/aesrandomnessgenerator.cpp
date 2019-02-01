#include "aesrandomnessgenerator.h"

#include <fmt/format.h>

namespace ABYN::Crypto {

  void AESRandomnessGenerator::Initialize(u8 key[AES_KEY_SIZE], u8 iv[AES_BLOCK_SIZE / 2]) {
    std::copy(key, key + AES_KEY_SIZE, std::begin(raw_key_));
    std::copy(iv, iv + AES_BLOCK_SIZE / 2, std::begin(aes_ctr_nonce_));
    if (!(ctx_ = EVP_CIPHER_CTX_new())) {
      throw (std::runtime_error(fmt::format("Could not initialize EVP context")));
    }
    initialized_ = true;
  };

  template<typename T>
  __uint128_t AESRandomnessGenerator::GetRingLimit() {
    const u64 mod_init = 1u << ((sizeof(T) * 8) - 1);

    __uint128_t mod;

    if constexpr(sizeof(T) == sizeof(u8) || sizeof(T) == sizeof(u16) ||
                 sizeof(T) == sizeof(u32)) {            //the case where we can store 2^l un the variable
      mod = mod_init;
    } else if constexpr(sizeof(T) == sizeof(u64)) {     //2^l is to large to store it in the standard variables
      mod = 1;
      mod <<= (sizeof(T) * 8) - 1;
    } else {                                            //unknown format
      throw (
          std::runtime_error(
              fmt::format("Unknown data type passed to input sharing randomization: {}", typeid(T).name())
          ));
    }

    return mod;
  }

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

///generate a random unsigned integer from kappa=128 bit randomness
  template<typename T, typename = std::enable_if_t <std::is_unsigned_v<T>>>
  T AESRandomnessGenerator::GetUnsigned(size_t gate_id) {

    if (!initialized_) {
      throw (fmt::format("Trying to get randomness from uninitialized generator"));
    }

    constexpr auto ring_limit = AESRandomnessGenerator::GetRingLimit<T>();

    u8 output[AES_BLOCK_SIZE], input[AES_BLOCK_SIZE];

    std::copy(std::begin(aes_ctr_nonce_), std::end(aes_ctr_nonce_), input);
    std::copy(&gate_id, &gate_id + sizeof(gate_id), input + COUNTER_OFFSET);

    //encrypt as in CTR mode, but without incrementing the counter after each encryption
    int output_length = Encrypt(input, output, 1);

    if (output_length != AES_BLOCK_SIZE) {
      throw (std::runtime_error(
          fmt::format("AES encryption output has length {}, expected {}",
                      output_length, AES_BLOCK_SIZE)
      ));
    }

    //combine resulting randomness xored with the gate_id, which is the actual input to AES-CTR
    __uint128_t result = reinterpret_cast<u64 *>(output)[0], mod = ring_limit;
    result <<= 64;
    result ^= reinterpret_cast<u64 *>(output)[1] ^ gate_id;
    result %= mod;

    return static_cast<T>(result); //static-cast the result to the smaller ring
  };

///generate random unsigned integers, each from kappa=128 bit randomness
  template<typename T, typename = std::enable_if_t <std::is_unsigned_v<T>>>
  std::vector <T> AESRandomnessGenerator::GetUnsigned(size_t gate_id, size_t num_of_gates) {
    if (num_of_gates == 0) {
      return {}; //return an empty vector if num_of_gates is zero
    }

    if (!initialized_) {
      throw (fmt::format("Trying to get randomness from uninitialized generator"));
    }

    constexpr auto ring_limit = AESRandomnessGenerator::GetRingLimit<T>();

    //Pre-initialize output vector
    std::vector <T> results;
    results.reserve(num_of_gates);

    std::vector <u8> output(AES_BLOCK_SIZE *num_of_gates);
    std::vector <u8> input(AES_BLOCK_SIZE *num_of_gates);

    auto gate_id_copy = gate_id;
    for (auto i = 0u; i < num_of_gates; ++i, ++gate_id_copy) {
      std::copy(std::begin(aes_ctr_nonce_), std::end(aes_ctr_nonce_), input.data() + i * AES_BLOCK_SIZE);
      std::copy(&gate_id_copy, &gate_id_copy + sizeof(gate_id_copy),
                input.data() + i * AES_BLOCK_SIZE + COUNTER_OFFSET);
    }

    //encrypt as in CTR mode, but without incrementing the counter after each encryption
    int output_length = Encrypt(input.data(), output.data(), num_of_gates);

    if (output_length != AES_BLOCK_SIZE * num_of_gates) {
      throw (std::runtime_error(
          fmt::format("AES encryption output has length {}, expected {}",
                      output_length, AES_BLOCK_SIZE * num_of_gates)
      ));
    }

    __uint128_t mod = ring_limit, single_result;
    //combine resulting randomness xored with the gate_id, which is the actual input to AES-CTR
    for (auto i = 0u; i < num_of_gates; ++i) {
      single_result = reinterpret_cast<u64 *>(output.data())[i * AES_BLOCK_SIZE];
      single_result <<= 64;
      single_result ^= reinterpret_cast<u64 *>(output.data())[i * AES_BLOCK_SIZE + 1] ^ gate_id++;
      single_result %= mod;
      results.push_back(static_cast<T>(single_result)); //static-cast the result to the smaller ring
    }

    return std::move(results);
  };

}