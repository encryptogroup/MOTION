#pragma once

#include <limits>
#include <thread>
#include <vector>

#include <openssl/aes.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>

#if (OPENSSL_VERSION_NUMBER < 0x1010000fL)
static auto &EVP_MD_CTX_new = EVP_MD_CTX_create;
static auto &EVP_MD_CTX_free = EVP_MD_CTX_destroy;
#endif

#include <fmt/format.h>

#include "utility/bit_vector.h"
#include "utility/constants.h"
#include "utility/helpers.h"
#include "utility/typedefs.h"

namespace ABYN::Crypto {

class AESRandomnessGenerator {
 public:
  constexpr static std::size_t MASTER_SEED_BYTE_LENGTH = 32;

  AESRandomnessGenerator(std::size_t party_id)
      : party_id_(party_id), ctx_arithmetic_(MakeCipherCtx()), ctx_boolean_(MakeCipherCtx()) {
    if (!ctx_arithmetic_ || !ctx_boolean_) {
      throw(std::runtime_error(fmt::format("Could not initialize EVP context")));
    }
  }

  void Initialize(unsigned char seed[AESRandomnessGenerator::MASTER_SEED_BYTE_LENGTH]);

  ~AESRandomnessGenerator() = default;

  std::vector<std::uint8_t> GetSeed();

  bool &IsInitialized() { return initialized_; }

  AESRandomnessGenerator(AESRandomnessGenerator &) = delete;

  AESRandomnessGenerator() = delete;

  //---------------------------------------------- Template funtions
  //----------------------------------------------
  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  T GetUnsigned(std::size_t gate_id) {
    while (!initialized_) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    std::uint8_t output[AES_BLOCK_SIZE], input[AES_BLOCK_SIZE];

    std::copy(std::begin(aes_ctr_nonce_arithmetic_), std::end(aes_ctr_nonce_arithmetic_), input);
    std::copy(reinterpret_cast<std::uint8_t *>(&gate_id),
              reinterpret_cast<std::uint8_t *>(&gate_id) + sizeof(gate_id),
              input + AESRandomnessGenerator::COUNTER_OFFSET);

    // encrypt as in CTR mode, but without sequentially incrementing the counter
    // after each encryption
    int output_length = Encrypt(ctx_arithmetic_.get(), input, output, 1);

    if (output_length != AES_BLOCK_SIZE) {
      throw(std::runtime_error(fmt::format("AES encryption output has length {}, expected {}",
                                           output_length, AES_BLOCK_SIZE)));
    }

    // combine resulting randomness xored with the gate_id, which is the actual
    // input to AES-CTR
    __uint128_t result = reinterpret_cast<std::uint64_t *>(output)[0],
                mod = std::numeric_limits<T>::max();
    result <<= 64;
    result ^= reinterpret_cast<std::uint64_t *>(output)[1] ^ gate_id;
    result %= mod;

    return static_cast<T>(result);  // static-cast the result to the smaller
                                    // ring
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  std::vector<T> GetUnsigned(std::size_t gate_id, std::size_t num_of_gates) {
    if (num_of_gates == 0) {
      return {};  // return an empty vector if num_of_gates is zero
    }

    Helpers::WaitFor(initialized_);

    // Pre-initialize output vector
    std::vector<T> results;
    results.reserve(num_of_gates);

    auto size_in_bytes = AES_BLOCK_SIZE * (num_of_gates);
    std::vector<std::uint8_t> output(size_in_bytes + AES_BLOCK_SIZE),
        input(size_in_bytes + AES_BLOCK_SIZE);

    auto gate_id_copy = gate_id;
    for (auto i = 0u; i < num_of_gates; ++i, ++gate_id_copy) {
      std::copy(std::begin(aes_ctr_nonce_arithmetic_), std::end(aes_ctr_nonce_arithmetic_),
                input.data() + i * AES_BLOCK_SIZE);
      std::copy(reinterpret_cast<std::uint8_t *>(&gate_id_copy),
                reinterpret_cast<std::uint8_t *>(&gate_id_copy) + sizeof(gate_id_copy),
                input.data() + i * AES_BLOCK_SIZE + AESRandomnessGenerator::COUNTER_OFFSET);
    }

    // encrypt as in CTR mode, but without sequentially incrementing the counter
    // after each encryption
    int output_length = Encrypt(ctx_arithmetic_.get(), input.data(), output.data(), num_of_gates);
    assert(output_length >= 0);

    if (static_cast<std::size_t>(output_length) < size_in_bytes ||
        static_cast<std::size_t>(output_length) > size_in_bytes + AES_BLOCK_SIZE) {
      throw(std::runtime_error(fmt::format("AES encryption output has length {}, expected {}",
                                           output_length, size_in_bytes)));
    }

    __uint128_t mod = std::numeric_limits<T>::max(), single_result;
    // combine resulting randomness xored with the gate_id, which is the actual
    // input to AES-CTR
    for (auto i = 0u; i < num_of_gates; ++i) {
      single_result = reinterpret_cast<std::uint64_t *>(output.data())[i * 2];
      single_result <<= 64;
      single_result ^= reinterpret_cast<std::uint64_t *>(output.data())[i * 2 + 1] ^ gate_id++;
      single_result %= mod;
      results.push_back(
          static_cast<T>(single_result));  // static-cast the result to the smaller ring
    }

    return std::move(results);
  }

  ENCRYPTO::BitVector GetBits(std::size_t gate_id, std::size_t num_of_gates);

 private:
  static constexpr std::size_t COUNTER_OFFSET =
      AES_BLOCK_SIZE / 2;  /// Byte length of the AES-CTR nonce
  std::int64_t party_id_ = -1;

  /// AES context, created only once and reused further
  using EVP_CIPHER_CTX_PTR = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
  static constexpr auto MakeCipherCtx = []() {
    return EVP_CIPHER_CTX_PTR(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
  };
  EVP_CIPHER_CTX_PTR ctx_arithmetic_, ctx_boolean_;

  std::uint8_t master_seed_[AESRandomnessGenerator::MASTER_SEED_BYTE_LENGTH] = {0};
  std::uint8_t raw_key_arithmetic_[AES_KEY_SIZE] = {0},
               raw_key_boolean_[AES_KEY_SIZE] = {0};  /// AES key in raw std::uint8_t format
  std::uint8_t aes_ctr_nonce_arithmetic_[AES_BLOCK_SIZE / 2] = {0};
  std::uint8_t aes_ctr_nonce_boolean_[AES_BLOCK_SIZE / 2] = {0};  /// Raw AES CTR nonce that is used
                                                                  /// in the left part of IV

  ///
  /// \brief Encrypt a sequence of bytes using 128-bit AES-ECB to further
  /// manually compute AES-CTR which hopefully improves the efficiency of the
  /// automated OpenSSL routine for AES-CTR, where counter is incremented after
  /// each encryption.
  ///
  int Encrypt(evp_cipher_ctx_st *ctx, std::uint8_t *input, std::uint8_t *output,
              std::size_t num_of_blocks);

  enum KeyType {
    ArithmeticGMWKey = 1u,
    ArithmeticGMWNonce = 2u,
    BooleanGMWKey = 3u,
    BooleanGMWNonce = 4u
  };

  // use old key to generate randomness for a new key
  std::vector<std::uint8_t> HashKey(const std::uint8_t old_key[AES_KEY_SIZE], KeyType key_type);

  bool initialized_ = false;

  ENCRYPTO::BitVector random_bits;
};
}  // namespace ABYN::Crypto
