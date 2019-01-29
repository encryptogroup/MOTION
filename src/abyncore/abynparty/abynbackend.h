#ifndef ABYNBACKEND_H
#define ABYNBACKEND_H

#include <memory>
#include <iterator>
#include <algorithm>

#include <boost/log/core/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sources/logger.hpp>
#include <boost/log/sinks/text_file_backend.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/sources/record_ostream.hpp>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/conf.h>
#include <openssl/err.h>

#include "utility/abynconfiguration.h"
#include "utility/constants.h"

namespace ABYN {

  class ABYNBackend {

  public:

    ABYNBackend(ABYNConfigurationPtr &abyn_config);

    ~ABYNBackend() {};

    ABYNConfigurationPtr &GetConfig() { return abyn_config_; };

    void Log(boost::log::trivial::severity_level severity_level, std::string &msg);

    void Log(boost::log::trivial::severity_level severity_level, std::string &&msg);

    void LogTrace(std::string &msg);

    void LogTrace(std::string &&msg);

    void LogInfo(std::string &msg);

    void LogInfo(std::string &&msg);

    void LogDebug(std::string &msg);

    void LogDebug(std::string &&msg);

    void LogError(std::string &msg);

    void LogError(std::string &&msg);

    size_t NextGateId();

    void InitializeRandomnessGenerator(u8 key[AES_KEY_SIZE], u8 iv[AES_BLOCK_SIZE / 2], size_t party_id) {
      randomness_generator_[party_id]->Initialize(key, iv);
    };


  private:
    ABYNBackend() {};

    void InitLogger();

    ABYNConfigurationPtr abyn_config_;
    size_t global_gate_id_ = 0;
    boost::log::sources::severity_logger<boost::log::trivial::severity_level> logger_;


    class RandomnessGenerator {
    public:
      RandomnessGenerator(size_t party_id, ABYNBackend *backend) : backend_(backend), party_id_(party_id) {};

      void Initialize(unsigned char key[AES_KEY_SIZE], unsigned char iv[AES_BLOCK_SIZE / 2]);

      ~RandomnessGenerator() { if (initialized_) EVP_CIPHER_CTX_free(ctx_); };

      template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
      T GetUnsigned(size_t gate_id);

      template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
      std::vector<T> GetUnsigned(size_t gate_id, size_t num_of_gates);

    private:
      ABYNBackend *backend_;           /// ABYNBackend to enable logging
      const size_t COUNTER_OFFSET = AES_BLOCK_SIZE / 2;/// Byte length of the AES-CTR nonce
      size_t party_id_ = -1;

      EVP_CIPHER_CTX *ctx_ = nullptr;                  /// AES context, created only once and reused further
      u8 raw_key_[AES_KEY_SIZE] = {0};                 /// AES key in raw u8 format
      u8 aes_ctr_nonce_[AES_BLOCK_SIZE / 2] = {0};     /// Raw AES CTR nonce that is used in the left part of IV

      RandomnessGenerator(RandomnessGenerator &) = delete;

      RandomnessGenerator() = delete;

      ///
      /// \brief Encrypt a sequence of bytes using 128-bit AES-ECB to further manually compute AES-CTR
      /// which hopefully improves the efficiency of the automated OpenSSL routine for AES-CTR,
      /// where counter is incremented after each encryption.
      ///
      int Encrypt(u8 *input, u8 *output, size_t num_of_blocks);

      ///
      /// \brief Returns 2^l as a 128-bit unsigned integer, where l is the bit-length of the type T.
      ///
      template<typename T>
      static __uint128_t GetRingLimit();

      bool initialized_ = false;
    };

    std::vector<std::unique_ptr<RandomnessGenerator>> randomness_generator_;

  };

  using ABYNBackendPtr = std::shared_ptr<ABYNBackend>;
}

#endif //ABYNBACKEND_H
