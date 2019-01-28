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

        ABYNBackend(ABYNConfigurationPtr &abyn_config) {
            abyn_config_ = abyn_config;
            InitLogger();
        };

        ~ABYNBackend() {};

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

        void InitializeRandomnessGenerator(unsigned char key[AES_KEY_SIZE], unsigned char iv[AES_BLOCK_SIZE / 2]) {
            randomness_generator_ = std::make_unique<RandomnessGenerator>(key, iv);
        };


    private:
        ABYNBackend() {};

        void InitLogger();

        ABYNConfigurationPtr abyn_config_;
        size_t global_gate_id_ = 0;
        boost::log::sources::severity_logger<boost::log::trivial::severity_level> logger_;


        class RandomnessGenerator {
        public:
            RandomnessGenerator(unsigned char key[AES_KEY_SIZE], unsigned char iv[AES_BLOCK_SIZE / 2]);

            ~RandomnessGenerator() {EVP_CIPHER_CTX_free(ctx_);};

            template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
            T GetUnsigned(size_t gate_id);

        private:
            const size_t COUNTER_OFFSET = AES_BLOCK_SIZE / 2;
            EVP_CIPHER_CTX *ctx_ = nullptr;
            unsigned char raw_key_[AES_KEY_SIZE] = {0};
            AES_KEY aes_key_;
            unsigned char aes_ctr_input_[AES_BLOCK_SIZE] = {0};
            unsigned char iv_[AES_BLOCK_SIZE] = {0};
            unsigned int num_ = 0;

            RandomnessGenerator(RandomnessGenerator&) = delete;
            RandomnessGenerator() = delete;
        };

        std::unique_ptr<RandomnessGenerator> randomness_generator_;
    };

    using ABYNBackendPtr = std::shared_ptr<ABYNBackend>;
}

#endif //ABYNBACKEND_H
