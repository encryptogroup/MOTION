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

        void InitializeRandomnessGenerator(unsigned int key[AES_KEY_LENGTH]){
            randomness_generator_ = std::make_unique<RandomnessGenerator>(key);
        };


    private:
        ABYNBackend() {};

        void InitLogger();

        ABYNConfigurationPtr abyn_config_;
        size_t global_gate_id_ = 0;
        boost::log::sources::severity_logger<boost::log::trivial::severity_level> logger_;


        class RandomnessGenerator {
        public:
            RandomnessGenerator(unsigned int key[AES_KEY_LENGTH]) {
                std::copy(key, key + AES_KEY_LENGTH, std::begin(key_));
            };

            template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
            T GetUnsigned(T input){return input;};

        private:
            unsigned int key_[AES_KEY_LENGTH];

            RandomnessGenerator() = delete;
        };

        std::unique_ptr<RandomnessGenerator> randomness_generator_;
    };


    using ABYNBackendPtr = std::shared_ptr<ABYNBackend>;
}

#endif //ABYNBACKEND_H
