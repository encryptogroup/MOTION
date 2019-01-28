#include "abynbackend.h"

#define BOOST_FILESYSTEM_NO_DEPRECATED

//#include <boost/filesystem/path.hpp>


#include <fmt/format.h>
#include <fmt/time.h>

#include <boost/log/support/date_time.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include "utility/constants.h"

namespace logging = boost::log;
namespace keywords = boost::log::keywords;
namespace src = boost::log::sources;
namespace sinks = boost::log::sinks;
namespace expr = boost::log::expressions;

namespace ABYN {

    void ABYNBackend::InitLogger() {
        auto time_now = std::time(nullptr);
        auto id = abyn_config_->GetMyId();
        auto date = fmt::format("{:%Y.%m.%d--%H:%M:%S}.", *std::localtime(&time_now));
        logging::add_file_log(keywords::file_name = fmt::format("id{}_{}_{}_%N.log", id, date, LOG_PATH).c_str(),
                              keywords::rotation_size = 100 * MB,
                              keywords::format =
                                      (
                                              expr::stream
                                                      << expr::format_date_time<boost::posix_time::ptime>("TimeStamp",
                                                                                                          "%Y-%m-%d %H:%M:%S.%f")
                                                      << ": <" << logging::trivial::severity
                                                      << "> " << expr::smessage
                                      )
        );

        logging::core::get()->set_filter(logging::trivial::severity >= abyn_config_->GetLoggingSeverityLevel());
        logging::add_common_attributes();
        logger_ = src::severity_logger<logging::trivial::severity_level>();
    }

    void ABYNBackend::Log(logging::trivial::severity_level severity_level, std::string &msg) {
        BOOST_LOG_SEV(logger_, severity_level) << msg;
    };

    void ABYNBackend::Log(logging::trivial::severity_level severity_level, std::string &&msg) {
        BOOST_LOG_SEV(logger_, severity_level) << msg;
    };

    void ABYNBackend::LogTrace(std::string &msg) {
        if constexpr(VERBOSE_DEBUG) {
            BOOST_LOG_SEV(logger_, logging::trivial::trace) << msg;
        }
    };

    void ABYNBackend::LogTrace(std::string &&msg) {
        if constexpr(VERBOSE_DEBUG) {
            BOOST_LOG_SEV(logger_, logging::trivial::trace) << msg;
        }
    };

    void ABYNBackend::LogInfo(std::string &msg) {
        BOOST_LOG_SEV(logger_, logging::trivial::info) << msg;
    };

    void ABYNBackend::LogInfo(std::string &&msg) {
        BOOST_LOG_SEV(logger_, logging::trivial::info) << msg;
    };

    void ABYNBackend::LogDebug(std::string &msg) {
        if constexpr(DEBUG) {
            BOOST_LOG_SEV(logger_, logging::trivial::debug) << msg;
        }
    };

    void ABYNBackend::LogDebug(std::string &&msg) {
        if constexpr(DEBUG) {
            BOOST_LOG_SEV(logger_, logging::trivial::debug) << msg;
        }
    };

    void ABYNBackend::LogError(std::string &msg) {
        BOOST_LOG_SEV(logger_, logging::trivial::error) << msg;
    };

    void ABYNBackend::LogError(std::string &&msg) {
        BOOST_LOG_SEV(logger_, logging::trivial::error) << msg;
    };

    size_t ABYNBackend::NextGateId() {
        return global_gate_id_++;
    };

    ABYNBackend::RandomnessGenerator::RandomnessGenerator(
            unsigned char key[AES_KEY_SIZE], unsigned char iv[AES_BLOCK_SIZE / 2]) {
        std::copy(key, key + AES_KEY_SIZE, std::begin(raw_key_));
        std::copy(iv, iv + AES_BLOCK_SIZE / 2, std::begin(aes_ctr_input_));
        if (!(ctx_ = EVP_CIPHER_CTX_new())) {
            throw (std::runtime_error(fmt::format("Could not initialize EVP context")));
        }
    };

    template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    T ABYNBackend::RandomnessGenerator::GetUnsigned(size_t gate_id) {
        u8 output[AES_BLOCK_SIZE] = {0};
        u8 input[AES_BLOCK_SIZE];
        int output_length;

        std::copy(&gate_id + COUNTER_OFFSET, &gate_id + COUNTER_OFFSET + sizeof(gate_id), input);


        //encrypt as in CTR mode, but without incrementing the counter after each encryption
        if (1 != EVP_EncryptInit_ex(ctx_, EVP_aes_128_ecb(), NULL, raw_key_, nullptr)) {
            throw (std::runtime_error(fmt::format("Could not re-initialize EVP context")));
        }

        if (1 != EVP_EncryptUpdate(ctx_, output, &output_length, input, AES_BLOCK_SIZE)) {
            throw (std::runtime_error(fmt::format("Could not EVP_EncryptUpdate")));
        }

        if (1 != EVP_EncryptFinal_ex(ctx_, output + output_length, &output_length)) {
            throw (std::runtime_error(fmt::format("Could not finalize EVP-AES encryption")));
        }

        if (output_length != AES_BLOCK_SIZE) {
            throw (std::runtime_error(
                    fmt::format("AES encryption output has length {}, expected {}",
                                output_length, AES_BLOCK_SIZE)
            ));
        }

        __uint128_t result = reinterpret_cast<u64 *>(output)[0];
        result <<= 64;
        result ^= reinterpret_cast<u64 *>(output)[1] ^ gate_id;

        const u64 mod_init = 1 << ((sizeof(T) * 8) - 1);

        __uint128_t mod;
        if constexpr(sizeof(T) == sizeof(u8) || sizeof(T) == sizeof(u16) || sizeof(T) == sizeof(u32)) {
            mod = mod_init;
        } else if constexpr(sizeof(T) == sizeof(u64)) {
            mod = 1;
            mod <<= (sizeof(T) * 8) - 1;
        } else {
            throw (std::runtime_error(
                    fmt::format("Unknown data type passed to input sharing randomization: {}", typeid(T).name())));
        }

        result %= mod;

        return static_cast<T>(result);
    };

}