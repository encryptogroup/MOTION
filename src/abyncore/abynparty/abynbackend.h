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

#include "communication/partycommunicationhandler.h"
#include "communication/hellomessage.h"
#include "message_generated.h"

#include "crypto/aesrandomnessgenerator.h"

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

    void InitializeRandomnessGenerator(u8 key[AES_KEY_SIZE], u8 iv[AES_IV_SIZE], size_t party_id);

    void InitializeCommunicationHandlers();

  private:
    ABYNBackend() {};

    void InitLogger();

    ABYNConfigurationPtr abyn_config_;
    size_t global_gate_id_ = 0;
    boost::log::sources::severity_logger<boost::log::trivial::severity_level> logger_;
    std::vector<std::unique_ptr<ABYN::Crypto::AESRandomnessGenerator>> randomness_generators_;
    std::vector<ABYN::Communication::PartyCommunicationHandlerPtr> communication_handlers_;

    size_t num_threads_ = 16;
  };

  using ABYNBackendPtr = std::shared_ptr<ABYNBackend>;
}

#endif //ABYNBACKEND_H
