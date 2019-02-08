#include "abynbackend.h"

#define BOOST_FILESYSTEM_NO_DEPRECATED

#include <fmt/format.h>

#include "utility/constants.h"
#include "crypto/aesrandomnessgenerator.h"

namespace ABYN {

  ABYNBackend::ABYNBackend(ABYNConfigurationPtr &abyn_config) : abyn_config_(abyn_config) {
    logger_ = std::make_shared<ABYN::Logger>(abyn_config_->GetMyId(),
                                             abyn_config_->GetLoggingSeverityLevel());

    for (auto i = 0u; i < abyn_config_->GetNumOfParties(); ++i) {
      randomness_generators_.push_back(std::make_unique<ABYN::Crypto::AESRandomnessGenerator>(i));
      abyn_config_->GetParty(i)->SetLogger(logger_);
    }
  }

  size_t ABYNBackend::NextGateId() {
    return global_gate_id_++;
  }

  void ABYNBackend::InitializeRandomnessGenerator(u8 key[AES_KEY_SIZE], u8 iv[AES_BLOCK_SIZE / 2], size_t party_id) {
    randomness_generators_[party_id]->Initialize(key, iv);
  }

  void ABYNBackend::InitializeCommunicationHandlers() {
    using PartyCommunicationHandler = ABYN::Communication::PartyCommunicationHandler;
    communication_handlers_.resize(abyn_config_->GetNumOfParties(), nullptr);
    for (auto i = 0u; i < abyn_config_->GetNumOfParties(); ++i) {
      if (i == abyn_config_->GetMyId()) { continue; }
      auto message = fmt::format(
          "Party #{} creates CommHandler for Party #{} with end ip {}, local port {} and remote port {}",
          abyn_config_->GetMyId(), i,
          abyn_config_->GetParty(i)->GetIp(),
          abyn_config_->GetParty(i)->GetSocket()->local_endpoint().port(),
          abyn_config_->GetParty(i)->GetSocket()->remote_endpoint().port());
      logger_->LogDebug(message);

      communication_handlers_.at(i) = std::make_shared<PartyCommunicationHandler>(abyn_config_->GetParty(i), logger_);
    }
  }
}