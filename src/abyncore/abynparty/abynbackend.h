#ifndef ABYNBACKEND_H
#define ABYNBACKEND_H

#include <memory>
#include <iterator>
#include <algorithm>

#include "utility/abynconfiguration.h"
#include "utility/constants.h"
#include "utility/logger.h"

#include "communication/partycommunicationhandler.h"
#include "message_generated.h"

#include "crypto/aesrandomnessgenerator.h"

namespace ABYN {

  class ABYNBackend {

  public:

    ABYNBackend(ABYNConfigurationPtr &abyn_config);

    ~ABYNBackend() {};

    const ABYNConfigurationPtr &GetConfig() { return abyn_config_; };

    const LoggerPtr &GetLogger() { return logger_; };

    size_t NextGateId();

    void InitializeRandomnessGenerator(u8 key[AES_KEY_SIZE], u8 iv[AES_IV_SIZE], size_t party_id);

    void InitializeCommunicationHandlers();

    void Send(size_t party_id, flatbuffers::FlatBufferBuilder &message) {
      if (party_id == abyn_config_->GetMyId()) { throw (std::runtime_error("Want to send message to myself")); }
      communication_handlers_[party_id]->SendMessage(message);
    }

    void TerminateCommunication() {
      for (auto i = 0u; i < communication_handlers_.size(); ++i) {
        if (communication_handlers_[i]) { communication_handlers_[i]->TerminateCommunication(); }
      }
    }

    void WaitForConnectionEnd() {
      for (auto &handler : communication_handlers_) {
        if (handler) { handler->WaitForConnectionEnd(); }
      }
    }

    bool VerifyHelloMessages(){
      bool success = true;
      for(auto & handler : communication_handlers_){
        success &= handler->VerifyHelloMessage();
      }
      return success;
    }

  private:
    ABYNBackend() = delete;

    ABYNConfigurationPtr abyn_config_;
    size_t global_gate_id_ = 0;
    ABYN::LoggerPtr logger_ = nullptr;
    std::vector<std::unique_ptr<ABYN::Crypto::AESRandomnessGenerator>> randomness_generators_;
    std::vector<ABYN::Communication::PartyCommunicationHandlerPtr> communication_handlers_;

    size_t num_threads_ = 16;
  };

  using ABYNBackendPtr = std::shared_ptr<ABYNBackend>;
}

#endif //ABYNBACKEND_H
