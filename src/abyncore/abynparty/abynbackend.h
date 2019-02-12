#ifndef ABYNBACKEND_H
#define ABYNBACKEND_H

#include <memory>
#include <iterator>
#include <algorithm>

#include "abyncore.h"

#include "utility/abynconfiguration.h"
#include "utility/constants.h"
#include "utility/logger.h"

#include "communication/partycommunicationhandler.h"
#include "message_generated.h"

#include "crypto/aesrandomnessgenerator.h"

#include "share/share.h"

static_assert(FLATBUFFERS_LITTLEENDIAN);

namespace ABYN {

  class ABYNBackend {

  public:

    ABYNBackend(ABYNConfigurationPtr &abyn_config);

    ~ABYNBackend() {};

    const ABYNConfigurationPtr &GetConfig() { return abyn_config_; }

    const LoggerPtr &GetLogger() { return abyn_core_->GetLogger(); }

    const ABYNCorePtr &GetCore() { return abyn_core_; }

    size_t NextGateId() const { return abyn_core_->NextGateId(); }

    void InitializeRandomnessGenerator(u8 key[AES_KEY_SIZE], u8 iv[AES_IV_SIZE], size_t party_id);

    void InitializeCommunicationHandlers();

    void SendHelloToOthers();

    void VerifyHelloMessages();

    void Send(size_t party_id, flatbuffers::FlatBufferBuilder &message);

    void EvaluateSequential();

    void EvaluateParallel();

    void TerminateCommunication();

    void WaitForConnectionEnd();

    const std::vector<ABYN::Shares::SharePtr> &GetInputs() const { return input_shares_; };

  private:
    ABYNBackend() = delete;

    ABYNConfigurationPtr abyn_config_;
    ABYNCorePtr abyn_core_;
    std::vector<ABYN::Communication::PartyCommunicationHandlerPtr> communication_handlers_;

    bool share_inputs_ = true;

    std::vector<Shares::SharePtr> input_shares_;
  };

  using ABYNBackendPtr = std::shared_ptr<ABYNBackend>;
}

#endif //ABYNBACKEND_H
