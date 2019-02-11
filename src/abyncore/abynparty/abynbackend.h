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

static_assert(FLATBUFFERS_LITTLEENDIAN);

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

    void SendHelloToOthers();

    void VerifyHelloMessages();

    void Send(size_t party_id, flatbuffers::FlatBufferBuilder &message);

    void TerminateCommunication();

    void WaitForConnectionEnd();

  private:
    ABYNBackend() = delete;

    ABYNConfigurationPtr abyn_config_;
    size_t global_gate_id_ = 0;
    ABYN::LoggerPtr logger_ = nullptr;
    std::vector<ABYN::Communication::PartyCommunicationHandlerPtr> communication_handlers_;

    //determines how many worker threads are used in openmp, but not in communication handlers!
    //the latter always use at least 2 threads for each communication channel to send and receive data to prevent
    //the communication become a bottleneck, e.g., in 10 Gbps networks.
    size_t num_threads_ = std::thread::hardware_concurrency();
    bool share_inputs_ = true;
  };

  using ABYNBackendPtr = std::shared_ptr<ABYNBackend>;
}

#endif //ABYNBACKEND_H
