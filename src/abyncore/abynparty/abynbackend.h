#ifndef ABYNBACKEND_H
#define ABYNBACKEND_H

#include <memory>
#include <iterator>
#include <algorithm>

#include "abyncore.h"

#include "utility/abynconfiguration.h"
#include "utility/constants.h"
#include "utility/logger.h"

#include "crypto/aesrandomnessgenerator.h"

#include "gate/gate.h"

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

    void RegisterInputGate(Gates::Interfaces::InputGatePtr &input_gate);

    void EvaluateSequential();

    void EvaluateParallel();

    void TerminateCommunication();

    void WaitForConnectionEnd();

    Gates::Interfaces::GatePtr GetGate(size_t gate_id) { return abyn_core_->GetGate(gate_id)->shared_from_this(); }

    const std::vector<Gates::Interfaces::InputGatePtr> &GetInputs() const { return input_gates_; };

  private:
    ABYNBackend() = delete;

    ABYNConfigurationPtr abyn_config_;
    ABYNCorePtr abyn_core_;

    std::vector<ABYN::Communication::PartyCommunicationHandlerPtr> communication_handlers_;

    bool share_inputs_ = true;

    std::vector<Gates::Interfaces::GatePtr> gates_;

    std::vector<Gates::Interfaces::InputGatePtr> input_gates_;
    std::queue<Gates::Interfaces::GatePtr> active_gates_;     //< gates that are currently being processed
    std::vector<Gates::Interfaces::OutputGatePtr> ouput_gates_;

  };

  using ABYNBackendPtr = std::shared_ptr<ABYNBackend>;
}

#endif //ABYNBACKEND_H
