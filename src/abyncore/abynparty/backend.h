#ifndef ABYNBACKEND_H
#define ABYNBACKEND_H

#include <algorithm>
#include <iterator>
#include <memory>

#include "core.h"

#include "utility/configuration.h"
#include "utility/constants.h"
#include "utility/logger.h"

#include "crypto/aes_randomness_generator.h"

#include "gate/gate.h"

static_assert(FLATBUFFERS_LITTLEENDIAN);

namespace ABYN {

class Backend {
 public:
  Backend(ConfigurationPtr &config);

  ~Backend(){};

  const ConfigurationPtr &GetConfig() { return config_; }

  const LoggerPtr &GetLogger() { return core_->GetLogger(); }

  const CorePtr &GetCore() { return core_; }

  std::size_t NextGateId() const { return core_->NextGateId(); }

  void InitializeRandomnessGenerator(u8 key[AES_KEY_SIZE], u8 iv[AES_IV_SIZE],
                                     std::size_t party_id);

  void InitializeCommunicationHandlers();

  void SendHelloToOthers();

  void VerifyHelloMessages();

  void Send(std::size_t party_id, flatbuffers::FlatBufferBuilder &message);

  void RegisterInputGate(const Gates::Interfaces::InputGatePtr &input_gate);

  void RegisterGate(const Gates::Interfaces::GatePtr &gate);

  void EvaluateSequential();

  void EvaluateParallel();

  void TerminateCommunication();

  void WaitForConnectionEnd();

  const Gates::Interfaces::GatePtr &GetGate(std::size_t gate_id) { return gates_.at(gate_id); }

  const std::vector<Gates::Interfaces::InputGatePtr> &GetInputs() const { return input_gates_; };

 private:
  Backend() = delete;

  ConfigurationPtr config_;
  CorePtr core_;

  std::vector<ABYN::Communication::CommunicationHandlerPtr> communication_handlers_;

  bool share_inputs_ = true;

  std::vector<Gates::Interfaces::InputGatePtr> input_gates_;
  std::queue<Gates::Interfaces::GatePtr>
      active_gates_;  //< gates that are currently being processed
  std::vector<Gates::Interfaces::GatePtr> gates_;
};

using BackendPtr = std::shared_ptr<Backend>;
}  // namespace ABYN

#endif  // ABYNBACKEND_H
