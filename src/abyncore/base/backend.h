#pragma once

#include <memory>

#include "flatbuffers/flatbuffers.h"

#include "utility/constants.h"
#include "utility/logger.h"

static_assert(FLATBUFFERS_LITTLEENDIAN);

namespace ABYN {

class Configuration;
using ConfigurationPtr = std::shared_ptr<Configuration>;

class Register;
using RegisterPtr = std::shared_ptr<Register>;

namespace Gates::Interfaces {
class Gate;
using GatePtr = std::shared_ptr<Gate>;

class InputGate;
using InputGatePtr = std::shared_ptr<InputGate>;
}  // namespace Gates::Interfaces

namespace Communication {
class CommunicationHandler;
using CommunicationHandlerPtr = std::shared_ptr<CommunicationHandler>;
}  // namespace Communication

class Backend {
 public:
  Backend(ConfigurationPtr &config);

  ~Backend() = default;

  const ConfigurationPtr &GetConfig() { return config_; }

  const LoggerPtr &GetLogger();

  const RegisterPtr &GetRegister() { return register_; }

  std::size_t NextGateId() const;

  void InitializeRandomnessGenerator(std::uint8_t key[AES_KEY_SIZE], std::uint8_t iv[AES_IV_SIZE],
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

  const Gates::Interfaces::GatePtr &GetGate(std::size_t gate_id) const;

  const std::vector<Gates::Interfaces::GatePtr> &GetInputGates() const;

 private:
  Backend() = delete;

  ConfigurationPtr config_;
  RegisterPtr register_;

  std::vector<Communication::CommunicationHandlerPtr> communication_handlers_;

  bool share_inputs_ = true;
};

using BackendPtr = std::shared_ptr<Backend>;
}  // namespace ABYN
