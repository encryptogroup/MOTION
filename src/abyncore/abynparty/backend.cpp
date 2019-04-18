#include "backend.h"

#include <algorithm>

#include <fmt/format.h>

#include "communication/hello_message.h"
#include "communication/message.h"
#include "utility/constants.h"

#define BOOST_FILESYSTEM_NO_DEPRECATED

namespace ABYN {

Backend::Backend(ConfigurationPtr &config) : config_(config) {
  core_ = std::make_shared<ABYN::Core>(config);

  for (auto i = 0u; i < config_->GetNumOfParties(); ++i) {
    if (config_->GetCommunicationContext(i) == nullptr) {
      continue;
    }
    config_->GetCommunicationContext(i)->InitializeMyRandomnessGenerator();
    config_->GetCommunicationContext(i)->SetLogger(core_->GetLogger());
    auto &logger = core_->GetLogger();
    auto seed = std::move(config_->GetCommunicationContext(i)
                              ->GetMyRandomnessGenerator()
                              ->GetSeed());
    logger->LogTrace(fmt::format(
        "Initialized my randomness generator for Party#{} with Seed: {}", i,
        Helpers::Print::Hex(seed)));
  }
}

void Backend::InitializeCommunicationHandlers() {
  using PartyCommunicationHandler = ABYN::Communication::CommunicationHandler;
  communication_handlers_.resize(config_->GetNumOfParties(), nullptr);
#pragma omp parallel for
  for (auto i = 0u; i < config_->GetNumOfParties(); ++i) {
    if (i == config_->GetMyId()) {
      continue;
    }
    auto message = fmt::format(
        "Party #{} creates CommHandler for Party #{} with end ip {}, local "
        "port {} and remote port {}",
        config_->GetMyId(), i, config_->GetCommunicationContext(i)->GetIp(),
        config_->GetCommunicationContext(i)
            ->GetSocket()
            ->local_endpoint()
            .port(),
        config_->GetCommunicationContext(i)
            ->GetSocket()
            ->remote_endpoint()
            .port());
    core_->GetLogger()->LogDebug(message);

    communication_handlers_.at(i) = std::make_shared<PartyCommunicationHandler>(
        config_->GetCommunicationContext(i), core_->GetLogger());
  }
  core_->RegisterCommunicationHandlers(communication_handlers_);
}

void Backend::SendHelloToOthers() {
  core_->GetLogger()->LogInfo("Send hello message to other parties");
  for (auto destination_id = 0u; destination_id < config_->GetNumOfParties();
       ++destination_id) {
    if (destination_id == config_->GetMyId()) {
      continue;
    }
    std::vector<u8> seed;
    if (share_inputs_) {
      seed = std::move(config_->GetCommunicationContext(destination_id)
                           ->GetMyRandomnessGenerator()
                           ->GetSeed());
    }

    auto seed_ptr = share_inputs_ ? &seed : nullptr;
    auto hello_message = ABYN::Communication::BuildHelloMessage(
        config_->GetMyId(), destination_id, config_->GetNumOfParties(),
        seed_ptr, config_->OnlineAfterSetup(), ABYN::ABYN_VERSION);
    Send(destination_id, hello_message);
  }
}

void Backend::Send(std::size_t party_id,
                   flatbuffers::FlatBufferBuilder &message) {
  core_->Send(party_id, message);
}

void Backend::RegisterInputGate(
    const Gates::Interfaces::InputGatePtr &input_gate) {
  input_gates_.push_back(input_gate);
  RegisterGate(std::static_pointer_cast<Gates::Interfaces::Gate>(input_gate));
}

void Backend::RegisterGate(const Gates::Interfaces::GatePtr &gate) {
  gates_.push_back(gate);
}

void Backend::EvaluateSequential() {
#pragma omp parallel num_threads(config_->GetNumOfThreads()) default(shared)
  {
#pragma omp single nowait
    {
#pragma omp task
#pragma omp taskloop num_tasks(             \
    std::min(static_cast <std::size_t>(50), \
             static_cast <std::size_t>(input_gates_.size())))
      for (auto i = 0u; i < input_gates_.size(); ++i) {
        input_gates_[i]->Evaluate();
      }
// evaluate all other gates moved to the active queue
#pragma omp task
      while (core_->GetNumOfEvaluatedGates() < core_->GetTotalNumOfGates()) {
        auto gate_id = core_->GetNextGateFromOnlineQueue();
#pragma omp task if (gate_id < 0)  // doesn't make much sense, but will create a
                                   // task if gate_id >= 0
        {
          assert(gate_id >= 0);
          core_->GetGate(gate_id)->Evaluate();
        }
        if (gate_id <= 0) {
          std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
      }
    }
  }
}

void Backend::EvaluateParallel() {
  // TODO
}

void Backend::TerminateCommunication() {
  for (auto party_id = 0u; party_id < communication_handlers_.size();
       ++party_id) {
    if (communication_handlers_.at(party_id)) {
      communication_handlers_.at(party_id)->TerminateCommunication();
    }
  }
}

void Backend::WaitForConnectionEnd() {
  for (auto &handler : communication_handlers_) {
    if (handler) {
      handler->WaitForConnectionEnd();
    }
  }
}

void Backend::VerifyHelloMessages() {
  bool success = true;
  for (auto &handler : communication_handlers_) {
    if (handler) {
      success &= handler->VerifyHelloMessage();
    }
  }

  if (!success) {
    core_->GetLogger()->LogError("Hello message verification failed");
  } else {
    core_->GetLogger()->LogInfo("Successfully verified hello messages");
  }
}
}