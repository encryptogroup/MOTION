#include "abynbackend.h"

#include <algorithm>

#include <fmt/format.h>

#include "utility/constants.h"
#include "communication/message.h"
#include "communication/hellomessage.h"

#define BOOST_FILESYSTEM_NO_DEPRECATED

namespace ABYN {

  ABYNBackend::ABYNBackend(ABYNConfigurationPtr &abyn_config) : abyn_config_(abyn_config) {
    abyn_core_ = std::make_shared<ABYN::ABYNCore>(abyn_config);

    for (auto i = 0u; i < abyn_config_->GetNumOfParties(); ++i) {
      if (abyn_config_->GetParty(i) == nullptr) { continue; }
      abyn_config_->GetParty(i)->InitializeMyRandomnessGenerator();
      abyn_config_->GetParty(i)->SetLogger(abyn_core_->GetLogger());
      auto &logger = abyn_core_->GetLogger();
      auto seed = std::move(abyn_config_->GetParty(i)->GetMyRandomnessGenerator()->GetSeed());
      logger->LogTrace(fmt::format("Initialized my randomness generator for Party#{} with Seed: {}",
                                   i, Helpers::Print::Hex(seed)));
    }
  }

  void ABYNBackend::InitializeCommunicationHandlers() {
    using PartyCommunicationHandler = ABYN::Communication::PartyCommunicationHandler;
    communication_handlers_.resize(abyn_config_->GetNumOfParties(), nullptr);
#pragma omp parallel for
    for (auto i = 0u; i < abyn_config_->GetNumOfParties(); ++i) {
      if (i == abyn_config_->GetMyId()) { continue; }
      auto message = fmt::format(
          "Party #{} creates CommHandler for Party #{} with end ip {}, local port {} and remote port {}",
          abyn_config_->GetMyId(), i,
          abyn_config_->GetParty(i)->GetIp(),
          abyn_config_->GetParty(i)->GetSocket()->local_endpoint().port(),
          abyn_config_->GetParty(i)->GetSocket()->remote_endpoint().port());
      abyn_core_->GetLogger()->LogDebug(message);

      communication_handlers_.at(i) =
          std::make_shared<PartyCommunicationHandler>(abyn_config_->GetParty(i), abyn_core_->GetLogger());
    }
    abyn_core_->RegisterCommunicationHandlers(communication_handlers_);
  }

  void ABYNBackend::SendHelloToOthers() {
    abyn_core_->GetLogger()->LogInfo("Send hello message to other parties");
    for (auto destination_id = 0u; destination_id < abyn_config_->GetNumOfParties(); ++destination_id) {
      if (destination_id == abyn_config_->GetMyId()) { continue; }
      std::vector<u8> seed;
      if (share_inputs_) {
        seed = std::move(abyn_config_->GetParty(destination_id)->GetMyRandomnessGenerator()->GetSeed());
      }

      auto seed_ptr = share_inputs_ ? &seed : nullptr;
      auto hello_message = ABYN::Communication::BuildHelloMessage(abyn_config_->GetMyId(),
                                                                  destination_id,
                                                                  abyn_config_->GetNumOfParties(),
                                                                  seed_ptr,
                                                                  abyn_config_->OnlineAfterSetup(),
                                                                  ABYN::ABYN_VERSION);
      Send(destination_id, hello_message);
    }
  }

  void ABYNBackend::Send(size_t party_id, flatbuffers::FlatBufferBuilder &message) {
    abyn_core_->Send(party_id, message);
  }

  void ABYNBackend::RegisterInputGate(Gates::Interfaces::InputGatePtr &input_gate) {
    input_gates_.push_back(input_gate);
  }

  void ABYNBackend::EvaluateSequential() {
#pragma omp parallel num_threads(abyn_config_->GetNumOfThreads()) default(shared)
    {
#pragma omp parallel sections
      {

#pragma omp section //evaluate input gates
        {
#pragma omp taskloop num_tasks(std::min(static_cast<size_t>(50), static_cast<size_t>(input_gates_.size())))
          for (auto i = 0u; i < input_gates_.size(); ++i) {
            input_gates_[i]->Evaluate();
          }
        }

#pragma omp section //evaluate all other gates moved to the active queue
        {
          while (abyn_core_->GetNumOfEvaluatedGates() < abyn_core_->GetTotalNumOfGates()) {
            auto gate_id = abyn_core_->GetNextGateFromOnlineQueue() == -1;
            if (gate_id) {
              std::this_thread::sleep_for(std::chrono::microseconds(100));
            } else { //evaluate the gate
#pragma omp task
              abyn_core_->GetGate(gate_id)->Evaluate();
            }
          }
        }
      }
    }
  }

  void ABYNBackend::EvaluateParallel() {
//TODO
  }


  void ABYNBackend::TerminateCommunication() {
    for (auto party_id = 0u; party_id < communication_handlers_.size(); ++party_id) {
      if (communication_handlers_.at(party_id)) { communication_handlers_.at(party_id)->TerminateCommunication(); }
    }
  }

  void ABYNBackend::WaitForConnectionEnd() {
    for (auto &handler : communication_handlers_) {
      if (handler) { handler->WaitForConnectionEnd(); }
    }
  }

  void ABYNBackend::VerifyHelloMessages() {
    bool success = true;
    for (auto &handler : communication_handlers_) {
      if (handler) { success &= handler->VerifyHelloMessage(); }
    }

    if (!success) { abyn_core_->GetLogger()->LogError("Hello message verification failed"); }
    else { abyn_core_->GetLogger()->LogInfo("Successfully verified hello messages"); }
  }
}