#include "backend.h"

#include <algorithm>
#include <iterator>

#include <fmt/format.h>

#include "configuration.h"
#include "register.h"

#include "communication/context.h"
#include "communication/handler.h"
#include "communication/hello_message.h"
#include "communication/message.h"
#include "crypto/aes_randomness_generator.h"
#include "gate/boolean_gmw_gate.h"
#include "utility/constants.h"
#include "utility/data_storage.h"
#include "utility/logger.h"

#define BOOST_FILESYSTEM_NO_DEPRECATED

namespace ABYN {

Backend::Backend(ConfigurationPtr &config) : config_(config) {
  register_ = std::make_shared<Register>(config_);

  for (auto i = 0u; i < config_->GetNumOfParties(); ++i) {
    if (i != config_->GetMyId()) {
      assert(config_->GetCommunicationContext(i));
    } else {
      continue;
    }

    config_->GetCommunicationContext(i)->InitializeMyRandomnessGenerator();
    config_->GetCommunicationContext(i)->SetLogger(register_->GetLogger());
    auto &logger = register_->GetLogger();

    if constexpr (ABYN_VERBOSE_DEBUG) {
      auto seed =
          std::move(config_->GetCommunicationContext(i)->GetMyRandomnessGenerator()->GetSeed());
      logger->LogTrace(fmt::format("Initialized my randomness generator for Party#{} with Seed: {}",
                                   i, Helpers::Print::Hex(seed)));
    }
  }
}

const LoggerPtr &Backend::GetLogger() const noexcept { return register_->GetLogger(); }

std::size_t Backend::NextGateId() const { return register_->NextGateId(); }

void Backend::InitializeCommunicationHandlers() {
  communication_handlers_.resize(config_->GetNumOfParties(), nullptr);
#pragma omp parallel for
  for (auto i = 0u; i < config_->GetNumOfParties(); ++i) {
    if (i == config_->GetMyId()) {
      continue;
    }

    if constexpr (ABYN_DEBUG) {
      auto message = fmt::format(
          "Party #{} created CommHandler for Party #{} with end ip {}, local "
          "port {} and remote port {}",
          config_->GetMyId(), i, config_->GetCommunicationContext(i)->GetIp(),
          config_->GetCommunicationContext(i)->GetSocket()->local_endpoint().port(),
          config_->GetCommunicationContext(i)->GetSocket()->remote_endpoint().port());
      register_->GetLogger()->LogDebug(message);
    }

    communication_handlers_.at(i) = std::make_shared<Communication::Handler>(
        config_->GetCommunicationContext(i), register_->GetLogger());
  }
  register_->RegisterCommunicationHandlers(communication_handlers_);
}

void Backend::SendHelloToOthers() {
  register_->GetLogger()->LogInfo("Send hello message to other parties");
  for (auto destination_id = 0u; destination_id < config_->GetNumOfParties(); ++destination_id) {
    if (destination_id == config_->GetMyId()) {
      continue;
    }
    std::vector<std::uint8_t> seed;
    if (share_inputs_) {
      seed = std::move(
          config_->GetCommunicationContext(destination_id)->GetMyRandomnessGenerator()->GetSeed());
    }

    auto seed_ptr = share_inputs_ ? &seed : nullptr;
    auto hello_message = ABYN::Communication::BuildHelloMessage(
        config_->GetMyId(), destination_id, config_->GetNumOfParties(), seed_ptr,
        config_->GetOnlineAfterSetup(), ABYN::ABYN_VERSION);
    Send(destination_id, hello_message);
  }
}

void Backend::Send(std::size_t party_id, flatbuffers::FlatBufferBuilder &message) {
  register_->Send(party_id, message);
}

void Backend::RegisterInputGate(const Gates::Interfaces::InputGatePtr &input_gate) {
  auto gate = std::static_pointer_cast<Gates::Interfaces::Gate>(input_gate);
  register_->RegisterNextInputGate(gate);
}

void Backend::RegisterGate(const Gates::Interfaces::GatePtr &gate) {
  register_->RegisterNextGate(gate);
}

void Backend::EvaluateSequential() {
  register_->GetLogger()->LogInfo(
      "Start evaluating the circuit gates sequentially (online after all finished setup)");
#pragma omp parallel num_threads(config_->GetNumOfThreads()) default(shared)
  {
#pragma omp single
    {
      {
        auto &gates = register_->GetGates();
#pragma omp taskloop num_tasks(std::min(gates.size(), config_->GetNumOfThreads()))
        for (auto i = 0ull; i < gates.size(); ++i) {
          gates.at(i)->EvaluateSetup();
        }
#pragma omp taskwait
      }
      for (auto &input_gate : register_->GetInputGates()) {
        register_->AddToActiveQueue(input_gate->GetID());
      }
      // evaluate all other gates moved to the active queue
      while (register_->GetNumOfEvaluatedGates() < register_->GetTotalNumOfGates()) {
        // get some active gates from the queue
        std::vector<std::size_t> gates_ids;
        {
          std::int64_t gate_id;
          do {
            gate_id = register_->GetNextGateFromOnlineQueue();
            if (gate_id >= 0) {
              gates_ids.push_back(static_cast<std::size_t>(gate_id));
            }
          } while (gate_id >= 0);
        }
        // evaluate the gates in a batch
#pragma omp taskloop num_tasks(std::min(gates_ids.size(), config_->GetNumOfThreads()))
        for (auto i = 0ull; i < gates_ids.size(); ++i) {
          register_->GetGate(gates_ids.at(i))->EvaluateOnline();
        }
#pragma omp taskwait
      }
    }
  }
}

void Backend::EvaluateParallel() {
  register_->GetLogger()->LogInfo(
      "Start evaluating the circuit gates in parallel (online as soon as some finished setup)");
#pragma omp parallel num_threads(config_->GetNumOfThreads()) default(shared)
  {
#pragma omp single
    {
      for (auto &input_gate : register_->GetInputGates()) {
        register_->AddToActiveQueue(input_gate->GetID());
      }
      // evaluate all other gates moved to the active queue
      while (register_->GetNumOfEvaluatedGates() < register_->GetTotalNumOfGates()) {
        // get some active gates from the queue
        std::vector<std::size_t> gates_ids;
        {
          std::int64_t gate_id;
          do {
            gate_id = register_->GetNextGateFromOnlineQueue();
            if (gate_id >= 0) {
              gates_ids.push_back(static_cast<std::size_t>(gate_id));
            }
          } while (gate_id >= 0);
        }
        // evaluate the gates in a batch
#pragma omp taskloop num_tasks(std::min(gates_ids.size(), config_->GetNumOfThreads()))
        for (auto i = 0ull; i < gates_ids.size(); ++i) {
          register_->GetGate(gates_ids.at(i))->EvaluateSetup();
          register_->GetGate(gates_ids.at(i))->EvaluateOnline();
        }
#pragma omp taskwait
      }
    }
  }
}

void Backend::TerminateCommunication() {
  for (auto party_id = 0u; party_id < communication_handlers_.size(); ++party_id) {
    if (GetConfig()->GetMyId() != party_id) {
      assert(communication_handlers_.at(party_id));
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

const Gates::Interfaces::GatePtr &Backend::GetGate(std::size_t gate_id) const {
  return register_->GetGate(gate_id);
}

const std::vector<Gates::Interfaces::GatePtr> &Backend::GetInputGates() const {
  return register_->GetInputGates();
}

void Backend::VerifyHelloMessages() {
  bool success = true;
  for (auto &handler : communication_handlers_) {
    if (handler) {
      success &= handler->VerifyHelloMessage();
    }
  }

  if (!success) {
    register_->GetLogger()->LogError("Hello message verification failed");
  } else {
    register_->GetLogger()->LogInfo("Successfully verified hello messages");
  }
}

void Backend::Reset() { register_->Reset(); }

void Backend::Clear() { register_->Clear(); }

Shares::SharePtr Backend::BooleanGMWInput(std::size_t party_id, bool input) {
  return BooleanGMWInput(party_id, ENCRYPTO::BitVector(1, input));
}

Shares::SharePtr Backend::BooleanGMWInput(std::size_t party_id, const ENCRYPTO::BitVector &input) {
  return BooleanGMWInput(party_id, std::vector<ENCRYPTO::BitVector>{input});
}

Shares::SharePtr Backend::BooleanGMWInput(std::size_t party_id, ENCRYPTO::BitVector &&input) {
  return BooleanGMWInput(party_id, std::vector<ENCRYPTO::BitVector>{std::move(input)});
}

Shares::SharePtr Backend::BooleanGMWInput(std::size_t party_id,
                                          const std::vector<ENCRYPTO::BitVector> &input) {
  auto in_gate = std::make_shared<Gates::GMW::GMWInputGate>(input, party_id, weak_from_this());
  auto in_gate_cast = std::static_pointer_cast<Gates::Interfaces::InputGate>(in_gate);
  RegisterInputGate(in_gate_cast);
  return std::static_pointer_cast<Shares::Share>(in_gate->GetOutputAsGMWShare());
}

Shares::SharePtr Backend::BooleanGMWInput(std::size_t party_id,
                                          std::vector<ENCRYPTO::BitVector> &&input) {
  auto in_gate = std::make_shared<Gates::GMW::GMWInputGate>(std::move(input), party_id, weak_from_this());
  auto in_gate_cast = std::static_pointer_cast<Gates::Interfaces::InputGate>(in_gate);
  RegisterInputGate(in_gate_cast);
  return std::static_pointer_cast<Shares::Share>(in_gate->GetOutputAsGMWShare());
}

Shares::SharePtr Backend::BooleanGMWXOR(const Shares::GMWSharePtr &a,
                                        const Shares::GMWSharePtr &b) {
  assert(a);
  assert(b);
  auto xor_gate = std::make_shared<Gates::GMW::GMWXORGate>(a, b);
  RegisterGate(xor_gate);
  return xor_gate->GetOutputAsShare();
}

Shares::SharePtr Backend::BooleanGMWXOR(const Shares::SharePtr &a, const Shares::SharePtr &b) {
  assert(a);
  assert(b);
  auto casted_parent_a_ptr = std::dynamic_pointer_cast<Shares::GMWShare>(a);
  auto casted_parent_b_ptr = std::dynamic_pointer_cast<Shares::GMWShare>(b);
  assert(casted_parent_a_ptr);
  assert(casted_parent_b_ptr);
  return BooleanGMWXOR(casted_parent_a_ptr, casted_parent_b_ptr);
}

Shares::SharePtr Backend::BooleanGMWOutput(const Shares::SharePtr &parent,
                                           std::size_t output_owner) {
  assert(parent);
  auto out_gate = std::make_shared<Gates::GMW::GMWOutputGate>(parent->GetWires(), output_owner);
  auto out_gate_cast = std::static_pointer_cast<Gates::Interfaces::Gate>(out_gate);
  RegisterGate(out_gate_cast);
  return std::static_pointer_cast<Shares::Share>(out_gate->GetOutputAsShare());
}
}