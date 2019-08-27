// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko
// Cryptography and Privacy Engineering Group (ENCRYPTO)
// TU Darmstadt, Germany
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "backend.h"

#include <algorithm>
#include <functional>
#include <iterator>

#include <fmt/format.h>

#include "configuration.h"
#include "register.h"

#include "communication/context.h"
#include "communication/handler.h"
#include "communication/hello_message.h"
#include "communication/message.h"
#include "crypto/base_ots/ot_hl17.h"
#include "crypto/oblivious_transfer/ot_provider.h"
#include "crypto/sharing_randomness_generator.h"
#include "gate/boolean_gmw_gate.h"
#include "utility/constants.h"
#include "utility/data_storage.h"
#include "utility/logger.h"

#define BOOST_FILESYSTEM_NO_DEPRECATED

namespace ABYN {

Backend::Backend(ConfigurationPtr &config) : config_(config) {
  register_ = std::make_shared<Register>(config_);
  ot_provider_.resize(config_->GetNumOfParties(), nullptr);

  for (auto i = 0u; i < config_->GetNumOfParties(); ++i) {
    if (i != config_->GetMyId()) {
      assert(config_->GetCommunicationContext(i));
    } else {
      continue;
    }

    config_->GetCommunicationContext(i)->InitializeMyRandomnessGenerator();
    config_->GetCommunicationContext(i)->SetLogger(register_->GetLogger());
    auto &logger = register_->GetLogger();

    auto &data_storage = config_->GetCommunicationContext(i)->GetDataStorage();

    auto send_function = [this, i](flatbuffers::FlatBufferBuilder &&message) {
      Send(i, std::move(message));
    };

    using namespace ENCRYPTO::ObliviousTransfer;
    ot_provider_.at(i) = std::static_pointer_cast<OTProvider>(
        std::make_shared<OTProviderFromOTExtension>(send_function, data_storage));

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
  auto fixed_key_aes_key = ENCRYPTO::BitVector<>::Random(128);
  auto aes_ptr =
      reinterpret_cast<const std::uint8_t *>(GetConfig()->GetMyFixedAESKeyShare().GetData().data());
  std::vector<std::uint8_t> aes_fixed_key(aes_ptr, aes_ptr + 16);
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
        config_->GetMyId(), destination_id, config_->GetNumOfParties(), seed_ptr, &aes_fixed_key,
        config_->GetOnlineAfterSetup(), ABYN::ABYN_VERSION);
    Send(destination_id, std::move(hello_message));
  }
}

void Backend::Send(std::size_t party_id, flatbuffers::FlatBufferBuilder &&message) {
  register_->Send(party_id, std::move(message));
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
          auto gate = register_->GetGate(gates_ids.at(i));
          gate->EvaluateSetup();
          gate->EvaluateOnline();
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

Shares::SharePtr Backend::BooleanGMWInput(std::size_t party_id,
                                          const ENCRYPTO::BitVector<> &input) {
  return BooleanGMWInput(party_id, std::vector<ENCRYPTO::BitVector<>>{input});
}

Shares::SharePtr Backend::BooleanGMWInput(std::size_t party_id, ENCRYPTO::BitVector<> &&input) {
  return BooleanGMWInput(party_id, std::vector<ENCRYPTO::BitVector<>>{std::move(input)});
}

Shares::SharePtr Backend::BooleanGMWInput(std::size_t party_id,
                                          const std::vector<ENCRYPTO::BitVector<>> &input) {
  auto in_gate = std::make_shared<Gates::GMW::GMWInputGate>(input, party_id, weak_from_this());
  auto in_gate_cast = std::static_pointer_cast<Gates::Interfaces::InputGate>(in_gate);
  RegisterInputGate(in_gate_cast);
  return std::static_pointer_cast<Shares::Share>(in_gate->GetOutputAsGMWShare());
}

Shares::SharePtr Backend::BooleanGMWInput(std::size_t party_id,
                                          std::vector<ENCRYPTO::BitVector<>> &&input) {
  auto in_gate =
      std::make_shared<Gates::GMW::GMWInputGate>(std::move(input), party_id, weak_from_this());
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

void Backend::Sync() {
  for (auto i = 0u; i < config_->GetNumOfParties(); ++i) {
    if (i == config_->GetMyId()) {
      continue;
    }
    communication_handlers_.at(i)->Sync();
  }
}

void Backend::ComputeBaseOTs() {
  for (auto i = 0ull; i < config_->GetNumOfParties(); ++i) {
    if (i == config_->GetMyId()) {
      continue;
    }

    auto send_function = [this, i](flatbuffers::FlatBufferBuilder &&message) {
      Send(i, std::move(message));
    };
    auto &data_storage = GetConfig()->GetContexts().at(i)->GetDataStorage();
    auto base_ots = std::make_unique<OT_HL17>(send_function, data_storage);
#pragma omp parallel sections num_threads(3)
    {
#pragma omp section
      {
        auto choices = ENCRYPTO::BitVector<>::Random(128);
        auto chosen_messages = base_ots->recv(choices);  // sender base ots
        auto &receiver_data = data_storage->GetBaseOTsReceiverData();
        receiver_data->c_ = std::move(choices);
        for (std::size_t i = 0; i < chosen_messages.size(); ++i) {
          auto b = receiver_data->messages_c_.at(i).begin();
          std::copy(chosen_messages.at(i).begin(), chosen_messages.at(i).begin() + 16, b);
        }
        std::scoped_lock lock(receiver_data->is_ready_condition_->GetMutex());
        receiver_data->is_ready_ = true;
      }
#pragma omp section
      {
        auto both_messages = base_ots->send(128);  // receiver base ots
        auto &sender_data = data_storage->GetBaseOTsSenderData();
        for (std::size_t i = 0; i < both_messages.size(); ++i) {
          auto b = sender_data->messages_0_.at(i).begin();
          std::copy(both_messages.at(i).first.begin(), both_messages.at(i).first.begin() + 16, b);
        }
        for (std::size_t i = 0; i < both_messages.size(); ++i) {
          auto b = sender_data->messages_1_.at(i).begin();
          std::copy(both_messages.at(i).second.begin(), both_messages.at(i).second.begin() + 16, b);
        }
        std::scoped_lock lock(sender_data->is_ready_condition_->GetMutex());
        sender_data->is_ready_ = true;
      }
    }
  }
  base_ots_finished_ = true;
}

void Backend::ImportBaseOTs(std::size_t i) {
  GetConfig()->GetContexts().at(i)->GetDataStorage()->GetBaseOTsReceiverData();
  GetConfig()->GetContexts().at(i)->GetDataStorage()->GetBaseOTsSenderData();
  // TODO
}

void Backend::ImportBaseOTs() {
  // GetConfig()->GetContexts().at(i)->GetDataStorage()->GetBaseOTsReceiverData();
  // GetConfig()->GetContexts().at(i)->GetDataStorage()->GetBaseOTsSenderData();
  // TODO
}

void Backend::ExportBaseOTs() {
  // TODO
  for (std::size_t i = 0; i < GetConfig()->GetNumOfParties(); ++i) {
    if (i == GetConfig()->GetMyId()) {
      continue;
    }
    GetConfig()->GetContexts().at(i)->GetDataStorage()->GetBaseOTsReceiverData();
    GetConfig()->GetContexts().at(i)->GetDataStorage()->GetBaseOTsSenderData();
  }
}

void Backend::GenerateFixedKeyAESKey() {
  if (GetConfig()->IsFixedKeyAESKeyReady()) {
    return;
  }

  auto &key = GetConfig()->GetMutableFixedKeyAESKey();
  key = GetConfig()->GetMyFixedAESKeyShare();
  for (auto i = 0ull; i < GetConfig()->GetNumOfParties(); ++i) {
    if (i == GetConfig()->GetMyId()) {
      continue;
    }
    auto &data_storage = GetConfig()->GetContexts().at(i)->GetDataStorage();
    auto &cond = data_storage->GetReceivedHelloMessageCondition();
    while (!(*cond)()) {
      cond->WaitFor(std::chrono::milliseconds(1));
    }
    auto other_key_ptr = data_storage->GetReceivedHelloMessage()->fixed_key_aes_seed()->data();
    ENCRYPTO::AlignedBitVector other_key(other_key_ptr, 128);
    key ^= other_key;
  }
  GetConfig()->SetFixedKeyAESKeyReady();
  for (auto i = 0ull; i < GetConfig()->GetNumOfParties(); ++i) {
    if (i == GetConfig()->GetMyId()) {
      continue;
    }
    auto data_storage = GetConfig()->GetContexts().at(i)->GetDataStorage();
    data_storage->SetFixedKeyAESKey(key);
  }
}

void Backend::ComputeOTExtension() {
  require_base_ots = true;

  if (!GetConfig()->IsFixedKeyAESKeyReady()) {
    GenerateFixedKeyAESKey();
  }

  if (!base_ots_finished_) {
    ComputeBaseOTs();
  }

#pragma omp taskloop
  for (auto i = 0ull; i < config_->GetNumOfParties(); ++i) {
    if (i == config_->GetMyId()) {
      continue;
    }
#pragma omp parallel sections num_threads(3) default(none) shared(ot_provider_, i)
    {
#pragma omp section
      { ot_provider_.at(i)->SendSetup(); }
#pragma omp section
      { ot_provider_.at(i)->ReceiveSetup(); }
    }
  }
}
}