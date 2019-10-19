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

#include <functional>
#include <future>
#include <iterator>

#include <fmt/format.h>
#include <omp.h>
#include <boost/asio/thread_pool.hpp>

#include "communication/handler.h"
#include "communication/hello_message.h"
#include "communication/message.h"
#include "crypto/base_ots/ot_hl17.h"
#include "crypto/multiplication_triple/mt_provider.h"
#include "crypto/oblivious_transfer/ot_provider.h"
#include "gate/bmr_gate.h"
#include "gate/boolean_gmw_gate.h"
#include "register.h"
#include "utility/constants.h"

namespace MOTION {

Backend::Backend(ConfigurationPtr &config) : config_(config) {
  omp_set_nested(1);
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

    if constexpr (MOTION_VERBOSE_DEBUG) {
      auto seed = config_->GetCommunicationContext(i)->GetMyRandomnessGenerator()->GetSeed();
      logger->LogTrace(fmt::format("Initialized my randomness generator for Party#{} with Seed: {}",
                                   i, Helpers::Print::Hex(seed)));
    }
  }

  mt_provider_ = std::make_shared<MTProviderFromOTs>(ot_provider_, GetConfig()->GetMyId());
}

const LoggerPtr &Backend::GetLogger() const noexcept { return register_->GetLogger(); }

std::size_t Backend::NextGateId() const { return register_->NextGateId(); }

void Backend::InitializeCommunicationHandlers() {
  std::vector<std::future<void>> threads;
  communication_handlers_.resize(config_->GetNumOfParties(), nullptr);
  for (auto i = 0u; i < config_->GetNumOfParties(); ++i) {
    if (i == config_->GetMyId()) {
      continue;
    }
    threads.emplace_back(std::async(std::launch::async, [i, this]() {
      if constexpr (MOTION_DEBUG) {
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
    }));
  }
  for (auto &t : threads) t.get();
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
      seed =
          config_->GetCommunicationContext(destination_id)->GetMyRandomnessGenerator()->GetSeed();
    }

    auto seed_ptr = share_inputs_ ? &seed : nullptr;
    auto hello_message = MOTION::Communication::BuildHelloMessage(
        config_->GetMyId(), destination_id, config_->GetNumOfParties(), seed_ptr, &aes_fixed_key,
        config_->GetOnlineAfterSetup(), MOTION::MOTION_VERSION);
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

bool Backend::NeedOTs() {
  for (auto i = 0ull; i < GetConfig()->GetNumOfParties(); ++i) {
    if (i == GetConfig()->GetMyId()) continue;
    if (GetOTProvider(i)->GetNumOTsReceiver() > 0 || GetOTProvider(i)->GetNumOTsSender() > 0)
      return true;
  }
  return false;
}

void Backend::EvaluateSequential() {
  register_->GetLogger()->LogInfo(
      "Start evaluating the circuit gates sequentially (online after all finished setup)");
  const bool needs_mts = GetMTProvider()->NeedMTs();

  if (needs_mts) {
    mt_provider_->PreSetup();
  }

  const bool need_ots = NeedOTs();

  if (need_ots) {
    OTExtensionSetup();
    if (needs_mts) {
      mt_provider_->Setup();
    }
  }

  boost::asio::thread_pool pool_setup(register_->GetTotalNumOfGates());

  for (auto i = 0ull; i < register_->GetTotalNumOfGates(); ++i) {
    boost::asio::post(pool_setup, [this, i]() { register_->GetGate(i)->EvaluateSetup(); });
  }
  pool_setup.join();

  for (auto &input_gate : register_->GetInputGates()) {
    register_->AddToActiveQueue(input_gate->GetID());
  }

  boost::asio::thread_pool pool_online(register_->GetTotalNumOfGates());
  while (register_->GetNumOfEvaluatedGates() < register_->GetTotalNumOfGates()) {
    const std::int64_t gate_id = register_->GetNextGateFromActiveQueue();
    if (gate_id < 0) {
      std::this_thread::sleep_for(std::chrono::microseconds(100));
      continue;
    }
    boost::asio::post(pool_online, [this, gate_id]() {
      auto gate = register_->GetGate(static_cast<std::size_t>(gate_id));
      gate->EvaluateOnline();
    });
  }
  pool_online.join();
}

void Backend::EvaluateParallel() {
  register_->GetLogger()->LogInfo(
      "Start evaluating the circuit gates in parallel (online as soon as some finished setup)");

  // Run preprocessing setup in a separate thread
  auto f_setup = std::async(std::launch::async, [this] {
    const bool needs_mts = mt_provider_->NeedMTs();
    if (needs_mts) {
      mt_provider_->PreSetup();
    }
    const bool need_ots = NeedOTs();
    if (need_ots) {
      OTExtensionSetup();
      if (needs_mts) {
        mt_provider_->Setup();
      }
    }
    boost::asio::thread_pool pool_setup(register_->GetTotalNumOfGates());
    for (auto &gate : register_->GetGates()) {
      boost::asio::post(pool_setup, [gate]() { gate->EvaluateSetup(); });
    }
    pool_setup.join();
  });

  // Run setup and online phase of circuit evaluation
  for (auto &input_gate : register_->GetInputGates()) {
    register_->AddToActiveQueue(input_gate->GetID());
  }
  boost::asio::thread_pool pool_online(register_->GetTotalNumOfGates());
  while (register_->GetNumOfEvaluatedGates() < register_->GetTotalNumOfGates()) {
    const std::int64_t gate_id = register_->GetNextGateFromActiveQueue();
    if (gate_id < 0) {
      std::this_thread::sleep_for(std::chrono::microseconds(100));
      continue;
    }
    boost::asio::post(pool_online, [this, gate_id]() {
      auto gate = register_->GetGate(static_cast<std::size_t>(gate_id));
      gate->EvaluateOnline();
    });
  }
  pool_online.join();

  f_setup.get();
}  // namespace MOTION

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
    if (handler) handler->WaitForConnectionEnd();
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
  const auto in_gate =
      std::make_shared<Gates::GMW::GMWInputGate>(input, party_id, weak_from_this());
  const auto in_gate_cast = std::static_pointer_cast<Gates::Interfaces::InputGate>(in_gate);
  RegisterInputGate(in_gate_cast);
  return std::static_pointer_cast<Shares::Share>(in_gate->GetOutputAsGMWShare());
}

Shares::SharePtr Backend::BooleanGMWInput(std::size_t party_id,
                                          std::vector<ENCRYPTO::BitVector<>> &&input) {
  const auto in_gate =
      std::make_shared<Gates::GMW::GMWInputGate>(std::move(input), party_id, weak_from_this());
  const auto in_gate_cast = std::static_pointer_cast<Gates::Interfaces::InputGate>(in_gate);
  RegisterInputGate(in_gate_cast);
  return std::static_pointer_cast<Shares::Share>(in_gate->GetOutputAsGMWShare());
}

Shares::SharePtr Backend::BooleanGMWXOR(const Shares::GMWSharePtr &a,
                                        const Shares::GMWSharePtr &b) {
  assert(a);
  assert(b);
  const auto xor_gate = std::make_shared<Gates::GMW::GMWXORGate>(a, b);
  RegisterGate(xor_gate);
  return xor_gate->GetOutputAsShare();
}

Shares::SharePtr Backend::BooleanGMWXOR(const Shares::SharePtr &a, const Shares::SharePtr &b) {
  assert(a);
  assert(b);
  const auto casted_a = std::dynamic_pointer_cast<Shares::GMWShare>(a);
  const auto casted_b = std::dynamic_pointer_cast<Shares::GMWShare>(b);
  assert(casted_a);
  assert(casted_b);
  return BooleanGMWXOR(casted_a, casted_b);
}

Shares::SharePtr Backend::BooleanGMWAND(const Shares::GMWSharePtr &a,
                                        const Shares::GMWSharePtr &b) {
  assert(a);
  assert(b);
  const auto and_gate = std::make_shared<Gates::GMW::GMWANDGate>(a, b);
  RegisterGate(and_gate);
  return and_gate->GetOutputAsShare();
}

Shares::SharePtr Backend::BooleanGMWAND(const Shares::SharePtr &a, const Shares::SharePtr &b) {
  assert(a);
  assert(b);
  const auto casted_a = std::dynamic_pointer_cast<Shares::GMWShare>(a);
  const auto casted_b = std::dynamic_pointer_cast<Shares::GMWShare>(b);
  assert(casted_a);
  assert(casted_b);
  return BooleanGMWAND(casted_a, casted_b);
}

Shares::SharePtr Backend::BooleanGMWMUX(const Shares::GMWSharePtr &a, const Shares::GMWSharePtr &b,
                                        const Shares::GMWSharePtr &sel) {
  assert(a);
  assert(b);
  assert(sel);
  const auto mux_gate = std::make_shared<Gates::GMW::GMWMUXGate>(a, b, sel);
  RegisterGate(mux_gate);
  return mux_gate->GetOutputAsShare();
}

Shares::SharePtr Backend::BooleanGMWMUX(const Shares::SharePtr &a, const Shares::SharePtr &b,
                                        const Shares::SharePtr &sel) {
  assert(a);
  assert(b);
  assert(sel);
  const auto casted_a = std::dynamic_pointer_cast<Shares::GMWShare>(a);
  const auto casted_b = std::dynamic_pointer_cast<Shares::GMWShare>(b);
  const auto casted_sel = std::dynamic_pointer_cast<Shares::GMWShare>(sel);
  assert(casted_a);
  assert(casted_b);
  assert(casted_sel);
  return BooleanGMWMUX(casted_a, casted_b, casted_sel);
}

Shares::SharePtr Backend::BooleanGMWOutput(const Shares::SharePtr &parent,
                                           std::size_t output_owner) {
  assert(parent);
  const auto out_gate = std::make_shared<Gates::GMW::GMWOutputGate>(parent, output_owner);
  const auto out_gate_cast = std::static_pointer_cast<Gates::Interfaces::Gate>(out_gate);
  RegisterGate(out_gate_cast);
  return std::static_pointer_cast<Shares::Share>(out_gate->GetOutputAsShare());
}

Shares::SharePtr Backend::BMRInput(std::size_t party_id, bool input) {
  return BMRInput(party_id, ENCRYPTO::BitVector(1, input));
}

Shares::SharePtr Backend::BMRInput(std::size_t party_id, const ENCRYPTO::BitVector<> &input) {
  return BMRInput(party_id, std::vector<ENCRYPTO::BitVector<>>{input});
}

Shares::SharePtr Backend::BMRInput(std::size_t party_id, ENCRYPTO::BitVector<> &&input) {
  return BMRInput(party_id, std::vector<ENCRYPTO::BitVector<>>{std::move(input)});
}

Shares::SharePtr Backend::BMRInput(std::size_t party_id,
                                   const std::vector<ENCRYPTO::BitVector<>> &input) {
  const auto in_gate =
      std::make_shared<Gates::BMR::BMRInputGate>(input, party_id, weak_from_this());
  const auto in_gate_cast = std::static_pointer_cast<Gates::Interfaces::InputGate>(in_gate);
  RegisterInputGate(in_gate_cast);
  return std::static_pointer_cast<Shares::Share>(in_gate->GetOutputAsBMRShare());
}

Shares::SharePtr Backend::BMRInput(std::size_t party_id,
                                   std::vector<ENCRYPTO::BitVector<>> &&input) {
  const auto in_gate =
      std::make_shared<Gates::BMR::BMRInputGate>(std::move(input), party_id, weak_from_this());
  const auto in_gate_cast = std::static_pointer_cast<Gates::Interfaces::InputGate>(in_gate);
  RegisterInputGate(in_gate_cast);
  return std::static_pointer_cast<Shares::Share>(in_gate->GetOutputAsBMRShare());
}

Shares::SharePtr Backend::BMROutput(const Shares::SharePtr &parent, std::size_t output_owner) {
  assert(parent);
  const auto out_gate = std::make_shared<Gates::BMR::BMROutputGate>(parent, output_owner);
  const auto out_gate_cast = std::static_pointer_cast<Gates::Interfaces::Gate>(out_gate);
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
  if constexpr (MOTION_DEBUG) {
    register_->GetLogger()->LogDebug("Start computing base OTs");
  }

  std::vector<std::future<void>> task_futures;
  std::vector<std::unique_ptr<OT_HL17>> base_ots;
  std::vector<std::shared_ptr<DataStorage>> data_storages;

  task_futures.reserve(2 * (config_->GetNumOfParties() - 1));
  base_ots.reserve(config_->GetNumOfParties());
  data_storages.reserve(config_->GetNumOfParties());

  for (auto i = 0ull; i < config_->GetNumOfParties(); ++i) {
    if (i == config_->GetMyId()) {
      data_storages.push_back(nullptr);
      base_ots.emplace_back(nullptr);
      continue;
    }

    auto send_function = [this, i](flatbuffers::FlatBufferBuilder &&message) {
      Send(i, std::move(message));
    };
    auto data_storage = GetConfig()->GetContexts().at(i)->GetDataStorage();
    data_storages.push_back(data_storage);
    base_ots.emplace_back(std::make_unique<OT_HL17>(send_function, data_storage));

    task_futures.emplace_back(std::async(std::launch::async, [&base_ots, &data_storages, i] {
      auto choices = ENCRYPTO::BitVector<>::Random(128);
      auto chosen_messages = base_ots[i]->recv(choices);  // sender base ots
      auto &receiver_data = data_storages[i]->GetBaseOTsReceiverData();
      receiver_data->c_ = std::move(choices);
      for (std::size_t i = 0; i < chosen_messages.size(); ++i) {
        auto b = receiver_data->messages_c_.at(i).begin();
        std::copy(chosen_messages.at(i).begin(), chosen_messages.at(i).begin() + 16, b);
      }
      std::scoped_lock lock(receiver_data->is_ready_condition_->GetMutex());
      receiver_data->is_ready_ = true;
    }));

    task_futures.emplace_back(std::async(std::launch::async, [&base_ots, &data_storages, i] {
      auto both_messages = base_ots[i]->send(128);  // receiver base ots
      auto &sender_data = data_storages[i]->GetBaseOTsSenderData();
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
    }));
  }
  std::for_each(task_futures.begin(), task_futures.end(), [](auto &f) { f.get(); });
  base_ots_finished_ = true;

  if constexpr (MOTION_DEBUG) {
    register_->GetLogger()->LogDebug("Finished computing base OTs");
  }
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

void Backend::OTExtensionSetup() {
  require_base_ots_ = true;

  if (ot_extension_finished_) {
    return;
  }

  if (!GetConfig()->IsFixedKeyAESKeyReady()) {
    GenerateFixedKeyAESKey();
  }

  if (!base_ots_finished_) {
    ComputeBaseOTs();
  }

  if constexpr (MOTION_DEBUG) {
    register_->GetLogger()->LogDebug("Start computing setup for OTExtensions");
  }

  std::vector<std::future<void>> task_futures;
  task_futures.reserve(2 * (config_->GetNumOfParties() - 1));

  for (auto i = 0ull; i < config_->GetNumOfParties(); ++i) {
    if (i == config_->GetMyId()) {
      continue;
    }
    task_futures.emplace_back(
        std::async(std::launch::async, [this, i] { ot_provider_.at(i)->SendSetup(); }));
    task_futures.emplace_back(
        std::async(std::launch::async, [this, i] { ot_provider_.at(i)->ReceiveSetup(); }));
  }

  std::for_each(task_futures.begin(), task_futures.end(), [](auto &f) { f.get(); });
  ot_extension_finished_ = true;

  if constexpr (MOTION_DEBUG) {
    register_->GetLogger()->LogDebug("Finished setup for OTExtensions");
  }
}
}  // namespace MOTION
