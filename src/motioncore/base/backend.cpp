// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko, Lennart Braun
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

#include <chrono>
#include <functional>
#include <future>
#include <iterator>

#include <fmt/format.h>
#include <boost/asio/thread_pool.hpp>

#include "communication/fbs_headers/hello_message_generated.h"
#include "communication/handler.h"
#include "communication/hello_message.h"
#include "communication/message.h"
#include "crypto/base_ots/base_ot_provider.h"
#include "crypto/multiplication_triple/mt_provider.h"
#include "crypto/multiplication_triple/sb_provider.h"
#include "crypto/multiplication_triple/sp_provider.h"
#include "crypto/oblivious_transfer/ot_provider.h"
#include "data_storage/base_ot_data.h"
#include "data_storage/data_storage.h"
#include "gate/bmr_gate.h"
#include "gate/boolean_gmw_gate.h"
#include "register.h"
#include "share/bmr_share.h"
#include "share/boolean_gmw_share.h"
#include "utility/constants.h"
#include "utility/fiber_thread_pool/fiber_thread_pool.hpp"

using namespace std::chrono_literals;

namespace MOTION {

Backend::Backend(ConfigurationPtr &config) : config_(config) {
  register_ = std::make_shared<Register>(config_);
  base_ot_provider_ = std::make_unique<BaseOTProvider>(*config_, *register_->GetLogger(), *register_);
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
  sp_provider_ = std::make_shared<SPProviderFromOTs>(ot_provider_, GetConfig()->GetMyId());
  sb_provider_ = std::make_shared<SBProviderFromSPs>(config_, register_, sp_provider_);
}

Backend::~Backend() = default;

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

void Backend::RunPreprocessing() {
  register_->GetLogger()->LogInfo("Start preprocessing");

  // SB needs SP
  // SP needs OT
  // MT needs OT

  const bool needs_mts = GetMTProvider()->NeedMTs();
  if (needs_mts) {
    mt_provider_->PreSetup();
  }
  const bool needs_sbs = GetSBProvider()->NeedSBs();
  if (needs_sbs) {
    sb_provider_->PreSetup();
  }
  const bool needs_sps = GetSPProvider()->NeedSPs();
  if (needs_sps) {
    sp_provider_->PreSetup();
  }

  if (NeedOTs()) {
    OTExtensionSetup();
  }

  std::array<std::future<void>, 3> futures;
  futures.at(0) = std::async(std::launch::async, [this] { mt_provider_->Setup(); });
  futures.at(1) = std::async(std::launch::async, [this] { sp_provider_->Setup(); });
  futures.at(2) = std::async(std::launch::async, [this] { sb_provider_->Setup(); });
  std::for_each(futures.begin(), futures.end(), [](auto &f) { f.get(); });
}

void Backend::EvaluateSequential() {
  RunPreprocessing();

  register_->GetLogger()->LogInfo(
      "Start evaluating the circuit gates sequentially (online after all finished setup)");

  // setup phase: -------------------------------------------------------

  // create a pool with std::thread::hardware_concurrency() no. of threads
  // to execute fibers
  ENCRYPTO::FiberThreadPool fpool_setup(0, config_->GetNumOfParties());

  // evaluate all the gates
  for (auto& gate : register_->GetGates()) {
    fpool_setup.post([&] { gate->EvaluateSetup(); });
  }

  // we have to wait until all gates are evaluated before we close the pool
  register_->GetGatesSetupDoneCondition()->Wait();

  fpool_setup.join();

  assert(register_->GetNumOfEvaluatedGateSetups() == register_->GetTotalNumOfGates());

  // online phase: ------------------------------------------------------

  // create a pool with std::thread::hardware_concurrency() no. of threads
  // to execute fibers
  ENCRYPTO::FiberThreadPool fpool_online(0, config_->GetNumOfParties());

  // evaluate all the gates
  for (auto& gate : register_->GetGates()) {
    fpool_online.post([&] { gate->EvaluateOnline(); });
  }

  // we have to wait until all gates are evaluated before we close the pool
  register_->GetGatesOnlineDoneCondition()->Wait();

  fpool_online.join();

  // XXX: since we never pop elements from the active queue, clear it manually for now
  // otherwise there will be complains that it is not empty upon repeated execution
  // -> maybe remove the active queue in the future
  register_->ClearActiveQueue();
}

void Backend::EvaluateParallel() {
  register_->GetLogger()->LogInfo(
      "Start evaluating the circuit gates in parallel (online as soon as some finished setup)");

  // Run preprocessing setup in a separate thread
  auto f_preprocessing = std::async(std::launch::async, [this] { RunPreprocessing(); });

  // create a pool with std::thread::hardware_concurrency() no. of threads
  // to execute fibers
  ENCRYPTO::FiberThreadPool fpool(0, config_->GetNumOfParties());

  // evaluate all the gates
  for (auto& gate : register_->GetGates()) {
    fpool.post([&] { gate->EvaluateSetup();
        // XXX: maybe insert a 'yield' here?
        gate->EvaluateOnline(); });
  }

  f_preprocessing.get();

  // we have to wait until all gates are evaluated before we close the pool
  register_->GetGatesOnlineDoneCondition()->Wait();
  fpool.join();

  // XXX: since we never pop elements from the active queue, clear it manually for now
  // otherwise there will be complains that it is not empty upon repeated execution
  // -> maybe remove the active queue in the future
  register_->ClearActiveQueue();
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
  base_ot_provider_->ComputeBaseOTs();
  base_ots_finished_ = true;
}

void Backend::ImportBaseOTs(std::size_t i, const ReceiverMsgs &msgs) {
  base_ot_provider_->ImportBaseOTs(i, msgs);
}

void Backend::ImportBaseOTs(std::size_t i, const SenderMsgs &msgs) {
  base_ot_provider_->ImportBaseOTs(i, msgs);
}

std::pair<ReceiverMsgs, SenderMsgs> Backend::ExportBaseOTs(std::size_t i) {
  return base_ot_provider_->ExportBaseOTs(i);
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
