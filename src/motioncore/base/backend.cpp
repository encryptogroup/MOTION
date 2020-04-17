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

#include <boost/log/trivial.hpp>
#include <chrono>
#include <functional>
#include <future>
#include <iterator>

#include <fmt/format.h>
#include <boost/asio/thread_pool.hpp>

#include "communication/communication_layer.h"
#include "communication/message.h"
#include "configuration.h"
#include "crypto/base_ots/base_ot_provider.h"
#include "crypto/bmr_provider.h"
#include "crypto/motion_base_provider.h"
#include "crypto/multiplication_triple/mt_provider.h"
#include "crypto/multiplication_triple/sb_provider.h"
#include "crypto/multiplication_triple/sp_provider.h"
#include "crypto/oblivious_transfer/ot_provider.h"
#include "data_storage/base_ot_data.h"
#include "executor/gate_executor.h"
#include "gate/bmr_gate.h"
#include "gate/boolean_gmw_gate.h"
#include "register.h"
#include "share/bmr_share.h"
#include "share/boolean_gmw_share.h"
#include "statistics/run_time_stats.h"
#include "utility/constants.h"

using namespace std::chrono_literals;

namespace MOTION {

Backend::Backend(Communication::CommunicationLayer &communication_layer, ConfigurationPtr &config,
                 std::shared_ptr<Logger> logger)
    : run_time_stats_(1),
      communication_layer_(communication_layer),
      logger_(logger),
      config_(config),
      register_(std::make_shared<Register>(logger_)),
      gate_executor_(std::make_unique<GateExecutor>(
          *register_, [this] { RunPreprocessing(); }, logger_)) {
  motion_base_provider_ =
      std::make_unique<Crypto::MotionBaseProvider>(communication_layer_, logger_);
  base_ot_provider_ = std::make_unique<BaseOTProvider>(communication_layer, logger_);

  communication_layer_.set_logger(logger_);
  auto my_id = communication_layer_.get_my_id();

  ot_provider_manager_ = std::make_unique<ENCRYPTO::ObliviousTransfer::OTProviderManager>(
      communication_layer_, *base_ot_provider_, *motion_base_provider_, logger_);

  mt_provider_ = std::make_shared<MTProviderFromOTs>(ot_provider_manager_->get_providers(), my_id,
                                                     *logger_, run_time_stats_.back());
  sp_provider_ = std::make_shared<SPProviderFromOTs>(ot_provider_manager_->get_providers(), my_id,
                                                     *logger_, run_time_stats_.back());
  sb_provider_ = std::make_shared<SBProviderFromSPs>(communication_layer_, sp_provider_, *logger_,
                                                     run_time_stats_.back());
  bmr_provider_ = std::make_unique<Crypto::BMRProvider>(communication_layer_);
  communication_layer_.start();
}

Backend::~Backend() = default;

const LoggerPtr &Backend::GetLogger() const noexcept { return logger_; }

std::size_t Backend::NextGateId() const { return register_->NextGateId(); }

// TODO: remove this method
void Backend::Send(std::size_t party_id, flatbuffers::FlatBufferBuilder &&message) {
  communication_layer_.send_message(party_id, std::move(message));
}

void Backend::RegisterInputGate(const Gates::Interfaces::InputGatePtr &input_gate) {
  auto gate = std::static_pointer_cast<Gates::Interfaces::Gate>(input_gate);
  register_->RegisterNextInputGate(gate);
}

void Backend::RegisterGate(const Gates::Interfaces::GatePtr &gate) {
  register_->RegisterNextGate(gate);
}

// TODO: move this to OTProvider(Wrapper)
bool Backend::NeedOTs() {
  auto &ot_providers = ot_provider_manager_->get_providers();
  for (auto party_id = 0ull; party_id < communication_layer_.get_num_parties(); ++party_id) {
    if (party_id == communication_layer_.get_my_id()) continue;
    if (ot_providers.at(party_id)->GetNumOTsReceiver() > 0 ||
        ot_providers.at(party_id)->GetNumOTsSender() > 0)
      return true;
  }
  return false;
}

void Backend::RunPreprocessing() {
  logger_->LogInfo("Start preprocessing");
  run_time_stats_.back().record_start<Statistics::RunTimeStats::StatID::preprocessing>();

  // TODO: should this be measured?
  motion_base_provider_->setup();

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

  run_time_stats_.back().record_end<Statistics::RunTimeStats::StatID::preprocessing>();
}

void Backend::EvaluateSequential() {
  gate_executor_->evaluate_setup_online(run_time_stats_.back());
}

void Backend::EvaluateParallel() {
  gate_executor_->evaluate(run_time_stats_.back());
}

const Gates::Interfaces::GatePtr &Backend::GetGate(std::size_t gate_id) const {
  return register_->GetGate(gate_id);
}

const std::vector<Gates::Interfaces::GatePtr> &Backend::GetInputGates() const {
  return register_->GetInputGates();
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
  const auto in_gate = std::make_shared<Gates::GMW::GMWInputGate>(input, party_id, *this);
  const auto in_gate_cast = std::static_pointer_cast<Gates::Interfaces::InputGate>(in_gate);
  RegisterInputGate(in_gate_cast);
  return std::static_pointer_cast<Shares::Share>(in_gate->GetOutputAsGMWShare());
}

Shares::SharePtr Backend::BooleanGMWInput(std::size_t party_id,
                                          std::vector<ENCRYPTO::BitVector<>> &&input) {
  const auto in_gate =
      std::make_shared<Gates::GMW::GMWInputGate>(std::move(input), party_id, *this);
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
  const auto in_gate = std::make_shared<Gates::BMR::BMRInputGate>(input, party_id, *this);
  const auto in_gate_cast = std::static_pointer_cast<Gates::Interfaces::InputGate>(in_gate);
  RegisterInputGate(in_gate_cast);
  return std::static_pointer_cast<Shares::Share>(in_gate->GetOutputAsBMRShare());
}

Shares::SharePtr Backend::BMRInput(std::size_t party_id,
                                   std::vector<ENCRYPTO::BitVector<>> &&input) {
  const auto in_gate =
      std::make_shared<Gates::BMR::BMRInputGate>(std::move(input), party_id, *this);
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

void Backend::Sync() { communication_layer_.sync(); }

void Backend::ComputeBaseOTs() {
  run_time_stats_.back().record_start<Statistics::RunTimeStats::StatID::base_ots>();
  base_ot_provider_->ComputeBaseOTs();
  run_time_stats_.back().record_end<Statistics::RunTimeStats::StatID::base_ots>();

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

// TODO: move to OTProvider(Wrapper)
void Backend::OTExtensionSetup() {
  require_base_ots_ = true;

  if (ot_extension_finished_) {
    return;
  }

  if (!base_ots_finished_) {
    ComputeBaseOTs();
  }

  motion_base_provider_->setup();

  if constexpr (MOTION_DEBUG) {
    logger_->LogDebug("Start computing setup for OTExtensions");
  }

  run_time_stats_.back().record_start<Statistics::RunTimeStats::StatID::ot_extension_setup>();

  std::vector<std::future<void>> task_futures;
  task_futures.reserve(2 * (communication_layer_.get_num_parties() - 1));

  for (auto i = 0ull; i < communication_layer_.get_num_parties(); ++i) {
    if (i == communication_layer_.get_my_id()) {
      continue;
    }
    task_futures.emplace_back(std::async(
        std::launch::async, [this, i] { ot_provider_manager_->get_provider(i).SendSetup(); }));
    task_futures.emplace_back(std::async(
        std::launch::async, [this, i] { ot_provider_manager_->get_provider(i).ReceiveSetup(); }));
  }

  std::for_each(task_futures.begin(), task_futures.end(), [](auto &f) { f.get(); });
  ot_extension_finished_ = true;

  run_time_stats_.back().record_end<Statistics::RunTimeStats::StatID::ot_extension_setup>();

  if constexpr (MOTION_DEBUG) {
    logger_->LogDebug("Finished setup for OTExtensions");
  }
}

ENCRYPTO::ObliviousTransfer::OTProvider &Backend::GetOTProvider(std::size_t party_id) {
  return ot_provider_manager_->get_provider(party_id);
}

}  // namespace MOTION
