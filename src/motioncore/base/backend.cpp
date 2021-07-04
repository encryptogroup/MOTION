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

#include <boost/asio/thread_pool.hpp>

#include "backend.h"
#include "motion_base_provider.h"

#include <boost/log/trivial.hpp>
#include <chrono>
#include <functional>
#include <future>
#include <iterator>
#include <span>

#include <fmt/format.h>

#include "communication/communication_layer.h"
#include "communication/message.h"
#include "configuration.h"
#include "data_storage/base_ot_data.h"
#include "executor/gate_executor.h"
#include "multiplication_triple/mt_provider.h"
#include "multiplication_triple/sb_provider.h"
#include "multiplication_triple/sp_provider.h"
#include "oblivious_transfer/base_ots/base_ot_provider.h"
#include "oblivious_transfer/ot_provider.h"
#include "protocols/bmr/bmr_gate.h"
#include "protocols/bmr/bmr_provider.h"
#include "protocols/bmr/bmr_share.h"
#include "protocols/boolean_gmw/boolean_gmw_gate.h"
#include "protocols/boolean_gmw/boolean_gmw_share.h"
#include "register.h"
#include "statistics/run_time_statistics.h"
#include "utility/constants.h"

using namespace std::chrono_literals;

namespace encrypto::motion {

Backend::Backend(communication::CommunicationLayer& communication_layer,
                 ConfigurationPointer& configuration, std::shared_ptr<Logger> logger)
    : run_time_statistics_(1),
      communication_layer_(communication_layer),
      logger_(logger),
      configuration_(configuration),
      register_(std::make_shared<Register>(logger_)),
      gate_executor_(std::make_unique<GateExecutor>(
          *register_, [this] { RunPreprocessing(); }, logger_)) {
  motion_base_provider_ = std::make_unique<BaseProvider>(communication_layer_, logger_);
  base_ot_provider_ = std::make_unique<BaseOtProvider>(communication_layer, logger_);

  communication_layer_.SetLogger(logger_);
  auto my_id = communication_layer_.GetMyId();

  ot_provider_manager_ = std::make_unique<OtProviderManager>(
      communication_layer_, *base_ot_provider_, *motion_base_provider_, logger_);

  mt_provider_ = std::make_shared<MtProviderFromOts>(ot_provider_manager_->GetProviders(), my_id,
                                                     *logger_, run_time_statistics_.back());
  sp_provider_ = std::make_shared<SpProviderFromOts>(ot_provider_manager_->GetProviders(), my_id,
                                                     *logger_, run_time_statistics_.back());
  sb_provider_ = std::make_shared<SbProviderFromSps>(communication_layer_, sp_provider_, *logger_,
                                                     run_time_statistics_.back());
  bmr_provider_ = std::make_unique<proto::bmr::Provider>(communication_layer_);
  communication_layer_.Start();
}

Backend::~Backend() = default;

const LoggerPointer& Backend::GetLogger() const noexcept { return logger_; }

std::size_t Backend::NextGateId() const { return register_->NextGateId(); }

// TODO: remove this method
void Backend::Send(std::size_t party_id, flatbuffers::FlatBufferBuilder&& message) {
  communication_layer_.SendMessage(party_id, std::move(message));
}

void Backend::RegisterInputGate(const InputGatePointer& input_gate) {
  auto gate = std::static_pointer_cast<Gate>(input_gate);
  register_->RegisterNextInputGate(gate);
}

void Backend::RegisterGate(const GatePointer& gate) { register_->RegisterNextGate(gate); }

// TODO: move this to OtProvider(Wrapper)
bool Backend::NeedOts() {
  auto& ot_providers = ot_provider_manager_->GetProviders();
  for (auto party_id = 0ull; party_id < communication_layer_.GetNumberOfParties(); ++party_id) {
    if (party_id == communication_layer_.GetMyId()) continue;
    if (ot_providers.at(party_id)->GetNumOtsReceiver() > 0 ||
        ot_providers.at(party_id)->GetNumOtsSender() > 0)
      return true;
  }
  return false;
}

void Backend::RunPreprocessing() {
  logger_->LogInfo("Start preprocessing");
  run_time_statistics_.back().RecordStart<RunTimeStatistics::StatisticsId::kPreprocessing>();

  // TODO: should this be measured?
  motion_base_provider_->Setup();

  // SB needs SP
  // SP needs OT
  // MT needs OT

  const bool needs_mts = GetMtProvider()->NeedMts();
  if (needs_mts) {
    mt_provider_->PreSetup();
  }
  const bool needs_sbs = GetSbProvider()->NeedSbs();
  if (needs_sbs) {
    sb_provider_->PreSetup();
  }
  const bool needs_sps = GetSpProvider()->NeedSps();
  if (needs_sps) {
    sp_provider_->PreSetup();
  }

  if (NeedOts()) {
    OtExtensionSetup();
  }

  std::array<std::future<void>, 3> futures;
  futures.at(0) = std::async(std::launch::async, [this] { mt_provider_->Setup(); });
  futures.at(1) = std::async(std::launch::async, [this] { sp_provider_->Setup(); });
  futures.at(2) = std::async(std::launch::async, [this] { sb_provider_->Setup(); });
  std::for_each(futures.begin(), futures.end(), [](auto& f) { f.get(); });

  run_time_statistics_.back().RecordEnd<RunTimeStatistics::StatisticsId::kPreprocessing>();
}

void Backend::EvaluateSequential() {
  gate_executor_->EvaluateSetupOnline(run_time_statistics_.back());
}

void Backend::EvaluateParallel() { gate_executor_->Evaluate(run_time_statistics_.back()); }

const GatePointer& Backend::GetGate(std::size_t gate_id) const {
  return register_->GetGate(gate_id);
}

const std::vector<GatePointer>& Backend::GetInputGates() const {
  return register_->GetInputGates();
}

void Backend::Reset() { register_->Reset(); }

void Backend::Clear() { register_->Clear(); }

SharePointer Backend::BooleanGmwInput(std::size_t party_id, bool input) {
  return BooleanGmwInput(party_id, BitVector(1, input));
}

SharePointer Backend::BooleanGmwInput(std::size_t party_id, const BitVector<>& input) {
  return BooleanGmwInput(party_id, std::vector<BitVector<>>{input});
}

SharePointer Backend::BooleanGmwInput(std::size_t party_id, BitVector<>&& input) {
  return BooleanGmwInput(party_id, std::vector<BitVector<>>{std::move(input)});
}

SharePointer Backend::BooleanGmwInput(std::size_t party_id, std::span<const BitVector<>> input) {
  const auto input_gate = std::make_shared<proto::boolean_gmw::InputGate>(input, party_id, *this);
  const auto input_gate_cast = std::static_pointer_cast<InputGate>(input_gate);
  RegisterInputGate(input_gate_cast);
  return std::static_pointer_cast<Share>(input_gate->GetOutputAsGmwShare());
}

SharePointer Backend::BooleanGmwInput(std::size_t party_id, std::vector<BitVector<>>&& input) {
  const auto input_gate =
      std::make_shared<proto::boolean_gmw::InputGate>(std::move(input), party_id, *this);
  const auto input_gate_cast = std::static_pointer_cast<InputGate>(input_gate);
  RegisterInputGate(input_gate_cast);
  return std::static_pointer_cast<Share>(input_gate->GetOutputAsGmwShare());
}

SharePointer Backend::BooleanGmwXor(const proto::boolean_gmw::SharePointer& a,
                                    const proto::boolean_gmw::SharePointer& b) {
  assert(a);
  assert(b);
  const auto xor_gate = std::make_shared<proto::boolean_gmw::XorGate>(a, b);
  RegisterGate(xor_gate);
  return xor_gate->GetOutputAsShare();
}

SharePointer Backend::BooleanGmwXor(const SharePointer& a, const SharePointer& b) {
  assert(a);
  assert(b);
  const auto casted_a = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(a);
  const auto casted_b = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(b);
  assert(casted_a);
  assert(casted_b);
  return BooleanGmwXor(casted_a, casted_b);
}

SharePointer Backend::BooleanGmwAnd(const proto::boolean_gmw::SharePointer& a,
                                    const proto::boolean_gmw::SharePointer& b) {
  assert(a);
  assert(b);
  const auto and_gate = std::make_shared<proto::boolean_gmw::AndGate>(a, b);
  RegisterGate(and_gate);
  return and_gate->GetOutputAsShare();
}

SharePointer Backend::BooleanGmwAnd(const SharePointer& a, const SharePointer& b) {
  assert(a);
  assert(b);
  const auto casted_a = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(a);
  const auto casted_b = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(b);
  assert(casted_a);
  assert(casted_b);
  return BooleanGmwAnd(casted_a, casted_b);
}

SharePointer Backend::BooleanGmwMux(const proto::boolean_gmw::SharePointer& a,
                                    const proto::boolean_gmw::SharePointer& b,
                                    const proto::boolean_gmw::SharePointer& selection) {
  assert(a);
  assert(b);
  assert(selection);
  const auto mux_gate = std::make_shared<proto::boolean_gmw::MuxGate>(a, b, selection);
  RegisterGate(mux_gate);
  return mux_gate->GetOutputAsShare();
}

SharePointer Backend::BooleanGmwMux(const SharePointer& a, const SharePointer& b,
                                    const SharePointer& selection) {
  assert(a);
  assert(b);
  assert(selection);
  const auto casted_a = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(a);
  const auto casted_b = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(b);
  const auto casted_selection = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(selection);
  assert(casted_a);
  assert(casted_b);
  assert(casted_selection);
  return BooleanGmwMux(casted_a, casted_b, casted_selection);
}

SharePointer Backend::BooleanGmwOutput(const SharePointer& parent, std::size_t output_owner) {
  assert(parent);
  const auto output_gate = std::make_shared<proto::boolean_gmw::OutputGate>(parent, output_owner);
  const auto ouput_gate_cast = std::static_pointer_cast<Gate>(output_gate);
  RegisterGate(ouput_gate_cast);
  return std::static_pointer_cast<Share>(output_gate->GetOutputAsShare());
}

SharePointer Backend::BmrInput(std::size_t party_id, bool input) {
  return BmrInput(party_id, BitVector(1, input));
}

SharePointer Backend::BmrInput(std::size_t party_id, const BitVector<>& input) {
  return BmrInput(party_id, std::vector<BitVector<>>{input});
}

SharePointer Backend::BmrInput(std::size_t party_id, BitVector<>&& input) {
  return BmrInput(party_id, std::vector<BitVector<>>{std::move(input)});
}

SharePointer Backend::BmrInput(std::size_t party_id, std::span<const BitVector<>> input) {
  const auto input_gate = std::make_shared<proto::bmr::InputGate>(input, party_id, *this);
  const auto input_gate_cast = std::static_pointer_cast<InputGate>(input_gate);
  RegisterInputGate(input_gate_cast);
  return std::static_pointer_cast<Share>(input_gate->GetOutputAsBmrShare());
}

SharePointer Backend::BmrInput(std::size_t party_id, std::vector<BitVector<>>&& input) {
  const auto input_gate =
      std::make_shared<proto::bmr::InputGate>(std::move(input), party_id, *this);
  const auto input_gate_cast = std::static_pointer_cast<InputGate>(input_gate);
  RegisterInputGate(input_gate_cast);
  return std::static_pointer_cast<Share>(input_gate->GetOutputAsBmrShare());
}

SharePointer Backend::BmrOutput(const SharePointer& parent, std::size_t output_owner) {
  assert(parent);
  const auto output_gate = std::make_shared<proto::bmr::OutputGate>(parent, output_owner);
  const auto ouput_gate_cast = std::static_pointer_cast<Gate>(output_gate);
  RegisterGate(ouput_gate_cast);
  return std::static_pointer_cast<Share>(output_gate->GetOutputAsShare());
}

void Backend::Synchronize() { communication_layer_.Synchronize(); }

void Backend::ComputeBaseOts() {
  run_time_statistics_.back().RecordStart<RunTimeStatistics::StatisticsId::kBaseOts>();
  base_ot_provider_->ComputeBaseOts();
  run_time_statistics_.back().RecordEnd<RunTimeStatistics::StatisticsId::kBaseOts>();

  base_ots_finished_ = true;
}

void Backend::ImportBaseOts(std::size_t i, const ReceiverMessage& messages) {
  base_ot_provider_->ImportBaseOts(i, messages);
}

void Backend::ImportBaseOts(std::size_t i, const SenderMessage& messages) {
  base_ot_provider_->ImportBaseOts(i, messages);
}

std::pair<ReceiverMessage, SenderMessage> Backend::ExportBaseOts(std::size_t i) {
  return base_ot_provider_->ExportBaseOts(i);
}

// TODO: move to OtProvider(Wrapper)
void Backend::OtExtensionSetup() {
  require_base_ots_ = true;

  if (ot_extension_finished_) {
    return;
  }

  if (!base_ots_finished_) {
    ComputeBaseOts();
  }

  motion_base_provider_->Setup();

  if constexpr (kDebug) {
    logger_->LogDebug("Start computing setup for OTExtensions");
  }

  run_time_statistics_.back().RecordStart<RunTimeStatistics::StatisticsId::kOtExtensionSetup>();

  std::vector<std::future<void>> task_futures;
  task_futures.reserve(2 * (communication_layer_.GetNumberOfParties() - 1));

  for (auto i = 0ull; i < communication_layer_.GetNumberOfParties(); ++i) {
    if (i == communication_layer_.GetMyId()) {
      continue;
    }
    task_futures.emplace_back(std::async(
        std::launch::async, [this, i] { ot_provider_manager_->GetProvider(i).SendSetup(); }));
    task_futures.emplace_back(std::async(
        std::launch::async, [this, i] { ot_provider_manager_->GetProvider(i).ReceiveSetup(); }));
  }

  std::for_each(task_futures.begin(), task_futures.end(), [](auto& f) { f.get(); });
  ot_extension_finished_ = true;

  run_time_statistics_.back().RecordEnd<RunTimeStatistics::StatisticsId::kOtExtensionSetup>();

  if constexpr (kDebug) {
    logger_->LogDebug("Finished setup for OTExtensions");
  }
}

OtProvider& Backend::GetOtProvider(std::size_t party_id) {
  return ot_provider_manager_->GetProvider(party_id);
}

}  // namespace encrypto::motion
