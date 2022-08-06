// MIT License
//
// Copyright (c) 2019-2022 Oleksandr Tkachenko, Lennart Braun, Arianne Roselina Prananto
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
#include "oblivious_transfer/1_out_of_n/kk13_ot_provider.h"
#include "oblivious_transfer/base_ots/base_ot_provider.h"
#include "oblivious_transfer/ot_provider.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_share.h"
#include "protocols/astra/astra_gate.h"
#include "protocols/astra/astra_share.h"
#include "protocols/bmr/bmr_gate.h"
#include "protocols/bmr/bmr_provider.h"
#include "protocols/bmr/bmr_share.h"
#include "protocols/boolean_gmw/boolean_gmw_gate.h"
#include "protocols/boolean_gmw/boolean_gmw_share.h"
#include "protocols/constant/constant_share.h"
#include "protocols/garbled_circuit/garbled_circuit_gate.h"
#include "protocols/garbled_circuit/garbled_circuit_provider.h"
#include "protocols/garbled_circuit/garbled_circuit_share.h"
#include "register.h"
#include "statistics/run_time_statistics.h"
#include "utility/constants.h"

using namespace std::chrono_literals;

namespace encrypto::motion {

Backend::Backend(std::unique_ptr<communication::CommunicationLayer> communication_layer,
                 ConfigurationPointer configuration, std::shared_ptr<Logger> logger)
    : run_time_statistics_(1),
      communication_layer_(std::move(communication_layer)),
      logger_(logger),
      configuration_(configuration),
      register_(std::make_shared<Register>(logger_)),
      gate_executor_(std::make_unique<GateExecutor>(
          *register_, [this] { RunPreprocessing(); }, logger_)) {
  motion_base_provider_ = std::make_unique<BaseProvider>(*communication_layer_);
  base_ot_provider_ = std::make_unique<BaseOtProvider>(*communication_layer_);
  communication_layer_->SetLogger(logger_);
  auto my_id = communication_layer_->GetMyId();

  ot_provider_manager_ = std::make_unique<OtProviderManager>(
      *communication_layer_, *base_ot_provider_, *motion_base_provider_);

  kk13_ot_provider_manager_ = std::make_unique<Kk13OtProviderManager>(
      *communication_layer_, *base_ot_provider_, *motion_base_provider_);

  mt_provider_ = std::make_shared<MtProviderFromOts>(ot_provider_manager_->GetProviders(), my_id,
                                                     logger, run_time_statistics_.back());
  sp_provider_ = std::make_shared<SpProviderFromOts>(ot_provider_manager_->GetProviders(), my_id,
                                                     logger, run_time_statistics_.back());
  sb_provider_ = std::make_shared<SbProviderFromSps>(*communication_layer_, sp_provider_, logger,
                                                     run_time_statistics_.back());
  bmr_provider_ = std::make_unique<proto::bmr::Provider>(*communication_layer_);
  if (communication_layer_->GetNumberOfParties() == 2) {
    garbled_circuit_provider_ =
        proto::garbled_circuit::Provider::MakeProvider(*communication_layer_);
  }

  // TODO should probably throw if it has been already started
  communication_layer_->Start();
}

Backend::~Backend() {}

const LoggerPointer& Backend::GetLogger() const noexcept { return logger_; }

void Backend::RunPreprocessing() {
  logger_->LogInfo("Start preprocessing");
  run_time_statistics_.back().RecordStart<RunTimeStatistics::StatisticsId::kPreprocessing>();

  // TODO: should this be measured?
  motion_base_provider_->Setup();

  // TODO: design and implement a dependency manager that automatically arranges and runs
  // components depending on their dependencies
  // SB needs SP
  // SP needs OT
  // MT needs OT

  const bool needs_mts = mt_provider_->NeedMts();
  if (needs_mts) {
    mt_provider_->PreSetup();
  }
  const bool needs_sbs = sb_provider_->NeedSbs();
  if (needs_sbs) {
    sb_provider_->PreSetup();
  }
  const bool needs_sps = sp_provider_->NeedSps();
  if (needs_sps) {
    sp_provider_->PreSetup();
  }

  if (kk13_ot_provider_manager_->HasWork()) {
    kk13_ot_provider_manager_->PreSetup();
  }

  if (ot_provider_manager_->HasWork()) {
    ot_provider_manager_->PreSetup();
  }

  if (base_ot_provider_->HasWork()) {
    base_ot_provider_->PreSetup();
  }

  communication_layer_->Synchronize();

  if (base_ot_provider_->HasWork()) {
    base_ot_provider_->ComputeBaseOts();
  }

  if (ot_provider_manager_->HasWork() || kk13_ot_provider_manager_->HasWork()) {
    OtExtensionSetup();
  }

  std::vector<std::future<void>> futures;
  futures.reserve(4);
  futures.emplace_back(std::async(std::launch::async, [this] { mt_provider_->Setup(); }));
  futures.emplace_back(std::async(std::launch::async, [this] { sp_provider_->Setup(); }));
  futures.emplace_back(std::async(std::launch::async, [this] { sb_provider_->Setup(); }));
  if (garbled_circuit_provider_ && garbled_circuit_provider_->HasWork()) {
    futures.emplace_back(
        std::async(std::launch::async, [this] { garbled_circuit_provider_->Setup(); }));
  }

  for (auto& f : futures) {
    assert(f.valid());
    f.get();
  }

  run_time_statistics_.back().RecordEnd<RunTimeStatistics::StatisticsId::kPreprocessing>();
}

void Backend::EvaluateSequential() {
  gate_executor_->EvaluateSetupOnline(run_time_statistics_.back());
}

void Backend::EvaluateParallel() { gate_executor_->Evaluate(run_time_statistics_.back()); }

const GatePointer& Backend::GetGate(std::size_t gate_id) const {
  return register_->GetGate(gate_id);
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
  const auto input_gate =
      register_->EmplaceGate<proto::boolean_gmw::InputGate>(input, party_id, *this);
  return std::static_pointer_cast<Share>(input_gate->GetOutputAsGmwShare());
}

SharePointer Backend::BooleanGmwInput(std::size_t party_id, std::vector<BitVector<>>&& input) {
  const auto input_gate =
      register_->EmplaceGate<proto::boolean_gmw::InputGate>(input, party_id, *this);
  return std::static_pointer_cast<Share>(input_gate->GetOutputAsGmwShare());
}

SharePointer Backend::BooleanGmwOutput(const SharePointer& parent, std::size_t output_owner) {
  assert(parent);
  const auto output_gate =
      register_->EmplaceGate<proto::boolean_gmw::OutputGate>(parent, output_owner);
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
  const auto input_gate = register_->EmplaceGate<proto::bmr::InputGate>(input, party_id, *this);
  return std::static_pointer_cast<Share>(input_gate->GetOutputAsBmrShare());
}

SharePointer Backend::BmrInput(std::size_t party_id, std::vector<BitVector<>>&& input) {
  const auto input_gate = register_->EmplaceGate<proto::bmr::InputGate>(input, party_id, *this);
  return std::static_pointer_cast<Share>(input_gate->GetOutputAsBmrShare());
}

SharePointer Backend::BmrOutput(const SharePointer& parent, std::size_t output_owner) {
  assert(parent);
  const auto output_gate = register_->EmplaceGate<proto::bmr::OutputGate>(parent, output_owner);
  return std::static_pointer_cast<Share>(output_gate->GetOutputAsShare());
}

template <typename T>
SharePointer Backend::ArithmeticGmwInput(std::size_t party_id, T input) {
  std::vector<T> input_vector{input};
  return ArithmeticGmwInput(party_id, std::move(input_vector));
}

template SharePointer Backend::ArithmeticGmwInput<std::uint8_t>(std::size_t party_id,
                                                                std::uint8_t input);
template SharePointer Backend::ArithmeticGmwInput<std::uint16_t>(std::size_t party_id,
                                                                 std::uint16_t input);
template SharePointer Backend::ArithmeticGmwInput<std::uint32_t>(std::size_t party_id,
                                                                 std::uint32_t input);
template SharePointer Backend::ArithmeticGmwInput<std::uint64_t>(std::size_t party_id,
                                                                 std::uint64_t input);
template SharePointer Backend::ArithmeticGmwInput<__uint128_t>(std::size_t party_id,
                                                               __uint128_t input);

template <typename T>
SharePointer Backend::ArithmeticGmwInput(std::size_t party_id, const std::vector<T>& input_vector) {
  auto input_gate =
      register_->EmplaceGate<proto::arithmetic_gmw::InputGate<T>>(input_vector, party_id, *this);
  return std::static_pointer_cast<Share>(input_gate->GetOutputAsArithmeticShare());
}

template SharePointer Backend::ArithmeticGmwInput<std::uint8_t>(
    std::size_t party_id, const std::vector<std::uint8_t>& input);
template SharePointer Backend::ArithmeticGmwInput<std::uint16_t>(
    std::size_t party_id, const std::vector<std::uint16_t>& input);
template SharePointer Backend::ArithmeticGmwInput<std::uint32_t>(
    std::size_t party_id, const std::vector<std::uint32_t>& input);
template SharePointer Backend::ArithmeticGmwInput<std::uint64_t>(
    std::size_t party_id, const std::vector<std::uint64_t>& input);
template SharePointer Backend::ArithmeticGmwInput<__uint128_t>(
    std::size_t party_id, const std::vector<__uint128_t>& input);

template <typename T>
SharePointer Backend::ArithmeticGmwInput(std::size_t party_id, std::vector<T>&& input_vector) {
  auto input_gate =
      register_->EmplaceGate<proto::arithmetic_gmw::InputGate<T>>(input_vector, party_id, *this);
  return std::static_pointer_cast<Share>(input_gate->GetOutputAsArithmeticShare());
}

template SharePointer Backend::ArithmeticGmwInput<std::uint8_t>(std::size_t party_id,
                                                                std::vector<std::uint8_t>&& input);
template SharePointer Backend::ArithmeticGmwInput<std::uint16_t>(
    std::size_t party_id, std::vector<std::uint16_t>&& input);
template SharePointer Backend::ArithmeticGmwInput<std::uint32_t>(
    std::size_t party_id, std::vector<std::uint32_t>&& input);
template SharePointer Backend::ArithmeticGmwInput<std::uint64_t>(
    std::size_t party_id, std::vector<std::uint64_t>&& input);
template SharePointer Backend::ArithmeticGmwInput<__uint128_t>(std::size_t party_id,
                                                               std::vector<__uint128_t>&& input);

template <typename T>
SharePointer Backend::ArithmeticGmwOutput(const proto::arithmetic_gmw::SharePointer<T>& parent,
                                          std::size_t output_owner) {
  assert(parent);
  auto output_gate =
      register_->EmplaceGate<proto::arithmetic_gmw::OutputGate<T>>(parent, output_owner);
  return std::static_pointer_cast<Share>(output_gate->GetOutputAsArithmeticShare());
}

template SharePointer Backend::ArithmeticGmwOutput<std::uint8_t>(
    const proto::arithmetic_gmw::SharePointer<std::uint8_t>& parent, std::size_t output_owner);
template SharePointer Backend::ArithmeticGmwOutput<std::uint16_t>(
    const proto::arithmetic_gmw::SharePointer<std::uint16_t>& parent, std::size_t output_owner);
template SharePointer Backend::ArithmeticGmwOutput<std::uint32_t>(
    const proto::arithmetic_gmw::SharePointer<std::uint32_t>& parent, std::size_t output_owner);
template SharePointer Backend::ArithmeticGmwOutput<std::uint64_t>(
    const proto::arithmetic_gmw::SharePointer<std::uint64_t>& parent, std::size_t output_owner);
template SharePointer Backend::ArithmeticGmwOutput<__uint128_t>(
    const proto::arithmetic_gmw::SharePointer<__uint128_t>& parent, std::size_t output_owner);

template <typename T>
SharePointer Backend::ArithmeticGmwOutput(const SharePointer& parent, std::size_t output_owner) {
  assert(parent);
  auto casted_parent_pointer = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(parent);
  assert(casted_parent_pointer);
  return ArithmeticGmwOutput(casted_parent_pointer, output_owner);
}

template SharePointer Backend::ArithmeticGmwOutput<std::uint8_t>(const SharePointer& parent,
                                                                 std::size_t output_owner);
template SharePointer Backend::ArithmeticGmwOutput<std::uint16_t>(const SharePointer& parent,
                                                                  std::size_t output_owner);
template SharePointer Backend::ArithmeticGmwOutput<std::uint32_t>(const SharePointer& parent,
                                                                  std::size_t output_owner);
template SharePointer Backend::ArithmeticGmwOutput<std::uint64_t>(const SharePointer& parent,
                                                                  std::size_t output_owner);
template SharePointer Backend::ArithmeticGmwOutput<__uint128_t>(const SharePointer& parent,
                                                                std::size_t output_owner);

template <typename T>
SharePointer Backend::AstraInput(std::size_t party_id, T input) {
  return AstraInput(party_id, std::vector<T>(input));
}

template SharePointer Backend::AstraInput<std::uint8_t>(std::size_t party_id, std::uint8_t input);
template SharePointer Backend::AstraInput<std::uint16_t>(std::size_t party_id, std::uint16_t input);
template SharePointer Backend::AstraInput<std::uint32_t>(std::size_t party_id, std::uint32_t input);
template SharePointer Backend::AstraInput<std::uint64_t>(std::size_t party_id, std::uint64_t input);
template SharePointer Backend::AstraInput<__uint128_t>(std::size_t party_id, __uint128_t input);

template <typename T>
SharePointer Backend::AstraInput(std::size_t party_id, std::vector<T> input) {
  auto input_gate =
      register_->EmplaceGate<proto::astra::InputGate<T>>(std::move(input), party_id, *this);
  return std::static_pointer_cast<Share>(input_gate->GetOutputAsAstraShare());
}

template SharePointer Backend::AstraInput<std::uint8_t>(std::size_t party_id,
                                                        std::vector<std::uint8_t> input);
template SharePointer Backend::AstraInput<std::uint16_t>(std::size_t party_id,
                                                         std::vector<std::uint16_t> input);
template SharePointer Backend::AstraInput<std::uint32_t>(std::size_t party_id,
                                                         std::vector<std::uint32_t> input);
template SharePointer Backend::AstraInput<std::uint64_t>(std::size_t party_id,
                                                         std::vector<std::uint64_t> input);
template SharePointer Backend::AstraInput<__uint128_t>(std::size_t party_id,
                                                       std::vector<__uint128_t> input);

template <typename T>
SharePointer Backend::AstraOutput(const proto::astra::SharePointer<T>& parent,
                                  std::size_t output_owner) {
  assert(parent);
  auto output_gate = register_->EmplaceGate<proto::astra::OutputGate<T>>(parent, output_owner);
  return std::static_pointer_cast<Share>(output_gate->GetOutputAsAstraShare());
}

template SharePointer Backend::AstraOutput<std::uint8_t>(
    const proto::astra::SharePointer<std::uint8_t>& parent, std::size_t output_owner);
template SharePointer Backend::AstraOutput<std::uint16_t>(
    const proto::astra::SharePointer<std::uint16_t>& parent, std::size_t output_owner);
template SharePointer Backend::AstraOutput<std::uint32_t>(
    const proto::astra::SharePointer<std::uint32_t>& parent, std::size_t output_owner);
template SharePointer Backend::AstraOutput<std::uint64_t>(
    const proto::astra::SharePointer<std::uint64_t>& parent, std::size_t output_owner);
template SharePointer Backend::AstraOutput<__uint128_t>(
    const proto::astra::SharePointer<__uint128_t>& parent, std::size_t output_owner);

template <typename T>
SharePointer Backend::AstraOutput(const SharePointer& parent, std::size_t output_owner) {
  assert(parent);
  auto casted_parent_pointer = std::dynamic_pointer_cast<proto::astra::Share<T>>(parent);
  assert(casted_parent_pointer);
  return AstraOutput<T>(casted_parent_pointer, output_owner);
}

template SharePointer Backend::AstraOutput<std::uint8_t>(const SharePointer& parent,
                                                         std::size_t output_owner);
template SharePointer Backend::AstraOutput<std::uint16_t>(const SharePointer& parent,
                                                          std::size_t output_owner);
template SharePointer Backend::AstraOutput<std::uint32_t>(const SharePointer& parent,
                                                          std::size_t output_owner);
template SharePointer Backend::AstraOutput<std::uint64_t>(const SharePointer& parent,
                                                          std::size_t output_owner);
template SharePointer Backend::AstraOutput<__uint128_t>(const SharePointer& parent,
                                                        std::size_t output_owner);

SharePointer Backend::GarbledCircuitInput(std::size_t party_id,
                                          std::span<const BitVector<>> input) {
  bool is_garbler =
      communication_layer_->GetMyId() == static_cast<std::size_t>(GarbledCircuitRole::kGarbler);
  namespace gc = proto::garbled_circuit;
  auto scast{[](auto p) { return static_pointer_cast<gc::InputGate>(p); }};
  auto input_gate =
      is_garbler
          ? scast(GetRegister()->EmplaceGate<gc::InputGateGarbler>(input, party_id, *this))
          : scast(GetRegister()->EmplaceGate<gc::InputGateEvaluator>(input, party_id, *this));
  return std::static_pointer_cast<Share>(input_gate->GetOutputAsGarbledCircuitShare());
}

SharePointer Backend::GarbledCircuitInput(std::size_t party_id, std::vector<BitVector<>>&& input) {
  return GarbledCircuitInput(party_id, std::span(input));
}

std::pair<SharePointer, ReusableFiberPromise<std::vector<BitVector<>>>*>
Backend::GarbledCircuitInput(std::size_t input_owner_id, std::size_t number_of_wires,
                             std::size_t number_of_simd) {
  auto input_gate = GetGarbledCircuitProvider().MakeInputGate(input_owner_id, number_of_wires,
                                                              number_of_simd, *this);
  bool my_input{input_owner_id == GetCommunicationLayer().GetMyId()};
  auto input_promise_ptr = my_input ? &input_gate->GetInputPromise() : nullptr;
  return std::pair(std::static_pointer_cast<Share>(input_gate->GetOutputAsGarbledCircuitShare()),
                   input_promise_ptr);
}

SharePointer Backend::GarbledCircuitOutput(const SharePointer& parent, std::size_t output_owner) {
  assert(parent);
  const auto output_gate =
      GetRegister()->EmplaceGate<proto::garbled_circuit::OutputGate>(parent, output_owner);
  return output_gate->GetOutputAsConstantShare();
}

void Backend::Synchronize() { communication_layer_->Synchronize(); }

void Backend::ComputeBaseOts() {
  run_time_statistics_.back().RecordStart<RunTimeStatistics::StatisticsId::kBaseOts>();
  base_ot_provider_->ComputeBaseOts();
  run_time_statistics_.back().RecordEnd<RunTimeStatistics::StatisticsId::kBaseOts>();
}

// TODO: move to OtProviderManager::Setup()
void Backend::OtExtensionSetup() {
  if constexpr (kDebug) {
    logger_->LogDebug("Start computing setup for OTExtensions");
  }

  run_time_statistics_.back().RecordStart<RunTimeStatistics::StatisticsId::kOtExtensionSetup>();

  std::vector<std::future<void>> task_futures;
  task_futures.reserve(2 * (communication_layer_->GetNumberOfParties() - 1));

  for (auto i = 0ull; i < communication_layer_->GetNumberOfParties(); ++i) {
    if (i == communication_layer_->GetMyId()) {
      continue;
    }
    if (ot_provider_manager_->GetProvider(i).HasWork()) {
      task_futures.emplace_back(std::async(
          std::launch::async, [this, i] { ot_provider_manager_->GetProvider(i).SendSetup(); }));
      task_futures.emplace_back(std::async(
          std::launch::async, [this, i] { ot_provider_manager_->GetProvider(i).ReceiveSetup(); }));
    }
    if (kk13_ot_provider_manager_->GetProvider(i).HasWork()) {
      task_futures.emplace_back(std::async(std::launch::async, [this, i] {
        kk13_ot_provider_manager_->GetProvider(i).SendSetup();
      }));
      task_futures.emplace_back(std::async(std::launch::async, [this, i] {
        kk13_ot_provider_manager_->GetProvider(i).ReceiveSetup();
      }));
    }
  }

  for (auto& f : task_futures) f.get();

  run_time_statistics_.back().RecordEnd<RunTimeStatistics::StatisticsId::kOtExtensionSetup>();

  if constexpr (kDebug) {
    logger_->LogDebug("Finished setup for OTExtensions");
  }
}

OtProvider& Backend::GetOtProvider(std::size_t party_id) {
  return ot_provider_manager_->GetProvider(party_id);
}

Kk13OtProvider& Backend::GetKk13OtProvider(std::size_t party_id) {
  return kk13_ot_provider_manager_->GetProvider(party_id);
}

}  // namespace encrypto::motion
