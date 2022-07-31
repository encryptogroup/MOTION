// MIT License
//
// Copyright (c) 2019 Lennart Braun
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

#include "sb_provider.h"

#include <cassert>
#include <memory>
#include <type_traits>

#include "communication/communication_layer.h"
#include "communication/message.h"
#include "sb_impl.h"
#include "sp_provider.h"
#include "statistics/run_time_statistics.h"
#include "utility/constants.h"
#include "utility/helpers.h"
#include "utility/logger.h"

namespace encrypto::motion {

bool SbProvider::NeedSbs() const noexcept {
  return 0 < number_of_sbs_8_ + number_of_sbs_16_ + number_of_sbs_32_ + number_of_sbs_64_;
}

SbProvider::SbProvider(const std::size_t my_id) : my_id_(my_id) {
  finished_condition_ = std::make_shared<FiberCondition>([this]() { return finished_; });
}

SbProviderFromSps::SbProviderFromSps(communication::CommunicationLayer& communication_layer,
                                     std::shared_ptr<SpProvider> sp_provider,
                                     std::shared_ptr<Logger> logger,
                                     RunTimeStatistics& run_time_statistics)
    : SbProvider(communication_layer.GetMyId()),
      communication_layer_(communication_layer),
      number_of_parties_(communication_layer_.GetNumberOfParties()),
      sp_provider_(sp_provider),
      logger_(logger),
      run_time_statistics_(run_time_statistics) {}

SbProviderFromSps::~SbProviderFromSps() {}

void SbProviderFromSps::PreSetup() {
  if (!NeedSbs()) {
    return;
  }

  if constexpr (kDebug) {
    logger_->LogDebug("Start computing presetup for SBs");
  }
  run_time_statistics_.RecordStart<RunTimeStatistics::StatisticsId::kSbPresetup>();

  RegisterSps();
  RegisterForMessages();

  run_time_statistics_.RecordEnd<RunTimeStatistics::StatisticsId::kSbPresetup>();
  if constexpr (kDebug) {
    logger_->LogDebug("Finished computing presetup for SBs");
  }
}

void SbProviderFromSps::Setup() {
  if (!NeedSbs()) {
    return;
  }

  if constexpr (kDebug) {
    logger_->LogDebug("Start computing setup for SBs");
  }
  run_time_statistics_.RecordStart<RunTimeStatistics::StatisticsId::kSbSetup>();

  sp_provider_->WaitFinished();

  ComputeSbs();

  {
    std::scoped_lock lock(finished_condition_->GetMutex());
    finished_ = true;
  }
  finished_condition_->NotifyAll();

  run_time_statistics_.RecordEnd<RunTimeStatistics::StatisticsId::kSbSetup>();
  if constexpr (kDebug) {
    logger_->LogDebug("Finished computing setup for SBs");
  }
}

void SbProviderFromSps::RegisterSps() {
  offset_sps_16_ = sp_provider_->RequestSps<uint16_t>(number_of_sbs_8_);
  offset_sps_32_ = sp_provider_->RequestSps<uint32_t>(number_of_sbs_16_);
  offset_sps_64_ = sp_provider_->RequestSps<uint64_t>(number_of_sbs_32_);
  offset_sps_128_ = sp_provider_->RequestSps<__uint128_t>(number_of_sbs_64_);
}

void SbProviderFromSps::RegisterForMessages() {
  mask_message_futures_ = communication_layer_.GetMessageManager().RegisterReceiveAll(
      communication::MessageType::kSharedBitsMask, 0);
  reconstruct_message_futures_ = communication_layer_.GetMessageManager().RegisterReceiveAll(
      communication::MessageType::kSharedBitsReconstruct, 0);
}

template <typename T>
static constexpr auto GetByteSize(const std::vector<T>& v) {
  auto size = v.size() * sizeof(typename std::remove_reference_t<decltype(v)>::value_type);
  return size;
}

static std::vector<std::uint8_t> Gather(const std::vector<std::uint16_t>& ds_8,
                                        const std::vector<std::uint32_t>& ds_16,
                                        const std::vector<std::uint64_t>& ds_32,
                                        const std::vector<__uint128_t>& ds_64) {
  auto size_8 = GetByteSize(ds_8);
  auto size_16 = GetByteSize(ds_16);
  auto size_32 = GetByteSize(ds_32);
  auto size_64 = GetByteSize(ds_64);

  std::vector<std::uint8_t> buffer(size_8 + size_16 + size_32 + size_64);
  auto start_8 = reinterpret_cast<std::uint16_t*>(buffer.data());
  auto start_16 = reinterpret_cast<std::uint32_t*>(buffer.data() + size_8);
  auto start_32 = reinterpret_cast<std::uint64_t*>(buffer.data() + size_8 + size_16);
  auto start_64 = reinterpret_cast<__uint128_t*>(buffer.data() + size_8 + size_16 + size_32);
  std::copy(ds_8.cbegin(), ds_8.cend(), start_8);
  std::copy(ds_16.cbegin(), ds_16.cend(), start_16);
  std::copy(ds_32.cbegin(), ds_32.cend(), start_32);
  std::copy(ds_64.cbegin(), ds_64.cend(), start_64);
  return buffer;
}

static std::vector<std::uint8_t> Scatter(std::vector<std::uint16_t>& ds_8,
                                         std::vector<std::uint32_t>& ds_16,
                                         std::vector<std::uint64_t>& ds_32,
                                         std::vector<__uint128_t>& ds_64,
                                         const std::vector<std::uint8_t>& buffer) {
  auto size_8 = GetByteSize(ds_8);
  auto size_16 = GetByteSize(ds_16);
  auto size_32 = GetByteSize(ds_32);
  [[maybe_unused]] auto size_64 = GetByteSize(ds_64);

  assert(communication::GetMessage(buffer.data())->payload()->size() ==
         size_8 + size_16 + size_32 + size_64);

  const std::uint8_t* pointer{communication::GetMessage(buffer.data())->payload()->data()};

  auto start_8 = reinterpret_cast<const std::uint16_t*>(pointer);
  auto start_16 = reinterpret_cast<const std::uint32_t*>(pointer + size_8);
  auto start_32 = reinterpret_cast<const std::uint64_t*>(pointer + size_8 + size_16);
  auto start_64 = reinterpret_cast<const __uint128_t*>(pointer + size_8 + size_16 + size_32);
  std::copy(start_8, start_8 + ds_8.size(), ds_8.begin());
  std::copy(start_16, start_16 + ds_16.size(), ds_16.begin());
  std::copy(start_32, start_32 + ds_32.size(), ds_32.begin());
  std::copy(start_64, start_64 + ds_64.size(), ds_64.begin());
  return buffer;
}

// reconstruct all the shared values packed into one message
static void ReconstructionHelper(
    std::vector<std::uint16_t>& xs_8, std::vector<std::uint32_t>& xs_16,
    std::vector<std::uint64_t>& xs_32, std::vector<__uint128_t>& xs_64,
    std::size_t number_of_parties,
    std::function<void(const std::vector<uint8_t>&)> broadcast_function,
    std::vector<ReusableFiberFuture<std::vector<std::uint8_t>>>& futures) {
  // Gather all shared in a single buffer
  auto xs = Gather(xs_8, xs_16, xs_32, xs_64);

  // prepare buffers to Scatter received shares into
  std::vector<std::uint16_t> xs_8_o(xs_8.size());
  std::vector<std::uint32_t> xs_16_o(xs_16.size());
  std::vector<std::uint64_t> xs_32_o(xs_32.size());
  std::vector<__uint128_t> xs_64_o(xs_64.size());

  // broadcast our share
  broadcast_function(xs);

  // collect the other shares
  std::vector<std::vector<std::uint8_t>> received_xs;
  received_xs.reserve(number_of_parties - 1);
  std::transform(futures.begin(), futures.end(), std::back_inserter(received_xs), [](auto& f) {
    if (f.valid())
      return f.get();
    else
      return std::vector<std::uint8_t>();
  });

  // reconstruct the xs
  for (auto& xs_j : received_xs) {
    if (xs_j.empty()) {
      continue;
    }
    Scatter(xs_8_o, xs_16_o, xs_32_o, xs_64_o, xs_j);
    std::transform(xs_8_o.cbegin(), xs_8_o.cend(), xs_8.cbegin(), xs_8.begin(),
                   [](auto a_j, auto a_i) { return a_j + a_i; });
    std::transform(xs_16_o.cbegin(), xs_16_o.cend(), xs_16.cbegin(), xs_16.begin(),
                   [](auto a_j, auto a_i) { return a_j + a_i; });
    std::transform(xs_32_o.cbegin(), xs_32_o.cend(), xs_32.cbegin(), xs_32.begin(),
                   [](auto a_j, auto a_i) { return a_j + a_i; });
    std::transform(xs_64_o.cbegin(), xs_64_o.cend(), xs_64.cbegin(), xs_64.begin(),
                   [](auto a_j, auto a_i) { return a_j + a_i; });
  }

  // now ds_.. contain the reconstructed ds (unreduced)
}

void SbProviderFromSps::ComputeSbs() noexcept {
  auto sps_16 = sp_provider_->GetSps<std::uint16_t>(offset_sps_16_, number_of_sbs_8_);
  auto sps_32 = sp_provider_->GetSps<std::uint32_t>(offset_sps_32_, number_of_sbs_16_);
  auto sps_64 = sp_provider_->GetSps<std::uint64_t>(offset_sps_64_, number_of_sbs_32_);
  auto sps_128 = sp_provider_->GetSps<__uint128_t>(offset_sps_128_, number_of_sbs_64_);

  auto broadcast_mask = [this](const auto& buffer) {
    auto msg{communication::BuildMessage(communication::MessageType::kSharedBitsMask, buffer)};
    communication_layer_.BroadcastMessage(msg.Release());
  };

  auto broadcast_reconstruct = [this](const auto& buffer) {
    auto msg{
        communication::BuildMessage(communication::MessageType::kSharedBitsReconstruct, buffer)};
    communication_layer_.BroadcastMessage(msg.Release());
  };

  auto [wb1_8, wb2_8] = detail::compute_sbs_phase_1<std::uint8_t>(number_of_sbs_8_, my_id_, sps_16);
  auto [wb1_16, wb2_16] =
      detail::compute_sbs_phase_1<std::uint16_t>(number_of_sbs_16_, my_id_, sps_32);
  auto [wb1_32, wb2_32] =
      detail::compute_sbs_phase_1<std::uint32_t>(number_of_sbs_32_, my_id_, sps_64);
  auto [wb1_64, wb2_64] =
      detail::compute_sbs_phase_1<std::uint64_t>(number_of_sbs_64_, my_id_, sps_128);
  ReconstructionHelper(wb2_8, wb2_16, wb2_32, wb2_64, number_of_parties_, broadcast_mask,
                       mask_message_futures_);
  detail::compute_sbs_phase_2<std::uint8_t>(wb1_8, wb2_8, my_id_, sps_16);
  detail::compute_sbs_phase_2<std::uint16_t>(wb1_16, wb2_16, my_id_, sps_32);
  detail::compute_sbs_phase_2<std::uint32_t>(wb1_32, wb2_32, my_id_, sps_64);
  detail::compute_sbs_phase_2<std::uint64_t>(wb1_64, wb2_64, my_id_, sps_128);
  ReconstructionHelper(wb2_8, wb2_16, wb2_32, wb2_64, number_of_parties_, broadcast_reconstruct,
                       reconstruct_message_futures_);
  detail::compute_sbs_phase_3<std::uint8_t>(wb1_8, wb2_8, sbs_8_, my_id_);
  detail::compute_sbs_phase_3<std::uint16_t>(wb1_16, wb2_16, sbs_16_, my_id_);
  detail::compute_sbs_phase_3<std::uint32_t>(wb1_32, wb2_32, sbs_32_, my_id_);
  detail::compute_sbs_phase_3<std::uint64_t>(wb1_64, wb2_64, sbs_64_, my_id_);
}

}  // namespace encrypto::motion
