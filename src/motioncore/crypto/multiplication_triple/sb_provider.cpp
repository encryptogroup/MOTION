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

#include <cassert>
#include <memory>
#include <type_traits>
#include "communication/communication_layer.h"
#include "communication/fbs_headers/shared_bits_message_generated.h"
#include "communication/message_handler.h"
#include "communication/shared_bits_message.h"
#include "data_storage/shared_bits_data.h"
#include "sb_impl.h"
#include "sb_provider.h"
#include "sp_provider.h"
#include "statistics/run_time_stats.h"
#include "utility/constants.h"
#include "utility/helpers.h"
#include "utility/logger.h"

namespace MOTION {

bool SBProvider::NeedSBs() const noexcept {
  return num_sbs_8_ + num_sbs_16_ + num_sbs_32_ + num_sbs_64_ > 0;
}

SBProvider::SBProvider(const std::size_t my_id) : my_id_(my_id) {
  finished_condition_ = std::make_shared<ENCRYPTO::FiberCondition>([this]() { return finished_; });
}

class SBMessageHandler : public Communication::MessageHandler {
 public:
  SBMessageHandler(SharedBitsData& data) : data_(data) {}

  // method which is called with received messages of the type the handler is registered for
  void received_message(std::size_t, std::vector<std::uint8_t>&& message);

 private:
  SharedBitsData& data_;
};

void SBMessageHandler::received_message(std::size_t, std::vector<std::uint8_t>&& raw_message) {
  assert(!raw_message.empty());
  auto message = Communication::GetMessage(raw_message.data());
  auto message_type = message->message_type();
  auto sb_msg_payload = Communication::GetSharedBitsMessage(message->payload()->data())->payload();
  switch (message_type) {
    case Communication::MessageType::SharedBitsMask: {
      data_.MessageReceived(SharedBitsMessageType::mask_message, sb_msg_payload->data(),
                            sb_msg_payload->size());
      break;
    }
    case Communication::MessageType::SharedBitsReconstruct: {
      data_.MessageReceived(SharedBitsMessageType::reconstruct_message, sb_msg_payload->data(),
                            sb_msg_payload->size());
      break;
    }
    default: {
      assert(false);
      break;
    }
  }
}

SBProviderFromSPs::SBProviderFromSPs(Communication::CommunicationLayer& communication_layer,
                                     std::shared_ptr<SPProvider> sp_provider, Logger& logger,
                                     Statistics::RunTimeStats& run_time_stats)
    : SBProvider(communication_layer.get_my_id()),
      communication_layer_(communication_layer),
      num_parties_(communication_layer_.get_num_parties()),
      sp_provider_(sp_provider),
      data_(num_parties_),
      logger_(logger),
      run_time_stats_(run_time_stats) {
  // TODO: register message handler
  auto my_id = communication_layer.get_my_id();
  for (std::size_t party_id = 0; party_id < num_parties_; ++party_id) {
    if (party_id == my_id) {
      continue;
    }
    data_.at(party_id) = std::make_unique<SharedBitsData>();
  }
  communication_layer_.register_message_handler(
      [this](std::size_t party_id) {
        return std::make_shared<SBMessageHandler>(*data_.at(party_id));
      },
      {MOTION::Communication::MessageType::SharedBitsMask,
       MOTION::Communication::MessageType::SharedBitsReconstruct});
}

SBProviderFromSPs::~SBProviderFromSPs() {
  // deregister message handler
  communication_layer_.deregister_message_handler(
      {MOTION::Communication::MessageType::SharedBitsMask,
       MOTION::Communication::MessageType::SharedBitsReconstruct});
}

void SBProviderFromSPs::PreSetup() {
  if (!NeedSBs()) {
    return;
  }

  if constexpr (MOTION_DEBUG) {
    logger_.LogDebug("Start computing presetup for SBs");
  }
  run_time_stats_.record_start<Statistics::RunTimeStats::StatID::sb_presetup>();

  RegisterSPs();
  RegisterForMessages();

  run_time_stats_.record_end<Statistics::RunTimeStats::StatID::sb_presetup>();
  if constexpr (MOTION_DEBUG) {
    logger_.LogDebug("Finished computing presetup for SBs");
  }
}

void SBProviderFromSPs::Setup() {
  if (!NeedSBs()) {
    return;
  }

  if constexpr (MOTION_DEBUG) {
    logger_.LogDebug("Start computing setup for SBs");
  }
  run_time_stats_.record_start<Statistics::RunTimeStats::StatID::sb_setup>();

  sp_provider_->WaitFinished();

  ComputeSBs();

  {
    std::scoped_lock lock(finished_condition_->GetMutex());
    finished_ = true;
  }
  finished_condition_->NotifyAll();

  run_time_stats_.record_end<Statistics::RunTimeStats::StatID::sb_setup>();
  if constexpr (MOTION_DEBUG) {
    logger_.LogDebug("Finished computing setup for SBs");
  }
}

void SBProviderFromSPs::RegisterSPs() {
  offset_sps_16_ = sp_provider_->RequestSPs<uint16_t>(num_sbs_8_);
  offset_sps_32_ = sp_provider_->RequestSPs<uint32_t>(num_sbs_16_);
  offset_sps_64_ = sp_provider_->RequestSPs<uint64_t>(num_sbs_32_);
  offset_sps_128_ = sp_provider_->RequestSPs<__uint128_t>(num_sbs_64_);
}

void SBProviderFromSPs::RegisterForMessages() {
  std::size_t expected_msg_size =
      num_sbs_8_ * 2 + num_sbs_16_ * 4 + num_sbs_32_ * 8 + num_sbs_64_ * 16;

  auto num_parties = communication_layer_.get_num_parties();
  reconstruct_message_futures_.reserve(num_parties);
  for (std::size_t i = 0; i < num_parties; ++i) {
    if (i == my_id_) {
      mask_message_futures_.emplace_back();
      reconstruct_message_futures_.emplace_back();
      continue;
    }
    auto& sb_data = *data_.at(i);
    mask_message_futures_.emplace_back(sb_data.RegisterForMaskMessage(expected_msg_size));
    reconstruct_message_futures_.emplace_back(
        sb_data.RegisterForReconstructMessage(expected_msg_size));
  }
}

template <typename T>
static constexpr auto get_byte_size(const std::vector<T>& v) {
  auto size = v.size() * sizeof(typename std::remove_reference_t<decltype(v)>::value_type);
  return size;
}

static std::vector<std::uint8_t> gather(const std::vector<std::uint16_t>& ds_8,
                                        const std::vector<std::uint32_t>& ds_16,
                                        const std::vector<std::uint64_t>& ds_32,
                                        const std::vector<__uint128_t>& ds_64) {
  auto size_8 = get_byte_size(ds_8);
  auto size_16 = get_byte_size(ds_16);
  auto size_32 = get_byte_size(ds_32);
  auto size_64 = get_byte_size(ds_64);

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
static std::vector<std::uint8_t> scatter(std::vector<std::uint16_t>& ds_8,
                                         std::vector<std::uint32_t>& ds_16,
                                         std::vector<std::uint64_t>& ds_32,
                                         std::vector<__uint128_t>& ds_64,
                                         const std::vector<std::uint8_t>& buffer) {
  auto size_8 = get_byte_size(ds_8);
  auto size_16 = get_byte_size(ds_16);
  auto size_32 = get_byte_size(ds_32);
  [[maybe_unused]] auto size_64 = get_byte_size(ds_64);

  assert(buffer.size() == size_8 + size_16 + size_32 + size_64);
  auto start_8 = reinterpret_cast<const std::uint16_t*>(buffer.data());
  auto start_16 = reinterpret_cast<const std::uint32_t*>(buffer.data() + size_8);
  auto start_32 = reinterpret_cast<const std::uint64_t*>(buffer.data() + size_8 + size_16);
  auto start_64 = reinterpret_cast<const __uint128_t*>(buffer.data() + size_8 + size_16 + size_32);
  std::copy(start_8, start_8 + ds_8.size(), ds_8.begin());
  std::copy(start_16, start_16 + ds_16.size(), ds_16.begin());
  std::copy(start_32, start_32 + ds_32.size(), ds_32.begin());
  std::copy(start_64, start_64 + ds_64.size(), ds_64.begin());
  return buffer;
}

// reconstruct all the shared values packed into one message
static void reconstruct_helper(
    std::vector<std::uint16_t>& xs_8, std::vector<std::uint32_t>& xs_16,
    std::vector<std::uint64_t>& xs_32, std::vector<__uint128_t>& xs_64, std::size_t num_parties,
    std::function<void(const std::vector<uint8_t>&)> broadcast_fctn,
    std::vector<ENCRYPTO::ReusableFuture<std::vector<std::uint8_t>>>& futures) {
  // gather all shared in a single buffer
  auto xs = gather(xs_8, xs_16, xs_32, xs_64);

  // prepare buffers to scatter received shares into
  std::vector<std::uint16_t> xs_8_o(xs_8.size());
  std::vector<std::uint32_t> xs_16_o(xs_16.size());
  std::vector<std::uint64_t> xs_32_o(xs_32.size());
  std::vector<__uint128_t> xs_64_o(xs_64.size());

  // broadcast our share
  broadcast_fctn(xs);

  // collect the other shares
  std::vector<std::vector<std::uint8_t>> received_xs;
  received_xs.reserve(num_parties);
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
    scatter(xs_8_o, xs_16_o, xs_32_o, xs_64_o, xs_j);
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

void SBProviderFromSPs::ComputeSBs() noexcept {
  auto sps_16 = sp_provider_->GetSPs<std::uint16_t>(offset_sps_16_, num_sbs_8_);
  auto sps_32 = sp_provider_->GetSPs<std::uint32_t>(offset_sps_32_, num_sbs_16_);
  auto sps_64 = sp_provider_->GetSPs<std::uint64_t>(offset_sps_64_, num_sbs_32_);
  auto sps_128 = sp_provider_->GetSPs<__uint128_t>(offset_sps_128_, num_sbs_64_);

  auto broadcast_mask = [this](const auto& buffer) {
    auto mask_builder = Communication::BuildSharedBitsMaskMessage(buffer);
    communication_layer_.broadcast_message(std::move(mask_builder));
  };

  auto broadcast_reconstruct = [this](const auto& buffer) {
    auto mask_builder = Communication::BuildSharedBitsReconstructMessage(buffer);
    communication_layer_.broadcast_message(std::move(mask_builder));
  };

  auto [wb1_8, wb2_8] = detail::compute_sbs_phase_1<std::uint8_t>(num_sbs_8_, my_id_, sps_16);
  auto [wb1_16, wb2_16] = detail::compute_sbs_phase_1<std::uint16_t>(num_sbs_16_, my_id_, sps_32);
  auto [wb1_32, wb2_32] = detail::compute_sbs_phase_1<std::uint32_t>(num_sbs_32_, my_id_, sps_64);
  auto [wb1_64, wb2_64] = detail::compute_sbs_phase_1<std::uint64_t>(num_sbs_64_, my_id_, sps_128);
  reconstruct_helper(wb2_8, wb2_16, wb2_32, wb2_64, num_parties_, broadcast_mask,
                     mask_message_futures_);
  detail::compute_sbs_phase_2<std::uint8_t>(wb1_8, wb2_8, my_id_, sps_16);
  detail::compute_sbs_phase_2<std::uint16_t>(wb1_16, wb2_16, my_id_, sps_32);
  detail::compute_sbs_phase_2<std::uint32_t>(wb1_32, wb2_32, my_id_, sps_64);
  detail::compute_sbs_phase_2<std::uint64_t>(wb1_64, wb2_64, my_id_, sps_128);
  reconstruct_helper(wb2_8, wb2_16, wb2_32, wb2_64, num_parties_, broadcast_reconstruct,
                     reconstruct_message_futures_);
  detail::compute_sbs_phase_3<std::uint8_t>(wb1_8, wb2_8, sbs_8_, my_id_);
  detail::compute_sbs_phase_3<std::uint16_t>(wb1_16, wb2_16, sbs_16_, my_id_);
  detail::compute_sbs_phase_3<std::uint32_t>(wb1_32, wb2_32, sbs_32_, my_id_);
  detail::compute_sbs_phase_3<std::uint64_t>(wb1_64, wb2_64, sbs_64_, my_id_);
}

}  // namespace MOTION
