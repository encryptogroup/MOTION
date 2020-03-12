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

#include "crypto/oblivious_transfer/ot_provider.h"
#include "sp_provider.h"
#include "statistics/run_time_stats.h"
#include "utility/constants.h"
#include "utility/logger.h"

namespace MOTION {

bool SPProvider::NeedSPs() const noexcept {
  return num_sps_8_ + num_sps_16_ + num_sps_32_ + num_sps_64_ + num_sps_128_ > 0;
}

SPProvider::SPProvider(const std::size_t my_id) : my_id_(my_id) {
  finished_condition_ = std::make_shared<ENCRYPTO::FiberCondition>([this]() { return finished_; });
}

SPProviderFromOTs::SPProviderFromOTs(
    std::vector<std::unique_ptr<ENCRYPTO::ObliviousTransfer::OTProvider>>& ot_providers,
    const std::size_t my_id, Logger& logger, Statistics::RunTimeStats& run_time_stats)
    : SPProvider(my_id),
      ot_providers_(ot_providers),
      ots_rcv_(ot_providers_.size()),
      ots_snd_(ot_providers_.size()),
      logger_(logger),
      run_time_stats_(run_time_stats) {}

void SPProviderFromOTs::PreSetup() {
  if (!NeedSPs()) {
    return;
  }

  if constexpr (MOTION_DEBUG) {
    logger_.LogDebug("Start computing presetup for SPs");
  }
  run_time_stats_.record_start<Statistics::RunTimeStats::StatID::sp_presetup>();

  RegisterOTs();

  run_time_stats_.record_end<Statistics::RunTimeStats::StatID::sp_presetup>();
  if constexpr (MOTION_DEBUG) {
    logger_.LogDebug("Finished computing presetup for SPs");
  }
}

void SPProviderFromOTs::Setup() {
  if (!NeedSPs()) {
    return;
  }

  if constexpr (MOTION_DEBUG) {
    logger_.LogDebug("Start computing setup for SPs");
  }
  run_time_stats_.record_start<Statistics::RunTimeStats::StatID::sp_setup>();

#pragma omp parallel for
  for (auto i = 0ull; i < ot_providers_.size(); ++i) {
    if (i == my_id_) {
      continue;
    }
    for (auto& ot : ots_snd_.at(i)) {
      ot->SendMessages();
    }
    for (auto& ot : ots_rcv_.at(i)) {
      ot->SendCorrections();
    }
  }
  ParseOutputs();
  {
    std::scoped_lock lock(finished_condition_->GetMutex());
    finished_ = true;
  }
  finished_condition_->NotifyAll();

  run_time_stats_.record_end<Statistics::RunTimeStats::StatID::sp_setup>();
  if constexpr (MOTION_DEBUG) {
    logger_.LogDebug("Finished computing setup for SPs");
  }
}

template <typename T>
static void generate_random_pairs(SPVector<T>& sps, std::size_t num_sps) {
  if (num_sps > 0u) {
    sps.a = Helpers::RandomVector<T>(num_sps);
    sps.c.resize(num_sps);
    std::transform(sps.a.cbegin(), sps.a.cend(), sps.c.begin(),
                   [](const auto& a_i) { return a_i * a_i; });
  }
}

template <typename T>
static void register_helper_send(
    ENCRYPTO::ObliviousTransfer::OTProvider& ot_provider,
    std::list<std::shared_ptr<ENCRYPTO::ObliviousTransfer::OTVectorSender>>& ots_snd,
    std::size_t max_batch_size, const SPVector<T>& sps, std::size_t num_sps) {
  constexpr std::size_t bit_size = sizeof(T) * 8;
  constexpr auto ACOT = ENCRYPTO::ObliviousTransfer::OTProtocol::ACOT;

  for (std::size_t sp_id = 0; sp_id < num_sps;) {
    const auto batch_size = std::min(max_batch_size, num_sps - sp_id);
    auto ot_s = ot_provider.RegisterSend(bit_size, batch_size * bit_size, ACOT);
    std::vector<ENCRYPTO::BitVector<>> v_s;
    for (auto k = 0ull; k < batch_size; ++k) {
      for (auto bit_i = 0u; bit_i < bit_size; ++bit_i) {
        const T input = sps.a.at(sp_id + k) << bit_i;
        v_s.emplace_back(reinterpret_cast<const std::byte*>(&input), bit_size);
      }
    }
    ot_s->SetInputs(std::move(v_s));
    ots_snd.emplace_back(std::move(ot_s));
    sp_id += batch_size;
  }
}

template <typename T>
static void register_helper_recv(
    ENCRYPTO::ObliviousTransfer::OTProvider& ot_provider,
    std::list<std::shared_ptr<ENCRYPTO::ObliviousTransfer::OTVectorReceiver>>& ots_rcv,
    std::size_t max_batch_size, const SPVector<T>& sps, std::size_t num_sps) {
  constexpr std::size_t bit_size = sizeof(T) * 8;
  constexpr auto ACOT = ENCRYPTO::ObliviousTransfer::OTProtocol::ACOT;

  for (std::size_t sp_id = 0; sp_id < num_sps;) {
    const auto batch_size = std::min(max_batch_size, num_sps - sp_id);
    auto ot_r = ot_provider.RegisterReceive(bit_size, batch_size * bit_size, ACOT);
    ENCRYPTO::BitVector<> choices;
    for (auto k = 0ull; k < batch_size; ++k) {
      for (auto bit_i = 0u; bit_i < bit_size; ++bit_i) {
        const bool choice = ((sps.a.at(sp_id + k) >> bit_i) & 1u) == 1;
        choices.Append(choice);
      }
    }
    ot_r->SetChoices(std::move(choices));
    ots_rcv.emplace_back(std::move(ot_r));
    sp_id += batch_size;
  }
}

void SPProviderFromOTs::RegisterOTs() {
  generate_random_pairs<std::uint8_t>(sps_8_, num_sps_8_);
  generate_random_pairs<std::uint16_t>(sps_16_, num_sps_16_);
  generate_random_pairs<std::uint32_t>(sps_32_, num_sps_32_);
  generate_random_pairs<std::uint64_t>(sps_64_, num_sps_64_);
  generate_random_pairs<__uint128_t>(sps_128_, num_sps_128_);

#pragma omp parallel for num_threads(ot_providers_.size())
  for (std::size_t i = 0; i < ot_providers_.size(); ++i) {
    if (i == my_id_) {
      continue;
    }

    if (i < my_id_) {
      register_helper_send<std::uint8_t>(*ot_providers_.at(i), ots_snd_.at(i), max_batch_size_,
                                         sps_8_, num_sps_8_);
      register_helper_send<std::uint16_t>(*ot_providers_.at(i), ots_snd_.at(i), max_batch_size_,
                                          sps_16_, num_sps_16_);
      register_helper_send<std::uint32_t>(*ot_providers_.at(i), ots_snd_.at(i), max_batch_size_,
                                          sps_32_, num_sps_32_);
      register_helper_send<std::uint64_t>(*ot_providers_.at(i), ots_snd_.at(i), max_batch_size_,
                                          sps_64_, num_sps_64_);
      register_helper_send<__uint128_t>(*ot_providers_.at(i), ots_snd_.at(i), max_batch_size_,
                                          sps_128_, num_sps_128_);
    } else if (i > my_id_) {
      register_helper_recv<std::uint8_t>(*ot_providers_.at(i), ots_rcv_.at(i), max_batch_size_,
                                         sps_8_, num_sps_8_);
      register_helper_recv<std::uint16_t>(*ot_providers_.at(i), ots_rcv_.at(i), max_batch_size_,
                                          sps_16_, num_sps_16_);
      register_helper_recv<std::uint32_t>(*ot_providers_.at(i), ots_rcv_.at(i), max_batch_size_,
                                          sps_32_, num_sps_32_);
      register_helper_recv<std::uint64_t>(*ot_providers_.at(i), ots_rcv_.at(i), max_batch_size_,
                                          sps_64_, num_sps_64_);
      register_helper_recv<__uint128_t>(*ot_providers_.at(i), ots_rcv_.at(i), max_batch_size_,
                                          sps_128_, num_sps_128_);
    }
  }
}

template <typename T>
static void parse_helper_send(
    std::list<std::shared_ptr<ENCRYPTO::ObliviousTransfer::OTVectorSender>>& ots_snd,
    std::size_t max_batch_size, SPVector<T>& sps, std::size_t num_sps) {
  constexpr std::size_t bit_size = sizeof(T) * 8;

  for (std::size_t sp_id = 0; sp_id < num_sps;) {
    const auto batch_size = std::min(max_batch_size, num_sps - sp_id);
    const auto& ot_s = ots_snd.front();
    const auto& out_s = ot_s->GetOutputs();
    for (auto j = 0ull; j < batch_size; ++j) {
      for (auto bit_i = 0u; bit_i < bit_size; ++bit_i) {
        sps.c.at(sp_id + j) -=
            2 * *reinterpret_cast<const T*>(out_s.at(j * bit_size + bit_i).GetData().data());
      }
    }
    ots_snd.pop_front();
    sp_id += batch_size;
  }
}

template <typename T>
static void parse_helper_recv(
    std::list<std::shared_ptr<ENCRYPTO::ObliviousTransfer::OTVectorReceiver>>& ots_rcv,
    std::size_t max_batch_size, SPVector<T>& sps, std::size_t num_sps) {
  constexpr std::size_t bit_size = sizeof(T) * 8;

  for (std::size_t sp_id = 0; sp_id < num_sps;) {
    const auto batch_size = std::min(max_batch_size, num_sps - sp_id);
    const auto& ot_r = ots_rcv.front();
    const auto& out_r = ot_r->GetOutputs();
    for (auto j = 0ull; j < batch_size; ++j) {
      for (auto bit_i = 0u; bit_i < bit_size; ++bit_i) {
        sps.c.at(sp_id + j) +=
            2 * *reinterpret_cast<const T*>(out_r.at(j * bit_size + bit_i).GetData().data());
      }
    }
    ots_rcv.pop_front();
    sp_id += batch_size;
  }
}

void SPProviderFromOTs::ParseOutputs() {
  for (std::size_t i = 0; i < ot_providers_.size(); ++i) {
    if (i == my_id_) {
      continue;
    }

    if (i < my_id_) {
      parse_helper_send<std::uint8_t>(ots_snd_.at(i), max_batch_size_, sps_8_, num_sps_8_);
      parse_helper_send<std::uint16_t>(ots_snd_.at(i), max_batch_size_, sps_16_, num_sps_16_);
      parse_helper_send<std::uint32_t>(ots_snd_.at(i), max_batch_size_, sps_32_, num_sps_32_);
      parse_helper_send<std::uint64_t>(ots_snd_.at(i), max_batch_size_, sps_64_, num_sps_64_);
      parse_helper_send<__uint128_t>(ots_snd_.at(i), max_batch_size_, sps_128_, num_sps_128_);
    } else if (i > my_id_) {
      parse_helper_recv<std::uint8_t>(ots_rcv_.at(i), max_batch_size_, sps_8_, num_sps_8_);
      parse_helper_recv<std::uint16_t>(ots_rcv_.at(i), max_batch_size_, sps_16_, num_sps_16_);
      parse_helper_recv<std::uint32_t>(ots_rcv_.at(i), max_batch_size_, sps_32_, num_sps_32_);
      parse_helper_recv<std::uint64_t>(ots_rcv_.at(i), max_batch_size_, sps_64_, num_sps_64_);
      parse_helper_recv<__uint128_t>(ots_rcv_.at(i), max_batch_size_, sps_128_, num_sps_128_);
    }
  }
}

}  // namespace MOTION
