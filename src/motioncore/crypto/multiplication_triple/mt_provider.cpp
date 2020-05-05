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

#include "mt_provider.h"

#include "crypto/oblivious_transfer/ot_flavors.h"
#include "statistics/run_time_stats.h"
#include "utility/constants.h"
#include "utility/logger.h"

namespace MOTION {

bool MTProvider::NeedMTs() const noexcept {
  return (GetNumMTs<bool>() + GetNumMTs<std::uint8_t>() + GetNumMTs<std::uint16_t>() +
          GetNumMTs<std::uint32_t>() + GetNumMTs<std::uint64_t>()) > 0;
}

std::size_t MTProvider::RequestBinaryMTs(const std::size_t num_mts) noexcept {
  const auto offset = num_bit_mts_;
  num_bit_mts_ += num_mts;
  return offset;
}

// get bits [i, i+n] as vector
BinaryMTVector MTProvider::GetBinary(const std::size_t offset, const std::size_t n) const {
  assert(bit_mts_.a.GetSize() == bit_mts_.b.GetSize());
  assert(bit_mts_.b.GetSize() == bit_mts_.c.GetSize());
  WaitFinished();
  return BinaryMTVector{bit_mts_.a.Subset(offset, offset + n),
                        bit_mts_.b.Subset(offset, offset + n),
                        bit_mts_.c.Subset(offset, offset + n)};
}

const BinaryMTVector& MTProvider::GetBinaryAll() const noexcept {
  WaitFinished();
  return bit_mts_;
}

MTProvider::MTProvider(const std::size_t my_id, const std::size_t num_parties)
    : my_id_(my_id), num_parties_(num_parties) {
  finished_condition_ =
      std::make_shared<ENCRYPTO::FiberCondition>([this]() { return finished_.load(); });
}

MTProviderFromOTs::MTProviderFromOTs(
    std::vector<std::unique_ptr<ENCRYPTO::ObliviousTransfer::OTProvider>>& ot_providers,
    const std::size_t my_id, Logger& logger, Statistics::RunTimeStats& run_time_stats)
    : MTProvider(my_id, ot_providers.size()),
      ot_providers_(ot_providers),
      ots_rcv_(num_parties_),
      ots_snd_(num_parties_),
      bit_ots_rcv_(num_parties_),
      bit_ots_snd_(num_parties_),
      logger_(logger),
      run_time_stats_(run_time_stats) {}

MTProviderFromOTs::~MTProviderFromOTs() = default;

void MTProviderFromOTs::PreSetup() {
  if (!NeedMTs()) {
    return;
  }

  if constexpr (MOTION_DEBUG) {
    logger_.LogDebug("Start computing presetup for MTs");
  }
  run_time_stats_.record_start<Statistics::RunTimeStats::StatID::mt_presetup>();

  RegisterOTs();

  run_time_stats_.record_end<Statistics::RunTimeStats::StatID::mt_presetup>();
  if constexpr (MOTION_DEBUG) {
    logger_.LogDebug("Finished computing presetup for MTs");
  }
}

// needs completed OTExtension
void MTProviderFromOTs::Setup() {
  if (!NeedMTs()) {
    return;
  }

  if constexpr (MOTION_DEBUG) {
    logger_.LogDebug("Start computing setup for MTs");
  }
  run_time_stats_.record_start<Statistics::RunTimeStats::StatID::mt_setup>();

#pragma omp parallel for
  for (auto i = 0ull; i < num_parties_; ++i) {
    if (i == my_id_) {
      continue;
    }
    for (auto& ot : ots_snd_.at(i)) {
      ot->SendMessages();
    }
    for (auto& ot : ots_rcv_.at(i)) {
      ot->SendCorrections();
    }
    if (num_bit_mts_ > 0) {
      assert(bit_ots_rcv_.at(i) != nullptr);
      assert(bit_ots_snd_.at(i) != nullptr);
      bit_ots_rcv_.at(i)->SendCorrections();
      bit_ots_snd_.at(i)->SendMessages();
    }
  }
  ParseOutputs();
  {
    std::scoped_lock lock(finished_condition_->GetMutex());
    finished_ = true;
  }
  finished_condition_->NotifyAll();

  run_time_stats_.record_end<Statistics::RunTimeStats::StatID::mt_setup>();
  if constexpr (MOTION_DEBUG) {
    logger_.LogDebug("Finished computing setup for MTs");
  }
}

static void generate_random_triples_bool(BinaryMTVector& bit_mts, std::size_t num_bit_mts) {
  if (num_bit_mts > 0u) {
    bit_mts.a = ENCRYPTO::BitVector<>::Random(num_bit_mts);
    bit_mts.b = ENCRYPTO::BitVector<>::Random(num_bit_mts);
    bit_mts.c = bit_mts.a & bit_mts.b;
  }
}

template <typename T>
static void generate_random_triples(IntegerMTVector<T>& mts, std::size_t num_mts) {
  if (num_mts > 0u) {
    mts.a = Helpers::RandomVector<T>(num_mts);
    mts.b = Helpers::RandomVector<T>(num_mts);
    mts.c.resize(num_mts);
    std::transform(mts.a.cbegin(), mts.a.cend(), mts.b.cbegin(), mts.c.begin(),
                   [](const auto& a_i, const auto& b_i) { return a_i * b_i; });
  }
}

static void register_helper_bool(
    ENCRYPTO::ObliviousTransfer::OTProvider& ot_provider,
    std::unique_ptr<ENCRYPTO::ObliviousTransfer::XCOTBitSender>& ots_snd,
    std::unique_ptr<ENCRYPTO::ObliviousTransfer::XCOTBitReceiver>& ots_rcv,
    const BinaryMTVector& bit_mts, std::size_t num_bit_mts) {
  ots_snd = ot_provider.RegisterSendXCOTBit(num_bit_mts);
  ots_rcv = ot_provider.RegisterReceiveXCOTBit(num_bit_mts);

  ots_snd->SetCorrelations(bit_mts.a);
  ots_rcv->SetChoices(bit_mts.b);
}

template <typename T>
static void register_helper(
    ENCRYPTO::ObliviousTransfer::OTProvider& ot_provider,
    std::list<std::shared_ptr<ENCRYPTO::ObliviousTransfer::OTVectorSender>>& ots_snd,
    std::list<std::shared_ptr<ENCRYPTO::ObliviousTransfer::OTVectorReceiver>>& ots_rcv,
    std::size_t max_batch_size, const IntegerMTVector<T>& mts, std::size_t num_mts) {
  constexpr std::size_t bit_size = sizeof(T) * 8;
  constexpr auto ACOT = ENCRYPTO::ObliviousTransfer::OTProtocol::ACOT;

  for (std::size_t mt_id = 0; mt_id < num_mts;) {
    const auto batch_size = std::min(max_batch_size, num_mts - mt_id);
    auto ot_s = ot_provider.RegisterSend(bit_size, batch_size * bit_size, ACOT);
    std::vector<ENCRYPTO::BitVector<>> v_s;
    v_s.reserve(batch_size);
    for (auto k = 0ull; k < batch_size; ++k) {
      for (auto bit_i = 0u; bit_i < bit_size; ++bit_i) {
        const T input = mts.a.at(mt_id + k) << bit_i;
        v_s.emplace_back(reinterpret_cast<const std::byte*>(&input), bit_size);
      }
    }
    ot_s->SetInputs(std::move(v_s));

    auto ot_r = ot_provider.RegisterReceive(bit_size, batch_size * bit_size, ACOT);
    ENCRYPTO::BitVector<> choices;
    choices.Reserve(Helpers::Convert::BitsToBytes(batch_size * bit_size));
    for (auto k = 0ull; k < batch_size; ++k) {
      for (auto bit_i = 0u; bit_i < bit_size; ++bit_i) {
        const bool choice = ((mts.b.at(mt_id + k) >> bit_i) & 1u) == 1;
        choices.Append(choice);
      }
    }
    ot_r->SetChoices(std::move(choices));

    ots_snd.emplace_back(std::move(ot_s));
    ots_rcv.emplace_back(std::move(ot_r));

    mt_id += batch_size;
  }
}

void MTProviderFromOTs::RegisterOTs() {
  if (num_bit_mts_ > 0) {
    generate_random_triples_bool(bit_mts_, num_bit_mts_);
  }
  generate_random_triples<std::uint8_t>(mts8_, num_mts_8_);
  generate_random_triples<std::uint16_t>(mts16_, num_mts_16_);
  generate_random_triples<std::uint32_t>(mts32_, num_mts_32_);
  generate_random_triples<std::uint64_t>(mts64_, num_mts_64_);

#pragma omp parallel for num_threads(num_parties_)
  for (auto i = 0ull; i < num_parties_; ++i) {
    if (i == my_id_) {
      continue;
    }

    if (num_bit_mts_ > 0) {
      register_helper_bool(*ot_providers_.at(i), bit_ots_snd_.at(i), bit_ots_rcv_.at(i), bit_mts_,
                           num_bit_mts_);
    }
    register_helper<std::uint8_t>(*ot_providers_.at(i), ots_snd_.at(i), ots_rcv_.at(i),
                                  max_batch_size_, mts8_, num_mts_8_);
    register_helper<std::uint16_t>(*ot_providers_.at(i), ots_snd_.at(i), ots_rcv_.at(i),
                                   max_batch_size_, mts16_, num_mts_16_);
    register_helper<std::uint32_t>(*ot_providers_.at(i), ots_snd_.at(i), ots_rcv_.at(i),
                                   max_batch_size_, mts32_, num_mts_32_);
    register_helper<std::uint64_t>(*ot_providers_.at(i), ots_snd_.at(i), ots_rcv_.at(i),
                                   max_batch_size_, mts64_, num_mts_64_);
  }
}

static void parse_helper_bool(
    std::unique_ptr<ENCRYPTO::ObliviousTransfer::XCOTBitSender>& ots_snd,
    std::unique_ptr<ENCRYPTO::ObliviousTransfer::XCOTBitReceiver>& ots_rcv,
    BinaryMTVector& bit_mts) {
  ots_snd->ComputeOutputs();
  ots_rcv->ComputeOutputs();
  const auto& out_s = ots_snd->GetOutputs();
  const auto& out_r = ots_rcv->GetOutputs();
  bit_mts.c ^= out_s;
  bit_mts.c ^= out_r;
}

template <typename T>
static void parse_helper(
    std::list<std::shared_ptr<ENCRYPTO::ObliviousTransfer::OTVectorSender>>& ots_snd,
    std::list<std::shared_ptr<ENCRYPTO::ObliviousTransfer::OTVectorReceiver>>& ots_rcv,
    std::size_t max_batch_size, IntegerMTVector<T>& mts, std::size_t num_mts) {
  constexpr std::size_t bit_size = sizeof(T) * 8;

  for (std::size_t mt_id = 0; mt_id < num_mts;) {
    const auto batch_size = std::min(max_batch_size, num_mts - mt_id);
    const auto& ot_s = ots_snd.front();
    const auto& ot_r = ots_rcv.front();
    const auto& out_s = ot_s->GetOutputs();
    const auto& out_r = ot_r->GetOutputs();
    for (auto j = 0ull; j < batch_size; ++j) {
      for (auto bit_i = 0u; bit_i < bit_size; ++bit_i) {
        mts.c.at(mt_id + j) += *reinterpret_cast<const T* __restrict__>(
                                   out_r.at(j * bit_size + bit_i).GetData().data()) -
                               *reinterpret_cast<const T* __restrict__>(
                                   out_s.at(j * bit_size + bit_i).GetData().data());
      }
    }
    ots_snd.pop_front();
    ots_rcv.pop_front();
    mt_id += batch_size;
  }
}

void MTProviderFromOTs::ParseOutputs() {
  for (auto i = 0ull; i < num_parties_; ++i) {
    if (i == my_id_) {
      continue;
    }

    if (num_bit_mts_ > 0) {
      parse_helper_bool(bit_ots_snd_.at(i), bit_ots_rcv_.at(i), bit_mts_);
    }
    parse_helper<std::uint8_t>(ots_snd_.at(i), ots_rcv_.at(i), max_batch_size_, mts8_, num_mts_8_);
    parse_helper<std::uint16_t>(ots_snd_.at(i), ots_rcv_.at(i), max_batch_size_, mts16_,
                                num_mts_16_);
    parse_helper<std::uint32_t>(ots_snd_.at(i), ots_rcv_.at(i), max_batch_size_, mts32_,
                                num_mts_32_);
    parse_helper<std::uint64_t>(ots_snd_.at(i), ots_rcv_.at(i), max_batch_size_, mts64_,
                                num_mts_64_);

    assert(ots_snd_.at(i).empty());
    assert(ots_rcv_.at(i).empty());
  }
}
}  // namespace MOTION
