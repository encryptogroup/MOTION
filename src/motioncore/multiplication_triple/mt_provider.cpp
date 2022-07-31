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

#include "oblivious_transfer/ot_flavors.h"
#include "statistics/run_time_statistics.h"
#include "utility/constants.h"
#include "utility/logger.h"

namespace encrypto::motion {

bool MtProvider::NeedMts() const noexcept {
  return 0 < (GetNumberOfMts<bool>() + GetNumberOfMts<std::uint8_t>() +
              GetNumberOfMts<std::uint16_t>() + GetNumberOfMts<std::uint32_t>() +
              GetNumberOfMts<std::uint64_t>());
}

std::size_t MtProvider::RequestBinaryMts(const std::size_t number_of_mts) noexcept {
  const auto offset = number_of_bit_mts_;
  number_of_bit_mts_ += number_of_mts;
  return offset;
}

// get bits [i, i+n] as vector
BinaryMtVector MtProvider::GetBinary(const std::size_t offset, const std::size_t n) const {
  assert(bit_mts_.a.GetSize() == bit_mts_.b.GetSize());
  assert(bit_mts_.b.GetSize() == bit_mts_.c.GetSize());
  WaitFinished();
  return BinaryMtVector{bit_mts_.a.Subset(offset, offset + n),
                        bit_mts_.b.Subset(offset, offset + n),
                        bit_mts_.c.Subset(offset, offset + n)};
}

const BinaryMtVector& MtProvider::GetBinaryAll() const noexcept {
  WaitFinished();
  return bit_mts_;
}

MtProvider::MtProvider(const std::size_t my_id, const std::size_t number_of_parties)
    : my_id_(my_id), number_of_parties_(number_of_parties) {
  finished_condition_ = std::make_shared<FiberCondition>([this]() { return finished_.load(); });
}

MtProviderFromOts::MtProviderFromOts(std::vector<std::unique_ptr<OtProvider>>& ot_providers,
                                     const std::size_t my_id, std::shared_ptr<Logger> logger,
                                     RunTimeStatistics& run_time_statistics)
    : MtProvider(my_id, ot_providers.size()),
      ot_providers_(ot_providers),
      ots_receiver_8_(number_of_parties_),
      ots_sender_8_(number_of_parties_),
      ots_receiver_16_(number_of_parties_),
      ots_sender_16_(number_of_parties_),
      ots_receiver_32_(number_of_parties_),
      ots_sender_32_(number_of_parties_),
      ots_receiver_64_(number_of_parties_),
      ots_sender_64_(number_of_parties_),
      bit_ots_receiver_(number_of_parties_),
      bit_ots_sender_(number_of_parties_),
      logger_(logger),
      run_time_statistics_(run_time_statistics) {}

MtProviderFromOts::~MtProviderFromOts() = default;

void MtProviderFromOts::PreSetup() {
  if (!NeedMts()) {
    return;
  }

  if constexpr (kDebug) {
    logger_->LogDebug("Start computing presetup for MTs");
  }
  run_time_statistics_.RecordStart<RunTimeStatistics::StatisticsId::kMtPresetup>();

  RegisterOts();

  run_time_statistics_.RecordEnd<RunTimeStatistics::StatisticsId::kMtPresetup>();
  if constexpr (kDebug) {
    logger_->LogDebug("Finished computing presetup for MTs");
  }
}

// needs completed OTExtension
void MtProviderFromOts::Setup() {
  if (!NeedMts()) {
    return;
  }

  if constexpr (kDebug) {
    logger_->LogDebug("Start computing setup for MTs");
  }
  run_time_statistics_.RecordStart<RunTimeStatistics::StatisticsId::kMtSetup>();

  for (auto i = 0ull; i < number_of_parties_; ++i) {
    if (i == my_id_) {
      continue;
    }
    for (auto& ot : ots_sender_8_.at(i)) {
      dynamic_cast<AcOtSender<std::uint8_t>*>(ot.get())->SendMessages();
    }
    for (auto& ot : ots_receiver_8_.at(i)) ot->SendCorrections();
    for (auto& ot : ots_sender_16_.at(i)) {
      dynamic_cast<AcOtSender<std::uint16_t>*>(ot.get())->SendMessages();
    }
    for (auto& ot : ots_receiver_16_.at(i)) ot->SendCorrections();
    for (auto& ot : ots_sender_32_.at(i)) {
      dynamic_cast<AcOtSender<std::uint32_t>*>(ot.get())->SendMessages();
    }
    for (auto& ot : ots_receiver_32_.at(i)) ot->SendCorrections();
    for (auto& ot : ots_sender_64_.at(i)) {
      dynamic_cast<AcOtSender<std::uint64_t>*>(ot.get())->SendMessages();
    }
    for (auto& ot : ots_receiver_64_.at(i)) ot->SendCorrections();

    if (number_of_bit_mts_ > 0) {
      assert(bit_ots_receiver_.at(i) != nullptr);
      assert(bit_ots_sender_.at(i) != nullptr);
      bit_ots_receiver_.at(i)->SendCorrections();
      bit_ots_sender_.at(i)->SendMessages();
    }
  }

  ParseOutputs();
  {
    std::scoped_lock lock(finished_condition_->GetMutex());
    finished_ = true;
  }

  finished_condition_->NotifyAll();

  run_time_statistics_.RecordEnd<RunTimeStatistics::StatisticsId::kMtSetup>();
  if constexpr (kDebug) {
    logger_->LogDebug("Finished computing setup for MTs");
  }
}

static void GenerateRandomTriplesBool(BinaryMtVector& bit_mts, std::size_t number_of_bit_mts) {
  if (number_of_bit_mts > 0u) {
    bit_mts.a = BitVector<>::SecureRandom(number_of_bit_mts);
    bit_mts.b = BitVector<>::SecureRandom(number_of_bit_mts);
    bit_mts.c = bit_mts.a & bit_mts.b;
  }
}

template <typename T>
static void GenerateRandomTriples(IntegerMtVector<T>& mts, std::size_t number_of_mts) {
  if (number_of_mts > 0u) {
    mts.a = RandomVector<T>(number_of_mts);
    mts.b = RandomVector<T>(number_of_mts);
    mts.c.resize(number_of_mts);
    std::transform(mts.a.cbegin(), mts.a.cend(), mts.b.cbegin(), mts.c.begin(),
                   [](const auto& a_i, const auto& b_i) { return a_i * b_i; });
  }
}

static void RegisterHelperBool(OtProvider& ot_provider, std::unique_ptr<XcOtBitSender>& ots_sender,
                               std::unique_ptr<XcOtBitReceiver>& ots_receiver,
                               const BinaryMtVector& bit_mts, std::size_t number_of_bit_mts) {
  ots_sender = ot_provider.RegisterSendXcOtBit(number_of_bit_mts);
  ots_receiver = ot_provider.RegisterReceiveXcOtBit(number_of_bit_mts);

  ots_sender->SetCorrelations(bit_mts.a);
  ots_receiver->SetChoices(bit_mts.b);
}

template <typename T>
static void RegisterHelper(OtProvider& ot_provider,
                           std::list<std::unique_ptr<BasicOtSender>>& ots_sender,
                           std::list<std::unique_ptr<BasicOtReceiver>>& ots_receiver,
                           std::size_t max_batch_size, const IntegerMtVector<T>& mts,
                           std::size_t number_of_mts) {
  constexpr std::size_t bit_size = sizeof(T) * 8;

  for (std::size_t mt_id = 0; mt_id < number_of_mts;) {
    const auto batch_size = std::min(max_batch_size, number_of_mts - mt_id);
    auto ptr_send{ot_provider.RegisterSendAcOt(batch_size * bit_size, sizeof(T) * 8)};
    auto ot_to_send = dynamic_cast<AcOtSender<T>*>(ptr_send.get());
    std::vector<T> vector_to_send;
    vector_to_send.reserve(batch_size * bit_size);
    for (auto k = 0ull; k < batch_size; ++k) {
      for (auto bit_i = 0u; bit_i < bit_size; ++bit_i) {
        const T input = mts.a.at(mt_id + k) << bit_i;
        vector_to_send.emplace_back(input);
      }
    }
    ot_to_send->SetCorrelations(std::move(vector_to_send));

    auto ptr_receive{ot_provider.RegisterReceiveAcOt(batch_size * bit_size, sizeof(T) * 8)};
    auto ot_to_receive = dynamic_cast<AcOtReceiver<T>*>(ptr_receive.get());
    BitVector<> choices;
    choices.Reserve(batch_size * bit_size);
    for (auto k = 0ull; k < batch_size; ++k) {
      for (auto bit_i = 0u; bit_i < bit_size; ++bit_i) {
        const bool choice = ((mts.b.at(mt_id + k) >> bit_i) & 1u) == 1;
        choices.Append(choice);
      }
    }
    ot_to_receive->SetChoices(std::move(choices));

    ots_sender.emplace_back(std::move(ptr_send));
    ots_receiver.emplace_back(std::move(ptr_receive));

    mt_id += batch_size;
  }
}

void MtProviderFromOts::RegisterOts() {
  if (number_of_bit_mts_ > 0) {
    GenerateRandomTriplesBool(bit_mts_, number_of_bit_mts_);
  }
  GenerateRandomTriples<std::uint8_t>(mts8_, number_of_mts_8_);
  GenerateRandomTriples<std::uint16_t>(mts16_, number_of_mts_16_);
  GenerateRandomTriples<std::uint32_t>(mts32_, number_of_mts_32_);
  GenerateRandomTriples<std::uint64_t>(mts64_, number_of_mts_64_);

  for (auto i = 0ull; i < number_of_parties_; ++i) {
    if (i == my_id_) {
      continue;
    }
    if (number_of_bit_mts_ > 0) {
      RegisterHelperBool(*ot_providers_.at(i), bit_ots_sender_.at(i), bit_ots_receiver_.at(i),
                         bit_mts_, number_of_bit_mts_);
    }
    RegisterHelper<std::uint8_t>(*ot_providers_.at(i), ots_sender_8_.at(i), ots_receiver_8_.at(i),
                                 kMaxBatchSize, mts8_, number_of_mts_8_);
    RegisterHelper<std::uint16_t>(*ot_providers_.at(i), ots_sender_16_.at(i),
                                  ots_receiver_16_.at(i), kMaxBatchSize, mts16_, number_of_mts_16_);
    RegisterHelper<std::uint32_t>(*ot_providers_.at(i), ots_sender_32_.at(i),
                                  ots_receiver_32_.at(i), kMaxBatchSize, mts32_, number_of_mts_32_);
    RegisterHelper<std::uint64_t>(*ot_providers_.at(i), ots_sender_64_.at(i),
                                  ots_receiver_64_.at(i), kMaxBatchSize, mts64_, number_of_mts_64_);
  }
}

static void ParseHelperBool(std::unique_ptr<XcOtBitSender>& ots_sender,
                            std::unique_ptr<XcOtBitReceiver>& ots_receiver,
                            BinaryMtVector& bit_mts) {
  ots_sender->ComputeOutputs();
  ots_receiver->ComputeOutputs();
  const auto& output_sender = ots_sender->GetOutputs();
  const auto& output_receiver = ots_receiver->GetOutputs();
  bit_mts.c ^= output_sender;
  bit_mts.c ^= output_receiver;
}

template <typename T>
static void ParseHelper(std::list<std::unique_ptr<BasicOtSender>>& ots_sender,
                        std::list<std::unique_ptr<BasicOtReceiver>>& ots_receiver,
                        std::size_t max_batch_size, IntegerMtVector<T>& mts,
                        std::size_t number_of_mts) {
  constexpr std::size_t bit_size = sizeof(T) * 8;

  for (std::size_t mt_id = 0; mt_id < number_of_mts;) {
    const auto batch_size = std::min(max_batch_size, number_of_mts - mt_id);
    const auto& ot_to_send = dynamic_cast<AcOtSender<T>*>(ots_sender.front().get());
    const auto& ot_to_receive = dynamic_cast<AcOtReceiver<T>*>(ots_receiver.front().get());
    ot_to_send->ComputeOutputs();
    const auto& output_sender = ot_to_send->GetOutputs();
    ot_to_receive->ComputeOutputs();
    const auto& output_receiver = ot_to_receive->GetOutputs();
    for (auto j = 0ull; j < batch_size; ++j) {
      for (auto bit_i = 0u; bit_i < bit_size; ++bit_i) {
        mts.c.at(mt_id + j) +=
            output_receiver[j * bit_size + bit_i] - output_sender[j * bit_size + bit_i];
      }
    }
    ots_sender.pop_front();
    ots_receiver.pop_front();
    mt_id += batch_size;
  }
}

void MtProviderFromOts::ParseOutputs() {
  for (auto i = 0ull; i < number_of_parties_; ++i) {
    if (i == my_id_) {
      continue;
    }

    if (number_of_bit_mts_ > 0) {
      ParseHelperBool(bit_ots_sender_.at(i), bit_ots_receiver_.at(i), bit_mts_);
    }
    ParseHelper<std::uint8_t>(ots_sender_8_.at(i), ots_receiver_8_.at(i), kMaxBatchSize, mts8_,
                              number_of_mts_8_);
    ParseHelper<std::uint16_t>(ots_sender_16_.at(i), ots_receiver_16_.at(i), kMaxBatchSize, mts16_,
                               number_of_mts_16_);
    ParseHelper<std::uint32_t>(ots_sender_32_.at(i), ots_receiver_32_.at(i), kMaxBatchSize, mts32_,
                               number_of_mts_32_);
    ParseHelper<std::uint64_t>(ots_sender_64_.at(i), ots_receiver_64_.at(i), kMaxBatchSize, mts64_,
                               number_of_mts_64_);
  }
}

}  // namespace encrypto::motion
