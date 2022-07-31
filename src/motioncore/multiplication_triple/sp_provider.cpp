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

#include "sp_provider.h"
#include "oblivious_transfer/ot_provider.h"
#include "statistics/run_time_statistics.h"
#include "utility/constants.h"
#include "utility/logger.h"

namespace encrypto::motion {

bool SpProvider::NeedSps() const noexcept {
  return 0 < number_of_sps_8_ + number_of_sps_16_ + number_of_sps_32_ + number_of_sps_64_ +
                 number_of_sps_128_;
}

SpProvider::SpProvider(const std::size_t my_id) : my_id_(my_id) {
  finished_condition_ = std::make_shared<FiberCondition>([this]() { return finished_; });
}

SpProviderFromOts::SpProviderFromOts(std::vector<std::unique_ptr<OtProvider>>& ot_providers,
                                     const std::size_t my_id, std::shared_ptr<Logger> logger,
                                     RunTimeStatistics& run_time_statistics)
    : SpProvider(my_id),
      ot_providers_(ot_providers),
      ots_receiver_8_(ot_providers_.size()),
      ots_sender_8_(ot_providers_.size()),
      ots_receiver_16_(ot_providers_.size()),
      ots_sender_16_(ot_providers_.size()),
      ots_receiver_32_(ot_providers_.size()),
      ots_sender_32_(ot_providers_.size()),
      ots_receiver_64_(ot_providers_.size()),
      ots_sender_64_(ot_providers_.size()),
      ots_receiver_128_(ot_providers_.size()),
      ots_sender_128_(ot_providers_.size()),
      logger_(logger),
      run_time_statistics_(run_time_statistics) {}

void SpProviderFromOts::PreSetup() {
  if (!NeedSps()) {
    return;
  }

  if constexpr (kDebug) {
    logger_->LogDebug("Start computing presetup for SPs");
  }
  run_time_statistics_.RecordStart<RunTimeStatistics::StatisticsId::kSpPresetup>();

  RegisterOts();

  run_time_statistics_.RecordEnd<RunTimeStatistics::StatisticsId::kSpPresetup>();
  if constexpr (kDebug) {
    logger_->LogDebug("Finished computing presetup for SPs");
  }
}

void SpProviderFromOts::Setup() {
  if (!NeedSps()) {
    return;
  }

  if constexpr (kDebug) {
    logger_->LogDebug("Start computing setup for SPs");
  }
  run_time_statistics_.RecordStart<RunTimeStatistics::StatisticsId::kSpSetup>();

#pragma omp parallel for
  for (auto i = 0ull; i < ot_providers_.size(); ++i) {
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
    for (auto& ot : ots_sender_128_.at(i)) {
      dynamic_cast<AcOtSender<__uint128_t>*>(ot.get())->SendMessages();
    }
    for (auto& ot : ots_receiver_128_.at(i)) ot->SendCorrections();
  }

  ParseOutputs();
  {
    std::scoped_lock lock(finished_condition_->GetMutex());
    finished_ = true;
  }
  finished_condition_->NotifyAll();

  run_time_statistics_.RecordEnd<RunTimeStatistics::StatisticsId::kSpSetup>();
  if constexpr (kDebug) {
    logger_->LogDebug("Finished computing setup for SPs");
  }
}

template <typename T>
static void GenerateRandomPairs(SpVector<T>& sps, std::size_t number_of_sps) {
  if (number_of_sps > 0u) {
    sps.a = RandomVector<T>(number_of_sps);
    sps.c.resize(number_of_sps);
    std::transform(sps.a.cbegin(), sps.a.cend(), sps.c.begin(),
                   [](const auto& a_i) { return a_i * a_i; });
  }
}

template <typename T>
static void RegisterHelperSend(OtProvider& ot_provider,
                               std::list<std::unique_ptr<BasicOtSender>>& ots_sender,
                               std::size_t max_batch_size, const SpVector<T>& sps,
                               std::size_t number_of_sps) {
  constexpr std::size_t bit_size = sizeof(T) * 8;

  for (std::size_t sp_id = 0; sp_id < number_of_sps;) {
    const auto batch_size = std::min(max_batch_size, number_of_sps - sp_id);
    auto ptr{ot_provider.RegisterSendAcOt(batch_size * bit_size, sizeof(T) * 8)};
    auto ot_to_send = dynamic_cast<AcOtSender<T>*>(ptr.get());
    std::vector<T> vector_to_send;
    for (auto k = 0ull; k < batch_size; ++k) {
      for (auto bit_i = 0u; bit_i < bit_size; ++bit_i) {
        const T input = sps.a.at(sp_id + k) << bit_i;
        vector_to_send.emplace_back(input);
      }
    }
    ot_to_send->SetCorrelations(std::move(vector_to_send));
    ots_sender.emplace_back(std::move(ptr));
    sp_id += batch_size;
  }
}

template <typename T>
static void RegisterHelperReceptor(OtProvider& ot_provider,
                                   std::list<std::unique_ptr<BasicOtReceiver>>& ots_receiver,
                                   std::size_t max_batch_size, const SpVector<T>& sps,
                                   std::size_t number_of_sps) {
  constexpr std::size_t bit_size = sizeof(T) * 8;

  for (std::size_t sp_id = 0; sp_id < number_of_sps;) {
    const auto batch_size = std::min(max_batch_size, number_of_sps - sp_id);
    auto ptr{ot_provider.RegisterReceiveAcOt(batch_size * bit_size, sizeof(T) * 8)};
    auto ot_to_receive = dynamic_cast<AcOtReceiver<T>*>(ptr.get());
    BitVector<> choices;
    for (auto k = 0ull; k < batch_size; ++k) {
      for (auto bit_i = 0u; bit_i < bit_size; ++bit_i) {
        const bool choice = ((sps.a.at(sp_id + k) >> bit_i) & 1u) == 1;
        choices.Append(choice);
      }
    }
    ot_to_receive->SetChoices(std::move(choices));
    ots_receiver.emplace_back(std::move(ptr));
    sp_id += batch_size;
  }
}

void SpProviderFromOts::RegisterOts() {
  GenerateRandomPairs<std::uint8_t>(sps_8_, number_of_sps_8_);
  GenerateRandomPairs<std::uint16_t>(sps_16_, number_of_sps_16_);
  GenerateRandomPairs<std::uint32_t>(sps_32_, number_of_sps_32_);
  GenerateRandomPairs<std::uint64_t>(sps_64_, number_of_sps_64_);
  GenerateRandomPairs<__uint128_t>(sps_128_, number_of_sps_128_);

#pragma omp parallel for num_threads(ot_providers_.size())
  for (std::size_t i = 0; i < ot_providers_.size(); ++i) {
    if (i == my_id_) {
      continue;
    }

    if (i < my_id_) {
      RegisterHelperSend<std::uint8_t>(*ot_providers_.at(i), ots_sender_8_.at(i), kMaxBatchSize,
                                       sps_8_, number_of_sps_8_);
      RegisterHelperSend<std::uint16_t>(*ot_providers_.at(i), ots_sender_16_.at(i), kMaxBatchSize,
                                        sps_16_, number_of_sps_16_);
      RegisterHelperSend<std::uint32_t>(*ot_providers_.at(i), ots_sender_32_.at(i), kMaxBatchSize,
                                        sps_32_, number_of_sps_32_);
      RegisterHelperSend<std::uint64_t>(*ot_providers_.at(i), ots_sender_64_.at(i), kMaxBatchSize,
                                        sps_64_, number_of_sps_64_);
      RegisterHelperSend<__uint128_t>(*ot_providers_.at(i), ots_sender_128_.at(i), kMaxBatchSize,
                                      sps_128_, number_of_sps_128_);
    } else if (i > my_id_) {
      RegisterHelperReceptor<std::uint8_t>(*ot_providers_.at(i), ots_receiver_8_.at(i),
                                           kMaxBatchSize, sps_8_, number_of_sps_8_);
      RegisterHelperReceptor<std::uint16_t>(*ot_providers_.at(i), ots_receiver_16_.at(i),
                                            kMaxBatchSize, sps_16_, number_of_sps_16_);
      RegisterHelperReceptor<std::uint32_t>(*ot_providers_.at(i), ots_receiver_32_.at(i),
                                            kMaxBatchSize, sps_32_, number_of_sps_32_);
      RegisterHelperReceptor<std::uint64_t>(*ot_providers_.at(i), ots_receiver_64_.at(i),
                                            kMaxBatchSize, sps_64_, number_of_sps_64_);
      RegisterHelperReceptor<__uint128_t>(*ot_providers_.at(i), ots_receiver_128_.at(i),
                                          kMaxBatchSize, sps_128_, number_of_sps_128_);
    }
  }
}

template <typename T>
static void ParseHelperSend(std::list<std::unique_ptr<BasicOtSender>>& ots_sender,
                            std::size_t max_batch_size, SpVector<T>& sps,
                            std::size_t number_of_sps) {
  constexpr std::size_t bit_size = sizeof(T) * 8;

  for (std::size_t sp_id = 0; sp_id < number_of_sps;) {
    const auto batch_size = std::min(max_batch_size, number_of_sps - sp_id);
    const auto& ot_to_send = dynamic_cast<AcOtSender<T>*>(ots_sender.front().get());
    ot_to_send->ComputeOutputs();
    const auto output_to_send = ot_to_send->GetOutputs();
    for (auto j = 0ull; j < batch_size; ++j) {
      for (auto bit_i = 0u; bit_i < bit_size; ++bit_i) {
        sps.c.at(sp_id + j) -= 2 * output_to_send[j * bit_size + bit_i];
      }
    }
    ots_sender.pop_front();
    sp_id += batch_size;
  }
}

template <typename T>
static void ParseHelperReceive(std::list<std::unique_ptr<BasicOtReceiver>>& ots_receiver,
                               std::size_t max_batch_size, SpVector<T>& sps,
                               std::size_t number_of_sps) {
  constexpr std::size_t bit_size = sizeof(T) * 8;

  for (std::size_t sp_id = 0; sp_id < number_of_sps;) {
    const auto batch_size = std::min(max_batch_size, number_of_sps - sp_id);
    const auto& ot_to_receive = dynamic_cast<AcOtReceiver<T>*>(ots_receiver.front().get());
    ot_to_receive->ComputeOutputs();
    const auto output_to_receive = ot_to_receive->GetOutputs();
    for (auto j = 0ull; j < batch_size; ++j) {
      for (auto bit_i = 0u; bit_i < bit_size; ++bit_i) {
        sps.c.at(sp_id + j) += 2 * output_to_receive[j * bit_size + bit_i];
      }
    }
    ots_receiver.pop_front();
    sp_id += batch_size;
  }
}

void SpProviderFromOts::ParseOutputs() {
  for (std::size_t i = 0; i < ot_providers_.size(); ++i) {
    if (i == my_id_) {
      continue;
    }

    if (i < my_id_) {
      ParseHelperSend<std::uint8_t>(ots_sender_8_.at(i), kMaxBatchSize, sps_8_, number_of_sps_8_);
      ParseHelperSend<std::uint16_t>(ots_sender_16_.at(i), kMaxBatchSize, sps_16_,
                                     number_of_sps_16_);
      ParseHelperSend<std::uint32_t>(ots_sender_32_.at(i), kMaxBatchSize, sps_32_,
                                     number_of_sps_32_);
      ParseHelperSend<std::uint64_t>(ots_sender_64_.at(i), kMaxBatchSize, sps_64_,
                                     number_of_sps_64_);
      ParseHelperSend<__uint128_t>(ots_sender_128_.at(i), kMaxBatchSize, sps_128_,
                                   number_of_sps_128_);
    } else if (i > my_id_) {
      ParseHelperReceive<std::uint8_t>(ots_receiver_8_.at(i), kMaxBatchSize, sps_8_,
                                       number_of_sps_8_);
      ParseHelperReceive<std::uint16_t>(ots_receiver_16_.at(i), kMaxBatchSize, sps_16_,
                                        number_of_sps_16_);
      ParseHelperReceive<std::uint32_t>(ots_receiver_32_.at(i), kMaxBatchSize, sps_32_,
                                        number_of_sps_32_);
      ParseHelperReceive<std::uint64_t>(ots_receiver_64_.at(i), kMaxBatchSize, sps_64_,
                                        number_of_sps_64_);
      ParseHelperReceive<__uint128_t>(ots_receiver_128_.at(i), kMaxBatchSize, sps_128_,
                                      number_of_sps_128_);
    }
  }
}

}  // namespace encrypto::motion
