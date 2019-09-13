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

namespace ABYN {

bool MTProvider::GetMTsNeeded() const noexcept {
  return (GetNumMTs<bool>() + GetNumMTs<std::uint8_t>() + GetNumMTs<std::uint16_t>() +
          GetNumMTs<std::uint32_t>() + GetNumMTs<std::uint64_t>()) > 0;
}

std::size_t MTProvider::RequestBinaryMTs(const std::size_t num_mts) noexcept {
  const auto offset = num_bit_mts_;
  num_bit_mts_ += num_mts;
  return offset;
}

// get bits [i, i+n] as vector
BinaryMTVector MTProvider::GetBinary(const std::size_t offset, const std::size_t n) {
  assert(bit_mts_.a.GetSize() == bit_mts_.b.GetSize());
  assert(bit_mts_.b.GetSize() == bit_mts_.c.GetSize());
  WaitFinished();
  return BinaryMTVector{bit_mts_.a.Subset(offset, offset + n),
                        bit_mts_.b.Subset(offset, offset + n),
                        bit_mts_.c.Subset(offset, offset + n)};
}

const BinaryMTVector& MTProvider::GetBinaryAll() noexcept {
  WaitFinished();
  return bit_mts_;
}

MTProvider::MTProvider(const std::size_t my_id) : my_id_(my_id) {
  finished_condition_ = std::make_shared<ENCRYPTO::Condition>([this]() { return finished_; });
}

MTProviderFromOTs::MTProviderFromOTs(
    std::vector<std::shared_ptr<ENCRYPTO::ObliviousTransfer::OTProvider>>& ot_providers,
    const std::size_t my_id)
    : MTProvider(my_id), ot_providers_(ot_providers) {
  ots_rcv_.resize(ot_providers_.size());
  ots_snd_.resize(ot_providers_.size());
}

void MTProviderFromOTs::PreSetup() {
  if (num_bit_mts_ > 0u) {
    RegisterOTs();
  }
}

// needs completed OTExtension
void MTProviderFromOTs::Setup() {
  if (num_bit_mts_ == 0u) {
    return;
  }
#pragma omp parallel for
  for (auto i = 0ull; i < ot_providers_.size(); ++i) {
    // switch roles in batches for load balancing between the OT sender and OT receiver role
    if (i == my_id_) {
      continue;
    }
#pragma omp parallel sections
    {
#pragma omp section
      {
        for (auto& ot : ots_snd_.at(i)) {
          ot->SendMessages();
        }
      }
#pragma omp section
      {
        for (auto& ot : ots_rcv_.at(i)) {
          ot->SendCorrections();
        }
      }
    }
  }
  ParseOutputs();
  {
    std::scoped_lock lock(finished_condition_->GetMutex());
    finished_ = true;
  }
  finished_condition_->NotifyAll();
}

void MTProviderFromOTs::RegisterOTs() {
  constexpr auto XCOT = ENCRYPTO::ObliviousTransfer::OTProtocol::XCOT;
  bit_mts_.a = ENCRYPTO::BitVector<>::Random(num_bit_mts_);
  bit_mts_.b = ENCRYPTO::BitVector<>::Random(num_bit_mts_);
  bit_mts_.c = bit_mts_.a & bit_mts_.b;

#pragma omp parallel for num_threads(ot_providers_.size())
  for (auto i = 0ull; i < ot_providers_.size(); ++i) {
    if (i == my_id_) {
      continue;
    }
    for (std::size_t mt_id = 0; mt_id < num_bit_mts_;) {
      const auto batch_size = std::min(max_batch_size_, num_bit_mts_ - mt_id);
      auto ot_s = ot_providers_.at(i)->RegisterSend(1, batch_size, XCOT);
      std::vector<ENCRYPTO::BitVector<>> v_r;
      for (auto k = 0ull; k < batch_size; ++k) {
        v_r.emplace_back(ENCRYPTO::BitVector<>(1, bit_mts_.a[mt_id + k]));
      }
      ot_s->SetInputs(std::move(v_r));

      auto ot_r = ot_providers_.at(i)->RegisterReceive(1, batch_size, XCOT);
      ot_r->SetChoices(bit_mts_.b.Subset(mt_id, mt_id + batch_size));

      ots_snd_.at(i).emplace_back(std::move(ot_s));
      ots_rcv_.at(i).emplace_back(std::move(ot_r));

      mt_id += batch_size;
    }
  }
}

void MTProviderFromOTs::ParseOutputs() {
#pragma omp parallel for num_threads(ot_providers_.size())
  for (auto i = 0ull; i < ot_providers_.size(); ++i) {
    if (i == my_id_) {
      continue;
    }
    for (std::size_t mt_id = 0; mt_id < num_bit_mts_;) {
      const auto batch_size = std::min(max_batch_size_, num_bit_mts_ - mt_id);
      const auto& ot_s = ots_snd_.at(i).front();
      const auto& ot_r = ots_rcv_.at(i).front();
      const auto& out_s = ot_s->GetOutputs();
      const auto& out_r = ot_r->GetOutputs();
      for (auto j = 0ull; j < batch_size; ++j) {
        bit_mts_.c.Set(out_r.at(j)[0] ^ out_s.at(j)[0] ^ bit_mts_.c[mt_id + j], mt_id + j);
      }
      ots_snd_.at(i).pop_front();
      ots_rcv_.at(i).pop_front();
      mt_id += batch_size;
    }
    assert(ots_snd_.at(i).empty());
    assert(ots_rcv_.at(i).empty());
  }
}
}  // namespace ABYN
