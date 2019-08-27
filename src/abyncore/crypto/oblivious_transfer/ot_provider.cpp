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

#include "ot_provider.h"

#include "utility/bit_matrix.h"

#include "omp.h"

namespace ENCRYPTO::ObliviousTransfer {
void OTProviderFromOTExtension::SendSetup() {
  constexpr std::size_t kappa = 128, n_threads = 4;

  std::size_t i;
  const std::size_t bit_size = sender_provider_.GetNumOTs();
  auto &ot_ext = data_storage_->GetOTExtensionSenderData();
  ot_ext->bit_size_ = bit_size;
  const std::size_t byte_size = ABYN::Helpers::Convert::BitsToBytes(bit_size);
  const auto bit_size_padded = bit_size + kappa - (bit_size % kappa);
  auto &base_ots = data_storage_->GetBaseOTsReceiverData();

  std::array<PRG, n_threads> prgs_fixed_key, prgs_var_key;
  const auto key = data_storage_->GetFixedKeyAESKey().GetData().data();
  for (auto &prg : prgs_fixed_key) {
    prg.SetKey(key);
  }

  std::vector<AlignedBitVector> v(kappa);
  //#pragma omp parallel for num_threads(n_threads) schedule(dynamic, 1)
  for (i = 0; i < kappa; ++i) {
    const std::size_t thread_id = static_cast<std::size_t>(omp_get_thread_num());
    assert(thread_id < prgs_var_key.size());
    prgs_var_key.at(thread_id).SetKey(base_ots->messages_c_.at(i).data());
    auto row(prgs_var_key.at(thread_id).Encrypt(byte_size));
    v.at(i) = AlignedBitVector(std::move(row), bit_size);
  }

  while (!(*ot_ext->received_u_condition_)() || !ot_ext->received_u_ids_.empty()) {
    std::size_t u_id = std::numeric_limits<std::size_t>::max();
    {
      std::scoped_lock lock(ot_ext->received_u_condition_->GetMutex());
      if (!ot_ext->received_u_ids_.empty()) {
        u_id = ot_ext->received_u_ids_.front();
        ot_ext->received_u_ids_.pop();
      }
    }
    if (u_id != std::numeric_limits<std::size_t>::max()) {
      if (base_ots->c_[u_id]) {
        const auto &u = ot_ext->u_.at(u_id);
        assert(u.GetSize() == v.at(u_id).GetSize());
        v.at(u_id) ^= u;
      }
    } else {
      ot_ext->received_u_condition_->WaitFor(std::chrono::milliseconds(1));
    }
  }
  ot_ext->u_ = {};

  // transpose matrix V
  if (bit_size_padded != bit_size) {
    for (i = 0u; i < v.size(); ++i) {
      v.at(i).Resize(bit_size_padded, true);
    }
  }
  std::array<std::byte *, kappa> ptrs;
  for (i = 0u; i < ptrs.size(); ++i) {
    ptrs.at(i) = v.at(i).GetMutableData().data();
  }
  BitMatrix::TransposeUsingBitSlicing(ptrs, bit_size_padded);

  //#pragma omp parallel for num_threads(n_threads) schedule(dynamic, 1024)
  for (i = 0; i < ot_ext->bitlengths_.size(); ++i) {
    const std::size_t thread_id = static_cast<std::size_t>(omp_get_thread_num());
    assert(thread_id < prgs_fixed_key.size());
    auto &out0 = ot_ext->y0_.at(i);
    auto &out1 = ot_ext->y1_.at(i);
    const auto bitlen = ot_ext->bitlengths_.at(i);

    const auto row_i = i % kappa;
    const auto blk_offset = ((kappa / 8) * (i / kappa));
    const auto V_row = ptrs.at(row_i) + blk_offset;

    if (bitlen <= kappa) {
      out0 = BitVector<>(prgs_fixed_key.at(thread_id).FixedKeyAES(V_row, i), bitlen);

      auto out1_in = data_storage_->GetBaseOTsReceiverData()->c_ ^ BitVector<>(V_row, kappa);
      out1 = BitVector<>(prgs_fixed_key.at(thread_id).FixedKeyAES(out1_in.GetData().data(), i),
                         bitlen);
    } else {
      auto seed0 = prgs_fixed_key.at(thread_id).FixedKeyAES(V_row, i);
      prgs_var_key.at(thread_id).SetKey(seed0.data());
      out0 = BitVector<>(
          prgs_var_key.at(thread_id).Encrypt(ABYN::Helpers::Convert::BitsToBytes(bitlen)), bitlen);

      auto out1_in = data_storage_->GetBaseOTsReceiverData()->c_ ^ BitVector<>(V_row, kappa);
      auto seed1 = prgs_fixed_key.at(thread_id).FixedKeyAES(out1_in.GetData().data(), i);
      prgs_var_key.at(thread_id).SetKey(seed1.data());
      out1 = BitVector<>(
          prgs_var_key.at(thread_id).Encrypt(ABYN::Helpers::Convert::BitsToBytes(bitlen)), bitlen);
    }
  }

  {
    std::scoped_lock(ot_ext->setup_finished_condition_->GetMutex());
    ot_ext->setup_finished_ = true;
  }
  ot_ext->setup_finished_condition_->NotifyAll();
}

void OTProviderFromOTExtension::ReceiveSetup() {
  std::size_t i = 0, j = 0;
  constexpr std::size_t kappa = 128, n_threads = 4;
  const std::size_t bit_size = receiver_provider_.GetNumOTs();
  const std::size_t byte_size = ABYN::Helpers::Convert::BitsToBytes(bit_size);
  const auto bit_size_padded = bit_size + kappa - (bit_size % kappa);

  if (byte_size == 0) {
    return;
  }
  auto &base_ots = data_storage_->GetBaseOTsSenderData();
  auto &ot_ext = data_storage_->GetOTExtensionReceiverData();
  ot_ext->random_choices_ =
      std::make_unique<AlignedBitVector>(AlignedBitVector::Random(bit_size_padded));
  ot_ext->real_choices_ = std::make_unique<BitVector<>>(bit_size_padded);

  std::vector<AlignedBitVector> v(kappa);
  std::array<PRG, n_threads> prgs_fixed_key, prgs_var_key;
  const auto key = data_storage_->GetFixedKeyAESKey().GetData().data();
  for (auto &prg : prgs_fixed_key) {
    prg.SetKey(key);
  }

  //#pragma omp parallel for num_threads(n_threads) schedule(dynamic, 1)
  for (i = 0; i < kappa; ++i) {
    const std::size_t thread_id = static_cast<std::size_t>(omp_get_thread_num());
    assert(thread_id < prgs_var_key.size());
    // T[j] = PRG(s_{j,0})
    prgs_var_key.at(thread_id).SetKey(base_ots->messages_0_.at(i).data());
    auto row(prgs_var_key.at(thread_id).Encrypt(byte_size));
    v.at(i) = AlignedBitVector(std::move(row), bit_size);
    auto u = v.at(i);
    // u_j = T[j] XOR r
    u ^= *ot_ext->random_choices_;

    // u_j = u_j XOR PRG(s_{j,1})
    prgs_var_key.at(thread_id).SetKey(base_ots->messages_1_.at(i).data());
    u ^= AlignedBitVector(prgs_var_key.at(thread_id).Encrypt(byte_size), bit_size);

    Send_(ABYN::Communication::BuildOTExtensionMessageReceiverMasks(u.GetData().data(),
                                                                    u.GetData().size(), i));
  }

  // transpose matrix T
  if (bit_size_padded != bit_size) {
    for (i = 0u; i < v.size(); ++i) {
      v.at(i).Resize(bit_size_padded, true);
    }
  }

  std::array<std::byte *, kappa> ptrs;
  for (j = 0; j < ptrs.size(); ++j) {
    ptrs.at(j) = v.at(j).GetMutableData().data();
  }
  BitMatrix::TransposeUsingBitSlicing(ptrs, bit_size_padded);

  //#pragma omp parallel for num_threads(n_threads) schedule(dynamic, 1024)
  for (i = 0; i < ot_ext->outputs_.size(); ++i) {
    const auto row_i = i % kappa;
    const auto blk_offset = ((kappa / 8) * (i / kappa));
    const auto T_row = ptrs.at(row_i) + blk_offset;
    const std::size_t thread_id = static_cast<std::size_t>(omp_get_thread_num());
    assert(thread_id < prgs_fixed_key.size());
    auto &out = ot_ext->outputs_.at(i);
    const auto bitlen = ot_ext->bitlengths_.at(i);
    if (bitlen <= kappa) {
      out = BitVector<>(prgs_fixed_key.at(thread_id).FixedKeyAES(T_row, i), bitlen);
    } else {
      auto seed = prgs_fixed_key.at(thread_id).FixedKeyAES(T_row, i);
      prgs_var_key.at(thread_id).SetKey(seed.data());
      out = BitVector<>(
          prgs_var_key.at(thread_id).Encrypt(ABYN::Helpers::Convert::BitsToBytes(bitlen)), bitlen);
    }
  }
  {
    std::scoped_lock(ot_ext->setup_finished_condition_->GetMutex());
    ot_ext->setup_finished_ = true;
  }
  ot_ext->setup_finished_condition_->NotifyAll();
}
}