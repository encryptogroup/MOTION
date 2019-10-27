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

#include "communication/ot_extension_message.h"
#include "crypto/pseudo_random_generator.h"
#include "utility/bit_matrix.h"
#include "utility/condition.h"
#include "utility/config.h"
#include "utility/data_storage.h"
#include "utility/logger.h"

namespace ENCRYPTO::ObliviousTransfer {
void OTProviderFromOTExtension::SendSetup() {
  constexpr std::size_t kappa = 128;
  const std::size_t bit_size = sender_provider_.GetNumOTs();
  if (bit_size == 0) return;

  std::size_t i;
  auto &ot_ext = data_storage_->GetOTExtensionSenderData();
  ot_ext->bit_size_ = bit_size;
  const std::size_t byte_size = MOTION::Helpers::Convert::BitsToBytes(bit_size);
  const auto bit_size_padded = bit_size + kappa - (bit_size % kappa);
  auto &base_ots = data_storage_->GetBaseOTsReceiverData();

  PRG prgs_fixed_key, prgs_var_key;
  const auto key = data_storage_->GetFixedKeyAESKey().GetData().data();
  prgs_fixed_key.SetKey(key);

  std::vector<AlignedBitVector> v(kappa);

  for (i = 0; i < kappa; ++i) {
    prgs_var_key.SetKey(base_ots->messages_c_.at(i).data());
    prgs_var_key.SetOffset(base_ots->consumed_offset_);
    auto row(prgs_var_key.Encrypt(byte_size));
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

  for (i = 0; i < ot_ext->bitlengths_.size(); ++i) {
    auto &out0 = ot_ext->y0_.at(i);
    auto &out1 = ot_ext->y1_.at(i);
    const auto bitlen = ot_ext->bitlengths_.at(i);

    const auto row_i = i % kappa;
    const auto blk_offset = ((kappa / 8) * (i / kappa));
    const auto V_row = ptrs.at(row_i) + blk_offset;

    if (bitlen <= kappa) {
      out0 = BitVector<>(prgs_fixed_key.FixedKeyAES(V_row, i), bitlen);

      auto out1_in = data_storage_->GetBaseOTsReceiverData()->c_ ^ BitVector<>(V_row, kappa);
      out1 = BitVector<>(prgs_fixed_key.FixedKeyAES(out1_in.GetData().data(), i), bitlen);
    } else {
      auto seed0 = prgs_fixed_key.FixedKeyAES(V_row, i);
      prgs_var_key.SetKey(seed0.data());
      out0 = BitVector<>(prgs_var_key.Encrypt(MOTION::Helpers::Convert::BitsToBytes(bitlen)), bitlen);

      auto out1_in = data_storage_->GetBaseOTsReceiverData()->c_ ^ BitVector<>(V_row, kappa);
      auto seed1 = prgs_fixed_key.FixedKeyAES(out1_in.GetData().data(), i);
      prgs_var_key.SetKey(seed1.data());
      out1 = BitVector<>(prgs_var_key.Encrypt(MOTION::Helpers::Convert::BitsToBytes(bitlen)), bitlen);
    }
  }

  {
    std::scoped_lock(ot_ext->setup_finished_cond_->GetMutex());
    ot_ext->setup_finished_ = true;
  }
  ot_ext->setup_finished_cond_->NotifyAll();
}

void OTProviderFromOTExtension::ReceiveSetup() {
  std::size_t i = 0, j = 0;
  constexpr std::size_t kappa = 128;
  const std::size_t bit_size = receiver_provider_.GetNumOTs();
  if (bit_size == 0) return;

  const std::size_t byte_size = MOTION::Helpers::Convert::BitsToBytes(bit_size);
  const auto bit_size_padded = bit_size + kappa - (bit_size % kappa);

  if (byte_size == 0) {
    return;
  }
  auto &base_ots = data_storage_->GetBaseOTsSenderData();
  auto &ot_ext = data_storage_->GetOTExtensionReceiverData();
  ot_ext->random_choices_ =
      std::make_unique<AlignedBitVector>(AlignedBitVector::Random(bit_size_padded));

  std::vector<AlignedBitVector> v(kappa);
  PRG prgs_fixed_key, prgs_var_key;
  const auto key = data_storage_->GetFixedKeyAESKey().GetData().data();
  prgs_fixed_key.SetKey(key);

  for (i = 0; i < kappa; ++i) {
    // T[j] = PRG(s_{j,0})
    prgs_var_key.SetKey(base_ots->messages_0_.at(i).data());
    prgs_var_key.SetOffset(base_ots->consumed_offset_);
    auto row(prgs_var_key.Encrypt(byte_size));
    v.at(i) = AlignedBitVector(std::move(row), bit_size);
    auto u = v.at(i);
    // u_j = T[j] XOR r
    u ^= *ot_ext->random_choices_;

    // u_j = u_j XOR PRG(s_{j,1})
    prgs_var_key.SetKey(base_ots->messages_1_.at(i).data());
    prgs_var_key.SetOffset(base_ots->consumed_offset_);
    u ^= AlignedBitVector(prgs_var_key.Encrypt(byte_size), bit_size);

    Send_(MOTION::Communication::BuildOTExtensionMessageReceiverMasks(u.GetData().data(),
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

  for (i = 0; i < ot_ext->outputs_.size(); ++i) {
    const auto row_i = i % kappa;
    const auto blk_offset = ((kappa / 8) * (i / kappa));
    const auto T_row = ptrs.at(row_i) + blk_offset;
    auto &out = ot_ext->outputs_.at(i);
    const auto bitlen = ot_ext->bitlengths_.at(i);
    if (bitlen <= kappa) {
      out = BitVector<>(prgs_fixed_key.FixedKeyAES(T_row, i), bitlen);
    } else {
      auto seed = prgs_fixed_key.FixedKeyAES(T_row, i);
      prgs_var_key.SetKey(seed.data());
      out = BitVector<>(prgs_var_key.Encrypt(MOTION::Helpers::Convert::BitsToBytes(bitlen)), bitlen);
    }
  }
  {
    std::scoped_lock(ot_ext->setup_finished_cond_->GetMutex());
    ot_ext->setup_finished_ = true;
  }
  ot_ext->setup_finished_cond_->NotifyAll();
}

OTProviderFromOTExtension::OTProviderFromOTExtension(
    std::function<void(flatbuffers::FlatBufferBuilder &&)> Send,
    const std::shared_ptr<MOTION::DataStorage> &data_storage)
    : OTProvider(data_storage, Send) {
  auto &ot_ext = data_storage_->GetOTExtensionReceiverData();
  ot_ext->real_choices_ = std::make_unique<BitVector<>>();
}

OTVector::OTVector(const std::size_t ot_id, const std::size_t vector_id, const std::size_t num_ots,
                   const std::size_t bitlen, const OTProtocol p,
                   const std::shared_ptr<MOTION::DataStorage> &data_storage,
                   const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send)
    : ot_id_(ot_id),
      vector_id_(vector_id),
      num_ots_(num_ots),
      bitlen_(bitlen),
      p_(p),
      data_storage_(data_storage),
      Send_(Send) {}

const std::vector<BitVector<>> &OTVectorSender::GetOutputs() {
  WaitSetup();
  auto &ote = data_storage_->GetOTExtensionSenderData();
  if (outputs_.empty()) {
    for (auto i = 0ull; i < num_ots_; ++i) {
      auto bv = ote->y0_.at(ot_id_ + i);
      bv.Append(ote->y1_.at(ot_id_ + i));
      outputs_.push_back(std::move(bv));
    }
  }
  return outputs_;
}

void OTVectorSender::WaitSetup() {
  auto &cond = data_storage_->GetOTExtensionSenderData()->setup_finished_cond_;
  while (!(*cond)()) {
    cond->WaitFor(std::chrono::milliseconds(1));
  }
}

OTVectorSender::OTVectorSender(const std::size_t ot_id, const std::size_t vector_id,
                               const std::size_t num_ots, const std::size_t bitlen,
                               const OTProtocol p,
                               const std::shared_ptr<MOTION::DataStorage> &data_storage,
                               const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send)
    : OTVector(ot_id, vector_id, num_ots, bitlen, p, data_storage, Send) {
  Reserve(ot_id, num_ots, bitlen);
}

void OTVectorSender::Reserve(const std::size_t id, const std::size_t num_ots,
                             const std::size_t bitlen) {
  auto &data = data_storage_->GetOTExtensionSenderData();
  data->y0_.resize(data->y0_.size() + num_ots);
  data->y1_.resize(data->y1_.size() + num_ots);
  data->bitlengths_.resize(data->bitlengths_.size() + num_ots);
  data->corrections_.Resize(data->corrections_.GetSize() + num_ots);
  for (auto i = 0ull; i < num_ots; ++i) {
    data->bitlengths_.at(data->bitlengths_.size() - 1 - i) = bitlen;
  }
  data->num_ots_in_batch_.emplace(id, num_ots);
}

GOTVectorSender::GOTVectorSender(const std::size_t ot_id, const std::size_t vector_id,
                                 const std::size_t num_ots, const std::size_t bitlen,
                                 const std::shared_ptr<MOTION::DataStorage> &data_storage,
                                 const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send)
    : OTVectorSender(ot_id, vector_id, num_ots, bitlen, OTProtocol::GOT, data_storage, Send) {
  auto &ote_data = data_storage_->GetOTExtensionSenderData();
  ote_data->received_correction_offsets_cond_.emplace(
      ot_id_, std::make_unique<Condition>([this, &ote_data]() {
        std::scoped_lock lock(ote_data->corrections_mutex_);
        return ote_data->received_correction_offsets_.find(ot_id_) !=
               ote_data->received_correction_offsets_.end();
      }));
}

void GOTVectorSender::SetInputs(std::vector<BitVector<>> &&v) {
  for ([[maybe_unused]] auto &bv : v) {
    assert(bv.GetSize() == (bitlen_ * 2));
  }
  inputs_ = std::move(v);
  outputs_ = inputs_;
}

void GOTVectorSender::SetInputs(const std::vector<BitVector<>> &v) {
  for ([[maybe_unused]] auto &bv : v) {
    assert(bv.GetSize() == (bitlen_ * 2));
  }
  inputs_ = v;
  outputs_ = inputs_;
}

// blocking wait for correction bits
void GOTVectorSender::SendMessages() {
  assert(!inputs_.empty());
  WaitSetup();
  auto &ote = data_storage_->GetOTExtensionSenderData();
  MOTION::Helpers::WaitFor(*ote->received_correction_offsets_cond_.at(ot_id_));
  std::unique_lock lock(ote->corrections_mutex_);
  auto corrections = ote->corrections_.Subset(ot_id_, ot_id_ + num_ots_);
  lock.unlock();
  assert(inputs_.size() == corrections.GetSize());

  BitVector<> buffer;
  for (auto i = 0ull; i < num_ots_; ++i) {
    const auto bv_0 = inputs_.at(i).Subset(0, bitlen_);
    const auto bv_1 = inputs_.at(i).Subset(bitlen_, bitlen_ * 2);
    if (corrections[i]) {
      buffer.Append(bv_1 ^ ote->y0_.at(ot_id_ + i));
      buffer.Append(bv_0 ^ ote->y1_.at(ot_id_ + i));
    } else {
      buffer.Append(bv_0 ^ ote->y0_.at(ot_id_ + i));
      buffer.Append(bv_1 ^ ote->y1_.at(ot_id_ + i));
    }
  }
  Send_(MOTION::Communication::BuildOTExtensionMessageSender(buffer.GetData().data(),
                                                           buffer.GetData().size(), ot_id_));
}

COTVectorSender::COTVectorSender(const std::size_t id, const std::size_t vector_id,
                                 const std::size_t num_ots, const std::size_t bitlen, OTProtocol p,
                                 const std::shared_ptr<MOTION::DataStorage> &data_storage,
                                 const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send)
    : OTVectorSender(id, vector_id, num_ots, bitlen, p, data_storage, Send) {
  if (p == OTProtocol::ACOT && (bitlen != 8u && bitlen != 16u && bitlen != 32u && bitlen != 64u)) {
    throw std::runtime_error(fmt::format(
        "Invalid parameter bitlen={}, only 8, 16, 32, or 64 are allowed in ACOT", bitlen_));
  }
  auto &ote_data = data_storage_->GetOTExtensionSenderData();
  ote_data->received_correction_offsets_cond_.emplace(
      ot_id_, std::make_unique<Condition>([this, &ote_data]() {
        std::scoped_lock lock(ote_data->corrections_mutex_);
        return ote_data->received_correction_offsets_.find(ot_id_) !=
               ote_data->received_correction_offsets_.end();
      }));
}

void COTVectorSender::SetInputs(std::vector<BitVector<>> &&v) {
  for ([[maybe_unused]] auto &bv : v) {
    assert(bv.GetSize() == (bitlen_));
  }
  inputs_ = std::move(v);
}

void COTVectorSender::SetInputs(const std::vector<BitVector<>> &v) {
  for ([[maybe_unused]] auto &bv : v) {
    assert(bv.GetSize() == (bitlen_));
  }
  inputs_ = v;
}

const std::vector<BitVector<>> &COTVectorSender::GetOutputs() {
  if (inputs_.empty()) {
    throw std::runtime_error("Inputs have to be chosen before calling GetOutputs()");
  }
  WaitSetup();
  auto &ote = data_storage_->GetOTExtensionSenderData();
  MOTION::Helpers::WaitFor(*ote->received_correction_offsets_cond_.at(ot_id_));
  if (outputs_.empty()) {
    std::unique_lock lock(ote->corrections_mutex_);
    const auto corrections = ote->corrections_.Subset(ot_id_, ot_id_ + num_ots_);
    lock.unlock();
    for (auto i = 0ull; i < num_ots_; ++i) {
      BitVector<> bv;
      if (corrections[i]) {
        bv = ote->y1_.at(ot_id_ + i);
      } else {
        bv = ote->y0_.at(ot_id_ + i);
      }
      if (p_ == OTProtocol::ACOT) {
        if (corrections[i]) {
          bv.Append(ote->y1_.at(ot_id_ + i));
        } else {
          bv.Append(ote->y0_.at(ot_id_ + i));
        }
        switch (bitlen_) {
          case (8u): {
            *reinterpret_cast<uint8_t *>(bv.GetMutableData().data() + 1) +=
                *reinterpret_cast<const uint8_t *>(inputs_.at(i).GetData().data());
            break;
          }
          case (16u): {
            *reinterpret_cast<uint16_t *>(bv.GetMutableData().data() + 2) +=
                *reinterpret_cast<const uint16_t *>(inputs_.at(i).GetData().data());
            break;
          }
          case (32u): {
            *reinterpret_cast<uint32_t *>(bv.GetMutableData().data() + 4) +=
                *reinterpret_cast<const uint32_t *>(inputs_.at(i).GetData().data());
            break;
          }
          case (64u): {
            *reinterpret_cast<uint64_t *>(bv.GetMutableData().data() + 8) +=
                *reinterpret_cast<const uint64_t *>(inputs_.at(i).GetData().data());
            break;
          }
        }
      } else {  // OTProtocol::XCOT
        bv.Append(inputs_.at(i) ^ bv);
      }
      outputs_.emplace_back(std::move(bv));
    }
  }
  return outputs_;
}

void COTVectorSender::SendMessages() {
  if (inputs_.empty()) {
    throw std::runtime_error("Inputs have to be chosen before calling SendMessages()");
  }
  WaitSetup();
  auto &ote = data_storage_->GetOTExtensionSenderData();
  BitVector<> buffer;
  for (auto i = 0ull; i < num_ots_; ++i) {
    if (p_ == OTProtocol::ACOT) {
      BitVector bv = ote->y0_.at(ot_id_ + i);
      switch (bitlen_) {
        case 8u: {
          *(reinterpret_cast<std::uint8_t *>(bv.GetMutableData().data())) +=
              *(reinterpret_cast<const std::uint8_t *>(inputs_.at(i).GetMutableData().data()));
          *(reinterpret_cast<std::uint8_t *>(bv.GetMutableData().data())) +=
              *(reinterpret_cast<const std::uint8_t *>(
                  ote->y1_.at(ot_id_ + i).GetMutableData().data()));

          break;
        }
        case 16u: {
          *(reinterpret_cast<std::uint16_t *>(bv.GetMutableData().data())) +=
              *(reinterpret_cast<const std::uint16_t *>(inputs_.at(i).GetMutableData().data()));
          *(reinterpret_cast<std::uint16_t *>(bv.GetMutableData().data())) +=
              *(reinterpret_cast<const std::uint16_t *>(
                  ote->y1_.at(ot_id_ + i).GetMutableData().data()));
          break;
        }
        case 32u: {
          *(reinterpret_cast<std::uint32_t *>(bv.GetMutableData().data())) +=
              *(reinterpret_cast<const std::uint32_t *>(inputs_.at(i).GetMutableData().data()));
          *(reinterpret_cast<std::uint32_t *>(bv.GetMutableData().data())) +=
              *(reinterpret_cast<const std::uint32_t *>(
                  ote->y1_.at(ot_id_ + i).GetMutableData().data()));
          break;
        }
        case 64u: {
          *(reinterpret_cast<std::uint64_t *>(bv.GetMutableData().data())) +=
              *(reinterpret_cast<const std::uint64_t *>(inputs_.at(i).GetMutableData().data()));
          *(reinterpret_cast<std::uint64_t *>(bv.GetMutableData().data())) +=
              *(reinterpret_cast<const std::uint64_t *>(
                  ote->y1_.at(ot_id_ + i).GetMutableData().data()));
          break;
        }
        default: {
          throw std::runtime_error(fmt::format("Unsupported bitlength {}", bitlen_));
        }
      }
      buffer.Append(bv);
    } else if (p_ == OTProtocol::XCOT) {
      buffer.Append(inputs_.at(i) ^ ote->y0_.at(ot_id_ + i) ^ ote->y1_.at(ot_id_ + i));
    } else {
      throw std::runtime_error("Unknown OT protocol");
    }
  }
  Send_(MOTION::Communication::BuildOTExtensionMessageSender(buffer.GetData().data(),
                                                           buffer.GetData().size(), ot_id_));
}

ROTVectorSender::ROTVectorSender(const std::size_t ot_id, const std::size_t vector_id,
                                 const std::size_t num_ots, const std::size_t bitlen,
                                 const std::shared_ptr<MOTION::DataStorage> &data_storage,
                                 const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send)
    : OTVectorSender(ot_id, vector_id, num_ots, bitlen, OTProtocol::ROT, data_storage, Send) {}

void ROTVectorSender::SetInputs([[maybe_unused]] std::vector<BitVector<>> &&v) {
  throw std::runtime_error("Inputs are random in ROT and thus cannot be set");
}

void ROTVectorSender::SetInputs([[maybe_unused]] const std::vector<BitVector<>> &v) {
  throw std::runtime_error("Inputs are random in ROT and thus cannot be set");
}

void ROTVectorSender::SendMessages() {
  throw std::runtime_error("Inputs in ROT are available locally and thus do not need to be sent");
}

void OTVectorReceiver::WaitSetup() {
  auto &cond = data_storage_->GetOTExtensionReceiverData()->setup_finished_cond_;
  while (!(*cond)()) {
    cond->WaitFor(std::chrono::milliseconds(1));
  }
}

OTVectorReceiver::OTVectorReceiver(const std::size_t ot_id, const std::size_t vector_id,
                                   const std::size_t num_ots, const std::size_t bitlen,
                                   const OTProtocol p,
                                   const std::shared_ptr<MOTION::DataStorage> &data_storage,
                                   std::function<void(flatbuffers::FlatBufferBuilder &&)> Send)
    : OTVector(ot_id, vector_id, num_ots, bitlen, p, data_storage, Send) {
  Reserve(ot_id, num_ots, bitlen);
}

void OTVectorReceiver::Reserve(const std::size_t id, const std::size_t num_ots,
                               const std::size_t bitlen) {
  auto &data = data_storage_->GetOTExtensionReceiverData();
  data->outputs_.resize(id + num_ots);
  data->bitlengths_.resize(id + num_ots);
  for (auto i = 0ull; i < num_ots; ++i) {
    data->bitlengths_.at(id + i) = bitlen;
  }
  data->num_ots_in_batch_.emplace(id, num_ots);
}

GOTVectorReceiver::GOTVectorReceiver(
    const std::size_t ot_id, const std::size_t vector_id, const std::size_t num_ots,
    const std::size_t bitlen, const std::shared_ptr<MOTION::DataStorage> &data_storage,
    const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send)
    : OTVectorReceiver(ot_id, vector_id, num_ots, bitlen, OTProtocol::GOT, data_storage, Send) {
  data_storage_->GetOTExtensionReceiverData()->num_messages_.emplace(ot_id_, 2);
}

void GOTVectorReceiver::SetChoices(BitVector<> &&v) {
  assert(v.GetSize() == num_ots_);
  choices_ = std::move(v);
  auto &ote = data_storage_->GetOTExtensionReceiverData();
  {
    std::scoped_lock lock(ote->real_choices_mutex_, ote->real_choices_cond_.at(ot_id_)->GetMutex());
    ote->real_choices_->Copy(ot_id_, choices_);
    ote->set_real_choices_.emplace(ot_id_);
  }
  ote->real_choices_cond_.at(ot_id_)->NotifyOne();
  choices_flag_ = true;
}

void GOTVectorReceiver::SetChoices(const BitVector<> &v) {
  assert(v.GetSize() == num_ots_);
  choices_ = v;
  auto &ote = data_storage_->GetOTExtensionReceiverData();
  {
    std::scoped_lock lock(ote->real_choices_mutex_, ote->real_choices_cond_.at(ot_id_)->GetMutex());
    ote->real_choices_->Copy(ot_id_, choices_);
    ote->set_real_choices_.emplace(ot_id_);
  }
  ote->real_choices_cond_.at(ot_id_)->NotifyOne();
  choices_flag_ = true;
}

void GOTVectorReceiver::SendCorrections() {
  if (choices_.Empty()) {
    throw std::runtime_error("Choices in GOT must be set before calling SendCorrections()");
  }

  const auto &ote = data_storage_->GetOTExtensionReceiverData();
  auto corrections = choices_ ^ ote->random_choices_->Subset(ot_id_, ot_id_ + num_ots_);
  Send_(MOTION::Communication::BuildOTExtensionMessageReceiverCorrections(
      corrections.GetData().data(), corrections.GetData().size(), ot_id_));
  corrections_sent_ = true;
}

const std::vector<BitVector<>> &GOTVectorReceiver::GetOutputs() {
  if (!corrections_sent_) {
    throw std::runtime_error("In GOT, corrections must be set before calling GetOutputs()");
  }
  WaitSetup();
  auto &ote = data_storage_->GetOTExtensionReceiverData();
  auto &cond = ote->output_conds_.at(ot_id_);
  MOTION::Helpers::WaitFor(*cond);
  if (messages_.empty()) {
    for (auto i = 0ull; i < num_ots_; ++i) {
      if (ote->outputs_.at(ot_id_ + i).GetSize() > 0) {
        messages_.emplace_back(std::move(ote->outputs_.at(ot_id_ + i)));
      }
    }
  }
  return messages_;
}

COTVectorReceiver::COTVectorReceiver(
    const std::size_t ot_id, const std::size_t vector_id, const std::size_t num_ots,
    const std::size_t bitlen, OTProtocol p, const std::shared_ptr<MOTION::DataStorage> &data_storage,
    const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send)
    : OTVectorReceiver(ot_id, vector_id, num_ots, bitlen, p, data_storage, Send) {
  if (p == OTProtocol::ACOT && (bitlen != 8u && bitlen != 16u && bitlen != 32u && bitlen != 64u)) {
    throw std::runtime_error(fmt::format(
        "Invalid parameter bitlen={}, only 8, 16, 32, or 64 are allowed in ACOT", bitlen_));
  }
  data_storage_->GetOTExtensionReceiverData()->num_messages_.emplace(ot_id_, 1);
  if (p == OTProtocol::XCOT) {
    data_storage_->GetOTExtensionReceiverData()->xor_correlation_.emplace(ot_id_);
  }
}

void COTVectorReceiver::SendCorrections() {
  if (choices_.Empty()) {
    throw std::runtime_error("Choices in COT must be set before calling SendCorrections()");
  }
  const auto &ote = data_storage_->GetOTExtensionReceiverData();
  auto corrections = choices_ ^ ote->random_choices_->Subset(ot_id_, ot_id_ + num_ots_);
  Send_(MOTION::Communication::BuildOTExtensionMessageReceiverCorrections(
      corrections.GetData().data(), corrections.GetData().size(), ot_id_));
  corrections_sent_ = true;
}

void COTVectorReceiver::SetChoices(BitVector<> &&v) {
  choices_ = std::move(v);
  auto &ote = data_storage_->GetOTExtensionReceiverData();
  {
    std::scoped_lock lock(ote->real_choices_mutex_, ote->real_choices_cond_.at(ot_id_)->GetMutex());
    ote->real_choices_->Copy(ot_id_, choices_);
    ote->set_real_choices_.emplace(ot_id_);
  }
  ote->real_choices_cond_.at(ot_id_)->NotifyOne();
  choices_flag_ = true;
}

void COTVectorReceiver::SetChoices(const BitVector<> &v) {
  choices_ = v;
  auto &ote = data_storage_->GetOTExtensionReceiverData();
  {
    std::scoped_lock lock(ote->real_choices_mutex_, ote->real_choices_cond_.at(ot_id_)->GetMutex());
    ote->real_choices_->Copy(ot_id_, choices_);
    ote->set_real_choices_.emplace(ot_id_);
  }
  ote->real_choices_cond_.at(ot_id_)->NotifyOne();
  choices_flag_ = true;
}

const std::vector<BitVector<>> &COTVectorReceiver::GetOutputs() {
  if (!corrections_sent_) {
    throw std::runtime_error("In COT, corrections must be set before calling GetOutputs()");
  }
  WaitSetup();
  auto &ote = data_storage_->GetOTExtensionReceiverData();
  MOTION::Helpers::WaitFor(*ote->output_conds_.at(ot_id_));

  if (messages_.empty()) {
    for (auto i = 0ull; i < num_ots_; ++i) {
      if (ote->outputs_.at(ot_id_ + i).GetSize() > 0) {
        messages_.emplace_back(std::move(ote->outputs_.at(ot_id_ + i)));
      }
    }
  }
  return messages_;
}

ROTVectorReceiver::ROTVectorReceiver(
    const std::size_t ot_id, const std::size_t vector_id, const std::size_t num_ots,
    const std::size_t bitlen, const std::shared_ptr<MOTION::DataStorage> &data_storage,
    const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send)
    : OTVectorReceiver(ot_id, vector_id, num_ots, bitlen, OTProtocol::ROT, data_storage, Send) {
  Reserve(ot_id, num_ots, bitlen);
}

void ROTVectorReceiver::SetChoices([[maybe_unused]] const BitVector<> &v) {
  throw std::runtime_error("Choices are random in ROT and thus cannot be set");
}

void ROTVectorReceiver::SetChoices([[maybe_unused]] BitVector<> &&v) {
  throw std::runtime_error("Choices are random in ROT and thus cannot be set");
}

void ROTVectorReceiver::SendCorrections() {
  throw std::runtime_error(
      "Choices are random in ROT and thus there is no need for correction bits");
}

const BitVector<> &ROTVectorReceiver::GetChoices() {
  WaitSetup();
  if (choices_.GetSize() == 0) {
    auto &ote = data_storage_->GetOTExtensionReceiverData();
    auto a_bv = ote->random_choices_->Subset(ot_id_, ot_id_ + num_ots_);
    choices_ = BitVector<>(a_bv.GetData().data(), a_bv.GetSize());
  }
  return choices_;
}

const std::vector<BitVector<>> &ROTVectorReceiver::GetOutputs() {
  WaitSetup();
  if (messages_.size() == 0) {
    auto &ote = data_storage_->GetOTExtensionReceiverData();
    auto data = ote->outputs_.begin();
    messages_.insert(messages_.end(), data + ot_id_, data + ot_id_ + num_ots_);
  }
  return messages_;
}

std::shared_ptr<OTVectorSender> &OTProviderSender::GetOTs(std::size_t offset) {
  auto iterator = sender_data_.find(offset);
  if (iterator == sender_data_.end()) {
    throw std::runtime_error(fmt::format("Could not find an OTVector with offset {}", offset));
  }
  return iterator->second;
}

std::shared_ptr<OTVectorSender> &OTProviderSender::RegisterOTs(
    const std::size_t bitlen, const std::size_t num_ots, const OTProtocol p,
    const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send) {
  const auto i = total_ots_count_;
  total_ots_count_ += num_ots;
  std::shared_ptr<OTVectorSender> ot;
  switch (p) {
    case OTProtocol::GOT: {
      ot = std::make_shared<GOTVectorSender>(i, next_vector_id_, num_ots, bitlen, data_storage_,
                                             Send);
      if constexpr (MOTION::MOTION_DEBUG) {
        assert(data_storage_->GetID() >= 0);
        const auto party_id = static_cast<std::size_t>(data_storage_->GetID());
        data_storage_->GetLogger()->LogDebug(
            fmt::format("Party#{}: registered {} parallel {}-bit sender GOTs", party_id, party_id,
                        num_ots, bitlen));
      }
      break;
    }
    case OTProtocol::ACOT: {
      ot = std::make_shared<COTVectorSender>(i, next_vector_id_, num_ots, bitlen, p, data_storage_,
                                             Send);
      if constexpr (MOTION::MOTION_DEBUG) {
        assert(data_storage_->GetID() >= 0);
        const auto party_id = static_cast<std::size_t>(data_storage_->GetID());
        data_storage_->GetLogger()->LogDebug(fmt::format(
            "Party#{}: registered {} parallel {}-bit sender ACOTs", party_id, num_ots, bitlen));
      }
      break;
    }
    case OTProtocol::XCOT: {
      ot = std::make_shared<COTVectorSender>(i, next_vector_id_, num_ots, bitlen, p, data_storage_,
                                             Send);
      if constexpr (MOTION::MOTION_DEBUG) {
        assert(data_storage_->GetID() >= 0);
        const auto party_id = static_cast<std::size_t>(data_storage_->GetID());
        data_storage_->GetLogger()->LogDebug(fmt::format(
            "Party#{}: registered {} parallel {}-bit sender XCOTs", party_id, num_ots, bitlen));
      }
      break;
    }
    case OTProtocol::ROT: {
      ot = std::make_shared<ROTVectorSender>(i, next_vector_id_, num_ots, bitlen, data_storage_,
                                             Send);
      if constexpr (MOTION::MOTION_DEBUG) {
        assert(data_storage_->GetID() >= 0);
        const auto party_id = static_cast<std::size_t>(data_storage_->GetID());
        data_storage_->GetLogger()->LogDebug(fmt::format(
            "Party#{}: registered {} parallel {}-bit sender ROTs", party_id, num_ots, bitlen));
      }
      break;
    }
    default:
      throw std::runtime_error("Unknown OT protocol");
  }
  ++next_vector_id_;
  return sender_data_.insert(std::pair(i, ot)).first->second;
}

void OTProviderSender::Clear() {
  data_storage_->GetBaseOTsSenderData()->consumed_offset_ += total_ots_count_;
  total_ots_count_ = 0;

  auto &ote = data_storage_->GetOTExtensionSenderData();
  {
    std::scoped_lock lock(ote->setup_finished_cond_->GetMutex());
    ote->setup_finished_ = false;
  }
  {
    std::scoped_lock lock(ote->corrections_mutex_);
    ote->received_correction_offsets_.clear();
  }

  ote->num_u_received_ = 0;
}

void OTProviderSender::Reset() {
  Clear();
  // TODO
}

std::shared_ptr<OTVectorReceiver> &OTProviderReceiver::GetOTs(std::size_t offset) {
  auto iterator = receiver_data_.find(offset);
  if (iterator == receiver_data_.end()) {
    throw std::runtime_error(fmt::format("Could not find an OTVector with offset {}", offset));
  }
  return iterator->second;
}

std::shared_ptr<OTVectorReceiver> &OTProviderReceiver::RegisterOTs(
    const std::size_t bitlen, const std::size_t num_ots, const OTProtocol p,
    const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send) {
  const auto i = total_ots_count_;
  total_ots_count_ += num_ots;

  auto &data = data_storage_->GetOTExtensionReceiverData();

  if (p != OTProtocol::ROT) {
    {
      auto &&e =
          std::pair(i, std::make_unique<Condition>([i, &data]() {
                      std::scoped_lock lock(data->received_outputs_mutex_);
                      return data->received_outputs_.find(i) != data->received_outputs_.end();
                    }));
      data->output_conds_.insert(std::move(e));
    }
    {
      auto &&e =
          std::pair(i, std::make_unique<Condition>([i, &data]() {
                      std::scoped_lock lock(data->real_choices_mutex_);
                      return data->set_real_choices_.find(i) != data->set_real_choices_.end();
                    }));
      data->real_choices_cond_.insert(std::move(e));
    }
  }

  std::shared_ptr<OTVectorReceiver> ot;

  switch (p) {
    case OTProtocol::GOT: {
      ot = std::make_shared<GOTVectorReceiver>(i, next_vector_id_, num_ots, bitlen, data_storage_,
                                               Send);
      if constexpr (MOTION::MOTION_DEBUG) {
        assert(data_storage_->GetID() >= 0);
        const auto party_id = static_cast<std::size_t>(data_storage_->GetID());
        data_storage_->GetLogger()->LogDebug(fmt::format(
            "Party#{}: registered {} parallel {}-bit receiver GOTs", party_id, num_ots, bitlen));
      }
      break;
    }
    case OTProtocol::XCOT: {
      ot = std::make_shared<COTVectorReceiver>(i, next_vector_id_, num_ots, bitlen, p,
                                               data_storage_, Send);
      if constexpr (MOTION::MOTION_DEBUG) {
        assert(data_storage_->GetID() >= 0);
        const auto party_id = static_cast<std::size_t>(data_storage_->GetID());
        data_storage_->GetLogger()->LogDebug(fmt::format(
            "Party#{}: registered {} parallel {}-bit receiver XCOTs", party_id, num_ots, bitlen));
      }
      break;
    }
    case OTProtocol::ACOT: {
      ot = std::make_shared<COTVectorReceiver>(i, next_vector_id_, num_ots, bitlen, p,
                                               data_storage_, Send);
      if constexpr (MOTION::MOTION_DEBUG) {
        assert(data_storage_->GetID() >= 0);
        const auto party_id = static_cast<std::size_t>(data_storage_->GetID());
        data_storage_->GetLogger()->LogDebug(fmt::format(
            "Party#{}: registered {} parallel {}-bit receiver ACOTs", party_id, num_ots, bitlen));
      }
      break;
    }
    case OTProtocol::ROT: {
      ot = std::make_shared<ROTVectorReceiver>(i, next_vector_id_, num_ots, bitlen, data_storage_,
                                               Send);
      if constexpr (MOTION::MOTION_DEBUG) {
        assert(data_storage_->GetID() >= 0);
        const auto party_id = static_cast<std::size_t>(data_storage_->GetID());
        data_storage_->GetLogger()->LogDebug(fmt::format(
            "Party#{}: registered {} parallel {}-bit receiver ROTs", party_id, num_ots, bitlen));
      }
      break;
    }
    default:
      throw std::runtime_error("Unknown OT protocol");
  }

  ++next_vector_id_;
  auto &&e = std::pair(i, ot);
  data_storage_->GetOTExtensionReceiverData()->real_choices_->Resize(total_ots_count_, false);
  return receiver_data_.insert(std::move(e)).first->second;
}

void OTProviderReceiver::Clear() {
  data_storage_->GetBaseOTsReceiverData()->consumed_offset_ += total_ots_count_;
  total_ots_count_ = 0;

  auto &ote = data_storage_->GetOTExtensionReceiverData();

  {
    std::scoped_lock lock(ote->setup_finished_cond_->GetMutex());
    ote->setup_finished_ = false;
  }

  {
    std::scoped_lock lock(ote->real_choices_mutex_);
    ote->set_real_choices_.clear();
  }

  {
    std::scoped_lock lock(ote->received_outputs_mutex_);
    ote->received_outputs_.clear();
  }
}
void OTProviderReceiver::Reset() { Clear(); }

}