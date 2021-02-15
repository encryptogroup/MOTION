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
#include "base_ots/base_ot_provider.h"
#include "ot_flavors.h"

#include "base/motion_base_provider.h"
#include "communication/communication_layer.h"
#include "communication/fbs_headers/ot_extension_generated.h"
#include "communication/message_handler.h"
#include "communication/ot_extension_message.h"
#include "data_storage/base_ot_data.h"
#include "data_storage/ot_extension_data.h"
#include "primitives/pseudo_random_generator.h"
#include "utility/bit_matrix.h"
#include "utility/config.h"
#include "utility/fiber_condition.h"
#include "utility/logger.h"

namespace encrypto::motion {

OtProvider::OtProvider(std::function<void(flatbuffers::FlatBufferBuilder&&)> send_function,
                       OtExtensionData& data, std::size_t party_id, std::shared_ptr<Logger> logger)
    : send_function_(send_function),
      data_(data),
      receiver_provider_(data_.GetReceiverData(), party_id, logger),
      sender_provider_(data_.GetSenderData(), party_id, logger) {}

void OtProvider::WaitSetup() const {
  data_.GetReceiverData().setup_finished_condition->Wait();
  data_.GetSenderData().setup_finished_condition->Wait();
}

[[nodiscard]] std::unique_ptr<FixedXcOt128Sender> OtProvider::RegisterSendFixedXcOt128(
    std::size_t number_of_ots) {
  return sender_provider_.RegisterFixedXcOt128s(number_of_ots, send_function_);
}

[[nodiscard]] std::unique_ptr<XcOtBitSender> OtProvider::RegisterSendXcOtBit(
    std::size_t number_of_ots) {
  return sender_provider_.RegisterXcOtBits(number_of_ots, send_function_);
}

template <typename T>
[[nodiscard]] std::unique_ptr<AcOtSender<T>> OtProvider::RegisterSendAcOt(std::size_t number_of_ots,
                                                                          std::size_t vector_size) {
  return sender_provider_.RegisterAcOt<T>(number_of_ots, vector_size, send_function_);
}

template std::unique_ptr<AcOtSender<std::uint8_t>> OtProvider::RegisterSendAcOt(
    std::size_t number_of_ots, std::size_t vector_size);
template std::unique_ptr<AcOtSender<std::uint16_t>> OtProvider::RegisterSendAcOt(
    std::size_t number_of_ots, std::size_t vector_size);
template std::unique_ptr<AcOtSender<std::uint32_t>> OtProvider::RegisterSendAcOt(
    std::size_t number_of_ots, std::size_t vector_size);
template std::unique_ptr<AcOtSender<std::uint64_t>> OtProvider::RegisterSendAcOt(
    std::size_t number_of_ots, std::size_t vector_size);
template std::unique_ptr<AcOtSender<__uint128_t>> OtProvider::RegisterSendAcOt(
    std::size_t number_of_ots, std::size_t vector_size);

[[nodiscard]] std::unique_ptr<GOt128Sender> OtProvider::RegisterSendGOt128(
    std::size_t number_of_ots) {
  return sender_provider_.RegisterGOt128(number_of_ots, send_function_);
}

[[nodiscard]] std::unique_ptr<GOtBitSender> OtProvider::RegisterSendGOtBit(
    std::size_t number_of_ots) {
  return sender_provider_.RegisterGOtBit(number_of_ots, send_function_);
}

[[nodiscard]] std::unique_ptr<FixedXcOt128Receiver> OtProvider::RegisterReceiveFixedXcOt128(
    std::size_t number_of_ots) {
  return receiver_provider_.RegisterFixedXcOt128s(number_of_ots, send_function_);
}

[[nodiscard]] std::unique_ptr<XcOtBitReceiver> OtProvider::RegisterReceiveXcOtBit(
    std::size_t number_of_ots) {
  return receiver_provider_.RegisterXcOtBits(number_of_ots, send_function_);
}

template <typename T>
[[nodiscard]] std::unique_ptr<AcOtReceiver<T>> OtProvider::RegisterReceiveAcOt(
    std::size_t number_of_ots, std::size_t vector_size) {
  return receiver_provider_.RegisterAcOt<T>(number_of_ots, vector_size, send_function_);
}

template std::unique_ptr<AcOtReceiver<std::uint8_t>> OtProvider::RegisterReceiveAcOt(
    std::size_t number_of_ots, std::size_t vector_size);
template std::unique_ptr<AcOtReceiver<std::uint16_t>> OtProvider::RegisterReceiveAcOt(
    std::size_t number_of_ots, std::size_t vector_size);
template std::unique_ptr<AcOtReceiver<std::uint32_t>> OtProvider::RegisterReceiveAcOt(
    std::size_t number_of_ots, std::size_t vector_size);
template std::unique_ptr<AcOtReceiver<std::uint64_t>> OtProvider::RegisterReceiveAcOt(
    std::size_t number_of_ots, std::size_t vector_size);
template std::unique_ptr<AcOtReceiver<__uint128_t>> OtProvider::RegisterReceiveAcOt(
    std::size_t number_of_ots, std::size_t vector_size);

[[nodiscard]] std::unique_ptr<GOt128Receiver> OtProvider::RegisterReceiveGOt128(
    std::size_t number_of_ots) {
  return receiver_provider_.RegisterGOt128(number_of_ots, send_function_);
}

[[nodiscard]] std::unique_ptr<GOtBitReceiver> OtProvider::RegisterReceiveGOtBit(
    std::size_t number_of_ots) {
  return receiver_provider_.RegisterGOtBit(number_of_ots, send_function_);
}

OtProviderFromOtExtension::OtProviderFromOtExtension(
    std::function<void(flatbuffers::FlatBufferBuilder&&)> send_function, OtExtensionData& data,
    const BaseOtData& base_ot_data, BaseProvider& motion_base_provider, std::size_t party_id,
    std::shared_ptr<Logger> logger)
    : OtProvider(send_function, data, party_id, logger),
      base_ot_data_(base_ot_data),
      motion_base_provider_(motion_base_provider) {
  auto& ot_extension_receiver_data = data_.GetReceiverData();
  ot_extension_receiver_data.real_choices = std::make_unique<BitVector<>>();
}

void OtProviderFromOtExtension::SendSetup() {
  // security parameter
  constexpr std::size_t kKappa = 128;

  // storage for sender and base OT receiver data
  const auto& base_ots_receiver_data = base_ot_data_.GetReceiverData();
  auto& ot_extension_sender_data = data_.GetSenderData();

  // number of OTs after extension
  // == width of the bit matrix
  const std::size_t bit_size = sender_provider_.GetNumOts();
  if (bit_size == 0) return;  // no OTs needed
  ot_extension_sender_data.bit_size = bit_size;

  // XXX: index variable?
  std::size_t i;

  // bit size of the matrix rounded to bytes
  // XXX: maybe round to blocks?
  const std::size_t byte_size = BitsToBytes(bit_size);

  // bit size rounded to blocks
  const auto bit_size_padded = bit_size + kKappa - (bit_size % kKappa);

  // vector containing the matrix rows
  // XXX: note that rows/columns are swapped compared to the ALSZ paper
  std::vector<AlignedBitVector> v(kKappa);

  // PRG which is used to expand the keys we got from the base OTs
  primitives::Prg prgs_variable_key;
  //// fill the rows of the matrix
  for (i = 0; i < kKappa; ++i) {
    // use the key we got from the base OTs as seed
    prgs_variable_key.SetKey(base_ots_receiver_data.messages_c.at(i).data());
    // change the offset in the output stream since we might have already used
    // the same base OTs previously
    prgs_variable_key.SetOffset(base_ots_receiver_data.consumed_offset);
    // expand the seed such that it fills one row of the matrix
    auto row(prgs_variable_key.Encrypt(byte_size));
    v[i] = AlignedBitVector(std::move(row), bit_size_padded);
  }

  // receive the vectors u one by one from the receiver
  // and xor them to the expanded keys if the corresponding selection bit is 1
  // transmitted one by one to prevent waiting for finishing all messages to start sending
  // the vectors can be transmitted in the wrong order

  for (auto it = ot_extension_sender_data.u_futures.begin();
       it < ot_extension_sender_data.u_futures.end(); ++it) {
    const std::size_t u_id{it->get()};
    if (base_ots_receiver_data.c[u_id]) {
      const auto& u = ot_extension_sender_data.u[u_id];
      BitSpan bs(v[u_id].GetMutableData().data(), bit_size, true);
      bs ^= u;
    }
  }

  // delete the allocated memory
  ot_extension_sender_data.u = {};

  // array with pointers to each row of the matrix
  std::array<const std::byte*, kKappa> pointers;
  for (i = 0u; i < pointers.size(); ++i) {
    pointers[i] = v[i].GetData().data();
  }

  motion_base_provider_.Setup();
  const auto& fixed_key_aes_key = motion_base_provider_.GetAesFixedKey();

  // for each (extended) OT i
  primitives::Prg prg_fixed_key;
  prg_fixed_key.SetKey(fixed_key_aes_key.data());

  // transpose the bit matrix
  // XXX: figure out how the result looks like
  BitMatrix::SenderTransposeAndEncrypt(
      pointers, ot_extension_sender_data.y0, ot_extension_sender_data.y1, base_ots_receiver_data.c,
      prg_fixed_key, bit_size_padded, ot_extension_sender_data.bitlengths);
  /*
    for (i = 0; i < ot_extension_sender_data.bitlengths.size(); ++i) {
      // here we want to store the sender's outputs
      // XXX: why are the y0_, y1_ vectors resized every time new ots are registered?
      auto &out0 = ot_extension_sender_data.y0[i];
      auto &out1 = ot_extension_sender_data.y1[i];

      // bit length of the OT
      const auto bitlength = ot_extension_sender_data.bitlengths[i];

      // in which of the above "rows" can we find the block
      const auto row_i = i % kKappa;
      // where in the "row" do we have to look for the block
      const auto blk_offset = ((kKappa / 8) * (i / kKappa));
      auto V_row = reinterpret_cast<std::byte *>(
          __builtin_assume_aligned(pointers.at(row_i) + blk_offset,
    kAlignment));

      // compute the sender outputs
      if (bitlength <= kKappa) {
        // the bit length is smaller than 128 bit
        out0 = BitVector<>(prg_fixed_key.FixedKeyAes(V_row, i), bitlength);

        auto out1_in = base_ots_receiver_data.c ^ BitSpan(V_row, kKappa, true);
        out1 = BitVector<>(prg_fixed_key.FixedKeyAes(out1_in.GetData().data(), i), bitlength);
      } else {
        // string OT with bit length > 128 bit
        // -> do seed compression and send later only 128 bit seeds
        auto seed0 = prg_fixed_key.FixedKeyAes(V_row, i);
        prgs_variable_key.SetKey(seed0.data());
        out0 =
            BitVector<>(prgs_variable_key.Encrypt(BitsToBytes(bitlength)),
    bitlength);

        auto out1_in = base_ots_receiver_data.c ^ BitSpan(V_row, kKappa, true);
        auto seed1 = prg_fixed_key.FixedKeyAes(out1_in.GetData().data(), i);
        prgs_variable_key.SetKey(seed1.data());
        out1 =
            BitVector<>(prgs_variable_key.Encrypt(BitsToBytes(bitlength)),
    bitlength);
      }
    }*/

  // we are done with the setup for the sender side
  {
    std::scoped_lock(ot_extension_sender_data.setup_finished_condition->GetMutex());
    ot_extension_sender_data.setup_finished = true;
  }
  ot_extension_sender_data.setup_finished_condition->NotifyAll();
}

void OtProviderFromOtExtension::ReceiveSetup() {
  // some index variables
  std::size_t i = 0, j = 0;
  // security parameter and number of base OTs
  constexpr std::size_t kKappa = 128;
  // number of OTs and width of the bit matrix
  const std::size_t bit_size = receiver_provider_.GetNumOts();
  if (bit_size == 0) return;  // nothing to do

  // rounded up to a multiple of the security parameter
  const auto bit_size_padded = bit_size + kKappa - (bit_size % kKappa);

  // convert to bytes
  const std::size_t byte_size = BitsToBytes(bit_size);
  // XXX: if byte_size is 0 then bit_size was also zero (or an overflow happened
  if (byte_size == 0) {
    return;
  }
  // storage for receiver and base OT sender data
  const auto& base_ots_sender_data = base_ot_data_.GetSenderData();
  auto& ot_extension_receiver_data = data_.GetReceiverData();

  // make random choices (this is precomputation, real inputs are not known yet)
  ot_extension_receiver_data.random_choices =
      std::make_unique<AlignedBitVector>(AlignedBitVector::SecureRandom(bit_size));

  // create matrix with kKappa rows
  std::vector<AlignedBitVector> v(kKappa);

  // PRG we use with the fixed-key AES function

  // PRG which is used to expand the keys we got from the base OTs
  primitives::Prg prg_fixed_key, prg_variable_key;
  // fill the rows of the matrix
  for (i = 0; i < kKappa; ++i) {
    // generate rows of the matrix using the corresponding 0 key
    // T[j] = Prg(s_{j,0})
    prg_variable_key.SetKey(base_ots_sender_data.messages_0.at(i).data());
    // change the offset in the output stream since we might have already used
    // the same base OTs previously
    prg_variable_key.SetOffset(base_ots_sender_data.consumed_offset);
    // expand the seed such that it fills one row of the matrix
    auto row(prg_variable_key.Encrypt(byte_size));
    v.at(i) = AlignedBitVector(std::move(row), bit_size);
    // take a copy of the row and XOR it with our choices
    auto u = v.at(i);
    // u_j = T[j] XOR r
    u ^= *ot_extension_receiver_data.random_choices;

    // now mask the result with random stream expanded from the 1 key
    // u_j = u_j XOR Prg(s_{j,1})
    prg_variable_key.SetKey(base_ots_sender_data.messages_1.at(i).data());
    prg_variable_key.SetOffset(base_ots_sender_data.consumed_offset);
    u ^= AlignedBitVector(prg_variable_key.Encrypt(byte_size), bit_size);

    // send this row
    send_function_(communication::BuildOtExtensionMessageReceiverMasks(u.GetData().data(),
                                                                       u.GetData().size(), i));
  }

  // transpose matrix T
  if (bit_size_padded != bit_size) {
    for (i = 0u; i < v.size(); ++i) {
      v.at(i).Resize(bit_size_padded, true);
    }
  }

  std::array<const std::byte*, kKappa> pointers;
  for (j = 0; j < pointers.size(); ++j) {
    pointers.at(j) = v.at(j).GetMutableData().data();
  }

  motion_base_provider_.Setup();
  const auto& fixed_key_aes_key = motion_base_provider_.GetAesFixedKey();
  prg_fixed_key.SetKey(fixed_key_aes_key.data());
  BitMatrix::ReceiverTransposeAndEncrypt(pointers, ot_extension_receiver_data.outputs,
                                         prg_fixed_key, bit_size_padded,
                                         ot_extension_receiver_data.bitlengths);
  /*BitMatrix::TransposeUsingBitSlicing(pointers, bit_size_padded);
  for (i = 0; i < ot_extension_receiver_data.outputs.size(); ++i) {
    const auto row_i = i % kKappa;
    const auto blk_offset = ((kKappa / 8) * (i / kKappa));
    const auto T_row = pointers.at(row_i) + blk_offset;
    auto &out = ot_extension_receiver_data.outputs.at(i);

    std::unique_lock lock(ot_extension_receiver_data.bitlengths_mutex);
    const std::size_t bitlength = ot_extension_receiver_data.bitlengths.at(i);
    lock.unlock();

    if (bitlength <= kKappa) {
      out = BitVector<>(prg_fixed_key.FixedKeyAes(T_row, i), bitlength);
    } else {
      auto seed = prg_fixed_key.FixedKeyAes(T_row, i);
      prg_variable_key.SetKey(seed.data());
      out = BitVector<>(prg_variable_key.Encrypt(BitsToBytes(bitlength)), bitlength);
    }
  }*/

  {
    std::scoped_lock(ot_extension_receiver_data.setup_finished_condition->GetMutex());
    ot_extension_receiver_data.setup_finished = true;
  }
  ot_extension_receiver_data.setup_finished_condition->NotifyAll();
}

OtVector::OtVector(const std::size_t ot_id, const std::size_t number_of_ots,
                   const std::size_t bitlength, const OtProtocol p,
                   const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function)
    : ot_id_(ot_id),
      number_of_ots_(number_of_ots),
      bitlen_(bitlength),
      p_(p),
      send_function_(send_function) {}

const std::vector<BitVector<>>& OtVectorSender::GetOutputs() {
  WaitSetup();
  if (outputs_.empty()) {
    outputs_.reserve(number_of_ots_);
    for (auto i = 0ull; i < number_of_ots_; ++i) {
      BitVector bv;
      bv.Reserve(BitsToBytes(data_.y0.at(ot_id_ + i).GetSize() * 2));
      bv.Append(data_.y0.at(ot_id_ + i));
      bv.Append(data_.y1.at(ot_id_ + i));
      outputs_.emplace_back(std::move(bv));
    }
  }
  return outputs_;
}

void OtVectorSender::WaitSetup() { data_.setup_finished_condition->Wait(); }

OtVectorSender::OtVectorSender(
    const std::size_t ot_id, const std::size_t number_of_ots, const std::size_t bitlength,
    const OtProtocol p, OtExtensionSenderData& data,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function)
    : OtVector(ot_id, number_of_ots, bitlength, p, send_function), data_(data) {
  Reserve(ot_id, number_of_ots, bitlength);
}

void OtVectorSender::Reserve(const std::size_t id, const std::size_t number_of_ots,
                             const std::size_t bitlength) {
  data_.y0.resize(data_.y0.size() + number_of_ots);
  data_.y1.resize(data_.y1.size() + number_of_ots);
  data_.bitlengths.resize(data_.bitlengths.size() + number_of_ots);
  data_.corrections.Resize(data_.corrections.GetSize() + number_of_ots);
  for (auto i = 0ull; i < number_of_ots; ++i) {
    data_.bitlengths.at(data_.bitlengths.size() - 1 - i) = bitlength;
  }
  data_.number_of_ots_in_batch.emplace(id, number_of_ots);
}

GOtVectorSender::GOtVectorSender(
    const std::size_t ot_id, const std::size_t number_of_ots, const std::size_t bitlength,
    OtExtensionSenderData& data,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function)
    : OtVectorSender(ot_id, number_of_ots, bitlength, OtProtocol::kGOt, data, send_function) {
  data_.received_correction_offsets_condition.emplace(
      ot_id_, std::make_unique<FiberCondition>([ot_id, this]() {
        std::scoped_lock lock(data_.corrections_mutex);
        return data_.received_correction_offsets.find(ot_id) !=
               data_.received_correction_offsets.end();
      }));
}

void GOtVectorSender::SetInputs(std::vector<BitVector<>>&& v) {
  for ([[maybe_unused]] auto& bv : v) {
    assert(bv.GetSize() == (bitlen_ * 2));
  }
  inputs_ = std::move(v);
  outputs_ = inputs_;
}

void GOtVectorSender::SetInputs(const std::vector<BitVector<>>& v) {
  for ([[maybe_unused]] auto& bv : v) {
    assert(bv.GetSize() == (bitlen_ * 2));
  }
  inputs_ = v;
  outputs_ = inputs_;
}

// blocking wait for correction bits
void GOtVectorSender::SendMessages() {
  assert(!inputs_.empty());
  WaitSetup();
  const auto& ot_extension_sender_data = data_;
  ot_extension_sender_data.received_correction_offsets_condition.at(ot_id_)->Wait();
  std::unique_lock lock(ot_extension_sender_data.corrections_mutex);
  const auto corrections =
      ot_extension_sender_data.corrections.Subset(ot_id_, ot_id_ + number_of_ots_);
  lock.unlock();
  assert(inputs_.size() == corrections.GetSize());

  BitVector<> buffer;
  for (auto i = 0ull; i < number_of_ots_; ++i) {
    const auto bv_0 = inputs_.at(i).Subset(0, bitlen_);
    const auto bv_1 = inputs_.at(i).Subset(bitlen_, bitlen_ * 2);
    if (corrections[i]) {
      buffer.Append(bv_1 ^ ot_extension_sender_data.y0.at(ot_id_ + i));
      buffer.Append(bv_0 ^ ot_extension_sender_data.y1.at(ot_id_ + i));
    } else {
      buffer.Append(bv_0 ^ ot_extension_sender_data.y0.at(ot_id_ + i));
      buffer.Append(bv_1 ^ ot_extension_sender_data.y1.at(ot_id_ + i));
    }
  }
  send_function_(communication::BuildOtExtensionMessageSender(buffer.GetData().data(),
                                                              buffer.GetData().size(), ot_id_));
}

COtVectorSender::COtVectorSender(
    const std::size_t id, const std::size_t number_of_ots, const std::size_t bitlength,
    OtProtocol p, OtExtensionSenderData& data,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function)
    : OtVectorSender(id, number_of_ots, bitlength, p, data, send_function) {
  if (p == OtProtocol::kAcOt && (bitlength != 8u && bitlength != 16u && bitlength != 32u &&
                                 bitlength != 64u && bitlength != 128)) {
    throw std::runtime_error(fmt::format(
        "Invalid parameter bitlength={}, only 8, 16, 32, 64, or 128 are allowed in ACOT", bitlen_));
  }
  data_.received_correction_offsets_condition.emplace(
      ot_id_, std::make_unique<FiberCondition>([this]() {
        std::scoped_lock lock(data_.corrections_mutex);
        return data_.received_correction_offsets.find(ot_id_) !=
               data_.received_correction_offsets.end();
      }));
}

void COtVectorSender::SetInputs(std::vector<BitVector<>>&& v) {
  for ([[maybe_unused]] auto& bv : v) {
    assert(bv.GetSize() == (bitlen_));
  }
  inputs_ = std::move(v);
}

void COtVectorSender::SetInputs(const std::vector<BitVector<>>& v) {
  for ([[maybe_unused]] auto& bv : v) {
    assert(bv.GetSize() == (bitlen_));
  }
  inputs_ = v;
}

const std::vector<BitVector<>>& COtVectorSender::GetOutputs() {
  if (inputs_.empty()) {
    throw std::runtime_error("Inputs have to be chosen before calling GetOutputs()");
  }
  WaitSetup();
  const auto& ot_extension_sender_data = data_;
  ot_extension_sender_data.received_correction_offsets_condition.at(ot_id_)->Wait();
  if (outputs_.empty()) {
    outputs_.reserve(number_of_ots_);
    std::unique_lock lock(ot_extension_sender_data.corrections_mutex);
    const auto corrections =
        ot_extension_sender_data.corrections.Subset(ot_id_, ot_id_ + number_of_ots_);
    lock.unlock();
    for (auto i = 0ull; i < number_of_ots_; ++i) {
      BitVector<> bv;
      bv.Reserve(BitsToBytes(ot_extension_sender_data.y1.at(ot_id_ + i).GetSize() * 2));
      if (corrections[i]) {
        bv.Append(ot_extension_sender_data.y1.at(ot_id_ + i));
      } else {
        bv.Append(ot_extension_sender_data.y0.at(ot_id_ + i));
      }
      if (p_ == OtProtocol::kAcOt) {
        if (corrections[i]) {
          bv.Append(ot_extension_sender_data.y1.at(ot_id_ + i));
        } else {
          bv.Append(ot_extension_sender_data.y0.at(ot_id_ + i));
        }
        switch (bitlen_) {
          case (8u): {
            *reinterpret_cast<uint8_t*>(bv.GetMutableData().data() + 1) +=
                *reinterpret_cast<const uint8_t*>(inputs_.at(i).GetData().data());
            break;
          }
          case (16u): {
            *reinterpret_cast<uint16_t*>(bv.GetMutableData().data() + 2) +=
                *reinterpret_cast<const uint16_t*>(inputs_.at(i).GetData().data());
            break;
          }
          case (32u): {
            *reinterpret_cast<uint32_t*>(bv.GetMutableData().data() + 4) +=
                *reinterpret_cast<const uint32_t*>(inputs_.at(i).GetData().data());
            break;
          }
          case (64u): {
            *reinterpret_cast<uint64_t*>(bv.GetMutableData().data() + 8) +=
                *reinterpret_cast<const uint64_t*>(inputs_.at(i).GetData().data());
            break;
          }
          case (128u): {
            *reinterpret_cast<__uint128_t*>(bv.GetMutableData().data() + 16) +=
                *reinterpret_cast<const __uint128_t*>(inputs_.at(i).GetData().data());
            break;
          }
        }
      } else {  // OtProtocol::kXcOt
        bv.Append(inputs_.at(i) ^ bv);
      }
      outputs_.emplace_back(std::move(bv));
    }
  }
  return outputs_;
}

void COtVectorSender::SendMessages() {
  if (inputs_.empty()) {
    throw std::runtime_error("Inputs have to be chosen before calling SendMessages()");
  }
  WaitSetup();
  const auto& ot_extension_sender_data = data_;
  BitVector<> buffer;
  std::size_t ot_batch_bit_size = 0;
  for (auto i = 0ull; i < number_of_ots_; ++i)
    ot_batch_bit_size += ot_extension_sender_data.y0.at(ot_id_ + i).GetSize();
  buffer.Reserve(BitsToBytes(ot_batch_bit_size));
  for (auto i = 0ull; i < number_of_ots_; ++i) {
    if (p_ == OtProtocol::kAcOt) {
      BitVector bv = ot_extension_sender_data.y0.at(ot_id_ + i);
      switch (bitlen_) {
        case 8u: {
          *(reinterpret_cast<std::uint8_t*>(bv.GetMutableData().data())) +=
              *(reinterpret_cast<const std::uint8_t*>(inputs_.at(i).GetData().data()));
          *(reinterpret_cast<std::uint8_t*>(bv.GetMutableData().data())) +=
              *(reinterpret_cast<const std::uint8_t*>(
                  ot_extension_sender_data.y1.at(ot_id_ + i).GetData().data()));

          break;
        }
        case 16u: {
          *(reinterpret_cast<std::uint16_t*>(bv.GetMutableData().data())) +=
              *(reinterpret_cast<const std::uint16_t*>(inputs_.at(i).GetData().data()));
          *(reinterpret_cast<std::uint16_t*>(bv.GetMutableData().data())) +=
              *(reinterpret_cast<const std::uint16_t*>(
                  ot_extension_sender_data.y1.at(ot_id_ + i).GetData().data()));
          break;
        }
        case 32u: {
          *(reinterpret_cast<std::uint32_t*>(bv.GetMutableData().data())) +=
              *(reinterpret_cast<const std::uint32_t*>(inputs_.at(i).GetData().data()));
          *(reinterpret_cast<std::uint32_t*>(bv.GetMutableData().data())) +=
              *(reinterpret_cast<const std::uint32_t*>(
                  ot_extension_sender_data.y1.at(ot_id_ + i).GetData().data()));
          break;
        }
        case 64u: {
          *(reinterpret_cast<std::uint64_t*>(bv.GetMutableData().data())) +=
              *(reinterpret_cast<const std::uint64_t*>(inputs_.at(i).GetData().data()));
          *(reinterpret_cast<std::uint64_t*>(bv.GetMutableData().data())) +=
              *(reinterpret_cast<const std::uint64_t*>(
                  ot_extension_sender_data.y1.at(ot_id_ + i).GetData().data()));
          break;
        }
        case 128u: {
          *(reinterpret_cast<__uint128_t*>(bv.GetMutableData().data())) +=
              *(reinterpret_cast<const __uint128_t*>(inputs_.at(i).GetData().data()));
          *(reinterpret_cast<__uint128_t*>(bv.GetMutableData().data())) +=
              *(reinterpret_cast<const __uint128_t*>(
                  ot_extension_sender_data.y1.at(ot_id_ + i).GetData().data()));
          break;
        }
        default: {
          throw std::runtime_error(fmt::format("Unsupported bitlength {}", bitlen_));
        }
      }
      buffer.Append(bv);
    } else if (p_ == OtProtocol::kXcOt) {
      buffer.Append(inputs_.at(i) ^ ot_extension_sender_data.y0.at(ot_id_ + i) ^
                    ot_extension_sender_data.y1.at(ot_id_ + i));
    } else {
      throw std::runtime_error("Unknown OT protocol");
    }
  }
  send_function_(communication::BuildOtExtensionMessageSender(buffer.GetData().data(),
                                                              buffer.GetData().size(), ot_id_));
}

ROtVectorSender::ROtVectorSender(
    const std::size_t ot_id, const std::size_t number_of_ots, const std::size_t bitlength,
    OtExtensionSenderData& data,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function)
    : OtVectorSender(ot_id, number_of_ots, bitlength, OtProtocol::kROt, data, send_function) {}

void ROtVectorSender::SetInputs([[maybe_unused]] std::vector<BitVector<>>&& v) {
  throw std::runtime_error("Inputs are random in ROT and thus cannot be set");
}

void ROtVectorSender::SetInputs([[maybe_unused]] const std::vector<BitVector<>>& v) {
  throw std::runtime_error("Inputs are random in ROT and thus cannot be set");
}

void ROtVectorSender::SendMessages() {
  throw std::runtime_error("Inputs in ROT are available locally and thus do not need to be sent");
}

void OtVectorReceiver::WaitSetup() { data_.setup_finished_condition->Wait(); }

OtVectorReceiver::OtVectorReceiver(
    const std::size_t ot_id, const std::size_t number_of_ots, const std::size_t bitlength,
    const OtProtocol p, OtExtensionReceiverData& data,
    std::function<void(flatbuffers::FlatBufferBuilder&&)> send_function)
    : OtVector(ot_id, number_of_ots, bitlength, p, send_function), data_(data) {
  Reserve(ot_id, number_of_ots, bitlength);
}

void OtVectorReceiver::Reserve(const std::size_t id, const std::size_t number_of_ots,
                               const std::size_t bitlength) {
  data_.outputs.resize(id + number_of_ots);
  data_.bitlengths.resize(id + number_of_ots);
  for (auto i = 0ull; i < number_of_ots; ++i) {
    data_.bitlengths.at(id + i) = bitlength;
  }
  data_.number_of_ots_in_batch.emplace(id, number_of_ots);
}

GOtVectorReceiver::GOtVectorReceiver(
    const std::size_t ot_id, const std::size_t number_of_ots, const std::size_t bitlength,
    OtExtensionReceiverData& data,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function)
    : OtVectorReceiver(ot_id, number_of_ots, bitlength, OtProtocol::kGOt, data, send_function) {
  std::scoped_lock lock(data_.number_of_messages_to_be_sent_mutex);
  data_.number_of_messages_to_be_sent.emplace(ot_id_, 2);
}

void GOtVectorReceiver::SetChoices(BitVector<>&& v) {
  assert(v.GetSize() == number_of_ots_);
  choices_ = std::move(v);
  {
    std::scoped_lock lock(data_.real_choices_mutex,
                          data_.real_choices_condition.at(ot_id_)->GetMutex());
    data_.real_choices->Copy(ot_id_, choices_);
    data_.set_real_choices.emplace(ot_id_);
  }
  data_.real_choices_condition.at(ot_id_)->NotifyOne();
  choices_flag_ = true;
}

void GOtVectorReceiver::SetChoices(const BitVector<>& v) {
  assert(v.GetSize() == number_of_ots_);
  choices_ = v;
  {
    std::scoped_lock lock(data_.real_choices_mutex,
                          data_.real_choices_condition.at(ot_id_)->GetMutex());
    data_.real_choices->Copy(ot_id_, choices_);
    data_.set_real_choices.emplace(ot_id_);
  }
  data_.real_choices_condition.at(ot_id_)->NotifyOne();
  choices_flag_ = true;
}

void GOtVectorReceiver::SendCorrections() {
  if (choices_.Empty()) {
    throw std::runtime_error("Choices in GOT must be set before calling SendCorrections()");
  }

  auto corrections = choices_ ^ data_.random_choices->Subset(ot_id_, ot_id_ + number_of_ots_);
  send_function_(communication::BuildOtExtensionMessageReceiverCorrections(
      corrections.GetData().data(), corrections.GetData().size(), ot_id_));
  corrections_sent_ = true;
}

const std::vector<BitVector<>>& GOtVectorReceiver::GetOutputs() {
  if (!corrections_sent_) {
    throw std::runtime_error("In GOT, corrections must be set before calling GetOutputs()");
  }
  WaitSetup();
  const auto& ot_extension_receiver_data = data_;
  ot_extension_receiver_data.output_conditions.at(ot_id_)->Wait();
  if (messages_.empty()) {
    for (auto i = 0ull; i < number_of_ots_; ++i) {
      if (ot_extension_receiver_data.outputs.at(ot_id_ + i).GetSize() > 0) {
        messages_.emplace_back(std::move(ot_extension_receiver_data.outputs.at(ot_id_ + i)));
      }
    }
  }
  return messages_;
}

COtVectorReceiver::COtVectorReceiver(
    const std::size_t ot_id, const std::size_t number_of_ots, const std::size_t bitlength,
    OtProtocol p, OtExtensionReceiverData& data,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function)
    : OtVectorReceiver(ot_id, number_of_ots, bitlength, p, data, send_function) {
  if (p == OtProtocol::kAcOt && (bitlength != 8u && bitlength != 16u && bitlength != 32u &&
                                 bitlength != 64u && bitlength != 128u)) {
    throw std::runtime_error(fmt::format(
        "Invalid parameter bitlength={}, only 8, 16, 32, 64, or 128 are allowed in ACOT", bitlen_));
  }
  {
    std::scoped_lock lock(data_.number_of_messages_to_be_sent_mutex);
    data_.number_of_messages_to_be_sent.emplace(ot_id_, 1);
  }
  if (p == OtProtocol::kXcOt) {
    data_.xor_correlation.emplace(ot_id_);
  }
}

void COtVectorReceiver::SendCorrections() {
  if (choices_.Empty()) {
    throw std::runtime_error("Choices in COT must be set before calling SendCorrections()");
  }
  auto corrections = choices_ ^ data_.random_choices->Subset(ot_id_, ot_id_ + number_of_ots_);
  send_function_(communication::BuildOtExtensionMessageReceiverCorrections(
      corrections.GetData().data(), corrections.GetData().size(), ot_id_));
  corrections_sent_ = true;
}

void COtVectorReceiver::SetChoices(BitVector<>&& v) {
  choices_ = std::move(v);
  {
    std::scoped_lock lock(data_.real_choices_mutex,
                          data_.real_choices_condition.at(ot_id_)->GetMutex());
    data_.real_choices->Copy(ot_id_, choices_);
    data_.set_real_choices.emplace(ot_id_);
  }
  data_.real_choices_condition.at(ot_id_)->NotifyOne();
  choices_flag_ = true;
}

void COtVectorReceiver::SetChoices(const BitVector<>& v) {
  choices_ = v;
  {
    std::scoped_lock lock(data_.real_choices_mutex,
                          data_.real_choices_condition.at(ot_id_)->GetMutex());
    data_.real_choices->Copy(ot_id_, choices_);
    data_.set_real_choices.emplace(ot_id_);
  }
  data_.real_choices_condition.at(ot_id_)->NotifyOne();
  choices_flag_ = true;
}

const std::vector<BitVector<>>& COtVectorReceiver::GetOutputs() {
  if (!corrections_sent_) {
    throw std::runtime_error("In COT, corrections must be set before calling GetOutputs()");
  }
  WaitSetup();
  data_.output_conditions.at(ot_id_)->Wait();

  if (messages_.empty()) {
    messages_.reserve(number_of_ots_);
    for (auto i = 0ull; i < number_of_ots_; ++i) {
      if (data_.outputs.at(ot_id_ + i).GetSize() > 0) {
        messages_.emplace_back(std::move(data_.outputs.at(ot_id_ + i)));
      }
    }
  }
  return messages_;
}

ROtVectorReceiver::ROtVectorReceiver(
    const std::size_t ot_id, const std::size_t number_of_ots, const std::size_t bitlength,
    OtExtensionReceiverData& data,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function)
    : OtVectorReceiver(ot_id, number_of_ots, bitlength, OtProtocol::kROt, data, send_function) {
  Reserve(ot_id, number_of_ots, bitlength);
}

void ROtVectorReceiver::SetChoices([[maybe_unused]] const BitVector<>& v) {
  throw std::runtime_error("Choices are random in ROT and thus cannot be set");
}

void ROtVectorReceiver::SetChoices([[maybe_unused]] BitVector<>&& v) {
  throw std::runtime_error("Choices are random in ROT and thus cannot be set");
}

void ROtVectorReceiver::SendCorrections() {
  throw std::runtime_error(
      "Choices are random in ROT and thus there is no need for correction bits");
}

const BitVector<>& ROtVectorReceiver::GetChoices() {
  WaitSetup();
  if (choices_.Empty()) {
    const auto a_bv = data_.random_choices->Subset(ot_id_, ot_id_ + number_of_ots_);
    choices_ = BitVector<>(a_bv.GetData().data(), a_bv.GetSize());
  }
  return choices_;
}

const std::vector<BitVector<>>& ROtVectorReceiver::GetOutputs() {
  WaitSetup();
  if (messages_.empty()) {
    const auto data = data_.outputs.begin();
    messages_.assign(data + ot_id_, data + ot_id_ + number_of_ots_);
  }
  return messages_;
}

std::shared_ptr<OtVectorSender>& OtProviderSender::GetOts(std::size_t offset) {
  auto iterator = sender_data_.find(offset);
  if (iterator == sender_data_.end()) {
    throw std::runtime_error(fmt::format("Could not find an OtVector with offset {}", offset));
  }
  return iterator->second;
}

std::shared_ptr<OtVectorSender>& OtProviderSender::RegisterOts(
    const std::size_t bitlength, const std::size_t number_of_ots, const OtProtocol p,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function) {
  const auto i = total_ots_count_;
  total_ots_count_ += number_of_ots;
  std::shared_ptr<OtVectorSender> ot;
  switch (p) {
    case OtProtocol::kGOt: {
      ot = std::make_shared<GOtVectorSender>(i, number_of_ots, bitlength, data_, send_function);
      if constexpr (kDebug) {
        if (logger_) {
          logger_->LogDebug(fmt::format("Party#{}: registered {} parallel {}-bit sender GOTs",
                                        party_id_, number_of_ots, bitlength));
        }
      }
      break;
    }
    case OtProtocol::kAcOt: {
      ot = std::make_shared<COtVectorSender>(i, number_of_ots, bitlength, p, data_, send_function);
      if constexpr (kDebug) {
        if (logger_) {
          logger_->LogDebug(fmt::format("Party#{}: registered {} parallel {}-bit sender ACOTs",
                                        party_id_, number_of_ots, bitlength));
        }
      }
      break;
    }
    case OtProtocol::kXcOt: {
      ot = std::make_shared<COtVectorSender>(i, number_of_ots, bitlength, p, data_, send_function);
      if constexpr (kDebug) {
        if (logger_) {
          logger_->LogDebug(fmt::format("Party#{}: registered {} parallel {}-bit sender XCOTs",
                                        party_id_, number_of_ots, bitlength));
        }
      }
      break;
    }
    case OtProtocol::kROt: {
      ot = std::make_shared<ROtVectorSender>(i, number_of_ots, bitlength, data_, send_function);
      if constexpr (kDebug) {
        if (logger_) {
          logger_->LogDebug(fmt::format("Party#{}: registered {} parallel {}-bit sender ROTs",
                                        party_id_, number_of_ots, bitlength));
        }
      }
      break;
    }
    default:
      throw std::logic_error("Unknown OT protocol");
  }
  return sender_data_.insert(std::pair(i, ot)).first->second;
}

std::unique_ptr<FixedXcOt128Sender> OtProviderSender::RegisterFixedXcOt128s(
    const std::size_t number_of_ots,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function) {
  const auto i = total_ots_count_;
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<FixedXcOt128Sender>(i, number_of_ots, data_, send_function);
  if constexpr (kDebug) {
    if (logger_) {
      logger_->LogDebug(fmt::format("Party#{}: registered {} parallel {}-bit sender FixedXCOT128s",
                                    party_id_, number_of_ots, 128));
    }
  }
  return ot;
}

std::unique_ptr<XcOtBitSender> OtProviderSender::RegisterXcOtBits(
    const std::size_t number_of_ots,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function) {
  const auto i = total_ots_count_;
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<XcOtBitSender>(i, number_of_ots, data_, send_function);
  if constexpr (kDebug) {
    if (logger_) {
      logger_->LogDebug(fmt::format("Party#{}: registered {} parallel {}-bit sender XCOTBits",
                                    party_id_, number_of_ots, 1));
    }
  }
  return ot;
}

template <typename T>
std::unique_ptr<AcOtSender<T>> OtProviderSender::RegisterAcOt(
    std::size_t number_of_ots, std::size_t vector_size,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function) {
  const auto i = total_ots_count_;
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<AcOtSender<T>>(i, number_of_ots, vector_size, data_, send_function);
  if constexpr (kDebug) {
    if (logger_) {
      logger_->LogDebug(fmt::format("Party#{}: registered {} parallel {}-bit sender ACOTs",
                                    party_id_, number_of_ots, 8 * sizeof(T)));
    }
  }
  return ot;
}

template std::unique_ptr<AcOtSender<std::uint8_t>> OtProviderSender::RegisterAcOt(
    std::size_t number_of_ots, std::size_t vector_size,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function);
template std::unique_ptr<AcOtSender<std::uint16_t>> OtProviderSender::RegisterAcOt(
    std::size_t number_of_ots, std::size_t vector_size,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function);
template std::unique_ptr<AcOtSender<std::uint32_t>> OtProviderSender::RegisterAcOt(
    std::size_t number_of_ots, std::size_t vector_size,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function);
template std::unique_ptr<AcOtSender<std::uint64_t>> OtProviderSender::RegisterAcOt(
    std::size_t number_of_ots, std::size_t vector_size,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function);
template std::unique_ptr<AcOtSender<__uint128_t>> OtProviderSender::RegisterAcOt(
    std::size_t number_of_ots, std::size_t vector_size,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function);

std::unique_ptr<GOt128Sender> OtProviderSender::RegisterGOt128(
    const std::size_t number_of_ots,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function) {
  const auto i = total_ots_count_;
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<GOt128Sender>(i, number_of_ots, data_, send_function);
  if constexpr (kDebug) {
    if (logger_) {
      logger_->LogDebug(fmt::format("Party#{}: registered {} parallel {}-bit sender GOT128s",
                                    party_id_, number_of_ots, 128));
    }
  }
  return ot;
}

std::unique_ptr<GOtBitSender> OtProviderSender::RegisterGOtBit(
    const std::size_t number_of_ots,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function) {
  const auto i = total_ots_count_;
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<GOtBitSender>(i, number_of_ots, data_, send_function);
  if constexpr (kDebug) {
    if (logger_) {
      logger_->LogDebug(fmt::format("Party#{}: registered {} parallel {}-bit sender GOTBits",
                                    party_id_, number_of_ots, 1));
    }
  }
  return ot;
}

void OtProviderSender::Clear() {
  // TODO: move this
  // data_storage_->GetBaseOTsData()->GetSenderData().consumed_offset += total_ots_count_;

  total_ots_count_ = 0;

  {
    std::scoped_lock lock(data_.setup_finished_condition->GetMutex());
    data_.setup_finished = false;
  }
  {
    std::scoped_lock lock(data_.corrections_mutex);
    data_.received_correction_offsets.clear();
  }
}

void OtProviderSender::Reset() {
  Clear();
  // TODO
}

std::shared_ptr<OtVectorReceiver>& OtProviderReceiver::GetOts(std::size_t offset) {
  auto iterator = receiver_data_.find(offset);
  if (iterator == receiver_data_.end()) {
    throw std::runtime_error(fmt::format("Could not find an OtVector with offset {}", offset));
  }
  return iterator->second;
}

std::shared_ptr<OtVectorReceiver>& OtProviderReceiver::RegisterOts(
    const std::size_t bitlength, const std::size_t number_of_ots, const OtProtocol p,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function) {
  const std::size_t i = total_ots_count_;
  total_ots_count_ += number_of_ots;

  if (p != OtProtocol::kROt) {
    {
      auto&& e = std::pair(i, std::make_unique<FiberCondition>([i, this]() {
                             std::scoped_lock lock(data_.received_outputs_mutex);
                             return data_.received_outputs.find(i) != data_.received_outputs.end();
                           }));
      data_.output_conditions.insert(std::move(e));
    }
    {
      auto&& e = std::pair(i, std::make_unique<FiberCondition>([i, this]() {
                             std::scoped_lock lock(data_.real_choices_mutex);
                             return data_.set_real_choices.find(i) != data_.set_real_choices.end();
                           }));
      std::scoped_lock lock(data_.real_choices_mutex);
      data_.real_choices_condition.insert(std::move(e));
    }
  }

  std::shared_ptr<OtVectorReceiver> ot;

  switch (p) {
    case OtProtocol::kGOt: {
      ot = std::make_shared<GOtVectorReceiver>(i, number_of_ots, bitlength, data_, send_function);
      if constexpr (kDebug) {
        if (logger_) {
          logger_->LogDebug(fmt::format("Party#{}: registered {} parallel {}-bit receiver GOTs",
                                        party_id_, number_of_ots, bitlength));
        }
      }
      break;
    }
    case OtProtocol::kXcOt: {
      ot =
          std::make_shared<COtVectorReceiver>(i, number_of_ots, bitlength, p, data_, send_function);
      if constexpr (kDebug) {
        if (logger_) {
          logger_->LogDebug(fmt::format("Party#{}: registered {} parallel {}-bit receiver XCOTs",
                                        party_id_, number_of_ots, bitlength));
        }
      }
      break;
    }
    case OtProtocol::kAcOt: {
      ot =
          std::make_shared<COtVectorReceiver>(i, number_of_ots, bitlength, p, data_, send_function);
      if constexpr (kDebug) {
        if (logger_) {
          logger_->LogDebug(fmt::format("Party#{}: registered {} parallel {}-bit receiver ACOTs",
                                        party_id_, number_of_ots, bitlength));
        }
      }
      break;
    }
    case OtProtocol::kROt: {
      ot = std::make_shared<ROtVectorReceiver>(i, number_of_ots, bitlength, data_, send_function);
      if constexpr (kDebug) {
        if (logger_) {
          logger_->LogDebug(fmt::format("Party#{}: registered {} parallel {}-bit receiver ROTs",
                                        party_id_, number_of_ots, bitlength));
        }
      }
      break;
    }
    default:
      throw std::runtime_error("Unknown OT protocol");
  }

  auto&& e = std::pair(i, ot);
  data_.real_choices->Resize(total_ots_count_, false);
  return receiver_data_.insert(std::move(e)).first->second;
}

std::unique_ptr<FixedXcOt128Receiver> OtProviderReceiver::RegisterFixedXcOt128s(
    const std::size_t number_of_ots,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function) {
  const auto i = total_ots_count_.load();
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<FixedXcOt128Receiver>(i, number_of_ots, data_, send_function);
  if constexpr (kDebug) {
    if (logger_) {
      logger_->LogDebug(
          fmt::format("Party#{}: registered {} parallel {}-bit receiver FixedXCOT128s", party_id_,
                      number_of_ots, 128));
    }
  }
  return ot;
}

std::unique_ptr<XcOtBitReceiver> OtProviderReceiver::RegisterXcOtBits(
    const std::size_t number_of_ots,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function) {
  const auto i = total_ots_count_.load();
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<XcOtBitReceiver>(i, number_of_ots, data_, send_function);
  if constexpr (kDebug) {
    if (logger_) {
      logger_->LogDebug(fmt::format("Party#{}: registered {} parallel {}-bit receiver XCOTBits",
                                    party_id_, number_of_ots, 1));
    }
  }
  return ot;
}

template <typename T>
std::unique_ptr<AcOtReceiver<T>> OtProviderReceiver::RegisterAcOt(
    std::size_t number_of_ots, std::size_t vector_size,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function) {
  const auto i = total_ots_count_.load();
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<AcOtReceiver<T>>(i, number_of_ots, vector_size, data_, send_function);
  if constexpr (kDebug) {
    if (logger_) {
      logger_->LogDebug(fmt::format("Party#{}: registered {} parallel {}-bit receiver ACOTs",
                                    party_id_, number_of_ots, 8 * sizeof(T)));
    }
  }
  return ot;
}

template std::unique_ptr<AcOtReceiver<std::uint8_t>> OtProviderReceiver::RegisterAcOt(
    std::size_t number_of_ots, std::size_t vector_size,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function);
template std::unique_ptr<AcOtReceiver<std::uint16_t>> OtProviderReceiver::RegisterAcOt(
    std::size_t number_of_ots, std::size_t vector_size,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function);
template std::unique_ptr<AcOtReceiver<std::uint32_t>> OtProviderReceiver::RegisterAcOt(
    std::size_t number_of_ots, std::size_t vector_size,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function);
template std::unique_ptr<AcOtReceiver<std::uint64_t>> OtProviderReceiver::RegisterAcOt(
    std::size_t number_of_ots, std::size_t vector_size,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function);
template std::unique_ptr<AcOtReceiver<__uint128_t>> OtProviderReceiver::RegisterAcOt(
    std::size_t number_of_ots, std::size_t vector_size,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function);

std::unique_ptr<GOt128Receiver> OtProviderReceiver::RegisterGOt128(
    const std::size_t number_of_ots,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function) {
  const auto i = total_ots_count_.load();
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<GOt128Receiver>(i, number_of_ots, data_, send_function);
  if constexpr (kDebug) {
    if (logger_) {
      logger_->LogDebug(fmt::format("Party#{}: registered {} parallel {}-bit receiver GOT128s",
                                    party_id_, number_of_ots, 128));
    }
  }
  return ot;
}

std::unique_ptr<GOtBitReceiver> OtProviderReceiver::RegisterGOtBit(
    const std::size_t number_of_ots,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function) {
  const auto i = total_ots_count_.load();
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<GOtBitReceiver>(i, number_of_ots, data_, send_function);
  if constexpr (kDebug) {
    if (logger_) {
      logger_->LogDebug(fmt::format("Party#{}: registered {} parallel {}-bit receiver GOTBits",
                                    party_id_, number_of_ots, 1));
    }
  }
  return ot;
}

void OtProviderReceiver::Clear() {
  // TODO: move this
  // data_storage_->GetBaseOTsData()->GetReceiverData().consumed_offset += total_ots_count_;
  //
  total_ots_count_ = 0;

  {
    std::scoped_lock lock(data_.setup_finished_condition->GetMutex());
    data_.setup_finished = false;
  }

  {
    std::scoped_lock lock(data_.real_choices_mutex);
    data_.set_real_choices.clear();
  }

  {
    std::scoped_lock lock(data_.received_outputs_mutex);
    data_.received_outputs.clear();
  }
}
void OtProviderReceiver::Reset() { Clear(); }

class OtExtensionMessageHandler : public communication::MessageHandler {
 public:
  OtExtensionMessageHandler(OtExtensionData& data) : data_(data) {}
  void ReceivedMessage(std::size_t, std::vector<std::uint8_t>&& message) override;

 private:
  OtExtensionData& data_;
};

void OtExtensionMessageHandler::ReceivedMessage(std::size_t,
                                                std::vector<std::uint8_t>&& raw_message) {
  assert(!raw_message.empty());
  auto message = communication::GetMessage(raw_message.data());
  auto message_type = message->message_type();
  auto index_i = communication::GetOtExtensionMessage(message->payload()->data())->i();
  auto ot_data = communication::GetOtExtensionMessage(message->payload()->data())->buffer()->data();
  auto ot_data_size =
      communication::GetOtExtensionMessage(message->payload()->data())->buffer()->size();
  switch (message_type) {
    case communication::MessageType::kOtExtensionReceiverMasks: {
      data_.MessageReceived(ot_data, ot_data_size, OtExtensionDataType::kReceptionMask, index_i);
      break;
    }
    case communication::MessageType::kOtExtensionReceiverCorrections: {
      data_.MessageReceived(ot_data, ot_data_size, OtExtensionDataType::kReceptionCorrection,
                            index_i);
      break;
    }
    case communication::MessageType::kOtExtensionSender: {
      data_.MessageReceived(ot_data, ot_data_size, OtExtensionDataType::kSendMessage, index_i);
      break;
    }
    default: {
      assert(false);
      break;
    }
  }
}

OtProviderManager::OtProviderManager(communication::CommunicationLayer& communication_layer,
                                     const BaseOtProvider& base_ot_provider,
                                     BaseProvider& motion_base_provider,
                                     std::shared_ptr<Logger> logger)
    : communication_layer_(communication_layer),
      number_of_parties_(communication_layer_.GetNumberOfParties()),
      providers_(number_of_parties_),
      data_(number_of_parties_) {
  auto my_id = communication_layer.GetMyId();
  for (std::size_t party_id = 0; party_id < number_of_parties_; ++party_id) {
    if (party_id == my_id) {
      continue;
    }
    auto send_function = [this, party_id](flatbuffers::FlatBufferBuilder&& message_builder) {
      communication_layer_.SendMessage(party_id, std::move(message_builder));
    };
    data_.at(party_id) = std::make_unique<OtExtensionData>();
    providers_.at(party_id) = std::make_unique<OtProviderFromOtExtension>(
        send_function, *data_.at(party_id), base_ot_provider.GetBaseOtsData(party_id),
        motion_base_provider, party_id, logger);
  }

  communication_layer_.RegisterMessageHandler(
      [this](std::size_t party_id) {
        return std::make_shared<OtExtensionMessageHandler>(*data_.at(party_id));
      },
      {communication::MessageType::kOtExtensionReceiverMasks,
       communication::MessageType::kOtExtensionReceiverCorrections,
       communication::MessageType::kOtExtensionSender});
}

OtProviderManager::~OtProviderManager() {
  communication_layer_.DeregisterMessageHandler(
      {communication::MessageType::kOtExtensionReceiverMasks,
       communication::MessageType::kOtExtensionReceiverCorrections,
       communication::MessageType::kOtExtensionSender});
}

}  // namespace encrypto::motion
