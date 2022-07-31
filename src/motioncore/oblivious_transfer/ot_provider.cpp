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
#include "communication/message.h"
#include "communication/message_manager.h"
#include "data_storage/base_ot_data.h"
#include "data_storage/ot_extension_data.h"
#include "primitives/pseudo_random_generator.h"
#include "utility/bit_matrix.h"
#include "utility/config.h"
#include "utility/fiber_condition.h"
#include "utility/logger.h"

namespace encrypto::motion {

std::size_t OtProviderFromOtExtension::GetPartyId() { return data_.party_id; }

[[nodiscard]] std::unique_ptr<ROtSender> OtProviderFromOtExtension::RegisterSendROt(
    std::size_t number_of_ots, std::size_t bitlength) {
  return sender_provider_.RegisterROt(number_of_ots, bitlength);
}

[[nodiscard]] std::unique_ptr<XcOtSender> OtProviderFromOtExtension::RegisterSendXcOt(
    std::size_t number_of_ots, std::size_t bitlength) {
  return sender_provider_.RegisterXcOt(number_of_ots, bitlength);
}

[[nodiscard]] std::unique_ptr<FixedXcOt128Sender>
OtProviderFromOtExtension::RegisterSendFixedXcOt128(std::size_t number_of_ots) {
  return sender_provider_.RegisterFixedXcOt128s(number_of_ots);
}

[[nodiscard]] std::unique_ptr<XcOtBitSender> OtProviderFromOtExtension::RegisterSendXcOtBit(
    std::size_t number_of_ots) {
  return sender_provider_.RegisterXcOtBits(number_of_ots);
}

[[nodiscard]] std::unique_ptr<BasicOtSender> OtProviderFromOtExtension::RegisterSendAcOt(
    std::size_t number_of_ots, std::size_t bitlength, std::size_t vector_size) {
  switch (bitlength) {
    case 8:
      return sender_provider_.RegisterAcOt<std::uint8_t>(number_of_ots, vector_size);
    case 16:
      return sender_provider_.RegisterAcOt<std::uint16_t>(number_of_ots, vector_size);
    case 32:
      return sender_provider_.RegisterAcOt<std::uint32_t>(number_of_ots, vector_size);
    case 64:
      return sender_provider_.RegisterAcOt<std::uint64_t>(number_of_ots, vector_size);
    case 128:
      return sender_provider_.RegisterAcOt<__uint128_t>(number_of_ots, vector_size);
    default:
      throw std::runtime_error(fmt::format("Bitlength {} is not supported", bitlength));
  }
}

[[nodiscard]] std::unique_ptr<GOtSender> OtProviderFromOtExtension::RegisterSendGOt(
    std::size_t number_of_ots, std::size_t bitlength) {
  return sender_provider_.RegisterGOt(number_of_ots, bitlength);
}

[[nodiscard]] std::unique_ptr<GOt128Sender> OtProviderFromOtExtension::RegisterSendGOt128(
    std::size_t number_of_ots) {
  return sender_provider_.RegisterGOt128(number_of_ots);
}

[[nodiscard]] std::unique_ptr<GOtBitSender> OtProviderFromOtExtension::RegisterSendGOtBit(
    std::size_t number_of_ots) {
  return sender_provider_.RegisterGOtBit(number_of_ots);
}

[[nodiscard]] std::unique_ptr<ROtReceiver> OtProviderFromOtExtension::RegisterReceiveROt(
    std::size_t number_of_ots, std::size_t bitlength) {
  return receiver_provider_.RegisterROt(number_of_ots, bitlength);
}

[[nodiscard]] std::unique_ptr<XcOtReceiver> OtProviderFromOtExtension::RegisterReceiveXcOt(
    std::size_t number_of_ots, std::size_t bitlength) {
  return receiver_provider_.RegisterXcOt(number_of_ots, bitlength);
}

[[nodiscard]] std::unique_ptr<FixedXcOt128Receiver>
OtProviderFromOtExtension::RegisterReceiveFixedXcOt128(std::size_t number_of_ots) {
  return receiver_provider_.RegisterFixedXcOt128s(number_of_ots);
}

[[nodiscard]] std::unique_ptr<XcOtBitReceiver> OtProviderFromOtExtension::RegisterReceiveXcOtBit(
    std::size_t number_of_ots) {
  return receiver_provider_.RegisterXcOtBits(number_of_ots);
}

[[nodiscard]] std::unique_ptr<BasicOtReceiver> OtProviderFromOtExtension::RegisterReceiveAcOt(
    std::size_t number_of_ots, std::size_t bitlength, std::size_t vector_size) {
  switch (bitlength) {
    case 8:
      return receiver_provider_.RegisterAcOt<std::uint8_t>(number_of_ots, vector_size);
    case 16:
      return receiver_provider_.RegisterAcOt<std::uint16_t>(number_of_ots, vector_size);
    case 32:
      return receiver_provider_.RegisterAcOt<std::uint32_t>(number_of_ots, vector_size);
    case 64:
      return receiver_provider_.RegisterAcOt<std::uint64_t>(number_of_ots, vector_size);
    case 128:
      return receiver_provider_.RegisterAcOt<__uint128_t>(number_of_ots, vector_size);
    default:
      throw std::runtime_error(fmt::format("Bitlength {} is not supported", bitlength));
  }
}

[[nodiscard]] std::unique_ptr<GOt128Receiver> OtProviderFromOtExtension::RegisterReceiveGOt128(
    std::size_t number_of_ots) {
  return receiver_provider_.RegisterGOt128(number_of_ots);
}

[[nodiscard]] std::unique_ptr<GOtBitReceiver> OtProviderFromOtExtension::RegisterReceiveGOtBit(
    std::size_t number_of_ots) {
  return receiver_provider_.RegisterGOtBit(number_of_ots);
}

[[nodiscard]] std::unique_ptr<GOtReceiver> OtProviderFromOtExtension::RegisterReceiveGOt(
    std::size_t number_of_ots, std::size_t bitlength) {
  return receiver_provider_.RegisterGOt(number_of_ots, bitlength);
}

OtProviderFromOtExtension::OtProviderFromOtExtension(OtExtensionData& data,
                                                     BaseOtProvider& base_ot_provider,
                                                     BaseProvider& motion_base_provider,
                                                     std::size_t party_id)
    : OtProvider(),
      data_(data),
      base_ot_provider_(base_ot_provider),
      motion_base_provider_(motion_base_provider),
      receiver_provider_(data_, party_id),
      sender_provider_(data_, party_id) {
  for (std::size_t i = 0; i < data_.sender_data.u_futures.size(); ++i) {
    data_.sender_data.u_futures[i] = data_.message_manager.RegisterReceive(
        party_id, communication::MessageType::kOtExtensionReceiverMasks, i);
  }
}

void OtProviderFromOtExtension::SetBaseOtOffset(std::size_t offset) {
  data_.base_ot_offset = offset;
}

std::size_t OtProviderFromOtExtension::GetBaseOtOffset() const { return data_.base_ot_offset; }

void OtProviderFromOtExtension::SendSetup() {
  // security parameter
  constexpr std::size_t kKappa = 128;

  // storage for sender and base OT receiver data
  const auto& base_ots_receiver_data =
      base_ot_provider_.GetBaseOtsData(data_.party_id).GetReceiverData();

  // number of OTs after extension
  // == width of the bit matrix
  const std::size_t bit_size = sender_provider_.GetNumOts();
  if (bit_size == 0) return;  // no OTs needed
  data_.sender_data.bit_size = bit_size;

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

  // fill the rows of the matrix, offset to differentiate other providers' base ots
  for (i = 0; i < kKappa; ++i) {
    // use the key we got from the base OTs as seed
    prgs_variable_key.SetKey(base_ots_receiver_data.messages_c.at(data_.base_ot_offset + i).data());
    // change the offset in the output stream since we might have already used
    // the same base OTs previously
    prgs_variable_key.SetOffset(data_.base_ot_offset);
    // expand the seed such that it fills one row of the matrix
    auto row(prgs_variable_key.Encrypt(byte_size));
    v[i] = AlignedBitVector(std::move(row), bit_size_padded);
  }

  // receive the vectors u one by one from the receiver
  // and xor them to the expanded keys if the corresponding selection bit is 1
  // transmitted one by one to prevent waiting for finishing all messages to start sending
  // the vectors can be transmitted in the wrong order

  for (i = 0; i < data_.sender_data.u_futures.size(); ++i) {
    auto raw_message{data_.sender_data.u_futures[i].get()};
    if (base_ots_receiver_data.c[data_.base_ot_offset + i]) {
      BitSpan bit_span_u(const_cast<std::uint8_t*>(
                             communication::GetMessage(raw_message.data())->payload()->data()),
                         bit_size);
      BitSpan bit_span_v(v[i].GetMutableData().data(), bit_size, true);
      bit_span_v ^= bit_span_u;
    }
  }

  // array with pointers to each row of the matrix
  std::array<const std::byte*, kKappa> pointers;
  for (i = 0u; i < pointers.size(); ++i) {
    pointers[i] = v[i].GetData().data();
  }
  const auto& fixed_key_aes_key = motion_base_provider_.GetAesFixedKey();

  // for each (extended) OT i
  primitives::Prg prg_fixed_key;
  prg_fixed_key.SetKey(fixed_key_aes_key.data());

  // transpose the bit matrix
  // XXX: figure out how the result looks like
  BitMatrix::SenderTranspose128AndEncrypt(
      pointers, data_.sender_data.y0, data_.sender_data.y1,
      base_ots_receiver_data.c.Subset(data_.base_ot_offset, data_.base_ot_offset + kKappa),
      prg_fixed_key, bit_size_padded, data_.sender_data.bitlengths);

  // we are done with the setup for the sender side
  data_.sender_data.SetSetupIsReady();
  SetSetupIsReady();
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
  const auto& base_ots_sender_data =
      base_ot_provider_.GetBaseOtsData(data_.party_id).GetSenderData();

  // make random choices (this is precomputation, real inputs are not known yet)
  data_.receiver_data.random_choices =
      std::make_unique<AlignedBitVector>(AlignedBitVector::SecureRandom(bit_size));

  // create matrix with kKappa rows
  std::vector<AlignedBitVector> v(kKappa);

  // PRG we use with the fixed-key AES function

  // PRG which is used to expand the keys we got from the base OTs
  primitives::Prg prg_fixed_key, prg_variable_key;

  // fill the rows of the matrix, offset to differentiate other providers' base ots
  for (i = 0; i < kKappa; ++i) {
    // generate rows of the matrix using the corresponding 0 key
    // T[j] = Prg(s_{j,0})
    prg_variable_key.SetKey(base_ots_sender_data.messages_0.at(data_.base_ot_offset + i).data());
    // change the offset in the output stream since we might have already used
    // the same base OTs previously
    prg_variable_key.SetOffset(data_.base_ot_offset);
    // expand the seed such that it fills one row of the matrix
    auto row(prg_variable_key.Encrypt(byte_size));
    v.at(i) = AlignedBitVector(std::move(row), bit_size);
    // take a copy of the row and XOR it with our choices
    auto u = v.at(i);
    // u_j = T[j] XOR r
    u ^= *data_.receiver_data.random_choices;

    // now mask the result with random stream expanded from the 1 key
    // u_j = u_j XOR Prg(s_{j,1})
    prg_variable_key.SetKey(base_ots_sender_data.messages_1.at(data_.base_ot_offset + i).data());
    prg_variable_key.SetOffset(data_.base_ot_offset);
    u ^= AlignedBitVector(prg_variable_key.Encrypt(byte_size), bit_size);

    auto buffer_span{
        std::span(reinterpret_cast<const std::uint8_t*>(u.GetData().data()), u.GetData().size())};
    auto msg{communication::BuildMessage(communication::MessageType::kOtExtensionReceiverMasks, i,
                                         buffer_span)};
    // send this row
    data_.send_function(std::move(msg));
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

  const auto& fixed_key_aes_key = motion_base_provider_.GetAesFixedKey();
  prg_fixed_key.SetKey(fixed_key_aes_key.data());
  BitMatrix::ReceiverTranspose128AndEncrypt(pointers, data_.receiver_data.outputs, prg_fixed_key,
                                            bit_size_padded, data_.receiver_data.bitlengths);

  data_.receiver_data.SetSetupIsReady();
  SetSetupIsReady();
}

void OtProviderFromOtExtension::PreSetup() {
  if (HasWork()) {
    data_.base_ot_offset = base_ot_provider_.Request(kKappa, data_.party_id);
  }
}

OtVector::OtVector(const std::size_t ot_id, const std::size_t number_of_ots,
                   const std::size_t bitlength, OtExtensionData& data)
    : ot_id_(ot_id), number_of_ots_(number_of_ots), bitlength_(bitlength), data_(data) {}

std::unique_ptr<ROtSender> OtProviderSender::RegisterROt(const std::size_t number_of_ots,
                                                         const std::size_t bitlength) {
  const auto i = total_ots_count_;
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<ROtSender>(i, number_of_ots, bitlength, data_);
  if constexpr (kDebug) {
    if (data_.logger) {
      data_.logger->LogDebug(fmt::format("Party#{}: registered {} parallel {}-bit sender ROt",
                                         party_id_, number_of_ots, bitlength));
    }
  }
  return ot;
}

std::unique_ptr<XcOtSender> OtProviderSender::RegisterXcOt(const std::size_t number_of_ots,
                                                           const std::size_t bitlength) {
  const auto i = total_ots_count_;
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<XcOtSender>(i, number_of_ots, bitlength, data_);
  if constexpr (kDebug) {
    if (data_.logger) {
      data_.logger->LogDebug(fmt::format("Party#{}: registered {} parallel {}-bit sender XcOt",
                                         party_id_, number_of_ots, bitlength));
    }
  }
  return ot;
}

std::unique_ptr<FixedXcOt128Sender> OtProviderSender::RegisterFixedXcOt128s(
    const std::size_t number_of_ots) {
  const auto i = total_ots_count_;
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<FixedXcOt128Sender>(i, number_of_ots, data_);
  if constexpr (kDebug) {
    if (data_.logger) {
      data_.logger->LogDebug(
          fmt::format("Party#{}: registered {} parallel {}-bit sender FixedXCOT128s", party_id_,
                      number_of_ots, 128));
    }
  }
  return ot;
}

std::unique_ptr<XcOtBitSender> OtProviderSender::RegisterXcOtBits(const std::size_t number_of_ots) {
  const auto i = total_ots_count_;
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<XcOtBitSender>(i, number_of_ots, data_);
  if constexpr (kDebug) {
    if (data_.logger) {
      data_.logger->LogDebug(fmt::format("Party#{}: registered {} parallel {}-bit sender XCOTBits",
                                         party_id_, number_of_ots, 1));
    }
  }
  return ot;
}

template <typename T>
std::unique_ptr<AcOtSender<T>> OtProviderSender::RegisterAcOt(std::size_t number_of_ots,
                                                              std::size_t vector_size) {
  const auto i = total_ots_count_;
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<AcOtSender<T>>(i, number_of_ots, vector_size, data_);
  if constexpr (kDebug) {
    if (data_.logger) {
      data_.logger->LogDebug(fmt::format("Party#{}: registered {} parallel {}-bit sender ACOTs",
                                         party_id_, number_of_ots, 8 * sizeof(T)));
    }
  }
  return ot;
}

template std::unique_ptr<AcOtSender<std::uint8_t>> OtProviderSender::RegisterAcOt(
    std::size_t number_of_ots, std::size_t vector_size);
template std::unique_ptr<AcOtSender<std::uint16_t>> OtProviderSender::RegisterAcOt(
    std::size_t number_of_ots, std::size_t vector_size);
template std::unique_ptr<AcOtSender<std::uint32_t>> OtProviderSender::RegisterAcOt(
    std::size_t number_of_ots, std::size_t vector_size);
template std::unique_ptr<AcOtSender<std::uint64_t>> OtProviderSender::RegisterAcOt(
    std::size_t number_of_ots, std::size_t vector_size);
template std::unique_ptr<AcOtSender<__uint128_t>> OtProviderSender::RegisterAcOt(
    std::size_t number_of_ots, std::size_t vector_size);

std::unique_ptr<GOtSender> OtProviderSender::RegisterGOt(const std::size_t number_of_ots,
                                                         const std::size_t bitlength) {
  const auto i = total_ots_count_;
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<GOtSender>(i, number_of_ots, bitlength, data_);
  if constexpr (kDebug) {
    if (data_.logger) {
      data_.logger->LogDebug(fmt::format("Party#{}: registered {} parallel {}-bit sender GOTs",
                                         party_id_, number_of_ots, bitlength));
    }
  }
  return ot;
}

std::unique_ptr<GOt128Sender> OtProviderSender::RegisterGOt128(const std::size_t number_of_ots) {
  const auto i = total_ots_count_;
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<GOt128Sender>(i, number_of_ots, data_);
  if constexpr (kDebug) {
    if (data_.logger) {
      data_.logger->LogDebug(fmt::format("Party#{}: registered {} parallel {}-bit sender GOT128s",
                                         party_id_, number_of_ots, 128));
    }
  }
  return ot;
}

std::unique_ptr<GOtBitSender> OtProviderSender::RegisterGOtBit(const std::size_t number_of_ots) {
  const auto i = total_ots_count_;
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<GOtBitSender>(i, number_of_ots, data_);
  if constexpr (kDebug) {
    if (data_.logger) {
      data_.logger->LogDebug(fmt::format("Party#{}: registered {} parallel {}-bit sender GOTBits",
                                         party_id_, number_of_ots, 1));
    }
  }
  return ot;
}

void OtProviderSender::Clear() {
  // TODO: move this
  // data_storage_->GetBaseOTsData()->GetSenderData().consumed_offset += total_ots_count_;

  total_ots_count_ = 0;

  ResetSetupIsReady();
}

void OtProviderSender::Reset() {
  Clear();
  // TODO
}

std::unique_ptr<ROtReceiver> OtProviderReceiver::RegisterROt(const std::size_t number_of_ots,
                                                             const std::size_t bitlength) {
  const auto i = total_ots_count_.load();
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<ROtReceiver>(i, number_of_ots, bitlength, data_);
  if constexpr (kDebug) {
    if (data_.logger) {
      data_.logger->LogDebug(fmt::format("Party#{}: registered {} parallel {}-bit receiver ROts",
                                         party_id_, number_of_ots, bitlength));
    }
  }
  return ot;
}

std::unique_ptr<XcOtReceiver> OtProviderReceiver::RegisterXcOt(const std::size_t number_of_ots,
                                                               const std::size_t bitlength) {
  const auto i = total_ots_count_.load();
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<XcOtReceiver>(i, number_of_ots, bitlength, data_);
  if constexpr (kDebug) {
    if (data_.logger) {
      data_.logger->LogDebug(fmt::format("Party#{}: registered {} parallel {}-bit receiver XcOts",
                                         party_id_, number_of_ots, bitlength));
    }
  }
  return ot;
}

std::unique_ptr<FixedXcOt128Receiver> OtProviderReceiver::RegisterFixedXcOt128s(
    const std::size_t number_of_ots) {
  const auto i = total_ots_count_.load();
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<FixedXcOt128Receiver>(i, number_of_ots, data_);
  if constexpr (kDebug) {
    if (data_.logger) {
      data_.logger->LogDebug(
          fmt::format("Party#{}: registered {} parallel {}-bit receiver FixedXCOT128s", party_id_,
                      number_of_ots, 128));
    }
  }
  return ot;
}

std::unique_ptr<XcOtBitReceiver> OtProviderReceiver::RegisterXcOtBits(
    const std::size_t number_of_ots) {
  const auto i = total_ots_count_.load();
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<XcOtBitReceiver>(i, number_of_ots, data_);
  if constexpr (kDebug) {
    if (data_.logger) {
      data_.logger->LogDebug(
          fmt::format("Party#{}: registered {} parallel {}-bit receiver XCOTBits", party_id_,
                      number_of_ots, 1));
    }
  }
  return ot;
}

template <typename T>
std::unique_ptr<AcOtReceiver<T>> OtProviderReceiver::RegisterAcOt(std::size_t number_of_ots,
                                                                  std::size_t vector_size) {
  const auto i = total_ots_count_.load();
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<AcOtReceiver<T>>(i, number_of_ots, vector_size, data_);
  if constexpr (kDebug) {
    if (data_.logger) {
      data_.logger->LogDebug(fmt::format("Party#{}: registered {} parallel {}-bit receiver ACOTs",
                                         party_id_, number_of_ots, 8 * sizeof(T)));
    }
  }
  return ot;
}

template std::unique_ptr<AcOtReceiver<std::uint8_t>> OtProviderReceiver::RegisterAcOt(
    std::size_t number_of_ots, std::size_t vector_size);
template std::unique_ptr<AcOtReceiver<std::uint16_t>> OtProviderReceiver::RegisterAcOt(
    std::size_t number_of_ots, std::size_t vector_size);
template std::unique_ptr<AcOtReceiver<std::uint32_t>> OtProviderReceiver::RegisterAcOt(
    std::size_t number_of_ots, std::size_t vector_size);
template std::unique_ptr<AcOtReceiver<std::uint64_t>> OtProviderReceiver::RegisterAcOt(
    std::size_t number_of_ots, std::size_t vector_size);
template std::unique_ptr<AcOtReceiver<__uint128_t>> OtProviderReceiver::RegisterAcOt(
    std::size_t number_of_ots, std::size_t vector_size);

std::unique_ptr<GOtReceiver> OtProviderReceiver::RegisterGOt(const std::size_t number_of_ots,
                                                             const std::size_t bitlength) {
  const auto i = total_ots_count_.load();
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<GOtReceiver>(i, number_of_ots, bitlength, data_);
  if constexpr (kDebug) {
    if (data_.logger) {
      data_.logger->LogDebug(fmt::format("Party#{}: registered {} parallel {}-bit receiver GOTs",
                                         party_id_, number_of_ots, bitlength));
    }
  }
  return ot;
}

std::unique_ptr<GOt128Receiver> OtProviderReceiver::RegisterGOt128(
    const std::size_t number_of_ots) {
  const auto i = total_ots_count_.load();
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<GOt128Receiver>(i, number_of_ots, data_);
  if constexpr (kDebug) {
    if (data_.logger) {
      data_.logger->LogDebug(fmt::format("Party#{}: registered {} parallel {}-bit receiver GOT128s",
                                         party_id_, number_of_ots, 128));
    }
  }
  return ot;
}

std::unique_ptr<GOtBitReceiver> OtProviderReceiver::RegisterGOtBit(
    const std::size_t number_of_ots) {
  const auto i = total_ots_count_.load();
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<GOtBitReceiver>(i, number_of_ots, data_);
  if constexpr (kDebug) {
    if (data_.logger) {
      data_.logger->LogDebug(fmt::format("Party#{}: registered {} parallel {}-bit receiver GOTBits",
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

  ResetSetupIsReady();
}
void OtProviderReceiver::Reset() { Clear(); }

OtProviderManager::OtProviderManager(communication::CommunicationLayer& communication_layer,
                                     BaseOtProvider& base_ot_provider,
                                     BaseProvider& motion_base_provider)
    : communication_layer_(communication_layer),
      providers_(communication_layer_.GetNumberOfParties()),
      data_(communication_layer_.GetNumberOfParties()){
  auto my_id = communication_layer.GetMyId();
  for (std::size_t party_id = 0; party_id < providers_.size(); ++party_id) {
    if (party_id == my_id) {
      continue;
    }
    auto send_function = [this, party_id](flatbuffers::FlatBufferBuilder&& message_builder) {
      communication_layer_.SendMessage(party_id, message_builder.Release());
    };
    data_.at(party_id) = std::make_unique<OtExtensionData>(
        party_id, send_function, communication_layer_.GetMessageManager(), communication_layer_.GetLogger());
    data_.at(party_id)->party_id = party_id;
    providers_.at(party_id) = std::make_unique<OtProviderFromOtExtension>(
        *data_.at(party_id), base_ot_provider, motion_base_provider, party_id);
  }
}

OtProviderManager::~OtProviderManager() {}

bool OtProviderManager::HasWork() {
  for (auto& provider : providers_) {
    if (provider != nullptr && (provider->GetPartyId() != communication_layer_.GetMyId()) &&
        provider->HasWork()) {
      return true;
    }
  }
  return false;
}

}  // namespace encrypto::motion
