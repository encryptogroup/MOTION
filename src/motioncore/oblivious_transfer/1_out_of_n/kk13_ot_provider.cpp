// MIT License
//
// Copyright (c) 2021 Arianne Roselina Prananto
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

#include "kk13_ot_provider.h"
#include "kk13_ot_flavors.h"

#include <cmath>
#include <span>

#include "base/motion_base_provider.h"
#include "communication/communication_layer.h"
#include "communication/message.h"
#include "communication/message_manager.h"
#include "data_storage/base_ot_data.h"
#include "data_storage/kk13_ot_extension_data.h"
#include "oblivious_transfer/base_ots/base_ot_provider.h"
#include "primitives/random/default_rng.h"
#include "utility/bit_matrix.h"
#include "utility/config.h"
#include "utility/fiber_condition.h"
#include "utility/logger.h"

namespace encrypto::motion {

Kk13OtProvider::Kk13OtProvider(Kk13OtExtensionData& data, BaseProvider& motion_base_provider)
    : data_(data),
      receiver_provider_(Kk13OtProviderReceiver(data)),
      sender_provider_(Kk13OtProviderSender(data)),
      motion_base_provider_(motion_base_provider) {}

[[nodiscard]] std::unique_ptr<RKk13OtSender> Kk13OtProvider::RegisterSendROt(
    std::size_t number_of_ots, std::size_t bitlength, std::size_t number_of_messages) {
  return sender_provider_.RegisterROt(number_of_ots, bitlength, number_of_messages);
}

[[nodiscard]] std::unique_ptr<GKk13OtSender> Kk13OtProvider::RegisterSendGOt(
    std::size_t number_of_ots, std::size_t bitlength, std::size_t number_of_messages) {
  return sender_provider_.RegisterGOt(number_of_ots, bitlength, number_of_messages);
}

[[nodiscard]] std::unique_ptr<GKk13Ot128Sender> Kk13OtProvider::RegisterSendGOt128(
    std::size_t number_of_ots, std::size_t number_of_messages) {
  return sender_provider_.RegisterGOt128(number_of_ots, number_of_messages);
}

[[nodiscard]] std::unique_ptr<GKk13OtBitSender> Kk13OtProvider::RegisterSendGOtBit(
    std::size_t number_of_ots, std::size_t number_of_messages) {
  return sender_provider_.RegisterGOtBit(number_of_ots, number_of_messages);
}

[[nodiscard]] std::unique_ptr<RKk13OtReceiver> Kk13OtProvider::RegisterReceiveROt(
    std::size_t number_of_ots, std::size_t bitlength, std::size_t number_of_messages) {
  return receiver_provider_.RegisterROt(number_of_ots, bitlength, number_of_messages);
}

[[nodiscard]] std::unique_ptr<GKk13OtReceiver> Kk13OtProvider::RegisterReceiveGOt(
    std::size_t number_of_ots, std::size_t bitlength, std::size_t number_of_messages) {
  return receiver_provider_.RegisterGOt(number_of_ots, bitlength, number_of_messages);
}

[[nodiscard]] std::unique_ptr<GKk13Ot128Receiver> Kk13OtProvider::RegisterReceiveGOt128(
    std::size_t number_of_ots, std::size_t number_of_messages) {
  return receiver_provider_.RegisterGOt128(number_of_ots, number_of_messages);
}

[[nodiscard]] std::unique_ptr<GKk13OtBitReceiver> Kk13OtProvider::RegisterReceiveGOtBit(
    std::size_t number_of_ots, std::size_t number_of_messages) {
  return receiver_provider_.RegisterGOtBit(number_of_ots, number_of_messages);
}

Kk13OtProviderFromKk13OtExtension::Kk13OtProviderFromKk13OtExtension(
    Kk13OtExtensionData& data, BaseOtProvider& base_ot_provider, BaseProvider& motion_base_provider)
    : Kk13OtProvider(data, motion_base_provider), base_ot_provider_(base_ot_provider) {
  for (std::size_t i = 0; i < data_.sender_data.u_futures.size(); ++i) {
    data_.sender_data.u_futures[i] = data_.message_manager.RegisterReceive(
        data_.party_id, communication::MessageType::kKK13OtExtensionReceiverMasks, i);
  }
  data_.receiver_data.key_future = data_.message_manager.RegisterReceive(
      data_.party_id, communication::MessageType::kKK13OtExtensionMaskSeed, 0);
}

std::size_t Kk13OtProviderFromKk13OtExtension::GetPartyId() const { return data_.party_id; }

std::vector<AlignedBitVector> MaskFunction(primitives::Prg& prg, std::vector<std::size_t> input,
                                           std::size_t max_element, std::size_t number_of_rows,
                                           std::size_t number_of_columns) {
  auto mask(prg.Encrypt(max_element * number_of_columns));

  std::vector<AlignedBitVector> masked_input(number_of_rows);
  for (std::size_t i = 0; i < number_of_rows; i++) {
    masked_input[i] =
        AlignedBitVector(mask.data() + (number_of_columns * input[i]), number_of_columns);
  }
  return masked_input;
}

// Complete KK13 OT Protocol
//             Sender                                 Receiver
// m tuples messages                     c = (c_1,...,c_m), 1 <= c_i <= n
// (x_{i,1},...,x_{i,n}) \element {0,1}^l
// +--------------------------------------------------------------------+------------+
// |                  for 1 <= j <= kKappa_accent:                      |            |
// |                           _________                                | setup      |
// | r_j \element_R {0,1} --> | Base OT | <--- s_{j,0}, s_{j,1}         | phase      |
// |            s_{j,r_j} <-- |_________|      \element_R {0,1}^kKappa' |            |
// +--------------------------------------------------------------------+------------+
// |                                       for 1 <= j <= kKappa_accent: |            |
// |                                              T_0[j] = PRG(s_j,0)   |            |
// |                        u = T_1[j] = T_0[j] ^ PRG(s_j,1) ^ X(c_j)   | ot         |
// |                                                                    | extension  |
// |                  (u_j, 1 <= j <= kKappa_accent)                    | phase      |
// |               <-----------------------------------                 |            |
// | for 1 <= j <= kKappa_accent:                                       |            |
// |   V[j] = (r_j x u_j) ^ PRG(s_j,r_j)                                |            |
// +--------------------------------------------------------------------+------------+
// | V' = V^T                                            T_0' = (T_0)^T | transpose  |
// +--------------------------------------------------------------------+------------+
// | for 1 <= i <= m, 1 <= a <= n:                                      |            |
// |   y_{i,a} = x_{i,a} ^ H(i, V'[i] ^ (X(a) & r))                     | correction |
// |                                                                    | and        |
// |                (y_{i,a}, 1 <= i <= m, 1 <= a <= n)                 | sending    |
// |               ----------------------------------->                 | phase      |
// |                                                   for 1 <= i <= m: |            |
// |                                x_{i,c_i} = y_{i,c_i} ^ H(i,T_0')   |            |
// +--------------------------------------------------------------------+------------+

void Kk13OtProviderFromKk13OtExtension::SendSetup() {
  // index variable
  std::size_t i;

  // security parameter
  constexpr std::size_t kKappa_accent = 2 * kKappa;

  // storage for sender and base OT receiver data
  const auto& base_ots_receiver_data =
      base_ot_provider_.GetBaseOtsData(data_.party_id).GetReceiverData();

  // number of OTs after extension
  // == width of the bit matrix
  const std::size_t bit_size = sender_provider_.GetTotalNumOts();
  if (bit_size == 0) return;  // no OTs needed
  data_.sender_data.bit_size = bit_size;

  // get each number of ots
  const auto each_bit_size = sender_provider_.GetNumOts();

  // get each number of messages
  const auto number_of_messages = sender_provider_.GetNumMessages();
  assert(!number_of_messages.empty());

  // get the maximum number of messages
  std::size_t max_number_of_messages = 0;
  for (i = 0; i < number_of_messages.size(); i++) {
    max_number_of_messages = std::max(max_number_of_messages, number_of_messages[i]);
    if (number_of_messages[i] < 2) {
      throw std::runtime_error(
          fmt::format("Number of message {} must be at least 2", number_of_messages[i]));
    } else if (number_of_messages[i] > kKappa_accent) {
      throw std::runtime_error(fmt::format("Number of message {} must be less than {}",
                                           number_of_messages[i], kKappa_accent));
    }
  }

  // bit size of the matrix rounded to bytes
  const std::size_t byte_size = BitsToBytes(bit_size);

  // bit size rounded to blocks
  const auto bit_size_padded = bit_size + kKappa_accent - (bit_size % kKappa_accent);

  // generate X(a)
  std::vector<std::size_t> message_number(max_number_of_messages);
  for (i = 0; i < max_number_of_messages; i++) {
    message_number[i] = i;
  }

  // generate an AES key for mask function
  std::array<std::byte, kKappa> key;
  encrypto::motion::DefaultRng rng;
  rng.RandomBytes(key.data(), key.size());

  data_.send_function(communication::BuildMessage(
      communication::MessageType::kKK13OtExtensionMaskSeed,
      std::span(reinterpret_cast<const std::uint8_t*>(key.data()), key.size())));

  // prepare PRG for mask function
  primitives::Prg prg_mask;
  prg_mask.SetKey(key.data());

  auto x_a = MaskFunction(prg_mask, message_number, max_number_of_messages, max_number_of_messages,
                          kKappa_accent);

  // vector containing the matrix rows
  std::vector<AlignedBitVector> v(kKappa_accent);

  // PRG which is used to expand the keys we got from the base OTs
  primitives::Prg prgs_variable_key;
  // fill the rows of the matrix
  for (i = 0; i < kKappa_accent; ++i) {
    // use the key we got from the base OTs as seed
    prgs_variable_key.SetKey(base_ots_receiver_data.messages_c[data_.base_ot_offset + i].data());
    // change the offset in the output stream since we might have already used
    // the same base OTs previously
    prgs_variable_key.SetOffset(data_.base_ot_offset);
    // expand the seed such that it fills one row of the matrix
    auto row(prgs_variable_key.Encrypt(byte_size));
    v[i] = AlignedBitVector(std::move(row), bit_size);
  }

  // receive the vectors u one by one from the receiver and xor them to the expanded keys
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

  // delete the allocated memory
  data_.sender_data.u = {};

  // array with pointers to each row of the matrix
  std::array<const std::byte*, kKappa_accent> pointers;
  for (i = 0u; i < pointers.size(); ++i) {
    pointers[i] = v[i].GetData().data();
  }

  motion_base_provider_.WaitSetup();

  const auto& fixed_key_aes_key = motion_base_provider_.GetAesFixedKey();

  // PRG for each (extended) OT i
  primitives::Prg prg_fixed_key;
  prg_fixed_key.SetKey(fixed_key_aes_key.data());

  // transpose the bit matrix
  BitMatrix::SenderTranspose256AndEncrypt(
      pointers, data_.sender_data.y,
      base_ots_receiver_data.c.Subset(data_.base_ot_offset, data_.base_ot_offset + kKappa_accent),
      x_a, prg_fixed_key, bit_size_padded, data_.sender_data.bitlengths);

  // we are done with the setup for the sender side
  data_.sender_data.SetSetupIsReady();
  SetSetupIsReady();
}

void Kk13OtProviderFromKk13OtExtension::ReceiveSetup() {
  // some index variables
  std::size_t i, j;

  // security parameter and number of base OTs
  constexpr std::size_t kKappa_accent = 2 * kKappa;

  // number of OTs and width of the bit matrix
  const auto bit_size = receiver_provider_.GetTotalNumOts();
  if (bit_size == 0) return;  // nothing to do

  // get each number of ots
  const auto each_bit_size = receiver_provider_.GetNumOts();

  // get each number of messages
  const auto number_of_messages = receiver_provider_.GetNumMessages();
  assert(!number_of_messages.empty());

  // get the maximum number of messages
  std::size_t max_number_of_messages = 0;
  for (i = 0; i < number_of_messages.size(); i++) {
    max_number_of_messages = std::max(max_number_of_messages, number_of_messages[i]);
    if (number_of_messages[i] < 2) {
      throw std::runtime_error(
          fmt::format("Number of message {} must be at least 2", number_of_messages[i]));
    } else if (number_of_messages[i] > kKappa_accent) {
      throw std::runtime_error(fmt::format("Number of message {} must be less than {}",
                                           number_of_messages[i], kKappa_accent));
    }
  }

  // rounded up to a multiple of the security parameter
  auto bit_size_padded = bit_size + kKappa_accent - (bit_size % kKappa_accent);

  // convert to bytes
  const std::size_t byte_size = BitsToBytes(bit_size);
  if (byte_size == 0) return;

  // PRG which is used to expand the keys
  primitives::Prg prg_fixed_key, prg_variable_key;

  std::size_t log_total_messages = 0;
  // calculate the sum of each log(number of message)
  for (i = 0; i < each_bit_size.size(); i++) {
    log_total_messages += ceil(log2(number_of_messages[i]));
  }

  // contains bit_size random sum of ceil(log(number_of_messages))-bit integers
  BitVector<> random_choices_bv = BitVector<>::SecureRandom(bit_size * log_total_messages);

  // prepare the variables used to generate receiver's random choices
  std::vector<std::uint8_t> random_choices_8(bit_size);
  std::vector<std::size_t> random_choices_64(bit_size);
  std::size_t index = 0;

  for (i = 0; i < each_bit_size.size(); i++) {
    auto this_bit_size = each_bit_size[i];
    auto max_bits = ceil(log2(number_of_messages[i]));

    for (j = 0; j < this_bit_size; j++) {
      // get each random choice from the BitVector<>
      auto random_choices_subset = random_choices_bv.Subset(
          ((i * this_bit_size) + j) * max_bits, ((i * this_bit_size) + (j + 1)) * max_bits);
      // make sure random choice doesn't exceed number of messages
      random_choices_8[index] =
          *reinterpret_cast<std::uint8_t*>(random_choices_subset.GetMutableData().data()) %
          number_of_messages[i];
      random_choices_64[index] = static_cast<std::size_t>(random_choices_8[index]);
      index++;
    }
  }

  data_.receiver_data.random_choices =
      std::make_unique<std::vector<std::uint8_t>>(random_choices_8);

  // prepare PRG for mask function
  primitives::Prg prg_mask;
  auto key = data_.receiver_data.key_future.get();
  prg_mask.SetKey(communication::GetMessage(key.data())->payload()->data());

  // mask random choices as X(random_choices)
  auto x_c =
      MaskFunction(prg_mask, random_choices_64, max_number_of_messages, bit_size, kKappa_accent);

  // transpose x_c
  auto bm_xc = BitMatrix(std::move(x_c));
  bm_xc.Transpose256Columns();

  // create matrix with kKappa_accent rows
  std::vector<AlignedBitVector> t_0(kKappa_accent);

  // fill the rows of the matrix
  for (i = 0; i < kKappa_accent; ++i) {
    // generate rows of the matrix using the corresponding 0 key
    // t_0[j] = Prg(s_{j,0})
    prg_variable_key.SetKey(base_ot_provider_.GetBaseOtsData(data_.party_id)
                                .sender_data.messages_0[data_.base_ot_offset + i]
                                .data());
    // change the offset in the output stream since we might have already used
    // the same base OTs previously
    prg_variable_key.SetOffset(data_.base_ot_offset);
    // expand the seed such that it fills one row of the matrix
    auto row(prg_variable_key.Encrypt(byte_size));
    t_0[i] = AlignedBitVector(std::move(row), bit_size);

    // take a copy of the row and XOR it with our choices
    auto t_1 = t_0[i];
    // t_1[j] = t_0[j] XOR X(c)
    t_1 ^= bm_xc.GetMutableRow(i);

    // now mask the result with random stream expanded from the 1 key
    // t_1[j] = t_1[j] XOR Prg(s_{j,1})
    prg_variable_key.SetKey(base_ot_provider_.GetBaseOtsData(data_.party_id)
                                .sender_data.messages_1[data_.base_ot_offset + i]
                                .data());
    prg_variable_key.SetOffset(data_.sender_data.consumed_offset);
    t_1 ^= AlignedBitVector(prg_variable_key.Encrypt(byte_size), bit_size);

    data_.send_function(communication::BuildMessage(
        communication::MessageType::kKK13OtExtensionReceiverMasks, i,
        std::span(reinterpret_cast<const std::uint8_t*>(t_1.GetData().data()),
                  t_1.GetData().size())));
  }

  // transpose matrix t_0
  if (bit_size_padded != bit_size) {
    for (i = 0u; i < t_0.size(); ++i) {
      t_0[i].Resize(bit_size_padded, true);
    }
  }

  std::array<const std::byte*, kKappa_accent> pointers;
  for (i = 0; i < pointers.size(); ++i) {
    pointers[i] = t_0[i].GetMutableData().data();
  }

  const auto& fixed_key_aes_key = motion_base_provider_.GetAesFixedKey();
  prg_fixed_key.SetKey(fixed_key_aes_key.data());

  // transpose the bit matrix
  BitMatrix::ReceiverTranspose256AndEncrypt(pointers, data_.receiver_data.outputs, prg_fixed_key,
                                            bit_size_padded, data_.receiver_data.bitlengths);

  data_.receiver_data.SetSetupIsReady();
  SetSetupIsReady();
}

void Kk13OtProviderFromKk13OtExtension::PreSetup() {
  if (HasWork()) {
    data_.base_ot_offset = base_ot_provider_.Request(kKappa * 2, data_.party_id);
  }
}

Kk13OtVector::Kk13OtVector(std::size_t ot_id, std::size_t number_of_ots, std::size_t bitlength,
                           std::size_t number_of_messages, OtProtocol p)
    : ot_id_(ot_id),
      number_of_ots_(number_of_ots),
      bitlen_(bitlength),
      number_of_messages_(number_of_messages),
      p_(p) {}

std::unique_ptr<RKk13OtSender> Kk13OtProviderSender::RegisterROt(
    const std::size_t number_of_ots, const std::size_t bitlength,
    const std::size_t number_of_messages) {
  const auto i = total_ots_count_;
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<RKk13OtSender>(i, number_of_ots, bitlength, number_of_messages, data_);
  number_of_ots_.push_back(number_of_ots);
  number_of_messages_.push_back(number_of_messages);
  if constexpr (kDebug) {
    if (data_.logger) {
      data_.logger->LogDebug(
          fmt::format("Party#{}: registered {} parallel {} {}-bit messages sender RKk13Ots",
                      data_.party_id, number_of_ots, number_of_messages, bitlength));
    }
  }
  return ot;
}

std::unique_ptr<GKk13OtSender> Kk13OtProviderSender::RegisterGOt(
    const std::size_t number_of_ots, const std::size_t bitlength,
    const std::size_t number_of_messages) {
  const auto i = total_ots_count_;
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<GKk13OtSender>(i, number_of_ots, bitlength, number_of_messages, data_);
  number_of_ots_.push_back(number_of_ots);
  number_of_messages_.push_back(number_of_messages);
  if constexpr (kDebug) {
    if (data_.logger) {
      data_.logger->LogDebug(
          fmt::format("Party#{}: registered {} parallel {} {}-bit-messages sender GKk13Ots",
                      data_.party_id, number_of_ots, number_of_messages, bitlength));
    }
  }
  return ot;
}

std::unique_ptr<GKk13Ot128Sender> Kk13OtProviderSender::RegisterGOt128(
    const std::size_t number_of_ots, const std::size_t number_of_messages) {
  const auto i = total_ots_count_;
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<GKk13Ot128Sender>(i, number_of_ots, number_of_messages, data_);
  number_of_ots_.push_back(number_of_ots);
  number_of_messages_.push_back(number_of_messages);
  if constexpr (kDebug) {
    if (data_.logger) {
      data_.logger->LogDebug(
          fmt::format("Party#{}: registered {} parallel {} {}-bit messages sender GKk13Ot128s",
                      data_.party_id, number_of_ots, number_of_messages, 128));
    }
  }
  return ot;
}

std::unique_ptr<GKk13OtBitSender> Kk13OtProviderSender::RegisterGOtBit(
    std::size_t number_of_ots, std::size_t number_of_messages) {
  const auto i = total_ots_count_;
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<GKk13OtBitSender>(i, number_of_ots, number_of_messages, data_);
  number_of_ots_.push_back(number_of_ots);
  number_of_messages_.push_back(number_of_messages);
  if constexpr (kDebug) {
    if (data_.logger) {
      data_.logger->LogDebug(
          fmt::format("Party#{}: registered {} parallel {} {}-bit messages sender GKk13OtBits",
                      data_.party_id, number_of_ots, number_of_messages, 1));
    }
  }
  return ot;
}

void Kk13OtProviderSender::Clear() {
  total_ots_count_ = 0;
  number_of_ots_.clear();
  number_of_messages_.clear();

  data_.ResetSetupIsReady();
}

void Kk13OtProviderSender::Reset() { Clear(); }

std::unique_ptr<RKk13OtReceiver> Kk13OtProviderReceiver::RegisterROt(
    const std::size_t number_of_ots, const std::size_t bitlength,
    const std::size_t number_of_messages) {
  const auto i = total_ots_count_.load();
  total_ots_count_ += number_of_ots;
  auto ot =
      std::make_unique<RKk13OtReceiver>(i, number_of_ots, bitlength, number_of_messages, data_);
  number_of_ots_.push_back(number_of_ots);
  number_of_messages_.push_back(number_of_messages);
  if constexpr (kDebug) {
    if (data_.logger) {
      data_.logger->LogDebug(
          fmt::format("Party#{}: registered {} parallel {} {}-bit messages receiver RKk13Ots",
                      data_.party_id, number_of_ots, number_of_messages, bitlength));
    }
  }
  return ot;
}

std::unique_ptr<GKk13OtReceiver> Kk13OtProviderReceiver::RegisterGOt(
    const std::size_t number_of_ots, const std::size_t bitlength,
    const std::size_t number_of_messages) {
  const auto i = total_ots_count_.load();
  total_ots_count_ += number_of_ots;
  auto ot =
      std::make_unique<GKk13OtReceiver>(i, number_of_ots, bitlength, number_of_messages, data_);
  number_of_ots_.push_back(number_of_ots);
  number_of_messages_.push_back(number_of_messages);
  if constexpr (kDebug) {
    if (data_.logger) {
      data_.logger->LogDebug(
          fmt::format("Party#{}: registered {} parallel {} {}-bit-messages receiver GKk13Ots",
                      data_.party_id, number_of_ots, number_of_messages, bitlength));
    }
  }
  return ot;
}

std::unique_ptr<GKk13Ot128Receiver> Kk13OtProviderReceiver::RegisterGOt128(
    const std::size_t number_of_ots, const std::size_t number_of_messages) {
  const auto i = total_ots_count_.load();
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<GKk13Ot128Receiver>(i, number_of_ots, number_of_messages, data_);
  number_of_ots_.push_back(number_of_ots);
  number_of_messages_.push_back(number_of_messages);
  if constexpr (kDebug) {
    if (data_.logger) {
      data_.logger->LogDebug(
          fmt::format("Party#{}: registered {} parallel {} {}-bit messages receiver GKk13Ot128s",
                      data_.party_id, number_of_ots, number_of_messages, 128));
    }
  }
  return ot;
}

std::unique_ptr<GKk13OtBitReceiver> Kk13OtProviderReceiver::RegisterGOtBit(
    const std::size_t number_of_ots, const std::size_t number_of_messages) {
  const auto i = total_ots_count_.load();
  total_ots_count_ += number_of_ots;
  auto ot = std::make_unique<GKk13OtBitReceiver>(i, number_of_ots, number_of_messages, data_);
  number_of_ots_.push_back(number_of_ots);
  number_of_messages_.push_back(number_of_messages);
  if constexpr (kDebug) {
    if (data_.logger) {
      data_.logger->LogDebug(
          fmt::format("Party#{}: registered {} parallel {} {}-bit messages receiver GKk13OtBits",
                      data_.party_id, number_of_ots, number_of_messages, 1));
    }
  }
  return ot;
}

void Kk13OtProviderReceiver::Clear() {
  total_ots_count_ = 0;
  number_of_ots_.clear();
  number_of_messages_.clear();

  data_.ResetSetupIsReady();
}

void Kk13OtProviderReceiver::Reset() { Clear(); }

Kk13OtProviderManager::Kk13OtProviderManager(communication::CommunicationLayer& communication_layer,
                                             BaseOtProvider& base_ot_provider,
                                             BaseProvider& motion_base_provider)
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
      communication_layer_.SendMessage(party_id, message_builder.Release());
    };
    data_[party_id] = std::make_unique<Kk13OtExtensionData>(party_id, send_function,
                                                            communication_layer.GetMessageManager(),
                                                            communication_layer.GetLogger());
    providers_[party_id] = std::make_unique<Kk13OtProviderFromKk13OtExtension>(
        *data_[party_id], base_ot_provider, motion_base_provider);
  }
}

Kk13OtProviderManager::~Kk13OtProviderManager() {}

bool Kk13OtProviderManager::HasWork() {
  for (auto& provider : providers_) {
    if (provider != nullptr && provider->GetPartyId() != communication_layer_.GetMyId() &&
        provider->HasWork()) {
      return true;
    }
  }
  return false;
}

}  // namespace encrypto::motion