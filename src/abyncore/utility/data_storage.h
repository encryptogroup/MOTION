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

#pragma once

#include <mutex>
#include <queue>
#include <unordered_set>

#include <fmt/format.h>
#include <boost/container/vector.hpp>

#include "communication/fbs_headers/hello_message_generated.h"
#include "communication/fbs_headers/message_generated.h"
#include "communication/fbs_headers/output_message_generated.h"

#include "utility/bit_vector.h"
#include "utility/typedefs.h"

namespace ENCRYPTO {
class Condition;
using ConditionPtr = std::shared_ptr<Condition>;

class BitMatrix;
}  // namespace ENCRYPTO

namespace ABYN {

class Logger;
using LoggerPtr = std::shared_ptr<Logger>;

struct BaseOTsReceiverData {
  BaseOTsReceiverData();
  ~BaseOTsReceiverData() = default;

  ENCRYPTO::BitVector<> c_;  /// choice bits
  std::array<std::array<std::byte, 16>, 128> messages_c_;

  std::vector<std::array<std::byte, 32>> S_;
  boost::container::vector<bool> received_S_;
  std::vector<std::unique_ptr<ENCRYPTO::Condition>> received_S_condition_;

  // number of used rows;
  std::size_t consumed_offset_{0};

  bool is_ready_ = false;
  std::unique_ptr<ENCRYPTO::Condition> is_ready_condition_;
};

struct BaseOTsSenderData {
  BaseOTsSenderData();
  ~BaseOTsSenderData() = default;

  std::array<std::array<std::byte, 16>, 128> messages_0_;
  std::array<std::array<std::byte, 16>, 128> messages_1_;

  std::vector<std::array<std::byte, 32>> R_;
  boost::container::vector<bool> received_R_;
  std::vector<std::unique_ptr<ENCRYPTO::Condition>> received_R_condition_;

  // number of used rows;
  std::size_t consumed_offset_{0};

  std::unique_ptr<ENCRYPTO::Condition> is_ready_condition_;
  bool is_ready_ = false;
};

struct OTExtensionSenderData {
  std::size_t bit_size_{0};
  /// receiver's mask that are needed to construct matrix @param V_
  std::array<ENCRYPTO::AlignedBitVector, 128> u_;
  std::queue<std::size_t> received_u_ids_;
  std::size_t num_u_received_{0};
  std::unique_ptr<ENCRYPTO::Condition> received_u_condition_;

  std::shared_ptr<ENCRYPTO::BitMatrix> V_;

  // offset, num_ots
  std::unordered_map<std::size_t, std::size_t> num_ots_in_batch_;

  // corrections for GOTs, i.e., if random choice bit is not the real choice bit
  // send 1 to flip the messages before encoding or 0 otherwise for each GOT
  std::unordered_set<std::size_t> received_correction_offsets_;
  std::unordered_map<std::size_t, std::unique_ptr<ENCRYPTO::Condition>>
      received_correction_offsets_cond_;
  ENCRYPTO::BitVector<> corrections_;
  std::mutex corrections_mutex_;

  // output buffer
  std::vector<ENCRYPTO::BitVector<>> y0_, y1_;
  std::vector<std::size_t> bitlengths_;

  std::unique_ptr<ENCRYPTO::Condition> setup_finished_cond_;
  bool setup_finished_ = false;
};

struct OTExtensionReceiverData {
  std::shared_ptr<ENCRYPTO::BitMatrix> T_;

  // if many OTs are received in batches, it is not necessary to store all of the flags
  // for received messages but only for the first OT id in the batch. Thus, use a hash table.
  std::unordered_set<std::size_t> received_outputs_;
  std::vector<ENCRYPTO::BitVector<>> outputs_;
  std::unordered_map<std::size_t, std::unique_ptr<ENCRYPTO::Condition>> output_conds_;
  std::mutex received_outputs_mutex_;

  std::unordered_map<std::size_t, std::size_t> num_messages_;
  std::unordered_set<std::size_t> xor_correlation_;
  std::vector<std::size_t> bitlengths_;

  std::unique_ptr<ENCRYPTO::BitVector<>> real_choices_;
  std::unordered_map<std::size_t, std::unique_ptr<ENCRYPTO::Condition>> real_choices_cond_;
  std::unordered_set<std::size_t> set_real_choices_;
  std::mutex real_choices_mutex_;

  std::unique_ptr<ENCRYPTO::AlignedBitVector> random_choices_;

  std::unordered_map<std::size_t, std::size_t> num_ots_in_batch_;

  std::unique_ptr<ENCRYPTO::Condition> setup_finished_cond_;
  bool setup_finished_ = false;
};

enum BaseOTsDataType : uint { HL17_R = 0, HL17_S = 1, BaseOTs_invalid_data_type = 2 };

enum OTExtensionDataType : uint {
  rcv_masks = 0,
  rcv_corrections = 1,
  snd_messages = 2,
  OTExtension_invalid_data_type = 3
};

class DataStorage {
 public:
  DataStorage(std::size_t id);

  ~DataStorage() = default;

  void SetLogger(const LoggerPtr &logger) { logger_ = logger; }

  void SetReceivedOutputMessage(std::vector<std::uint8_t> &&output_message);

  const Communication::OutputMessage *GetOutputMessage(const std::size_t gate_id);

  void SetReceivedHelloMessage(std::vector<std::uint8_t> &&hello_message);

  const Communication::HelloMessage *GetReceivedHelloMessage();

  ENCRYPTO::ConditionPtr &GetReceivedHelloMessageCondition() { return rcv_hello_msg_cond_; }

  void SetSentHelloMessage(std::vector<std::uint8_t> &&hello_message) {
    sent_hello_message_ = std::move(hello_message);
  }

  void SetSentHelloMessage(const std::uint8_t *message, std::size_t size);

  const Communication::HelloMessage *GetSentHelloMessage();

  ENCRYPTO::ConditionPtr &GetSentHelloMessageCondition() { return snt_hello_msg_cond_; }

  void Reset();

  void Clear();

  void SetReceivedSyncState(const size_t state);

  std::size_t IncrementMySyncState();

  ENCRYPTO::ConditionPtr &GetSyncCondition();

  void BaseOTsReceived(const std::uint8_t *message, const BaseOTsDataType type,
                       const std::size_t ot_id = 0);
  void OTExtensionReceived(const std::uint8_t *message, const OTExtensionDataType type,
                           const std::size_t i);

  auto &GetBaseOTsReceiverData() { return base_ots_receiver_data_; }
  auto &GetBaseOTsSenderData() { return base_ots_sender_data_; }

  auto &GetOTExtensionReceiverData() { return ot_extension_receiver_data_; }
  auto &GetOTExtensionSenderData() { return ot_extension_sender_data_; }

  void SetFixedKeyAESKey(const ENCRYPTO::AlignedBitVector &key) { fixed_key_aes_key_ = key; }
  const auto &GetFixedKeyAESKey() { return fixed_key_aes_key_; }

 private:
  std::vector<std::uint8_t> received_hello_message_, sent_hello_message_;
  ENCRYPTO::ConditionPtr rcv_hello_msg_cond_, snt_hello_msg_cond_, sync_cond_;

  ENCRYPTO::AlignedBitVector fixed_key_aes_key_;

  std::size_t sync_state_received_{0}, sync_state_actual_{0};

  // id, buffer
  std::unordered_map<std::size_t, std::vector<std::uint8_t>> received_output_messages_;
  // id, condition
  std::unordered_map<std::size_t, ENCRYPTO::ConditionPtr> output_message_conds_;

  std::unique_ptr<BaseOTsReceiverData> base_ots_receiver_data_;
  std::unique_ptr<BaseOTsSenderData> base_ots_sender_data_;

  std::unique_ptr<OTExtensionReceiverData> ot_extension_receiver_data_;
  std::unique_ptr<OTExtensionSenderData> ot_extension_sender_data_;

  LoggerPtr logger_;
  std::int64_t id_{-1};
  std::mutex output_message_mutex_;
};
}  // namespace ABYN
