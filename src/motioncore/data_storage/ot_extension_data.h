// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko, Lennart Braun
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

#include <array>
#include <atomic>
#include <cstddef>
#include <memory>
#include <mutex>
#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "utility/bit_matrix.h"
#include "utility/bit_vector.h"
#include "utility/block.h"
#include "utility/meta.hpp"
#include "utility/reusable_future.h"

namespace encrypto::motion {

class FiberCondition;

enum OtExtensionDataType : unsigned int {
  kReceptionMask = 0,
  kReceptionCorrection = 1,
  kSendMessage = 2,
  kOtExtensionInvalidDataType = 3
};

enum class OtMessageType {
  kGenericBoolean,
  kBit,
  kBlock128,
  kUint8,
  kUint16,
  kUint32,
  kUint64,
  kUint128
};

struct OtExtensionReceiverData {
  OtExtensionReceiverData();
  ~OtExtensionReceiverData() = default;

  [[nodiscard]] ReusableFiberFuture<Block128Vector> RegisterForBlock128SenderMessage(
      std::size_t ot_id, std::size_t size);
  [[nodiscard]] ReusableFiberFuture<BitVector<>> RegisterForBitSenderMessage(std::size_t ot_id,
                                                                             std::size_t size);
  [[nodiscard]] ReusableFiberFuture<std::vector<BitVector<>>> RegisterForGenericSenderMessage(
      std::size_t ot_id, std::size_t size, std::size_t bitlength);
  template <typename T>
  [[nodiscard]] ReusableFiberFuture<std::vector<T>> RegisterForIntSenderMessage(std::size_t ot_id,
                                                                                std::size_t size);

  // matrix of the OT extension scheme
  // XXX: can't we delete this after setup?
  std::shared_ptr<BitMatrix> T;

  // if many OTs are received in batches, it is not necessary to store all of the flags
  // for received messages but only for the first OT id in the batch. Thus, use a hash table.
  std::unordered_set<std::size_t> received_outputs;
  std::vector<BitVector<>> outputs;
  std::unordered_map<std::size_t, std::unique_ptr<FiberCondition>> output_conditions;
  std::mutex received_outputs_mutex;

  // bit length of every OT
  std::vector<std::size_t> bitlengths;

  // store the message types of new-style OTs
  std::unordered_map<std::size_t, OtMessageType> message_type;

  // Promises for the sender messages
  // ot_id -> (vector size, vector promise)
  std::unordered_map<std::size_t, std::pair<std::size_t, ReusableFiberPromise<BitVector<>>>>
      message_promises_bit;
  std::unordered_map<std::size_t, std::pair<std::size_t, ReusableFiberPromise<Block128Vector>>>
      message_promises_block128;

  // Promises for the generic sender messages
  // ot_id -> (vector size, length of each bitvector, vector promise)
  std::unordered_map<std::size_t, std::tuple<std::size_t, std::size_t,
                                             ReusableFiberPromise<std::vector<BitVector<>>>>>
      message_promises_generic;

  template <typename T>
  using PromiseMapType =
      std::unordered_map<std::size_t, std::pair<std::size_t, ReusableFiberPromise<std::vector<T>>>>;
  TypeMap<PromiseMapType, std::uint8_t, std::uint16_t, std::uint32_t, std::uint64_t, __uint128_t>
      message_promises_int;

  // have we already set the choices for this OT batch?
  std::unordered_set<std::size_t> set_real_choices;
  std::mutex real_choices_mutex;

  // random choices from OT precomputation
  std::unique_ptr<AlignedBitVector> random_choices;

  // how many ots are in each batch?
  std::unordered_map<std::size_t, std::size_t> number_of_ots_in_batch;

  // flag and condition variable: is setup is done?
  std::unique_ptr<FiberCondition> setup_finished_condition;
  std::atomic<bool> setup_finished{false};

  // XXX: unused
  std::atomic<std::size_t> consumed_offset{0};
};

struct OtExtensionSenderData {
  OtExtensionSenderData();
  ~OtExtensionSenderData() = default;

  // width of the bit matrix
  std::atomic<std::size_t> bit_size{0};

  /// receiver's mask that are needed to construct matrix @param V
  std::array<AlignedBitVector, 128> u;

  std::array<ReusablePromise<std::size_t>, 128> u_promises;
  std::array<ReusableFuture<std::size_t>, 128> u_futures;
  std::mutex u_mutex;
  std::size_t number_of_received_us{0};
  // matrix of the OT extension scheme
  // XXX: can't we delete this after setup?
  std::shared_ptr<BitMatrix> V;

  // offset, number_of_ots
  std::unordered_map<std::size_t, std::size_t> number_of_ots_in_batch;

  // corrections for GOTs, i.e., if random choice bit is not the real choice bit
  // send 1 to flip the messages before encoding or 0 otherwise for each GOT
  std::unordered_set<std::size_t> received_correction_offsets;
  std::unordered_map<std::size_t, std::unique_ptr<FiberCondition>>
      received_correction_offsets_condition;
  BitVector<> corrections;
  mutable std::mutex corrections_mutex;

  // random sender outputs
  // XXX: why not aligned?
  std::vector<BitVector<>> y0, y1;

  // bit length of every OT
  std::vector<std::size_t> bitlengths;

  // flag and condition variable: is setup is done?
  std::unique_ptr<FiberCondition> setup_finished_condition;
  std::atomic<bool> setup_finished{false};

  // XXX: unused
  std::atomic<std::size_t> consumed_offset{0};
};

struct OtExtensionData {
  void MessageReceived(const std::uint8_t* message, std::size_t message_size,
                       const OtExtensionDataType type, const std::size_t ot_id = 0);

  OtExtensionReceiverData& GetReceiverData() { return receiver_data; }
  const OtExtensionReceiverData& GetReceiverData() const { return receiver_data; }
  OtExtensionSenderData& GetSenderData() { return sender_data; }
  const OtExtensionSenderData& GetSenderData() const { return sender_data; }

  OtExtensionReceiverData receiver_data;
  OtExtensionSenderData sender_data;
};

}  // namespace encrypto::motion
