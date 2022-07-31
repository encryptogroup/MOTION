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
#include <span>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "utility/bit_matrix.h"
#include "utility/bit_vector.h"
#include "utility/block.h"

namespace encrypto::motion {

class FiberCondition;
class Logger;

struct OtExtensionReceiverData : public FiberSetupWaitable {
  OtExtensionReceiverData() = default;
  ~OtExtensionReceiverData() = default;

  // matrix of the OT extension scheme
  // XXX: can't we delete this after setup?
  std::shared_ptr<BitMatrix> T;

  // if many OTs are received in batches, it is not necessary to store all of the flags
  // for received messages but only for the first OT id in the batch. Thus, use a hash table.
  std::vector<BitVector<>> outputs;

  // bit length of every OT
  std::vector<std::size_t> bitlengths;

  // random choices from OT precomputation
  std::unique_ptr<AlignedBitVector> random_choices;

  // XXX: unused
  std::atomic<std::size_t> consumed_offset{0};
};

struct OtExtensionSenderData : public FiberSetupWaitable {
  OtExtensionSenderData() = default;
  ~OtExtensionSenderData() = default;

  // width of the bit matrix
  std::atomic<std::size_t> bit_size{0};

  std::array<ReusableFiberFuture<std::vector<std::uint8_t>>, 128> u_futures;
  // XXX: can't we delete this after setup?
  std::shared_ptr<BitMatrix> V;

  // random sender outputs
  // XXX: why not aligned?
  std::vector<BitVector<>> y0, y1;

  // bit length of every OT
  std::vector<std::size_t> bitlengths;

  // XXX: unused
  std::atomic<std::size_t> consumed_offset{0};
};

struct OtExtensionData {
  OtExtensionData(std::size_t party_id,
                  std::function<void(flatbuffers::FlatBufferBuilder&&)> send_function,
                  communication::MessageManager& message_manager, std::shared_ptr<Logger> logger)
      : party_id(party_id),
        send_function(send_function),
        message_manager(message_manager),
        logger(logger) {}

  // OT objects need the party id to refer to the right future map
  OtExtensionData() = delete;

  OtExtensionReceiverData receiver_data;
  OtExtensionSenderData sender_data;

  std::size_t party_id{std::numeric_limits<std::size_t>::max()};
  std::size_t base_ot_offset{std::numeric_limits<std::size_t>::max()};
  std::function<void(flatbuffers::FlatBufferBuilder&&)> send_function;
  communication::MessageManager& message_manager;
  std::shared_ptr<Logger> logger;
};

}  // namespace encrypto::motion
