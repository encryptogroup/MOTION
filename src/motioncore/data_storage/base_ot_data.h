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
#include <boost/container/vector.hpp>
#include <cstddef>
#include <memory>
#include <vector>

#include "communication/fbs_headers/message_generated.h"
#include "utility/bit_vector.h"
#include "utility/reusable_future.h"

namespace encrypto::motion {

class FiberCondition;

struct BaseOtReceiverData {
  BaseOtReceiverData();
  ~BaseOtReceiverData() = default;

  BitVector<> c;  /// choice bits
  std::array<std::array<std::byte, 16>, 128> messages_c;

  // number of used rows;
  std::size_t consumed_offset{0};

  std::atomic<bool> is_ready{false};
  std::unique_ptr<FiberCondition> is_ready_condition;
};

struct BaseOtSenderData {
  BaseOtSenderData();
  ~BaseOtSenderData() = default;

  std::array<std::array<std::byte, 16>, 128> messages_0;
  std::array<std::array<std::byte, 16>, 128> messages_1;

  // number of used rows;
  std::size_t consumed_offset{0};

  std::unique_ptr<FiberCondition> is_ready_condition;
  std::atomic<bool> is_ready{false};
};

struct BaseOtData {
  BaseOtReceiverData& GetReceiverData() { return receiver_data; }
  const BaseOtReceiverData& GetReceiverData() const { return receiver_data; }
  BaseOtSenderData& GetSenderData() { return sender_data; }
  const BaseOtSenderData& GetSenderData() const { return sender_data; }

  BaseOtReceiverData receiver_data;
  BaseOtSenderData sender_data;

  std::vector<ReusableFiberFuture<std::vector<std::uint8_t>>> receiver_futures;
  std::vector<ReusableFiberFuture<std::vector<std::uint8_t>>> sender_futures;
};

}  // namespace encrypto::motion
