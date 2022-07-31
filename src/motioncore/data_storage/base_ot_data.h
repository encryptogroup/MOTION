// MIT License
//
// Copyright (c) 2019-2022 Oleksandr Tkachenko, Lennart Braun, Arianne Roselina Prananto
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

#include "utility/bit_vector.h"
#include "utility/fiber_waitable.h"
#include "utility/reusable_future.h"

namespace encrypto::motion {

class FiberCondition;

struct BaseOtReceiverData : public FiberOnlineWaitable {
  BaseOtReceiverData() = default;
  ~BaseOtReceiverData() = default;

  void Add(std::size_t number_of_ots) { messages_c.resize(messages_c.size() + number_of_ots); }

  BitVector<> c;  /// choice bits
  std::vector<std::array<std::byte, 16>> messages_c;
};

struct BaseOtSenderData : public FiberOnlineWaitable {
  BaseOtSenderData() = default;
  ~BaseOtSenderData() = default;

  void Add(std::size_t number_of_ots) {
    messages_0.resize(messages_0.size() + number_of_ots);
    messages_1.resize(messages_1.size() + number_of_ots);
  }

  std::vector<std::array<std::byte, 16>> messages_0;
  std::vector<std::array<std::byte, 16>> messages_1;
};

struct BaseOtData {
  BaseOtReceiverData& GetReceiverData() { return receiver_data; }
  const BaseOtReceiverData& GetReceiverData() const { return receiver_data; }
  BaseOtSenderData& GetSenderData() { return sender_data; }
  const BaseOtSenderData& GetSenderData() const { return sender_data; }

  void Add(std::size_t number_of_ots) {
    total_number_ots += number_of_ots;
    receiver_data.Add(number_of_ots);
    sender_data.Add(number_of_ots);
  }

  BaseOtReceiverData receiver_data;
  BaseOtSenderData sender_data;

  std::vector<ReusableFiberFuture<std::vector<std::uint8_t>>> receiver_futures;
  std::vector<ReusableFiberFuture<std::vector<std::uint8_t>>> sender_futures;

  std::size_t total_number_ots{0};
};

}  // namespace encrypto::motion
