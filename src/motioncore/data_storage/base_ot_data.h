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
#include "utility/bit_vector.h"

namespace ENCRYPTO {
class FiberCondition;
}

namespace MOTION {

enum BaseOTsDataType : uint { HL17_R = 0, HL17_S = 1, BaseOTs_invalid_data_type = 2 };

struct BaseOTsReceiverData {
  BaseOTsReceiverData();
  ~BaseOTsReceiverData() = default;

  ENCRYPTO::BitVector<> c_;  /// choice bits
  std::array<std::array<std::byte, 16>, 128> messages_c_;

  std::vector<std::array<std::byte, 32>> S_;
  boost::container::vector<bool> received_S_;
  std::vector<std::unique_ptr<ENCRYPTO::FiberCondition>> received_S_condition_;

  // number of used rows;
  std::size_t consumed_offset_{0};

  std::atomic<bool> is_ready_{false};
  std::unique_ptr<ENCRYPTO::FiberCondition> is_ready_condition_;
};

struct BaseOTsSenderData {
  BaseOTsSenderData();
  ~BaseOTsSenderData() = default;

  std::array<std::array<std::byte, 16>, 128> messages_0_;
  std::array<std::array<std::byte, 16>, 128> messages_1_;

  std::vector<std::array<std::byte, 32>> R_;
  boost::container::vector<bool> received_R_;
  std::vector<std::unique_ptr<ENCRYPTO::FiberCondition>> received_R_condition_;

  // number of used rows;
  std::size_t consumed_offset_{0};

  std::unique_ptr<ENCRYPTO::FiberCondition> is_ready_condition_;
  std::atomic<bool> is_ready_{false};
};

struct BaseOTsData {
  void MessageReceived(const std::uint8_t* message, const BaseOTsDataType type,
                       const std::size_t ot_id = 0);

  BaseOTsReceiverData& GetReceiverData() { return receiver_data_; }
  const BaseOTsReceiverData& GetReceiverData() const { return receiver_data_; }
  BaseOTsSenderData& GetSenderData() { return sender_data_; }
  const BaseOTsSenderData& GetSenderData() const { return sender_data_; }

  BaseOTsReceiverData receiver_data_;
  BaseOTsSenderData sender_data_;
};

}  // namespace MOTION
