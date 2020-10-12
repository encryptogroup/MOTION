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

#include "base_ot_data.h"
#include "utility/fiber_condition.h"

namespace encrypto::motion {

BaseOtReceiverData::BaseOtReceiverData() : received_S(128, false) {
  for (auto i = 0; i < 128; ++i) {
    received_S_condition.emplace_back(
        std::make_unique<FiberCondition>([this, i]() { return received_S.at(i); }));
  }
  S.resize(128);

  is_ready_condition = std::make_unique<FiberCondition>([this]() { return is_ready.load(); });
}

BaseOtSenderData::BaseOtSenderData() : received_R(128, false) {
  for (auto i = 0; i < 128; ++i) {
    received_R_condition.emplace_back(
        std::make_unique<FiberCondition>([this, i]() { return received_R.at(i); }));
  }
  R.resize(128);

  is_ready_condition = std::make_unique<FiberCondition>([this]() { return is_ready.load(); });
}

void BaseOtData::MessageReceived(const std::uint8_t* message, const BaseOtDataType type,
                                 const std::size_t ot_id) {
  switch (type) {
    case BaseOtDataType::kHL17R: {
      {
        std::scoped_lock lock(sender_data.received_R_condition.at(ot_id)->GetMutex());
        std::copy(message, message + sender_data.R.at(ot_id).size(),
                  reinterpret_cast<std::uint8_t*>(sender_data.R.at(ot_id).data()));
        sender_data.received_R.at(ot_id) = true;
      }
      sender_data.received_R_condition.at(ot_id)->NotifyOne();
      break;
    }
    case BaseOtDataType::kHL17S: {
      {
        std::scoped_lock lock(receiver_data.received_S_condition.at(ot_id)->GetMutex());
        std::copy(message, message + receiver_data.S.at(ot_id).size(),
                  reinterpret_cast<std::uint8_t*>(receiver_data.S.at(ot_id).begin()));
        receiver_data.received_S.at(ot_id) = true;
      }
      receiver_data.received_S_condition.at(ot_id)->NotifyOne();
      break;
    }
    default: {
      throw std::runtime_error(
          fmt::format("DataStorage::BaseOTsReceived: unknown data type {}; data_type must be <{}",
                      type, BaseOtDataType::kBaseOtInvalidDataType));
    }
  }
}

}  // namespace encrypto::motion
