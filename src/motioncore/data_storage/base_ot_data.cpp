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
#include "utility/condition.h"

namespace MOTION {

BaseOTsReceiverData::BaseOTsReceiverData() : received_S_(128, false) {
  for (auto i = 0; i < 128; ++i) {
    received_S_condition_.emplace_back(
        std::make_unique<ENCRYPTO::Condition>([this, i]() { return received_S_.at(i); }));
  }
  S_.resize(128);

  is_ready_condition_ =
      std::make_unique<ENCRYPTO::Condition>([this]() { return is_ready_.load(); });
}

BaseOTsSenderData::BaseOTsSenderData() : received_R_(128, false) {
  for (auto i = 0; i < 128; ++i) {
    received_R_condition_.emplace_back(
        std::make_unique<ENCRYPTO::Condition>([this, i]() { return received_R_.at(i); }));
  }
  R_.resize(128);

  is_ready_condition_ =
      std::make_unique<ENCRYPTO::Condition>([this]() { return is_ready_.load(); });
}

void BaseOTsData::MessageReceived(const std::uint8_t *message, const BaseOTsDataType type,
                                  const std::size_t ot_id) {
  switch (type) {
    case BaseOTsDataType::HL17_R: {
      {
        std::scoped_lock lock(sender_data_.received_R_condition_.at(ot_id)->GetMutex());
        std::copy(message, message + sender_data_.R_.at(ot_id).size(),
                  reinterpret_cast<std::uint8_t *>(sender_data_.R_.at(ot_id).data()));
        sender_data_.received_R_.at(ot_id) = true;
      }
      sender_data_.received_R_condition_.at(ot_id)->NotifyOne();
      break;
    }
    case BaseOTsDataType::HL17_S: {
      {
        std::scoped_lock lock(receiver_data_.received_S_condition_.at(ot_id)->GetMutex());
        std::copy(message, message + receiver_data_.S_.at(ot_id).size(),
                  reinterpret_cast<std::uint8_t *>(receiver_data_.S_.at(ot_id).begin()));
        receiver_data_.received_S_.at(ot_id) = true;
      }
      receiver_data_.received_S_condition_.at(ot_id)->NotifyOne();
      break;
    }
    default: {
      throw std::runtime_error(
          fmt::format("DataStorage::BaseOTsReceived: unknown data type {}; data_type must be <{}",
                      type, BaseOTsDataType::BaseOTs_invalid_data_type));
    }
  }
}

}  // namespace MOTION
