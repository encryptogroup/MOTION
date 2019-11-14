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

#include <thread>
#include "ot_extension_data.h"
#include "utility/condition.h"
#include "utility/fiber_condition.h"

namespace MOTION {

OTExtensionReceiverData::OTExtensionReceiverData() {
  setup_finished_cond_ =
      std::make_unique<ENCRYPTO::Condition>([this]() { return setup_finished_.load(); });
}

OTExtensionSenderData::OTExtensionSenderData() {
  received_u_condition_ =
      std::make_unique<ENCRYPTO::Condition>([this]() { return num_u_received_ == u_.size(); });

  setup_finished_cond_ =
      std::make_unique<ENCRYPTO::Condition>([this]() { return setup_finished_.load(); });
}

void OTExtensionData::MessageReceived(const std::uint8_t *message, const OTExtensionDataType type,
                                      const std::size_t i) {
  switch (type) {
    case OTExtensionDataType::rcv_masks: {
      {
        while (sender_data_.bit_size_ == 0) {
          // FIXME: bit_size_ is accessed without synchronization while we wait
          // for another thread to set its value. This is a data race.
          std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
        std::scoped_lock lock(sender_data_.received_u_condition_->GetMutex());
        sender_data_.u_.at(i) = ENCRYPTO::AlignedBitVector(message, sender_data_.bit_size_);
        sender_data_.num_u_received_++;
        sender_data_.received_u_ids_.push(i);
      }

      sender_data_.received_u_condition_->NotifyAll();
      break;
    }
    case OTExtensionDataType::rcv_corrections: {
      auto cond = sender_data_.received_correction_offsets_cond_.find(i);
      if (cond == sender_data_.received_correction_offsets_cond_.end()) {
        throw std::runtime_error(fmt::format(
            "Could not find Condition for OT#{} OTExtensionDataType::rcv_corrections", i));
      }
      {
        std::scoped_lock lock(cond->second->GetMutex(), sender_data_.corrections_mutex_);
        auto num_ots = sender_data_.num_ots_in_batch_.find(i);
        if (num_ots == sender_data_.num_ots_in_batch_.end()) {
          throw std::runtime_error(fmt::format(
              "Could not find num_ots for OT#{} OTExtensionDataType::rcv_corrections", i));
        }
        ENCRYPTO::BitVector<> local_corrections(message, num_ots->second);
        sender_data_.corrections_.Copy(i, i + num_ots->second, local_corrections);
        sender_data_.received_correction_offsets_.emplace(i);
      }
      cond->second->NotifyAll();
      break;
    }
    case OTExtensionDataType::snd_messages: {
      {
        MOTION::Helpers::WaitFor(*receiver_data_.setup_finished_cond_);

        auto it_c = receiver_data_.output_conds_.find(i);
        if (it_c == receiver_data_.output_conds_.end()) {
          throw std::runtime_error(fmt::format(
              "Could not find Condition for OT#{} OTExtensionDataType::snd_messages", i));
        }

        const auto bitlen = receiver_data_.bitlengths_.at(i);
        const auto bs_it = receiver_data_.num_ots_in_batch_.find(i);
        if (bs_it == receiver_data_.num_ots_in_batch_.end()) {
          throw std::runtime_error(fmt::format(
              "Could not find batch size for OT#{} OTExtensionDataType::snd_messages", i));
        }

        const auto batch_size = bs_it->second;
        while (receiver_data_.num_messages_.find(i) == receiver_data_.num_messages_.end()) {
          // FIXME: num_messages_ is accessed without synchronization while we
          // wait for another thread to set its value. This is a data race.
          std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
        const auto n = receiver_data_.num_messages_.at(i);

        ENCRYPTO::BitVector<> message_bv(message, batch_size * bitlen * n);

        while (receiver_data_.real_choices_cond_.find(i) ==
               receiver_data_.real_choices_cond_.end()) {
          // FIXME: real_choices_cond is accessed without synchronization while
          // we wait for another thread to set its value. This is a data race.
          std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
        MOTION::Helpers::WaitFor(*receiver_data_.real_choices_cond_.at(i));

        for (auto j = 0ull; j < batch_size; ++j) {
          if (n == 2) {
            if (receiver_data_.random_choices_->Get(i + j)) {
              receiver_data_.outputs_.at(i + j) ^=
                  message_bv.Subset((2 * j + 1) * bitlen, (2 * j + 2) * bitlen);
            } else {
              receiver_data_.outputs_.at(i + j) ^=
                  message_bv.Subset(2 * j * bitlen, (2 * j + 1) * bitlen);
            }
          } else if (n == 1) {
            if (receiver_data_.real_choices_->Get(i + j)) {
              if (receiver_data_.xor_correlation_.find(i) !=
                  receiver_data_.xor_correlation_.end()) {
                receiver_data_.outputs_.at(i + j) ^=
                    message_bv.Subset(j * bitlen, (j + 1) * bitlen);
              } else {
                auto msg = message_bv.Subset(j * bitlen, (j + 1) * bitlen);
                auto out = receiver_data_.outputs_.at(i + j).GetMutableData().data();
                switch (bitlen) {
                  case 8u: {
                    *reinterpret_cast<uint8_t *>(out) =
                        *reinterpret_cast<const uint8_t *>(msg.GetData().data()) -
                        *reinterpret_cast<const uint8_t *>(out);
                    break;
                  }
                  case 16u: {
                    *reinterpret_cast<uint16_t *>(out) =
                        *reinterpret_cast<const uint16_t *>(msg.GetData().data()) -
                        *reinterpret_cast<const uint16_t *>(out);
                    break;
                  }
                  case 32u: {
                    *reinterpret_cast<uint32_t *>(out) =
                        *reinterpret_cast<const uint32_t *>(msg.GetData().data()) -
                        *reinterpret_cast<const uint32_t *>(out);
                    break;
                  }
                  case 64u: {
                    *reinterpret_cast<uint64_t *>(out) =
                        *reinterpret_cast<const uint64_t *>(msg.GetData().data()) -
                        *reinterpret_cast<const uint64_t *>(out);
                    break;
                  }
                  case 128u: {
                    *reinterpret_cast<__uint128_t *>(out) =
                        *reinterpret_cast<const __uint128_t *>(msg.GetData().data()) -
                        *reinterpret_cast<const __uint128_t *>(out);
                    break;
                  }
                  default:
                    throw std::runtime_error(
                        fmt::format("Unsupported bitlen={} for additive correlation. Allowed are "
                                    "bitlengths: 8, 16, 32, 64.",
                                    bitlen));
                }
              }
            }
          } else {
            throw std::runtime_error("Not inmplemented yet");
          }
        }

        {
          std::scoped_lock lock(it_c->second->GetMutex(), receiver_data_.received_outputs_mutex_);
          receiver_data_.received_outputs_.emplace(i);
        }
        it_c->second->NotifyAll();
      }
      break;
    }
    default: {
      throw std::runtime_error(fmt::format(
          "DataStorage::OTExtensionDataType: unknown data type {}; data_type must be <{}", type,
          OTExtensionDataType::OTExtension_invalid_data_type));
    }
  }
}

}  // namespace MOTION
