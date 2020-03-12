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

#include "ot_extension_data.h"

#include <thread>

#include "utility/block.h"
#include "utility/condition.h"
#include "utility/fiber_condition.h"

namespace MOTION {

OTExtensionReceiverData::OTExtensionReceiverData() {
  setup_finished_cond_ =
      std::make_unique<ENCRYPTO::FiberCondition>([this]() { return setup_finished_.load(); });
}

OTExtensionSenderData::OTExtensionSenderData() {
  setup_finished_cond_ =
      std::make_unique<ENCRYPTO::FiberCondition>([this]() { return setup_finished_.load(); });

  for (std::size_t i = 0; i < u_promises_.size(); ++i) u_futures_[i] = u_promises_[i].get_future();
}

void OTExtensionData::MessageReceived(const std::uint8_t *message, const OTExtensionDataType type,
                                      const std::size_t i) {
  switch (type) {
    case OTExtensionDataType::rcv_masks: {
      {
        while (sender_data_.bit_size_ == 0) std::this_thread::yield();
        std::scoped_lock lock(sender_data_.u_mutex_);
        sender_data_.u_[i] = ENCRYPTO::AlignedBitVector(message, sender_data_.bit_size_);
        sender_data_.u_promises_[sender_data_.num_received_u_].set_value(i);

        // set to 0 after Clear()
        sender_data_.num_received_u_++;
      }

      break;
    }
    case OTExtensionDataType::rcv_corrections: {
      auto cond = sender_data_.received_correction_offsets_cond_.find(i);
      assert(cond != sender_data_.received_correction_offsets_cond_.end());
      {
        std::scoped_lock lock(cond->second->GetMutex(), sender_data_.corrections_mutex_);
        auto num_ots = sender_data_.num_ots_in_batch_.find(i);
        assert(num_ots != sender_data_.num_ots_in_batch_.end());
        ENCRYPTO::BitVector<> local_corrections(message, num_ots->second);
        sender_data_.corrections_.Copy(i, i + num_ots->second, local_corrections);
        sender_data_.received_correction_offsets_.emplace(i);
      }
      cond->second->NotifyAll();
      break;
    }
    case OTExtensionDataType::snd_messages: {
      {
        receiver_data_.setup_finished_cond_->Wait();

        std::unique_lock lock(receiver_data_.bitlengths_mutex_);
        const auto bitlen = receiver_data_.bitlengths_.at(i);
        lock.unlock();

        const auto bs_it = receiver_data_.num_ots_in_batch_.find(i);
        assert(bs_it != receiver_data_.num_ots_in_batch_.end());
        const auto batch_size = bs_it->second;

        if (receiver_data_.fixed_xcot_128_ot_.count(i) == 1) {
          // XXX: new implementation, don't do the work here, just put the
          // message into the future
          auto promise_it = receiver_data_.xcot_128_ot_message_promises_.find(i);
          assert(promise_it != receiver_data_.xcot_128_ot_message_promises_.end());
          promise_it->second.set_value(ENCRYPTO::block128_vector(batch_size, message));
          return;
        } else if (receiver_data_.xcot_1_ot_.count(i) == 1) {
          // XXX: new implementation, don't do the work here
          auto promise_it = receiver_data_.xcot_1_ot_message_promises_.find(i);
          assert(promise_it != receiver_data_.xcot_1_ot_message_promises_.end());
          promise_it->second.set_value(ENCRYPTO::BitVector<>(message, batch_size));
          return;
        }

        auto it_c = receiver_data_.output_conds_.find(i);
        assert(it_c != receiver_data_.output_conds_.end());

        bool success{false};
        do {
          {
            std::scoped_lock lock(receiver_data_.num_messages_mutex_);
            success = receiver_data_.num_messages_.find(i) != receiver_data_.num_messages_.end();
          }
          if (!success) std::this_thread::yield();
        } while (!success);

        const auto n = receiver_data_.num_messages_.at(i);

        ENCRYPTO::BitVector<> message_bv(message, batch_size * bitlen * n);

        success = false;
        do {
          {
            std::scoped_lock lock(receiver_data_.real_choices_mutex_);
            success = receiver_data_.real_choices_cond_.find(i) !=
                      receiver_data_.real_choices_cond_.end();
          }
          if (!success) std::this_thread::yield();
        } while (!success);
        receiver_data_.real_choices_cond_.at(i)->Wait();

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

ENCRYPTO::ReusableFiberFuture<ENCRYPTO::block128_vector>
OTExtensionReceiverData::RegisterForXCOT128SenderMessage(const std::size_t ot_id) {
  ENCRYPTO::ReusableFiberPromise<ENCRYPTO::block128_vector> promise;
  auto fut = promise.get_future();
  auto [it, success] =
      xcot_128_ot_message_promises_.insert({ot_id, std::move(promise)});
  if (!success) {
    throw std::runtime_error(
        fmt::format("tried to register twice for XCOT128SenderMessage for OT#{}", ot_id));
  }
  return fut;
}

ENCRYPTO::ReusableFiberFuture<ENCRYPTO::BitVector<>>
OTExtensionReceiverData::RegisterForXCOTBitSenderMessage(const std::size_t ot_id) {
  ENCRYPTO::ReusableFiberPromise<ENCRYPTO::BitVector<>> promise;
  auto fut = promise.get_future();
  auto [it, success] =
      xcot_1_ot_message_promises_.insert({ot_id, std::move(promise)});
  if (!success) {
    throw std::runtime_error(
        fmt::format("tried to register twice for XCOTBitSenderMessage for OT#{}", ot_id));
  }
  return fut;
}

}  // namespace MOTION
