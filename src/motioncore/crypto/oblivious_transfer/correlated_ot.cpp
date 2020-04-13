// MIT License
//
// Copyright (c) 2019 Lennart Braun
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

#include "communication/ot_extension_message.h"
#include "correlated_ot.h"
#include "data_storage/ot_extension_data.h"
#include "utility/fiber_condition.h"

namespace ENCRYPTO {
namespace ObliviousTransfer {

// ---------- BasicCOTSender ----------

BasicCOTSender::BasicCOTSender(std::size_t ot_id, std::size_t num_ots, std::size_t bitlen,
                               OTProtocol p,
                               const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send,
                               MOTION::OTExtensionSenderData &data)
    : OTVector(ot_id, num_ots, bitlen, p, Send), data_(data) {
  data_.received_correction_offsets_cond_.emplace(
      ot_id_, std::make_unique<FiberCondition>([this]() {
        std::scoped_lock lock(data_.corrections_mutex_);
        return data_.received_correction_offsets_.find(ot_id_) !=
               data_.received_correction_offsets_.end();
      }));
  data_.y0_.resize(data_.y0_.size() + num_ots);
  data_.y1_.resize(data_.y1_.size() + num_ots);
  data_.bitlengths_.resize(data_.bitlengths_.size() + num_ots, bitlen);
  data_.corrections_.Resize(data_.corrections_.GetSize() + num_ots);
  data_.num_ots_in_batch_.emplace(ot_id, num_ots);
}

void BasicCOTSender::WaitSetup() const { data_.setup_finished_cond_->Wait(); }

// ---------- BasicCOTReceiver ----------

BasicCOTReceiver::BasicCOTReceiver(
    std::size_t ot_id, std::size_t num_ots, std::size_t bitlen, OTProtocol p,
    const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send,
    MOTION::OTExtensionReceiverData &data)
    : OTVector(ot_id, num_ots, bitlen, p, Send), data_(data) {
  data_.outputs_.resize(ot_id + num_ots);
  data_.bitlengths_.resize(ot_id + num_ots, bitlen);
  data_.num_ots_in_batch_.emplace(ot_id, num_ots);
}

void BasicCOTReceiver::WaitSetup() const { data_.setup_finished_cond_->Wait(); }

void BasicCOTReceiver::SendCorrections() {
  if (choices_.Empty()) {
    throw std::runtime_error("Choices in COT must be set before calling SendCorrections()");
  }
  auto corrections = choices_ ^ data_.random_choices_->Subset(ot_id_, ot_id_ + num_ots_);
  Send_(MOTION::Communication::BuildOTExtensionMessageReceiverCorrections(
      corrections.GetData().data(), corrections.GetData().size(), ot_id_));
  corrections_sent_ = true;
}

// ---------- FixedXCOT128Sender ----------

FixedXCOT128Sender::FixedXCOT128Sender(
    std::size_t ot_id, std::size_t num_ots, MOTION::OTExtensionSenderData &data,
    const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send)
    : BasicCOTSender(ot_id, num_ots, 128, FixedXCOT128, Send, data) {}

void FixedXCOT128Sender::ComputeOutputs() {
  if (outputs_computed_) {
    // the work was already done
    return;
  }

  // setup phase needs to be finished
  WaitSetup();

  // data storage for all the sender data
  const auto &ot_ext_snd = data_;

  // wait until the receiver has sent its correction bits
  ot_ext_snd.received_correction_offsets_cond_.at(ot_id_)->Wait();

  // make space for all the OTs
  outputs_.resize(num_ots_);

  // get the corrections bits
  std::unique_lock lock(ot_ext_snd.corrections_mutex_);
  const auto corrections = ot_ext_snd.corrections_.Subset(ot_id_, ot_id_ + num_ots_);
  lock.unlock();

  // take one of the precomputed outputs
  for (std::size_t i = 0; i < num_ots_; ++i) {
    if (corrections[i]) {
      // if the correction bit is 1, we need to swap
      outputs_[i].load_from_memory(ot_ext_snd.y1_.at(ot_id_ + i).GetData().data());
    } else {
      outputs_[i].load_from_memory(ot_ext_snd.y0_.at(ot_id_ + i).GetData().data());
    }
  }

  // remember that we have done this
  outputs_computed_ = true;
}

void FixedXCOT128Sender::SendMessages() const {
  block128_vector buffer(num_ots_, correlation_);
  const auto &ot_ext_snd = data_;
  for (std::size_t i = 0; i < num_ots_; ++i) {
    buffer[i] ^= ot_ext_snd.y0_.at(ot_id_ + i).GetData().data();
    buffer[i] ^= ot_ext_snd.y1_.at(ot_id_ + i).GetData().data();
  }
  Send_(MOTION::Communication::BuildOTExtensionMessageSender(buffer.data()->data(),
                                                             buffer.byte_size(), ot_id_));
}

// ---------- FixedXCOT128Receiver ----------

FixedXCOT128Receiver::FixedXCOT128Receiver(
    const std::size_t ot_id, const std::size_t num_ots, MOTION::OTExtensionReceiverData &data,
    const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send)
    : BasicCOTReceiver(ot_id, num_ots, 128, FixedXCOT128, Send, data), outputs_(num_ots) {
  data_.fixed_xcot_128_ot_.emplace(ot_id);
  sender_message_future_ = data_.RegisterForXCOT128SenderMessage(ot_id);
}

void FixedXCOT128Receiver::ComputeOutputs() {
  if (outputs_computed_) {
    // already done
    return;
  }

  if (!corrections_sent_) {
    throw std::runtime_error("Choices in COT must be se(n)t before calling ComputeOutputs()");
  }
  auto sender_message = sender_message_future_.get();

  for (std::size_t i = 0; i < num_ots_; ++i) {
    outputs_[i].load_from_memory(data_.outputs_.at(ot_id_ + i).GetData().data());
    if (choices_[i]) {
      outputs_[i] ^= sender_message[i];
    }
  }
  outputs_computed_ = true;
}

// ---------- XCOTBitSender ----------

XCOTBitSender::XCOTBitSender(const std::size_t ot_id, const std::size_t num_ots,
                             MOTION::OTExtensionSenderData &data,
                             const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send)
    : BasicCOTSender(ot_id, num_ots, 1, XCOTBit, Send, data) {}

void XCOTBitSender::ComputeOutputs() {
  if (outputs_computed_) {
    // the work was already done
    return;
  }

  // setup phase needs to be finished
  WaitSetup();

  // wait until the receiver has sent its correction bits
  data_.received_correction_offsets_cond_.at(ot_id_)->Wait();

  // make space for all the OTs
  outputs_.Resize(num_ots_);

  // get the corrections bits
  std::unique_lock lock(data_.corrections_mutex_);
  const auto corrections = data_.corrections_.Subset(ot_id_, ot_id_ + num_ots_);
  lock.unlock();

  // take one of the precomputed outputs
  for (std::size_t i = 0; i < num_ots_; ++i) {
    if (corrections[i]) {
      // if the correction bit is 1, we need to swap
      outputs_.Set(bool(data_.y1_.at(ot_id_ + i).GetData()[0] & SET_BIT_MASK[0]), i);
    } else {
      outputs_.Set(bool(data_.y0_.at(ot_id_ + i).GetData()[0] & SET_BIT_MASK[0]), i);
    }
  }

  // remember that we have done this
  outputs_computed_ = true;
}

void XCOTBitSender::SendMessages() const {
  auto buffer = correlations_;
  for (std::size_t i = 0; i < num_ots_; ++i) {
    auto tmp = buffer[i];
    tmp ^= bool(data_.y0_.at(ot_id_ + i).GetData()[0] & SET_BIT_MASK[0]);
    tmp ^= bool(data_.y1_.at(ot_id_ + i).GetData()[0] & SET_BIT_MASK[0]);
    buffer.Set(tmp, i);
  }
  Send_(MOTION::Communication::BuildOTExtensionMessageSender(buffer.GetData().data(),
                                                             buffer.GetData().size(), ot_id_));
}

// ---------- XCOTBitReceiver ----------

XCOTBitReceiver::XCOTBitReceiver(const std::size_t ot_id, const std::size_t num_ots,
                                 MOTION::OTExtensionReceiverData &data,
                                 const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send)
    : BasicCOTReceiver(ot_id, num_ots, 1, XCOTBit, Send, data), outputs_(num_ots) {
  data_.xcot_1_ot_.emplace(ot_id);
  sender_message_future_ = data_.RegisterForXCOTBitSenderMessage(ot_id);
}

void XCOTBitReceiver::ComputeOutputs() {
  if (outputs_computed_) {
    // already done
    return;
  }

  if (!corrections_sent_) {
    throw std::runtime_error("Choices in COT must be se(n)t before calling ComputeOutputs()");
  }

  outputs_ = sender_message_future_.get();
  outputs_ &= choices_;

  for (std::size_t i = 0; i < num_ots_; ++i) {
    auto tmp = outputs_[i];
    outputs_.Set(tmp ^ bool(data_.outputs_.at(ot_id_ + i).GetData()[0] & SET_BIT_MASK[0]), i);
  }
  outputs_computed_ = true;
}

}  // namespace ObliviousTransfer
}  // namespace ENCRYPTO
