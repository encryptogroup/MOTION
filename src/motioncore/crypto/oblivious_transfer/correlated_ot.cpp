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
#include "data_storage/data_storage.h"
#include "data_storage/ot_extension_data.h"
#include "utility/fiber_condition.h"

namespace ENCRYPTO {
namespace ObliviousTransfer {

// ---------- BasicCOTSender ----------

void BasicCOTSender::WaitSetup() const {
  data_storage_->GetOTExtensionData()->GetSenderData().setup_finished_cond_->Wait();
}

// ---------- BasicCOTReceiver ----------

void BasicCOTReceiver::WaitSetup() const {
  data_storage_->GetOTExtensionData()->GetReceiverData().setup_finished_cond_->Wait();
}

void BasicCOTReceiver::SendCorrections() {
  if (choices_.Empty()) {
    throw std::runtime_error("Choices in COT must be set before calling SendCorrections()");
  }
  const auto &ot_ext_rcv = data_storage_->GetOTExtensionData()->GetReceiverData();
  auto corrections = choices_ ^ ot_ext_rcv.random_choices_->Subset(ot_id_, ot_id_ + num_ots_);
  Send_(MOTION::Communication::BuildOTExtensionMessageReceiverCorrections(
      corrections.GetData().data(), corrections.GetData().size(), ot_id_));
  corrections_sent_ = true;
}

// ---------- FixedXCOT128VectorSender ----------

FixedXCOT128VectorSender::FixedXCOT128VectorSender(
    const std::size_t ot_id, const std::size_t num_ots,
    const std::shared_ptr<MOTION::DataStorage> &data_storage,
    const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send)
    : BasicCOTSender(ot_id, num_ots, 128, FixedXCOT128, data_storage, Send) {
  auto &ot_ext_snd = data_storage_->GetOTExtensionData()->GetSenderData();
  ot_ext_snd.received_correction_offsets_cond_.emplace(
      ot_id_, std::make_unique<FiberCondition>([this, &ot_ext_snd]() {
        std::scoped_lock lock(ot_ext_snd.corrections_mutex_);
        return ot_ext_snd.received_correction_offsets_.find(ot_id_) !=
               ot_ext_snd.received_correction_offsets_.end();
      }));

  ot_ext_snd.y0_.resize(ot_ext_snd.y0_.size() + num_ots);
  ot_ext_snd.y1_.resize(ot_ext_snd.y1_.size() + num_ots);
  ot_ext_snd.bitlengths_.resize(ot_ext_snd.bitlengths_.size() + num_ots, 128);
  ot_ext_snd.corrections_.Resize(ot_ext_snd.corrections_.GetSize() + num_ots);
  ot_ext_snd.num_ots_in_batch_.emplace(ot_id, num_ots);
}

void FixedXCOT128VectorSender::ComputeOutputs() {
  if (outputs_computed_) {
    // the work was already done
    return;
  }

  // setup phase needs to be finished
  WaitSetup();

  // data storage for all the sender data
  const auto &ot_ext_snd = data_storage_->GetOTExtensionData()->GetSenderData();

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

  // remember that the have done this
  outputs_computed_ = true;
}

void FixedXCOT128VectorSender::SendMessages() const {
  block128_vector buffer(num_ots_, correlation_);
  const auto &ot_ext_snd = data_storage_->GetOTExtensionData()->GetSenderData();
  for (std::size_t i = 0; i < num_ots_; ++i) {
    buffer[i] ^= ot_ext_snd.y0_.at(ot_id_ + i).GetData().data();
    buffer[i] ^= ot_ext_snd.y1_.at(ot_id_ + i).GetData().data();
  }
  Send_(MOTION::Communication::BuildOTExtensionMessageSender(buffer.data()->data(),
                                                             buffer.byte_size(), ot_id_));
}

// ---------- FixedXCOT128VectorReceiver ----------

FixedXCOT128VectorReceiver::FixedXCOT128VectorReceiver(
    const std::size_t ot_id, const std::size_t num_ots,
    const std::shared_ptr<MOTION::DataStorage> &data_storage,
    const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send)
    : BasicCOTReceiver(ot_id, num_ots, 128, FixedXCOT128, data_storage, Send), outputs_(num_ots) {
  auto &ot_ext_rcv = data_storage_->GetOTExtensionData()->GetReceiverData();

  ot_ext_rcv.outputs_.resize(ot_id + num_ots);
  ot_ext_rcv.bitlengths_.resize(ot_id + num_ots, 128);
  ot_ext_rcv.num_ots_in_batch_.emplace(ot_id, num_ots);

  ot_ext_rcv.fixed_xcot_128_ot_.emplace(ot_id);

  sender_message_future_ =
      data_storage_->GetOTExtensionData()->RegisterForXCOT128SenderMessage(ot_id);
}

void FixedXCOT128VectorReceiver::ComputeOutputs() {
  if (outputs_computed_) {
    // already done
    return;
  }

  if (!corrections_sent_) {
    throw std::runtime_error("Choices in COT must be se(n)t before calling ComputeOutputs()");
  }
  auto sender_message = sender_message_future_.get();
  const auto &ot_ext_rcv = data_storage_->GetOTExtensionData()->GetReceiverData();

  for (std::size_t i = 0; i < num_ots_; ++i) {
    outputs_[i].load_from_memory(ot_ext_rcv.outputs_.at(ot_id_ + i).GetData().data());
    if (choices_[i]) {
      outputs_[i] ^= sender_message[i];
    }
  }
  outputs_computed_ = true;
}

// ---------- XCOTBitVectorSender ----------

XCOTBitVectorSender::XCOTBitVectorSender(
    const std::size_t ot_id, const std::size_t num_ots,
    const std::shared_ptr<MOTION::DataStorage> &data_storage,
    const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send)
    : BasicCOTSender(ot_id, num_ots, 1, XCOTBit, data_storage, Send) {
  auto &ot_ext_snd = data_storage_->GetOTExtensionData()->GetSenderData();
  ot_ext_snd.received_correction_offsets_cond_.emplace(
      ot_id_, std::make_unique<FiberCondition>([this, &ot_ext_snd]() {
        std::scoped_lock lock(ot_ext_snd.corrections_mutex_);
        return ot_ext_snd.received_correction_offsets_.find(ot_id_) !=
               ot_ext_snd.received_correction_offsets_.end();
      }));

  ot_ext_snd.y0_.resize(ot_ext_snd.y0_.size() + num_ots);
  ot_ext_snd.y1_.resize(ot_ext_snd.y1_.size() + num_ots);
  ot_ext_snd.bitlengths_.resize(ot_ext_snd.bitlengths_.size() + num_ots, 1);
  ot_ext_snd.corrections_.Resize(ot_ext_snd.corrections_.GetSize() + num_ots);
  ot_ext_snd.num_ots_in_batch_.emplace(ot_id, num_ots);
}

void XCOTBitVectorSender::ComputeOutputs() {
  if (outputs_computed_) {
    // the work was already done
    return;
  }

  // setup phase needs to be finished
  WaitSetup();

  // data storage for all the sender data
  const auto &ot_ext_snd = data_storage_->GetOTExtensionData()->GetSenderData();

  // wait until the receiver has sent its correction bits
  ot_ext_snd.received_correction_offsets_cond_.at(ot_id_)->Wait();

  // make space for all the OTs
  outputs_.Resize(num_ots_);

  // get the corrections bits
  std::unique_lock lock(ot_ext_snd.corrections_mutex_);
  const auto corrections = ot_ext_snd.corrections_.Subset(ot_id_, ot_id_ + num_ots_);
  lock.unlock();

  // take one of the precomputed outputs
  for (std::size_t i = 0; i < num_ots_; ++i) {
    if (corrections[i]) {
      // if the correction bit is 1, we need to swap
      outputs_.Set(bool(ot_ext_snd.y1_.at(ot_id_ + i).GetData()[0] & SET_BIT_MASK[0]), i);
    } else {
      outputs_.Set(bool(ot_ext_snd.y0_.at(ot_id_ + i).GetData()[0] & SET_BIT_MASK[0]), i);
    }
  }

  // remember that the have done this
  outputs_computed_ = true;
}

void XCOTBitVectorSender::SendMessages() const {
  auto buffer = correlations_;
  const auto &ot_ext_snd = data_storage_->GetOTExtensionData()->GetSenderData();
  for (std::size_t i = 0; i < num_ots_; ++i) {
    auto tmp = buffer[i];
    tmp ^= bool(ot_ext_snd.y0_.at(ot_id_ + i).GetData()[0] & SET_BIT_MASK[0]);
    tmp ^= bool(ot_ext_snd.y1_.at(ot_id_ + i).GetData()[0] & SET_BIT_MASK[0]);
    buffer.Set(tmp, i);
  }
  Send_(MOTION::Communication::BuildOTExtensionMessageSender(buffer.GetData().data(),
                                                             buffer.GetData().size(), ot_id_));
}

// ---------- XCOTBitVectorReceiver ----------

XCOTBitVectorReceiver::XCOTBitVectorReceiver(
    const std::size_t ot_id, const std::size_t num_ots,
    const std::shared_ptr<MOTION::DataStorage> &data_storage,
    const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send)
    : BasicCOTReceiver(ot_id, num_ots, 1, XCOTBit, data_storage, Send), outputs_(num_ots) {
  auto &ot_ext_rcv = data_storage_->GetOTExtensionData()->GetReceiverData();

  ot_ext_rcv.outputs_.resize(ot_id + num_ots);
  ot_ext_rcv.bitlengths_.resize(ot_id + num_ots, 1);
  ot_ext_rcv.num_ots_in_batch_.emplace(ot_id, num_ots);

  ot_ext_rcv.xcot_1_ot_.emplace(ot_id);

  sender_message_future_ =
      data_storage_->GetOTExtensionData()->RegisterForXCOTBitSenderMessage(ot_id);
}

void XCOTBitVectorReceiver::ComputeOutputs() {
  if (outputs_computed_) {
    // already done
    return;
  }

  if (!corrections_sent_) {
    throw std::runtime_error("Choices in COT must be se(n)t before calling ComputeOutputs()");
  }
  const auto &ot_ext_rcv = data_storage_->GetOTExtensionData()->GetReceiverData();

  outputs_ = sender_message_future_.get();
  outputs_ &= choices_;

  for (std::size_t i = 0; i < num_ots_; ++i) {
    auto tmp = outputs_[i];
    outputs_.Set(tmp ^ bool(ot_ext_rcv.outputs_.at(ot_id_ + i).GetData()[0] & SET_BIT_MASK[0]), i);
  }
  outputs_computed_ = true;
}

}  // namespace ObliviousTransfer
}  // namespace ENCRYPTO
