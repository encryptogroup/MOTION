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

#include "ot_flavors.h"

#include "communication/ot_extension_message.h"
#include "data_storage/ot_extension_data.h"
#include "utility/fiber_condition.h"

namespace encrypto::motion {

// ---------- BasicOtSender ----------

BasicOtSender::BasicOtSender(
    std::size_t ot_id, std::size_t number_of_ots, std::size_t bitlength, OtProtocol p,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function,
    OtExtensionSenderData& data)
    : OtVector(ot_id, number_of_ots, bitlength, p, send_function), data_(data) {
  data_.received_correction_offsets_condition.emplace(
      ot_id_, std::make_unique<FiberCondition>([this]() {
        std::scoped_lock lock(data_.corrections_mutex);
        return data_.received_correction_offsets.find(ot_id_) !=
               data_.received_correction_offsets.end();
      }));
  data_.y0.resize(data_.y0.size() + number_of_ots);
  data_.y1.resize(data_.y1.size() + number_of_ots);
  data_.bitlengths.resize(data_.bitlengths.size() + number_of_ots, bitlength);
  data_.corrections.Resize(data_.corrections.GetSize() + number_of_ots);
  data_.number_of_ots_in_batch.emplace(ot_id, number_of_ots);
}

void BasicOtSender::WaitSetup() const { data_.setup_finished_condition->Wait(); }

// ---------- BasicOtReceiver ----------

BasicOtReceiver::BasicOtReceiver(
    std::size_t ot_id, std::size_t number_of_ots, std::size_t bitlength, OtProtocol p,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function,
    OtExtensionReceiverData& data)
    : OtVector(ot_id, number_of_ots, bitlength, p, send_function), data_(data) {
  data_.outputs.resize(ot_id + number_of_ots);
  data_.bitlengths.resize(ot_id + number_of_ots, bitlength);
  data_.number_of_ots_in_batch.emplace(ot_id, number_of_ots);
}

void BasicOtReceiver::WaitSetup() const { data_.setup_finished_condition->Wait(); }

void BasicOtReceiver::SendCorrections() {
  if (choices_.Empty()) {
    throw std::runtime_error("Choices in COT must be set before calling SendCorrections()");
  }
  auto corrections = choices_ ^ data_.random_choices->Subset(ot_id_, ot_id_ + number_of_ots_);
  send_function_(communication::BuildOtExtensionMessageReceiverCorrections(
      corrections.GetData().data(), corrections.GetData().size(), ot_id_));
  corrections_sent_ = true;
}

ROtSender::ROtSender(std::size_t ot_id, std::size_t number_of_ots, std::size_t bitlength,
                     OtExtensionSenderData& data,
                     const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function)
    : OtVector(ot_id, number_of_ots, bitlength, kROt, send_function), data_(data) {
  data_.received_correction_offsets_condition.emplace(
      ot_id_, std::make_unique<FiberCondition>([this]() {
        std::scoped_lock lock(data_.corrections_mutex);
        return data_.received_correction_offsets.find(ot_id_) !=
               data_.received_correction_offsets.end();
      }));
  data_.y0.resize(data_.y0.size() + number_of_ots);
  data_.y1.resize(data_.y1.size() + number_of_ots);
  data_.bitlengths.resize(data_.bitlengths.size() + number_of_ots, bitlength);
  data_.number_of_ots_in_batch.emplace(ot_id, number_of_ots);
}

void ROtSender::WaitSetup() const { data_.setup_finished_condition->Wait(); }

void ROtSender::ComputeOutputs() {
  if (outputs_computed_) {
    // the work was already done
    return;
  }

  // setup phase needs to be finished
  WaitSetup();

  // data storage for all the sender data
  const auto& ot_extension_sender_data = data_;

  // make space for all the OTs
  outputs_.resize(number_of_ots_);

  // append both masks as the output
  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    outputs_[i].Reserve(bitlen_ * 2);
    outputs_[i].Append(ot_extension_sender_data.y0.at(ot_id_ + i));
    outputs_[i].Append(ot_extension_sender_data.y1.at(ot_id_ + i));
  }

  // remember that we have done this
  outputs_computed_ = true;
}

ROtReceiver::ROtReceiver(std::size_t ot_id, std::size_t number_of_ots, std::size_t bitlength,
                         OtExtensionReceiverData& data,
                         const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function)
    : OtVector(ot_id, number_of_ots, bitlength, kROt, send_function), data_(data) {
  data_.outputs.resize(ot_id + number_of_ots);
  data_.bitlengths.resize(ot_id + number_of_ots, bitlength);
  data_.number_of_ots_in_batch.emplace(ot_id, number_of_ots);
}

void ROtReceiver::WaitSetup() const { data_.setup_finished_condition->Wait(); }

void ROtReceiver::ComputeOutputs() {
  if (outputs_computed_) {
    // the work was already done
    return;
  }

  // setup phase needs to be finished
  WaitSetup();

  // copy random choices to the internal buffer
  choices_ = data_.random_choices->Subset(ot_id_, ot_id_ + number_of_ots_);

  // copy the selected random mask to the internal buffer
  outputs_.assign(data_.outputs.begin() + ot_id_, data_.outputs.begin() + ot_id_ + number_of_ots_);

  // flag that the outputs have been computed
  outputs_computed_ = true;
}

// ---------- Generic XcOtSender ----------

XcOtSender::XcOtSender(std::size_t ot_id, std::size_t number_of_ots, std::size_t bitlength,
                       OtExtensionSenderData& data,
                       const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function)
    : BasicOtSender(ot_id, number_of_ots, bitlength, kXcOt, send_function, data) {}

void XcOtSender::ComputeOutputs() {
  if (outputs_computed_) {
    // the work was already done
    return;
  }

  // setup phase needs to be finished
  WaitSetup();

  // data storage for all the sender data
  const auto& ot_extension_sender_data = data_;

  // wait until the receiver has sent its correction bits
  ot_extension_sender_data.received_correction_offsets_condition.at(ot_id_)->Wait();

  // make space for all the OTs
  outputs_.resize(number_of_ots_);

  // get the corrections bits
  std::unique_lock lock(ot_extension_sender_data.corrections_mutex);
  const auto corrections =
      ot_extension_sender_data.corrections.Subset(ot_id_, ot_id_ + number_of_ots_);
  lock.unlock();

  // take one of the precomputed outputs
  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    outputs_[i].Reserve(bitlen_ * 2);
    if (corrections[i]) {
      // if the correction bit is 1, we need to swap
      outputs_[i].Append(ot_extension_sender_data.y1.at(ot_id_ + i));
    } else {
      outputs_[i].Append(ot_extension_sender_data.y0.at(ot_id_ + i));
    }
    outputs_[i].Append(correlations_[i] ^ outputs_[i]);
  }

  // remember that we have done this
  outputs_computed_ = true;
}

void XcOtSender::SendMessages() const {
  BitVector<> buffer;
  buffer.Reserve(bitlen_ * number_of_ots_);
  const auto& ot_extension_sender_data = data_;
  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    buffer.Append(correlations_[i] ^ ot_extension_sender_data.y0.at(ot_id_ + i) ^
                  ot_extension_sender_data.y1.at(ot_id_ + i));
  }
  send_function_(communication::BuildOtExtensionMessageSender(buffer.GetData().data(),
                                                              buffer.GetData().size(), ot_id_));
}

// ---------- Generic XcOtReceiver ----------

XcOtReceiver::XcOtReceiver(
    const std::size_t ot_id, const std::size_t number_of_ots, const std::size_t bitlength,
    OtExtensionReceiverData& data,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function)
    : BasicOtReceiver(ot_id, number_of_ots, bitlength, kXcOt, send_function, data),
      outputs_(number_of_ots) {
  data_.message_type.emplace(ot_id, OtMessageType::kGenericBoolean);
  sender_message_future_ = data_.RegisterForGenericSenderMessage(ot_id, number_of_ots, bitlength);
}

void XcOtReceiver::ComputeOutputs() {
  if (outputs_computed_) {
    // already done
    return;
  }

  if (!corrections_sent_) {
    throw std::runtime_error("Choices in COT must be se(n)t before calling ComputeOutputs()");
  }
  auto sender_message = sender_message_future_.get();

  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    assert(sender_message[i].GetSize() == bitlen_);
    outputs_[i] = std::move(data_.outputs.at(ot_id_ + i));
    assert(outputs_[i].GetSize() == bitlen_);
    if (choices_[i]) {
      outputs_[i] ^= sender_message[i];
    }
  }
  outputs_computed_ = true;
}

// ---------- FixedXcOt128Sender ----------

FixedXcOt128Sender::FixedXcOt128Sender(
    std::size_t ot_id, std::size_t number_of_ots, OtExtensionSenderData& data,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function)
    : BasicOtSender(ot_id, number_of_ots, 128, kFixedXcOt128, send_function, data) {}

void FixedXcOt128Sender::ComputeOutputs() {
  if (outputs_computed_) {
    // the work was already done
    return;
  }

  // setup phase needs to be finished
  WaitSetup();

  // data storage for all the sender data
  const auto& ot_extension_sender_data = data_;

  // wait until the receiver has sent its correction bits
  ot_extension_sender_data.received_correction_offsets_condition.at(ot_id_)->Wait();

  // make space for all the OTs
  outputs_.resize(number_of_ots_);

  // get the corrections bits
  std::unique_lock lock(ot_extension_sender_data.corrections_mutex);
  const auto corrections =
      ot_extension_sender_data.corrections.Subset(ot_id_, ot_id_ + number_of_ots_);
  lock.unlock();

  // take one of the precomputed outputs
  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    if (corrections[i]) {
      // if the correction bit is 1, we need to swap
      outputs_[i].LoadFromMemory(ot_extension_sender_data.y1.at(ot_id_ + i).GetData().data());
    } else {
      outputs_[i].LoadFromMemory(ot_extension_sender_data.y0.at(ot_id_ + i).GetData().data());
    }
  }

  // remember that we have done this
  outputs_computed_ = true;
}

void FixedXcOt128Sender::SendMessages() const {
  Block128Vector buffer(number_of_ots_, correlation_);
  const auto& ot_extension_sender_data = data_;
  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    buffer[i] ^= ot_extension_sender_data.y0.at(ot_id_ + i).GetData().data();
    buffer[i] ^= ot_extension_sender_data.y1.at(ot_id_ + i).GetData().data();
  }
  send_function_(communication::BuildOtExtensionMessageSender(buffer.data()->data(),
                                                              buffer.ByteSize(), ot_id_));
}

// ---------- FixedXcOt128Receiver ----------

FixedXcOt128Receiver::FixedXcOt128Receiver(
    const std::size_t ot_id, const std::size_t number_of_ots, OtExtensionReceiverData& data,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function)
    : BasicOtReceiver(ot_id, number_of_ots, 128, kFixedXcOt128, send_function, data),
      outputs_(number_of_ots) {
  data_.message_type.emplace(ot_id, OtMessageType::kBlock128);
  sender_message_future_ = data_.RegisterForBlock128SenderMessage(ot_id, number_of_ots);
}

void FixedXcOt128Receiver::ComputeOutputs() {
  if (outputs_computed_) {
    // already done
    return;
  }

  if (!corrections_sent_) {
    throw std::runtime_error("Choices in COT must be se(n)t before calling ComputeOutputs()");
  }
  auto sender_message = sender_message_future_.get();

  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    outputs_[i].LoadFromMemory(data_.outputs.at(ot_id_ + i).GetData().data());
    if (choices_[i]) {
      outputs_[i] ^= sender_message[i];
    }
  }
  outputs_computed_ = true;
}

// ---------- XcOtBitSender ----------

XcOtBitSender::XcOtBitSender(
    const std::size_t ot_id, const std::size_t number_of_ots, OtExtensionSenderData& data,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function)
    : BasicOtSender(ot_id, number_of_ots, 1, kXcOtBit, send_function, data) {}

void XcOtBitSender::ComputeOutputs() {
  if (outputs_computed_) {
    // the work was already done
    return;
  }

  // setup phase needs to be finished
  WaitSetup();

  // wait until the receiver has sent its correction bits
  data_.received_correction_offsets_condition.at(ot_id_)->Wait();

  // make space for all the OTs
  outputs_.Resize(number_of_ots_);

  // get the corrections bits
  std::unique_lock lock(data_.corrections_mutex);
  const auto corrections = data_.corrections.Subset(ot_id_, ot_id_ + number_of_ots_);
  lock.unlock();

  // take one of the precomputed outputs
  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    if (corrections[i]) {
      // if the correction bit is 1, we need to swap
      outputs_.Set(bool(data_.y1.at(ot_id_ + i).GetData()[0] & kSetBitMask[0]), i);
    } else {
      outputs_.Set(bool(data_.y0.at(ot_id_ + i).GetData()[0] & kSetBitMask[0]), i);
    }
  }

  // remember that we have done this
  outputs_computed_ = true;
}

void XcOtBitSender::SendMessages() const {
  auto buffer = correlations_;
  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    auto tmp = buffer[i];
    tmp ^= bool(data_.y0.at(ot_id_ + i).GetData()[0] & kSetBitMask[0]);
    tmp ^= bool(data_.y1.at(ot_id_ + i).GetData()[0] & kSetBitMask[0]);
    buffer.Set(tmp, i);
  }
  send_function_(communication::BuildOtExtensionMessageSender(buffer.GetData().data(),
                                                              buffer.GetData().size(), ot_id_));
}

// ---------- XcOtBitReceiver ----------

XcOtBitReceiver::XcOtBitReceiver(
    const std::size_t ot_id, const std::size_t number_of_ots, OtExtensionReceiverData& data,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function)
    : BasicOtReceiver(ot_id, number_of_ots, 1, kXcOtBit, send_function, data),
      outputs_(number_of_ots) {
  data_.message_type.emplace(ot_id, OtMessageType::kBit);
  sender_message_future_ = data_.RegisterForBitSenderMessage(ot_id, number_of_ots);
}

void XcOtBitReceiver::ComputeOutputs() {
  if (outputs_computed_) {
    // already done
    return;
  }

  if (!corrections_sent_) {
    throw std::runtime_error("Choices in COT must be se(n)t before calling ComputeOutputs()");
  }

  outputs_ = sender_message_future_.get();
  outputs_ &= choices_;

  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    auto tmp = outputs_[i];
    outputs_.Set(tmp ^ bool(data_.outputs.at(ot_id_ + i).GetData()[0] & kSetBitMask[0]), i);
  }
  outputs_computed_ = true;
}

// ---------- AcOtSender ----------

template <typename T>
AcOtSender<T>::AcOtSender(
    const std::size_t ot_id, const std::size_t number_of_ots, const std::size_t vector_size,
    OtExtensionSenderData& data,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function)
    : BasicOtSender(ot_id, number_of_ots, 8 * sizeof(T) * vector_size, kAcOt, send_function, data),
      vector_size_(vector_size) {}

template <typename T>
void AcOtSender<T>::ComputeOutputs() {
  if (outputs_computed_) {
    // the work was already done
    return;
  }

  // setup phase needs to be finished
  WaitSetup();

  // wait until the receiver has sent its correction bits
  data_.received_correction_offsets_condition.at(ot_id_)->Wait();

  // make space for all the OTs
  outputs_.resize(number_of_ots_ * vector_size_);

  // get the corrections bits
  std::unique_lock lock(data_.corrections_mutex);
  const auto corrections = data_.corrections.Subset(ot_id_, ot_id_ + number_of_ots_);
  lock.unlock();

  // take one of the precomputed outputs
  if (vector_size_ == 1) {
    for (std::size_t ot_i = 0; ot_i < number_of_ots_; ++ot_i) {
      if (corrections[ot_i]) {
        // if the correction bit is 1, we need to swap
        outputs_[ot_i] = *reinterpret_cast<const T*>(data_.y1.at(ot_id_ + ot_i).GetData().data());
      } else {
        outputs_[ot_i] = *reinterpret_cast<const T*>(data_.y0.at(ot_id_ + ot_i).GetData().data());
      }
    }
  } else {
    for (std::size_t ot_i = 0; ot_i < number_of_ots_; ++ot_i) {
      if (corrections[ot_i]) {
        // if the correction bit is 1, we need to swap
        auto data_pointer = reinterpret_cast<const T*>(data_.y1.at(ot_id_ + ot_i).GetData().data());
        std::copy(data_pointer, data_pointer + vector_size_, &outputs_[ot_i * vector_size_]);
      } else {
        auto data_pointer = reinterpret_cast<const T*>(data_.y0.at(ot_id_ + ot_i).GetData().data());
        std::copy(data_pointer, data_pointer + vector_size_, &outputs_[ot_i * vector_size_]);
      }
    }
  }

  // remember that we have done this
  outputs_computed_ = true;
}

template <typename T>
void AcOtSender<T>::SendMessages() const {
  auto buffer = correlations_;
  if (vector_size_ == 1) {
    for (std::size_t ot_i = 0; ot_i < number_of_ots_; ++ot_i) {
      buffer[ot_i] += *reinterpret_cast<const T*>(data_.y0.at(ot_id_ + ot_i).GetData().data());
      buffer[ot_i] += *reinterpret_cast<const T*>(data_.y1.at(ot_id_ + ot_i).GetData().data());
    }
  } else {
    for (std::size_t ot_i = 0; ot_i < number_of_ots_; ++ot_i) {
      auto y0_pointer = reinterpret_cast<const T*>(data_.y0.at(ot_id_ + ot_i).GetData().data());
      auto y1_pointer = reinterpret_cast<const T*>(data_.y1.at(ot_id_ + ot_i).GetData().data());
      auto buffer_pointer = &buffer[ot_i * vector_size_];
      for (std::size_t j = 0; j < vector_size_; ++j) {
        buffer_pointer[j] += y0_pointer[j] + y1_pointer[j];
      }
    }
  }
  assert(buffer.size() == number_of_ots_ * vector_size_);
  send_function_(communication::BuildOtExtensionMessageSender(
      reinterpret_cast<const std::byte*>(buffer.data()), sizeof(T) * buffer.size(), ot_id_));
}

// ---------- AcOtReceiver ----------

template <typename T>
AcOtReceiver<T>::AcOtReceiver(
    const std::size_t ot_id, const std::size_t number_of_ots, const std::size_t vector_size,
    OtExtensionReceiverData& data,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function)
    : BasicOtReceiver(ot_id, number_of_ots, 8 * sizeof(T) * vector_size, kAcOt, send_function,
                      data),
      vector_size_(vector_size),
      outputs_(number_of_ots * vector_size) {
  constexpr auto kIntegralTypeToOtMessageEnumTypemap = boost::hana::make_map(
      boost::hana::make_pair(boost::hana::type_c<std::uint8_t>, OtMessageType::kUint8),
      boost::hana::make_pair(boost::hana::type_c<std::uint16_t>, OtMessageType::kUint16),
      boost::hana::make_pair(boost::hana::type_c<std::uint32_t>, OtMessageType::kUint32),
      boost::hana::make_pair(boost::hana::type_c<std::uint64_t>, OtMessageType::kUint64),
      boost::hana::make_pair(boost::hana::type_c<__uint128_t>, OtMessageType::kUint128));
  data_.message_type.emplace(ot_id, kIntegralTypeToOtMessageEnumTypemap[boost::hana::type_c<T>]);
  sender_message_future_ = data_.RegisterForIntSenderMessage<T>(ot_id, number_of_ots * vector_size);
}

template <typename T>
void AcOtReceiver<T>::ComputeOutputs() {
  if (outputs_computed_) {
    // already done
    return;
  }

  if (!corrections_sent_) {
    throw std::runtime_error("Choices in COT must be se(n)t before calling ComputeOutputs()");
  }

  auto sender_message = sender_message_future_.get();
  assert(sender_message.size() == number_of_ots_ * vector_size_);

  if (vector_size_ == 1) {
    for (std::size_t ot_i = 0; ot_i < number_of_ots_; ++ot_i) {
      auto ot_data_pointer =
          reinterpret_cast<const T*>(data_.outputs.at(ot_id_ + ot_i).GetData().data());
      if (choices_[ot_i]) {
        outputs_[ot_i] = sender_message[ot_i] - *ot_data_pointer;
      } else {
        outputs_[ot_i] = *ot_data_pointer;
      }
    }
  } else {
    for (std::size_t ot_i = 0; ot_i < number_of_ots_; ++ot_i) {
      auto ot_data_pointer =
          reinterpret_cast<const T*>(data_.outputs.at(ot_id_ + ot_i).GetData().data());
      if (choices_[ot_i]) {
        std::transform(ot_data_pointer, ot_data_pointer + vector_size_,
                       &sender_message[ot_i * vector_size_], &outputs_[ot_i * vector_size_],
                       [](auto d, auto m) { return m - d; });
      } else {
        std::copy(ot_data_pointer, ot_data_pointer + vector_size_, &outputs_[ot_i * vector_size_]);
      }
    }
  }
  outputs_computed_ = true;
}

// ---------- kAcOt template instantiations ----------

template class AcOtSender<std::uint8_t>;
template class AcOtSender<std::uint16_t>;
template class AcOtSender<std::uint32_t>;
template class AcOtSender<std::uint64_t>;
template class AcOtSender<__uint128_t>;
template class AcOtReceiver<std::uint8_t>;
template class AcOtReceiver<std::uint16_t>;
template class AcOtReceiver<std::uint32_t>;
template class AcOtReceiver<std::uint64_t>;
template class AcOtReceiver<__uint128_t>;

// ---------- GOt128Sender ----------

GOt128Sender::GOt128Sender(
    std::size_t ot_id, std::size_t number_of_ots, OtExtensionSenderData& data,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function)
    : BasicOtSender(ot_id, number_of_ots, 128, kGOt, send_function, data) {}

void GOt128Sender::SendMessages() const {
  Block128Vector buffer = std::move(inputs_);

  const auto& ot_extension_sender_data = data_;
  ot_extension_sender_data.received_correction_offsets_condition.at(ot_id_)->Wait();
  std::unique_lock lock(ot_extension_sender_data.corrections_mutex);
  const auto corrections =
      ot_extension_sender_data.corrections.Subset(ot_id_, ot_id_ + number_of_ots_);
  lock.unlock();

  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    if (corrections[i]) {
      Block128 difference = buffer[2 * i] ^ buffer[2 * i + 1];
      buffer[2 * i] ^= difference ^ ot_extension_sender_data.y0.at(ot_id_ + i).GetData().data();
      buffer[2 * i + 1] ^= difference ^ ot_extension_sender_data.y1.at(ot_id_ + i).GetData().data();
    } else {
      buffer[2 * i] ^= ot_extension_sender_data.y0.at(ot_id_ + i).GetData().data();
      buffer[2 * i + 1] ^= ot_extension_sender_data.y1.at(ot_id_ + i).GetData().data();
    }
  }
  send_function_(communication::BuildOtExtensionMessageSender(buffer.data()->data(),
                                                              buffer.ByteSize(), ot_id_));
}

// ---------- GOt128Receiver ----------

GOt128Receiver::GOt128Receiver(
    const std::size_t ot_id, const std::size_t number_of_ots, OtExtensionReceiverData& data,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function)
    : BasicOtReceiver(ot_id, number_of_ots, 128, kGOt, send_function, data),
      outputs_(number_of_ots) {
  data_.message_type.emplace(ot_id, OtMessageType::kBlock128);
  sender_message_future_ = data_.RegisterForBlock128SenderMessage(ot_id, 2 * number_of_ots);
}

void GOt128Receiver::ComputeOutputs() {
  if (outputs_computed_) {
    // already done
    return;
  }

  if (!corrections_sent_) {
    throw std::runtime_error("Choices in OT must be se(n)t before calling ComputeOutputs()");
  }
  auto sender_message = sender_message_future_.get();
  const auto random_choices = data_.random_choices->Subset(ot_id_, ot_id_ + number_of_ots_);

  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    Block128 difference;
    if (random_choices[i]) {
      difference = sender_message[2 * i + 1];
    } else {
      difference = sender_message[2 * i];
    }
    outputs_[i] = difference ^ data_.outputs.at(ot_id_ + i).GetData().data();
  }
  outputs_computed_ = true;
}

// ---------- GOtBitSender ----------

GOtBitSender::GOtBitSender(
    std::size_t ot_id, std::size_t number_of_ots, OtExtensionSenderData& data,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function)
    : BasicOtSender(ot_id, number_of_ots, 1, kGOt, send_function, data) {}

void GOtBitSender::SendMessages() const {
  auto buffer = std::move(inputs_);

  const auto& ot_extension_sender_data = data_;
  ot_extension_sender_data.received_correction_offsets_condition.at(ot_id_)->Wait();
  std::unique_lock lock(ot_extension_sender_data.corrections_mutex);
  const auto corrections =
      ot_extension_sender_data.corrections.Subset(ot_id_, ot_id_ + number_of_ots_);
  lock.unlock();

  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    bool b0 = buffer.Get(2 * i);
    bool b1 = buffer.Get(2 * i + 1);
    if (corrections[i]) {
      buffer.Set(b1 ^ ot_extension_sender_data.y0.at(ot_id_ + i).Get(0), 2 * i);
      buffer.Set(b0 ^ ot_extension_sender_data.y1.at(ot_id_ + i).Get(0), 2 * i + 1);
    } else {
      buffer.Set(b0 ^ ot_extension_sender_data.y0.at(ot_id_ + i).Get(0), 2 * i);
      buffer.Set(b1 ^ ot_extension_sender_data.y1.at(ot_id_ + i).Get(0), 2 * i + 1);
    }
  }
  send_function_(communication::BuildOtExtensionMessageSender(buffer.GetData().data(),
                                                              buffer.GetData().size(), ot_id_));
}

// ---------- GOtBitReceiver ----------

GOtBitReceiver::GOtBitReceiver(
    const std::size_t ot_id, const std::size_t number_of_ots, OtExtensionReceiverData& data,
    const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function)
    : BasicOtReceiver(ot_id, number_of_ots, 1, kGOt, send_function, data), outputs_(number_of_ots) {
  data_.message_type.emplace(ot_id, OtMessageType::kBit);
  sender_message_future_ = data_.RegisterForBitSenderMessage(ot_id, 2 * number_of_ots);
}

void GOtBitReceiver::ComputeOutputs() {
  if (outputs_computed_) {
    // already done
    return;
  }

  if (!corrections_sent_) {
    throw std::runtime_error("Choices in OT must be se(n)t before calling ComputeOutputs()");
  }
  auto sender_message = sender_message_future_.get();
  const auto random_choices = data_.random_choices->Subset(ot_id_, ot_id_ + number_of_ots_);

  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    bool difference;
    if (random_choices[i]) {
      difference = sender_message.Get(2 * i + 1);
    } else {
      difference = sender_message.Get(2 * i);
    }
    outputs_.Set(difference ^ data_.outputs.at(ot_id_ + i).Get(0), i);
  }
  outputs_computed_ = true;
}

// ---------- Generic GOtSender ----------

GOtSender::GOtSender(std::size_t ot_id, std::size_t number_of_ots, std::size_t bitlength,
                     OtExtensionSenderData& data,
                     const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function)
    : BasicOtSender(ot_id, number_of_ots, bitlength, kGOt, send_function, data) {}

void GOtSender::SendMessages() const {
  auto inputs = std::move(inputs_);

  const auto& ot_extension_sender_data = data_;
  ot_extension_sender_data.received_correction_offsets_condition.at(ot_id_)->Wait();
  std::unique_lock lock(ot_extension_sender_data.corrections_mutex);
  const auto corrections =
      ot_extension_sender_data.corrections.Subset(ot_id_, ot_id_ + number_of_ots_);
  lock.unlock();

  BitVector<> buffer;
  buffer.Reserve(number_of_ots_ * bitlen_ * 2);

  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    // swap the inputs if corrections[i] == true
    if (corrections[i]) {
      buffer.Append(inputs[i].Subset(bitlen_, 2 * bitlen_) ^
                    ot_extension_sender_data.y0.at(ot_id_ + i));
      buffer.Append(BitSpan(inputs[i].GetMutableData().data(), bitlen_) ^
                    ot_extension_sender_data.y1.at(ot_id_ + i));
    } else {
      buffer.Append(BitSpan(inputs[i].GetMutableData().data(), bitlen_) ^
                    ot_extension_sender_data.y0.at(ot_id_ + i));
      buffer.Append(inputs[i].Subset(bitlen_, 2 * bitlen_) ^
                    ot_extension_sender_data.y1.at(ot_id_ + i));
    }
  }
  send_function_(communication::BuildOtExtensionMessageSender(buffer.GetData().data(),
                                                              buffer.GetData().size(), ot_id_));
}

// ---------- Generic GOtSender ----------

GOtReceiver::GOtReceiver(const std::size_t ot_id, const std::size_t number_of_ots,
                         const std::size_t bitlength, OtExtensionReceiverData& data,
                         const std::function<void(flatbuffers::FlatBufferBuilder&&)>& send_function)
    : BasicOtReceiver(ot_id, number_of_ots, bitlength, kGOt, send_function, data),
      outputs_(number_of_ots) {
  data_.message_type.emplace(ot_id, OtMessageType::kGenericBoolean);
  sender_message_future_ =
      data_.RegisterForGenericSenderMessage(ot_id, 2 * number_of_ots, bitlength);
}

void GOtReceiver::ComputeOutputs() {
  if (outputs_computed_) {
    // already done
    return;
  }

  if (!corrections_sent_) {
    throw std::runtime_error("Choices in OT must be se(n)t before calling ComputeOutputs()");
  }
  auto sender_message = sender_message_future_.get();
  const auto random_choices = data_.random_choices->Subset(ot_id_, ot_id_ + number_of_ots_);

  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    BitSpan difference;
    if (random_choices[i]) {
      difference = sender_message[2 * i + 1];
    } else {
      difference = sender_message[2 * i];
    }
    outputs_[i] = difference ^ data_.outputs.at(ot_id_ + i);
  }
  outputs_computed_ = true;
}

}  // namespace encrypto::motion
