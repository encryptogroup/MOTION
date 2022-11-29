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

#include "communication/message.h"
#include "data_storage/ot_extension_data.h"
#include "utility/fiber_condition.h"

namespace encrypto::motion {

// ---------- BasicOtSender ----------

BasicOtSender::BasicOtSender(std::size_t ot_id, std::size_t number_of_ots, std::size_t bitlength,
                             OtExtensionData& data)
    : OtVector(ot_id, number_of_ots, bitlength, data) {
  data_.sender_data.y0.resize(data_.sender_data.y0.size() + number_of_ots);
  data_.sender_data.y1.resize(data_.sender_data.y1.size() + number_of_ots);
  data_.sender_data.bitlengths.resize(data_.sender_data.bitlengths.size() + number_of_ots,
                                      bitlength);
}

void BasicOtSender::WaitSetup() const { data_.sender_data.WaitSetup(); }

// ---------- BasicOtReceiver ----------

BasicOtReceiver::BasicOtReceiver(std::size_t ot_id, std::size_t number_of_ots,
                                 std::size_t bitlength, OtExtensionData& data)
    : OtVector(ot_id, number_of_ots, bitlength, data) {
  data_.receiver_data.outputs.resize(ot_id + number_of_ots);
  data_.receiver_data.bitlengths.resize(ot_id + number_of_ots, bitlength);
}

void BasicOtReceiver::WaitSetup() const { data_.receiver_data.WaitSetup(); }

void BasicOtReceiver::SendCorrections() {
  assert(data_.receiver_data.IsSetupReady());
  if (choices_.Empty()) {
    throw std::runtime_error("Choices in must be set before calling SendCorrections()");
  }
  auto corrections =
      choices_ ^ data_.receiver_data.random_choices->Subset(ot_id_, ot_id_ + number_of_ots_);
  auto buffer_span{std::span(reinterpret_cast<const std::uint8_t*>(corrections.GetData().data()),
                             corrections.GetData().size())};
  auto msg{communication::BuildMessage(communication::MessageType::kOtExtensionReceiverCorrections,
                                       ot_id_, buffer_span)};
  data_.send_function(std::move(msg));
  corrections_sent_ = true;
}

ROtSender::ROtSender(std::size_t ot_id, std::size_t number_of_ots, std::size_t bitlength,
                     OtExtensionData& data)
    : OtVector(ot_id, number_of_ots, bitlength, data) {
  data_.sender_data.y0.resize(data_.sender_data.y0.size() + number_of_ots);
  data_.sender_data.y1.resize(data_.sender_data.y1.size() + number_of_ots);
  data_.sender_data.bitlengths.resize(data_.sender_data.bitlengths.size() + number_of_ots,
                                      bitlength);
}

void ROtSender::WaitSetup() const { data_.sender_data.WaitSetup(); }

void ROtSender::ComputeOutputs() {
  if (outputs_computed_) {
    // the work was already done
    return;
  }

  // setup phase needs to be finished
  WaitSetup();

  // make space for all the OTs
  outputs_.resize(number_of_ots_);

  // append both masks as the output
  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    outputs_[i].Reserve(bitlength_ * 2);
    outputs_[i].Append(data_.sender_data.y0.at(ot_id_ + i));
    outputs_[i].Append(data_.sender_data.y1.at(ot_id_ + i));
  }

  // remember that we have done this
  outputs_computed_ = true;
}

ROtReceiver::ROtReceiver(std::size_t ot_id, std::size_t number_of_ots, std::size_t bitlength,
                         OtExtensionData& data)
    : OtVector(ot_id, number_of_ots, bitlength, data) {
  data_.receiver_data.outputs.resize(ot_id + number_of_ots);
  data_.receiver_data.bitlengths.resize(ot_id + number_of_ots, bitlength);
}

void ROtReceiver::WaitSetup() const { data_.receiver_data.WaitSetup(); }

void ROtReceiver::ComputeOutputs() {
  if (outputs_computed_) {
    // the work was already done
    return;
  }

  // setup phase needs to be finished
  WaitSetup();

  // copy random choices to the internal buffer
  choices_ = data_.receiver_data.random_choices->Subset(ot_id_, ot_id_ + number_of_ots_);

  // copy the selected random mask to the internal buffer
  outputs_.assign(data_.receiver_data.outputs.begin() + ot_id_,
                  data_.receiver_data.outputs.begin() + ot_id_ + number_of_ots_);

  // flag that the outputs have been computed
  outputs_computed_ = true;
}

// ---------- Generic XcOtSender ----------

XcOtSender::XcOtSender(std::size_t ot_id, std::size_t number_of_ots, std::size_t bitlength,
                       OtExtensionData& data)
    : BasicOtSender(ot_id, number_of_ots, bitlength, data),
      corrections_future_(data.message_manager.RegisterReceive(
          data_.party_id, communication::MessageType::kOtExtensionReceiverCorrections, ot_id)) {}

void XcOtSender::ComputeOutputs() {
  if (outputs_computed_) {
    // the work was already done
    return;
  }

  // setup phase needs to be finished
  WaitSetup();

  // make space for all the OTs
  outputs_.resize(number_of_ots_);

  // get the corrections bits
  std::vector<std::uint8_t> raw_corrections{corrections_future_.get()};
  auto pointer = const_cast<std::uint8_t*>(
      communication::GetMessage(raw_corrections.data())->payload()->data());
  BitSpan corrections_span(pointer, number_of_ots_);
  // take one of the precomputed outputs
  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    outputs_[i].Reserve(bitlength_ * 2);
    if (corrections_span[i]) {
      // if the correction bit is 1, we need to swap
      outputs_[i].Append(data_.sender_data.y1.at(ot_id_ + i));
    } else {
      outputs_[i].Append(data_.sender_data.y0.at(ot_id_ + i));
    }
    outputs_[i].Append(correlations_[i] ^ outputs_[i]);
  }

  // remember that we have done this
  outputs_computed_ = true;
}

void XcOtSender::SendMessages() const {
  BitVector<> buffer;
  buffer.Reserve(bitlength_ * number_of_ots_);
  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    buffer.Append(correlations_[i] ^ data_.sender_data.y0.at(ot_id_ + i) ^
                  data_.sender_data.y1.at(ot_id_ + i));
  }

  auto buffer_span{std::span(reinterpret_cast<const std::uint8_t*>(buffer.GetData().data()),
                             buffer.GetData().size())};
  auto msg{communication::BuildMessage(communication::MessageType::kOtExtensionSender, ot_id_,
                                       buffer_span)};
  data_.send_function(std::move(msg));
}

// ---------- Generic XcOtReceiver ----------

XcOtReceiver::XcOtReceiver(const std::size_t ot_id, const std::size_t number_of_ots,
                           const std::size_t bitlength, OtExtensionData& data)
    : BasicOtReceiver(ot_id, number_of_ots, bitlength, data), outputs_(number_of_ots) {
  sender_message_future_ = data_.message_manager.RegisterReceive(
      data_.party_id, communication::MessageType::kOtExtensionSender, ot_id);
}

void XcOtReceiver::ComputeOutputs() {
  assert(data_.receiver_data.IsSetupReady());
  if (outputs_computed_) {
    // already done
    return;
  }

  WaitSetup();

  if (!corrections_sent_) {
    throw std::runtime_error("Choices in COT must be se(n)t before calling ComputeOutputs()");
  }
  auto sender_message = sender_message_future_.get();
  auto pointer = const_cast<std::uint8_t*>(
      communication::GetMessage(sender_message.data())->payload()->data());
  BitSpan sender_message_span(pointer, bitlength_ * number_of_ots_);

  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    outputs_[i] = std::move(data_.receiver_data.outputs[ot_id_ + i]);
    assert(outputs_[i].GetSize() == bitlength_);
    if (choices_[i]) {
      outputs_[i] ^= sender_message_span.Subset(i * bitlength_, (i + 1) * bitlength_);
    }
  }
  outputs_computed_ = true;
}

// ---------- FixedXcOt128Sender ----------

FixedXcOt128Sender::FixedXcOt128Sender(std::size_t ot_id, std::size_t number_of_ots,
                                       OtExtensionData& data)
    : BasicOtSender(ot_id, number_of_ots, 128, data),
      corrections_future_(data.message_manager.RegisterReceive(
          data_.party_id, communication::MessageType::kOtExtensionReceiverCorrections, ot_id)) {}

void FixedXcOt128Sender::ComputeOutputs() {
  if (outputs_computed_) {
    // the work was already done
    return;
  }

  // setup phase needs to be finished
  WaitSetup();

  // make space for all the OTs
  outputs_.resize(number_of_ots_);

  // get the corrections bits
  std::vector<std::uint8_t> corrections_message{corrections_future_.get()};
  auto pointer = const_cast<std::uint8_t*>(
      communication::GetMessage(corrections_message.data())->payload()->data());
  BitSpan corrections_span{pointer, number_of_ots_};

  // take one of the precomputed outputs
  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    if (corrections_span[i]) {
      // if the correction bit is 1, we need to swap
      outputs_[i].LoadFromMemory(data_.sender_data.y1.at(ot_id_ + i).GetData().data());
    } else {
      outputs_[i].LoadFromMemory(data_.sender_data.y0.at(ot_id_ + i).GetData().data());
    }
  }

  // remember that we have done this
  outputs_computed_ = true;
}

void FixedXcOt128Sender::SendMessages() const {
  assert(data_.sender_data.IsSetupReady());
  Block128Vector buffer(number_of_ots_, correlation_);
  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    buffer[i] ^= data_.sender_data.y0.at(ot_id_ + i).GetData().data();
    buffer[i] ^= data_.sender_data.y1.at(ot_id_ + i).GetData().data();
  }

  auto buffer_span{
      std::span(reinterpret_cast<const std::uint8_t*>(buffer.data()), buffer.ByteSize())};
  auto msg{communication::BuildMessage(communication::MessageType::kOtExtensionSender, ot_id_,
                                       buffer_span)};
  data_.send_function(std::move(msg));
}

// ---------- FixedXcOt128Receiver ----------

FixedXcOt128Receiver::FixedXcOt128Receiver(const std::size_t ot_id, const std::size_t number_of_ots,
                                           OtExtensionData& data)
    : BasicOtReceiver(ot_id, number_of_ots, 128, data), outputs_(number_of_ots) {
  sender_message_future_ = data_.message_manager.RegisterReceive(
      data_.party_id, communication::MessageType::kOtExtensionSender, ot_id);
}

void FixedXcOt128Receiver::ComputeOutputs() {
  if (outputs_computed_) {
    // already done
    return;
  }

  WaitSetup();

  if (!corrections_sent_) {
    throw std::runtime_error("Choices in COT must be se(n)t before calling ComputeOutputs()");
  }
  auto sender_message = sender_message_future_.get();
  auto pointer = const_cast<std::uint8_t*>(
      communication::GetMessage(sender_message.data())->payload()->data());

  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    outputs_[i].LoadFromMemory(data_.receiver_data.outputs.at(ot_id_ + i).GetData().data());
    if (choices_[i]) {
      outputs_[i] ^= Block128::MakeFromMemory(reinterpret_cast<const std::byte*>(pointer) + 16 * i);
    }
  }
  outputs_computed_ = true;
}

// ---------- XcOtBitSender ----------

XcOtBitSender::XcOtBitSender(const std::size_t ot_id, const std::size_t number_of_ots,
                             OtExtensionData& data)
    : BasicOtSender(ot_id, number_of_ots, 1, data),
      corrections_future_(data.message_manager.RegisterReceive(
          data_.party_id, communication::MessageType::kOtExtensionReceiverCorrections, ot_id)) {}

void XcOtBitSender::ComputeOutputs() {
  if (outputs_computed_) {
    // the work was already done
    return;
  }

  // setup phase needs to be finished
  WaitSetup();

  // make space for all the OTs
  outputs_.Resize(number_of_ots_);

  // get the corrections bits
  std::vector<std::uint8_t> corrections_message{corrections_future_.get()};
  auto pointer = const_cast<std::uint8_t*>(
      communication::GetMessage(corrections_message.data())->payload()->data());
  BitSpan corrections_span{pointer, number_of_ots_};

  // take one of the precomputed outputs
  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    if (corrections_span[i]) {
      // if the correction bit is 1, we need to swap
      outputs_.Set(bool(data_.sender_data.y1.at(ot_id_ + i).GetData()[0] & kSetBitMask[0]), i);
    } else {
      outputs_.Set(bool(data_.sender_data.y0.at(ot_id_ + i).GetData()[0] & kSetBitMask[0]), i);
    }
  }

  // remember that we have done this
  outputs_computed_ = true;
}

void XcOtBitSender::SendMessages() const {
  WaitSetup();

  auto buffer = correlations_;
  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    auto tmp = buffer[i];
    tmp ^= bool(data_.sender_data.y0.at(ot_id_ + i).GetData()[0] & kSetBitMask[0]);
    tmp ^= bool(data_.sender_data.y1.at(ot_id_ + i).GetData()[0] & kSetBitMask[0]);
    buffer.Set(tmp, i);
  }

  auto buffer_span{std::span(reinterpret_cast<const std::uint8_t*>(buffer.GetData().data()),
                             buffer.GetData().size())};
  auto msg{communication::BuildMessage(communication::MessageType::kOtExtensionSender, ot_id_,
                                       buffer_span)};
  data_.send_function(std::move(msg));
}

// ---------- XcOtBitReceiver ----------

XcOtBitReceiver::XcOtBitReceiver(std::size_t ot_id, const std::size_t number_of_ots,
                                 OtExtensionData& data)
    : BasicOtReceiver(ot_id, number_of_ots, 1, data), outputs_(number_of_ots) {
  sender_message_future_ = data_.message_manager.RegisterReceive(
      data_.party_id, communication::MessageType::kOtExtensionSender, ot_id);
}

void XcOtBitReceiver::ComputeOutputs() {
  if (outputs_computed_) {
    // already done
    return;
  }

  WaitSetup();

  if (!corrections_sent_) {
    throw std::runtime_error("Choices in COT must be se(n)t before calling ComputeOutputs()");
  }

  std::vector<std::uint8_t> sender_message{sender_message_future_.get()};
  auto pointer = const_cast<std::uint8_t*>(
      communication::GetMessage(sender_message.data())->payload()->data());
  outputs_ = choices_ & BitSpan(pointer, choices_.GetSize());

  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    auto tmp = outputs_[i];
    outputs_.Set(
        tmp ^ bool(data_.receiver_data.outputs.at(ot_id_ + i).GetData()[0] & kSetBitMask[0]), i);
  }
  outputs_computed_ = true;
}

// ---------- AcOtSender ----------

template <typename T>
AcOtSender<T>::AcOtSender(std::size_t ot_id, std::size_t number_of_ots, std::size_t vector_size,
                          OtExtensionData& data)
    : BasicOtSender(ot_id, number_of_ots, 8 * sizeof(T) * vector_size, data),
      vector_size_(vector_size),
      corrections_future_(data.message_manager.RegisterReceive(
          data_.party_id, communication::MessageType::kOtExtensionReceiverCorrections, ot_id)) {}

template <typename T>
void AcOtSender<T>::ComputeOutputs() {
  if (outputs_computed_) {
    // the work was already done
    return;
  }

  // setup phase needs to be finished
  WaitSetup();

  // make space for all the OTs
  outputs_.resize(number_of_ots_ * vector_size_);

  // get the corrections bits
  std::vector<std::uint8_t> corrections_message{corrections_future_.get()};
  auto pointer = const_cast<std::uint8_t*>(
      communication::GetMessage(corrections_message.data())->payload()->data());
  BitSpan corrections_span{pointer, number_of_ots_};

  // take one of the precomputed outputs
  if (vector_size_ == 1) {
    for (std::size_t ot_i = 0; ot_i < number_of_ots_; ++ot_i) {
      if (corrections_span[ot_i]) {
        // if the correction bit is 1, we need to swap
        outputs_[ot_i] =
            *reinterpret_cast<const T*>(data_.sender_data.y1.at(ot_id_ + ot_i).GetData().data());
      } else {
        outputs_[ot_i] =
            *reinterpret_cast<const T*>(data_.sender_data.y0.at(ot_id_ + ot_i).GetData().data());
      }
    }
  } else {
    for (std::size_t ot_i = 0; ot_i < number_of_ots_; ++ot_i) {
      if (corrections_span[ot_i]) {
        // if the correction bit is 1, we need to swap
        auto data_pointer =
            reinterpret_cast<const T*>(data_.sender_data.y1.at(ot_id_ + ot_i).GetData().data());
        std::copy(data_pointer, data_pointer + vector_size_, &outputs_[ot_i * vector_size_]);
      } else {
        auto data_pointer =
            reinterpret_cast<const T*>(data_.sender_data.y0.at(ot_id_ + ot_i).GetData().data());
        std::copy(data_pointer, data_pointer + vector_size_, &outputs_[ot_i * vector_size_]);
      }
    }
  }

  // remember that we have done this
  outputs_computed_ = true;
}

template <typename T>
void AcOtSender<T>::SendMessages() const {
  assert(data_.sender_data.IsSetupReady());
  auto buffer = correlations_;
  if (vector_size_ == 1) {
    for (std::size_t ot_i = 0; ot_i < number_of_ots_; ++ot_i) {
      buffer[ot_i] +=
          *reinterpret_cast<const T*>(data_.sender_data.y0.at(ot_id_ + ot_i).GetData().data());
      buffer[ot_i] +=
          *reinterpret_cast<const T*>(data_.sender_data.y1.at(ot_id_ + ot_i).GetData().data());
    }
  } else {
    for (std::size_t ot_i = 0; ot_i < number_of_ots_; ++ot_i) {
      auto y0_pointer =
          reinterpret_cast<const T*>(data_.sender_data.y0.at(ot_id_ + ot_i).GetData().data());
      auto y1_pointer =
          reinterpret_cast<const T*>(data_.sender_data.y1.at(ot_id_ + ot_i).GetData().data());
      auto buffer_pointer = &buffer[ot_i * vector_size_];
      for (std::size_t j = 0; j < vector_size_; ++j) {
        buffer_pointer[j] += y0_pointer[j] + y1_pointer[j];
      }
    }
  }
  assert(buffer.size() == number_of_ots_ * vector_size_);

  auto buffer_span{
      std::span(reinterpret_cast<const std::uint8_t*>(buffer.data()), sizeof(T) * buffer.size())};
  auto msg{communication::BuildMessage(communication::MessageType::kOtExtensionSender, ot_id_,
                                       buffer_span)};
  data_.send_function(std::move(msg));
}

// ---------- AcOtReceiver ----------

template <typename T>
AcOtReceiver<T>::AcOtReceiver(std::size_t ot_id, std::size_t number_of_ots, std::size_t vector_size,
                              OtExtensionData& data)
    : BasicOtReceiver(ot_id, number_of_ots, 8 * sizeof(T) * vector_size, data),
      vector_size_(vector_size),
      outputs_(number_of_ots * vector_size) {
  // TODO: the new version of MOTION is very different from the old one
  sender_message_future_ = data_.message_manager.RegisterReceive(
      data_.party_id, communication::MessageType::kOtExtensionSender, ot_id);
}

template <typename T>
void AcOtReceiver<T>::ComputeOutputs() {
  if (outputs_computed_) {
    // already done
    return;
  }

  WaitSetup();

  if (!corrections_sent_) {
    throw std::runtime_error("Choices in COT must be se(n)t before calling ComputeOutputs()");
  }

  auto sender_message = sender_message_future_.get();
  auto pointer = const_cast<std::uint8_t*>(
      communication::GetMessage(sender_message.data())->payload()->data());
  assert(communication::GetMessage(sender_message.data())->payload()->size() ==
         number_of_ots_ * vector_size_ * sizeof(T));

  if (vector_size_ == 1) {
    for (std::size_t ot_i = 0; ot_i < number_of_ots_; ++ot_i) {
      auto ot_data_pointer = reinterpret_cast<const T*>(
          data_.receiver_data.outputs.at(ot_id_ + ot_i).GetData().data());
      if (choices_[ot_i]) {
        outputs_[ot_i] = *reinterpret_cast<T*>(&pointer[sizeof(T) * ot_i]) - *ot_data_pointer;
      } else {
        outputs_[ot_i] = *ot_data_pointer;
      }
    }
  } else {
    for (std::size_t ot_i = 0; ot_i < number_of_ots_; ++ot_i) {
      auto ot_data_pointer = reinterpret_cast<const T*>(
          data_.receiver_data.outputs.at(ot_id_ + ot_i).GetData().data());
      if (choices_[ot_i]) {
        std::transform(ot_data_pointer, ot_data_pointer + vector_size_,
                       reinterpret_cast<T*>(&pointer[sizeof(T) * ot_i * vector_size_]),
                       &outputs_[ot_i * vector_size_], [](auto d, auto m) { return m - d; });
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

// added by Liang Zhao

// ---------- AcOtSenderBoostUint ----------

template <typename T>
AcOtSenderBoostUint<T>::AcOtSenderBoostUint(const std::size_t ot_id,
                                            const std::size_t number_of_ots,
                                            const std::size_t vector_size, OtExtensionData& data)
    : BasicOtSender(ot_id, number_of_ots, (std::numeric_limits<T>::digits) * vector_size, data),
      vector_size_(vector_size),
      corrections_future_(data.message_manager.RegisterReceive(
          data_.party_id, communication::MessageType::kOtExtensionReceiverCorrections, ot_id)) {
  // std::cout << "AcOtSenderBoostUint" << std::endl;

  // std::cout << "number_of_ots: " << number_of_ots << std::endl;
}

template <typename T>
void AcOtSenderBoostUint<T>::ComputeOutputs() {
  // std::cout << "AcOtSenderBoostUint<T>::ComputeOutputs" << std::endl;

  if (outputs_computed_) {
    // the work was already done
    return;
  }

  // setup phase needs to be finished
  WaitSetup();

  // wait until the receiver has sent its correction bits
  // data_.received_correction_offsets_condition.at(ot_id_)->Wait();

  // make space for all the OTs
  outputs_.resize(number_of_ots_ * vector_size_);

  // get the corrections bits
  // std::unique_lock lock(data_.corrections_mutex);
  // const auto corrections = data_.corrections.Subset(ot_id_, ot_id_ + number_of_ots_);
  // lock.unlock();
  // get the corrections bits
  std::vector<std::uint8_t> corrections_message{corrections_future_.get()};
  auto pointer = const_cast<std::uint8_t*>(
      communication::GetMessage(corrections_message.data())->payload()->data());
  BitSpan corrections_span{pointer, number_of_ots_};

  // // only for debugging
  // std::vector<T> xxx;

  // take one of the precomputed outputs
  // if (vector_size_ == 1) {
  //   for (std::size_t ot_i = 0; ot_i < number_of_ots_; ++ot_i) {
  //     if (corrections_span[ot_i]) {
  //       std::vector<T> ot_data_y1_vector =
  //           ImportOtDataToBoostUintVector<std::vector, T, std::allocator<T>>(
  //               outputs_, ot_i, ot_id_, vector_size_, data_.sender_data.y1);
  //       outputs_[ot_i] = ot_data_y1_vector[0];

  //     } else {
  //       std::vector<T> ot_data_y0_vector =
  //           ImportOtDataToBoostUintVector<std::vector, T, std::allocator<T>>(
  //               outputs_, ot_i, ot_id_, vector_size_, data_.sender_data.y0);
  //       outputs_[ot_i] = ot_data_y0_vector[0];
  //     }
  //   }
  //   // std::cout << "AcOtSenderBoostUint vector_size_ == 1 ImportOtDataToBoostUintVector finish"
  //   //           << std::endl;
  // }

  // new optimized method
  // test passed
  // take one of the precomputed outputs
  if (vector_size_ == 1) {
    for (std::size_t ot_i = 0; ot_i < number_of_ots_; ++ot_i) {
      // std::cout << "corrections_span[ot_i]: " << corrections_span[ot_i] << std::endl;

      if (corrections_span[ot_i]) {
        // std::cout << "if (corrections_span[ot_i]): " << std::endl;

        ImportOtDataToBoostUintVector<std::vector, T, std::allocator<T>>(
            outputs_, ot_i, ot_id_, vector_size_, data_.sender_data.y1);

        // std::cout << "outputs_[ot_i]: " << outputs_[ot_i] << std::endl;
      } else {
        // std::cout << "else (corrections_span[ot_i]): " << std::endl;

        ImportOtDataToBoostUintVector<std::vector, T, std::allocator<T>>(
            outputs_, ot_i, ot_id_, vector_size_, data_.sender_data.y0);

        // std::cout << "outputs_[ot_i]: " << outputs_[ot_i] << std::endl;
      }
    }
  }

  // // vector_size_ > 1
  // else {
  //   for (std::size_t ot_i = 0; ot_i < number_of_ots_; ++ot_i) {
  //     if (corrections_span[ot_i]) {
  //       std::vector<T> ot_data_y1_vector =
  //           ImportOtDataToBoostUintVector<std::vector, T, std::allocator<T>>(
  //               outputs_, ot_i, ot_id_, vector_size_, data_.sender_data.y1);
  //       for (std::size_t vector_index = 0; vector_index < vector_size_; ++vector_index) {
  //         outputs_[ot_i * vector_size_ + vector_index] = ot_data_y1_vector[vector_index];
  //       }

  //     } else {
  //       std::vector<T> ot_data_y0_vector =
  //           ImportOtDataToBoostUintVector<std::vector, T, std::allocator<T>>(
  //               outputs_, ot_i, ot_id_, vector_size_, data_.sender_data.y0);
  //       for (std::size_t vector_index = 0; vector_index < vector_size_; ++vector_index) {
  //         outputs_[ot_i * vector_size_ + vector_index] = ot_data_y0_vector[vector_index];
  //       }
  //     }
  //   }
  // }

  // new optimized method
  // test passed
  else {
    for (std::size_t ot_i = 0; ot_i < number_of_ots_; ++ot_i) {
      if (corrections_span[ot_i]) {
        ImportOtDataToBoostUintVector<std::vector, T, std::allocator<T>>(
            outputs_, ot_i, ot_id_, vector_size_, data_.sender_data.y1);
      } else {
        ImportOtDataToBoostUintVector<std::vector, T, std::allocator<T>>(
            outputs_, ot_i, ot_id_, vector_size_, data_.sender_data.y0);
      }
    }
  }

  // remember that we have done this
  outputs_computed_ = true;
}

template <typename T>
void AcOtSenderBoostUint<T>::SendMessages() const {
  // std::cout<<"AcOtSenderBoostUint<T>::SendMessages"<<std::endl;

  assert(data_.sender_data.IsSetupReady());
  auto buffer = correlations_;
  // if (vector_size_ == 1) {
  //   for (std::size_t ot_i = 0; ot_i < number_of_ots_; ++ot_i) {
  //     std::vector<T> ot_data_y0_vector =
  //         ImportOtDataToBoostUintVector<std::vector, T, std::allocator<T>>(
  //             ot_i, ot_id_, vector_size_, data_.sender_data.y0);
  //     std::vector<T> ot_data_y1_vector =
  //         ImportOtDataToBoostUintVector<std::vector, T, std::allocator<T>>(
  //             ot_i, ot_id_, vector_size_, data_.sender_data.y1);
  //     buffer[ot_i] += ot_data_y0_vector[0] + ot_data_y1_vector[0];
  //   }
  // }

  if (vector_size_ == 1) {
    std::vector<T> ot_data_y0_vector(number_of_ots_);
    std::vector<T> ot_data_y1_vector(number_of_ots_);
    for (std::size_t ot_i = 0; ot_i < number_of_ots_; ++ot_i) {
      ImportOtDataToBoostUintVector<std::vector, T, std::allocator<T>>(
          ot_data_y0_vector, ot_i, ot_id_, vector_size_, data_.sender_data.y0);
      ImportOtDataToBoostUintVector<std::vector, T, std::allocator<T>>(
          ot_data_y1_vector, ot_i, ot_id_, vector_size_, data_.sender_data.y1);
      buffer[ot_i] += ot_data_y0_vector[ot_i] + ot_data_y1_vector[ot_i];

      // std::cout << "AcOtSenderBoostUint<T>::SendMessages: buffer[ot_i]: " << buffer[ot_i]
      //           << std::endl;
    }
  }

  // vector_size_ > 1
  // else {
  //   for (std::size_t ot_i = 0; ot_i < number_of_ots_; ++ot_i) {
  //     std::vector<T> ot_data_y0_vector =
  //         ImportOtDataToBoostUintVector<std::vector, T, std::allocator<T>>(
  //             ot_i, ot_id_, vector_size_, data_.sender_data.y0);
  //     std::vector<T> ot_data_y1_vector =
  //         ImportOtDataToBoostUintVector<std::vector, T, std::allocator<T>>(
  //             ot_i, ot_id_, vector_size_, data_.sender_data.y1);

  //     for (std::size_t vector_index = 0; vector_index < vector_size_; ++vector_index) {
  //       buffer[ot_i * vector_size_ + vector_index] +=
  //           ot_data_y0_vector[vector_index] + ot_data_y1_vector[vector_index];
  //     }
  //   }
  // }

  // test passed
  else {
    std::vector<T> ot_data_y0_vector(vector_size_ * number_of_ots_);
    std::vector<T> ot_data_y1_vector(vector_size_ * number_of_ots_);
    for (std::size_t ot_i = 0; ot_i < number_of_ots_; ++ot_i) {
      ImportOtDataToBoostUintVector<std::vector, T, std::allocator<T>>(
          ot_data_y0_vector, ot_i, ot_id_, vector_size_, data_.sender_data.y0);
      ImportOtDataToBoostUintVector<std::vector, T, std::allocator<T>>(
          ot_data_y1_vector, ot_i, ot_id_, vector_size_, data_.sender_data.y1);

      for (std::size_t vector_index = 0; vector_index < vector_size_; ++vector_index) {
        buffer[ot_i * vector_size_ + vector_index] +=
            ot_data_y0_vector[ot_i * vector_size_ + vector_index] +
            ot_data_y1_vector[ot_i * vector_size_ + vector_index];
      }
    }
  }
  assert(buffer.size() == number_of_ots_ * vector_size_);

  // send_function_(communication::BuildOtExtensionMessageSender(
  //     reinterpret_cast<const std::byte*>(buffer.data()), sizeof(T) * buffer.size(), ot_id_));

  std::size_t num_of_bytes = ((std::numeric_limits<T>::digits) / 8) * buffer.size();

  // TODO: check if ExportOtDataInUint8tFromBoostUintVector works correctly
  // std::vector<std::byte> buffer_byte_vector =
  //     ExportOtDataInUint8tFromBoostUintVector<T, std::allocator<T>>(num_of_bytes, buffer);
  std::vector<std::uint8_t> buffer_byte_vector =
      ExportOtDataInUint8tFromBoostUintVector<T, std::allocator<T>>(num_of_bytes, buffer);

  // std::cout << "AcOtSenderBoostUint<T>::SendMessages: buffer_byte_vector: " << std::endl;
  // for (std::size_t i = 0; i < num_of_bytes; ++i) {
  //   std::cout << unsigned(buffer_byte_vector[i]) << std::endl;
  // }

  // std::vector<std::uint8_t*> buffer_byte_vector =
  // ExportOtDataFromBoostUintVector<T, std::allocator<T>>(num_of_bytes, buffer);
  // send_function_(communication::BuildOtExtensionMessageSender(buffer_byte_vector.data(),
  //                                                             num_of_bytes, ot_id_));

  // auto msg{communication::BuildMessage(communication::MessageType::kOtExtensionSender, ot_id_,
  //                                      buffer_span)};

  // auto msg{communication::BuildMessage(communication::MessageType::kOtExtensionSender, ot_id_,
  //                                      buffer_byte_vector.data())};

  auto msg{communication::BuildMessage(communication::MessageType::kOtExtensionSender, ot_id_,
                                       buffer_byte_vector)};
  data_.send_function(std::move(msg));
}

// ---------- AcOtReceiverBoostUint ----------

template <typename T>
AcOtReceiverBoostUint<T>::AcOtReceiverBoostUint(const std::size_t ot_id,
                                                const std::size_t number_of_ots,
                                                const std::size_t vector_size,
                                                OtExtensionData& data)
    : BasicOtReceiver(ot_id, number_of_ots, (std::numeric_limits<T>::digits) * vector_size, data),
      vector_size_(vector_size),
      outputs_(number_of_ots * vector_size) {
  sender_message_future_ = data_.message_manager.RegisterReceive(
      data_.party_id, communication::MessageType::kOtExtensionSender, ot_id);

  // std::cout << "AcOtReceiverBoostUint" << std::endl;
  // std::cout << "number_of_ots: " << number_of_ots << std::endl;
  // std::cout << "vector_size: " << vector_size << std::endl;
}

template <typename T>
void AcOtReceiverBoostUint<T>::ComputeOutputs() {
  // std::cout << "AcOtReceiverBoostUint<T>::ComputeOutputs" << std::endl;
  if (outputs_computed_) {
    // already done
    return;
  }

  WaitSetup();

  if (!corrections_sent_) {
    throw std::runtime_error("Choices in COT must be se(n)t before calling ComputeOutputs()");
  }

  auto sender_message = sender_message_future_.get();
  auto pointer = const_cast<std::uint8_t*>(
      communication::GetMessage(sender_message.data())->payload()->data());
  assert(communication::GetMessage(sender_message.data())->payload()->size() ==
         number_of_ots_ * vector_size_ * (std::numeric_limits<T>::digits) / 8);

  // std::cout << "sender_message.size: " << sender_message.size() << std::endl;
  // std::cout << "number_of_ots_: " << number_of_ots_ << std::endl;
  // std::cout << "vector_size_: " << vector_size_ << std::endl;

  // assert(sender_message.size() == number_of_ots_ * vector_size_);

  // TODO: sender_message need special treatment

  // if (vector_size_ == 1) {
  //   for (std::size_t ot_i = 0; ot_i < number_of_ots_; ++ot_i) {
  //     std::vector<T> ot_data_output_vector =
  //         ImportOtDataToBoostUintVector<std::vector, T, std::allocator<T>>(
  //             ot_i, ot_id_, vector_size_, data_.receiver_data.outputs);

  //     if (choices_[ot_i]) {
  //       outputs_[ot_i] = sender_message[ot_i] - ot_data_output_vector[0];
  //     } else {
  //       outputs_[ot_i] = ot_data_output_vector[0];
  //     }
  //   }
  //   // std::cout << "AcOtReceiverBoostUint vector_size_ == 1 ImportOtDataToBoostUintVector
  //   finish"
  //   //           << std::endl;

  // }

  // std::cout << "sender_message.data(): " << std::endl;
  // for (std::size_t i = 0; i < number_of_ots_ * vector_size_ * (std::numeric_limits<T>::digits) / 8;
  //      i++) {
  //   std::cout << unsigned(pointer[i]) << std::endl;
  // }

  // std::cout << "pointer: " << std::endl;
  // for (std::size_t i = 0; i < number_of_ots_ * vector_size_ * (std::numeric_limits<T>::digits) / 8;
  //      i++) {
  //   std::cout << unsigned(pointer[i]) << std::endl;
  // }

  // TODO: need test
  // ! sender_message_T always be the same value, somewhere goes wrong
  std::vector<T> sender_message_T(number_of_ots_ * vector_size_);
  // ImportOtDataToBoostUintVector<std::vector, T, std::allocator<T>>(sender_message_T, vector_size_,
  //                                                                  sender_message.data());
  ImportOtDataToBoostUintVector<std::vector, T, std::allocator<T>>(sender_message_T, number_of_ots_ *vector_size_,
                                                                   pointer);

  if (vector_size_ == 1) {
    std::vector<T> ot_data_vector(number_of_ots_);
    for (std::size_t ot_i = 0; ot_i < number_of_ots_; ++ot_i) {
      ImportOtDataToBoostUintVector<std::vector, T, std::allocator<T>>(
          ot_data_vector, ot_i, ot_id_, vector_size_, data_.receiver_data.outputs);

      // std::cout << "sender_message_T: " << sender_message_T[ot_i * vector_size_] << std::endl;

      // std::cout << "ot_data_vector: " << ot_data_vector[ot_i * vector_size_] << std::endl;

      if (choices_[ot_i]) {
        // TODO: fix sender_message[ot_i]?
        // outputs_[ot_i] = sender_message[ot_i] - ot_data_vector[ot_i];
        outputs_[ot_i] = sender_message_T[ot_i] - ot_data_vector[ot_i];
      } else {
        outputs_[ot_i] = ot_data_vector[ot_i];
      }
    }
  }

  // vector_size_ > 1
  // else {
  //   for (std::size_t ot_i = 0; ot_i < number_of_ots_; ++ot_i) {
  //     std::vector<T> ot_data_output_vector =
  //         ImportOtDataToBoostUintVector<std::vector, T, std::allocator<T>>(
  //             ot_i, ot_id_, vector_size_, data_.receiver_data.outputs);

  //     if (choices_[ot_i]) {
  //       for (std::size_t vector_index = 0; vector_index < vector_size_; ++vector_index) {
  //         outputs_[ot_i * vector_size_ + vector_index] =
  //             sender_message[ot_i * vector_size_ + vector_index] -
  //             ot_data_output_vector[vector_index];
  //       }
  //     } else {
  //       for (std::size_t vector_index = 0; vector_index < vector_size_; ++vector_index) {
  //         outputs_[ot_i * vector_size_ + vector_index] = ot_data_output_vector[vector_index];
  //       }
  //     }
  //   }
  // }

  else {
    std::vector<T> ot_data_vector(number_of_ots_ * vector_size_);
    for (std::size_t ot_i = 0; ot_i < number_of_ots_; ++ot_i) {
      ImportOtDataToBoostUintVector<std::vector, T, std::allocator<T>>(
          ot_data_vector, ot_i, ot_id_, vector_size_, data_.receiver_data.outputs);

      if (choices_[ot_i]) {
        for (std::size_t vector_index = 0; vector_index < vector_size_; ++vector_index) {
          // outputs_[ot_i * vector_size_ + vector_index] =
          //     sender_message[ot_i * vector_size_ + vector_index] -
          //     ot_data_vector[ot_i * vector_size_ + vector_index];
          outputs_[ot_i * vector_size_ + vector_index] =
              sender_message_T[ot_i * vector_size_ + vector_index] -
              ot_data_vector[ot_i * vector_size_ + vector_index];
        }
      } else {
        for (std::size_t vector_index = 0; vector_index < vector_size_; ++vector_index) {
          outputs_[ot_i * vector_size_ + vector_index] =
              ot_data_vector[ot_i * vector_size_ + vector_index];
        }
      }
    }
  }
  outputs_computed_ = true;
}

// ---------- kAcOtBoostUint template instantiations ----------

template class AcOtSenderBoostUint<bm::uint256_t>;
template class AcOtReceiverBoostUint<bm::uint256_t>;

// ---------- GOt128Sender ----------

GOt128Sender::GOt128Sender(std::size_t ot_id, std::size_t number_of_ots, OtExtensionData& data)
    : BasicOtSender(ot_id, number_of_ots, 128, data),
      corrections_future_(data.message_manager.RegisterReceive(
          data_.party_id, communication::MessageType::kOtExtensionReceiverCorrections, ot_id)) {}

void GOt128Sender::SendMessages() const {
  assert(data_.sender_data.IsSetupReady());
  Block128Vector buffer = std::move(inputs_);
  std::vector<std::uint8_t> corrections_message{corrections_future_.get()};
  auto pointer = const_cast<std::uint8_t*>(
      communication::GetMessage(corrections_message.data())->payload()->data());
  BitSpan corrections_span(pointer, number_of_ots_);
  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    if (corrections_span[i]) {
      Block128 difference = buffer[2 * i] ^ buffer[2 * i + 1];
      buffer[2 * i] ^= difference ^ data_.sender_data.y0.at(ot_id_ + i).GetData().data();
      buffer[2 * i + 1] ^= difference ^ data_.sender_data.y1.at(ot_id_ + i).GetData().data();
    } else {
      buffer[2 * i] ^= data_.sender_data.y0.at(ot_id_ + i).GetData().data();
      buffer[2 * i + 1] ^= data_.sender_data.y1.at(ot_id_ + i).GetData().data();
    }
  }
  auto buffer_span{
      std::span(reinterpret_cast<const std::uint8_t*>(buffer.data()->data()), buffer.ByteSize())};
  auto msg{communication::BuildMessage(communication::MessageType::kOtExtensionSender, ot_id_,
                                       buffer_span)};
  data_.send_function(std::move(msg));
}

// ---------- GOt128Receiver ----------

GOt128Receiver::GOt128Receiver(const std::size_t ot_id, const std::size_t number_of_ots,
                               OtExtensionData& data)
    : BasicOtReceiver(ot_id, number_of_ots, 128, data), outputs_(number_of_ots) {
  sender_message_future_ = data_.message_manager.RegisterReceive(
      data_.party_id, communication::MessageType::kOtExtensionSender, ot_id);
}

void GOt128Receiver::ComputeOutputs() {
  if (outputs_computed_) {
    // already done
    return;
  }

  WaitSetup();

  if (!corrections_sent_) {
    throw std::runtime_error("Choices in OT must be se(n)t before calling ComputeOutputs()");
  }
  auto sender_message = sender_message_future_.get();
  auto pointer = const_cast<std::uint8_t*>(
      communication::GetMessage(sender_message.data())->payload()->data());
  const auto random_choices =
      data_.receiver_data.random_choices->Subset(ot_id_, ot_id_ + number_of_ots_);

  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    auto offset{static_cast<std::size_t>(random_choices[i]) * Block128::kBlockSize};
    auto difference{Block128::MakeFromMemory(reinterpret_cast<std::byte*>(pointer) +
                                             2 * i * Block128::kBlockSize + offset)};
    outputs_[i] = difference ^ data_.receiver_data.outputs.at(ot_id_ + i).GetData().data();
  }
  outputs_computed_ = true;
}

// ---------- GOtBitSender ----------

GOtBitSender::GOtBitSender(std::size_t ot_id, std::size_t number_of_ots, OtExtensionData& data)
    : BasicOtSender(ot_id, number_of_ots, 1, data),
      corrections_future_(data.message_manager.RegisterReceive(
          data_.party_id, communication::MessageType::kOtExtensionReceiverCorrections, ot_id)) {}

void GOtBitSender::SendMessages() const {
  assert(data_.sender_data.IsSetupReady());
  auto buffer = std::move(inputs_);

  std::vector<std::uint8_t> corrections_message{corrections_future_.get()};
  auto pointer = const_cast<std::uint8_t*>(
      communication::GetMessage(corrections_message.data())->payload()->data());
  BitSpan corrections_span{pointer, number_of_ots_};

  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    bool b0 = buffer.Get(2 * i);
    bool b1 = buffer.Get(2 * i + 1);
    if (corrections_span[i]) std::swap(b0, b1);

    buffer.Set(b0 ^ data_.sender_data.y0.at(ot_id_ + i).Get(0), 2 * i);
    buffer.Set(b1 ^ data_.sender_data.y1.at(ot_id_ + i).Get(0), 2 * i + 1);
  }

  auto buffer_span{std::span(reinterpret_cast<const std::uint8_t*>(buffer.GetData().data()),
                             buffer.GetData().size())};
  auto msg{communication::BuildMessage(communication::MessageType::kOtExtensionSender, ot_id_,
                                       buffer_span)};
  data_.send_function(std::move(msg));
}

// ---------- GOtBitReceiver ----------

GOtBitReceiver::GOtBitReceiver(const std::size_t ot_id, const std::size_t number_of_ots,
                               OtExtensionData& data)
    : BasicOtReceiver(ot_id, number_of_ots, 1, data), outputs_(number_of_ots) {
  sender_message_future_ = data_.message_manager.RegisterReceive(
      data_.party_id, communication::MessageType::kOtExtensionSender, ot_id);
}

void GOtBitReceiver::ComputeOutputs() {
  if (outputs_computed_) {
    // already done
    return;
  }

  WaitSetup();

  if (!corrections_sent_) {
    throw std::runtime_error("Choices in OT must be se(n)t before calling ComputeOutputs()");
  }
  std::vector<std::uint8_t> sender_message = sender_message_future_.get();
  auto pointer = const_cast<std::uint8_t*>(
      communication::GetMessage(sender_message.data())->payload()->data());
  BitSpan sender_message_span(pointer, 2 * number_of_ots_);
  const auto random_choices =
      data_.receiver_data.random_choices->Subset(ot_id_, ot_id_ + number_of_ots_);

  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    bool difference = sender_message_span.Get(2 * i + static_cast<std::size_t>(random_choices[i]));
    outputs_.Set(difference ^ data_.receiver_data.outputs.at(ot_id_ + i).Get(0), i);
  }
  outputs_computed_ = true;
}

// ---------- Generic GOtSender ----------

GOtSender::GOtSender(std::size_t ot_id, std::size_t number_of_ots, std::size_t bitlength,
                     OtExtensionData& data)
    : BasicOtSender(ot_id, number_of_ots, bitlength, data),
      corrections_future_(data.message_manager.RegisterReceive(
          data_.party_id, communication::MessageType::kOtExtensionReceiverCorrections, ot_id)) {}

void GOtSender::SendMessages() const {
  assert(data_.sender_data.IsSetupReady());
  auto inputs = std::move(inputs_);

  std::vector<std::uint8_t> corrections_message{corrections_future_.get()};
  auto pointer = const_cast<std::uint8_t*>(
      communication::GetMessage(corrections_message.data())->payload()->data());
  BitSpan corrections_span(pointer, number_of_ots_);

  BitVector<> buffer;
  buffer.Reserve(number_of_ots_ * bitlength_ * 2);

  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    // swap the inputs if corrections[i] == true
    if (corrections_span[i]) {
      buffer.Append(inputs[i].Subset(bitlength_, 2 * bitlength_) ^
                    data_.sender_data.y0[ot_id_ + i]);
      buffer.Append(BitSpan(inputs[i].GetMutableData().data(), bitlength_) ^
                    data_.sender_data.y1[ot_id_ + i]);
    } else {
      buffer.Append(BitSpan(inputs[i].GetMutableData().data(), bitlength_) ^
                    data_.sender_data.y0[ot_id_ + i]);
      buffer.Append(inputs[i].Subset(bitlength_, 2 * bitlength_) ^
                    data_.sender_data.y1[ot_id_ + i]);
    }
  }
  auto buffer_span{std::span(reinterpret_cast<const std::uint8_t*>(buffer.GetData().data()),
                             buffer.GetData().size())};
  auto msg{communication::BuildMessage(communication::MessageType::kOtExtensionSender, ot_id_,
                                       buffer_span)};
  data_.send_function(std::move(msg));
}

// ---------- Generic GOtSender ----------

GOtReceiver::GOtReceiver(const std::size_t ot_id, const std::size_t number_of_ots,
                         const std::size_t bitlength, OtExtensionData& data)
    : BasicOtReceiver(ot_id, number_of_ots, bitlength, data), outputs_(number_of_ots) {
  sender_message_future_ = data_.message_manager.RegisterReceive(
      data_.party_id, communication::MessageType::kOtExtensionSender, ot_id);
}

void GOtReceiver::ComputeOutputs() {
  if (outputs_computed_) {
    // already done
    return;
  }

  WaitSetup();

  if (!corrections_sent_) {
    throw std::runtime_error("Choices in OT must be se(n)t before calling ComputeOutputs()");
  }
  std::vector<std::uint8_t> sender_message{sender_message_future_.get()};
  auto pointer = const_cast<std::uint8_t*>(
      communication::GetMessage(sender_message.data())->payload()->data());
  BitSpan sender_message_span(pointer, 2 * bitlength_ * number_of_ots_);
  const auto random_choices =
      data_.receiver_data.random_choices->Subset(ot_id_, ot_id_ + number_of_ots_);

  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    if (random_choices[i]) {
      outputs_[i] = sender_message_span.Subset((2 * i + 1) * bitlength_, (2 * i + 2) * bitlength_);
    } else {
      outputs_[i] = sender_message_span.Subset((2 * i) * bitlength_, (2 * i + 1) * bitlength_);
    }
    outputs_[i] ^= data_.receiver_data.outputs.at(ot_id_ + i);
  }
  outputs_computed_ = true;
}

}  // namespace encrypto::motion
