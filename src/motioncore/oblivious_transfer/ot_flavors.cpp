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
