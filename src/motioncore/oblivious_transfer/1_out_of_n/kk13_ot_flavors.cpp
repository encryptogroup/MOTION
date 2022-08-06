// MIT License
//
// Copyright (c) 2021 Arianne Roselina Prananto
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

#include "kk13_ot_flavors.h"

#include "communication/message.h"
#include "data_storage/kk13_ot_extension_data.h"
#include "utility/fiber_condition.h"

namespace encrypto::motion {

// ---------- BasicKk13OtSender ----------

BasicKk13OtSender::BasicKk13OtSender(std::size_t ot_id, std::size_t number_of_ots,
                                     std::size_t bitlength, std::size_t number_of_messages,
                                     OtProtocol p, Kk13OtExtensionData& data)
    : Kk13OtVector(ot_id, number_of_ots, bitlength, number_of_messages, p),
      data_(data),
      corrections_future_(data_.message_manager.RegisterReceive(
          data_.party_id, communication::MessageType::kKK13OtExtensionReceiverCorrections, ot_id)) {
  assert(ot_id == data_.sender_data.bitlengths.size());

  auto each_y_size = data_.sender_data.y.empty() ? 0 : data_.sender_data.y.at(0).size();
  data_.sender_data.y.assign(std::max(data_.sender_data.y.size(), number_of_messages),
                             std::vector<BitVector<>>(each_y_size + number_of_ots));
  data_.sender_data.bitlengths.resize(ot_id + number_of_ots, bitlength);
}

void BasicKk13OtSender::WaitSetup() { data_.sender_data.WaitSetup(); }

// ---------- BasicKk13OtReceiver ----------

BasicKk13OtReceiver::BasicKk13OtReceiver(std::size_t ot_id, std::size_t number_of_ots,
                                         std::size_t bitlength, std::size_t number_of_messages,
                                         OtProtocol p, Kk13OtExtensionData& data)
    : Kk13OtVector(ot_id, number_of_ots, bitlength, number_of_messages, p),
      data_(data),
      sender_message_future_(data_.message_manager.RegisterReceive(
          data_.party_id, communication::MessageType::kKK13OtExtensionSender, ot_id)) {
  assert(ot_id == data_.receiver_data.bitlengths.size());
  data_.receiver_data.bitlengths.resize(ot_id + number_of_ots, bitlength);
  data_.receiver_data.outputs.resize(ot_id + number_of_ots);
}

void BasicKk13OtReceiver::SendCorrections() {
  if (choices_.empty()) {
    throw std::runtime_error("Choices in COT must be set before calling SendCorrections()");
  }

  // get subset from random_choices
  std::vector<std::uint8_t> random_choices_subset(number_of_ots_);
  std::copy(data_.receiver_data.random_choices->begin() + ot_id_,
            data_.receiver_data.random_choices->begin() + ot_id_ + number_of_ots_,
            random_choices_subset.begin());

  // prepare the corrections = (choices - random choices) % number of messages
  std::vector<uint8_t> corrections(number_of_ots_);
  for (std::size_t i = 0; i < number_of_ots_; i++) {
    auto difference = choices_[i] - random_choices_subset[i];
    if (difference < 0) {
      difference += number_of_messages_;
    }
    corrections[i] = difference % number_of_messages_;
  }

  data_.send_function(communication::BuildMessage(
      communication::MessageType::kKK13OtExtensionReceiverCorrections, ot_id_, corrections));
  corrections_sent_ = true;
}

void BasicKk13OtReceiver::WaitSetup() { data_.receiver_data.WaitSetup(); }

// ---------- RKk13OtSender ----------

RKk13OtSender::RKk13OtSender(std::size_t ot_id, std::size_t number_of_ots, std::size_t bitlength,
                             std::size_t number_of_messages, Kk13OtExtensionData& data)
    : Kk13OtVector(ot_id, number_of_ots, bitlength, number_of_messages, kROt), data_(data) {
  auto each_y_size = data_.sender_data.y.empty() ? 0 : data_.sender_data.y.at(0).size();
  data_.sender_data.y.assign(std::max(data_.sender_data.y.size(), number_of_messages),
                             std::vector<BitVector<>>(each_y_size + number_of_ots));
  data_.sender_data.bitlengths.resize(data_.sender_data.bitlengths.size() + number_of_ots,
                                      bitlength);
}

void RKk13OtSender::ComputeOutputs() {
  if (outputs_computed_) {
    // the work was already done
    return;
  }

  // setup phase needs to be finished
  WaitSetup();

  // make space for all the OTs
  outputs_.resize(number_of_ots_);

  // append all masks as the output
  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    outputs_[i].Reserve(bitlen_ * number_of_messages_);
    for (std::size_t j = 0; j < number_of_messages_; ++j) {
      outputs_[i].Append(data_.sender_data.y[j][ot_id_ + i]);
    }
  }

  // remember that we have done this
  outputs_computed_ = true;
}

void RKk13OtSender::WaitSetup() { data_.sender_data.WaitSetup(); }

// ---------- RKk13OtReceiver ----------

RKk13OtReceiver::RKk13OtReceiver(std::size_t ot_id, std::size_t number_of_ots,
                                 std::size_t bitlength, std::size_t number_of_messages,
                                 Kk13OtExtensionData& data)
    : Kk13OtVector(ot_id, number_of_ots, bitlength, number_of_messages, kROt), data_(data) {
  data_.receiver_data.outputs.resize(ot_id + number_of_ots);
  data_.receiver_data.bitlengths.resize(ot_id + number_of_ots, bitlength);
}

void RKk13OtReceiver::ComputeOutputs() {
  if (outputs_computed_) {
    // the work was already done
    return;
  }

  // setup phase needs to be finished
  WaitSetup();

  // copy random choices to the internal buffer
  choices_.assign(data_.receiver_data.random_choices->begin() + ot_id_,
                  data_.receiver_data.random_choices->begin() + ot_id_ + number_of_ots_);

  // copy the selected random mask to the internal buffer
  outputs_.assign(data_.receiver_data.outputs.begin() + ot_id_,
                  data_.receiver_data.outputs.begin() + ot_id_ + number_of_ots_);

  // flag that the outputs have been computed
  outputs_computed_ = true;
}

void RKk13OtReceiver::WaitSetup() { data_.receiver_data.WaitSetup(); }

// ---------- GKk13Ot128Sender ----------

GKk13Ot128Sender::GKk13Ot128Sender(std::size_t ot_id, std::size_t number_of_ots,
                                   std::size_t number_of_messages, Kk13OtExtensionData& data)
    : BasicKk13OtSender(ot_id, number_of_ots, 128, number_of_messages, kGOt, data) {}

void GKk13Ot128Sender::SendMessages() {
  Block128Vector buffer = std::move(inputs_);

  assert(corrections_future_.valid());
  auto corrections_msg{corrections_future_.get()};
  const auto corrections{communication::GetMessage(corrections_msg.data())->payload()->data()};

  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    if (corrections[i]) {
      Block128Vector differences(number_of_messages_);
      for (std::size_t j = 0; j < number_of_messages_; ++j) {
        auto index = (j + corrections[i]) % number_of_messages_;
        differences[j] =
            buffer[number_of_messages_ * i + j] ^ buffer[number_of_messages_ * i + index];
      }
      for (std::size_t j = 0; j < number_of_messages_; ++j) {
        buffer[number_of_messages_ * i + j] ^=
            differences[j] ^ data_.sender_data.y[j][ot_id_ + i].GetData().data();
      }
    } else {
      for (std::size_t j = 0; j < number_of_messages_; ++j) {
        buffer[number_of_messages_ * i + j] ^= data_.sender_data.y[j][ot_id_ + i].GetData().data();
      }
    }
  }

  data_.send_function(communication::BuildMessage(
      communication::MessageType::kKK13OtExtensionSender, ot_id_,
      std::span(reinterpret_cast<const uint8_t*>(buffer.data()->data()), buffer.ByteSize())));
}

// ---------- GKk13Ot128Receiver ----------

GKk13Ot128Receiver::GKk13Ot128Receiver(const std::size_t ot_id, const std::size_t number_of_ots,
                                       std::size_t number_of_messages, Kk13OtExtensionData& data)
    : BasicKk13OtReceiver(ot_id, number_of_ots, 128, number_of_messages, kGOt, data),
      outputs_(number_of_ots) {}

void GKk13Ot128Receiver::ComputeOutputs() {
  if (outputs_computed_) {
    // already done
    return;
  }

  if (!corrections_sent_) {
    throw std::runtime_error("Choices in OT must be se(n)t before calling ComputeOutputs()");
  }
  assert(sender_message_future_.valid());
  auto sender_message = sender_message_future_.get();
  auto payload = communication::GetMessage(sender_message.data())->payload();


  // get subset from random_choices
  std::vector<std::uint8_t> random_choices_subset(number_of_ots_);
  std::copy(data_.receiver_data.random_choices->begin() + ot_id_,
            data_.receiver_data.random_choices->begin() + ot_id_ + number_of_ots_,
            random_choices_subset.begin());

  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    Block128 difference = Block128::MakeFromMemory(reinterpret_cast<const std::byte*>(
        payload->data() +
        (number_of_messages_ * i + random_choices_subset[i]) * Block128::kBlockSize));
    outputs_[i] = difference ^ data_.receiver_data.outputs[ot_id_ + i].GetData().data();
  }

  outputs_computed_ = true;
}

// ---------- GKk13OtBitSender ----------

GKk13OtBitSender::GKk13OtBitSender(std::size_t ot_id, std::size_t number_of_ots,
                                   std::size_t number_of_messages, Kk13OtExtensionData& data)
    : BasicKk13OtSender(ot_id, number_of_ots, 1, number_of_messages, kGOt, data) {}

void GKk13OtBitSender::SendMessages() {
  auto buffer = std::move(inputs_);

  std::vector<bool> b(number_of_messages_);

  auto corrections_msg{corrections_future_.get()};
  const auto corrections{communication::GetMessage(corrections_msg.data())->payload()->data()};

  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    for (std::size_t j = 0; j < number_of_messages_; ++j) {
      b[j] = buffer.Get(number_of_messages_ * i + j);
    }
    // rotate the masks according to the corrections and xor with inputs
    for (std::size_t j = 0; j < number_of_messages_; ++j) {
      buffer.Set(
          b[(j + corrections[i]) % number_of_messages_] ^ data_.sender_data.y[j][ot_id_ + i].Get(0),
          number_of_messages_ * i + j);
    }
  }

  data_.send_function(communication::BuildMessage(
      communication::MessageType::kKK13OtExtensionSender, ot_id_,
      std::span(reinterpret_cast<const std::uint8_t*>(buffer.GetData().data()),
                buffer.GetData().size())));
}

// ---------- GKk13OtBitReceiver ----------

GKk13OtBitReceiver::GKk13OtBitReceiver(const std::size_t ot_id, const std::size_t number_of_ots,
                                       std::size_t number_of_messages, Kk13OtExtensionData& data)
    : BasicKk13OtReceiver(ot_id, number_of_ots, 1, number_of_messages, kGOt, data),
      outputs_(number_of_ots) {}

void GKk13OtBitReceiver::ComputeOutputs() {
  if (outputs_computed_) {
    // already done
    return;
  }

  if (!corrections_sent_) {
    throw std::runtime_error("Choices in OT must be se(n)t before calling ComputeOutputs()");
  }
  auto sender_message = sender_message_future_.get();
  auto payload = communication::GetMessage(sender_message.data())->payload();

  // get subset from random_choices
  std::vector<std::uint8_t> random_choices_subset(number_of_ots_);
  std::copy(data_.receiver_data.random_choices->begin() + ot_id_,
            data_.receiver_data.random_choices->begin() + ot_id_ + number_of_ots_,
            random_choices_subset.begin());

  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    bool difference = BitSpan(
        const_cast<std::uint8_t*>(payload->data()),
        number_of_ots_ * number_of_messages_)[number_of_messages_ * i + random_choices_subset[i]];
    outputs_.Set(difference ^ data_.receiver_data.outputs[ot_id_ + i].Get(0), i);
  }

  outputs_computed_ = true;
}

// ---------- Generic GKk13OtSender ----------

GKk13OtSender::GKk13OtSender(std::size_t ot_id, std::size_t number_of_ots, std::size_t bitlength,
                             std::size_t number_of_messages, Kk13OtExtensionData& data)
    : BasicKk13OtSender(ot_id, number_of_ots, bitlength, number_of_messages, kGOt, data) {}

void GKk13OtSender::SendMessages() {
  auto inputs = std::move(inputs_);

  assert(corrections_future_.valid());
  auto corrections_msg{corrections_future_.get()};
  const auto corrections{communication::GetMessage(corrections_msg.data())->payload()->data()};

  BitVector<> buffer;
  buffer.Reserve(number_of_ots_ * bitlen_ * number_of_messages_);

  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    // rotate the inputs according to corrections[i]
    for (std::size_t j = 0; j < number_of_messages_; ++j) {
      auto index = (j + corrections[i]) % number_of_messages_;
      buffer.Append(inputs[i].Subset(index * bitlen_, (index + 1) * bitlen_) ^
                    data_.sender_data.y[j][ot_id_ + i]);
    }
  }

  data_.send_function(communication::BuildMessage(
      communication::MessageType::kKK13OtExtensionSender, ot_id_,
      std::span(reinterpret_cast<const std::uint8_t*>(buffer.GetData().data()),
                buffer.GetData().size())));
}

// ---------- Generic GKk13OtReceiver ----------

GKk13OtReceiver::GKk13OtReceiver(std::size_t ot_id, std::size_t number_of_ots,
                                 std::size_t bitlength, std::size_t number_of_messages,
                                 Kk13OtExtensionData& data)
    : BasicKk13OtReceiver(ot_id, number_of_ots, bitlength, number_of_messages, kGOt, data),
      outputs_(number_of_ots) {}

void GKk13OtReceiver::ComputeOutputs() {
  if (outputs_computed_) {
    // already done
    return;
  }

  if (!corrections_sent_) {
    throw std::runtime_error("Choices in OT must be se(n)t before calling ComputeOutputs()");
  }
  assert(sender_message_future_.valid());
  auto sender_message = sender_message_future_.get();
  auto payload = communication::GetMessage(sender_message.data())->payload();

  // get subset from random_choices
  std::vector<std::uint8_t> random_choices_subset(number_of_ots_);
  std::copy(data_.receiver_data.random_choices->begin() + ot_id_,
            data_.receiver_data.random_choices->begin() + ot_id_ + number_of_ots_,
            random_choices_subset.begin());

  for (std::size_t i = 0; i < number_of_ots_; ++i) {
    BitVector<> difference =
        BitSpan(const_cast<std::uint8_t*>(payload->data()),
                number_of_ots_ * bitlen_ * number_of_messages_)
            .Subset(bitlen_ * (number_of_messages_ * i + random_choices_subset[i]),
                    bitlen_ * (number_of_messages_ * i + random_choices_subset[i] + 1));;
    outputs_[i] = difference ^ data_.receiver_data.outputs[ot_id_ + i];
  }
  outputs_computed_ = true;
}

}  // namespace encrypto::motion