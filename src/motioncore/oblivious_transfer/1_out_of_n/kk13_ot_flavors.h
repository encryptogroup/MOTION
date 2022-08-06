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

#pragma once

#include "kk13_ot_provider.h"

#include <span>

#include "utility/bit_vector.h"
#include "utility/block.h"
#include "utility/reusable_future.h"
#include "utility/type_traits.h"

namespace encrypto::motion {

// class capturing the common things among the sender implementations
class BasicKk13OtSender : public Kk13OtVector {
 public:
  void WaitSetup();

 protected:
  BasicKk13OtSender(std::size_t ot_id, std::size_t number_of_ots, std::size_t bitlength,
                    std::size_t number_of_messages, OtProtocol p, Kk13OtExtensionData& data);

  // reference to data storage
  Kk13OtExtensionData& data_;

  // future for the message containing client's corrections
  ReusableFiberFuture<std::vector<std::uint8_t>> corrections_future_;
};

// class capturing the common things among the receiver implementations
class BasicKk13OtReceiver : public Kk13OtVector {
 public:
  // set the receiver's inputs, the choices
  void SetChoices(std::vector<std::uint8_t>&& choices) {
    for (std::size_t i = 0; i < choices.size(); i++) {
      if (choices[i] >= number_of_messages_)
        std::runtime_error(fmt::format("Choice {} exceeds number of message {}.", choices[i],
                                       number_of_messages_));
    }
    choices_ = std::move(choices);
  }

  void SetChoices(const std::vector<std::uint8_t>& choices) {
    for (std::size_t i = 0; i < choices.size(); i++) {
      if (choices[i] >= number_of_messages_)
        std::runtime_error(fmt::format("Choice {} exceeds number of message {}.", choices[i],
                                       number_of_messages_));
    }
    choices_ = choices;
  }

  // get the receiver's inputs, the choices
  const std::vector<std::uint8_t>& GetChoices() const { return choices_; }

  // check if the choices are already set
  bool AreChoicesSet() const { return !choices_.empty(); }

  // send the correction in the online phase
  void SendCorrections();

  void WaitSetup();

 protected:
  BasicKk13OtReceiver(std::size_t ot_id, std::size_t number_of_ots, std::size_t bitlength,
                      std::size_t number_of_messages, OtProtocol p, Kk13OtExtensionData& data);

  // reference to data storage
  Kk13OtExtensionData& data_;

  // input of the receiver, the choices
  std::vector<std::uint8_t> choices_;

  // if the corrections have been transmitted
  bool corrections_sent_ = false;

  // future for the sender's message
  ReusableFiberFuture<std::vector<std::uint8_t>> sender_message_future_;
};

// sender implementation of batched xor-correlated bit ots
class RKk13OtSender : public Kk13OtVector {
 public:
  RKk13OtSender(std::size_t ot_id, std::size_t number_of_ots, std::size_t bitlength,
                std::size_t number_of_messages, Kk13OtExtensionData& data);

  // compute the sender's outputs
  void ComputeOutputs();

  // get the sender's outputs
  std::span<const BitVector<>> GetOutputs() const {
    assert(outputs_computed_);
    return outputs_;
  }

  // send the sender's messages
  void SendMessages();

  void WaitSetup();

 private:
  // reference to data storage
  Kk13OtExtensionData& data_;

  // all output masks of the sender
  std::vector<BitVector<>> outputs_;

  // if the sender outputs have been computed
  bool outputs_computed_ = false;
};

// receiver implementation of batched random generic ots
class RKk13OtReceiver : Kk13OtVector {
 public:
  RKk13OtReceiver(std::size_t ot_id, std::size_t number_of_ots, std::size_t bitlength,
                  std::size_t number_of_messages, Kk13OtExtensionData& data);

  // compute the receiver's outputs
  void ComputeOutputs();

  // get the receiver's outputs
  std::span<const BitVector<>> GetOutputs() {
    assert(outputs_computed_);
    return outputs_;
  }

  const std::vector<std::uint8_t>& GetChoices() {
    assert(outputs_computed_);
    return choices_;
  }

  void WaitSetup();

 private:
  // reference to data storage
  Kk13OtExtensionData& data_;

  // random message choices
  std::vector<std::uint8_t> choices_;

  // the output for the receiver
  std::vector<BitVector<>> outputs_;

  // if the sender outputs have been computed
  bool outputs_computed_ = false;
};

// sender implementation of batched 128 bit string OT
class GKk13Ot128Sender : public BasicKk13OtSender {
 public:
  GKk13Ot128Sender(std::size_t ot_id, std::size_t number_of_ots, std::size_t number_of_messages,
                   Kk13OtExtensionData& data);

  // set the message pairs for all OTs in this batch
  void SetInputs(Block128Vector&& inputs) { inputs_ = std::move(inputs); }
  void SetInputs(const Block128Vector& inputs) { inputs_ = inputs; }

  // send the sender's messages
  void SendMessages();

 private:
  // the sender's inputs, number_of_messages * number_of_ots blocks
  Block128Vector inputs_;
};

// receiver implementation of batched 128 bit string OT
class GKk13Ot128Receiver : public BasicKk13OtReceiver {
 public:
  GKk13Ot128Receiver(std::size_t ot_id, std::size_t number_of_ots, std::size_t number_of_messages,
                     Kk13OtExtensionData& data);

  // compute the receiver's outputs
  void ComputeOutputs();

  // get the receiver's outputs
  const Block128Vector& GetOutputs() const {
    assert(outputs_computed_);
    return outputs_;
  }

 private:
  // the output for the receiver
  Block128Vector outputs_;

  // if the sender outputs have been computed
  bool outputs_computed_ = false;
};

// sender implementation of batched 1 bit string OT
class GKk13OtBitSender : public BasicKk13OtSender {
 public:
  GKk13OtBitSender(std::size_t ot_id, std::size_t number_of_ots, std::size_t number_of_messages,
                   Kk13OtExtensionData& data);

  // set the message pairs for all OTs in this batch
  void SetInputs(BitVector<>&& inputs) { inputs_ = std::move(inputs); }
  void SetInputs(const BitVector<>& inputs) { inputs_ = inputs; }

  // send the sender's messages
  void SendMessages();

 private:
  // the sender's inputs, number_of_messages * number_of_ots blocks
  BitVector<> inputs_;
};

// receiver implementation of batched 1 bit string OT
class GKk13OtBitReceiver : public BasicKk13OtReceiver {
 public:
  GKk13OtBitReceiver(std::size_t ot_id, std::size_t number_of_ots, std::size_t number_of_messages,
                     Kk13OtExtensionData& data);

  // compute the receiver's outputs
  void ComputeOutputs();

  // get the receiver's outputs
  const BitVector<>& GetOutputs() const {
    assert(outputs_computed_);
    return outputs_;
  }

 private:
  // the output for the receiver
  BitVector<> outputs_;

  // if the sender outputs have been computed
  bool outputs_computed_ = false;
};

// sender implementation of batched arbitrary-size bit string OT
class GKk13OtSender : public BasicKk13OtSender {
 public:
  GKk13OtSender(std::size_t ot_id, std::size_t number_of_ots, std::size_t bitlength,
                std::size_t number_of_messages, Kk13OtExtensionData& data);

  // set the message pairs for all OTs in this batch
  void SetInputs(std::vector<BitVector<>>&& inputs) { inputs_ = std::move(inputs); }
  void SetInputs(const std::span<BitVector<>> inputs) {
    inputs_.assign(inputs.begin(), inputs.end());
  }

  // send the sender's messages
  void SendMessages();

 private:
  // the sender's inputs, number_of_messages * number_of_ots blocks
  std::vector<BitVector<>> inputs_;
};

// receiver implementation of batched arbitrary-size bit string OT
class GKk13OtReceiver : public BasicKk13OtReceiver {
 public:
  GKk13OtReceiver(std::size_t ot_id, std::size_t number_of_ots, std::size_t bitlength,
                  std::size_t number_of_messages, Kk13OtExtensionData& data);

  // compute the receiver's outputs
  void ComputeOutputs();

  // get the receiver's outputs
  std::span<const BitVector<>> GetOutputs() const {
    assert(outputs_computed_);
    return outputs_;
  }

 private:
  // the output for the receiver
  std::vector<BitVector<>> outputs_;

  // if the sender outputs have been computed
  bool outputs_computed_ = false;
};

}  // namespace encrypto::motion