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

#pragma once

#include "ot_provider.h"

#include <span>

#include "communication/message_manager.h"
#include "utility/bit_vector.h"
#include "utility/block.h"
#include "utility/reusable_future.h"
#include "utility/type_traits.h"

namespace encrypto::motion {

// base class capturing the common things among the sender implementations
class BasicOtSender : public OtVector {
 public:
  // wait that the ot extension setup has finished
  void WaitSetup() const;

 protected:
  BasicOtSender(std::size_t ot_id, std::size_t number_of_ots, std::size_t bitlength,
                OtExtensionData& data);
};

// base class capturing the common things among the receiver implementations
class BasicOtReceiver : public OtVector {
 public:
  // wait that the ot extension setup has finished
  void WaitSetup() const;

  // set the receiver's inputs, the choices
  void SetChoices(BitVector<>&& choices) { choices_ = std::move(choices); }
  void SetChoices(const BitVector<>& choices) { choices_ = choices; }

  // get the receiver's inputs, the choices
  const BitVector<>& GetChoices() const { return choices_; }

  // check if the choices are already set
  bool AreChoicesSet() const { return !choices_.Empty(); }

  // send the correction in the online phase
  void SendCorrections();

 protected:
  BasicOtReceiver(std::size_t ot_id, std::size_t number_of_ots, std::size_t bitlength,
                  OtExtensionData& data);

  // input of the receiver, the choices
  BitVector<> choices_;

  // if the corrections have been transmitted
  bool corrections_sent_ = false;
};

// sender implementation of batched random generic OTs
class ROtSender : public OtVector {
 public:
  ROtSender(std::size_t ot_id, std::size_t number_of_ots, std::size_t bitlength,
            OtExtensionData& data);

  [[nodiscard]] OtProtocol GetProtocol() const noexcept override { return OtProtocol::kROt; }

  // wait that the ot extension setup has finished
  void WaitSetup() const;

  // compute the sender's outputs
  void ComputeOutputs();

  // get the sender's outputs
  std::span<const BitVector<>> GetOutputs() const {
    assert(outputs_computed_);
    return outputs_;
  }

  // send the sender's messages
  void SendMessages() const;

 private:
  // both output masks of the sender
  std::vector<BitVector<>> outputs_;

  // if the sender outputs have been computed
  bool outputs_computed_ = false;
};

// sender implementation of batched xor-correlated 128 bit string OT with a
// fixed correlation for all OTs
class FixedXcOt128Sender : public BasicOtSender {
 public:
  FixedXcOt128Sender(std::size_t ot_id, std::size_t number_of_ots, OtExtensionData& data);

  // set the *single* correlation for all OTs in this batch
  void SetCorrelation(Block128 correlation) { correlation_ = correlation; }

  // compute the sender's outputs
  void ComputeOutputs();

  // get the sender's outputs
  Block128Vector& GetOutputs() {
    assert(outputs_computed_);
    return outputs_;
  }

  // send the sender's messages
  void SendMessages() const;

  [[nodiscard]] OtProtocol GetProtocol() const noexcept override {
    return OtProtocol::kFixedXcOt128;
  }

 private:
  // the correlation function is  f(x) = x ^ correlation_ for all OTs
  Block128 correlation_;

  // the "0 output" for the sender (the "1 output" can be computed by applying the correlation)
  Block128Vector outputs_;

  // if the sender outputs have been computed
  bool outputs_computed_ = false;

  // future for the message containing client's corrections
  ReusableFiberFuture<std::vector<std::uint8_t>> corrections_future_;
};

// receiver implementation of batched xor-correlated 128 bit string OT with a
// fixed correlation for all OTs
class FixedXcOt128Receiver : public BasicOtReceiver {
 public:
  FixedXcOt128Receiver(std::size_t ot_id, std::size_t number_of_ots, OtExtensionData& data);

  // compute the receiver's outputs
  void ComputeOutputs();

  // get the receiver's outputs
  const Block128Vector& GetOutputs() const {
    assert(outputs_computed_);
    return outputs_;
  }

  [[nodiscard]] OtProtocol GetProtocol() const noexcept override {
    return OtProtocol::kFixedXcOt128;
  }

 private:
  // future for the sender's message
  ReusableFiberFuture<std::vector<std::uint8_t>> sender_message_future_;

  // the output for the receiver
  Block128Vector outputs_;

  // if the sender outputs have been computed
  bool outputs_computed_ = false;
};

// sender implementation of batched xor-correlated bit ots
class XcOtBitSender : public BasicOtSender {
 public:
  XcOtBitSender(std::size_t ot_id, std::size_t number_of_ots, OtExtensionData& data);

  // set the correlations for the OTs in this batch
  void SetCorrelations(BitVector<>&& correlations) {
    assert(correlations.GetSize() == number_of_ots_);
    correlations_ = std::move(correlations);
  }
  void SetCorrelations(const BitVector<>& correlations) {
    assert(correlations.GetSize() == number_of_ots_);
    correlations_ = correlations;
  }

  // get the correlations for the OTs in this batch
  const BitVector<>& GetCorrelations() const { return correlations_; }

  // compute the sender's outputs
  void ComputeOutputs();

  // get the sender's outputs
  BitVector<>& GetOutputs() {
    assert(outputs_computed_);
    return outputs_;
  }

  // send the sender's messages
  void SendMessages() const;

  [[nodiscard]] OtProtocol GetProtocol() const noexcept override { return OtProtocol::kXcOtBit; }

 private:
  // the correlation vector
  BitVector<> correlations_;

  // the "0 output" for the sender (the "1 output" can be computed by applying the correlation)
  BitVector<> outputs_;

  // if the sender outputs have been computed
  bool outputs_computed_ = false;

  // future for the message containing client's corrections
  ReusableFiberFuture<std::vector<std::uint8_t>> corrections_future_;
};

// sender implementation of batched xor-correlated bit ots
class XcOtSender : public BasicOtSender {
 public:
  XcOtSender(std::size_t ot_id, std::size_t number_of_ots, std::size_t bitlength,
             OtExtensionData& data);

  // set the correlations for the OTs in this batch
  void SetCorrelations(std::vector<BitVector<>>&& correlations) {
    assert(correlations.size() == number_of_ots_);
    correlations_ = std::move(correlations);
  }
  void SetCorrelations(std::span<const BitVector<>> correlations) {
    assert(correlations.size() == number_of_ots_);
    correlations_.assign(correlations.begin(), correlations.end());
  }

  // get the correlations for the OTs in this batch
  std::span<const BitVector<>> GetCorrelations() const { return correlations_; }

  // compute the sender's outputs
  void ComputeOutputs();

  // get the sender's outputs
  std::span<const BitVector<>> GetOutputs() const {
    assert(outputs_computed_);
    return outputs_;
  }

  // send the sender's messages
  void SendMessages() const;

  [[nodiscard]] OtProtocol GetProtocol() const noexcept override { return OtProtocol::kXcOt; }

 private:
  // the correlation vector
  std::vector<BitVector<>> correlations_;

  // the "0 output" for the sender (the "1 output" can be computed by applying the correlation)
  std::vector<BitVector<>> outputs_;

  // if the sender outputs have been computed
  bool outputs_computed_ = false;

  // future for the message containing client's corrections
  ReusableFiberFuture<std::vector<std::uint8_t>> corrections_future_;
};

// receiver implementation of batched random generic ots
class ROtReceiver : OtVector {
 public:
  ROtReceiver(std::size_t ot_id, std::size_t number_of_ots, std::size_t bitlength,
              OtExtensionData& data);

  // wait that the ot extension setup has finished
  void WaitSetup() const;

  // compute the receiver's outputs
  void ComputeOutputs();

  // get the receiver's outputs
  std::span<const BitVector<>> GetOutputs() {
    assert(outputs_computed_);
    return outputs_;
  }

  const BitVector<>& GetChoices() {
    assert(outputs_computed_);
    return choices_;
  }

  [[nodiscard]] OtProtocol GetProtocol() const noexcept override { return OtProtocol::kROt; }

 private:
  // random message choices
  BitVector<> choices_;

  // the output for the receiver
  std::vector<BitVector<>> outputs_;

  // if the sender outputs have been computed
  bool outputs_computed_ = false;
};

// receiver implementation of batched xor-correlated bit ots
class XcOtBitReceiver : public BasicOtReceiver {
 public:
  XcOtBitReceiver(std::size_t ot_id, std::size_t number_of_ots, OtExtensionData& data);

  // compute the receiver's outputs
  void ComputeOutputs();

  // get the receiver's outputs
  BitVector<>& GetOutputs() {
    assert(outputs_computed_);
    return outputs_;
  }

  [[nodiscard]] OtProtocol GetProtocol() const noexcept override { return OtProtocol::kXcOtBit; }

 private:
  // future for the sender's message
  ReusableFiberFuture<std::vector<std::uint8_t>> sender_message_future_;

  // the output for the receiver
  BitVector<> outputs_;

  // if the sender outputs have been computed
  bool outputs_computed_ = false;
};

// receiver implementation of batched xor-correlated generic ots
class XcOtReceiver : public BasicOtReceiver {
 public:
  XcOtReceiver(std::size_t ot_id, std::size_t number_of_ots, std::size_t bitlength,
               OtExtensionData& data);

  // compute the receiver's outputs
  void ComputeOutputs();

  // get the receiver's outputs
  std::span<const BitVector<>> GetOutputs() {
    assert(outputs_computed_);
    return outputs_;
  }

  [[nodiscard]] OtProtocol GetProtocol() const noexcept override { return OtProtocol::kXcOt; }

 private:
  // future for the sender's message
  ReusableFiberFuture<std::vector<std::uint8_t>> sender_message_future_;

  // the output for the receiver
  std::vector<BitVector<>> outputs_;

  // if the sender outputs have been computed
  bool outputs_computed_ = false;
};

// sender implementation of batched additive-correlated ots
template <typename T>  //, typename U = IsUnsignedInt<T>>
class AcOtSender : public BasicOtSender {
  using IsUnsignedEnablerType = IsUnsignedInt<T>;

 public:
  AcOtSender(std::size_t ot_id, std::size_t number_of_ots, std::size_t vector_size,
             OtExtensionData& data);

  // set the correlations for the OTs in this batch
  void SetCorrelations(std::vector<T>&& correlations) {
    assert(correlations.size() == number_of_ots_ * vector_size_);
    correlations_ = std::move(correlations);
  }
  void SetCorrelations(const std::vector<T>& correlations) {
    assert(correlations.size() == number_of_ots_ * vector_size_);
    correlations_ = correlations;
  }

  // get the correlations for the OTs in this batch
  const std::vector<T>& GetCorrelations() const { return correlations_; }

  // compute the sender's outputs
  void ComputeOutputs();

  // get the sender's outputs
  std::vector<T>& GetOutputs() {
    assert(outputs_computed_);
    return outputs_;
  }

  // send the sender's messages
  void SendMessages() const;

  [[nodiscard]] OtProtocol GetProtocol() const noexcept override { return OtProtocol::kAcOt; }

 private:
  // dimension of each sender-input/output
  const std::size_t vector_size_;

  // the correlation vector
  std::vector<T> correlations_;

  // the "0 output" for the sender (the "1 output" can be computed by applying the correlation)
  std::vector<T> outputs_;

  // if the sender outputs have been computed
  bool outputs_computed_ = false;

  // future for the message containing client's corrections
  ReusableFiberFuture<std::vector<std::uint8_t>> corrections_future_;
};

// receiver implementation of batched additive-correlated ots
template <typename T>  //, typename = IsUnsignedInt<T>>
class AcOtReceiver : public BasicOtReceiver {
  using IsUnsignedEnablerType = IsUnsignedInt<T>;

 public:
  AcOtReceiver(std::size_t ot_id, std::size_t number_of_ots, std::size_t vector_size,
               OtExtensionData& data);

  // compute the receiver's outputs
  void ComputeOutputs();

  // get the receiver's outputs
  std::vector<T>& GetOutputs() {
    assert(outputs_computed_);
    return outputs_;
  }

  [[nodiscard]] OtProtocol GetProtocol() const noexcept override { return OtProtocol::kAcOt; }

 private:
  // dimension of each sender-input/output
  const std::size_t vector_size_;

  // future for the sender's message
  ReusableFiberFuture<std::vector<std::uint8_t>> sender_message_future_;

  // the output for the receiver
  std::vector<T> outputs_;

  // if the sender outputs have been computed
  bool outputs_computed_ = false;
};

// sender implementation of batched 128 bit string OT
class GOt128Sender : public BasicOtSender {
 public:
  GOt128Sender(std::size_t ot_id, std::size_t number_of_ots, OtExtensionData& data);

  // set the message pairs for all OTs in this batch
  void SetInputs(Block128Vector&& inputs) { inputs_ = std::move(inputs); }
  void SetInputs(const Block128Vector& inputs) { inputs_ = inputs; }

  // send the sender's messages
  void SendMessages() const;

  [[nodiscard]] OtProtocol GetProtocol() const noexcept override { return OtProtocol::kGOt128; }

 private:
  // the sender's inputs, 2 * number_of_ots blocks
  Block128Vector inputs_;

  // future for the message containing client's corrections
  mutable ReusableFiberFuture<std::vector<std::uint8_t>> corrections_future_;
};

// receiver implementation of batched 128 bit string OT
class GOt128Receiver : public BasicOtReceiver {
 public:
  GOt128Receiver(std::size_t ot_id, std::size_t number_of_ots, OtExtensionData& data);

  // compute the receiver's outputs
  void ComputeOutputs();

  // get the receiver's outputs
  const Block128Vector& GetOutputs() const {
    assert(outputs_computed_);
    return outputs_;
  }

  [[nodiscard]] OtProtocol GetProtocol() const noexcept override { return OtProtocol::kGOt128; }

 private:
  // future for the sender's message
  ReusableFiberFuture<std::vector<std::uint8_t>> sender_message_future_;

  // the output for the receiver
  Block128Vector outputs_;

  // if the sender outputs have been computed
  bool outputs_computed_ = false;
};

// sender implementation of batched string OT
class GOtBitSender : public BasicOtSender {
 public:
  GOtBitSender(std::size_t ot_id, std::size_t number_of_ots, OtExtensionData& datar);

  // set the message pairs for all OTs in this batch
  void SetInputs(BitVector<>&& inputs) { inputs_ = std::move(inputs); }
  void SetInputs(const BitVector<>& inputs) { inputs_ = inputs; }

  // send the sender's messages
  void SendMessages() const;

  [[nodiscard]] OtProtocol GetProtocol() const noexcept override { return OtProtocol::kGOtBit; }

 private:
  // the sender's inputs, 2 * number_of_ots blocks
  BitVector<> inputs_;

  // future for the message containing client's corrections
  mutable ReusableFiberFuture<std::vector<std::uint8_t>> corrections_future_;
};

// sender implementation of batched string OT
class GOtSender : public BasicOtSender {
 public:
  GOtSender(std::size_t ot_id, std::size_t number_of_ots, std::size_t bitlength,
            OtExtensionData& data);

  // set the message pairs for all OTs in this batch
  void SetInputs(std::vector<BitVector<>>&& inputs) { inputs_ = std::move(inputs); }
  void SetInputs(const std::span<BitVector<>> inputs) {
    inputs_.assign(inputs.begin(), inputs.end());
  }

  // send the sender's messages
  void SendMessages() const;

  [[nodiscard]] OtProtocol GetProtocol() const noexcept override { return OtProtocol::kGOt; }

 private:
  // the sender's inputs, 2 * number_of_ots blocks
  std::vector<BitVector<>> inputs_;

  // future for the message containing client's corrections
  mutable ReusableFiberFuture<std::vector<std::uint8_t>> corrections_future_;
};

// receiver implementation of batched string OT
class GOtBitReceiver : public BasicOtReceiver {
 public:
  GOtBitReceiver(std::size_t ot_id, std::size_t number_of_ots, OtExtensionData& data);

  // compute the receiver's outputs
  void ComputeOutputs();

  // get the receiver's outputs
  const BitVector<>& GetOutputs() const {
    assert(outputs_computed_);
    return outputs_;
  }

  [[nodiscard]] OtProtocol GetProtocol() const noexcept override { return OtProtocol::kGOtBit; }

 private:
  // future for the sender's message
  ReusableFiberFuture<std::vector<std::uint8_t>> sender_message_future_;

  // the output for the receiver
  BitVector<> outputs_;

  // if the sender outputs have been computed
  bool outputs_computed_ = false;
};

// receiver implementation of batched string OT
class GOtReceiver : public BasicOtReceiver {
 public:
  GOtReceiver(std::size_t ot_id, std::size_t number_of_ots, std::size_t bitlength,
              OtExtensionData& data);

  // compute the receiver's outputs
  void ComputeOutputs();

  // get the receiver's outputs
  const std::span<const BitVector<>> GetOutputs() const {
    assert(outputs_computed_);
    return outputs_;
  }

  [[nodiscard]] OtProtocol GetProtocol() const noexcept override { return OtProtocol::kGOt; }

 private:
  // future for the sender's message
  ReusableFiberFuture<std::vector<std::uint8_t>> sender_message_future_;

  // the output for the receiver
  std::vector<BitVector<>> outputs_;

  // if the sender outputs have been computed
  bool outputs_computed_ = false;
};

}  // namespace encrypto::motion
