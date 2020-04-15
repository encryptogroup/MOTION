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
#include "utility/bit_vector.h"
#include "utility/block.h"
#include "utility/reusable_future.h"
#include "utility/type_traits.hpp"

namespace ENCRYPTO {

namespace ObliviousTransfer {

// base class capturing the common things among the sender implementations
class BasicOTSender : public OTVector {
 public:
  // wait that the ot extension setup has finished
  void WaitSetup() const;

 protected:
  BasicOTSender(std::size_t ot_id, std::size_t num_ots, std::size_t bitlen, OTProtocol p,
                const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send,
                MOTION::OTExtensionSenderData &data);

  // reference to data storage
  MOTION::OTExtensionSenderData &data_;
};

// base class capturing the common things among the receiver implementations
class BasicOTReceiver : public OTVector {
 public:
  // wait that the ot extension setup has finished
  void WaitSetup() const;

  // set the receiver's inputs, the choices
  void SetChoices(BitVector<> &&choices) { choices_ = std::move(choices); }
  void SetChoices(const BitVector<> &choices) { choices_ = choices; }

  // get the receiver's inputs, the choices
  const BitVector<> &GetChoices() const { return choices_; }

  // check if the choices are already set
  bool ChoicesAreSet() const { return !choices_.Empty(); }

  // send the correction in the online phase
  void SendCorrections();

 protected:
  BasicOTReceiver(std::size_t ot_id, std::size_t num_ots, std::size_t bitlen, OTProtocol p,
                  const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send,
                  MOTION::OTExtensionReceiverData &data);

  // reference to data storage
  MOTION::OTExtensionReceiverData &data_;

  // input of the receiver, the choices
  BitVector<> choices_;

  // if the corrections have been transmitted
  bool corrections_sent_ = false;
};

// sender implementation of batched xor-correlated 128 bit string OT with a
// fixed correlation for all OTs
class FixedXCOT128Sender : public BasicOTSender {
 public:
  FixedXCOT128Sender(std::size_t ot_id, std::size_t num_ots, MOTION::OTExtensionSenderData &data,
                     const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send);

  // set the *single* correlation for all OTs in this batch
  void SetCorrelation(block128_t correlation) { correlation_ = correlation; }

  // compute the sender's outputs
  void ComputeOutputs();

  // get the sender's outputs
  block128_vector &GetOutputs() {
    assert(outputs_computed_);
    return outputs_;
  }

  // send the sender's messages
  void SendMessages() const;

 private:
  // the correlation function is  f(x) = x ^ correlation_ for all OTs
  block128_t correlation_;

  // the "0 output" for the sender (the "1 output" can be computed by applying the correlation)
  block128_vector outputs_;

  // if the sender outputs have been computed
  bool outputs_computed_ = false;
};

// receiver implementation of batched xor-correlated 128 bit string OT with a
// fixed correlation for all OTs
class FixedXCOT128Receiver : public BasicOTReceiver {
 public:
  FixedXCOT128Receiver(std::size_t ot_id, std::size_t num_ots,
                       MOTION::OTExtensionReceiverData &data,
                       const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send);

  // compute the receiver's outputs
  void ComputeOutputs();

  // get the receiver's outputs
  const block128_vector &GetOutputs() const {
    assert(outputs_computed_);
    return outputs_;
  }

 private:
  // future for the sender's message
  ReusableFiberFuture<block128_vector> sender_message_future_;

  // the output for the receiver
  block128_vector outputs_;

  // if the sender outputs have been computed
  bool outputs_computed_ = false;
};

// sender implementation of batched xor-correlated bit ots
class XCOTBitSender : public BasicOTSender {
 public:
  XCOTBitSender(std::size_t ot_id, std::size_t num_ots, MOTION::OTExtensionSenderData &data,
                const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send);

  // set the correlations for the OTs in this batch
  void SetCorrelations(BitVector<> &&correlations) {
    assert(correlations.GetSize() == num_ots_);
    correlations_ = std::move(correlations);
  }
  void SetCorrelations(const BitVector<> &correlations) {
    assert(correlations.GetSize() == num_ots_);
    correlations_ = correlations;
  }

  // get the correlations for the OTs in this batch
  const BitVector<> &GetCorrelations() const { return correlations_; }

  // compute the sender's outputs
  void ComputeOutputs();

  // get the sender's outputs
  BitVector<> &GetOutputs() {
    assert(outputs_computed_);
    return outputs_;
  }

  // send the sender's messages
  void SendMessages() const;

 private:
  // the correlation vector
  BitVector<> correlations_;

  // the "0 output" for the sender (the "1 output" can be computed by applying the correlation)
  BitVector<> outputs_;

  // if the sender outputs have been computed
  bool outputs_computed_ = false;
};

// receiver implementation of batched xor-correlated bit ots
class XCOTBitReceiver : public BasicOTReceiver {
 public:
  XCOTBitReceiver(std::size_t ot_id, std::size_t num_ots, MOTION::OTExtensionReceiverData &data,
                  const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send);

  // compute the receiver's outputs
  void ComputeOutputs();

  // get the receiver's outputs
  BitVector<> &GetOutputs() {
    assert(outputs_computed_);
    return outputs_;
  }

 private:
  // future for the sender's message
  ReusableFiberFuture<BitVector<>> sender_message_future_;

  // the output for the receiver
  BitVector<> outputs_;

  // if the sender outputs have been computed
  bool outputs_computed_ = false;
};

// sender implementation of batched additive-correlated ots
template <typename T>  //, typename U = is_unsigned_int_t<T>>
class ACOTSender : public BasicOTSender {
  using enabled_t_ = is_unsigned_int_t<T>;

 public:
  ACOTSender(std::size_t ot_id, std::size_t num_ots, std::size_t vector_size,
             MOTION::OTExtensionSenderData &data,
             const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send);

  // set the correlations for the OTs in this batch
  void SetCorrelations(std::vector<T> &&correlations) {
    assert(correlations.size() == num_ots_ * vector_size_);
    correlations_ = std::move(correlations);
  }
  void SetCorrelations(const std::vector<T> &correlations) {
    assert(correlations.size() == num_ots_ * vector_size_);
    correlations_ = correlations;
  }

  // get the correlations for the OTs in this batch
  const std::vector<T> &GetCorrelations() const { return correlations_; }

  // compute the sender's outputs
  void ComputeOutputs();

  // get the sender's outputs
  std::vector<T> &GetOutputs() {
    assert(outputs_computed_);
    return outputs_;
  }

  // send the sender's messages
  void SendMessages() const;

 private:
  // dimension of each sender-input/output
  const std::size_t vector_size_;

  // the correlation vector
  std::vector<T> correlations_;

  // the "0 output" for the sender (the "1 output" can be computed by applying the correlation)
  std::vector<T> outputs_;

  // if the sender outputs have been computed
  bool outputs_computed_ = false;
};

// receiver implementation of batched additive-correlated ots
template <typename T>  //, typename = is_unsigned_int_t<T>>
class ACOTReceiver : public BasicOTReceiver {
  using enabled_t_ = is_unsigned_int_t<T>;

 public:
  ACOTReceiver(std::size_t ot_id, std::size_t num_ots, std::size_t vector_size,
               MOTION::OTExtensionReceiverData &data,
               const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send);

  // compute the receiver's outputs
  void ComputeOutputs();

  // get the receiver's outputs
  std::vector<T> &GetOutputs() {
    assert(outputs_computed_);
    return outputs_;
  }

 private:
  // dimension of each sender-input/output
  const std::size_t vector_size_;

  // future for the sender's message
  ReusableFiberFuture<std::vector<T>> sender_message_future_;

  // the output for the receiver
  std::vector<T> outputs_;

  // if the sender outputs have been computed
  bool outputs_computed_ = false;
};

// sender implementation of batched 128 bit string OT
class GOT128Sender : public BasicOTSender {
 public:
  GOT128Sender(std::size_t ot_id, std::size_t num_ots, MOTION::OTExtensionSenderData &data,
               const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send);

  // set the message pairs for all OTs in this batch
  void SetInputs(block128_vector &&inputs) { inputs_ = std::move(inputs); }
  void SetInputs(const block128_vector &inputs) { inputs_ = inputs; }

  // send the sender's messages
  void SendMessages() const;

 private:
  // the sender's inputs, 2 * num_ots blocks
  block128_vector inputs_;

  // if the sender outputs have been computed
  bool outputs_computed_ = false;
};

// receiver implementation of batched 128 bit string OT
class GOT128Receiver : public BasicOTReceiver {
 public:
  GOT128Receiver(std::size_t ot_id, std::size_t num_ots, MOTION::OTExtensionReceiverData &data,
                 const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send);

  // compute the receiver's outputs
  void ComputeOutputs();

  // get the receiver's outputs
  const block128_vector &GetOutputs() const {
    assert(outputs_computed_);
    return outputs_;
  }

 private:
  // future for the sender's message
  ReusableFiberFuture<block128_vector> sender_message_future_;

  // the output for the receiver
  block128_vector outputs_;

  // if the sender outputs have been computed
  bool outputs_computed_ = false;
};

// sender implementation of batched 1 bit string OT
class GOTBitSender : public BasicOTSender {
 public:
  GOTBitSender(std::size_t ot_id, std::size_t num_ots, MOTION::OTExtensionSenderData &data,
               const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send);

  // set the message pairs for all OTs in this batch
  void SetInputs(BitVector<> &&inputs) { inputs_ = std::move(inputs); }
  void SetInputs(const BitVector<> &inputs) { inputs_ = inputs; }

  // send the sender's messages
  void SendMessages() const;

 private:
  // the sender's inputs, 2 * num_ots blocks
  BitVector<> inputs_;

  // if the sender outputs have been computed
  bool outputs_computed_ = false;
};

// receiver implementation of batched 128 bit string OT
class GOTBitReceiver : public BasicOTReceiver {
 public:
  GOTBitReceiver(std::size_t ot_id, std::size_t num_ots, MOTION::OTExtensionReceiverData &data,
                 const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send);

  // compute the receiver's outputs
  void ComputeOutputs();

  // get the receiver's outputs
  const BitVector<> &GetOutputs() const {
    assert(outputs_computed_);
    return outputs_;
  }

 private:
  // future for the sender's message
  ReusableFiberFuture<BitVector<>> sender_message_future_;

  // the output for the receiver
  BitVector<> outputs_;

  // if the sender outputs have been computed
  bool outputs_computed_ = false;
};

}  // namespace ObliviousTransfer
}  // namespace ENCRYPTO
