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

namespace ENCRYPTO {

namespace ObliviousTransfer {

// base class capturing the common things among the sender implementations
class BasicCOTSender : public OTVector {
 public:
  // wait that the ot extension setup has finished
  void WaitSetup() const;

 protected:
  BasicCOTSender(const std::size_t ot_id, const std::size_t num_ots, const std::size_t bitlen,
                 const OTProtocol p,
                 const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send,
                 MOTION::OTExtensionSenderData &data)
      : OTVector(ot_id, num_ots, bitlen, p, Send), data_(data) {}

  // reference to data storage
  MOTION::OTExtensionSenderData &data_;
};

// base class capturing the common things among the receiver implementations
class BasicCOTReceiver : public OTVector {
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
  BasicCOTReceiver(const std::size_t ot_id, const std::size_t num_ots, const std::size_t bitlen,
                   const OTProtocol p,
                   const std::function<void(flatbuffers::FlatBufferBuilder &&)> &Send,
                   MOTION::OTExtensionReceiverData &data)
      : OTVector(ot_id, num_ots, bitlen, p, Send), data_(data) {}

  // reference to data storage
  MOTION::OTExtensionReceiverData &data_;

  // input of the receiver, the choices
  BitVector<> choices_;

  // if the corrections have been transmitted
  bool corrections_sent_ = false;
};

// sender implementation of batched xor-correlated 128 bit string OT with a
// fixed correlation for all OTs
class FixedXCOT128VectorSender : public BasicCOTSender {
 public:
  FixedXCOT128VectorSender(std::size_t ot_id, std::size_t num_ots,
                           MOTION::OTExtensionSenderData &data,
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
class FixedXCOT128VectorReceiver : public BasicCOTReceiver {
 public:
  FixedXCOT128VectorReceiver(std::size_t ot_id, std::size_t num_ots,
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
class XCOTBitVectorSender : public BasicCOTSender {
 public:
  XCOTBitVectorSender(std::size_t ot_id, std::size_t num_ots,
                      MOTION::OTExtensionSenderData &data,
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
class XCOTBitVectorReceiver : public BasicCOTReceiver {
 public:
  XCOTBitVectorReceiver(std::size_t ot_id, std::size_t num_ots,
                        MOTION::OTExtensionReceiverData &data,
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

}  // namespace ObliviousTransfer
}  // namespace ENCRYPTO
