// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko, Lennart Braun
// Cryptography and Privacy Engineering Group (ENCRYPTO)
// TU Darmstadt, Germany
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

#include "bmr_data.h"
#include "utility/condition.h"

namespace MOTION {

void BMRData::MessageReceived(const std::uint8_t *message, const BMRDataType type,
                              const std::size_t gate_id) {
  // XXX: maybe check that the message has the right size
  switch (type) {
    case BMRDataType::input_step_0: {
      assert(input_public_value_promises_.find(gate_id) != input_public_value_promises_.end());
      std::size_t bitlen = input_public_value_promises_.at(gate_id).first;
      input_public_value_promises_.at(gate_id).second.set_value(
          ENCRYPTO::BitVector<>(message, bitlen));
      break;
    }
    case BMRDataType::input_step_1: {
      assert(input_public_key_promises_.find(gate_id) != input_public_key_promises_.end());
      std::size_t bitlen = input_public_key_promises_.at(gate_id).first;
      assert(bitlen % 128 == 0);
      input_public_key_promises_.at(gate_id).second.set_value(
          ENCRYPTO::BitVector<>(message, bitlen));
      break;
    }
    case BMRDataType::and_gate: {
      assert(garbled_rows_promises_.find(gate_id) != garbled_rows_promises_.end());
      std::size_t bitlen = garbled_rows_promises_.at(gate_id).first;
      assert(bitlen % 128 == 0);
      garbled_rows_promises_.at(gate_id).second.set_value(ENCRYPTO::BitVector<>(message, bitlen));
      break;
    }
    default:
      throw std::runtime_error("Unknown BMR message type");
  }
}

void BMRData::Clear() {}

ENCRYPTO::ReusableFiberFuture<ENCRYPTO::BitVector<>> BMRData::RegisterForInputPublicValues(
    std::size_t gate_id, std::size_t num_blocks) {
  ENCRYPTO::ReusableFiberPromise<ENCRYPTO::BitVector<>> promise;
  auto future = promise.get_future();
  auto [_, success] = input_public_value_promises_.insert(
      {gate_id, std::make_pair(num_blocks, std::move(promise))});
  if (!success) {
    // XXX: write an error to the log
    return {};  // XXX: maybe throw an exception here
  }
  // XXX: write a note to the log
  return future;
}

ENCRYPTO::ReusableFiberFuture<ENCRYPTO::BitVector<>> BMRData::RegisterForInputPublicKeys(
    std::size_t gate_id, std::size_t num_blocks) {
  ENCRYPTO::ReusableFiberPromise<ENCRYPTO::BitVector<>> promise;
  auto future = promise.get_future();
  auto [_, success] =
      input_public_key_promises_.insert({gate_id, std::make_pair(num_blocks, std::move(promise))});
  if (!success) {
    // XXX: write an error to the log
    return {};  // XXX: maybe throw an exception here
  }
  // XXX: write a note to the log
  return future;
}

ENCRYPTO::ReusableFiberFuture<ENCRYPTO::BitVector<>> BMRData::RegisterForGarbledRows(
    std::size_t gate_id, std::size_t bitlen) {
  ENCRYPTO::ReusableFiberPromise<ENCRYPTO::BitVector<>> promise;
  auto future = promise.get_future();
  auto [_, success] =
      garbled_rows_promises_.insert({gate_id, std::make_pair(bitlen, std::move(promise))});
  if (!success) {
    // XXX: write an error to the log
    return {};  // XXX: maybe throw an exception here
  }
  // XXX: write a note to the log
  return future;
}

}  // namespace MOTION
