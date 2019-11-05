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
                              const std::size_t i) {
  switch (type) {
    case BMRDataType::input_step_0: {
      assert(input_public_values_.find(i) != input_public_values_.end());
      std::size_t bitlen = input_public_values_.at(i).first;
      input_public_values_.at(i).second.set_value(
          std::make_unique<ENCRYPTO::BitVector<>>(message, bitlen));
      break;
    }
    case BMRDataType::input_step_1: {
      assert(input_public_keys_.find(i) != input_public_keys_.end());
      std::size_t bitlen = input_public_keys_.at(i).first;
      assert(bitlen % 128 == 0);
      input_public_keys_.at(i).second.set_value(
          std::make_unique<ENCRYPTO::BitVector<>>(message, bitlen));
      break;
    }
    case BMRDataType::and_gate: {
      assert(garbled_rows_.find(i) != garbled_rows_.end());
      std::size_t bitlen = garbled_rows_.at(i).first;
      assert(bitlen % 128 == 0);
      garbled_rows_.at(i).second.set_value(
          std::make_unique<ENCRYPTO::BitVector<>>(message, bitlen));
      break;
    }
    default:
      throw std::runtime_error("Unknown BMR message type");
  }
}

void BMRData::Clear() {
  for (auto &e : input_public_values_) {
    e.second.second = decltype(e.second.second)();
  }
  for (auto &e : input_public_keys_) {
    e.second.second = decltype(e.second.second)();
  }
}

}  // namespace MOTION
