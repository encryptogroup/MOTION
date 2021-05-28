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

#pragma once

#include <cstddef>
#include <memory>
#include <unordered_map>
#include <utility>
#include "utility/bit_vector.h"
#include "utility/block.h"
#include "utility/reusable_future.h"

namespace encrypto::motion::proto::bmr {

class Condition;

enum DataType : unsigned int { kInputStep0 = 0, kInputStep1 = 1, kAndGate = 2 };

struct Data {
  void MessageReceived(const std::uint8_t* message, const DataType type, const std::size_t i);
  void Reset();

  ReusableFiberFuture<BitVector<>> RegisterForInputPublicValues(std::size_t gate_id,
                                                                std::size_t bitlength);
  ReusableFiberFuture<Block128Vector> RegisterForInputPublicKeys(std::size_t gate_id,
                                                                 std::size_t number_of_blocks);
  ReusableFiberFuture<Block128Vector> RegisterForGarbledRows(std::size_t gate_id,
                                                             std::size_t number_of_blocks);

  // gate_id -> bit size X promise with public values
  using InputPublicValueType = std::pair<std::size_t, ReusableFiberPromise<BitVector<>>>;
  std::unordered_map<std::size_t, InputPublicValueType> input_public_value_promises_;

  // gate_id -> block size X promise with keys
  using KeysType = std::pair<std::size_t, ReusableFiberPromise<Block128Vector>>;
  std::unordered_map<std::size_t, KeysType> input_public_key_promises_;

  // gate_id -> block size X promise with partial garbled rows
  using GarbledRowsType = std::pair<std::size_t, ReusableFiberPromise<Block128Vector>>;
  std::unordered_map<std::size_t, GarbledRowsType> garbled_rows_promises_;
};

}  // namespace encrypto::motion::proto::bmr
