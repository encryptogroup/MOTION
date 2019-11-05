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

#include <boost/fiber/future.hpp>
#include <cstddef>
#include <memory>
#include <unordered_map>
#include <utility>
#include "utility/bit_vector.h"

namespace ENCRYPTO {
class Condition;
}

namespace MOTION {

enum BMRDataType : uint { input_step_0 = 0, input_step_1 = 1, and_gate = 2 };

struct BMRData {
  void MessageReceived(const std::uint8_t* message, const BMRDataType type, const std::size_t i);
  void Clear();

  // bitlen and promise with the return buffer
  using in_pub_val_t =
      std::pair<std::size_t, boost::fibers::promise<std::unique_ptr<ENCRYPTO::BitVector<>>>>;
  std::unordered_map<std::size_t, in_pub_val_t> input_public_values_;

  using keys_t =
      std::pair<std::size_t, boost::fibers::promise<std::unique_ptr<ENCRYPTO::BitVector<>>>>;
  std::unordered_map<std::size_t, keys_t> input_public_keys_;

  using g_rows_t =
      std::pair<std::size_t, boost::fibers::promise<std::unique_ptr<ENCRYPTO::BitVector<>>>>;
  std::unordered_map<std::size_t, g_rows_t> garbled_rows_;
};

}  // namespace MOTION
