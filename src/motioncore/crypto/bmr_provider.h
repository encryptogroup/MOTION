// MIT License
//
// Copyright (c) 2020 Lennart Braun
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

#include <memory>
#include <vector>

#include "utility/bit_vector.h"
#include "utility/block.h"
#include "utility/reusable_future.h"

namespace MOTION {

namespace Communication {
class CommunicationLayer;
}

class BMRData;

namespace Crypto {

class BMRProvider {
 public:
  BMRProvider(Communication::CommunicationLayer& communication_layer);
  ~BMRProvider();
  const ENCRYPTO::block128_t& get_global_offset() const { return global_offset_; }
  ENCRYPTO::ReusableFiberFuture<ENCRYPTO::BitVector<>> register_for_input_public_values(
      std::size_t input_owner, std::size_t gate_id, std::size_t bitlen);
  std::vector<ENCRYPTO::ReusableFiberFuture<ENCRYPTO::BitVector<>>>
  register_for_input_public_values(std::size_t gate_id, std::size_t bitlen);
  std::vector<ENCRYPTO::ReusableFiberFuture<ENCRYPTO::block128_vector>> register_for_input_keys(
      std::size_t gate_id, std::size_t num_blocks);
  std::vector<ENCRYPTO::ReusableFiberFuture<ENCRYPTO::block128_vector>> register_for_garbled_rows(
      std::size_t gate_id, std::size_t num_blocks);

 private:
  Communication::CommunicationLayer& communication_layer_;
  std::size_t my_id_;
  std::size_t num_parties_;
  std::vector<std::unique_ptr<BMRData>> data_;
  ENCRYPTO::block128_t global_offset_;
};

}  // namespace Crypto
}  // namespace MOTION
