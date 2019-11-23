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

#include <algorithm>
#include <boost/algorithm/hex.hpp>
#include <cassert>
#include "block.h"
#include "crypto/random/aes128_ctr_rng.h"

namespace ENCRYPTO {

void block128_t::set_to_random() {
  auto& rng = AES128_CTR_RNG::get_thread_instance();
  rng.random_blocks_aligned(byte_array.data(), 1);
}

std::string block128_t::as_string() const {
  std::string result;
  result.reserve(2 * sizeof(byte_array));
  boost::algorithm::hex(
      reinterpret_cast<const std::uint8_t*>(byte_array.data()),
      reinterpret_cast<const std::uint8_t*>(byte_array.data() + sizeof(byte_array)),
      std::back_inserter(result));
  return result;
}

}  // namespace ENCRYPTO
