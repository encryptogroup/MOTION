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

#include "block.h"
#include <algorithm>
#include <boost/algorithm/hex.hpp>
#include <cassert>
#include "primitives/random/aes128_ctr_rng.h"

namespace encrypto::motion {

void Block128::SetToRandom() {
  auto& rng = Aes128CtrRng::GetThreadInstance();
  rng.RandomBlocksAligned(byte_array.data(), 1);
}

std::string Block128::AsString() const {
  std::string result;
  result.reserve(2 * sizeof(byte_array));
  boost::algorithm::hex(
      reinterpret_cast<const std::uint8_t*>(byte_array.data()),
      reinterpret_cast<const std::uint8_t*>(byte_array.data() + sizeof(byte_array)),
      std::back_inserter(result));
  return result;
}

void Block128Vector::SetToRandom() {
  auto& rng = Aes128CtrRng::GetThreadInstance();
  rng.RandomBlocksAligned(reinterpret_cast<std::byte*>(block_vector.data()), block_vector.size());
}

}  // namespace encrypto::motion
