// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko
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

#include <random>
#include <vector>

#include "utility/typedefs.h"

namespace encrypto::motion {

inline std::vector<std::uint8_t> RandomVector(std::size_t size_in_bytes) {
  std::vector<std::uint8_t> buffer(size_in_bytes);
  std::random_device random_device("/dev/urandom");  // use real randomness to create seeds
  for (auto i = 0u; i < buffer.size();) {
    try {
      // if we can write a std::uint32_t to the buffer directly
      if (i + sizeof(std::uint32_t) <= buffer.size()) {
        auto u32_ptr = reinterpret_cast<std::uint32_t*>(buffer.data());
        u32_ptr[i / sizeof(std::uint32_t)] = random_device();
      } else {  // if we need less bytes than sizeof(std::uint32_t)
        auto r = random_device();
        auto bytes_left = buffer.size() - i;
        assert(bytes_left < sizeof(std::uint32_t));
        std::copy(&r, &r + bytes_left, buffer.data() + i);
      }
      i += sizeof(std::uint32_t);
    } catch (std::exception& e) {
      // could not get enough randomness from random device, try again
    }
  }
  return buffer;
}

}  // namespace encrypto::motion
