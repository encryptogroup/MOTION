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

#include "helpers.h"

#include <fmt/format.h>
#include <chrono>

#include "primitives/random/default_rng.h"

namespace encrypto::motion {
/// \brief Returns a vector of \p length random unsigned integral values.
/// \tparam UnsignedIntegralType
/// \param length
template <typename UnsignedIntegralType>
std::vector<UnsignedIntegralType> RandomVector(std::size_t length) {
  const auto byte_size = sizeof(UnsignedIntegralType) * length;
  std::vector<UnsignedIntegralType> vec(length);

  auto& rng = DefaultRng::GetThreadInstance();
  rng.RandomBytes(reinterpret_cast<std::byte*>(vec.data()), byte_size);

  return vec;
}

template std::vector<std::uint8_t> RandomVector<std::uint8_t>(std::size_t length);
template std::vector<std::uint16_t> RandomVector<std::uint16_t>(std::size_t length);
template std::vector<std::uint32_t> RandomVector<std::uint32_t>(std::size_t length);
template std::vector<std::uint64_t> RandomVector<std::uint64_t>(std::size_t length);
template std::vector<__uint128_t> RandomVector<__uint128_t>(std::size_t length);

std::size_t DivideAndCeil(std::size_t dividend, std::size_t divisor) {
  assert(divisor != 0);
  return 1 + ((dividend - 1) / divisor);
}

std::string Hex(const std::uint8_t* values, std::size_t n) {
  std::string buffer;
  for (auto i = 0ull; i < n; ++i) {
    buffer.append(fmt::format("{0:#x} ", values[i]));
  }
  buffer.erase(buffer.end() - 1);  // remove the last whitespace
  return buffer;
}

}  // namespace encrypto::motion
