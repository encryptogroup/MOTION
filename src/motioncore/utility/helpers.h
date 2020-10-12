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

#include <flatbuffers/flatbuffers.h>
#include <fmt/format.h>
#include <random>

#include "condition.h"
#include "primitives/random/aes128_ctr_rng.h"
#include "typedefs.h"

namespace encrypto::motion {

template <typename UnsignedIntegralType,
          typename = std::enable_if_t<std::is_unsigned_v<UnsignedIntegralType>>>
std::vector<UnsignedIntegralType> RandomVector(std::size_t length) {
  auto& rng = Aes128CtrRng::GetThreadInstance();
  const auto byte_size = sizeof(UnsignedIntegralType) * length;
  std::vector<UnsignedIntegralType> vec(length);
  rng.RandomBytes(reinterpret_cast<std::byte*>(vec.data()), byte_size);
  return vec;
}

template <typename UnsignedIntegralType,
          typename = std::enable_if_t<std::is_unsigned_v<UnsignedIntegralType>>>
inline std::vector<std::uint8_t> ToByteVector(const std::vector<UnsignedIntegralType>& values) {
  std::vector<std::uint8_t> result(reinterpret_cast<const std::uint8_t*>(values.data()),
                                   reinterpret_cast<const std::uint8_t*>(values.data()) +
                                       sizeof(UnsignedIntegralType) * values.size());
  return result;
}

template <typename UnsignedIntegralType,
          typename = std::enable_if_t<std::is_unsigned_v<UnsignedIntegralType>>>
inline std::vector<UnsignedIntegralType> FromByteVector(const std::vector<std::uint8_t>& buffer) {
  assert(buffer.size() % sizeof(UnsignedIntegralType) ==
         0);  // buffer length is multiple of the element size
  std::vector<UnsignedIntegralType> result(sizeof(UnsignedIntegralType) * buffer.size());
  std::copy(buffer.data(), buffer.data() + buffer.size(),
            reinterpret_cast<std::uint8_t*>(result.data()));
  return result;
}

template <typename UnsignedIntegralType,
          typename = std::enable_if_t<std::is_unsigned_v<UnsignedIntegralType>>>
inline std::vector<UnsignedIntegralType> FromByteVector(
    const flatbuffers::Vector<std::uint8_t>& buffer) {
  assert(buffer.size() % sizeof(UnsignedIntegralType) ==
         0);  // buffer length is multiple of the element size
  std::vector<UnsignedIntegralType> result(buffer.size() / sizeof(UnsignedIntegralType));
  std::copy(buffer.data(), buffer.data() + buffer.size(),
            reinterpret_cast<std::uint8_t*>(result.data()));
  return result;
}

template <typename T>
inline std::vector<T> AddVectors(std::vector<std::vector<T>>& vectors) {
  if (vectors.size() == 0) {
    return {};
  }  // if empty input vector

  std::vector<T> result = vectors.at(0);

  for (auto i = 1ull; i < vectors.size(); ++i) {
    auto& inner_vector = vectors.at(i);
    assert(inner_vector.size() == result.size());  // expect the vectors to be of the same size
    for (auto j = 0ull; j < result.size(); ++j) {
      result.at(j) += inner_vector.at(j);  // TODO: implement using AVX2 and AVX512
    }
  }
  return result;
}

template <typename T>
inline std::vector<T> AddVectors(std::vector<std::vector<T>>&& vectors) {
  return AddVectors(vectors);
}

template <typename T>
inline std::vector<T> AddVectors(const std::vector<T>& a, const std::vector<T>& b) {
  assert(a.size() == b.size());
  if (a.size() == 0) {
    return {};
  }  // if empty input vector
  std::vector<T> result = a;
#pragma omp simd
  for (auto j = 0ull; j < result.size(); ++j) {
    result.at(j) += b.at(j);  // TODO: implement using AVX2 and AVX512
  }
  return result;
}

template <typename T>
inline std::vector<T> RestrictAddVectors(const std::vector<T>& a, const std::vector<T>& b) {
  assert(a.size() == b.size());
  if (a.size() == 0) {
    return {};
  }  // if empty input vector
  std::vector<T> result(a.size());
  const T* __restrict__ a_pointer{a.data()};
  const T* __restrict__ b_pointer{b.data()};
  T* __restrict__ result_pointer{result.data()};
  std::transform(a_pointer, a_pointer + a.size(), b_pointer, result_pointer,
                 [](const T& a_value, const T& b_value) { return a_value + b_value; });
  return result;
}

template <typename T>
inline std::vector<T> RestrictMulVectors(const std::vector<T>& a, const std::vector<T>& b) {
  assert(a.size() == b.size());
  if (a.size() == 0) {
    return {};
  }  // if empty input vector
  std::vector<T> result(a.size());
  const T* __restrict__ a_pointer{a.data()};
  const T* __restrict__ b_pointer{b.data()};
  T* __restrict__ result_pointer{result.data()};
  std::transform(a_pointer, a_pointer + a.size(), b_pointer, result_pointer,
                 [](const T& a_value, const T& b_value) { return a_value * b_value; });
  return result;
}

template <typename T>
inline std::vector<T> RestrictSubVectors(const std::vector<T>& a, const std::vector<T>& b) {
  assert(a.size() == b.size());
  if (a.size() == 0) {
    return {};
  }  // if empty input vector
  std::vector<T> result(a.size());
  const T* __restrict__ a_pointer{a.data()};
  const T* __restrict__ b_pointer{b.data()};
  T* __restrict__ result_pointer{result.data()};
  std::transform(a_pointer, a_pointer + a.size(), b_pointer, result_pointer,
                 [](const T& a_value, const T& b_value) { return a_value - b_value; });
  return result;
}

template <typename T>
inline std::vector<T> SubVectors(const std::vector<T>& a, const std::vector<T>& b) {
  assert(a.size() == b.size());
  if (a.size() == 0) {
    return {};
  }  // if empty input vector
  std::vector<T> result = a;
  for (auto j = 0ull; j < result.size(); ++j) {
    result.at(j) -= b.at(j);  // TODO: implement using AVX2 and AVX512
  }
  return result;
}

template <typename T>
inline T SumReduction(const std::vector<T>& values) {
  if (values.size() == 0) {
    return 0;
  } else if (values.size() == 1) {
    return values.at(0);
  } else {
    T sum = 0;
#pragma omp parallel for reduction(+ : sum) default(none) shared(values)
    for (auto i = 0ull; i < values.size(); ++i) {
      sum += values.at(i);
    }
    return sum;
  }
}

template <typename T>
inline T SubReduction(const std::vector<T>& values) {
  if (values.size() == 0) {
    return 0;
  } else {
    T result = values.at(0);
    for (auto i = 1ull; i < values.size(); ++i) {
      result -= values.at(i);
    }
    return result;
  }
}

// +---------+-----------------------------------------+
// | sum_0 = | values_00 + values_01 + ... + values_0m |
// |  ...    | ....................................... |
// | sum_n = | values_n0 + values_n1 + ... + values_nm |
// +---------+-----------------------------------------+

template <typename T>
inline std::vector<T> RowSumReduction(const std::vector<std::vector<T>>& values) {
  if (values.size() == 0) {
    return {};
  } else {
    std::vector<T> sum(values.at(0).size());
    for (auto i = 1ull; i < values.size(); ++i) {
      assert(values.at(0).size() == values.at(i).size());
    }

    for (auto i = 0ull; i < sum.size(); ++i) {
      for (auto j = 0ull; j < values.size(); ++j) {
        sum.at(i) += values.at(j).at(i);
      }
    }
    return std::move(sum);
  }
}

template <typename T>
inline std::vector<T> RowSubReduction(const std::vector<std::vector<T>>& values) {
  if (values.size() == 0) {
    return {};
  } else {
    std::vector<T> result = values.at(0);
    for (auto i = 1ull; i < values.size(); ++i) {
      assert(values.at(0).size() == values.at(i).size());
    }

    for (auto i = 0ull; i < result.size(); ++i) {
      for (auto j = 1ull; j < values.size(); ++j) {
        result.at(i) -= values.at(j).at(i);
      }
    }
    return std::move(result);
  }
}

template <typename T>
inline std::vector<T> MultiplyVectors(std::vector<T> a, std::vector<T> b) {
  assert(a.size() == b.size());
  if (a.size() == 0) {
    return {};
  }  // if empty input vector
  std::vector<T> result = a;

  for (auto j = 0ull; j < result.size(); ++j) {
    result.at(j) *= b.at(j);  // TODO: implement using AVX2 and AVX512
  }
  return result;
}

template <typename T>
inline std::vector<T> RowMulReduction(const std::vector<std::vector<T>>& values) {
  if (values.size() == 0) {
    return {};
  } else {
    std::vector<T> product(values.at(0).size(), 1);
    for (auto i = 1ull; i < values.size(); ++i) {
      assert(values.at(0).size() == values.at(i).size());
    }

    for (auto i = 0ull; i < product.size(); ++i) {
      for (auto j = 0ull; j < values.size(); ++j) {
        product.at(i) *= values.at(j).at(i);
      }
    }
    return std::move(product);
  }
}

template <typename T>
inline T RowMulReduction(const std::vector<T>& values) {
  if (values.size() == 0) {
    return 0;
  } else {
    T product = values.at(0);
    for (auto i = 1ull; i < values.size(); ++i) {
      product *= values.at(i);
    }
    return product;
  }
}

template <typename UnsignedIntegralType,
          typename = std::enable_if_t<std::is_unsigned_v<UnsignedIntegralType>>>
bool IsPowerOfTwo(UnsignedIntegralType x) {
  return x > 0 && (!(x & (x - 1)));
}

inline std::string Hex(const std::uint8_t* values, std::size_t n) {
  std::string buffer;
  for (auto i = 0ull; i < n; ++i) {
    buffer.append(fmt::format("{0:#x} ", values[i]));
  }
  buffer.erase(buffer.end() - 1);  // remove the last whitespace
  return buffer;
}

inline std::string Hex(const std::byte* values, std::size_t n) {
  return Hex(reinterpret_cast<const std::uint8_t*>(values), n);
}

template <std::size_t N>
inline std::string Hex(const std::array<std::byte, N>& values) {
  return Hex(reinterpret_cast<const std::uint8_t*>(values.data()), values.size());
}

template <std::size_t N>
inline std::string Hex(const std::array<std::uint8_t, N>& values) {
  return Hex(values.data(), values.size());
}

inline std::string Hex(const std::vector<std::uint8_t>& values) {
  return Hex(values.data(), values.size());
}

inline std::string Hex(const std::vector<std::byte>& values) {
  return Hex(values.data(), values.size());
}

inline std::string Hex(const std::vector<std::uint8_t>&& values) { return Hex(values); }

template <typename T>
inline std::string to_string(std::vector<T> values) {
  using std::to_string;
  std::string result;
  for (auto& v : values) {
    result.append(to_string(v) + " ");
  }
  return result;
}

template <typename T>
inline bool Vectors(const std::vector<T>& a, const std::vector<T>& b) {
  if (a.size() != b.size()) {
    return false;
  }
  for (auto i = 0ull; i < a.size(); ++i) {
    if (a.at(i) != b.at(i)) {
      return false;
    }
  }
  return true;
}

template <typename T>
inline bool Dimensions(const std::vector<std::vector<T>>& values) {
  if (values.size() <= 1) {
    return true;
  } else {
    auto first_size = values.at(0).size();
    for (auto i = 1ull; i < values.size(); ++i) {
      if (first_size != values.at(i).size()) {
        return false;
      }
    }
  }
  return true;
}

std::size_t DivideAndCeil(std::size_t dividend, std::size_t divisor);

inline std::size_t BitsToBytes(const std::size_t bits) { return (bits + 7) / 8; }

}  // namespace encrypto::motion
