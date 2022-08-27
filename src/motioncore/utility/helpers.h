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
#include <algorithm>
#include <bit>
#include <cassert>
#include <concepts>
#include <cstdint>
#include <random>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

#include "condition.h"
#include "primitives/random/default_rng.h"
#include "typedefs.h"

namespace encrypto::motion {

/// \brief Returns a vector of \p length random unsigned integral values.
/// \tparam UnsignedIntegralType
/// \param length
template <typename UnsignedIntegralType>
std::vector<UnsignedIntegralType> RandomVector(std::size_t length);

/// \brief Converts a vector of unsigned integral values to a vector of uint8_t
/// \tparam UnsignedIntegralType
/// \param values
template <typename UnsignedIntegralType,
          typename = std::enable_if_t<std::is_unsigned_v<UnsignedIntegralType>>>
inline std::vector<std::uint8_t> ToByteVector(std::span<const UnsignedIntegralType> values) {
  std::vector<std::uint8_t> result(reinterpret_cast<const std::uint8_t*>(values.data()),
                                   reinterpret_cast<const std::uint8_t*>(values.data()) +
                                       sizeof(UnsignedIntegralType) * values.size());
  return result;
}

/// \brief Converts a vector of uint8_t to a vector of unsigned integral values
/// \tparam UnsignedIntegralType
/// \param buffer
template <typename UnsignedIntegralType,
          typename = std::enable_if_t<std::is_unsigned_v<UnsignedIntegralType>>>
inline std::vector<UnsignedIntegralType> FromByteVector(std::span<const std::uint8_t> buffer) {
  assert(buffer.size() % sizeof(UnsignedIntegralType) ==
         0);  // buffer length is multiple of the element size
  std::vector<UnsignedIntegralType> result(buffer.size() / sizeof(UnsignedIntegralType));
  std::copy(buffer.data(), buffer.data() + buffer.size(),
            reinterpret_cast<std::uint8_t*>(result.data()));
  return result;
}

/// \brief Adds each element in \p a and \p b and returns the result.
/// \tparam T type of the elements in the vectors. T must provide the += operator.
/// \param a
/// \param b
/// \return A vector containing at position i the sum the ith element in a and b.
/// \pre \p a and \p b must be of equal size.
template <typename T>
inline std::vector<T> AddVectors(std::span<const T> a, std::span<const T> b) {
  assert(a.size() == b.size());
  if (a.size() == 0) {
    return {};
  }  // if empty input vector
  std::vector<T> result(a.begin(), a.end());
#pragma omp simd
  for (auto j = 0ull; j < result.size(); ++j) {
    result[j] += b[j];  // TODO: implement using AVX2 and AVX512
  }
  return result;
}

/// \brief Subtracts each element in \p a and \p b and returns the result.
/// \tparam T type of the elements in the vectors. T must provide the -= operator.
/// \param a
/// \param b
/// \return A vector containing at position i the difference the ith element in a and b.
/// \pre \p a and \p b must be of equal size.
template <typename T>
inline std::vector<T> SubVectors(std::span<const T> a, std::span<const T> b) {
  assert(a.size() == b.size());
  if (a.size() == 0) {
    return {};
  }  // if empty input vector
  std::vector<T> result(a.begin(), a.end());
  for (auto j = 0ull; j < result.size(); ++j) {
    result[j] -= b[j];  // TODO: implement using AVX2 and AVX512
  }
  return result;
}

/// \brief Multiplies each element in \p a and \p b and returns the result.
/// \tparam T type of the elements in the vectors. T must provide the *= operator.
/// \param a
/// \param b
/// \return A vector containing at position i the product the ith element in a and b.
/// \pre \p a and \p b must be of equal size.
template <typename T>
inline std::vector<T> MultiplyVectors(std::span<const T> a, std::span<const T> b) {
  assert(a.size() == b.size());
  if (a.size() == 0) {
    return {};
  }  // if empty input vector
  std::vector<T> result(a.begin(), a.end());

  for (auto j = 0ull; j < result.size(); ++j) {
    result[j] *= b[j];  // TODO: implement using AVX2 and AVX512
  }
  return result;
}

/// \brief Performs the AddVectors operation on an arbitrary number of vectors.
/// \tparam T type of the elements in the vectors. T must provide the += operator.
/// \param vectors A vector of vectors.
/// \return A vector containing at position i the sum of each element
///         at position i of the input vectors.
/// \pre All vectors in \p vectors must be of equal size.
template <typename T>
inline std::vector<T> AddVectors(std::span<const std::vector<T>> vectors) {
  if (vectors.size() == 0) {
    return {};
  }  // if empty input vector

  std::vector<T> result = vectors[0];

  for (auto i = 1ull; i < vectors.size(); ++i) {
    auto& inner_vector = vectors[i];
    assert(inner_vector.size() == result.size());  // expect the vectors to be of the same size
    for (auto j = 0ull; j < result.size(); ++j) {
      result[j] += inner_vector[j];  // TODO: implement using AVX2 and AVX512
    }
  }
  return result;
}

/// \brief Performs the AddVectors operation on an arbitrary number of vectors.
/// \tparam T type of the elements in the vectors. T must provide the += operator.
/// \param vectors A vector of vectors.
/// \return A vector containing at position i the sum of each element
///         at position i of the input vectors.
/// \pre All vectors in \p vectors must be of equal size.
template <typename T>
inline std::vector<T> AddVectors(std::vector<std::vector<T>>&& vectors) {
  return AddVectors<T>(vectors);
}

// XXX two distinct vectors do not overlop, so I don't see the use for the restrict functions.

/// \brief Adds each element in \p a and \p b and returns the result.
///        It is assumed that the vectors do not overlap.
/// \tparam T type of the elements in the vectors. T must provide the binary + operator.
/// \param a
/// \param b
/// \return A vector containing at position i the sum the ith element in a and b.
/// \pre \p a and \p b must be of equal size.
template <typename T>
inline std::vector<T> RestrictAddVectors(std::span<const T> a, std::span<const T> b) {
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

/// \brief Subtracts each element in \p a and \p b and returns the result.
///        It is assumed that the vectors do not overlap.
/// \tparam T type of the elements in the vectors. T must provide the binary - operator.
/// \param a
/// \param b
/// \return A vector containing at position i the difference the ith element in a and b.
/// \pre \p a and \p b must be of equal size.
template <typename T>
inline std::vector<T> RestrictSubVectors(std::span<const T> a, std::span<const T> b) {
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

/// \brief Mulitiplies each element in \p a and \p b and returns the result.
///        It is assumed that the vectors do not overlap.
/// \tparam T type of the elements in the vectors. T must provide the binary * operator.
/// \param a
/// \param b
/// \return A vector containing at position i the product the ith element in a and b.
/// \pre \p a and \p b must be of equal size.
template <typename T>
inline std::vector<T> RestrictMulVectors(std::span<const T> a, std::span<const T> b) {
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

/// \brief Returns the sum of each element in \p values.
/// \tparam T type of the elements in the vectors. T must provide the += operator.
/// \param values
template <typename T>
inline T SumReduction(std::span<const T> values) {
  if (values.size() == 0) {
    return 0;
  } else if (values.size() == 1) {
    return values[0];
  } else {
    T sum = 0;
#pragma omp parallel for reduction(+ : sum) default(none) shared(values)
    for (auto i = 0ull; i < values.size(); ++i) {
      sum += values[i];
    }
    return sum;
  }
}

/// \brief Returns the difference of each element in \p values.
/// \tparam T type of the elements in the vectors. T must provide the -= operator.
/// \param values
template <typename T>
inline T SubReduction(std::span<const T> values) {
  if (values.size() == 0) {
    return 0;
  } else {
    T result = values[0];
    for (auto i = 1ull; i < values.size(); ++i) {
      result -= values[i];
    }
    return result;
  }
}

/// \brief Returns the product of each element in \p values.
/// \tparam T type of the elements in the vectors. T must provide the *= operator.
/// \param values
template <typename T>
inline T MulReduction(std::span<const T> values) {
  if (values.size() == 0) {
    return 0;
  } else {
    T product = values[0];
    for (auto i = 1ull; i < values.size(); ++i) {
      product *= values[i];
    }
    return product;
  }
}

/// \brief Returns the sum of each row in a matrix.
/// \tparam T type of the elements in the vectors. T must provide the += operator.
/// \param values A vector of vectors.
/// \return The resulting vector can be represented by the following graphic:
///         +----------+--------------------------------------------------+
///         | sum[0] = | values[0][0] + values[1][0] + ... + values[m][0] |
///         |  ...     | ................................................ |
///         | sum[n] = | values[0][n] + values[1][n] + ... + values[m][n] |
///         +----------+--------------------------------------------------+
/// \pre All vectors in \p vectors must be of equal size.
template <typename T>
inline std::vector<T> RowSumReduction(std::span<const std::vector<T>> values) {
  if (values.size() == 0) {
    return {};
  } else {
    std::vector<T> sum(values[0].size());
    for (auto i = 1ull; i < values.size(); ++i) {
      assert(values[0].size() == values[i].size());
    }

    for (auto i = 0ull; i < sum.size(); ++i) {
      for (auto j = 0ull; j < values.size(); ++j) {
        sum[i] += values[j][i];
      }
    }
    return std::move(sum);
  }
}

/// \brief Returns the difference of each row in a matrix.
/// \tparam T type of the elements in the vectors. T must provide the -= operator.
/// \param values A vector of vectors.
/// \return The resulting vector can be represented by the following graphic:
///         +-----------+--------------------------------------------------+
///         | diff[0] = | values[0][0] - values[1][0] - ... - values[m][0] |
///         |   ...     | ................................................ |
///         | diff[n] = | values[0][n] - values[1][n] - ... - values[m][n] |
///         +-----------+--------------------------------------------------+
/// \pre All vectors in \p vectors must be of equal size.
template <typename T>
inline std::vector<T> RowSubReduction(std::span<const std::vector<T>> values) {
  if (values.size() == 0) {
    return {};
  } else {
    std::vector<T> result = values[0];
    for (auto i = 1ull; i < values.size(); ++i) {
      assert(values[0].size() == values[i].size());
    }

    for (auto i = 0ull; i < result.size(); ++i) {
      for (auto j = 1ull; j < values.size(); ++j) {
        result[i] -= values[j][i];
      }
    }
    return std::move(result);
  }
}

/// \brief Returns the product of each row in a matrix.
/// \tparam T type of the elements in the vectors. T must provide the *= operator.
/// \param values A vector of vectors.
/// \return The resulting vector can be represented by the following graphic:
///         +-----------+--------------------------------------------------+
///         | prod[0] = | values[0][0] * values[1][0] * ... * values[m][0] |
///         |   ...     | ................................................ |
///         | prod[n] = | values[0][n] * values[1][n] * ... * values[m][n] |
///         +-----------+--------------------------------------------------+
/// \pre All vectors in \p vectors must be of equal size.
template <typename T>
inline std::vector<T> RowMulReduction(std::span<const std::vector<T>> values) {
  if (values.size() == 0) {
    return {};
  } else {
    std::vector<T> product(values[0].size(), 1);
    for (auto i = 1ull; i < values.size(); ++i) {
      assert(values[0].size() == values[i].size());
    }

    for (auto i = 0ull; i < product.size(); ++i) {
      for (auto j = 0ull; j < values.size(); ++j) {
        product[i] *= values[j][i];
      }
    }
    return std::move(product);
  }
}

/// \brief Check if unisgned integral value is a power of two.
/// \tparam UnsignedIntegralType
/// \param x
template <typename UnsignedIntegralType,
          typename = std::enable_if_t<std::is_unsigned_v<UnsignedIntegralType>>>
bool IsPowerOfTwo(UnsignedIntegralType x) {
  return x > 0 && (!(x & (x - 1)));
}

/// \brief Returns a hexadecimal string representation of the bytes stored in \p values
/// \param values
/// \param n Number of bytes.
std::string Hex(const std::uint8_t* values, std::size_t n);

/// \brief Returns a hexadecimal string representation of the bytes stored in \p values
/// \param values
/// \param n Number of bytes.
inline std::string Hex(const std::byte* values, std::size_t n) {
  return Hex(reinterpret_cast<const std::uint8_t*>(values), n);
}

/// \brief Returns a hexadecimal string representation of the bytes stored in \p values
/// \param values
template <std::size_t N>
inline std::string Hex(const std::array<std::byte, N>& values) {
  return Hex(reinterpret_cast<const std::uint8_t*>(values.data()), values.size());
}

/// \brief Returns a hexadecimal string representation of the bytes stored in \p values
/// \param values
template <std::size_t N>
inline std::string Hex(const std::array<std::uint8_t, N>& values) {
  return Hex(values.data(), values.size());
}

/// \brief Returns a hexadecimal string representation of the bytes stored in \p values
/// \param values
inline std::string Hex(const std::vector<std::uint8_t>& values) {
  return Hex(values.data(), values.size());
}

/// \brief Returns a hexadecimal string representation of the bytes stored in \p values
/// \param values
inline std::string Hex(const std::vector<std::byte>& values) {
  return Hex(values.data(), values.size());
}

/// \brief Returns a hexadecimal string representation of the bytes stored in \p values
/// \param values
inline std::string Hex(const std::vector<std::uint8_t>&& values) { return Hex(values); }

/// \brief Returns a string representation of the std::vector \p values
/// \tparam T Type of the element in the std::vector. Must provide an overload of to_string.
/// \param values
template <typename T>
inline std::string to_string(std::vector<T> values) {
  using std::to_string;
  std::string result;
  for (auto& v : values) {
    result.append(to_string(v) + " ");
  }
  return result;
}

/// XXX the std library implements operators for vector comparisions.

template <typename T>
inline bool Vectors(std::span<const T> a, std::span<const T> b) {
  if (a.size() != b.size()) {
    return false;
  }
  for (auto i = 0ull; i < a.size(); ++i) {
    if (a[i] != b[i]) {
      return false;
    }
  }
  return true;
}

/// \brief Checks if all the vectors have the same size.
/// \param values A vector of vectors.
template <typename T>
inline bool Dimensions(std::span<const std::vector<T>> values) {
  if (values.size() <= 1) {
    return true;
  } else {
    auto first_size = values[0].size();
    for (auto i = 1ull; i < values.size(); ++i) {
      if (first_size != values[i].size()) {
        return false;
      }
    }
  }
  return true;
}

/// \brief Divides two size_t and returns the ceiled quotient.
/// \param dividend
/// \param divisor
/// \pre Divisor is not 0.
std::size_t DivideAndCeil(std::size_t dividend, std::size_t divisor);

/// \brief Returns the number of bytes necessary to store \p bits bits.
/// \param bits
constexpr std::size_t BitsToBytes(const std::size_t bits) { return (bits + 7) / 8; }

/// \brief Returns the the dot product of rows of \p a and \p b, i.e., a result vector of size j
/// (number of rows), where result[j] is the sum of all a[i][j] * b[i][j].
template <typename T>
inline T DotProduct(std::span<const T> a, std::span<const T> b) {
  assert(a.size() > 0);
  assert(a.size() == b.size());
  T result = a[0] * b[0];
  for (std::size_t i = 1; i < a.size(); ++i) result += a[i] * b[i];
  return result;
}

/// \brief Returns the the dot product of \p a and \p b, i.e., the sum of all a[i] * b[i].
template <typename T>
inline std::vector<T> RowDotProduct(std::span<const std::vector<T>> a,
                                    std::span<const std::vector<T>> b) {
  assert(a.size() > 0);
  assert(a.size() == b.size());
  std::size_t row_size{a[0].size()};
  std::vector<T> result(row_size, 0);
  for (std::size_t i = 0; i < a.size(); ++i) {
    assert(a[i].size() == b[i].size());
    assert(a[i].size() == row_size);
    for (std::size_t j = 0; j < row_size; ++j) {
      result[j] += a[i][j] * b[i][j];
    }
  }
  return result;
}

template <std::signed_integral T>
auto ToTwosComplement(T input) {
  using U = typename std::make_unsigned_t<T>;
  return std::bit_cast<U>(input);
}

template <std::signed_integral T>
auto ToTwosComplement(const std::vector<T>& input) {
  using U = typename std::make_unsigned_t<T>;
  std::vector<U> twos_complement;
  twos_complement.reserve(input.size());
  for (const auto& x : input) twos_complement.emplace_back(ToTwosComplement<T>(x));
  return twos_complement;
}

template <std::unsigned_integral T>
auto FromTwosComplement(T input) {
  using S = typename std::make_signed_t<T>;
  return std::bit_cast<S>(input);
}

template <std::unsigned_integral T>
auto FromTwosComplement(const std::vector<T>& input) {
  using S = typename std::make_signed_t<T>;
  std::vector<S> result;
  result.reserve(input.size());
  for (const auto& x : input) result.emplace_back(FromTwosComplement<T>(x));
  return result;
}

}  // namespace encrypto::motion
