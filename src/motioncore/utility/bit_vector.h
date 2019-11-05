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

#include <cstddef>
#include <iostream>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include <fmt/format.h>
#include <boost/align/aligned_allocator.hpp>

#include "helpers.h"

namespace ENCRYPTO {
constexpr std::byte SET_BIT_MASK[] = {
    std::byte(0b10000000), std::byte(0b01000000), std::byte(0b00100000), std::byte(0b00010000),
    std::byte(0b00001000), std::byte(0b00000100), std::byte(0b00000010), std::byte(0b00000001)};

constexpr std::byte UNSET_BIT_MASK[] = {
    std::byte(0b01111111), std::byte(0b10111111), std::byte(0b11011111), std::byte(0b11101111),
    std::byte(0b11110111), std::byte(0b11111011), std::byte(0b11111101), std::byte(0b11111110)};

constexpr std::byte TRUNCATION_BIT_MASK[] = {
    std::byte(0b10000000), std::byte(0b11000000), std::byte(0b11100000), std::byte(0b111110000),
    std::byte(0b11111000), std::byte(0b11111100), std::byte(0b11111110), std::byte(0b11111111)};

template <typename Allocator = std::allocator<std::byte>>
class BitVector {
 public:
  BitVector() noexcept : bit_size_(0){};

  explicit BitVector(bool value) noexcept : bit_size_(0) { Append(value); }

  BitVector(BitVector&& bv) noexcept
      : data_vector_(std::move(bv.data_vector_)), bit_size_(bv.bit_size_) {}

  BitVector(const BitVector& bv) noexcept
      : data_vector_(bv.data_vector_.begin(), bv.data_vector_.end()), bit_size_(bv.bit_size_) {}

  BitVector(const std::vector<bool>& data) : BitVector(data, data.size()) {}

  explicit BitVector(uint n_bits, bool value = false)
      : BitVector(static_cast<std::size_t>(n_bits), value) {}

  explicit BitVector(int n_bits, bool value = false)
      : BitVector(static_cast<std::size_t>(n_bits), value) {}

  explicit BitVector(long n_bits, bool value = false)
      : BitVector(static_cast<std::size_t>(n_bits), value) {}

  explicit BitVector(long long n_bits, bool value = false)
      : BitVector(static_cast<std::size_t>(n_bits), value) {}

  explicit BitVector(long long unsigned int n_bits, bool value = false)
      : BitVector(static_cast<std::size_t>(n_bits), value) {}

  explicit BitVector(std::size_t n_bits, bool value = false) noexcept;

  BitVector(const unsigned char* buf, std::size_t bits)
      : BitVector(reinterpret_cast<const std::byte*>(buf), bits) {}

  BitVector(const std::byte* buf, std::size_t bits);

  BitVector(const std::vector<std::byte>& data, std::size_t n_bits);

  BitVector(std::vector<std::byte>&& data, std::size_t n_bits);

  BitVector(const std::vector<bool>& data, std::size_t n_bits);

  bool Empty() { return bit_size_ == 0; }

  /// \brief In-place bit-wise invert
  void Invert();

  BitVector operator~() const;

  template <typename Allocator2>
  bool operator!=(const BitVector<Allocator2>& other) const noexcept;

  template <typename Allocator2>
  BitVector operator&(const BitVector<Allocator2>& other) const noexcept;

  template <typename Allocator2>
  BitVector operator^(const BitVector<Allocator2>& other) const noexcept;

  template <typename Allocator2>
  BitVector operator|(const BitVector<Allocator2>& other) const noexcept;

  bool operator[](std::size_t pos) const { return Get(pos); }

  auto GetSize() const noexcept { return bit_size_; }

  const auto& GetData() const noexcept { return data_vector_; }

  auto& GetMutableData() noexcept { return data_vector_; }

  void Assign(const BitVector& other) noexcept { *this = other; }

  void Assign(BitVector&& other) noexcept { *this = std::move(other); }

  BitVector<Allocator>& operator=(const BitVector<Allocator>& other) noexcept;

  BitVector<Allocator>& operator=(BitVector<Allocator>&& other) noexcept;

  template <typename Allocator2>
  bool operator==(const BitVector<Allocator2>& other) const noexcept;

  void Set(bool value) noexcept;

  void Set(bool value, std::size_t pos);

  bool Get(std::size_t pos) const;

  template <typename Allocator2>
  BitVector& operator&=(const BitVector<Allocator2>& other) noexcept;

  template <typename Allocator2>
  BitVector& operator^=(const BitVector<Allocator2>& other) noexcept;

  template <typename Allocator2>
  BitVector& operator|=(const BitVector<Allocator2>& other) noexcept;

  void Resize(std::size_t n_bits, bool zero_fill = false) noexcept;

  void Append(bool bit) noexcept;

  void Append(const BitVector<Allocator>& other) noexcept;

  void Append(BitVector&& other) noexcept;

  void Copy(const std::size_t dest_from, const std::size_t dest_to, const BitVector& other);

  void Copy(const std::size_t dest_from, const BitVector& other);

  BitVector Subset(std::size_t from, std::size_t to) const;

  std::string AsString() const noexcept;

  void Clear() noexcept;

  static BitVector Random(std::size_t size) noexcept;

  static bool ANDReduceBitVector(const BitVector& vector);

  static BitVector ANDBitVectors(const std::vector<BitVector>& vectors);

  static bool ORReduceBitVector(const BitVector& vector);

  static BitVector ORBitVectors(const std::vector<BitVector>& vectors);

  static std::vector<BitVector> ANDBitVectors(const std::vector<BitVector>& a,
                                              const std::vector<BitVector>& b);

  static std::vector<BitVector> ANDBitVectors(const std::vector<std::vector<BitVector>>& vectors);

  static bool XORReduceBitVector(const BitVector& vector);

  static BitVector XORBitVectors(const std::vector<BitVector>& vectors);

  static std::vector<BitVector> XORBitVectors(const std::vector<BitVector>& a,
                                              const std::vector<BitVector>& b);

  static std::vector<BitVector> XORBitVectors(const std::vector<std::vector<BitVector>>& vectors);

  static bool EqualSizeDimensions(const std::vector<BitVector>& v);

 private:
  std::vector<std::byte, Allocator> data_vector_;

  std::size_t bit_size_;

  void TruncateToFit() noexcept;
};

// Input functions that convert inputs of integer and floating point types to vectors of
// BitVectors, which are a suitable input to MOTION

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>,
          typename Allocator = std::allocator<std::byte>>
std::vector<BitVector<Allocator>> ToInput(T t);

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>,
          typename Allocator = std::allocator<std::byte>>
std::vector<BitVector<Allocator>> ToInput(const std::vector<T>& in_v);

template <typename T, std::enable_if_t<std::is_floating_point_v<T>>,
          typename Allocator = std::allocator<std::byte>>
std::vector<BitVector<Allocator>> ToInput(T t);

template <typename T, std::enable_if_t<std::is_floating_point_v<T>>,
          typename Allocator = std::allocator<std::byte>>
std::vector<BitVector<Allocator>> ToInput(const std::vector<T>& t);

// Output functions for converting vectors of BitVectors to vectors of floating point or
// integer numbers

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>,
          typename Allocator = std::allocator<std::byte>>
T ToOutput(std::vector<BitVector<Allocator>> v) {
  static_assert(std::is_integral<T>::value);
  static_assert(sizeof(T) <= 8);
  if constexpr (sizeof(T) == 1) {
    static_assert(std::is_same_v<T, std::uint8_t>);
  } else if constexpr (sizeof(T) == 2) {
    static_assert(std::is_same_v<T, std::uint16_t>);
  } else if constexpr (sizeof(T) == 4) {
    static_assert(std::is_same_v<T, std::uint32_t>);
  } else if constexpr (sizeof(T) == 8) {
    static_assert(std::is_same_v<T, std::uint64_t>);
  }

  assert(!v.empty());
  if ((sizeof(T) * 8) != v.size()) {
    throw std::runtime_error(fmt::format(
        "Trying to convert to different bitlength: is {}, expected {}", v.size(), (sizeof(T) * 8)));
  }
  const auto n_simd{v.at(0).GetSize()};
  assert(n_simd > 0u);
  for ([[maybe_unused]] auto i = 0ull; i < v.size(); ++i) assert(v.at(i).GetSize() == n_simd);
  constexpr auto bitlen{sizeof(T) * 8};
  T t{0};
  for (auto i = 0ull; i < bitlen; ++i) {
    assert(v.at(i).GetSize() == 1);
    t += static_cast<T>(v.at(i)[0]) << i;
  }
  return t;
}

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>,
          typename Allocator = std::allocator<std::byte>>
std::vector<T> ToVectorOutput(std::vector<BitVector<Allocator>> v) {
  static_assert(std::is_integral<T>::value);
  static_assert(sizeof(T) <= 8);
  if constexpr (sizeof(T) == 1) {
    static_assert(std::is_same_v<T, std::uint8_t>);
  } else if constexpr (sizeof(T) == 2) {
    static_assert(std::is_same_v<T, std::uint16_t>);
  } else if constexpr (sizeof(T) == 4) {
    static_assert(std::is_same_v<T, std::uint32_t>);
  } else if constexpr (sizeof(T) == 8) {
    static_assert(std::is_same_v<T, std::uint64_t>);
  }

  assert(!v.empty());
  if ((sizeof(T) * 8) != v.size()) {
    throw std::runtime_error(fmt::format(
        "Trying to convert to different bitlength: is {}, expected {}", v.size(), (sizeof(T) * 8)));
  }
  const auto n_simd{v.at(0).GetSize()};
  assert(n_simd > 0u);
  for ([[maybe_unused]] auto i = 0ull; i < v.size(); ++i) assert(v.at(i).GetSize() == n_simd);

  constexpr auto bitlen{sizeof(T) * 8};
  std::vector<T> v_t;
  for (auto i = 0ull; i < n_simd; ++i) {
    T t{0};
    for (auto j = 0ull; j < bitlen; ++j) {
      t += static_cast<T>(v.at(j)[i]) << j;
    }
    v_t.emplace_back(t);
  }
  return v_t;
}

using AlignedBitVector = BitVector<boost::alignment::aligned_allocator<std::byte, 16>>;
}