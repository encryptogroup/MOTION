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

#include "config.h"
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

class BitSpan;

using std_alloc = std::allocator<std::byte>;
using aligned_alloc = boost::alignment::aligned_allocator<std::byte, MOTION::MOTION_ALIGNMENT>;

template <typename Allocator = std::allocator<std::byte>>
class BitVector {
  template <typename Allocator2>
  friend class BitVector;

 public:
  // Default constructor, results in an empty vector
  BitVector() noexcept : bit_size_(0){};

  // Initialized with a single bit
  explicit BitVector(bool value) noexcept
      : data_vector_{value ? SET_BIT_MASK[0] : std::byte(0x00)}, bit_size_(1) {}

  // Move constructor
  BitVector(BitVector&& bv) noexcept
      : data_vector_(std::move(bv.data_vector_)), bit_size_(bv.bit_size_) {}

  // Copy constructor
  BitVector(const BitVector& bv) noexcept
      : data_vector_(bv.data_vector_), bit_size_(bv.bit_size_) {}

  // Copy constructor from BitVector with different allocator
  template <typename Allocator2>
  BitVector(const BitVector<Allocator2>& bv) noexcept
      : data_vector_(bv.data_vector_.cbegin(), bv.data_vector_.cend()), bit_size_(bv.bit_size_) {}

  // Initialize from a std::vector<bool>, inefficient!
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

  // Initialize with given length and value
  explicit BitVector(std::size_t n_bits, bool value = false) noexcept;

  // Initialize from pointer + size
  BitVector(const unsigned char* buf, std::size_t bits)
      : BitVector(reinterpret_cast<const std::byte*>(buf), bits) {}

  // Initialize from pointer + size
  BitVector(const std::byte* buf, std::size_t bits);

  // Initialize from std::vector content, performs length check
  template <typename Allocator2>
  explicit BitVector(const std::vector<std::byte, Allocator2>& data, std::size_t n_bits);

  // Initialize from std::vector rvalue (requires same allocator), performs length check
  explicit BitVector(std::vector<std::byte, Allocator>&& data, std::size_t n_bits);

  // Initialize from a std::vector<bool>, inefficient!
  explicit BitVector(const std::vector<bool>& data, std::size_t n_bits);

  bool Empty() { return bit_size_ == 0; }

  /// \brief In-place bit-wise invert
  void Invert();

  constexpr bool IsAligned() const noexcept { return std::is_same_v<Allocator, aligned_alloc>; }

  BitVector operator~() const;

  template <typename Allocator2>
  bool operator!=(const BitVector<Allocator2>& other) const noexcept;

  bool operator!=(const BitSpan& bvv) const noexcept;

  template <typename Allocator2>
  BitVector operator&(const BitVector<Allocator2>& other) const noexcept;

  BitVector operator&(const BitSpan& bvv) const noexcept;

  template <typename Allocator2>
  BitVector operator^(const BitVector<Allocator2>& other) const noexcept;

  BitVector operator^(const BitSpan& bvv) const noexcept;

  template <typename Allocator2>
  BitVector operator|(const BitVector<Allocator2>& other) const noexcept;

  BitVector operator|(const BitSpan& bvv) const noexcept;

  bool operator[](std::size_t pos) const { return Get(pos); }

  auto GetSize() const noexcept { return bit_size_; }

  const auto& GetData() const noexcept { return data_vector_; }

  auto& GetMutableData() noexcept { return data_vector_; }

  void Assign(const BitVector& other) noexcept { *this = other; }

  void Assign(BitVector&& other) noexcept { *this = std::move(other); }

  BitVector<Allocator>& operator=(const BitVector<Allocator>& other) noexcept;

  BitVector<Allocator>& operator=(BitVector<Allocator>&& other) noexcept;

  template <typename Allocator2>
  BitVector<Allocator>& operator=(const BitVector<Allocator2>& other) noexcept;

  template <typename Allocator2>
  bool operator==(const BitVector<Allocator2>& other) const noexcept;

  bool operator==(const BitSpan& other) const noexcept;

  void Set(bool value) noexcept;

  void Set(bool value, std::size_t pos);

  bool Get(std::size_t pos) const;

  template <typename Allocator2>
  BitVector& operator&=(const BitVector<Allocator2>& other) noexcept;

  BitVector& operator&=(const BitSpan& other) noexcept;

  template <typename Allocator2>
  BitVector& operator^=(const BitVector<Allocator2>& other) noexcept;

  BitVector& operator^=(const BitSpan& other) noexcept;

  template <typename Allocator2>
  BitVector& operator|=(const BitVector<Allocator2>& other) noexcept;

  BitVector& operator|=(const BitSpan& other) noexcept;

  void Resize(std::size_t num_bits, bool zero_fill = false) noexcept;

  void Reserve(std::size_t num_bytes) { data_vector_.reserve(num_bytes); }

  void Append(bool bit) noexcept;

  void Append(const BitVector<Allocator>& other) noexcept;

  void Append(BitVector&& other) noexcept;

  void Append(const BitSpan& bs);

  void Append(BitSpan&& bs);

  void Append(const std::byte* ptr, const std::size_t append_bit_size) noexcept;

  void Copy(const std::size_t dest_from, const std::size_t dest_to, const BitVector& other);

  void Copy(const std::size_t dest_from, const BitVector& other);

  BitVector Subset(std::size_t from, std::size_t to) const;

  std::string AsString() const noexcept;

  void Clear() noexcept;

  static BitVector Random(const std::size_t size) noexcept;

  static BitVector RandomSeeded(const std::size_t size, const std::size_t seed = 0) noexcept;

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

  void BoundsCheckEquality([[maybe_unused]] const std::size_t bit_size) const;

  void BoundsCheckInRange([[maybe_unused]] const std::size_t bit_size) const;
};

template <typename Allocator>
std::ostream& operator<<(std::ostream& os, const BitVector<Allocator>& bar) {
  return os << bar.AsString();
}

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

using AlignedBitVector = BitVector<aligned_alloc>;

/// \brief provides a read-write BitVector API over a raw buffer, e.g., std::byte *.
/// The underlying buffer is not owned by the BitSpan, in contrast to BitVector.
/// Assumes that the buffer starts at leftmost bit of the underlying buffer.
/// Alternatively, non-owning non-resizeable BitVector

class BitSpan {
 public:
  BitSpan() = default;

  ~BitSpan() = default;

  BitSpan(std::byte* ptr, std::size_t bit_size, bool aligned = false);

  template <typename T>
  BitSpan(T* ptr, std::size_t bit_size, bool aligned = false);

  BitSpan(const BitSpan& other);

  BitSpan(BitSpan&& other);

  template <typename BitVectorT>
  BitSpan(BitVectorT& bv)
      : ptr_(bv.GetMutableData().data()), bit_size_(bv.GetSize()), aligned_(bv.IsAligned()) {}

  BitSpan& operator=(const BitSpan& other);

  BitSpan& operator=(BitSpan&& other);

  template <typename BitVectorT>
  BitSpan& operator=(BitVectorT& bv) {
    ptr_ = bv.GetMutableData().data();
    bit_size_ = bv.GetSize();
    aligned_ = bv.IsAligned();
    return *this;
  }

  template <typename BitVectorT = AlignedBitVector>
  BitVectorT As() const {
    return BitVectorT(ptr_, bit_size_);
  }

  template <typename BitVectorT = AlignedBitVector>
  BitVectorT Subset(const std::size_t from, const std::size_t to) const;

  bool Empty() const noexcept { return bit_size_; }

  void Invert();

  template <typename BitVectorT = AlignedBitVector>
  BitVectorT operator~() const {
    BitVectorT result(ptr_, bit_size_);
    result.Invert();
    return result;
  }

  template <typename BitVectorT = AlignedBitVector>
  bool operator==(const BitVectorT& bv) const;

  bool operator==(const BitSpan& bvv) const;

  template <typename BitVectorT = AlignedBitVector>
  BitVectorT operator&(const BitVectorT& bv) const;

  template <typename BitVectorT = AlignedBitVector>
  BitVectorT operator&(const BitSpan& bvv) const;

  template <typename BitVectorT = AlignedBitVector>
  BitVectorT operator|(const BitVectorT& bv) const;

  template <typename BitVectorT = AlignedBitVector>
  BitVectorT operator|(const BitSpan& bvv) const;

  template <typename BitVectorT = AlignedBitVector>
  BitVectorT operator^(const BitVectorT& bv) const;

  template <typename BitVectorT = AlignedBitVector>
  BitVectorT operator^(const BitSpan& bvv) const;

  template <typename BitVectorT = AlignedBitVector>
  BitSpan& operator&=(const BitVectorT& bv);

  BitSpan& operator&=(const BitSpan& bvv);

  template <typename BitVectorT = AlignedBitVector>
  BitSpan& operator|=(const BitVectorT& bv);

  BitSpan& operator|=(const BitSpan& bvv);

  template <typename BitVectorT = AlignedBitVector>
  BitSpan& operator^=(const BitVectorT& bv);

  BitSpan& operator^=(const BitSpan& bvv);

  bool Get(const std::size_t pos) const;

  bool operator[](const std::size_t pos) const { return Get(pos); }

  void Set(const bool value);

  void Set(const bool value, const std::size_t pos);

  const std::byte* GetData() const noexcept { return ptr_; }

  std::byte* GetMutableData() noexcept { return ptr_; }

  std::size_t GetSize() const noexcept { return bit_size_; }

  std::string AsString() const noexcept;

  bool IsAligned() const noexcept { return aligned_; }

  template <typename BitVectorT>
  void Copy(const std::size_t dest_from, const std::size_t dest_to, BitVectorT& other);

  template <typename BitVectorT>
  void Copy(const std::size_t dest_from, BitVectorT& other);

  void Copy(const std::size_t dest_from, const std::size_t dest_to, BitSpan& other);

  void Copy(const std::size_t dest_from, const std::size_t dest_to, BitSpan&& other);

  void Copy(const std::size_t dest_from, BitSpan& other);

  void Copy(const std::size_t dest_from, BitSpan&& other);

 private:
  std::byte* ptr_;
  std::size_t bit_size_;
  bool aligned_;
};

std::ostream& operator<<(std::ostream& os, const BitSpan& bar);
}  // namespace ENCRYPTO
