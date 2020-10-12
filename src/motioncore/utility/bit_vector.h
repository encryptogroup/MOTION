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

namespace encrypto::motion {

constexpr std::byte kSetBitMask[] = {
    std::byte(0b10000000), std::byte(0b01000000), std::byte(0b00100000), std::byte(0b00010000),
    std::byte(0b00001000), std::byte(0b00000100), std::byte(0b00000010), std::byte(0b00000001)};

constexpr std::byte kUnsetBitMask[] = {
    std::byte(0b01111111), std::byte(0b10111111), std::byte(0b11011111), std::byte(0b11101111),
    std::byte(0b11110111), std::byte(0b11111011), std::byte(0b11111101), std::byte(0b11111110)};

constexpr std::byte TruncationBitMask[] = {
    std::byte(0b10000000), std::byte(0b11000000), std::byte(0b11100000), std::byte(0b111110000),
    std::byte(0b11111000), std::byte(0b11111100), std::byte(0b11111110), std::byte(0b11111111)};

class BitSpan;

using StdAllocator = std::allocator<std::byte>;
using AlignedAllocator = boost::alignment::aligned_allocator<std::byte, kAlignment>;

// The idea behind this class is to be able to interleave multiple arithmetic values
// that are intended to be used in a SIMD way.
// Let x be an arithmetic value, with x0,...,xn being its little-endian bit representation.
// This value is then represented by a value v of type std::vector<BitVector> with v[j][0] == xj
// Now, if we interleave x with y and z of the same bit representation, then:
// v[j][0] == xj, v[j][1] == yj, v[j][2] == zj
template <typename Allocator = std::allocator<std::byte>>
class BitVector {
  template <typename OtherAllocator>
  friend class BitVector;

 public:
  // Default constructor, results in an empty vector
  BitVector() noexcept : bit_size_(0){};

  // Initialized with a single bit
  explicit BitVector(bool value) noexcept
      : data_vector_{value ? kSetBitMask[0] : std::byte(0x00)}, bit_size_(1) {}

  // Move constructor
  BitVector(BitVector&& bit_vector) noexcept
      : data_vector_(std::move(bit_vector.data_vector_)), bit_size_(bit_vector.bit_size_) {}

  // Copy constructor
  BitVector(const BitVector& bit_vector) noexcept
      : data_vector_(bit_vector.data_vector_), bit_size_(bit_vector.bit_size_) {}

  // Copy constructor from BitVector with different allocator
  template <typename OtherAllocator>
  BitVector(const BitVector<OtherAllocator>& bit_vector) noexcept
      : data_vector_(bit_vector.data_vector_.cbegin(), bit_vector.data_vector_.cend()),
        bit_size_(bit_vector.bit_size_) {}

  // Initialize from a std::vector<bool>, inefficient!
  BitVector(const std::vector<bool>& data) : BitVector(data, data.size()) {}

  explicit BitVector(uint number_of_bits, bool value = false)
      : BitVector(static_cast<std::size_t>(number_of_bits), value) {}

  explicit BitVector(int number_of_bits, bool value = false)
      : BitVector(static_cast<std::size_t>(number_of_bits), value) {}

  explicit BitVector(long number_of_bits, bool value = false)
      : BitVector(static_cast<std::size_t>(number_of_bits), value) {}

  explicit BitVector(long long number_of_bits, bool value = false)
      : BitVector(static_cast<std::size_t>(number_of_bits), value) {}

  explicit BitVector(long long unsigned int number_of_bits, bool value = false)
      : BitVector(static_cast<std::size_t>(number_of_bits), value) {}

  // Initialize with given length and value
  explicit BitVector(std::size_t number_of_bits, bool value = false) noexcept;

  // Initialize from pointer + size
  BitVector(const unsigned char* buffer, std::size_t bits)
      : BitVector(reinterpret_cast<const std::byte*>(buffer), bits) {}

  // Initialize from pointer + size
  BitVector(const std::byte* buffer, std::size_t bits);

  // Initialize from std::vector content, performs length check
  template <typename OtherAllocator>
  explicit BitVector(const std::vector<std::byte, OtherAllocator>& data,
                     std::size_t number_of_bits);

  // Initialize from std::vector rvalue (requires same allocator), performs length check
  explicit BitVector(std::vector<std::byte, Allocator>&& data, std::size_t number_of_bits);

  // Initialize from a std::vector<bool>, inefficient!
  explicit BitVector(const std::vector<bool>& data, std::size_t number_of_bits);

  bool Empty() const { return bit_size_ == 0; }

  /// \brief In-place bit-wise invert
  void Invert();

  static constexpr bool IsAligned() noexcept { return std::is_same_v<Allocator, AlignedAllocator>; }

  BitVector operator~() const;

  template <typename OtherAllocator>
  bool operator!=(const BitVector<OtherAllocator>& other) const noexcept;

  bool operator!=(const BitSpan& other) const noexcept;

  template <typename OtherAllocator>
  BitVector operator&(const BitVector<OtherAllocator>& other) const noexcept;

  BitVector operator&(const BitSpan& other) const noexcept;

  template <typename OtherAllocator>
  BitVector operator^(const BitVector<OtherAllocator>& other) const noexcept;

  BitVector operator^(const BitSpan& other) const noexcept;

  template <typename OtherAllocator>
  BitVector operator|(const BitVector<OtherAllocator>& other) const noexcept;

  BitVector operator|(const BitSpan& other) const noexcept;

  bool operator[](std::size_t position) const { return Get(position); }

  auto GetSize() const noexcept { return bit_size_; }

  const auto& GetData() const noexcept { return data_vector_; }

  auto& GetMutableData() noexcept { return data_vector_; }

  void Assign(const BitVector& other) noexcept { *this = other; }

  void Assign(BitVector&& other) noexcept { *this = std::move(other); }

  BitVector<Allocator>& operator=(const BitVector<Allocator>& other) noexcept;

  BitVector<Allocator>& operator=(BitVector<Allocator>&& other) noexcept;

  template <typename OtherAllocator>
  BitVector<Allocator>& operator=(const BitVector<OtherAllocator>& other) noexcept;

  template <typename OtherAllocator>
  bool operator==(const BitVector<OtherAllocator>& other) const noexcept;

  bool operator==(const BitSpan& bitspan) const noexcept;

  void Set(bool value) noexcept;

  void Set(bool value, std::size_t position);

  bool Get(std::size_t position) const;

  template <typename OtherAllocator>
  BitVector& operator&=(const BitVector<OtherAllocator>& other) noexcept;

  BitVector& operator&=(const BitSpan& bitspan) noexcept;

  template <typename OtherAllocator>
  BitVector& operator^=(const BitVector<OtherAllocator>& other) noexcept;

  BitVector& operator^=(const BitSpan& bitspan) noexcept;

  template <typename OtherAllocator>
  BitVector& operator|=(const BitVector<OtherAllocator>& other) noexcept;

  BitVector& operator|=(const BitSpan& bitspan) noexcept;

  void Resize(std::size_t number_of_bits, bool zero_fill = false) noexcept;

  void Reserve(std::size_t number_of_bytes) { data_vector_.reserve(number_of_bytes); }

  void Append(bool bit) noexcept;

  void Append(const BitVector<Allocator>& other) noexcept;

  void Append(BitVector&& other) noexcept;

  void Append(const BitSpan& bitspan);

  void Append(BitSpan&& bitspan);

  void Append(const std::byte* pointer, const std::size_t append_bit_size) noexcept;

  void Copy(const std::size_t offset_source, const std::size_t offset_destination,
            const BitVector& other);

  void Copy(const std::size_t offset_source, const BitVector& other);

  BitVector Subset(std::size_t from, std::size_t to) const;

  std::string AsString() const noexcept;

  void Clear() noexcept;

  static BitVector Random(const std::size_t size) noexcept;

  static BitVector RandomSeeded(const std::size_t size, const std::size_t seed = 0) noexcept;

  static bool AndReduceBitVector(const BitVector& bit_vector);

  static BitVector AndBitVectors(const std::vector<BitVector>& bit_vectors);

  static bool OrReduceBitVector(const BitVector& bit_vector);

  static BitVector OrBitVectors(const std::vector<BitVector>& bit_vectors);

  static std::vector<BitVector> AndBitVectors(const std::vector<BitVector>& a,
                                              const std::vector<BitVector>& b);

  static std::vector<BitVector> AndBitVectors(
      const std::vector<std::vector<BitVector>>& bit_vectors);

  static bool XorReduceBitVector(const BitVector& bit_vector);

  static BitVector XorBitVectors(const std::vector<BitVector>& bit_vectors);

  static std::vector<BitVector> XorBitVectors(const std::vector<BitVector>& a,
                                              const std::vector<BitVector>& b);

  static std::vector<BitVector> XorBitVectors(
      const std::vector<std::vector<BitVector>>& bit_vectors);

  static bool EqualSizeDimensions(const std::vector<BitVector>& bit_vectors);

 private:
  std::vector<std::byte, Allocator> data_vector_;

  std::size_t bit_size_;

  void TruncateToFit() noexcept;

  void BoundsCheckEquality([[maybe_unused]] const std::size_t bit_size) const;

  void BoundsCheckInRange([[maybe_unused]] const std::size_t bit_size) const;
};

template <typename Allocator>
std::ostream& operator<<(std::ostream& os, const BitVector<Allocator>& bit_vector) {
  return os << bit_vector.AsString();
}

// Input functions that convert inputs of integer and floating point types to vectors of
// BitVectors, which are a suitable input to MOTION

template <typename UnsignedIntegralType,
          typename = std::enable_if_t<std::is_unsigned_v<UnsignedIntegralType>>,
          typename Allocator = std::allocator<std::byte>>
std::vector<BitVector<Allocator>> ToInput(UnsignedIntegralType unsigned_integral_value);

template <typename UnsignedIntegralType,
          typename = std::enable_if_t<std::is_unsigned_v<UnsignedIntegralType>>,
          typename Allocator = std::allocator<std::byte>>
std::vector<BitVector<Allocator>> ToInput(
    const std::vector<UnsignedIntegralType>& unsigned_integral_vector);

template <typename FloatingPointType,
          typename = std::enable_if_t<std::is_floating_point_v<FloatingPointType>>,
          typename Allocator = std::allocator<std::byte>>
std::vector<BitVector<Allocator>> ToInput(FloatingPointType floating_point_value);

template <typename FloatingPointType,
          typename = std::enable_if_t<std::is_floating_point_v<FloatingPointType>>,
          typename Allocator = std::allocator<std::byte>>
std::vector<BitVector<Allocator>> ToInput(
    const std::vector<FloatingPointType>& floating_point_vector);

// Output functions for converting vectors of BitVectors to vectors of floating point or
// integer numbers

template <typename UnsignedIntegralType,
          typename = std::enable_if_t<std::is_unsigned_v<UnsignedIntegralType>>,
          typename Allocator = std::allocator<std::byte>>
UnsignedIntegralType ToOutput(std::vector<BitVector<Allocator>> bit_vectors) {
  static_assert(std::is_integral<UnsignedIntegralType>::value);
  static_assert(sizeof(UnsignedIntegralType) <= 8);
  if constexpr (sizeof(UnsignedIntegralType) == 1) {
    static_assert(std::is_same_v<UnsignedIntegralType, std::uint8_t>);
  } else if constexpr (sizeof(UnsignedIntegralType) == 2) {
    static_assert(std::is_same_v<UnsignedIntegralType, std::uint16_t>);
  } else if constexpr (sizeof(UnsignedIntegralType) == 4) {
    static_assert(std::is_same_v<UnsignedIntegralType, std::uint32_t>);
  } else if constexpr (sizeof(UnsignedIntegralType) == 8) {
    static_assert(std::is_same_v<UnsignedIntegralType, std::uint64_t>);
  }

  // kBitLength is always equal to bit_vectors
  constexpr auto kBitLength{sizeof(UnsignedIntegralType) * 8};

  assert(!bit_vectors.empty());
  if (kBitLength != bit_vectors.size()) {
    throw std::runtime_error(
        fmt::format("Trying to convert to different bitlength: is {}, expected {}",
                    bit_vectors.size(), kBitLength));
  }

  // TODO: It is asserted later that all BitVectors have a size equal to 1. This check can be
  // omitted
  const auto number_of_simd{bit_vectors.at(0).GetSize()};
  assert(number_of_simd > 0u);
  for ([[maybe_unused]] auto i = 0ull; i < bit_vectors.size(); ++i)
    // Asserting that every BitVector has the same size
    assert(bit_vectors.at(i).GetSize() == number_of_simd);

  UnsignedIntegralType output_value{0};
  // Converting values in a BitVector to UnsignedIntegralType
  for (auto i = 0ull; i < kBitLength; ++i) {
    // Asserting that every Bitvector has a size equal to 1.
    // Note: bit_vectors.size() == kBitLength here, since exception is thrown earlier if not
    assert(bit_vectors.at(i).GetSize() == 1);
    output_value += static_cast<UnsignedIntegralType>(bit_vectors.at(i)[0]) << i;
  }

  return output_value;
}

template <typename UnsignedIntegralType,
          typename = std::enable_if_t<std::is_unsigned_v<UnsignedIntegralType>>,
          typename Allocator = std::allocator<std::byte>>
std::vector<UnsignedIntegralType> ToVectorOutput(std::vector<BitVector<Allocator>> bit_vectors) {
  static_assert(std::is_integral<UnsignedIntegralType>::value);
  static_assert(sizeof(UnsignedIntegralType) <= 8);
  if constexpr (sizeof(UnsignedIntegralType) == 1) {
    static_assert(std::is_same_v<UnsignedIntegralType, std::uint8_t>);
  } else if constexpr (sizeof(UnsignedIntegralType) == 2) {
    static_assert(std::is_same_v<UnsignedIntegralType, std::uint16_t>);
  } else if constexpr (sizeof(UnsignedIntegralType) == 4) {
    static_assert(std::is_same_v<UnsignedIntegralType, std::uint32_t>);
  } else if constexpr (sizeof(UnsignedIntegralType) == 8) {
    static_assert(std::is_same_v<UnsignedIntegralType, std::uint64_t>);
  }

  constexpr auto kBitLength{sizeof(UnsignedIntegralType) * 8};

  assert(!bit_vectors.empty());
  if (kBitLength != bit_vectors.size()) {
    throw std::runtime_error(
        fmt::format("Trying to convert to different bitlength: is {}, expected {}",
                    bit_vectors.size(), kBitLength));
  }

  const auto number_of_simd{bit_vectors.at(0).GetSize()};
  assert(number_of_simd > 0u);
  for ([[maybe_unused]] auto i = 0ull; i < bit_vectors.size(); ++i)
    assert(bit_vectors.at(i).GetSize() == number_of_simd);

  // Converting values in a BitVector to a value of UnsignedIntegralType
  // Example: If the jth BitVector of size 3 is represented by the tuple: (xj, yj, zj)
  // Then output_vector[0] == x0*2^0 + x1*2^1 + ... + xn*2^n
  //     output_vector[1] == y0*2^0 + y1*2^1 + ... + yn*2^n
  //     output_vector[2] == z0*2^0 + z1*2^1 + ... + zn*2^n
  std::vector<UnsignedIntegralType> output_vector;
  for (auto i = 0ull; i < number_of_simd; ++i) {
    UnsignedIntegralType value{0};
    for (auto j = 0ull; j < kBitLength; ++j) {
      value += static_cast<UnsignedIntegralType>(bit_vectors.at(j)[i]) << j;
    }
    output_vector.emplace_back(value);
  }
  return output_vector;
}

using AlignedBitVector = BitVector<AlignedAllocator>;

/// \brief provides a read-write BitVector API over a raw buffer, e.g., std::byte *.
/// The underlying buffer is not owned by the BitSpan, in contrast to BitVector.
/// Assumes that the buffer starts at leftmost bit of the underlying buffer.
/// Alternatively, non-owning non-resizeable BitVector

class BitSpan {
 public:
  BitSpan() = default;

  ~BitSpan() = default;

  BitSpan(std::byte* pointer, std::size_t bit_size, bool aligned = false);

  template <typename T>
  BitSpan(T* pointer, std::size_t bit_size, bool aligned = false);

  BitSpan(const BitSpan& other);

  BitSpan(BitSpan&& other);

  template <typename BitVectorType>
  BitSpan(BitVectorType& bit_vector)
      : pointer_(bit_vector.GetMutableData().data()),
        bit_size_(bit_vector.GetSize()),
        aligned_(bit_vector.IsAligned()) {}

  BitSpan& operator=(const BitSpan& other);

  BitSpan& operator=(BitSpan&& other);

  template <typename BitVectorType>
  BitSpan& operator=(BitVectorType& bit_vector) {
    pointer_ = bit_vector.GetMutableData().data();
    bit_size_ = bit_vector.GetSize();
    aligned_ = bit_vector.IsAligned();
    return *this;
  }

  template <typename BitVectorType = AlignedBitVector>
  BitVectorType As() const {
    return BitVectorType(pointer_, bit_size_);
  }

  template <typename BitVectorType = AlignedBitVector>
  BitVectorType Subset(const std::size_t from, const std::size_t to) const;

  bool Empty() const noexcept { return bit_size_; }

  void Invert();

  template <typename BitVectorType = AlignedBitVector>
  BitVectorType operator~() const {
    BitVectorType result(pointer_, bit_size_);
    result.Invert();
    return result;
  }

  template <typename BitVectorType = AlignedBitVector>
  bool operator==(const BitVectorType& bit_vector) const;

  bool operator==(const BitSpan& other) const;

  template <typename BitVectorType = AlignedBitVector>
  BitVectorType operator&(const BitVectorType& bit_vector) const;

  template <typename BitVectorType = AlignedBitVector>
  BitVectorType operator&(const BitSpan& other) const;

  template <typename BitVectorType = AlignedBitVector>
  BitVectorType operator|(const BitVectorType& bit_vector) const;

  template <typename BitVectorType = AlignedBitVector>
  BitVectorType operator|(const BitSpan& other) const;

  template <typename BitVectorType = AlignedBitVector>
  BitVectorType operator^(const BitVectorType& bit_vector) const;

  template <typename BitVectorType = AlignedBitVector>
  BitVectorType operator^(const BitSpan& other) const;

  template <typename BitVectorType = AlignedBitVector>
  BitSpan& operator&=(const BitVectorType& bit_vector);

  BitSpan& operator&=(const BitSpan& other);

  template <typename BitVectorType = AlignedBitVector>
  BitSpan& operator|=(const BitVectorType& bit_vector);

  BitSpan& operator|=(const BitSpan& other);

  template <typename BitVectorType = AlignedBitVector>
  BitSpan& operator^=(const BitVectorType& bit_vector);

  BitSpan& operator^=(const BitSpan& other);

  bool Get(const std::size_t position) const;

  bool operator[](const std::size_t position) const { return Get(position); }

  void Set(const bool value);

  void Set(const bool value, const std::size_t position);

  const std::byte* GetData() const noexcept { return pointer_; }

  std::byte* GetMutableData() noexcept { return pointer_; }

  std::size_t GetSize() const noexcept { return bit_size_; }

  std::string AsString() const noexcept;

  bool IsAligned() const noexcept { return aligned_; }

  template <typename BitVectorType>
  void Copy(const std::size_t offset_source, const std::size_t offset_destination,
            BitVectorType& other);

  template <typename BitVectorType>
  void Copy(const std::size_t offset_source, BitVectorType& other);

  void Copy(const std::size_t offset_source, const std::size_t offset_destination, BitSpan& other);

  void Copy(const std::size_t offset_source, const std::size_t offset_destination, BitSpan&& other);

  void Copy(const std::size_t offset_source, BitSpan& other);

  void Copy(const std::size_t offset_source, BitSpan&& other);

 private:
  std::byte* pointer_;
  std::size_t bit_size_;
  bool aligned_;
};

std::ostream& operator<<(std::ostream& os, const BitSpan& bit_span);

}  // namespace encrypto::motion
