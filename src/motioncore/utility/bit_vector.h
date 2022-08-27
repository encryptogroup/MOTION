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

// bitmask to set a specific bit in a byte
constexpr std::byte kSetBitMask[] = {
    std::byte(0b00000001), std::byte(0b00000010), std::byte(0b00000100), std::byte(0b00001000),
    std::byte(0b00010000), std::byte(0b00100000), std::byte(0b01000000), std::byte(0b10000000)};

// bitmask to unset a specific bit in a byte
constexpr std::byte kUnsetBitMask[] = {
    std::byte(0b11111110), std::byte(0b11111101), std::byte(0b11111011), std::byte(0b11110111),
    std::byte(0b11101111), std::byte(0b11011111), std::byte(0b10111111), std::byte(0b01111111)};

// bitmask to truncate a byte to the first n bits
constexpr std::byte TruncationBitMask[] = {
    std::byte(0b00000000), std::byte(0b00000001), std::byte(0b00000011), std::byte(0b00000111),
    std::byte(0b00001111), std::byte(0b00011111), std::byte(0b00111111), std::byte(0b01111111)};

class BitSpan;

using StdAllocator = std::allocator<std::byte>;
using AlignedAllocator = boost::alignment::aligned_allocator<std::byte, kAlignment>;

/// \brief Class representing a series of bits and providing single bit access.
template <typename Allocator = std::allocator<std::byte>>
class BitVector {
  template <typename OtherAllocator>
  friend class BitVector;
  friend class BitSpan;

 public:
  using allocator = Allocator;
  // Default constructor, results in an empty vector
  BitVector() noexcept : bit_size_(0){};

  // Move constructor
  BitVector(BitVector&& bit_vector) noexcept
      : data_vector_(std::move(bit_vector.data_vector_)), bit_size_(bit_vector.bit_size_) {}

  // XXX Copy and Move constructor/assigment can be defaulted

  // Copy constructor
  BitVector(const BitVector& bit_vector) noexcept
      : data_vector_(bit_vector.data_vector_), bit_size_(bit_vector.bit_size_) {}

  // Copy assignment
  BitVector<Allocator>& operator=(const BitVector<Allocator>& other) noexcept;

  // Move assignment
  BitVector<Allocator>& operator=(BitVector<Allocator>&& other) noexcept;

  /// \brief Copy from a BitVector with different allocator.
  /// \tparam OtherAllocator
  /// \param other
  template <typename OtherAllocator>
  BitVector(const BitVector<OtherAllocator>& bit_vector) noexcept
      : data_vector_(bit_vector.data_vector_.cbegin(), bit_vector.data_vector_.cend()),
        bit_size_(bit_vector.bit_size_) {}

  /// \brief Move from a BitVector with different allocator. Falls back to copy constructor.
  /// \tparam OtherAllocator
  /// \param other
  template <typename OtherAllocator>
  BitVector(BitVector<OtherAllocator>&& bit_vector) noexcept : BitVector(bit_vector) {}

  /// \brief Copy-assign from BitVector with different allocator.
  /// \tparam OtherAllocator
  /// \param other
  template <typename OtherAllocator>
  BitVector<Allocator>& operator=(const BitVector<OtherAllocator>& other) noexcept;

  /// \brief Move-assign from BitVector with different allocator. Falls back to copy-assign.
  /// \tparam OtherAllocator
  /// \param other
  template <typename OtherAllocator>
  BitVector<Allocator>& operator=(BitVector<OtherAllocator>&& other) noexcept {
    return *this = other;
  }

  /// \brief Initialize from a std::vector<bool>.
  /// \param data
  /// \note Initializing a BitVector this way is inefficient!
  BitVector(const std::vector<bool>& data) : BitVector(data, data.size()) {}

  /// \brief Initialize from a std::vector<bool>.
  /// \param data
  /// \param number_of_bits Expected number of bits.
  /// \pre \p data must be of size equal to \p number_of_bits.
  /// \note Initializing a BitVector this way is inefficient!
  explicit BitVector(const std::vector<bool>& data, std::size_t number_of_bits);

  /// \brief Construct a BitVector with exactly \p number_of_bits bits set to \p value.
  /// \param number_of_bits
  /// \param value
  explicit BitVector(std::size_t number_of_bits, bool value = false) noexcept;

  /// \brief Initialize BitVector from buffer.
  /// \param buffer
  /// \param bits Size of the buffer.
  BitVector(const unsigned char* buffer, std::size_t bits)
      : BitVector(reinterpret_cast<const std::byte*>(buffer), bits) {}

  /// \brief Initialize BitVector from buffer.
  /// \param buffer
  /// \param bits Size of the buffer.
  BitVector(const std::byte* buffer, std::size_t bits);

  /// \brief Initialize by copying content of std::vector.
  /// \param data
  /// \param number_of_bits Expected number of bits.
  /// \pre \p data must be of size equal to \p number_of_bits.
  template <typename OtherAllocator>
  explicit BitVector(const std::vector<std::byte, OtherAllocator>& data,
                     std::size_t number_of_bits);

  /// \brief Initialize by moving content of std::vector (requires same allocator).
  /// \param data
  /// \param number_of_bits Expected number of bits.
  /// \pre \p data must be of size equal to \p number_of_bits.
  explicit BitVector(std::vector<std::byte, Allocator>&& data, std::size_t number_of_bits);

  /// \brief Check if BitVector is empty.
  bool Empty() const { return bit_size_ == 0; }

  /// \brief Get size of BitVector.
  auto GetSize() const noexcept { return bit_size_; }

  /// \brief Get const reference to content of BitVector.
  const auto& GetData() const noexcept { return data_vector_; }

  /// \brief Get reference to content of BitVector.
  auto& GetMutableData() noexcept { return data_vector_; }

  /// \brief Copy-assign other BitVector.
  /// \param other
  void Assign(const BitVector& other) noexcept { *this = other; }

  /// \brief Move-assign other BitVector.
  /// \param other
  void Assign(BitVector&& other) noexcept { *this = std::move(other); }

  /// \brief Sets or unsets all bits in the BitVector
  /// \param value
  void Set(bool value) noexcept;

  /// \brief Sets or unsets the bit at \p position in the BitVector
  /// \param value
  /// \param position
  void Set(bool value, std::size_t position);

  /// \brief Get bit at given position
  /// \param position
  bool Get(std::size_t position) const;

  /// \brief Resize BitVector to size \p number_of_bits. New bits are uninitialized by default.
  /// \param number_of_bits
  /// \param zero_fill Sets new bits to 0 if option is set to true.
  void Resize(std::size_t number_of_bits, bool zero_fill = false) noexcept;

  /// \brief Reserves new space for BitVector, so that it can contain at least \p number_of_bits
  /// bits \param number_of_bits
  void Reserve(std::size_t number_of_bits) { data_vector_.reserve(BitsToBytes(number_of_bits)); }

  /// \brief Appends a bit to BitVector.
  /// \param bit
  void Append(bool bit) noexcept;

  /// \brief Appends another BitVector to BitVector.
  /// \param other
  void Append(const BitVector<Allocator>& other) noexcept;

  /// \brief Appends another BitVector to BitVector.
  /// \param other
  void Append(BitVector&& other) noexcept;

  /// \brief Appends a BitSpan to BitVector.
  /// \param other
  /// \note A BitSpan is essentially a BitVector, with the only difference that
  ///       it does not have ownership of its data.
  void Append(const BitSpan& other);

  /// \brief Appends a BitSpan to BitVector.
  /// \param other
  /// \note A BitSpan is essentially a BitVector, with the only difference that
  ///       it does not have ownership of its data.
  void Append(BitSpan&& other);

  /// \brief Appends \p append_bit_size bytes starting from \p pointer to BitVector.
  /// \param pointer
  /// \param append_bit_size
  void Append(const std::byte* pointer, const std::size_t append_bit_size) noexcept;

  /// \brief copies the first (dest_to - dest_from) bits from other to the bits [dest_from, dest_to)
  /// in this.
  /// \throws an std::out_of_range exception if accessing invalid positions in this or other.
  void Copy(const std::size_t dest_from, const std::size_t dest_to, const BitVector& other);

  /// \brief copies the first (dest_to - dest_from) bits from data to the bits [dest_from, dest_to)
  /// in this.
  void Copy(const std::size_t dest_from, const std::size_t dest_to, const std::byte* data);

  /// \brief copies other to this[dest_from...dest_from+GetSize()].
  /// \throws an std::out_of_range exception if this is smaller than other.
  void Copy(const std::size_t dest_from, const BitVector& other);

  /// \brief Returns a new BitVector containing the bits of this BitVector between positions \p from
  /// and \p to. \param from \param to
  BitVector Subset(std::size_t from, std::size_t to) const;

  /// \brief Returns a string representation of this BitVector.
  std::string AsString() const noexcept;

  /// \brief Clear this Bitvector.
  void Clear() noexcept;

  /// \brief In-place bit-wise invert.
  void Invert();

  /// \brief Get bit at given position in the BitVector.
  /// \param position
  bool operator[](std::size_t position) const { return Get(position); }

  /// \brief Return an inverted copy of this BitVector.
  BitVector operator~() const;

  /// \brief Perform AND operation between every bit of two BitVectors.
  /// \param other
  template <typename OtherAllocator>
  BitVector operator&(const BitVector<OtherAllocator>& other) const noexcept;

  /// \brief Perform AND operation between every bit of a BitVector and a BitSpan.
  /// \param other
  /// \note A BitSpan is essentially a BitVector, with the only difference that
  ///       it does not have ownership of its data.
  BitVector operator&(const BitSpan& other) const noexcept;

  /// \brief Perform XOR operation between every bit of two BitVectors.
  /// \param other
  template <typename OtherAllocator>
  BitVector operator^(const BitVector<OtherAllocator>& other) const noexcept;

  /// \brief Perform XOR operation between every bit of a BitVector and a BitSpan.
  /// \param other
  /// \note A BitSpan is essentially a BitVector, with the only difference that
  ///       it does not have ownership of its data.
  BitVector operator^(const BitSpan& other) const noexcept;

  /// \brief Perform OR operation between every bit of two BitVectors.
  /// \param other
  template <typename OtherAllocator>
  BitVector operator|(const BitVector<OtherAllocator>& other) const noexcept;

  /// \brief Perform OR operation between every bit of a BitVector and a BitSpan.
  /// \param other
  /// \note A BitSpan is essentially a BitVector, with the only difference that
  ///       it does not have ownership of its data.
  BitVector operator|(const BitSpan& other) const noexcept;

  /// \brief Compares two BitVectors for inequality.
  /// \param other
  template <typename OtherAllocator>
  bool operator!=(const BitVector<OtherAllocator>& other) const noexcept;

  /// \brief Compares a BitVector and a BitSpan for inequality.
  /// \param other
  /// \note A BitSpan is essentially a BitVector, with the only difference that
  ///       it does not have ownership of its data.
  bool operator!=(const BitSpan& other) const noexcept;

  /// \brief Compares two BitVectors for equality.
  /// \param other
  template <typename OtherAllocator>
  bool operator==(const BitVector<OtherAllocator>& other) const noexcept;

  /// \brief Compares a BitVector and a BitSpan for equality.
  /// \param other
  /// \note A BitSpan is essentially a BitVector, with the only difference that
  ///       it does not have ownership of its data.
  bool operator==(const BitSpan& other) const noexcept;

  /// \brief Perform AND-assign operation between every bit of this and the other BitVector.
  /// \param other
  template <typename OtherAllocator>
  BitVector& operator&=(const BitVector<OtherAllocator>& other) noexcept;

  /// \brief Perform AND-assign operation between every bit of this and a BitSpan.
  /// \param other
  /// \note A BitSpan is essentially a BitVector, with the only difference that
  ///       it does not have ownership of its data.
  BitVector& operator&=(const BitSpan& other) noexcept;

  /// \brief Perform XOR-assign operation between every bit of this and the other BitVector.
  /// \param other
  template <typename OtherAllocator>
  BitVector& operator^=(const BitVector<OtherAllocator>& other) noexcept;

  /// \brief Perform XOR-assign operation between every bit of this and a BitSpan.
  /// \param other
  /// \note A BitSpan is essentially a BitVector, with the only difference that
  ///       it does not have ownership of its data.
  BitVector& operator^=(const BitSpan& other) noexcept;

  /// \brief Perform OR-assign operation between every bit of this and the other BitVector.
  /// \param other
  template <typename OtherAllocator>
  BitVector& operator|=(const BitVector<OtherAllocator>& other) noexcept;

  /// \brief Perform OR-assign operation between every bit of this and a BitSpan.
  /// \param other
  /// \note A BitSpan is essentially a BitVector, with the only difference that
  ///       it does not have ownership of its data.
  BitVector& operator|=(const BitSpan& other) noexcept;

  /// \brief Returns a random BitVector.
  /// \param size The size of the returned BitVector.
  static BitVector SecureRandom(const std::size_t size) noexcept;

  /// \brief Returns a random BitVector using an input seed.
  /// Internally uses Mersenne twister, do not use as cryptographic randomness!
  /// \param size The size of the returned BitVector.
  /// \param seed
  static BitVector RandomSeeded(const std::size_t size, const std::size_t seed = 0) noexcept;

  /// \brief Performs OR operation between all bits in BitVector.
  /// \param bit_vector
  static bool OrReduceBitVector(const BitVector& bit_vector);

  /// \brief Performs OR operation between all BitVectors in \p bit_vectors.
  /// \param bit_vectors
  static BitVector OrBitVectors(const std::vector<BitVector>& bit_vectors);

  /// \brief Performs AND operation between all bits in BitVector.
  /// \param bit_vector
  static bool AndReduceBitVector(const BitVector& bit_vector);

  /// \brief Performs AND operation between all BitVectors in \p bit_vectors.
  /// \param bit_vectors
  static BitVector AndBitVectors(const std::vector<BitVector>& bit_vectors);

  /// \brief Performs AND operation between every BitVector in \p a and \p b.
  /// \param a
  /// \param b
  /// \pre \p a and \p b must be of equal size.
  static std::vector<BitVector> AndBitVectors(const std::vector<BitVector>& a,
                                              const std::vector<BitVector>& b);

  /// \brief Performs AndBitVectors operation between all vectors of BitVector in \p bit_vectors.
  /// \param bit_vectors
  static std::vector<BitVector> AndBitVectors(
      const std::vector<std::vector<BitVector>>& bit_vectors);

  /// \brief Performs XOR operation between all bits in BitVector.
  /// \param bit_vector
  static bool XorReduceBitVector(const BitVector& bit_vector);

  /// \brief Performs XOR operation between all BitVectors in \p bit_vectors.
  /// \param bit_vectors
  static BitVector XorBitVectors(const std::vector<BitVector>& bit_vectors);

  /// \brief Performs XOR operation between every BitVector in \p a and \p b.
  /// \param a
  /// \param b
  /// \pre \p a and \p b must be of equal size.
  static std::vector<BitVector> XorBitVectors(const std::vector<BitVector>& a,
                                              const std::vector<BitVector>& b);

  /// \brief Performs XorBitVectors operation between all vectors of BitVector in \p bit_vectors.
  /// \param bit_vectors
  static std::vector<BitVector> XorBitVectors(
      const std::vector<std::vector<BitVector>>& bit_vectors);

  /// \brief Check if all Bitvectors in \p bit_vectors are of equal dimension.
  /// \param bit_vectors
  static bool IsEqualSizeDimensions(const std::vector<BitVector>& bit_vectors);

  /// \brief Returns true if Allocator is aligned allocator.
  static constexpr bool IsAligned() noexcept { return std::is_same_v<Allocator, AlignedAllocator>; }

  std::size_t HammingWeight() const;

 private:
  std::vector<std::byte, Allocator> data_vector_;

  std::size_t bit_size_;

  void TruncateToFit() noexcept;

  void BoundsCheckEquality([[maybe_unused]] const std::size_t bit_size) const;

  void BoundsCheckInRange([[maybe_unused]] const std::size_t bit_size) const;
};

/// \brief Output string representation of BitVector to std::ostream.
template <typename Allocator>
std::ostream& operator<<(std::ostream& os, const BitVector<Allocator>& bit_vector) {
  return os << bit_vector.AsString();
}

// Input functions that convert inputs of integer and floating point types to vectors of
// BitVectors, which are a suitable input to MOTION.

/// \brief Converts a value of an unsigned integer type or a floating point type to a vector of
/// BitVector.
/// \details A vector of BitVectors allows to interleave multiple arithmetic values
///          intended to be used in a SIMD way. Let x be an arithmetic value,
///          with x0,...,xn being its little-endian bit representation.
///          This value is then represented by a value v of type std::vector<BitVector>
///          with v[j][0] == xj.
///          Now, if we interleave x with y and z of the same bit representation, then:
///          v[j][0] == xj, v[j][1] == yj, v[j][2] == zj.
/// \post - All BitVectors in the returned vector will have size equal 1.
///       - The returned vector will have size equal to number of bits in \p UnsignedIntegralType.
/// \tparam T
/// \param value
/// \relates BitVector
template <typename T,
          typename = std::enable_if_t<std::is_floating_point_v<T> || std::is_integral_v<T>>,
          typename Allocator = std::allocator<std::byte>>
std::vector<BitVector<Allocator>> ToInput(T value);

/// \brief Converts a vector of an unsigned integer type or a floating point type to a vector of
/// BitVector.
/// \details A vector of BitVectors allows to interleave multiple arithmetic values
///          intended to be used in a SIMD way. Let x be an arithmetic value,
///          with x0,...,xn being its little-endian bit representation.
///          This value is then represented by a value v of type std::vector<BitVector>
///          with v[j][0] == xj.
///          Now, if we interleave x with y and z of the same bit representation, then:
///          v[j][0] == xj, v[j][1] == yj, v[j][2] == zj.
/// \post - All BitVectors in the vector returned will have size equal to \p
/// unsigned_integral_vector.size().
///       - The returned vector will have size equal to number of bits in \p UnsignedIntegralType.
/// \tparam T
/// \param vector
template <typename T,
          typename = std::enable_if_t<std::is_floating_point_v<T> || std::is_integral_v<T>>,
          typename Allocator = std::allocator<std::byte>>
std::vector<BitVector<Allocator>> ToInput(const std::vector<T>& vector);

// Output functions for converting vectors of BitVectors to vectors of floating point or
// integer numbers

/// \brief Converts a vector of BitVectors to a value of UnsignedIntegralType.
/// \details A vector of BitVectors allows to interleave multiple arithmetic values
///          intended to be used in a SIMD way. Let x be an arithmetic value,
///          with x0,...,xn being its little-endian bit representation.
///          This value is then represented by a value v of type std::vector<BitVector>
///          with v[j][0] == xj.
///          Now, if we interleave x with y and z of the same bit representation, then:
///          v[j][0] == xj, v[j][1] == yj, v[j][2] == zj.
/// \pre - Size of \p bit_vectors is equal to number of bits in \p UnsignedIntegralType.
///      - Each BitVector in \p bit_vectors has size equal 1.
/// \tparam UnsignedIntegralType
/// \param bit_vectors
template <typename IntegralType, typename = std::enable_if_t<std::is_integral_v<IntegralType>>,
          typename Allocator = std::allocator<std::byte>>
IntegralType ToOutput(std::vector<BitVector<Allocator>> bit_vectors) {
  // kBitLength is always equal to bit_vectors
  constexpr auto kBitLength{sizeof(IntegralType) * 8};

  assert(!bit_vectors.empty());
  if (kBitLength != bit_vectors.size()) {
    throw std::runtime_error(
        fmt::format("Trying to convert to different bitlength: is {}, expected {}",
                    bit_vectors.size(), kBitLength));
  }

  assert(bit_vectors.at(0).GetSize() > 0u);
  for ([[maybe_unused]] auto i = 0ull; i < bit_vectors.size(); ++i)
    assert(bit_vectors.at(i).GetSize() == bit_vectors.at(0).GetSize());

  IntegralType output_value{0};
  if constexpr (std::is_unsigned_v<IntegralType>) {
    // Converting values in a BitVector to UnsignedIntegralType
    for (auto i = 0ull; i < kBitLength; ++i) {
      assert(bit_vectors.at(i).GetSize() == 1);
      output_value += static_cast<IntegralType>(bit_vectors[i][0]) << i;
    }
  } else {
    std::make_unsigned_t<IntegralType> unsigned_value{0};
    for (auto j = 0ull; j < kBitLength; ++j) {
      unsigned_value += static_cast<std::make_unsigned_t<IntegralType>>(bit_vectors[j][0]) << j;
    }
    output_value = FromTwosComplement(unsigned_value);
  }

  return output_value;
}

/// \brief Converts a vector of UnsignedIntegralType to a vector of BitVectors.
/// \details A vector of BitVectors allows to interleave multiple arithmetic values
///          intended to be used in a SIMD way. Let x be an arithmetic value,
///          with x0,...,xn being its little-endian bit representation.
///          This value is then represented by a value v of type std::vector<BitVector>
///          with v[j][0] == xj.
///          Now, if we interleave x with y and z of the same bit representation, then:
///          v[j][0] == xj, v[j][1] == yj, v[j][2] == zj.
/// \pre - Size of \p bit_vectors is equal to number of bits in \p UnsignedIntegralType
///      - Each BitVector in \p bit_vectors has size equal to bit_vectors.size()
/// \tparam UnsignedIntegralType
/// \param bit_vectors
/// \relates BitVector
template <typename IntegralType, typename = std::enable_if_t<std::is_integral_v<IntegralType>>,
          typename Allocator = std::allocator<std::byte>>
std::vector<IntegralType> ToVectorOutput(std::vector<BitVector<Allocator>> bit_vectors) {
  constexpr auto kBitLength{sizeof(IntegralType) * 8};

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
  std::vector<IntegralType> output_vector;
  output_vector.reserve(number_of_simd);
  for (auto i = 0ull; i < number_of_simd; ++i) {
    if constexpr (std::is_unsigned_v<IntegralType>) {
      IntegralType value{0};
      for (auto j = 0ull; j < kBitLength; ++j) {
        value += static_cast<IntegralType>(bit_vectors[j][i]) << j;
      }
      output_vector.emplace_back(value);
    } else {
      std::make_unsigned_t<IntegralType> unsigned_value{0};
      for (auto j = 0ull; j < kBitLength; ++j) {
        unsigned_value += static_cast<std::make_unsigned_t<IntegralType>>(bit_vectors[j][i]) << j;
      }
      output_vector.emplace_back(FromTwosComplement(unsigned_value));
    }
  }
  return output_vector;
}

using AlignedBitVector = BitVector<AlignedAllocator>;

/// \brief Non-owning non-resizeable BitVector.
/// \details Provides a read-write BitVector API over a raw buffer, e.g. std::byte *.
/// The underlying buffer is not owned by the BitSpan, in contrast to BitVector.
/// Assumes that the buffer starts at the leftmost bit of the underlying buffer.
class BitSpan {
 public:
  BitSpan() = default;

  ~BitSpan() = default;

  // XXX Copy and move constructor/assignment can be declared default.
  // XXX Assignments do not check for self-assignment.
  BitSpan(const BitSpan& other);

  BitSpan(BitSpan&& other);

  BitSpan& operator=(const BitSpan& other);

  BitSpan& operator=(BitSpan&& other);

  /// \brief Construct a BitSpan from a BitVector
  /// \param bit_vector
  template <typename BitVectorType>
  BitSpan(BitVectorType& bit_vector)
      : pointer_(bit_vector.GetMutableData().data()),
        bit_size_(bit_vector.GetSize()),
        aligned_(bit_vector.IsAligned()) {}

  /// \brief Assignment from BitVector
  /// \param bit_vectpr
  template <typename BitVectorType>
  BitSpan& operator=(BitVectorType& bit_vector) {
    pointer_ = bit_vector.GetMutableData().data();
    bit_size_ = bit_vector.GetSize();
    aligned_ = bit_vector.IsAligned();
    return *this;
  }

  /// \brief Construct a BitSpan from std::byte \p buffer of length \p bit_size.
  /// \param buffer
  /// \param bit_size
  /// \param aligned Alignment of the buffer
  BitSpan(std::byte* buffer, std::size_t bit_size, bool aligned = false);

  /// \brief Construct a BitSpan from a \p buffer of length \p bit_size.
  /// \param buffer
  /// \param bit_size
  /// \param aligned Alignment of the buffer
  template <typename T>
  BitSpan(T* buffer, std::size_t bit_size, bool aligned = false)
      : pointer_(reinterpret_cast<std::byte*>(buffer)), bit_size_(bit_size), aligned_(aligned) {}

  // TODO make this a user-defined conversion.
  /// \brief Converts this BitSpan to a BitVector
  /// \tparam BitVectorType The concrete type of the BitVector
  template <typename BitVectorType = AlignedBitVector>
  BitVectorType As() const {
    return BitVectorType(pointer_, bit_size_);
  }

  /// \brief Returns a new BitVector containing the bits of this BitSpan between positions \p from
  /// and \p to. \param from \param to
  template <typename BitVectorType = AlignedBitVector>
  BitVectorType Subset(const std::size_t from, const std::size_t to) const;

  /// \brief Check if BitSpan is empty.
  bool Empty() const noexcept { return bit_size_; }

  /// \brief In-place bit-wise invert.
  void Invert();

  /// \brief Return a BitVector containing bit-inverted values of this BitSpan.
  template <typename BitVectorType = AlignedBitVector>
  BitVectorType operator~() const {
    BitVectorType result(pointer_, bit_size_);
    result.Invert();
    return result;
  }

  /// \brief Compare the content of a BitVectorType for equality.
  /// \tparam BitVectorType
  /// \param other
  template <typename BitVectorType = AlignedBitVector>
  bool operator==(const BitVectorType& other) const;

  /// \brief Compare the content with another BitSpan for equality.
  /// \param other
  bool operator==(const BitSpan& other) const;

  /// \brief Perform AND operation on every bit of BitSpan and BitVector.
  /// \param other
  template <typename BitVectorType = AlignedBitVector>
  BitVectorType operator&(const BitVectorType& other) const;

  /// \brief Perform AND operation on every bit of both BitSpans.
  /// \param other
  template <typename BitVectorType = AlignedBitVector>
  BitVectorType operator&(const BitSpan& other) const;

  /// \brief Perform OR operation on every bit of BitSpan and BitVector.
  /// \param other
  template <typename BitVectorType = AlignedBitVector>
  BitVectorType operator|(const BitVectorType& other) const;

  /// \brief Perform OR operation on every bit of both BitSpans.
  /// \param other
  template <typename BitVectorType = AlignedBitVector>
  BitVectorType operator|(const BitSpan& other) const;

  /// \brief Perform XOR operation on every bit of BitSpan and BitVector.
  /// \param other
  template <typename BitVectorType = AlignedBitVector>
  BitVectorType operator^(const BitVectorType& other) const;

  /// \brief Perform XOR operation on every bit of both BitSpans.
  /// \param other
  template <typename BitVectorType = AlignedBitVector>
  BitVectorType operator^(const BitSpan& other) const;

  /// \brief Perform AND-assign operation on every bit of BitSpan and BitVector.
  /// \param other
  template <typename BitVectorType = AlignedBitVector>
  BitSpan& operator&=(const BitVectorType& other);

  /// \brief Perform AND-assign operation on every bit of both BitSpans.
  /// \param other
  BitSpan& operator&=(const BitSpan& other);

  /// \brief Perform OR-assign operation on every bit of BitSpan and BitVector.
  /// \param other
  template <typename BitVectorType = AlignedBitVector>
  BitSpan& operator|=(const BitVectorType& other);

  /// \brief Perform OR-assign operation on every bit of both BitSpans.
  /// \param other
  BitSpan& operator|=(const BitSpan& other);

  /// \brief Perform XOR-assign operation on every bit of BitSpan and BitVector.
  /// \param other
  template <typename BitVectorType = AlignedBitVector>
  BitSpan& operator^=(const BitVectorType& other);

  /// \brief Perform XOR-assign operation on every bit of both BitSpans.
  /// \param other
  BitSpan& operator^=(const BitSpan& other);

  /// \brief Get bit at given position.
  /// \param position
  bool Get(const std::size_t position) const;

  /// \brief Get bit at given position in the BitSpan.
  /// \param position
  bool operator[](const std::size_t position) const { return Get(position); }

  /// \brief Sets all bits to \p value.
  /// \param value
  void Set(const bool value);

  /// \brief Sets bit at \p postion to \p value.
  /// \param value
  /// \param position
  void Set(const bool value, const std::size_t position);

  /// \brief Get const reference to content of BitSpan.
  const std::byte* GetData() const noexcept { return pointer_; }

  /// \brief Get reference to content of BitSpan.
  std::byte* GetMutableData() noexcept { return pointer_; }

  /// \brief Get size of BitSpan.
  std::size_t GetSize() const noexcept { return bit_size_; }

  /// \brief Returns a string representation of this BitVector.
  std::string AsString() const noexcept;

  /// \brief Returns true if Allocator is aligned allocator.
  bool IsAligned() const noexcept { return aligned_; }

  /// \brief copies the first (dest_to - dest_from) bits from other to the bits [dest_from,
  /// dest_to) in this. \throws std::out_of_range if accessing invalid positions in this or other.
  template <typename BitVectorType>
  void Copy(const std::size_t dest_from, const std::size_t dest_to, BitVectorType& other);

  /// \brief copies other to this[dest_from...dest_from+GetSize()].
  /// \throws an std::out_of_range exception if this is smaller than other.
  template <typename BitVectorType>
  void Copy(const std::size_t dest_from, BitVectorType& other);

  /// \brief copies the first (dest_to - dest_from) bits from other to the bits [dest_from,
  /// dest_to) in this. \throws an std::out_of_range exception if accessing invalid positions in
  /// this or other.
  void Copy(const std::size_t dest_from, const std::size_t dest_to, BitSpan& other);

  /// \brief copies the first (dest_to - dest_from) bits from other to the bits [dest_from,
  /// dest_to) in this. \throws an std::out_of_range exception if accessing invalid positions in
  /// this or other.
  void Copy(const std::size_t dest_from, const std::size_t dest_to, BitSpan&& other);

  /// \brief copies other to this[dest_from...dest_from+GetSize()].
  /// \throws an std::out_of_range exception if this is smaller than other.
  void Copy(const std::size_t dest_from, BitSpan& other);

  /// \brief copies other to this[dest_from...dest_from+GetSize()].
  /// \throws an std::out_of_range exception if this is smaller than other.
  void Copy(const std::size_t dest_from, BitSpan&& other);

  std::size_t HammingWeight() const;

 private:
  std::byte* pointer_;
  std::size_t bit_size_;
  bool aligned_;
};

/// \brief Output string representation of BitVector to std::ostream.
std::ostream& operator<<(std::ostream& os, const BitSpan& bit_span);

}  // namespace encrypto::motion
