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

#pragma once

#include <algorithm>
#include <array>
#include <boost/align/aligned_allocator.hpp>
#include <vector>
#include "config.h"

namespace encrypto::motion {

// XXX this should be a class due to its many functions (see
// https://google.github.io/styleguide/cppguide.html#Structs_vs._Classes).
/// \brief Block of aligned 128 bit / 16 B.
struct Block128 {
  // default constructor: uninitialized
  Block128(){};

  // XXX Copy and move constructors/assignments can be defaulted.
  // XXX Ássignments do not check for self-assignment.

  // copy constructor
  Block128(const Block128& other) : byte_array(other.byte_array) {}

  // move constructor
  Block128(Block128&& other) : byte_array(std::move(other.byte_array)) {}

  // copy assignment
  Block128& operator=(const Block128& other) {
    byte_array = other.byte_array;
    return *this;
  }

  // move assignment
  Block128& operator=(Block128&& other) {
    byte_array = std::move(other.byte_array);
    return *this;
  }

  // default destructor
  ~Block128() = default;

  /// \brief Create a zero-initialized Block128.
  static Block128 MakeZero() {
    Block128 result;
    result.SetToZero();
    return result;
  }

  /// \brief Create a random-initialized Block128.
  static Block128 MakeRandom() {
    Block128 result;
    result.SetToRandom();
    return result;
  }

  /// \brief Load data from memory and store it in Block128.
  /// \param pointer Pointer to the data to be loaded.
  static Block128 MakeFromMemory(const std::byte* pointer) {
    Block128 result;
    result.LoadFromMemory(pointer);
    return result;
  }

  /// \brief Compares two Block128 for equality.
  /// \param other
  bool operator==(const Block128& other) const { return byte_array == other.byte_array; }

  /// \brief Compares two Block128 for inequality.
  /// \param other
  bool operator!=(const Block128& other) const { return byte_array != other.byte_array; }

  /// \brief Performs XOR-assign operation between two Block128.
  /// \param other
  Block128& operator^=(const Block128& __restrict__ other) {
    auto k0 =
        reinterpret_cast<std::byte*>(__builtin_assume_aligned(byte_array.data(), kBlockAlignment));
    auto k1 = reinterpret_cast<const std::byte*>(
        __builtin_assume_aligned(other.byte_array.data(), kBlockAlignment));
    std::transform(k0, k0 + kBlockSize, k1, k0, [](auto a, auto b) { return a ^ b; });
    return *this;
  }

  /// \brief Performs XOR operation between two Block128.
  /// \param other
  Block128 operator^(const Block128& other) const {
    Block128 result = *this;
    result ^= other;
    return result;
  }

  /// \brief Performs XOR-assign operation between this Block128 and a non-overlapping arbitrary
  /// range of bytes. \param other
  Block128& operator^=(const std::byte* __restrict__ other) {
    auto k0 =
        reinterpret_cast<std::byte*>(__builtin_assume_aligned(byte_array.data(), kBlockAlignment));
    std::transform(k0, k0 + kBlockSize, other, k0, [](auto a, auto b) { return a ^ b; });
    return *this;
  }

  /// \brief Performs XOR operation between this Block128 and a non-overlapping arbitrary range of
  /// bytes. \param other
  Block128 operator^(const std::byte* __restrict__ other) const {
    Block128 result = *this;
    result ^= other;
    return result;
  }

  /// \brief Set this Block128 to zero.
  void SetToZero() {
    auto k0 =
        reinterpret_cast<std::byte*>(__builtin_assume_aligned(byte_array.data(), kBlockAlignment));
    std::fill(k0, k0 + kBlockSize, std::byte(0x00));
  }

  /// \brief Set this Block128 to a random value.
  void SetToRandom();

  /// \brief Put 16 bytes starting at \p pointer into this Block128.
  /// \param pointer
  void LoadFromMemory(const std::byte* pointer) {
    std::copy(pointer, pointer + kBlockSize, byte_array.data());
  }

  /// \brief Format this Block128 as string of hexadecimal digits.
  std::string AsString() const;

  /// \brief Get a pointer to the beginning of this Block128.
  std::byte* data() { return byte_array.data(); }
  const std::byte* data() const { return byte_array.data(); }

  /// \brief Get size of Block128.
  static constexpr std::size_t size() { return kBlockSize; }

  /// \brief Get alignment of Block128.
  static constexpr std::size_t alignment() { return kBlockAlignment; }

  // Size in bytes of Block128.
  static constexpr std::size_t kBlockSize = 16;

  // Alignment of Block128
  static constexpr std::size_t kBlockAlignment = 16;

  // The underlying array of bytes
  alignas(kBlockAlignment) std::array<std::byte, 16> byte_array;
};

// XXX this should be a class due to its many functions (see
// https://google.github.io/styleguide/cppguide.html#Structs_vs._Classes).
/// \brief Vector of 128 bit / 16 B blocks.
struct Block128Vector {
  static constexpr std::size_t kBlockAlignment = kAlignment;
  using Allocator = boost::alignment::aligned_allocator<Block128, kBlockAlignment>;
  using Container = std::vector<Block128, Allocator>;

  // create an empty vector
  Block128Vector() = default;

  // XXX Copy and move constructors/assignments can be defaulted.
  // XXX Ássignments do not check for self-assignment.

  // copy constructor
  Block128Vector(const Block128Vector& other) : block_vector(other.block_vector) {}

  // move constructor
  Block128Vector(Block128Vector&& other) : block_vector(std::move(other.block_vector)) {}

  // copy assignment
  Block128Vector& operator=(const Block128Vector& other) {
    block_vector = other.block_vector;
    return *this;
  }
  // move assignment
  Block128Vector& operator=(Block128Vector&& other) {
    block_vector = std::move(other.block_vector);
    return *this;
  }

  // default destructor
  ~Block128Vector() = default;

  /// \brief Creates uninitialized vector of size elements.
  /// \param size
  Block128Vector(std::size_t size) : block_vector(size) {}

  /// \brief Creates initialized vector of size elements with given value.
  /// \param size
  /// \param value
  Block128Vector(std::size_t size, const Block128& value) : block_vector(size, value) {}

  /// \brief Creates initialized vector of \p size elements read from memory.
  /// \param size
  /// \param pointer Pointer to memory.
  Block128Vector(std::size_t size, const void* __restrict__ pointer) : block_vector(size) {
    auto input = reinterpret_cast<const std::byte*>(pointer);
    auto buffer = reinterpret_cast<std::byte*>(block_vector[0].data());
    std::copy(input, input + 16 * size, buffer);
  }

  /// \brief Creates initialized vector of \p size elements read from memory.
  /// \param size
  /// \param pointer Pointer to memory.
  Block128Vector(Container::const_iterator source_begin, const Container::const_iterator source_end)
      : block_vector(std::distance(source_begin, source_end)) {
    auto this_begin = block_vector.begin();
    while (source_begin != source_end) {
      *this_begin = *source_begin;
      std::advance(source_begin, 1);
      std::advance(this_begin, 1);
    }
  }

  /// \brief Access Block128 at \p index. Throws an exception if index is out of bounds.
  /// \param index
  Block128& at(std::size_t index) { return block_vector.at(index); };
  const Block128& at(std::size_t index) const { return block_vector.at(index); };

  /// \brief Get pointer to the first Block128.
  Block128* data() { return block_vector.data(); }

  /// \brief Get const pointer to the first Block128.
  const Block128* data() const { return block_vector.data(); }

  /// \brief Get size of Block128Vector.
  std::size_t size() const { return block_vector.size(); };

  /// \brief Get size of the Block128Vector content in bytes.
  std::size_t ByteSize() const { return block_vector.size() * Block128::size(); };

  /// \brief Resize the Block128Vector to contain \p new_size elements.
  ///        New elements are left uninitialized.
  /// \param new_size
  void resize(std::size_t new_size) { block_vector.resize(new_size); }

  /// \brief Resize the Block128Vector to contain \p new_size elements.
  ///        New elements are set to \p value.
  /// \param new_size
  /// \param value
  void resize(std::size_t new_size, const Block128& value) { block_vector.resize(new_size, value); }

  /// \brief Returns an iterator to the first element of the Block128Vector.
  auto begin() { return block_vector.begin(); }

  /// \brief Returns a const iterator to the first element of the Block128Vector.
  auto begin() const { return block_vector.begin(); }

  /// \brief Returns an iterator to the element following the last element of the Block128Vector.
  auto end() { return block_vector.end(); }

  /// \brief Returns a const iterator to the element following the last element of the
  /// Block128Vector.
  auto end() const { return block_vector.end(); }

  /// \brief Set all Block128 in this vector to zero.
  void SetToZero() {
    auto start = reinterpret_cast<std::byte* __restrict__>(
        __builtin_assume_aligned(data(), kBlockAlignment));
    std::fill(start, start + ByteSize(), std::byte(0x00));
  }

  /// \brief Set all Block128 in this vector to random values.
  void SetToRandom();

  /// \brief Perform a XOR-assign operation between all the Block128 in this vector
  ///        and the Block128 in a different one of same size.
  /// \param other
  /// \pre \p other is has the same size as this Block128Vector.
  Block128Vector& operator^=(const Block128Vector& __restrict__ other) {
    assert(size() == other.size());
    auto k0 = reinterpret_cast<std::byte* __restrict__>(
        __builtin_assume_aligned(block_vector.data(), kBlockAlignment));
    auto k1 = reinterpret_cast<const std::byte* __restrict__>(
        __builtin_assume_aligned(other.block_vector.data(), kBlockAlignment));
    std::transform(k0, k0 + 16 * size(), k1, k0, [](auto a, auto b) { return a ^ b; });
    return *this;
  }

  /// \brief Perform a XOR operation between all the Block128 in this vector
  ///        and the Block128 in a different one of same size.
  /// \param other
  /// \pre \p other is has the same size as this Block128Vector.
  Block128Vector operator^(const Block128Vector& __restrict__ other) const {
    assert(size() == other.size());
    Block128Vector result(size());
    auto k0 = reinterpret_cast<const std::byte* __restrict__>(
        __builtin_assume_aligned(block_vector.data(), kBlockAlignment));
    auto k1 = reinterpret_cast<const std::byte* __restrict__>(
        __builtin_assume_aligned(other.block_vector.data(), kBlockAlignment));
    auto kout = reinterpret_cast<std::byte* __restrict__>(
        __builtin_assume_aligned(result.block_vector.data(), kBlockAlignment));
    std::transform(k0, k0 + 16 * size(), k1, kout, [](auto a, auto b) { return a ^ b; });
    return result;
  }

  /// \brief Access Block128 at \p index. Undefined behaviour if index is out of bounds.
  /// \param index
  Block128& operator[](std::size_t index) { return block_vector[index]; };

  /// \brief Access Block128 at \p index. Undefined behaviour if index is out of bounds.
  /// \param index
  const Block128& operator[](std::size_t index) const { return block_vector[index]; };

  /// \brief Creates a zero-filled vector of \p size elements.
  /// \param size
  static Block128Vector MakeZero(std::size_t size) {
    auto result = Block128Vector(size);
    auto start = reinterpret_cast<std::byte* __restrict__>(
        __builtin_assume_aligned(result.data(), kBlockAlignment));
    std::fill(start, start + result.ByteSize(), std::byte(0x00));
    return result;
  }

  /// \brief Creates a vector of \p size elements filled with random data.
  /// \param size
  static Block128Vector MakeRandom(std::size_t size) {
    Block128Vector result(size);
    result.SetToRandom();
    return result;
  }

  // underlying vector of blocks
  Container block_vector;
};

}  // namespace encrypto::motion
