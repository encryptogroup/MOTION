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

// block of aligned 128 bit / 16 B
struct Block128 {
  // default constructor: uninitialized
  Block128(){};

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

  // create a zero-initialized block
  static Block128 MakeZero() {
    Block128 result;
    result.SetToZero();
    return result;
  }

  // create a random-initialized block
  static Block128 MakeRandom() {
    Block128 result;
    result.SetToRandom();
    return result;
  }

  // load data from memory and store it in a block
  static Block128 MakeFromMemory(const std::byte* pointer) {
    Block128 result;
    result.LoadFromMemory(pointer);
    return result;
  }

  bool operator==(const Block128& other) const { return byte_array == other.byte_array; }

  bool operator!=(const Block128& other) const { return byte_array != other.byte_array; }

  // xor this block with a *different* one
  Block128& operator^=(const Block128& __restrict__ other) {
    auto k0 =
        reinterpret_cast<std::byte*>(__builtin_assume_aligned(byte_array.data(), kBlockAlignment));
    auto k1 = reinterpret_cast<const std::byte*>(
        __builtin_assume_aligned(other.byte_array.data(), kBlockAlignment));
    std::transform(k0, k0 + kBlockSize, k1, k0, [](auto a, auto b) { return a ^ b; });
    return *this;
  }
  Block128 operator^(const Block128& other) const {
    Block128 result = *this;
    result ^= other;
    return result;
  }

  // xor this block with an arbitrary range of bytes (which is not the block itself)
  Block128& operator^=(const std::byte* __restrict__ other) {
    auto k0 =
        reinterpret_cast<std::byte*>(__builtin_assume_aligned(byte_array.data(), kBlockAlignment));
    std::transform(k0, k0 + kBlockSize, other, k0, [](auto a, auto b) { return a ^ b; });
    return *this;
  }
  Block128 operator^(const std::byte* __restrict__ other) const {
    Block128 result = *this;
    result ^= other;
    return result;
  }

  // set this block to zeros
  void SetToZero() {
    auto k0 =
        reinterpret_cast<std::byte*>(__builtin_assume_aligned(byte_array.data(), kBlockAlignment));
    std::fill(k0, k0 + kBlockSize, std::byte(0x00));
  }

  // set this block to random
  void SetToRandom();

  // put 16 B from a given memory location into this block
  void LoadFromMemory(const std::byte* pointer) {
    std::copy(pointer, pointer + kBlockSize, byte_array.data());
  }

  // format this block as string of hexadecimal digits
  std::string AsString() const;

  // get pointer to the beginning of the block
  std::byte* data() { return byte_array.data(); }
  const std::byte* data() const { return byte_array.data(); }

  // get size of this block
  static constexpr std::size_t size() { return kBlockSize; }

  // get alignment of this block
  static constexpr std::size_t alignment() { return kBlockAlignment; }

  static constexpr std::size_t kBlockSize = 16;

  static constexpr std::size_t kBlockAlignment = 16;

  // the underlying array of bytes
  alignas(kBlockAlignment) std::array<std::byte, 16> byte_array;
};

// vector of 128 bit / 16 B blocks
struct Block128Vector {
  // copy constructor
  Block128Vector(const Block128Vector& other) : block_vector(other.block_vector) {}

  // move constructor
  Block128Vector(Block128Vector&& other) : block_vector(std::move(other.block_vector)) {}

  // create uninitialized vector of size elements
  Block128Vector(std::size_t size) : block_vector(size) {}

  // create initialized vector of size elements with given value
  Block128Vector(std::size_t size, const Block128& value) : block_vector(size, value) {}

  // create an empty vector
  Block128Vector() = default;

  // create initialized vector of size elements read from memory
  Block128Vector(std::size_t size, const void* __restrict__ p) : block_vector(size) {
    auto input = reinterpret_cast<const std::byte*>(p);
    auto buffer = reinterpret_cast<std::byte*>(block_vector[0].data());
    std::copy(input, input + 16 * size, buffer);
  }

  // default destructor
  ~Block128Vector() = default;

  // create zero-filled vector of size elements
  static Block128Vector MakeZero(std::size_t size) {
    auto result = Block128Vector(size);
    auto start = reinterpret_cast<std::byte* __restrict__>(
        __builtin_assume_aligned(result.data(), kBlockAlignment));
    std::fill(start, start + result.ByteSize(), std::byte(0x00));
    return result;
  }

  // create vector of size elements filled with random data
  static Block128Vector MakeRandom(std::size_t size) {
    Block128Vector result(size);
    result.SetToRandom();
    return result;
  }

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

  // xor the blocks in this vector with the blocks in a *different* one of same size
  Block128Vector& operator^=(const Block128Vector& __restrict__ other) {
    assert(size() == other.size());
    auto k0 = reinterpret_cast<std::byte* __restrict__>(
        __builtin_assume_aligned(block_vector.data(), kBlockAlignment));
    auto k1 = reinterpret_cast<const std::byte* __restrict__>(
        __builtin_assume_aligned(other.block_vector.data(), kBlockAlignment));
    std::transform(k0, k0 + 16 * size(), k1, k0, [](auto a, auto b) { return a ^ b; });
    return *this;
  }
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

  // set this vector to zero
  void SetToZero() {
    auto start = reinterpret_cast<std::byte* __restrict__>(
        __builtin_assume_aligned(data(), kBlockAlignment));
    std::fill(start, start + ByteSize(), std::byte(0x00));
  }

  // set this vector to random
  void SetToRandom();

  // subscript operator
  Block128& operator[](std::size_t index) { return block_vector[index]; };
  const Block128& operator[](std::size_t index) const { return block_vector[index]; };

  // at access operator
  Block128& at(std::size_t index) { return block_vector.at(index); };
  const Block128& at(std::size_t index) const { return block_vector.at(index); };

  // get pointer to the first block
  Block128* data() { return block_vector.data(); }
  const Block128* data() const { return block_vector.data(); }

  // number of blocks in the vector
  std::size_t size() const { return block_vector.size(); };

  // size of the total vector in bytes
  std::size_t ByteSize() const { return block_vector.size() * Block128::size(); };

  // resize the vector s.t. new elements are uninitialized
  void resize(std::size_t new_size) { block_vector.resize(new_size); }

  // resize the vector s.t. new elements initialized with given value
  void resize(std::size_t new_size, const Block128& value) { block_vector.resize(new_size, value); }

  // iterator support
  auto begin() { return block_vector.begin(); }
  auto begin() const { return block_vector.begin(); }
  auto end() { return block_vector.end(); }
  auto end() const { return block_vector.end(); }

  static constexpr std::size_t kBlockAlignment = kAlignment;

  // underlying vector of blocks
  std::vector<Block128, boost::alignment::aligned_allocator<Block128, kBlockAlignment>>
      block_vector;
};

}  // namespace encrypto::motion
