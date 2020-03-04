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

namespace ENCRYPTO {

// block of aligned 128 bit / 16 B
struct block128_t {
  // default constructor: uninitialized
  block128_t(){};

  // copy constructor
  block128_t(const block128_t& other) : byte_array(other.byte_array) {}

  // move constructor
  block128_t(block128_t&& other) : byte_array(std::move(other.byte_array)) {}

  // copy assignment
  block128_t& operator=(const block128_t& other) {
    byte_array = other.byte_array;
    return *this;
  }

  // move assignment
  block128_t& operator=(block128_t&& other) {
    byte_array = std::move(other.byte_array);
    return *this;
  }

  // default destructor
  ~block128_t() = default;

  // create a zero-initialized block
  static block128_t make_zero() {
    block128_t result;
    result.set_to_zero();
    return result;
  }

  // create a random-initialized block
  static block128_t make_random() {
    block128_t result;
    result.set_to_random();
    return result;
  }

  // load data from memory and store it in a block
  static block128_t make_from_memory(const std::byte* p) {
    block128_t result;
    result.load_from_memory(p);
    return result;
  }

  bool operator==(const block128_t& other) const { return byte_array == other.byte_array; }

  bool operator!=(const block128_t& other) const { return byte_array != other.byte_array; }

  // xor this block with a *different* one
  block128_t& operator^=(const block128_t& __restrict__ other) {
    auto k0 = reinterpret_cast<std::byte*>(__builtin_assume_aligned(byte_array.data(), alignment));
    auto k1 = reinterpret_cast<const std::byte*>(
        __builtin_assume_aligned(other.byte_array.data(), alignment));
    std::transform(k0, k0 + 16, k1, k0, [](auto a, auto b) { return a ^ b; });
    return *this;
  }
  block128_t operator^(const block128_t& other) const {
    block128_t result = *this;
    result ^= other;
    return result;
  }

  // xor this block with an arbitrary range of bytes (which is not the block itself)
  block128_t& operator^=(const std::byte* __restrict__ other) {
    auto k0 = reinterpret_cast<std::byte*>(__builtin_assume_aligned(byte_array.data(), alignment));
    std::transform(k0, k0 + 16, other, k0, [](auto a, auto b) { return a ^ b; });
    return *this;
  }
  block128_t operator^(const std::byte* __restrict__ other) const {
    block128_t result = *this;
    result ^= other;
    return result;
  }

  // set this block to zeros
  void set_to_zero() {
    auto k0 = reinterpret_cast<std::byte*>(__builtin_assume_aligned(byte_array.data(), alignment));
    std::fill(k0, k0 + 16, std::byte(0x00));
  }

  // set this block to random
  void set_to_random();

  // put 16 B from a given memory location into this block
  void load_from_memory(const std::byte* p) { std::copy(p, p + 16, byte_array.data()); }

  // format this block as string of hexadecimal digits
  std::string as_string() const;

  // get pointer to the beginning of the block
  std::byte* data() { return byte_array.data(); }
  const std::byte* data() const { return byte_array.data(); }

  // get size of this block
  static constexpr std::size_t size() { return 16; }

  // get alignment of this block
  static constexpr size_t alignment = 16;

  // the underlying array of bytes
  alignas(alignment) std::array<std::byte, 16> byte_array;
};

// vector of 128 bit / 16 B blocks
struct block128_vector {
  // copy constructor
  block128_vector(const block128_vector& other) : block_vector(other.block_vector) {}

  // move constructor
  block128_vector(block128_vector&& other) : block_vector(std::move(other.block_vector)) {}

  // create uninitialized vector of size elements
  block128_vector(std::size_t size) : block_vector(size) {}

  // create initialized vector of size elements with given value
  block128_vector(std::size_t size, const block128_t& value) : block_vector(size, value) {}

  // create an empty vector
  block128_vector() = default;

  // create initialized vector of size elements read from memory
  block128_vector(std::size_t size, const void* __restrict__ p) : block_vector(size) {
    auto input = reinterpret_cast<const std::byte*>(p);
    auto buffer = reinterpret_cast<std::byte*>(block_vector[0].data());
    std::copy(input, input + 16 * size, buffer);
  }

  // default destructor
  ~block128_vector() = default;

  // create zero-filled vector of size elements
  static block128_vector make_zero(std::size_t size) {
    auto result = block128_vector(size);
    auto start = reinterpret_cast<std::byte* __restrict__>(
        __builtin_assume_aligned(result.data(), alignment));
    std::fill(start, start + result.byte_size(), std::byte(0x00));
    return result;
  }

  // create vector of size elements filled with random data
  static block128_vector make_random(std::size_t size) {
    block128_vector result(size);
    result.set_to_random();
    return result;
  }

  // copy assignment
  block128_vector& operator=(const block128_vector& other) {
    block_vector = other.block_vector;
    return *this;
  }
  // move assignment
  block128_vector& operator=(block128_vector&& other) {
    block_vector = std::move(other.block_vector);
    return *this;
  }

  // xor the blocks in this vector with the blocks in a *different* one of same size
  block128_vector& operator^=(const block128_vector& __restrict__ other) {
    assert(size() == other.size());
    auto k0 = reinterpret_cast<std::byte* __restrict__>(
        __builtin_assume_aligned(block_vector.data(), alignment));
    auto k1 = reinterpret_cast<const std::byte* __restrict__>(
        __builtin_assume_aligned(other.block_vector.data(), alignment));
    std::transform(k0, k0 + 16 * size(), k1, k0, [](auto a, auto b) { return a ^ b; });
    return *this;
  }
  block128_vector operator^(const block128_vector& __restrict__ other) const {
    assert(size() == other.size());
    block128_vector result(size());
    auto k0 = reinterpret_cast<const std::byte* __restrict__>(
        __builtin_assume_aligned(block_vector.data(), alignment));
    auto k1 = reinterpret_cast<const std::byte* __restrict__>(
        __builtin_assume_aligned(other.block_vector.data(), alignment));
    auto kout = reinterpret_cast<std::byte* __restrict__>(
        __builtin_assume_aligned(result.block_vector.data(), alignment));
    std::transform(k0, k0 + 16 * size(), k1, kout, [](auto a, auto b) { return a ^ b; });
    return result;
  }

  // set this vector to random
  void set_to_random();

  // subscript operator
  block128_t& operator[](std::size_t index) { return block_vector[index]; };
  const block128_t& operator[](std::size_t index) const { return block_vector[index]; };

  // at access operator
  block128_t& at(std::size_t index) { return block_vector.at(index); };
  const block128_t& at(std::size_t index) const { return block_vector.at(index); };

  // get pointer to the first block
  block128_t* data() { return block_vector.data(); }
  const block128_t* data() const { return block_vector.data(); }

  // number of blocks in the vector
  std::size_t size() const { return block_vector.size(); };

  // size of the total vector in bytes
  std::size_t byte_size() const { return block_vector.size() * block128_t::size(); };

  // resize the vector s.t. new elements are uninitialized
  void resize(std::size_t new_size) { block_vector.resize(new_size); }

  // resize the vector s.t. new elements initialized with given value
  void resize(std::size_t new_size, const block128_t& value) {
    block_vector.resize(new_size, value);
  }

  // iterator support
  auto begin() { return block_vector.begin(); }
  auto begin() const { return block_vector.begin(); }
  auto end() { return block_vector.end(); }
  auto end() const { return block_vector.end(); }

  // underlying vector of blocks
  std::vector<block128_t, boost::alignment::aligned_allocator<block128_t, MOTION::MOTION_ALIGNMENT>>
      block_vector;

  static constexpr std::size_t alignment = MOTION::MOTION_ALIGNMENT;
};

}  // namespace ENCRYPTO
