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

#include "boost/align/aligned_allocator.hpp"
#include "fmt/format.h"

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

  explicit BitVector(bool value) noexcept : data_vector_({std::byte(value)}), bit_size_(1) {}

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

  explicit BitVector(std::size_t n_bits, bool value = false) noexcept : bit_size_(n_bits) {
    if (n_bits > 0u) {
      const std::byte value_byte = value ? std::byte(0xFF) : std::byte(0);
      const auto byte_size = ABYN::Helpers::Convert::BitsToBytes(n_bits);
      data_vector_.reserve(byte_size);

      while (data_vector_.size() < byte_size) {
        data_vector_.push_back(value_byte);
      }

      if (value) {
        TruncateToFit();
      }
    }
  }

  BitVector(const unsigned char* buf, std::size_t bits)
      : BitVector(reinterpret_cast<const std::byte*>(buf), bits) {}

  BitVector(const std::byte* buf, std::size_t bits) : bit_size_(bits) {
    data_vector_.insert(data_vector_.begin(), buf, buf + ABYN::Helpers::Convert::BitsToBytes(bits));

    TruncateToFit();
  }

  BitVector(const std::vector<std::byte>& data, std::size_t n_bits) : bit_size_(n_bits) {
    const std::size_t byte_size = ABYN::Helpers::Convert::BitsToBytes(n_bits);
    if (byte_size > data.size()) {
      throw std::out_of_range(fmt::format("BitVector: accessing {} of {}", byte_size, data.size()));
    }
    data_vector_.insert(data_vector_.begin(), data.begin(), data.begin() + byte_size);

    TruncateToFit();
  }

  BitVector(std::vector<std::byte>&& data, std::size_t n_bits) : bit_size_(n_bits) {
    const std::size_t byte_size = ABYN::Helpers::Convert::BitsToBytes(n_bits);
    if (byte_size > data.size()) {
      throw std::out_of_range(fmt::format("BitVector: accessing {} of {}", byte_size, data.size()));
    }
    data_vector_.assign(data.begin(), data.begin() + byte_size);

    TruncateToFit();
  }

  BitVector(const std::vector<bool>& data, std::size_t n_bits) : bit_size_(n_bits) {
    if (bit_size_ > data.size()) {
      throw std::out_of_range(fmt::format("BitVector: accessing {} of {}", n_bits, data.size()));
    }

    const std::size_t byte_size = ABYN::Helpers::Convert::BitsToBytes(n_bits);
    constexpr std::byte zero_byte = std::byte();
    data_vector_.reserve(byte_size);
    while (data_vector_.size() < byte_size) {
      data_vector_.push_back(zero_byte);
    }

    for (auto i = 0ull; i < data.size(); ++i) {
      if (data.at(i)) {
        Set(data.at(i), i);
      }
    }
  }

  bool Empty() { return bit_size_ == 0; }

  void Invert() {
    for (auto i = 0ull; i < data_vector_.size(); ++i) {
      data_vector_.at(i) = ~data_vector_.at(i);
    }
    TruncateToFit();
  }

  template <typename T2>
  bool operator!=(const BitVector<T2>& other) const noexcept {
    return !(*this == other);
  }

  template <typename T2>
  BitVector operator&(const BitVector<T2>& other) const noexcept {
    auto result = *this;
    result &= other;
    return result;
  }

  template <typename T2>
  BitVector operator^(const BitVector<T2>& other) const noexcept {
    auto result = *this;
    result ^= other;
    return result;
  }

  template <typename T2>
  BitVector operator|(const BitVector<T2>& other) const noexcept {
    auto result = *this;
    result |= other;
    return result;
  }

  bool operator[](std::size_t pos) const { return Get(pos); }

  auto GetSize() const noexcept { return bit_size_; }

  const auto& GetData() const noexcept { return data_vector_; }

  auto& GetMutableData() noexcept { return data_vector_; }

  void Assign(const BitVector& other) noexcept { *this = other; }

  void Assign(BitVector&& other) noexcept { *this = std::move(other); }

  BitVector& operator=(const BitVector& other) noexcept {
    bit_size_ = other.bit_size_;
    data_vector_ = other.data_vector_;
    return *this;
  }

  BitVector& operator=(BitVector&& other) noexcept {
    bit_size_ = other.bit_size_;
    data_vector_ = std::move(other.data_vector_);
    return *this;
  }

  template <typename T2>
  bool operator==(const BitVector<T2>& other) const noexcept {
    if (bit_size_ != other.bit_size_) {
      return false;
    }
    assert(data_vector_.size() == other.data_vector_.size());

    for (auto i = 0ull; i < data_vector_.size(); ++i) {
      if (data_vector_.at(i) != other.data_vector_.at(i)) {
        return false;
      }
    }

    return true;
  }

  void Set(bool value) noexcept {
    for (auto& byte : data_vector_) {
      if (value) {  // set
        byte |= std::byte(0xFFu);
      } else {  // unset
        byte &= std::byte(0u);
      }
    }

    if (value) {
      TruncateToFit();
    }
  }

  void Set(bool value, std::size_t pos) {
    if (pos >= bit_size_) {
      throw std::out_of_range(fmt::format("BitVector: accessing {} of {}", pos, bit_size_));
    }

    std::size_t byte_offset = pos / 8;
    std::size_t bit_offset = pos % 8;

    if (value) {
      data_vector_.at(byte_offset) |= SET_BIT_MASK[bit_offset];
    } else {
      data_vector_.at(byte_offset) &= UNSET_BIT_MASK[bit_offset];
    }
  }

  bool Get(std::size_t pos) const {
    if (pos >= bit_size_) {
      throw std::out_of_range(fmt::format("BitVector: accessing {} of {}", pos, bit_size_));
    }

    std::size_t byte_offset = pos / 8;
    std::size_t bit_offset = pos % 8;

    auto result = data_vector_.at(byte_offset);
    result &= SET_BIT_MASK[bit_offset];

    return result == SET_BIT_MASK[bit_offset];
  }

  template <typename T2>
  BitVector& operator&=(const BitVector<T2>& other) noexcept {
    const auto max_bit_size = std::max(bit_size_, other.bit_size_);
    const auto min_byte_size = std::min(data_vector_.size(), other.data_vector_.size());

    Resize(max_bit_size, true);

#pragma omp simd
    for (auto i = 0ull; i < min_byte_size; ++i) {
      data_vector_.at(i) &= other.data_vector_.at(i);
    }
    return *this;
  }

  template <typename T2>
  BitVector& operator^=(const BitVector<T2>& other) noexcept {
    const auto max_bit_size = std::max(bit_size_, other.GetSize());
    const auto min_byte_size = std::min(data_vector_.size(), other.GetData().size());

    Resize(max_bit_size, true);

#pragma omp simd
    for (auto i = 0ull; i < min_byte_size; ++i) {
      data_vector_.at(i) ^= other.GetData().at(i);
    }

    if (data_vector_.size() < other.GetData().size()) {
      for (auto i = min_byte_size; i < other.GetData().size(); ++i) {
        data_vector_.at(i) ^= other.GetData().at(i);
      }
    }
    return *this;
  }

  template <typename T2>
  BitVector& operator|=(const BitVector<T2>& other) noexcept {
    const auto max_bit_size = std::max(bit_size_, other.bit_size_);
    const auto min_byte_size = std::min(data_vector_.size(), other.GetData().size());
    const auto max_byte_size = ABYN::Helpers::Convert::BitsToBytes(max_bit_size);

    Resize(max_bit_size, true);

#pragma omp simd
    for (auto i = 0ull; i < min_byte_size; ++i) {
      data_vector_.at(i) |= other.GetData().at(i);
    }

    if (min_byte_size == max_byte_size) {
#pragma omp simd
      for (auto i = min_byte_size; i < max_byte_size; ++i) {
        data_vector_.at(i) = other.GetData().at(i);
      }
    }
    return *this;
  }

  void Resize(std::size_t n_bits, bool zero_fill = false) noexcept {
    if (bit_size_ == n_bits) {
      return;
    }
    bit_size_ = n_bits;
    const auto byte_size = ABYN::Helpers::Convert::BitsToBytes(bit_size_);
    if (zero_fill) {
      constexpr std::byte zero_byte = std::byte();
      data_vector_.reserve(byte_size);
      while (data_vector_.size() < byte_size) {
        data_vector_.push_back(zero_byte);
      }
    } else {
      data_vector_.resize(byte_size);
    }
    TruncateToFit();
  }

  void Append(bool bit) noexcept {
    const auto bit_offset = bit_size_ % 8;
    if (bit_offset == 0u) {
      if (bit) {
        data_vector_.push_back(SET_BIT_MASK[0]);
      } else {
        data_vector_.push_back(std::byte(0));
      }
    } else {
      if (bit) {
        data_vector_.at(data_vector_.size() - 1) |= SET_BIT_MASK[bit_offset];
      }
    }
    ++bit_size_;
  }

  void Append(const BitVector& other) noexcept {
    if (other.bit_size_ > 0u) {
      const auto old_bit_offset = bit_size_ % 8;

      const auto new_bit_size = bit_size_ + other.bit_size_;
      const auto new_byte_size = ABYN::Helpers::Convert::BitsToBytes(new_bit_size);

      if (new_bit_size <= 8u) {
        if (bit_size_ == 0u) {
          data_vector_ = other.data_vector_;
        } else {
          data_vector_.at(0) |= (other.data_vector_.at(0) >> old_bit_offset);
        }
      } else if (old_bit_offset == 0u) {
        data_vector_.insert(data_vector_.end(), other.data_vector_.begin(),
                            other.data_vector_.end());
      } else if (old_bit_offset + other.bit_size_ <= 8u) {
        data_vector_.at(data_vector_.size() - 1) |= other.data_vector_.at(0) >> old_bit_offset;
      } else if (other.bit_size_ <= 8u) {
        data_vector_.at(data_vector_.size() - 1) |= other.data_vector_.at(0) >> old_bit_offset;
        if (old_bit_offset + other.bit_size_ > 8u) {
          data_vector_.push_back(other.data_vector_.at(0) << (8 - old_bit_offset));
        }
      } else {
        auto old_byte_offset = data_vector_.size() - 1;
        constexpr std::byte zero_byte = std::byte();
        data_vector_.reserve(new_byte_size);
        while (data_vector_.size() < new_byte_size) {
          data_vector_.push_back(zero_byte);
        }
        for (std::size_t i = 0; i < other.data_vector_.size(); ++i) {
          data_vector_.at(old_byte_offset) |= (other.data_vector_.at(i) >> old_bit_offset);
          const bool other_has_next_block = i + 1 < other.data_vector_.size();
          const bool last_shift_needed = old_bit_offset + (other.bit_size_ % 8) > 8u;
          const bool other_fits_byte_size = other.bit_size_ % 8 == 0;
          if (other_has_next_block || last_shift_needed || other_fits_byte_size) {
            data_vector_.at(old_byte_offset + 1) |= other.data_vector_.at(i)
                                                    << (8 - old_bit_offset);
          }
          ++old_byte_offset;
        }
      }
      bit_size_ = new_bit_size;
    }
  }

  void Append(BitVector&& other) noexcept {
    if (other.bit_size_ > 0u) {
      Append(other);
    }
  }

  void Copy(const std::size_t dest_from, const std::size_t dest_to, const BitVector& other) {
    assert(dest_from <= dest_to);
    const std::size_t bitlen = dest_to - dest_from;

    if (dest_from > bit_size_ || dest_to > bit_size_) {
      throw std::out_of_range(
          fmt::format("Accessing positions {} to {} of {}", dest_from, dest_to, bit_size_));
    }

    if (bitlen > other.GetSize()) {
      throw std::out_of_range(
          fmt::format("Accessing position {} of {}", dest_to - dest_from, other.GetSize()));
    }

    if (dest_from == dest_to) {
      return;
    }

    const auto num_bits = dest_to - dest_from;

    if (num_bits == 1) {
      Set(other.Get(0), dest_from);
      return;
    }

    const auto dest_to_offset = dest_to % 8;
    const auto dest_from_offset = dest_from % 8;

    if (dest_from_offset + num_bits < 8) {
      const auto mask = (std::byte(0xFF) >> dest_from_offset) &
                        (std::byte(0xFF) << (8 - dest_from_offset - num_bits));
      const auto from_bytes = dest_from / 8;
      data_vector_.at(from_bytes) &= ~mask;
      data_vector_.at(from_bytes) |= (other.data_vector_.at(0) >> dest_from_offset) & mask;
    } else if (dest_from == 0) {
      const auto num_bytes = ABYN::Helpers::Convert::BitsToBytes(num_bits);
      const auto from_bytes = dest_from / 8;
      const auto dest_to_1 = dest_to_offset > 0 ? 1 : 0;
      for (auto i = 0ull; i < num_bytes - dest_to_1; ++i) {
        data_vector_.at(from_bytes + i) = other.data_vector_.at(i);
      }
      if (dest_to_offset > 0) {
        const auto mask = std::byte(0xFF) >> dest_to_offset;
        data_vector_.at(from_bytes + num_bytes - 1) &= mask;
        data_vector_.at(from_bytes + num_bytes - 1) |=
            (other.data_vector_.at(num_bytes - 1) & ~mask);
      }
    } else {
      const auto num_bytes = ABYN::Helpers::Convert::BitsToBytes(dest_from_offset + num_bits);
      const auto num_complete_bytes =
          ABYN::Helpers::Convert::BitsToBytes(num_bits - (8 - dest_from_offset) - dest_to_offset);
      const auto dest_from_offset = dest_from % 8;
      BitVector tmp(dest_from_offset);
      if (num_bits != other.GetSize()) {
        tmp.Append(other.Subset(0, num_bits));
      } else {
        tmp.Append(other);
      }
      const auto from_bytes = dest_from / 8;

      const auto mask = ~(std::byte(0xFF) >> dest_from_offset);
      data_vector_.at(from_bytes) &= mask;
      data_vector_.at(from_bytes) |= tmp.data_vector_.at(0);

      if (num_complete_bytes > 0u) {
        std::copy(tmp.data_vector_.begin() + 1, tmp.data_vector_.begin() + num_complete_bytes + 1,
                  data_vector_.begin() + from_bytes + 1);
      }

      if (dest_to_offset > 0) {
        auto mask = std::byte(0xFFu >> dest_to_offset);
        data_vector_.at(from_bytes + num_bytes - 1) &= mask;
        data_vector_.at(from_bytes + num_bytes - 1) |=
            (tmp.data_vector_.at(tmp.data_vector_.size() - 1));
      }
    }
  }

  void Copy(const std::size_t dest_from, const BitVector& other) {
    Copy(dest_from, dest_from + other.GetSize(), other);
  }

  BitVector Subset(std::size_t from, std::size_t to) const {
    assert(from <= to);

    if (from > bit_size_ || to > bit_size_) {
      throw std::out_of_range(
          fmt::format("Accessing positions {} to {} of {}", from, to, bit_size_));
    }

    BitVector bv;
    if (from == to) {
      return bv;
    }

    if (to - from == bit_size_) {
      return *this;
    }

    bv.Resize(to - from);

    const auto from_bit_offset = from % 8;

    if (from_bit_offset == 0u) {
      std::copy(data_vector_.begin() + (from / 8),
                data_vector_.begin() + (ABYN::Helpers::Convert::BitsToBytes(to)),
                bv.data_vector_.begin());
    } else if (from_bit_offset + bv.bit_size_ <= 8u) {
      bv.data_vector_.at(0) = data_vector_.at(from / 8);
      bv.data_vector_.at(0) <<= from_bit_offset;
    } else {
      auto new_byte_offset = 0ull;
      auto bit_counter = 0ull;
      const auto max = bv.bit_size_;
      for (; bit_counter < max; ++new_byte_offset) {
        auto left_part = data_vector_.at((from / 8) + new_byte_offset) << from_bit_offset;
        bv.data_vector_.at(new_byte_offset) |= left_part;
        bit_counter += 8 - from_bit_offset;
        if (bit_counter < max) {
          auto right_part =
              data_vector_.at((from / 8) + new_byte_offset + 1) >> (8 - from_bit_offset);
          bv.data_vector_.at(new_byte_offset) |= right_part;
          bit_counter += from_bit_offset;
        }
      }
    }

    bv.TruncateToFit();

    return bv;
  }

  std::string AsString() const noexcept {
    std::string result;
    for (auto i = 0ull; i < bit_size_; ++i) {
      result.append(std::to_string(Get(i)));
    }
    return result;
  }

  void Clear() noexcept {
    data_vector_ = {};
    bit_size_ = 0;
  }

  static BitVector Random(std::size_t size) noexcept {
    std::random_device rd;
    std::uniform_int_distribution<std::uint64_t> dist(0, std::numeric_limits<std::uint64_t>::max());
    std::uniform_int_distribution<std::uint64_t> dist_bool(0, 1);

    BitVector bv(size);
    auto ptr = reinterpret_cast<std::uint64_t*>(bv.data_vector_.data());

    std::size_t i;

    for (i = 0ull; i + 64 <= size; i += 64) {
      *(ptr + (i / 64)) = dist(rd);
    }

    for (; i < size; ++i) {
      bv.Set(dist_bool(rd) == true, i);
    }

    return bv;
  }

  static bool ANDReduceBitVector(const BitVector& vector) {
    if (vector.GetSize() == 0) {
      return {};
    } else if (vector.GetSize() == 1) {
      return vector.Get(0);
    } else if (vector.GetSize() <= 64) {
      bool result = vector.Get(0);
      for (auto i = 1ull; i < vector.GetSize(); ++i) {
        result &= vector.Get(i);
      }
      return result;
    } else {
      auto raw_vector = vector.GetData();
      std::byte b = raw_vector.at(0);
#pragma omp simd
      for (auto i = 1ull; i < raw_vector.size(); ++i) {
        b &= raw_vector.at(i);
      }
      BitVector bv({b}, 8);
      bool result = bv.Get(0);

      for (auto i = 1; i < 8; ++i) {
        result &= bv.Get(i);
      }

      return result;
    }
  }

  static BitVector ANDBitVectors(const std::vector<BitVector>& vectors) {
    if (vectors.size() == 0) {
      return {};
    } else if (vectors.size() == 1) {
      return vectors.at(0);
    } else {
      auto result = vectors.at(0);
#pragma omp simd
      for (auto i = 1ull; i < vectors.size(); ++i) {
        result &= vectors.at(i);
      }
      return result;
    }
  }

  static std::vector<BitVector> ANDBitVectors(const std::vector<BitVector>& a,
                                              const std::vector<BitVector>& b) {
    assert(a.size() == b.size());
    if (a.size() == 0) {
      return {};
    } else {
      std::vector<BitVector> result(a.begin(), a.end());
#pragma omp simd
      for (auto i = 0ull; i < a.size(); ++i) {
        result.at(i) &= b.at(i);
      }
      return result;
    }
  }

  static std::vector<BitVector> ANDBitVectors(const std::vector<std::vector<BitVector>>& vectors) {
    if (vectors.size() == 0) {
      return {};
    } else if (vectors.size() == 1) {
      return vectors.at(0);
    } else {
      auto result = vectors.at(0);
      for (auto i = 1ull; i < vectors.size(); ++i) {
        result = ANDBitVectors(result, vectors.at(i));
      }
      return result;
    }
  }

  static bool XORReduceBitVector(const BitVector& vector) {
    if (vector.GetSize() == 0) {
      return {};
    } else if (vector.GetSize() == 1) {
      return vector.Get(0);
    } else if (vector.GetSize() <= 64) {
      bool result = vector.Get(0);
      for (auto i = 1ull; i < vector.GetSize(); ++i) {
        result ^= vector.Get(i);
      }
      return result;
    } else {
      auto raw_vector = vector.GetData();
      std::byte b = raw_vector.at(0);
#pragma omp simd
      for (auto i = 1ull; i < raw_vector.size(); ++i) {
        b ^= raw_vector.at(i);
      }
      BitVector bv({b}, 8);
      bool result = bv.Get(0);

      for (auto i = 1; i < 8; ++i) {
        result ^= bv.Get(i);
      }

      return result;
    }
  }

  static BitVector XORBitVectors(const std::vector<BitVector>& vectors) {
    if (vectors.size() == 0) {
      return {};
    } else if (vectors.size() == 1) {
      return vectors.at(0);
    } else {
      auto result = vectors.at(0);
#pragma omp simd
      for (auto i = 1ull; i < vectors.size(); ++i) {
        result ^= vectors.at(i);
      }
      return result;
    }
  }

  static std::vector<BitVector> XORBitVectors(const std::vector<BitVector>& a,
                                              const std::vector<BitVector>& b) {
    assert(a.size() == b.size());
    if (a.size() == 0) {
      return {};
    } else {
      std::vector<BitVector> result(a.begin(), a.end());
#pragma omp simd
      for (auto i = 0ull; i < a.size(); ++i) {
        result.at(i) ^= b.at(i);
      }
      return result;
    }
  }

  static std::vector<BitVector> XORBitVectors(const std::vector<std::vector<BitVector>>& vectors) {
    if (vectors.size() == 0) {
      return {};
    } else if (vectors.size() == 1) {
      return vectors.at(0);
    } else {
      auto result = vectors.at(0);
      for (auto i = 1ull; i < vectors.size(); ++i) {
        result = XORBitVectors(result, vectors.at(i));
      }
      return result;
    }
  }

  static bool EqualSizeDimensions(const std::vector<BitVector>& v) {
    if (v.size() <= 1) {
      return true;
    } else {
      auto first_size = v.at(0).GetSize();
      for (auto i = 1ull; i < v.size(); ++i) {
        if (first_size != v.at(i).GetSize()) {
          return false;
        }
      }
    }
    return true;
  }

 private:
  std::vector<std::byte, Allocator> data_vector_;

  std::size_t bit_size_;

  void TruncateToFit() noexcept {
    auto bit_offset = bit_size_ % 8;
    if (bit_offset > 0u) {
      data_vector_.at(data_vector_.size() - 1) &= TRUNCATION_BIT_MASK[bit_offset - 1];
    }
  }
};

using AlignedBitVector = BitVector<boost::alignment::aligned_allocator<std::byte, 16>>;
}