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

#include "bit_vector.h"

namespace ENCRYPTO {

using std_alloc = std::allocator<std::byte>;
using aligned_alloc = boost::alignment::aligned_allocator<std::byte, MOTION::MOTION_ALIGNMENT>;

auto constexpr bits_to_bytes(std::size_t n_bits) { return (n_bits + 7) >> 3; }

template <typename Allocator>
BitVector<Allocator>::BitVector(std::size_t n_bits, bool value) noexcept
    : data_vector_(bits_to_bytes(n_bits), value ? std::byte(0xFF) : std::byte(0x00)),
      bit_size_(n_bits) {
  if (value) {
    TruncateToFit();
  }
}

template <typename Allocator>
BitVector<Allocator>::BitVector(const std::byte* buf, std::size_t n_bits)
    : data_vector_(buf, buf + bits_to_bytes(n_bits)), bit_size_(n_bits) {
  TruncateToFit();
}

template <typename Allocator>
template <typename Allocator2>
BitVector<Allocator>::BitVector(const std::vector<std::byte, Allocator2>& data, std::size_t n_bits)
    : bit_size_(n_bits) {
  const std::size_t byte_size = bits_to_bytes(n_bits);
  if (byte_size > data.size()) {
    throw std::out_of_range(fmt::format("BitVector: accessing {} of {}", byte_size, data.size()));
  }
  data_vector_.assign(data.cbegin(), data.cbegin() + byte_size);
  TruncateToFit();
}

template BitVector<std_alloc>::BitVector(const std::vector<std::byte, std_alloc>& data,
                                         std::size_t n_bits);
template BitVector<std_alloc>::BitVector(const std::vector<std::byte, aligned_alloc>& data,
                                         std::size_t n_bits);
template BitVector<aligned_alloc>::BitVector(const std::vector<std::byte, std_alloc>& data,
                                             std::size_t n_bits);
template BitVector<aligned_alloc>::BitVector(const std::vector<std::byte, aligned_alloc>& data,
                                             std::size_t n_bits);

template <typename Allocator>
BitVector<Allocator>::BitVector(std::vector<std::byte, Allocator>&& data, std::size_t n_bits)
    : bit_size_(n_bits) {
  const std::size_t byte_size = MOTION::Helpers::Convert::BitsToBytes(n_bits);
  if (byte_size > data.size()) {
    throw std::out_of_range(fmt::format("BitVector: accessing {} of {}", byte_size, data.size()));
  }
  data_vector_ = std::move(data);
  data_vector_.resize(byte_size);
  TruncateToFit();
}

template <typename Allocator>
BitVector<Allocator>::BitVector(const std::vector<bool>& data, std::size_t n_bits)
    : bit_size_(n_bits) {
  if (bit_size_ > data.size()) {
    throw std::out_of_range(fmt::format("BitVector: accessing {} of {}", n_bits, data.size()));
  }

  const std::size_t byte_size = MOTION::Helpers::Convert::BitsToBytes(n_bits);
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

template <typename Allocator>
void BitVector<Allocator>::Invert() {
  for (auto i = 0ull; i < data_vector_.size(); ++i) {
    data_vector_.at(i) = ~data_vector_.at(i);
  }
  TruncateToFit();
}

template <typename Allocator>
BitVector<Allocator> BitVector<Allocator>::operator~() const {
  BitVector bv = *this;
  bv.Invert();
  return bv;
}

template <typename Allocator1>
template <typename Allocator2>
bool BitVector<Allocator1>::operator!=(const BitVector<Allocator2>& other) const noexcept {
  return !(*this == other);
}

template bool BitVector<std_alloc>::operator!=(const BitVector<std_alloc>& other) const noexcept;
template bool BitVector<std_alloc>::operator!=(const BitVector<aligned_alloc>& other) const
    noexcept;
template bool BitVector<aligned_alloc>::operator!=(const BitVector<std_alloc>& other) const
    noexcept;
template bool BitVector<aligned_alloc>::operator!=(const BitVector<aligned_alloc>& other) const
    noexcept;

template <typename Allocator1>
template <typename Allocator2>
BitVector<Allocator1> BitVector<Allocator1>::operator&(const BitVector<Allocator2>& other) const
    noexcept {
  auto result = *this;
  result &= other;
  return result;
}

template BitVector<std_alloc> BitVector<std_alloc>::operator&(
    const BitVector<std_alloc>& other) const noexcept;
template BitVector<std_alloc> BitVector<std_alloc>::operator&(
    const BitVector<aligned_alloc>& other) const noexcept;
template BitVector<aligned_alloc> BitVector<aligned_alloc>::operator&(
    const BitVector<std_alloc>& other) const noexcept;
template BitVector<aligned_alloc> BitVector<aligned_alloc>::operator&(
    const BitVector<aligned_alloc>& other) const noexcept;

template <typename Allocator1>
template <typename Allocator2>
BitVector<Allocator1> BitVector<Allocator1>::operator^(const BitVector<Allocator2>& other) const
    noexcept {
  auto result = *this;
  result ^= other;
  return result;
}

template BitVector<std_alloc> BitVector<std_alloc>::operator^(
    const BitVector<std_alloc>& other) const noexcept;
template BitVector<std_alloc> BitVector<std_alloc>::operator^(
    const BitVector<aligned_alloc>& other) const noexcept;
template BitVector<aligned_alloc> BitVector<aligned_alloc>::operator^(
    const BitVector<std_alloc>& other) const noexcept;
template BitVector<aligned_alloc> BitVector<aligned_alloc>::operator^(
    const BitVector<aligned_alloc>& other) const noexcept;

template <typename Allocator1>
template <typename Allocator2>
BitVector<Allocator1> BitVector<Allocator1>::operator|(const BitVector<Allocator2>& other) const
    noexcept {
  auto result = *this;
  result |= other;
  return result;
}

template BitVector<std_alloc> BitVector<std_alloc>::operator|(
    const BitVector<std_alloc>& other) const noexcept;
template BitVector<std_alloc> BitVector<std_alloc>::operator|(
    const BitVector<aligned_alloc>& other) const noexcept;
template BitVector<aligned_alloc> BitVector<aligned_alloc>::operator|(
    const BitVector<std_alloc>& other) const noexcept;
template BitVector<aligned_alloc> BitVector<aligned_alloc>::operator|(
    const BitVector<aligned_alloc>& other) const noexcept;

template <typename Allocator>
BitVector<Allocator>& BitVector<Allocator>::operator=(const BitVector<Allocator>& other) noexcept {
  bit_size_ = other.bit_size_;
  data_vector_ = other.data_vector_;
  return *this;
}

template <typename Allocator>
template <typename Allocator2>
BitVector<Allocator>& BitVector<Allocator>::operator=(const BitVector<Allocator2>& other) noexcept {
  bit_size_ = other.GetSize();
  data_vector_.assign(other.data_vector_.cbegin(), other.data_vector_.cend());
  return *this;
}

template BitVector<std_alloc>& BitVector<std_alloc>::operator=(
    const BitVector<aligned_alloc>& other) noexcept;
template BitVector<aligned_alloc>& BitVector<aligned_alloc>::operator=(
    const BitVector<std_alloc>& other) noexcept;

template <typename Allocator>
BitVector<Allocator>& BitVector<Allocator>::operator=(BitVector<Allocator>&& other) noexcept {
  bit_size_ = other.GetSize();
  data_vector_ = std::move(other.GetData());
  return *this;
}

template <typename Allocator1>
template <typename Allocator2>
bool BitVector<Allocator1>::operator==(const BitVector<Allocator2>& other) const noexcept {
  if (bit_size_ != other.GetSize()) {
    return false;
  }
  assert(data_vector_.size() == other.GetData().size());

  for (auto i = 0ull; i < data_vector_.size(); ++i) {
    if (data_vector_.at(i) != other.GetData().at(i)) {
      return false;
    }
  }

  return true;
}

template bool BitVector<std_alloc>::operator==(const BitVector<std_alloc>& other) const noexcept;
template bool BitVector<std_alloc>::operator==(const BitVector<aligned_alloc>& other) const
    noexcept;
template bool BitVector<aligned_alloc>::operator==(const BitVector<std_alloc>& other) const
    noexcept;
template bool BitVector<aligned_alloc>::operator==(const BitVector<aligned_alloc>& other) const
    noexcept;

template <typename Allocator>
void BitVector<Allocator>::Set(bool value) noexcept {
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

template <typename Allocator>
void BitVector<Allocator>::Set(bool value, std::size_t pos) {
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

template <typename Allocator>
bool BitVector<Allocator>::Get(std::size_t pos) const {
  if (pos >= bit_size_) {
    throw std::out_of_range(fmt::format("BitVector: accessing {} of {}", pos, bit_size_));
  }

  std::size_t byte_offset = pos / 8;
  std::size_t bit_offset = pos % 8;

  auto result = data_vector_.at(byte_offset);
  result &= SET_BIT_MASK[bit_offset];

  return result == SET_BIT_MASK[bit_offset];
}

template <typename Allocator1>
template <typename Allocator2>
BitVector<Allocator1>& BitVector<Allocator1>::operator&=(
    const BitVector<Allocator2>& other) noexcept {
  const auto max_bit_size = std::max(bit_size_, other.GetSize());
  const auto min_byte_size = std::min(data_vector_.size(), other.GetData().size());

  Resize(max_bit_size, true);

  for (auto i = 0ull; i < min_byte_size; ++i) {
    data_vector_.at(i) &= other.GetData().at(i);
  }
  return *this;
}

template BitVector<std_alloc>& BitVector<std_alloc>::operator&=(
    const BitVector<std_alloc>& other) noexcept;
template BitVector<std_alloc>& BitVector<std_alloc>::operator&=(
    const BitVector<aligned_alloc>& other) noexcept;
template BitVector<aligned_alloc>& BitVector<aligned_alloc>::operator&=(
    const BitVector<std_alloc>& other) noexcept;
template BitVector<aligned_alloc>& BitVector<aligned_alloc>::operator&=(
    const BitVector<aligned_alloc>& other) noexcept;

template <typename Allocator1>
template <typename Allocator2>
BitVector<Allocator1>& BitVector<Allocator1>::operator^=(
    const BitVector<Allocator2>& other) noexcept {
  const auto max_bit_size = std::max(bit_size_, other.GetSize());
  const auto min_byte_size = std::min(data_vector_.size(), other.GetData().size());

  Resize(max_bit_size, true);

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

template BitVector<std_alloc>& BitVector<std_alloc>::operator^=(
    const BitVector<std_alloc>& other) noexcept;
template BitVector<std_alloc>& BitVector<std_alloc>::operator^=(
    const BitVector<aligned_alloc>& other) noexcept;
template BitVector<aligned_alloc>& BitVector<aligned_alloc>::operator^=(
    const BitVector<std_alloc>& other) noexcept;
template BitVector<aligned_alloc>& BitVector<aligned_alloc>::operator^=(
    const BitVector<aligned_alloc>& other) noexcept;

template <typename Allocator1>
template <typename Allocator2>
BitVector<Allocator1>& BitVector<Allocator1>::operator|=(
    const BitVector<Allocator2>& other) noexcept {
  const auto max_bit_size = std::max(bit_size_, other.GetSize());
  const auto min_byte_size = std::min(data_vector_.size(), other.GetData().size());
  const auto max_byte_size = MOTION::Helpers::Convert::BitsToBytes(max_bit_size);

  Resize(max_bit_size, true);

  for (auto i = 0ull; i < min_byte_size; ++i) {
    data_vector_.at(i) |= other.GetData().at(i);
  }

  if (min_byte_size == max_byte_size) {
    for (auto i = min_byte_size; i < max_byte_size; ++i) {
      data_vector_.at(i) = other.GetData().at(i);
    }
  }
  return *this;
}

template BitVector<std_alloc>& BitVector<std_alloc>::operator|=(
    const BitVector<std_alloc>& other) noexcept;
template BitVector<std_alloc>& BitVector<std_alloc>::operator|=(
    const BitVector<aligned_alloc>& other) noexcept;
template BitVector<aligned_alloc>& BitVector<aligned_alloc>::operator|=(
    const BitVector<std_alloc>& other) noexcept;
template BitVector<aligned_alloc>& BitVector<aligned_alloc>::operator|=(
    const BitVector<aligned_alloc>& other) noexcept;

template <typename Allocator>
void BitVector<Allocator>::Resize(std::size_t n_bits, bool zero_fill) noexcept {
  if (bit_size_ == n_bits) {
    return;
  }
  bit_size_ = n_bits;
  const auto byte_size = MOTION::Helpers::Convert::BitsToBytes(bit_size_);
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

template <typename Allocator>
void BitVector<Allocator>::Append(bool bit) noexcept {
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

template <typename Allocator>
void BitVector<Allocator>::Append(const BitVector<Allocator>& other) noexcept {
  if (other.GetSize() > 0u) {
    const auto old_bit_offset = bit_size_ % 8;

    const auto new_bit_size = bit_size_ + other.GetSize();
    const auto new_byte_size = MOTION::Helpers::Convert::BitsToBytes(new_bit_size);

    if (new_bit_size <= 8u) {
      if (bit_size_ == 0u) {
        data_vector_ = other.GetData();
      } else {
        data_vector_.at(0) |= (other.GetData().at(0) >> old_bit_offset);
      }
    } else if (old_bit_offset == 0u) {
      data_vector_.insert(data_vector_.end(), other.GetData().begin(), other.GetData().end());
    } else if (old_bit_offset + other.GetSize() <= 8u) {
      data_vector_.at(data_vector_.size() - 1) |= other.GetData().at(0) >> old_bit_offset;
    } else if (other.GetSize() <= 8u) {
      data_vector_.at(data_vector_.size() - 1) |= other.GetData().at(0) >> old_bit_offset;
      if (old_bit_offset + other.GetSize() > 8u) {
        data_vector_.push_back(other.GetData().at(0) << (8 - old_bit_offset));
      }
    } else {
      auto old_byte_offset = data_vector_.size() - 1;
      constexpr std::byte zero_byte = std::byte();
      data_vector_.reserve(new_byte_size);
      while (data_vector_.size() < new_byte_size) {
        data_vector_.push_back(zero_byte);
      }
      for (std::size_t i = 0; i < other.GetData().size(); ++i) {
        data_vector_.at(old_byte_offset) |= (other.GetData().at(i) >> old_bit_offset);
        const bool other_has_next_block = i + 1 < other.GetData().size();
        const bool last_shift_needed = old_bit_offset + (other.GetSize() % 8) > 8u;
        const bool other_fits_byte_size = other.GetSize() % 8 == 0;
        if (other_has_next_block || last_shift_needed || other_fits_byte_size) {
          data_vector_.at(old_byte_offset + 1) |= other.GetData().at(i) << (8 - old_bit_offset);
        }
        ++old_byte_offset;
      }
    }
    bit_size_ = new_bit_size;
  }
}

template <typename Allocator>
void BitVector<Allocator>::Append(BitVector&& other) noexcept {
  if (other.GetSize() > 0u) {
    Append(other);
  }
}

template <typename Allocator>
void BitVector<Allocator>::Copy(const std::size_t dest_from, const std::size_t dest_to,
                                const BitVector& other) {
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
    data_vector_.at(from_bytes) |= (other.GetData().at(0) >> dest_from_offset) & mask;
  } else if (dest_from == 0) {
    const auto num_bytes = MOTION::Helpers::Convert::BitsToBytes(num_bits);
    const auto from_bytes = dest_from / 8;
    const auto dest_to_1 = dest_to_offset > 0 ? 1 : 0;
    for (auto i = 0ull; i < num_bytes - dest_to_1; ++i) {
      data_vector_.at(from_bytes + i) = other.GetData().at(i);
    }
    if (dest_to_offset > 0) {
      const auto mask = std::byte(0xFF) >> dest_to_offset;
      data_vector_.at(from_bytes + num_bytes - 1) &= mask;
      data_vector_.at(from_bytes + num_bytes - 1) |= (other.GetData().at(num_bytes - 1) & ~mask);
    }
  } else {
    const auto num_bytes = MOTION::Helpers::Convert::BitsToBytes(dest_from_offset + num_bits);
    const auto num_complete_bytes =
        MOTION::Helpers::Convert::BitsToBytes(num_bits - (8 - dest_from_offset) - dest_to_offset);
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

template <typename Allocator>
void BitVector<Allocator>::Copy(const std::size_t dest_from, const BitVector& other) {
  Copy(dest_from, dest_from + other.GetSize(), other);
}

template <typename Allocator>
BitVector<Allocator> BitVector<Allocator>::Subset(std::size_t from, std::size_t to) const {
  assert(from <= to);

  if (from > bit_size_ || to > bit_size_) {
    throw std::out_of_range(fmt::format("Accessing positions {} to {} of {}", from, to, bit_size_));
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
              data_vector_.begin() + (MOTION::Helpers::Convert::BitsToBytes(to)),
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

template <typename Allocator>
std::string BitVector<Allocator>::AsString() const noexcept {
  std::string result;
  for (auto i = 0ull; i < bit_size_; ++i) {
    result.append(std::to_string(Get(i)));
  }
  return result;
}

template <typename Allocator>
void BitVector<Allocator>::Clear() noexcept {
  data_vector_ = {};
  bit_size_ = 0;
}

template <typename Allocator>
BitVector<Allocator> BitVector<Allocator>::Random(std::size_t size) noexcept {
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

template <typename Allocator>
bool BitVector<Allocator>::ANDReduceBitVector(const BitVector& vector) {
  if (vector.GetSize() == 0) {
    return true;
  } else if (vector.GetSize() == 1) {
    return vector.Get(0);
  } else if (vector.GetSize() <= 16) {
    bool result = vector.Get(0);
    for (auto i = 1ull; i < vector.GetSize(); ++i) {
      result &= vector.Get(i);
    }
    return result;
  } else {
    auto raw_vector = vector.GetData();
    std::byte b = raw_vector.at(0);

    const bool div_by_8{(vector.GetSize() % 8) == 0};
    const auto size{div_by_8 ? raw_vector.size() : raw_vector.size() - 1};
    const auto remainder_size{vector.GetSize() - (size * 8)};

    for (auto i = 1ull; i < size; ++i) b &= raw_vector.at(i);

    BitVector bv({b}, 8);
    bool result{b == std::byte(0xFF)};

    for (auto i = 1; i < 8; ++i) result &= bv.Get(i);

    for (std::size_t i = 0; i < remainder_size; ++i) result &= vector.Get(vector.GetSize() - i - 1);

    return result;
  }
}

template <typename Allocator>
BitVector<Allocator> BitVector<Allocator>::ANDBitVectors(const std::vector<BitVector>& vectors) {
  if (vectors.size() == 0) {
    return {};
  } else if (vectors.size() == 1) {
    return vectors.at(0);
  } else {
    auto result = vectors.at(0);

    for (auto i = 1ull; i < vectors.size(); ++i) {
      result &= vectors.at(i);
    }
    return result;
  }
}

template <typename Allocator>
bool BitVector<Allocator>::ORReduceBitVector(const BitVector& vector) {
  if (vector.GetSize() == 0) {
    return {};
  } else if (vector.GetSize() == 1) {
    return vector.Get(0);
  } else if (vector.GetSize() <= 64) {
    bool result = vector.Get(0);
    for (auto i = 1ull; i < vector.GetSize(); ++i) {
      result |= vector.Get(i);
    }
    return result;
  } else {
    auto raw_vector = vector.GetData();
    std::byte b = raw_vector.at(0);

    for (auto i = 1ull; i < raw_vector.size(); ++i) {
      b |= raw_vector.at(i);
    }
    BitVector bv({b}, 8);
    bool result = bv.Get(0);

    for (auto i = 1; i < 8; ++i) {
      result |= bv.Get(i);
    }

    return result;
  }
}

template <typename Allocator>
BitVector<Allocator> BitVector<Allocator>::ORBitVectors(const std::vector<BitVector>& vectors) {
  if (vectors.size() == 0) {
    return {};
  } else if (vectors.size() == 1) {
    return vectors.at(0);
  } else {
    auto result = vectors.at(0);

    for (auto i = 1ull; i < vectors.size(); ++i) {
      result |= vectors.at(i);
    }
    return result;
  }
}

template <typename Allocator>
std::vector<BitVector<Allocator>> BitVector<Allocator>::ANDBitVectors(
    const std::vector<BitVector>& a, const std::vector<BitVector>& b) {
  assert(a.size() == b.size());
  if (a.size() == 0) {
    return {};
  } else {
    std::vector<BitVector> result(a.begin(), a.end());

    for (auto i = 0ull; i < a.size(); ++i) {
      result.at(i) &= b.at(i);
    }
    return result;
  }
}

template <typename Allocator>
std::vector<BitVector<Allocator>> BitVector<Allocator>::ANDBitVectors(
    const std::vector<std::vector<BitVector>>& vectors) {
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

template <typename Allocator>
bool BitVector<Allocator>::XORReduceBitVector(const BitVector& vector) {
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

template <typename Allocator>
BitVector<Allocator> BitVector<Allocator>::XORBitVectors(const std::vector<BitVector>& vectors) {
  if (vectors.size() == 0) {
    return {};
  } else if (vectors.size() == 1) {
    return vectors.at(0);
  } else {
    auto result = vectors.at(0);

    for (auto i = 1ull; i < vectors.size(); ++i) {
      result ^= vectors.at(i);
    }
    return result;
  }
}

template <typename Allocator>
std::vector<BitVector<Allocator>> BitVector<Allocator>::XORBitVectors(
    const std::vector<BitVector>& a, const std::vector<BitVector>& b) {
  assert(a.size() == b.size());
  if (a.size() == 0) {
    return {};
  } else {
    std::vector<BitVector> result(a.begin(), a.end());

    for (auto i = 0ull; i < a.size(); ++i) {
      result.at(i) ^= b.at(i);
    }
    return result;
  }
}

template <typename Allocator>
std::vector<BitVector<Allocator>> BitVector<Allocator>::XORBitVectors(
    const std::vector<std::vector<BitVector>>& vectors) {
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

template <typename Allocator>
bool BitVector<Allocator>::EqualSizeDimensions(const std::vector<BitVector>& v) {
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

template <typename Allocator>
void BitVector<Allocator>::TruncateToFit() noexcept {
  auto bit_offset = bit_size_ % 8;
  if (bit_offset > 0u) {
    data_vector_.at(data_vector_.size() - 1) &= TRUNCATION_BIT_MASK[bit_offset - 1];
  }
}

template class BitVector<std_alloc>;
template class BitVector<aligned_alloc>;

template <>
std::vector<BitVector<std_alloc>> ToInput<float, std::true_type, std_alloc>(float t) {
  uint32_t tmp;
  std::copy(reinterpret_cast<std::uint32_t*>(&t), reinterpret_cast<std::uint32_t*>(&t) + 1, &tmp);
  return ToInput(tmp);
}

template <>
std::vector<BitVector<std_alloc>> ToInput<double, std::true_type, std_alloc>(double t) {
  uint64_t tmp;
  std::copy(reinterpret_cast<std::uint64_t*>(&t), reinterpret_cast<std::uint64_t*>(&t) + 1, &tmp);
  return ToInput(tmp);
}

template <>
std::vector<BitVector<std_alloc>> ToInput<float, std::true_type, std_alloc>(
    const std::vector<float>& v) {
  std::vector<std::uint32_t> v_conv;
  v_conv.reserve(v.size());
  for (const auto& f : v) v_conv.emplace_back(*reinterpret_cast<const std::uint32_t*>(&f));
  return ToInput(v_conv);
}

template <>
std::vector<BitVector<std_alloc>> ToInput<double, std::true_type, std_alloc>(
    const std::vector<double>& v) {
  std::vector<std::uint32_t> v_conv;
  v_conv.reserve(v.size());
  for (const auto& f : v) v_conv.emplace_back(*reinterpret_cast<const std::uint64_t*>(&f));
  return ToInput(v_conv);
}

template <typename T, typename, typename Allocator>
std::vector<BitVector<Allocator>> ToInput(T t) {
  constexpr auto bitlen{sizeof(T) * 8};

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
  std::vector<BitVector<Allocator>> v;
  for (auto i = 0ull; i < bitlen; ++i) v.emplace_back(((t >> i) & 1) == 1);
  return v;
}

template std::vector<BitVector<std_alloc>> ToInput(std::uint8_t);
template std::vector<BitVector<std_alloc>> ToInput(std::uint16_t);
template std::vector<BitVector<std_alloc>> ToInput(std::uint32_t);
template std::vector<BitVector<std_alloc>> ToInput(std::uint64_t);

template <typename T, typename, typename Allocator>
std::vector<BitVector<Allocator>> ToInput(const std::vector<T>& in_v) {
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

  constexpr auto bitlen{sizeof(T) * 8};
  std::vector<BitVector<Allocator>> v(bitlen);
  for (auto i = 0ull; i < in_v.size(); ++i) {
    for (auto j = 0ull; j < bitlen; ++j) {
      v.at(j).Append(((in_v.at(i) >> j) & 1) == 1);
    }
  }
  return v;
}

template std::vector<BitVector<std_alloc>> ToInput(const std::vector<std::uint8_t>&);
template std::vector<BitVector<std_alloc>> ToInput(const std::vector<std::uint16_t>&);
template std::vector<BitVector<std_alloc>> ToInput(const std::vector<std::uint32_t>&);
template std::vector<BitVector<std_alloc>> ToInput(const std::vector<std::uint64_t>&);
}  // namespace ENCRYPTO
