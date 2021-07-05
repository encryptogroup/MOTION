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

namespace encrypto::motion {

auto constexpr NumberOfBitsToNumberOfBytes(std::size_t number_of_bits) {
  return (number_of_bits + 7) >> 3;
}

// TODO: migrate BitVector functions to the functions below

inline void TruncateToFitImplementation(std::byte* pointer, const std::size_t bit_size) {
  const auto bit_offset = bit_size % 8;
  const auto byte_size = NumberOfBitsToNumberOfBytes(bit_size);
  if (bit_offset) *(pointer + byte_size - 1) &= TruncationBitMask[bit_offset - 1];
}

inline void SetImplementation(std::byte* pointer, const bool value,
                              const std::size_t bit_size) noexcept {
  const std::size_t byte_size{NumberOfBitsToNumberOfBytes(bit_size)};
  for (auto i = 0ull; i < byte_size; ++i) {
    if (value) {  // set
      *(pointer + i) |= std::byte(0xFFu);
    } else {  // unset
      *(pointer + i) &= std::byte(0u);
    }
  }

  if (value) {
    TruncateToFitImplementation(pointer, bit_size);
  }
}

inline void SetAtImplementation(std::byte* pointer, const bool value,
                                const std::size_t position) noexcept {
  const std::size_t byte_offset = position / 8;
  const std::size_t bit_offset = position % 8;

  if (value) {
    *(pointer + byte_offset) |= kSetBitMask[bit_offset];
  } else {
    *(pointer + byte_offset) &= kUnsetBitMask[bit_offset];
  }
}

inline bool GetImplementation(const std::byte* pointer, const std::size_t position) noexcept {
  const std::size_t byte_offset = position / 8;
  const std::size_t bit_offset = position % 8;

  const auto result = *(pointer + byte_offset) & kSetBitMask[bit_offset];
  return result == kSetBitMask[bit_offset];
}

template <typename T, typename U>
inline bool EqualImplementation(const T* pointer1, const U* pointer2, const std::size_t byte_size) {
  const auto pointer1_cast{reinterpret_cast<const std::byte*>(pointer1)};
  const auto pointer2_cast{reinterpret_cast<const std::byte*>(pointer2)};
  return std::equal(pointer1_cast, pointer1_cast + byte_size, pointer2_cast);
}

// TODO: check how good this is vectorized
template <typename T, typename U>
inline bool AlignedEqualImplementation(const T* pointer1, const U* pointer2,
                                       const std::size_t byte_size) {
  const auto pointer1_cast{
      reinterpret_cast<const std::byte*>(__builtin_assume_aligned(pointer1, kAlignment))};
  const auto pointer2_cast{
      reinterpret_cast<const std::byte*>(__builtin_assume_aligned(pointer2, kAlignment))};
  return std::equal(pointer1_cast, pointer1_cast + byte_size, pointer2_cast);
}

template <typename T, typename U>
inline void XorImplementation(const T* input, U* result, const std::size_t byte_size) {
  const auto input_cast{reinterpret_cast<const std::byte*>(input)};
  auto result_cast{reinterpret_cast<std::byte*>(result)};
  std::transform(input_cast, input_cast + byte_size, result_cast, result_cast,
                 [](const std::byte& a, const std::byte& b) { return a ^ b; });
}

// TODO: check how good this is vectorized
template <typename T, typename U>
inline void AlignedXorImplementation(const T* input, U* result, const std::size_t byte_size) {
  const auto input_cast{
      reinterpret_cast<const std::byte*>(__builtin_assume_aligned(input, kAlignment))};
  auto result_cast{reinterpret_cast<std::byte*>(__builtin_assume_aligned(result, kAlignment))};
  std::transform(input_cast, input_cast + byte_size, result_cast, result_cast,
                 [](const std::byte& a, const std::byte& b) { return a ^ b; });
}

template <typename T, typename U>
inline void AndImplementation(const T* input, U* result, const std::size_t byte_size) {
  const auto input_cast{reinterpret_cast<const std::byte*>(input)};
  auto result_cast{reinterpret_cast<std::byte*>(result)};
  std::transform(input_cast, input_cast + byte_size, result_cast, result_cast,
                 [](const std::byte& a, const std::byte& b) { return a & b; });
}

template <typename T, typename U>
inline void AlignedAndImplementation(const T* input, U* result, const std::size_t byte_size) {
  const auto input_cast{
      reinterpret_cast<const std::byte*>(__builtin_assume_aligned(input, kAlignment))};
  auto result_cast{reinterpret_cast<std::byte*>(__builtin_assume_aligned(result, kAlignment))};
  std::transform(input_cast, input_cast + byte_size, result_cast, result_cast,
                 [](const std::byte& a, const std::byte& b) { return a & b; });
}

template <typename T, typename U>
inline void OrImplementation(const T* input, U* result, const std::size_t byte_size) {
  const auto input_cast{reinterpret_cast<const std::byte*>(input)};
  auto result_cast{reinterpret_cast<std::byte*>(result)};
  std::transform(input_cast, input_cast + byte_size, result_cast, result_cast,
                 [](const std::byte& a, const std::byte& b) { return a | b; });
}

template <typename T, typename U>
inline void AlignedOrImplementation(const T* input, U* result, const std::size_t byte_size) {
  const auto input_cast{
      reinterpret_cast<const std::byte*>(__builtin_assume_aligned(input, kAlignment))};
  auto result_cast{reinterpret_cast<std::byte*>(__builtin_assume_aligned(result, kAlignment))};
  std::transform(input_cast, input_cast + byte_size, result_cast, result_cast,
                 [](const std::byte& a, const std::byte& b) { return a | b; });
}

inline void CopyImplementation(const std::size_t from, const std::size_t to, std::byte* source,
                               std::byte* destination) {
  if (from > to) {
    throw std::logic_error(
        fmt::format("'from' index ({}) needs to be smaller less than 'to' index ({})", from, to));
  }

  const auto number_of_bits = to - from;

  if (number_of_bits == 1) {
    SetAtImplementation(destination, GetImplementation(source, 0), from);
    return;
  }

  const auto destination_to_offset = to % 8;
  const auto destination_from_offset = from % 8;

  if (destination_from_offset + number_of_bits < 8) {
    const auto mask = (std::byte(0xFF) >> destination_from_offset) &
                      (std::byte(0xFF) << (8 - destination_from_offset - number_of_bits));
    const auto from_bytes = from / 8;
    *(destination + from_bytes) &= ~mask;
    *(destination + from_bytes) |= ((*source) >> destination_from_offset) & mask;
  } else if ((from % 8) == 0) {
    const auto number_of_bytes = BitsToBytes(number_of_bits);
    const auto from_bytes = from / 8;
    const auto destination_to_1 = destination_to_offset > 0 ? 1 : 0;
    for (auto i = 0ull; i < number_of_bytes - destination_to_1; ++i) {
      *(destination + from_bytes + i) = *(source + i);
    }
    if (destination_to_offset > 0) {
      const auto mask = std::byte(0xFF) >> destination_to_offset;
      *(destination + from_bytes + number_of_bytes - 1) &= mask;
      *(destination + from_bytes + number_of_bytes - 1) |= *(source + number_of_bytes - 1) & ~mask;
    }
  } else {
    const auto number_of_bytes = BitsToBytes(destination_from_offset + number_of_bits);
    const auto number_of_complete_bytes =
        BitsToBytes(number_of_bits - (8 - destination_from_offset) - destination_to_offset);
    BitVector tmp(destination_from_offset);
    tmp.Append(BitSpan(source, number_of_bits));

    const auto from_bytes = from / 8;

    const auto mask0 = ~(std::byte(0xFF) >> destination_from_offset);
    *(destination + from_bytes) &= mask0;
    *(destination + from_bytes) |= tmp.GetData()[0];

    if (number_of_complete_bytes > 0u) {
      std::copy(tmp.GetData().data() + 1, tmp.GetData().data() + number_of_complete_bytes + 1,
                destination + from_bytes + 1);
    }

    if (destination_to_offset > 0) {
      const auto mask1 = std::byte(0xFFu >> destination_to_offset);
      *(destination + from_bytes + number_of_bytes - 1) &= mask1;
      *(destination + from_bytes + number_of_bytes - 1) |=
          (tmp.GetData()[tmp.GetData().size() - 1]);
    }
  }
}

template <typename Allocator>
BitVector<Allocator>::BitVector(std::size_t number_of_bits, bool value) noexcept
    : data_vector_(NumberOfBitsToNumberOfBytes(number_of_bits),
                   value ? std::byte(0xFF) : std::byte(0x00)),
      bit_size_(number_of_bits) {
  if (value) {
    TruncateToFit();
  }
}

template <typename Allocator>
BitVector<Allocator>::BitVector(const std::byte* buffer, std::size_t number_of_bits)
    : data_vector_(buffer, buffer + NumberOfBitsToNumberOfBytes(number_of_bits)),
      bit_size_(number_of_bits) {
  TruncateToFit();
}

template <typename Allocator>
template <typename OtherAllocator>
BitVector<Allocator>::BitVector(const std::vector<std::byte, OtherAllocator>& data,
                                std::size_t number_of_bits)
    : bit_size_(number_of_bits) {
  const std::size_t byte_size = NumberOfBitsToNumberOfBytes(number_of_bits);
  if (byte_size > data.size()) {
    throw std::out_of_range(fmt::format("BitVector: accessing {} of {}", byte_size, data.size()));
  }
  data_vector_.assign(data.cbegin(), data.cbegin() + byte_size);
  TruncateToFit();
}

template BitVector<StdAllocator>::BitVector(const std::vector<std::byte, StdAllocator>& data,
                                            std::size_t number_of_bits);
template BitVector<StdAllocator>::BitVector(const std::vector<std::byte, AlignedAllocator>& data,
                                            std::size_t number_of_bits);
template BitVector<AlignedAllocator>::BitVector(const std::vector<std::byte, StdAllocator>& data,
                                                std::size_t number_of_bits);
template BitVector<AlignedAllocator>::BitVector(
    const std::vector<std::byte, AlignedAllocator>& data, std::size_t number_of_bits);

template <typename Allocator>
BitVector<Allocator>::BitVector(std::vector<std::byte, Allocator>&& data,
                                std::size_t number_of_bits)
    : bit_size_(number_of_bits) {
  const std::size_t byte_size = BitsToBytes(number_of_bits);
  if (byte_size > data.size()) {
    throw std::out_of_range(fmt::format("BitVector: accessing {} of {}", byte_size, data.size()));
  }
  data_vector_ = std::move(data);
  data_vector_.resize(byte_size);
  TruncateToFit();
}

template <typename Allocator>
BitVector<Allocator>::BitVector(const std::vector<bool>& data, std::size_t number_of_bits)
    : bit_size_(number_of_bits) {
  if (bit_size_ > data.size()) {
    throw std::out_of_range(
        fmt::format("BitVector: accessing {} of {}", number_of_bits, data.size()));
  }

  const std::size_t byte_size = BitsToBytes(number_of_bits);
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
  BitVector bit_vector = *this;
  bit_vector.Invert();
  return bit_vector;
}

template <typename Allocator>
template <typename OtherAllocator>
bool BitVector<Allocator>::operator!=(const BitVector<OtherAllocator>& other) const noexcept {
  return !(*this == other);
}

template bool BitVector<StdAllocator>::operator!=(
    const BitVector<StdAllocator>& other) const noexcept;
template bool BitVector<StdAllocator>::operator!=(
    const BitVector<AlignedAllocator>& other) const noexcept;
template bool BitVector<AlignedAllocator>::operator!=(
    const BitVector<StdAllocator>& other) const noexcept;
template bool BitVector<AlignedAllocator>::operator!=(
    const BitVector<AlignedAllocator>& other) const noexcept;

template <typename Allocator>
template <typename OtherAllocator>
BitVector<Allocator> BitVector<Allocator>::operator&(
    const BitVector<OtherAllocator>& other) const noexcept {
  auto result = *this;
  result &= other;
  return result;
}

template BitVector<StdAllocator> BitVector<StdAllocator>::operator&(
    const BitVector<StdAllocator>& other) const noexcept;
template BitVector<StdAllocator> BitVector<StdAllocator>::operator&(
    const BitVector<AlignedAllocator>& other) const noexcept;
template BitVector<AlignedAllocator> BitVector<AlignedAllocator>::operator&(
    const BitVector<StdAllocator>& other) const noexcept;
template BitVector<AlignedAllocator> BitVector<AlignedAllocator>::operator&(
    const BitVector<AlignedAllocator>& other) const noexcept;

template <typename Allocator>
BitVector<Allocator> BitVector<Allocator>::operator&(const BitSpan& bit_span) const noexcept {
  return bit_span & *this;
}

template <typename Allocator>
template <typename OtherAllocator>
BitVector<Allocator> BitVector<Allocator>::operator^(
    const BitVector<OtherAllocator>& other) const noexcept {
  auto result = *this;
  result ^= other;
  return result;
}

template BitVector<StdAllocator> BitVector<StdAllocator>::operator^(
    const BitVector<StdAllocator>& other) const noexcept;
template BitVector<StdAllocator> BitVector<StdAllocator>::operator^(
    const BitVector<AlignedAllocator>& other) const noexcept;
template BitVector<AlignedAllocator> BitVector<AlignedAllocator>::operator^(
    const BitVector<StdAllocator>& other) const noexcept;
template BitVector<AlignedAllocator> BitVector<AlignedAllocator>::operator^(
    const BitVector<AlignedAllocator>& other) const noexcept;

template <typename Allocator>
BitVector<Allocator> BitVector<Allocator>::operator^(const BitSpan& bit_span) const noexcept {
  return bit_span ^ *this;
}

template <typename Allocator>
template <typename OtherAllocator>
BitVector<Allocator> BitVector<Allocator>::operator|(
    const BitVector<OtherAllocator>& other) const noexcept {
  auto result = *this;
  result |= other;
  return result;
}

template BitVector<StdAllocator> BitVector<StdAllocator>::operator|(
    const BitVector<StdAllocator>& other) const noexcept;
template BitVector<StdAllocator> BitVector<StdAllocator>::operator|(
    const BitVector<AlignedAllocator>& other) const noexcept;
template BitVector<AlignedAllocator> BitVector<AlignedAllocator>::operator|(
    const BitVector<StdAllocator>& other) const noexcept;
template BitVector<AlignedAllocator> BitVector<AlignedAllocator>::operator|(
    const BitVector<AlignedAllocator>& other) const noexcept;

template <typename Allocator>
BitVector<Allocator> BitVector<Allocator>::operator|(const BitSpan& bit_span) const noexcept {
  return bit_span | *this;
}

template <typename Allocator>
BitVector<Allocator>& BitVector<Allocator>::operator=(const BitVector<Allocator>& other) noexcept {
  bit_size_ = other.bit_size_;
  data_vector_ = other.data_vector_;
  return *this;
}

template <typename Allocator>
template <typename OtherAllocator>
BitVector<Allocator>& BitVector<Allocator>::operator=(
    const BitVector<OtherAllocator>& other) noexcept {
  bit_size_ = other.GetSize();
  data_vector_.assign(other.data_vector_.cbegin(), other.data_vector_.cend());
  return *this;
}

template BitVector<StdAllocator>& BitVector<StdAllocator>::operator=(
    const BitVector<AlignedAllocator>& other) noexcept;
template BitVector<AlignedAllocator>& BitVector<AlignedAllocator>::operator=(
    const BitVector<StdAllocator>& other) noexcept;

template <typename Allocator>
BitVector<Allocator>& BitVector<Allocator>::operator=(BitVector<Allocator>&& other) noexcept {
  bit_size_ = other.GetSize();
  data_vector_ = std::move(other.data_vector_);
  return *this;
}

template <typename Allocator>
template <typename OtherAllocator>
bool BitVector<Allocator>::operator==(const BitVector<OtherAllocator>& other) const noexcept {
  if (bit_size_ != other.GetSize()) {
    return false;
  }
  assert(data_vector_.size() == other.GetData().size());
  if constexpr (std::is_same_v<Allocator, OtherAllocator>) {
    return data_vector_ == other.data_vector_;
  } else {
    return std::equal(data_vector_.begin(), data_vector_.end(), other.data_vector_.begin());
  }
}

template bool BitVector<StdAllocator>::operator==(
    const BitVector<StdAllocator>& other) const noexcept;
template bool BitVector<StdAllocator>::operator==(
    const BitVector<AlignedAllocator>& other) const noexcept;
template bool BitVector<AlignedAllocator>::operator==(
    const BitVector<StdAllocator>& other) const noexcept;
template bool BitVector<AlignedAllocator>::operator==(
    const BitVector<AlignedAllocator>& other) const noexcept;

template <typename Allocator>
bool BitVector<Allocator>::operator==(const BitSpan& bit_span) const noexcept {
  return bit_span.operator==(*this);
}

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
void BitVector<Allocator>::Set(bool value, std::size_t position) {
  if (position >= bit_size_) {
    throw std::out_of_range(fmt::format("BitVector: accessing {} of {}", position, bit_size_));
  }

  std::size_t byte_offset = position / 8;
  std::size_t bit_offset = position % 8;

  if (value) {
    data_vector_.at(byte_offset) |= kSetBitMask[bit_offset];
  } else {
    data_vector_.at(byte_offset) &= kUnsetBitMask[bit_offset];
  }
}

template <typename Allocator>
bool BitVector<Allocator>::Get(std::size_t position) const {
  if (position >= bit_size_) {
    throw std::out_of_range(fmt::format("BitVector: accessing {} of {}", position, bit_size_));
  }

  std::size_t byte_offset = position / 8;
  std::size_t bit_offset = position % 8;

  auto result = data_vector_.at(byte_offset);
  result &= kSetBitMask[bit_offset];

  return result == kSetBitMask[bit_offset];
}

template <typename Allocator>
template <typename OtherAllocator>
BitVector<Allocator>& BitVector<Allocator>::operator&=(
    const BitVector<OtherAllocator>& other) noexcept {
  const auto max_bit_size = std::max(bit_size_, other.GetSize());
  const auto min_byte_size = std::min(data_vector_.size(), other.GetData().size());

  Resize(max_bit_size, true);

  for (auto i = 0ull; i < min_byte_size; ++i) {
    data_vector_.at(i) &= other.GetData().at(i);
  }
  return *this;
}

template BitVector<StdAllocator>& BitVector<StdAllocator>::operator&=(
    const BitVector<StdAllocator>& other) noexcept;
template BitVector<StdAllocator>& BitVector<StdAllocator>::operator&=(
    const BitVector<AlignedAllocator>& other) noexcept;
template BitVector<AlignedAllocator>& BitVector<AlignedAllocator>::operator&=(
    const BitVector<StdAllocator>& other) noexcept;
template BitVector<AlignedAllocator>& BitVector<AlignedAllocator>::operator&=(
    const BitVector<AlignedAllocator>& other) noexcept;

template <typename Allocator>
BitVector<Allocator>& BitVector<Allocator>::operator&=(const BitSpan& bit_span) noexcept {
  BoundsCheckEquality(bit_span.GetSize());

  const auto byte_size{BitsToBytes(bit_span.GetSize())};

  if (IsAligned() && bit_span.IsAligned())
    AlignedAndImplementation(bit_span.GetData(), data_vector_.data(), byte_size);
  else
    AndImplementation(bit_span.GetData(), data_vector_.data(), byte_size);
  return *this;
}

template <typename Allocator>
template <typename OtherAllocator>
BitVector<Allocator>& BitVector<Allocator>::operator^=(
    const BitVector<OtherAllocator>& other) noexcept {
  auto min_byte_size = std::min(data_vector_.size(), other.data_vector_.size());

  std::transform(data_vector_.cbegin(), data_vector_.cbegin() + min_byte_size,
                 other.data_vector_.cbegin(), data_vector_.begin(),
                 [](auto a, auto b) { return a ^ b; });

  return *this;
}

template BitVector<StdAllocator>& BitVector<StdAllocator>::operator^=(
    const BitVector<StdAllocator>& other) noexcept;
template BitVector<StdAllocator>& BitVector<StdAllocator>::operator^=(
    const BitVector<AlignedAllocator>& other) noexcept;
template BitVector<AlignedAllocator>& BitVector<AlignedAllocator>::operator^=(
    const BitVector<StdAllocator>& other) noexcept;
template BitVector<AlignedAllocator>& BitVector<AlignedAllocator>::operator^=(
    const BitVector<AlignedAllocator>& other) noexcept;

template <typename Allocator>
BitVector<Allocator>& BitVector<Allocator>::operator^=(const BitSpan& bit_span) noexcept {
  BoundsCheckEquality(bit_span.GetSize());

  const auto byte_size{BitsToBytes(bit_span.GetSize())};

  if (IsAligned() && bit_span.IsAligned())
    AlignedXorImplementation(bit_span.GetData(), data_vector_.data(), byte_size);
  else
    XorImplementation(bit_span.GetData(), data_vector_.data(), byte_size);
  return *this;
}

template <typename Allocator>
template <typename OtherAllocator>
BitVector<Allocator>& BitVector<Allocator>::operator|=(
    const BitVector<OtherAllocator>& other) noexcept {
  const auto max_bit_size = std::max(bit_size_, other.GetSize());
  const auto min_byte_size = std::min(data_vector_.size(), other.GetData().size());
  const auto max_byte_size = BitsToBytes(max_bit_size);

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

template BitVector<StdAllocator>& BitVector<StdAllocator>::operator|=(
    const BitVector<StdAllocator>& other) noexcept;
template BitVector<StdAllocator>& BitVector<StdAllocator>::operator|=(
    const BitVector<AlignedAllocator>& other) noexcept;
template BitVector<AlignedAllocator>& BitVector<AlignedAllocator>::operator|=(
    const BitVector<StdAllocator>& other) noexcept;
template BitVector<AlignedAllocator>& BitVector<AlignedAllocator>::operator|=(
    const BitVector<AlignedAllocator>& other) noexcept;

template <typename Allocator>
BitVector<Allocator>& BitVector<Allocator>::operator|=(const BitSpan& bit_span) noexcept {
  BoundsCheckEquality(bit_span.GetSize());

  const auto byte_size{BitsToBytes(bit_span.GetSize())};

  if (IsAligned() && bit_span.IsAligned())
    AlignedOrImplementation(bit_span.GetData(), data_vector_.data(), byte_size);
  else
    OrImplementation(bit_span.GetData(), data_vector_.data(), byte_size);
  return *this;
}

template <typename Allocator>
void BitVector<Allocator>::Resize(std::size_t number_of_bits, bool zero_fill) noexcept {
  if (bit_size_ == number_of_bits) {
    return;
  }
  bit_size_ = number_of_bits;
  const auto byte_size = BitsToBytes(bit_size_);
  if (zero_fill) {
    constexpr std::byte kZeroByte = std::byte();
    data_vector_.reserve(byte_size);
    while (data_vector_.size() < byte_size) {
      data_vector_.push_back(kZeroByte);
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
      data_vector_.push_back(kSetBitMask[0]);
    } else {
      data_vector_.push_back(std::byte(0));
    }
  } else {
    if (bit) {
      data_vector_.at(data_vector_.size() - 1) |= kSetBitMask[bit_offset];
    }
  }
  ++bit_size_;
}

template <typename Allocator>
void BitVector<Allocator>::Append(const std::byte* pointer,
                                  const std::size_t append_bit_size) noexcept {
  if (append_bit_size > 0u) {
    const auto old_bit_offset = bit_size_ % 8;
    const auto append_byte_size = BitsToBytes(append_bit_size);
    const auto new_bit_size = bit_size_ + append_bit_size;
    const auto new_byte_size = BitsToBytes(new_bit_size);

    if (new_bit_size <= 8u) {
      if (bit_size_ == 0u) {
        data_vector_.emplace_back(*pointer);
      } else {
        data_vector_.at(0) |= (*pointer >> old_bit_offset);
      }
    } else if (old_bit_offset == 0u) {
      data_vector_.insert(data_vector_.end(), pointer, pointer + append_byte_size);
    } else if (old_bit_offset + append_bit_size <= 8u) {
      data_vector_.at(data_vector_.size() - 1) |= *pointer >> old_bit_offset;
    } else if (append_bit_size <= 8u) {
      data_vector_.at(data_vector_.size() - 1) |= *pointer >> old_bit_offset;
      if (old_bit_offset + append_bit_size > 8u) {
        data_vector_.push_back(*pointer << (8 - old_bit_offset));
      }
    } else {
      auto old_byte_offset = data_vector_.size() - 1;
      constexpr std::byte zero_byte = std::byte();
      data_vector_.reserve(new_byte_size);
      while (data_vector_.size() < new_byte_size) {
        data_vector_.push_back(zero_byte);
      }
      for (std::size_t i = 0; i < append_byte_size; ++i) {
        data_vector_.at(old_byte_offset) |= (*(pointer + i) >> old_bit_offset);
        const bool other_has_next_block = i + 1 < append_byte_size;
        const bool last_shift_needed = old_bit_offset + (append_bit_size % 8) > 8u;
        const bool other_fits_byte_size = append_bit_size % 8 == 0;
        if (other_has_next_block || last_shift_needed || other_fits_byte_size) {
          data_vector_.at(old_byte_offset + 1) |= *(pointer + i) << (8 - old_bit_offset);
        }
        ++old_byte_offset;
      }
    }
    bit_size_ = new_bit_size;
  }
}

template <typename Allocator>
void BitVector<Allocator>::Append(const BitVector<Allocator>& other) noexcept {
  Append(other.GetData().data(), other.GetSize());
  // No need to truncate because the BitVector is zero-padded
}

// XXX this method does the same thing as the method above. Remove or change.
template <typename Allocator>
void BitVector<Allocator>::Append(BitVector&& other) noexcept {
  if (other.GetSize() > 0u) {
    Append(other);
    // No need to truncate because the BitVector is zero-padded
  }
}

template <typename Allocator>
void BitVector<Allocator>::Append(const BitSpan& bit_span) {
  if (bit_span.GetSize() > 0u) {
    Append(bit_span.GetData());
    // Need to truncate because the buffer is not owned and we do not know what bits are behind
    // the assigned range
    TruncateToFit();
  }
}

// XXX this method does the same thing as the method above. Remove or change.
template <typename Allocator>
void BitVector<Allocator>::Append(BitSpan&& bit_span) {
  if (bit_span.GetSize() > 0u) {
    Append(bit_span.GetData(), bit_span.GetSize());
    // Need to truncate because the buffer is not owned and we do not know what bits are behind
    // the assigned range
    TruncateToFit();
  }
}

template <typename Allocator>
void BitVector<Allocator>::Copy(const std::size_t dest_from, const std::size_t dest_to,
                                const BitVector& other) {
  assert(dest_from <= dest_to);
  const std::size_t bitlength = dest_to - dest_from;

  if (dest_from > bit_size_ || dest_to > bit_size_) {
    throw std::out_of_range(
        fmt::format("Accessing positions {} to {} of {}", dest_from, dest_to, bit_size_));
  }

  if (bitlength > other.GetSize()) {
    throw std::out_of_range(
        fmt::format("Accessing position {} of {}", dest_to - dest_from, other.GetSize()));
  }

  if (dest_from == dest_to) {
    return;
  }

  const auto number_of_bits = dest_to - dest_from;

  if (number_of_bits == 1) {
    Set(other.Get(0), dest_from);
    return;
  }

  const auto destination_to_offset = dest_to % 8;
  const auto destination_from_offset = dest_from % 8;

  if (destination_from_offset + number_of_bits < 8) {
    const auto mask = (std::byte(0xFF) >> destination_from_offset) &
                      (std::byte(0xFF) << (8 - destination_from_offset - number_of_bits));
    const auto from_bytes = dest_from / 8;
    data_vector_.at(from_bytes) &= ~mask;
    data_vector_.at(from_bytes) |= (other.GetData().at(0) >> destination_from_offset) & mask;
  } else if ((dest_from % 8) == 0) {
    const auto number_of_bytes = BitsToBytes(number_of_bits);
    const auto from_bytes = dest_from / 8;
    const auto destination_to_1 = destination_to_offset > 0 ? 1 : 0;
    for (auto i = 0ull; i < number_of_bytes - destination_to_1; ++i) {
      data_vector_.at(from_bytes + i) = other.GetData().at(i);
    }
    if (destination_to_offset > 0) {
      const auto mask = std::byte(0xFF) >> destination_to_offset;
      data_vector_.at(from_bytes + number_of_bytes - 1) &= mask;
      data_vector_.at(from_bytes + number_of_bytes - 1) |=
          (other.GetData().at(number_of_bytes - 1) & ~mask);
    }
  } else {
    const auto number_of_bytes = BitsToBytes(destination_from_offset + number_of_bits);
    const auto number_of_complete_bytes =
        BitsToBytes(number_of_bits - (8 - destination_from_offset) - destination_to_offset);
    const auto destination_from_offset = dest_from % 8;
    BitVector tmp(destination_from_offset);
    if (number_of_bits != other.GetSize()) {
      tmp.Append(other.Subset(0, number_of_bits));
    } else {
      tmp.Append(other);
    }
    const auto from_bytes = dest_from / 8;

    const auto mask = ~(std::byte(0xFF) >> destination_from_offset);
    data_vector_.at(from_bytes) &= mask;
    data_vector_.at(from_bytes) |= tmp.data_vector_.at(0);

    if (number_of_complete_bytes > 0u) {
      std::copy(tmp.data_vector_.begin() + 1,
                tmp.data_vector_.begin() + number_of_complete_bytes + 1,
                data_vector_.begin() + from_bytes + 1);
    }

    if (destination_to_offset > 0) {
      auto mask = std::byte(0xFFu >> destination_to_offset);
      data_vector_.at(from_bytes + number_of_bytes - 1) &= mask;
      data_vector_.at(from_bytes + number_of_bytes - 1) |=
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

  BitVector bit_vector;
  if (from == to) {
    return bit_vector;
  }

  if (to - from == bit_size_) {
    return *this;
  }

  bit_vector.Resize(to - from);

  const auto from_bit_offset = from % 8;

  if (from_bit_offset == 0u) {
    std::copy(data_vector_.begin() + (from / 8), data_vector_.begin() + (BitsToBytes(to)),
              bit_vector.data_vector_.begin());
  } else if (from_bit_offset + bit_vector.bit_size_ <= 8u) {
    bit_vector.data_vector_.at(0) = data_vector_.at(from / 8);
    bit_vector.data_vector_.at(0) <<= from_bit_offset;
  } else {
    auto new_byte_offset = 0ull;
    auto bit_counter = 0ull;
    const auto max = bit_vector.bit_size_;
    for (; bit_counter < max; ++new_byte_offset) {
      auto left_part = data_vector_.at((from / 8) + new_byte_offset) << from_bit_offset;
      bit_vector.data_vector_.at(new_byte_offset) |= left_part;
      bit_counter += 8 - from_bit_offset;
      if (bit_counter < max) {
        auto right_part =
            data_vector_.at((from / 8) + new_byte_offset + 1) >> (8 - from_bit_offset);
        bit_vector.data_vector_.at(new_byte_offset) |= right_part;
        bit_counter += from_bit_offset;
      }
    }
  }

  bit_vector.TruncateToFit();

  return bit_vector;
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
BitVector<Allocator> BitVector<Allocator>::RandomSeeded(const std::size_t size,
                                                        const std::size_t seed) noexcept {
  std::mt19937_64 e(seed);
  std::uniform_int_distribution<std::uint64_t> dist(0, std::numeric_limits<std::uint64_t>::max());
  std::uniform_int_distribution<std::uint64_t> dist_bool(0, 1);

  BitVector bit_vector(size);
  auto pointer = reinterpret_cast<std::uint64_t*>(bit_vector.data_vector_.data());

  std::size_t i;

  for (i = 0ull; i + 64 <= size; i += 64) {
    *(pointer + (i / 64)) = dist(e);
  }

  for (; i < size; ++i) {
    bit_vector.Set(dist_bool(e) == true, i);
  }

  return bit_vector;
}

template <typename Allocator>
BitVector<Allocator> BitVector<Allocator>::SecureRandom(const std::size_t bit_size) noexcept {
  auto byte_size = BitsToBytes(bit_size);
  BitVector bit_vector(bit_size);

  auto& rng = DefaultRng::GetThreadInstance();
  rng.RandomBytes(bit_vector.data_vector_.data(), byte_size);
  bit_vector.TruncateToFit();

  return bit_vector;
}

template <typename Allocator>
bool BitVector<Allocator>::AndReduceBitVector(const BitVector& bit_vector) {
  if (bit_vector.GetSize() == 0) {
    return true;
  } else if (bit_vector.GetSize() == 1) {
    return bit_vector.Get(0);
  } else if (bit_vector.GetSize() <= 16) {
    bool result = bit_vector.Get(0);
    for (auto i = 1ull; i < bit_vector.GetSize(); ++i) {
      result &= bit_vector.Get(i);
    }
    return result;
  } else {
    auto raw_vector = bit_vector.GetData();
    std::byte b = raw_vector.at(0);

    const bool div_by_8{(bit_vector.GetSize() % 8) == 0};
    const auto size{div_by_8 ? raw_vector.size() : raw_vector.size() - 1};
    const auto remainder_size{bit_vector.GetSize() - (size * 8)};

    for (auto i = 1ull; i < size; ++i) b &= raw_vector.at(i);

    BitVector tmp({b}, 8);
    bool result{b == std::byte(0xFF)};

    for (auto i = 1; i < 8; ++i) result &= tmp.Get(i);

    for (std::size_t i = 0; i < remainder_size; ++i)
      result &= bit_vector.Get(bit_vector.GetSize() - i - 1);

    return result;
  }
}

template <typename Allocator>
BitVector<Allocator> BitVector<Allocator>::AndBitVectors(
    const std::vector<BitVector>& bit_vectors) {
  if (bit_vectors.size() == 0) {
    return {};
  } else if (bit_vectors.size() == 1) {
    return bit_vectors.at(0);
  } else {
    auto result = bit_vectors.at(0);

    for (auto i = 1ull; i < bit_vectors.size(); ++i) {
      result &= bit_vectors.at(i);
    }
    return result;
  }
}

template <typename Allocator>
bool BitVector<Allocator>::OrReduceBitVector(const BitVector& bit_vector) {
  if (bit_vector.GetSize() == 0) {
    return {};
  } else if (bit_vector.GetSize() == 1) {
    return bit_vector.Get(0);
  } else if (bit_vector.GetSize() <= 64) {
    bool result = bit_vector.Get(0);
    for (auto i = 1ull; i < bit_vector.GetSize(); ++i) {
      result |= bit_vector.Get(i);
    }
    return result;
  } else {
    auto raw_vector = bit_vector.GetData();
    std::byte b = raw_vector.at(0);

    for (auto i = 1ull; i < raw_vector.size(); ++i) {
      b |= raw_vector.at(i);
    }
    BitVector tmp({b}, 8);
    bool result = tmp.Get(0);

    for (auto i = 1; i < 8; ++i) {
      result |= tmp.Get(i);
    }

    return result;
  }
}

template <typename Allocator>
BitVector<Allocator> BitVector<Allocator>::OrBitVectors(const std::vector<BitVector>& bit_vectors) {
  if (bit_vectors.size() == 0) {
    return {};
  } else if (bit_vectors.size() == 1) {
    return bit_vectors.at(0);
  } else {
    auto result = bit_vectors.at(0);

    for (auto i = 1ull; i < bit_vectors.size(); ++i) {
      result |= bit_vectors.at(i);
    }
    return result;
  }
}

template <typename Allocator>
std::vector<BitVector<Allocator>> BitVector<Allocator>::AndBitVectors(
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
std::vector<BitVector<Allocator>> BitVector<Allocator>::AndBitVectors(
    const std::vector<std::vector<BitVector>>& bit_vectors) {
  if (bit_vectors.size() == 0) {
    return {};
  } else if (bit_vectors.size() == 1) {
    return bit_vectors.at(0);
  } else {
    auto result = bit_vectors.at(0);
    for (auto i = 1ull; i < bit_vectors.size(); ++i) {
      result = AndBitVectors(result, bit_vectors.at(i));
    }
    return result;
  }
}

template <typename Allocator>
bool BitVector<Allocator>::XorReduceBitVector(const BitVector& bit_vector) {
  if (bit_vector.GetSize() == 0) {
    return {};
  } else if (bit_vector.GetSize() == 1) {
    return bit_vector.Get(0);
  } else if (bit_vector.GetSize() <= 64) {
    bool result = bit_vector.Get(0);
    for (auto i = 1ull; i < bit_vector.GetSize(); ++i) {
      result ^= bit_vector.Get(i);
    }
    return result;
  } else {
    auto raw_vector = bit_vector.GetData();
    std::byte b = raw_vector.at(0);

    for (auto i = 1ull; i < raw_vector.size(); ++i) {
      b ^= raw_vector.at(i);
    }
    BitVector tmp({b}, 8);
    bool result = tmp.Get(0);

    for (auto i = 1; i < 8; ++i) {
      result ^= tmp.Get(i);
    }

    return result;
  }
}

template <typename Allocator>
BitVector<Allocator> BitVector<Allocator>::XorBitVectors(
    const std::vector<BitVector>& bit_vectors) {
  if (bit_vectors.size() == 0) {
    return {};
  } else if (bit_vectors.size() == 1) {
    return bit_vectors.at(0);
  } else {
    auto result = bit_vectors.at(0);

    for (auto i = 1ull; i < bit_vectors.size(); ++i) {
      result ^= bit_vectors.at(i);
    }
    return result;
  }
}

template <typename Allocator>
std::vector<BitVector<Allocator>> BitVector<Allocator>::XorBitVectors(
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
std::vector<BitVector<Allocator>> BitVector<Allocator>::XorBitVectors(
    const std::vector<std::vector<BitVector>>& bit_vectors) {
  if (bit_vectors.size() == 0) {
    return {};
  } else if (bit_vectors.size() == 1) {
    return bit_vectors.at(0);
  } else {
    auto result = bit_vectors.at(0);
    for (auto i = 1ull; i < bit_vectors.size(); ++i) {
      result = XorBitVectors(result, bit_vectors.at(i));
    }
    return result;
  }
}

template <typename Allocator>
bool BitVector<Allocator>::IsEqualSizeDimensions(const std::vector<BitVector>& bit_vectors) {
  if (bit_vectors.size() <= 1) {
    return true;
  } else {
    auto first_size = bit_vectors.at(0).GetSize();
    for (auto i = 1ull; i < bit_vectors.size(); ++i) {
      if (first_size != bit_vectors.at(i).GetSize()) {
        return false;
      }
    }
  }
  return true;
}

template <typename Allocator>
void BitVector<Allocator>::TruncateToFit() noexcept {
  const auto bit_offset = bit_size_ % 8;
  if (bit_offset > 0u) {
    data_vector_.at(data_vector_.size() - 1) &= TruncationBitMask[bit_offset - 1];
  }
}
template <typename Allocator>
void BitVector<Allocator>::BoundsCheckEquality([[maybe_unused]] const std::size_t bit_size) const {
  if constexpr (kDebug) {
    if (bit_size_ != bit_size)
      throw std::logic_error(
          fmt::format("Required exact size match with {}, but got {}", bit_size_, bit_size));
  }
}

template <typename Allocator>
void BitVector<Allocator>::BoundsCheckInRange([[maybe_unused]] const std::size_t bit_size) const {
  if constexpr (kDebug) {
    if (bit_size_ != bit_size)
      throw std::out_of_range(fmt::format("Trying to access {} from {}", bit_size_, bit_size));
  }
}

template class BitVector<StdAllocator>;
template class BitVector<AlignedAllocator>;

template <>
std::vector<BitVector<StdAllocator>> ToInput<float, std::true_type, StdAllocator>(float t) {
  uint32_t tmp;
  std::copy(reinterpret_cast<std::uint32_t*>(&t), reinterpret_cast<std::uint32_t*>(&t) + 1, &tmp);
  return ToInput(tmp);
}

template <>
std::vector<BitVector<StdAllocator>> ToInput<double, std::true_type, StdAllocator>(double t) {
  uint64_t tmp;
  std::copy(reinterpret_cast<std::uint64_t*>(&t), reinterpret_cast<std::uint64_t*>(&t) + 1, &tmp);
  return ToInput(tmp);
}

template <>
std::vector<BitVector<StdAllocator>> ToInput<float, std::true_type, StdAllocator>(
    const std::vector<float>& vector_of_floats) {
  std::vector<std::uint32_t> vector_of_floats_converted;
  vector_of_floats_converted.reserve(vector_of_floats.size());
  for (const auto& f : vector_of_floats)
    vector_of_floats_converted.emplace_back(*reinterpret_cast<const std::uint32_t*>(&f));
  return ToInput(vector_of_floats_converted);
}

template <>
std::vector<BitVector<StdAllocator>> ToInput<double, std::true_type, StdAllocator>(
    const std::vector<double>& vector_of_doubles) {
  std::vector<std::uint32_t> vector_of_doubles_converted;
  vector_of_doubles_converted.reserve(vector_of_doubles.size());
  for (const auto& d : vector_of_doubles)
    vector_of_doubles_converted.emplace_back(*reinterpret_cast<const std::uint64_t*>(&d));
  return ToInput(vector_of_doubles_converted);
}

template <typename IntegralType, typename, typename Allocator>
std::vector<BitVector<Allocator>> ToInput(IntegralType integral_value) {
  constexpr auto kBitLength{sizeof(IntegralType) * 8};

  static_assert(std::is_integral<IntegralType>::value);
  static_assert(sizeof(IntegralType) <= 8);
  if constexpr (sizeof(IntegralType) == 1) {
    static_assert(std::is_same_v<IntegralType, std::uint8_t>);
  } else if constexpr (sizeof(IntegralType) == 2) {
    static_assert(std::is_same_v<IntegralType, std::uint16_t>);
  } else if constexpr (sizeof(IntegralType) == 4) {
    static_assert(std::is_same_v<IntegralType, std::uint32_t>);
  } else if constexpr (sizeof(IntegralType) == 8) {
    static_assert(std::is_same_v<IntegralType, std::uint64_t>);
  }
  std::vector<BitVector<Allocator>> result;
  for (auto i = 0ull; i < kBitLength; ++i) result.emplace_back(1, ((integral_value >> i) & 1) == 1);
  return result;
}

template std::vector<BitVector<StdAllocator>> ToInput(std::uint8_t);
template std::vector<BitVector<StdAllocator>> ToInput(std::uint16_t);
template std::vector<BitVector<StdAllocator>> ToInput(std::uint32_t);
template std::vector<BitVector<StdAllocator>> ToInput(std::uint64_t);

template <typename IntegralType, typename, typename Allocator>
std::vector<BitVector<Allocator>> ToInput(const std::vector<IntegralType>& input_vector) {
  static_assert(std::is_integral<IntegralType>::value);
  static_assert(sizeof(IntegralType) <= 8);
  if constexpr (sizeof(IntegralType) == 1) {
    static_assert(std::is_same_v<IntegralType, std::uint8_t>);
  } else if constexpr (sizeof(IntegralType) == 2) {
    static_assert(std::is_same_v<IntegralType, std::uint16_t>);
  } else if constexpr (sizeof(IntegralType) == 4) {
    static_assert(std::is_same_v<IntegralType, std::uint32_t>);
  } else if constexpr (sizeof(IntegralType) == 8) {
    static_assert(std::is_same_v<IntegralType, std::uint64_t>);
  }

  constexpr auto kBitLength{sizeof(IntegralType) * 8};
  std::vector<BitVector<Allocator>> result(kBitLength);
  for (auto i = 0ull; i < input_vector.size(); ++i) {
    for (auto j = 0ull; j < kBitLength; ++j) {
      result.at(j).Append(BitVector<Allocator>(1, ((input_vector.at(i) >> j) & 1) == 1));
    }
  }
  return result;
}

template std::vector<BitVector<StdAllocator>> ToInput(const std::vector<std::uint8_t>&);
template std::vector<BitVector<StdAllocator>> ToInput(const std::vector<std::uint16_t>&);
template std::vector<BitVector<StdAllocator>> ToInput(const std::vector<std::uint32_t>&);
template std::vector<BitVector<StdAllocator>> ToInput(const std::vector<std::uint64_t>&);

BitSpan::BitSpan(std::byte* buffer, std::size_t bit_size, bool aligned)
    : pointer_(buffer), bit_size_(bit_size), aligned_(aligned) {}

BitSpan::BitSpan(const BitSpan& other) { *this = other; }

BitSpan::BitSpan(BitSpan&& other) { *this = std::move(other); }

BitSpan& BitSpan::operator=(const BitSpan& other) {
  pointer_ = other.pointer_;
  bit_size_ = other.bit_size_;
  aligned_ = other.aligned_;
  return *this;
}

BitSpan& BitSpan::operator=(BitSpan&& other) {
  pointer_ = other.pointer_;
  bit_size_ = other.bit_size_;
  aligned_ = other.aligned_;
  return *this;
}

template <typename BitVectorType>
bool BitSpan::operator==(const BitVectorType& other) const {
  assert(bit_size_ == other.GetSize());
  const auto byte_size{BitsToBytes(bit_size_)};
  if (aligned_ && other.IsAligned())
    return AlignedEqualImplementation(pointer_, other.GetData().data(), byte_size);
  else
    return EqualImplementation(pointer_, other.GetData().data(), byte_size);
}

template bool BitSpan::operator==(const BitVector<StdAllocator>& other) const;
template bool BitSpan::operator==(const BitVector<AlignedAllocator>& other) const;

bool BitSpan::operator==(const BitSpan& other) const {
  assert(bit_size_ == other.bit_size_);
  const auto byte_size{BitsToBytes(bit_size_)};
  if (aligned_ && other.aligned_)
    return AlignedEqualImplementation(pointer_, other.pointer_, byte_size);
  else
    return EqualImplementation(pointer_, other.pointer_, byte_size);
}

template <typename BitVectorType>
BitVectorType BitSpan::operator&(const BitVectorType& other) const {
  assert(bit_size_ == other.GetSize());
  const auto byte_size{BitsToBytes(bit_size_)};
  BitVectorType result;
  if constexpr (BitVectorType::IsAligned()) {
    result = BitVectorType(pointer_, bit_size_);
    AlignedAndImplementation(other.GetData().data(), result.GetMutableData().data(), byte_size);
  } else {  // we do not want an AlignedBitVector as output
    result = BitVectorType(pointer_, bit_size_);
    AndImplementation(other.GetData().data(), result.GetMutableData().data(), byte_size);
  }
  return result;
}

template BitVector<StdAllocator> BitSpan::operator&(const BitVector<StdAllocator>& other) const;
template BitVector<AlignedAllocator> BitSpan::operator&(
    const BitVector<AlignedAllocator>& other) const;

template <typename BitVectorType>
BitVectorType BitSpan::operator&(const BitSpan& other) const {
  assert(bit_size_ == other.bit_size_);
  const auto byte_size{BitsToBytes(bit_size_)};
  BitVectorType result;
  if constexpr (std::is_same_v<AlignedBitVector, BitVectorType>) {
    if (other.aligned_) {
      result = BitVectorType(pointer_, bit_size_);
      AlignedAndImplementation(other.pointer_, result.GetMutableData().data(), byte_size);
    } else if (aligned_) {
      result = BitVectorType(other.pointer_, bit_size_);
      AlignedAndImplementation(pointer_, result.GetMutableData().data(), byte_size);
    } else {  // none of both is aligned
      result = BitVectorType(pointer_, bit_size_);
      AndImplementation(other.pointer_, result.GetMutableData().data(), byte_size);
    }
  } else {  // we do not want an AlignedBitVector as output
    result = BitVectorType(pointer_, bit_size_);
    AndImplementation(other.pointer_, result.GetMutableData().data(), byte_size);
  }
  return result;
}

template BitVector<StdAllocator> BitSpan::operator&(const BitSpan& other) const;
template BitVector<AlignedAllocator> BitSpan::operator&(const BitSpan& other) const;

template <typename BitVectorType>
BitVectorType BitSpan::operator|(const BitVectorType& other) const {
  assert(bit_size_ == other.GetSize());
  const auto byte_size{BitsToBytes(bit_size_)};
  BitVectorType result;
  if constexpr (BitVectorType::IsAligned()) {
    result = BitVectorType(pointer_, bit_size_);
    AlignedOrImplementation(other.GetData().data(), result.GetMutableData().data(), byte_size);
  } else {
    result = BitVectorType(pointer_, bit_size_);
    OrImplementation(other.GetData().data(), result.GetMutableData().data(), byte_size);
  }
  return result;
}

template BitVector<StdAllocator> BitSpan::operator|(const BitVector<StdAllocator>& other) const;
template BitVector<AlignedAllocator> BitSpan::operator|(
    const BitVector<AlignedAllocator>& other) const;

template <typename BitVectorType>
BitVectorType BitSpan::operator|(const BitSpan& other) const {
  assert(bit_size_ == other.bit_size_);
  const auto byte_size{BitsToBytes(bit_size_)};
  BitVectorType result;
  if constexpr (std::is_same_v<AlignedBitVector, BitVectorType>) {
    if (other.aligned_) {
      result = BitVectorType(pointer_, bit_size_);
      AlignedOrImplementation(other.pointer_, result.GetMutableData().data(), byte_size);
    } else if (aligned_) {
      result = BitVectorType(other.pointer_, bit_size_);
      AlignedOrImplementation(pointer_, result.GetMutableData().data(), byte_size);
    } else {
      result = BitVectorType(pointer_, bit_size_);
      OrImplementation(other.pointer_, result.GetMutableData().data(), byte_size);
    }
  } else {
    result = BitVectorType(pointer_, bit_size_);
    OrImplementation(other.pointer_, result.GetMutableData().data(), byte_size);
  }
  return result;
}

template BitVector<StdAllocator> BitSpan::operator|(const BitSpan& other) const;
template BitVector<AlignedAllocator> BitSpan::operator|(const BitSpan& other) const;

template <typename BitVectorType>
BitVectorType BitSpan::operator^(const BitVectorType& other) const {
  assert(bit_size_ == other.GetSize());
  const auto byte_size{BitsToBytes(bit_size_)};
  BitVectorType result;
  if constexpr (BitVectorType::IsAligned()) {
    result = BitVectorType(pointer_, bit_size_);
    AlignedXorImplementation(other.GetData().data(), result.GetMutableData().data(), byte_size);
  } else {
    result = BitVectorType(pointer_, bit_size_);
    XorImplementation(other.GetData().data(), result.GetMutableData().data(), byte_size);
  }
  return result;
}

template BitVector<StdAllocator> BitSpan::operator^(const BitVector<StdAllocator>& other) const;
template BitVector<AlignedAllocator> BitSpan::operator^(
    const BitVector<AlignedAllocator>& other) const;

template <typename BitVectorType>
BitVectorType BitSpan::operator^(const BitSpan& other) const {
  assert(bit_size_ == other.bit_size_);
  const auto byte_size{BitsToBytes(bit_size_)};
  BitVectorType result;
  if constexpr (std::is_same_v<AlignedBitVector, BitVectorType>) {
    if (other.aligned_) {
      result = BitVectorType(pointer_, bit_size_);
      AlignedXorImplementation(other.pointer_, result.GetMutableData().data(), byte_size);
    } else if (aligned_) {
      result = BitVectorType(other.pointer_, bit_size_);
      AlignedXorImplementation(pointer_, result.GetMutableData().data(), byte_size);
    } else {
      result = BitVectorType(pointer_, bit_size_);
      XorImplementation(other.pointer_, result.GetMutableData().data(), byte_size);
    }
  } else {
    result = BitVectorType(pointer_, bit_size_);
    XorImplementation(other.pointer_, result.GetMutableData().data(), byte_size);
  }
  return result;
}

template BitVector<StdAllocator> BitSpan::operator^(const BitSpan& other) const;
template BitVector<AlignedAllocator> BitSpan::operator^(const BitSpan& other) const;

template <typename BitVectorType>
BitSpan& BitSpan::operator&=(const BitVectorType& other) {
  assert(bit_size_ == other.GetSize());
  const auto byte_size{BitsToBytes(bit_size_)};
  if constexpr (BitVectorType::IsAligned()) {
    if (aligned_)
      AlignedAndImplementation(other.GetData().data(), pointer_, byte_size);
    else
      AndImplementation(other.GetData().data(), pointer_, byte_size);
  } else
    AndImplementation(other.GetData().data(), pointer_, byte_size);
  return *this;
}

template BitSpan& BitSpan::operator&=(const BitVector<StdAllocator>& other);
template BitSpan& BitSpan::operator&=(const BitVector<AlignedAllocator>& other);

BitSpan& BitSpan::operator&=(const BitSpan& other) {
  assert(bit_size_ == other.bit_size_);
  const auto byte_size{BitsToBytes(bit_size_)};
  if (aligned_ && other.aligned_)
    AlignedAndImplementation(other.pointer_, pointer_, byte_size);
  else
    AndImplementation(other.pointer_, pointer_, byte_size);
  return *this;
}

template <typename BitVectorType>
BitSpan& BitSpan::operator|=(const BitVectorType& other) {
  assert(bit_size_ == other.GetSize());
  const auto byte_size{BitsToBytes(bit_size_)};
  if constexpr (BitVectorType::IsAligned()) {
    if (aligned_)
      AlignedOrImplementation(other.GetData().data(), pointer_, byte_size);
    else
      OrImplementation(other.GetData().data(), pointer_, byte_size);
  } else
    OrImplementation(other.GetData().data(), pointer_, byte_size);
  return *this;
}

template BitSpan& BitSpan::operator|=(const BitVector<StdAllocator>& other);
template BitSpan& BitSpan::operator|=(const BitVector<AlignedAllocator>& other);

BitSpan& BitSpan::operator|=(const BitSpan& other) {
  assert(bit_size_ == other.bit_size_);
  const auto byte_size{BitsToBytes(bit_size_)};
  if (aligned_ && other.aligned_)
    AlignedOrImplementation(other.pointer_, pointer_, byte_size);
  else
    OrImplementation(other.pointer_, pointer_, byte_size);
  return *this;
}

template <typename BitVectorType>
BitSpan& BitSpan::operator^=(const BitVectorType& other) {
  assert(bit_size_ == other.GetSize());
  const auto byte_size{BitsToBytes(bit_size_)};
  if constexpr (BitVectorType::IsAligned()) {
    if (aligned_)
      AlignedXorImplementation(other.GetData().data(), pointer_, byte_size);
    else
      XorImplementation(other.GetData().data(), pointer_, byte_size);
  } else
    XorImplementation(other.GetData().data(), pointer_, byte_size);
  return *this;
}

template BitSpan& BitSpan::operator^=(const BitVector<StdAllocator>& other);
template BitSpan& BitSpan::operator^=(const BitVector<AlignedAllocator>& other);

BitSpan& BitSpan::operator^=(const BitSpan& other) {
  assert(bit_size_ == other.bit_size_);
  const auto byte_size{BitsToBytes(bit_size_)};
  if (aligned_ && other.aligned_)
    AlignedXorImplementation(other.pointer_, pointer_, byte_size);
  else
    XorImplementation(other.pointer_, pointer_, byte_size);
  return *this;
}

bool BitSpan::Get(const std::size_t position) const {
  return GetImplementation(pointer_, position);
}

void BitSpan::Set(const bool value) { SetImplementation(pointer_, value, bit_size_); }

void BitSpan::Set(const bool value, const std::size_t position) {
  SetAtImplementation(pointer_, value, position);
}

void BitSpan::Invert() {
  std::transform(pointer_, pointer_ + NumberOfBitsToNumberOfBytes(bit_size_), pointer_,
                 [](std::byte& b) { return ~b; });
  TruncateToFitImplementation(pointer_, bit_size_);
}

template <typename BitVectorType>
BitVectorType BitSpan::Subset(const std::size_t from, const std::size_t to) const {
  if (from > to || to > bit_size_) {
    throw std::out_of_range(
        fmt::format("Accessing positions {} to {} in BitSpan of bit_size {}", from, to, bit_size_));
  }
  assert(from <= to);

  if (from == to) {
    return BitVectorType();
  }

  if (to - from == bit_size_) {
    return BitVectorType(pointer_, bit_size_);
  }

  const auto subset_bit_size{to - from};

  BitVectorType result;
  result.Resize(subset_bit_size);

  std::byte* result_pointer = result.IsAligned()
                                  ? reinterpret_cast<std::byte*>(__builtin_assume_aligned(
                                        result.GetMutableData().data(), kAlignment))
                                  : result.GetMutableData().data();
  const auto from_bit_offset{from % 8};

  if (from_bit_offset == 0u) {
    std::copy(pointer_ + (from / 8), pointer_ + (BitsToBytes(to)), result_pointer);
  } else if (from_bit_offset + subset_bit_size <= 8u) {
    *result_pointer = *(pointer_ + (from / 8));
    *result_pointer <<= from_bit_offset;
  } else {
    auto new_byte_offset = 0ull;
    auto bit_counter = 0ull;
    for (; bit_counter < subset_bit_size; ++new_byte_offset) {
      auto left_part = *(pointer_ + (from / 8) + new_byte_offset) << from_bit_offset;
      *(result_pointer + new_byte_offset) |= left_part;
      bit_counter += 8 - from_bit_offset;
      if (bit_counter < subset_bit_size) {
        auto right_part = *(pointer_ + (from / 8) + new_byte_offset + 1) >> (8 - from_bit_offset);
        *(result_pointer + new_byte_offset) |= right_part;
        bit_counter += from_bit_offset;
      }
    }
  }
  result.TruncateToFit();
  return result;
}

template BitVector<StdAllocator> BitSpan::Subset(const std::size_t from,
                                                 const std::size_t to) const;
template BitVector<AlignedAllocator> BitSpan::Subset(const std::size_t from,
                                                     const std::size_t to) const;

std::string BitSpan::AsString() const noexcept {
  std::string result;
  for (auto i = 0ull; i < bit_size_; ++i) {
    result.append(std::to_string(GetImplementation(pointer_, i)));
  }
  return result;
}

template <typename BitVectorType>
void BitSpan::Copy(const std::size_t dest_from, const std::size_t dest_to, BitVectorType& other) {
  const std::size_t bitlength = dest_to - dest_from;

  if (dest_from > bit_size_ || dest_to > bit_size_) {
    throw std::out_of_range(
        fmt::format("Accessing positions {} to {} of {}", dest_from, dest_to, bit_size_));
  }

  if (bitlength > other.GetSize()) {
    throw std::out_of_range(
        fmt::format("Accessing position {} of {}", dest_to - dest_from, other.GetSize()));
  }

  if (dest_from == dest_to) {
    return;
  }

  CopyImplementation(dest_from, dest_to, other.GetMutableData().data(), pointer_);
}

template void BitSpan::Copy<BitVector<StdAllocator>>(const std::size_t dest_from,
                                                     const std::size_t dest_to,
                                                     BitVector<StdAllocator>& other);
template void BitSpan::Copy<BitVector<AlignedAllocator>>(const std::size_t dest_from,
                                                         const std::size_t dest_to,
                                                         BitVector<AlignedAllocator>& other);

template <typename BitVectorType>
void BitSpan::Copy(const std::size_t dest_from, BitVectorType& other) {
  CopyImplementation(dest_from, dest_from + other.GetSize(), other.GetMutableData().data(),
                     pointer_);
}
template void BitSpan::Copy<BitVector<StdAllocator>>(const std::size_t dest_from,
                                                     BitVector<StdAllocator>& other);
template void BitSpan::Copy<BitVector<AlignedAllocator>>(const std::size_t dest_from,
                                                         BitVector<AlignedAllocator>& other);

void BitSpan::Copy(const std::size_t dest_from, const std::size_t dest_to, BitSpan&& other) {
  CopyImplementation(dest_from, dest_to, other.GetMutableData(), pointer_);
}

void BitSpan::Copy(const std::size_t dest_from, const std::size_t dest_to, BitSpan& other) {
  CopyImplementation(dest_from, dest_to, other.GetMutableData(), pointer_);
}

void BitSpan::Copy(const std::size_t dest_from, BitSpan& other) {
  CopyImplementation(dest_from, dest_from + other.bit_size_, other.GetMutableData(), pointer_);
}

void BitSpan::Copy(const std::size_t dest_from, BitSpan&& other) {
  CopyImplementation(dest_from, dest_from + other.bit_size_, other.GetMutableData(), pointer_);
}

std::ostream& operator<<(std::ostream& os, const BitSpan& bit_span) {
  return os << bit_span.AsString();
}

}  // namespace encrypto::motion
