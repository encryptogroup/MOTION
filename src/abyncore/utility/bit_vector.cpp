#include "bit_vector.h"

#include <iostream>
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

BitVector::BitVector(std::size_t n_bits) : bit_size_(n_bits) {
  data_vector_.resize(ABYN::Helpers::Convert::BitsToBytes(n_bits), std::byte(0));
}

BitVector::BitVector(const std::vector<std::byte>& data, std::size_t n_bits) : bit_size_(n_bits) {
  std::size_t byte_size = ABYN::Helpers::Convert::BitsToBytes(n_bits);
  if (byte_size > data.size()) {
    throw std::out_of_range(fmt::format("BitVector: accessing {} of {}", byte_size, data.size()));
  }
  data_vector_.insert(data_vector_.begin(), data.begin(), data.end());

  auto bit_offset = n_bits % 8;
  if (bit_offset > 0u) {
    data_vector_.at(byte_size) &= TRUNCATION_BIT_MASK[bit_offset];
  }
}

BitVector::BitVector(std::vector<std::byte>&& data, std::size_t n_bits) : bit_size_(n_bits) {
  std::size_t byte_size = ABYN::Helpers::Convert::BitsToBytes(n_bits);
  if (byte_size > data.size()) {
    throw std::out_of_range(fmt::format("BitVector: accessing {} of {}", byte_size, data.size()));
  }
  data_vector_ = std::move(data);
  data_vector_.resize(byte_size);

  auto bit_offset = n_bits % 8;
  if (bit_offset > 0u) {
    data_vector_.at(byte_size) &= TRUNCATION_BIT_MASK[bit_offset];
  }
}

BitVector::BitVector(const std::vector<bool>& data, std::size_t n_bits) : bit_size_(n_bits) {
  if (bit_size_ > data.size()) {
    throw std::out_of_range(fmt::format("BitVector: accessing {} of {}", n_bits, data.size()));
  }

  std::size_t byte_size = ABYN::Helpers::Convert::BitsToBytes(n_bits);
  data_vector_.resize(byte_size, std::byte(0));

  for (auto i = 0ull; i < data.size(); ++i) {
    Set(data.at(i), i);
  }
}

void BitVector::Set(bool value) {
  for (auto& byte : data_vector_) {
    if (value) {  // set
      byte |= std::byte(0xFFu);
    } else {  // unset
      byte &= std::byte(0u);
    }
  }

  std::size_t bit_offset = bit_size_ % 8;
  if (value && bit_offset != 0u) {
    std::size_t byte_offset = bit_size_ / 8;
    data_vector_.at(byte_offset) &= TRUNCATION_BIT_MASK[bit_offset];
  }
}

void BitVector::Set(bool value, std::size_t pos) {
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

bool BitVector::Get(std::size_t pos) {
  if (pos >= bit_size_) {
    throw std::out_of_range(fmt::format("BitVector: accessing {} of {}", pos, bit_size_));
  }

  std::size_t byte_offset = pos / 8;
  std::size_t bit_offset = pos % 8;

  auto result = data_vector_.at(byte_offset);
  result &= SET_BIT_MASK[bit_offset];

  return result == SET_BIT_MASK[bit_offset];
}

BitVector BitVector::operator&(const BitVector& other) {
  auto max_bit_size = std::max(bit_size_, other.bit_size_);
  auto min_byte_size = std::min(data_vector_.size(), other.data_vector_.size());

  BitVector result(max_bit_size);

  for (auto i = 0ull; i < min_byte_size; ++i) {
    result.data_vector_.at(i) = data_vector_.at(i) & other.data_vector_.at(i);
  }

  return result;
}

BitVector BitVector::operator^(const BitVector& other) {
  auto max_bit_size = std::max(bit_size_, other.bit_size_);
  auto min_byte_size = std::min(data_vector_.size(), other.data_vector_.size());
  auto max_byte_size = ABYN::Helpers::Convert::BitsToBytes(max_bit_size);

  BitVector result(max_bit_size);
  auto i = 0ull;
  for (; i < min_byte_size; ++i) {
    result.data_vector_.at(i) = data_vector_.at(i) ^ other.data_vector_.at(i);
  }

  if (min_byte_size == max_byte_size) {
    return result;
  }

  const auto& larger_vector =
      data_vector_.size() > other.data_vector_.size() ? data_vector_ : other.data_vector_;
  for (; i < min_byte_size; ++i) {
    result.data_vector_.at(i) ^= larger_vector.at(i);
  }

  return result;
}

BitVector BitVector::operator|(const BitVector& other) {
  auto max_bit_size = std::max(bit_size_, other.bit_size_);
  auto min_byte_size = std::min(data_vector_.size(), other.data_vector_.size());
  auto max_byte_size = ABYN::Helpers::Convert::BitsToBytes(max_bit_size);

  BitVector result(max_bit_size);
  auto i = 0ull;
  for (; i < min_byte_size; ++i) {
    result.data_vector_.at(i) = data_vector_.at(i) | other.data_vector_.at(i);
  }

  if (min_byte_size == max_byte_size) {
    return result;
  }

  const auto& larger_vector =
      data_vector_.size() > other.data_vector_.size() ? data_vector_ : other.data_vector_;
  for (; i < min_byte_size; ++i) {
    result.data_vector_.at(i) = larger_vector.at(i);
  }

  return result;
}

void BitVector::Resize(std::size_t n_bits) {
  bit_size_ = n_bits;
  auto byte_size = ABYN::Helpers::Convert::BitsToBytes(bit_size_);
  data_vector_.resize(byte_size, std::byte(0));

  auto bit_offset = n_bits % 8;
  if (bit_offset > 0u) {
    data_vector_.at(byte_size - 1) &= TRUNCATION_BIT_MASK[bit_offset];
  }
}

void BitVector::Append(bool bit) {
  auto bit_offset = bit_size_ % 8;
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

void BitVector::Append(BitVector&& other) {
  if (other.bit_size_ > 0u) {
    auto old_bit_offset = bit_size_ % 8;

    auto new_bit_size = bit_size_ + other.bit_size_;
    auto new_byte_size = ABYN::Helpers::Convert::BitsToBytes(new_bit_size);

    if (new_bit_size <= 8u) {
      if (bit_size_ == 0u) {
        data_vector_ = other.data_vector_;
      } else {
        data_vector_.at(0) |= (other.data_vector_.at(0) >> old_bit_offset);
      }
    } else if (old_bit_offset == 0u) {
      data_vector_.insert(data_vector_.end(), other.data_vector_.begin(), other.data_vector_.end());
    } else if (old_bit_offset + other.bit_size_ <= 8u) {
      data_vector_.at(data_vector_.size() - 1) |= other.data_vector_.at(0) >> old_bit_offset;
    } else if (other.bit_size_ <= 8u) {
      data_vector_.at(data_vector_.size() - 1) |= other.data_vector_.at(0) >> old_bit_offset;
      if (old_bit_offset + other.bit_size_ > 8u) {
        data_vector_.push_back(other.data_vector_.at(0) << (8 - old_bit_offset));
      }
    } else {
      auto old_byte_offset = data_vector_.size() - 1;
      data_vector_.resize(new_byte_size, std::byte(0));
      for (auto i = 0ull; i < other.data_vector_.size(); ++i) {
        data_vector_.at(old_byte_offset) |= (other.data_vector_.at(i) >> old_bit_offset);
        if (i + 1 < other.data_vector_.size() || old_bit_offset + (other.bit_size_ % 8) > 8u) {
          data_vector_.at(old_byte_offset + 1) |=
              other.data_vector_.at(i) << (8 - old_bit_offset);
        }
        ++old_byte_offset;
      }
    }
    bit_size_ = new_bit_size;
  }
}

void BitVector::Append(const BitVector& other) {
  if (other.bit_size_ > 0u) {
    BitVector bv(other);
    Append(std::move(bv));
  }
}

}