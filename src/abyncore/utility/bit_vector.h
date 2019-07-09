#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace ENCRYPTO {
class BitVector {
 public:
  BitVector() noexcept : bit_size_(0){};

  BitVector(std::size_t n_bits, bool value = false) noexcept;

  BitVector(BitVector&& bv) noexcept
      : data_vector_(std::move(bv.data_vector_)), bit_size_(bv.bit_size_) {}

  BitVector(const BitVector& bv) noexcept
      : data_vector_(bv.data_vector_.begin(), bv.data_vector_.end()), bit_size_(bv.bit_size_) {}

  BitVector(const std::vector<std::byte>& data, std::size_t n_bits);

  BitVector(std::vector<std::byte>&& data, std::size_t n_bits);

  BitVector(const std::vector<bool>& data, std::size_t n_bits);

  BitVector(const std::vector<bool>& data) : BitVector(data, data.size()) {}

  void operator=(const BitVector& other) noexcept;

  void operator=(BitVector&& other) noexcept;

  bool operator==(const BitVector& other) const noexcept;

  void Set(bool value) noexcept;

  void Set(bool value, std::size_t pos);

  bool Get(std::size_t pos) const;

  BitVector operator&(const BitVector& other) const noexcept;
  BitVector operator^(const BitVector& other) const noexcept;
  BitVector operator|(const BitVector& other) const noexcept;

  void operator&=(const BitVector& other) { *this = *this & other; }
  void operator^=(const BitVector& other) { *this = *this ^ other; }
  void operator|=(const BitVector& other) { *this = *this | other; }

  bool operator[](std::size_t pos) { return Get(pos); }

  void Resize(std::size_t n_bits) noexcept;

  const auto GetSize() const noexcept { return bit_size_; }

  const auto& GetData() const noexcept { return data_vector_; }

  auto& GetMutableData() noexcept { return data_vector_; }

  void Append(bool bit) noexcept;

  void Append(const BitVector& other) noexcept;

  void Append(BitVector&& other) noexcept;

  void Assign(const BitVector& other) noexcept { *this = other; }

  void Assign(BitVector&& other) noexcept { *this = std::move(other); }

  BitVector Subset(std::size_t from, std::size_t to) const;

  const std::string AsString() const noexcept;

  void Clear() noexcept;

  static BitVector Random(std::size_t size) noexcept;

 private:
  std::vector<std::byte> data_vector_;

  std::size_t bit_size_;

  void TruncateToFit() noexcept;
};
}