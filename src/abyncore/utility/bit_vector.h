#pragma once

#include <vector>

namespace ENCRYPTO {

class BitVector {
 public:
  BitVector() : bit_size_(0){};

  BitVector(std::size_t n_bits);

  BitVector(BitVector&& bv) : data_vector_(std::move(bv.data_vector_)), bit_size_(bv.bit_size_) {}

  BitVector(const BitVector& bv)
      : data_vector_(bv.data_vector_.begin(), bv.data_vector_.end()), bit_size_(bv.bit_size_) {}

  BitVector(const std::vector<std::byte>& data, std::size_t n_bits);

  BitVector(std::vector<std::byte>&& data, std::size_t n_bits);

  BitVector(const std::vector<bool>& data, std::size_t n_bits);

  BitVector(const std::vector<bool>& data) : BitVector(data, data.size()) {}

  void Set(bool value);

  void Set(bool value, std::size_t pos);

  bool Get(std::size_t pos);

  BitVector operator&(const BitVector& other);

  BitVector operator^(const BitVector& other);

  BitVector operator|(const BitVector& other);

  bool operator[](std::size_t pos) { return Get(pos); }

  void Resize(std::size_t n_bits);

  const auto GetSize() const { return bit_size_; }

  const auto& GetData() const { return data_vector_; }

  auto& GetMutableData() { return data_vector_; }

  void Append(bool bit);

  void Append(const BitVector& other);

  void Append(BitVector&& other);

 private:
  std::vector<std::byte> data_vector_;

  std::size_t bit_size_;
};
}