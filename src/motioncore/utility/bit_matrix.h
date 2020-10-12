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

#include "bit_vector.h"

#include <stdint.h>
#include <stdlib.h>
#include <cassert>
#include <memory>

namespace encrypto::motion::primitives {

class Prg;

}  // namespace encrypto::motion::primitives

namespace encrypto::motion {

class BitMatrix {
 public:
  BitMatrix() = default;

  BitMatrix(std::size_t rows, std::size_t columns, bool value = false)
      : number_of_columns_(columns) {
    for (auto i = 0ull; i < rows; ++i) {
      data_.emplace_back(columns, value);
    }
  }

  BitMatrix(std::vector<AlignedBitVector>&& vectors) : data_(std::move(vectors)) {
    if (data_.size() > 0) {
      auto number_of_columns = data_.at(0).GetSize();
      for (auto i = 1ull; i < data_.size(); ++i) {
        assert(data_.at(i).GetSize() == number_of_columns);
      }
      number_of_columns_ = number_of_columns;
    }
  }

  BitMatrix(const std::vector<AlignedBitVector>& vectors) : data_(vectors) {
    if (data_.size() > 0) {
      auto number_of_columns = data_.at(0).GetSize();
      for (auto i = 1ull; i < data_.size(); ++i) {
        assert(data_.at(i).GetSize() == number_of_columns);
      }
      number_of_columns_ = number_of_columns;
    }
  }

  BitMatrix(const BitMatrix& other) {
    data_.insert(data_.begin(), other.data_.begin(), other.data_.end());
    number_of_columns_ = other.number_of_columns_;
  }

  BitMatrix(BitMatrix&& other) {
    data_ = std::move(other.data_);
    number_of_columns_ = other.number_of_columns_;
  }

  void operator=(const BitMatrix& other) {
    data_.insert(data_.begin(), other.data_.begin(), other.data_.end());
    number_of_columns_ = other.number_of_columns_;
  }

  void operator=(BitMatrix&& other) {
    data_ = std::move(other.data_);
    number_of_columns_ = other.number_of_columns_;
  }

  const AlignedBitVector& GetRow(std::size_t i) const { return data_.at(i); }

  /// \brief Returns a mutable BitVector corresponding to row # i of the matrix.
  /// Changing the size of the underlying BitVector causes <b>Undefined Behaviour</b>.
  /// The underlying BitVector can be replaced completely by a BitVector of the same size.
  AlignedBitVector& GetMutableRow(std::size_t i) { return data_.at(i); }

  bool Get(std::size_t row_i, std::size_t column_i) const { return data_.at(row_i).Get(column_i); }

  void Set(std::size_t row_i, std::size_t column_i, bool value) {
    data_.at(row_i).Set(value, column_i);
  }

  void AppendRow(const AlignedBitVector& bit_vector);

  void AppendRow(AlignedBitVector&& bit_vector);

  void AppendColumn(const AlignedBitVector& bit_vector);

  void AppendColumn(AlignedBitVector&& bit_vector) { AppendColumn(bit_vector); }

  std::string AsString() const;

  void ForceSetNumColumns(std::size_t n) { number_of_columns_ = n; }

  /// \brief Transposes the matrix inplace
  void Transpose();

  void Transpose128Rows();

  static void Transpose128RowsInplace(std::array<std::byte*, 128>& matrix,
                                      std::size_t number_of_columns);

  static void TransposeUsingBitSlicing(std::array<std::byte*, 128>& matrix,
                                       std::size_t number_of_columns);

  static void SenderTransposeAndEncrypt(const std::array<const std::byte*, 128>& matrix,
                                        std::vector<BitVector<>>& y0, std::vector<BitVector<>>& y1,
                                        const BitVector<> choices, primitives::Prg& prg_fixed_key,
                                        const std::size_t number_of_columns,
                                        const std::vector<std::size_t>& bitlengths);

  static void ReceiverTransposeAndEncrypt(const std::array<const std::byte*, 128>& matrix,
                                          std::vector<BitVector<>>& output,
                                          primitives::Prg& prg_fixed_key,
                                          const std::size_t number_of_columns,
                                          const std::vector<std::size_t>& bitlengths);

  bool operator==(const BitMatrix& other);

  bool operator!=(const BitMatrix& other) { return !(*this == other); }

  auto GetNumRows() const noexcept { return data_.size(); }

  auto GetNumColumns() const noexcept { return number_of_columns_; }

 private:
  std::vector<AlignedBitVector> data_;

  std::size_t number_of_columns_ = 0;

  // blockwise inplace
  void TransposeInternal();

  // blockwise inplace
  void Transpose128RowsInternal();

  static void Transpose128x128InPlace(std::array<std::uint64_t*, 128>& rows_64_bit,
                                      std::array<std::uint32_t*, 128>& rows_32_bit);
};

}  // namespace encrypto::motion
