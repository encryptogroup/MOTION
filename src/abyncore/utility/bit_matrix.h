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

#include <cassert>
#include <emmintrin.h>
#include <memory>
#include <stdint.h>
#include <stdlib.h>

#include "boost/align/aligned_allocator.hpp"

namespace ENCRYPTO {

using AlignedBitVector = BitVector<boost::alignment::aligned_allocator<std::byte, 16>>;

class BitMatrix {
 public:
  BitMatrix() = default;

  BitMatrix(std::size_t rows, std::size_t columns, bool value = false) : num_columns_(columns) {
    for (auto i = 0ull; i < rows; ++i) {
      data_.emplace_back(columns, value);
    }
  }

  BitMatrix(std::vector<AlignedBitVector> vectors) : data_(vectors) {
    if (data_.size() > 0) {
      auto num_columns = data_.at(0).GetSize();
      for (auto i = 1ull; i < data_.size(); ++i) {
        assert(data_.at(i).GetSize() == num_columns);
      }
      num_columns_ = num_columns;
    }
  }

  BitMatrix(const BitMatrix& other) {
    data_.insert(data_.begin(), other.data_.begin(), other.data_.end());
    num_columns_ = other.num_columns_;
  }

  BitMatrix(BitMatrix&& other) {
    data_ = std::move(other.data_);
    num_columns_ = other.num_columns_;
  }

  void operator=(const BitMatrix& other) {
    data_.insert(data_.begin(), other.data_.begin(), other.data_.end());
    num_columns_ = other.num_columns_;
  }

  void operator=(BitMatrix&& other) {
    data_ = std::move(other.data_);
    num_columns_ = other.num_columns_;
  }

  const AlignedBitVector& GetRow(std::size_t i) const { return data_.at(i); }

  /// \brief Returns a mutable BitVector corresponding to row #i of the matrix.
  /// Changing the size of the underlying BitVector causes <b>Undefined Behaviour</b>.
  /// The underlying BitVector can be replaced completely by a BitVector of the same size.
  AlignedBitVector& GetMutableRow(std::size_t i) { return data_.at(i); }

  bool Get(std::size_t row_i, std::size_t column_i) const { return data_.at(row_i).Get(column_i); }

  void Set(std::size_t row_i, std::size_t column_i, bool value) {
    data_.at(row_i).Set(value, column_i);
  }

  void AppendRow(const AlignedBitVector& bv);

  void AppendRow(AlignedBitVector&& bv);

  void AppendColumn(const AlignedBitVector& bv);

  void AppendColumn(AlignedBitVector&& bv) { AppendColumn(bv); }

  std::string AsString() const;

  void ForceSetNumColumns(std::size_t n) { num_columns_ = n; }

  /// \brief Transposes the matrix inplace
  void Transpose();

  void Transpose128Rows();

  static void Transpose128RowsInplace(std::array<std::byte*, 128>& matrix, std::size_t num_columns);

  static void TransposeUsingBitSlicing(std::array<std::byte*, 128>& matrix, std::size_t num_columns);

  bool operator==(const BitMatrix& other);

  bool operator!=(const BitMatrix& other) { return !(*this == other); }

 private:
  std::vector<AlignedBitVector> data_;

  std::size_t num_columns_ = 0;

  // blockwise inplace
  void TransposeInternal();

  // blockwise inplace
  void Transpose128RowsInternal();

  static void Transpose128x128InPlace(std::array<std::uint64_t*, 128>& rows_64,
                                      std::array<std::uint32_t*, 128>& rows_32);
};
}