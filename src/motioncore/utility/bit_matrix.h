// MIT License
//
// Copyright (c) 2019-2022 Oleksandr Tkachenko, Arianne Roselina Prananto
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

  /// \brief Construct a \p rows x \p columns BitMatrix with all bits set to \p value.
  /// \param rows
  /// \param columns
  /// \param value
  BitMatrix(std::size_t rows, std::size_t columns, bool value = false)
      : number_of_columns_(columns) {
    for (auto i = 0ull; i < rows; ++i) {
      data_.emplace_back(columns, value);
    }
  }

  /// \brief Construct a BitMatrix by moving a vector of AlignedBitVectors.
  /// \param vectors Each AlignedBitVector represents a row of the BitMatrix.
  /// \pre All AlignedBitVectors have the same size.
  BitMatrix(std::vector<AlignedBitVector>&& vectors) : data_(std::move(vectors)) {
    if (data_.size() > 0) {
      auto number_of_columns = data_.at(0).GetSize();
      for (auto i = 1ull; i < data_.size(); ++i) {
        assert(data_.at(i).GetSize() == number_of_columns);
      }
      number_of_columns_ = number_of_columns;
    }
  }

  /// \brief Construct a BitMatrix by copying a vector of AlignedBitVectors.
  /// \param vectors Each AlignedBitVector represents a row of the BitMatrix.
  /// \pre All AlignedBitVectors have the same size.
  BitMatrix(const std::vector<AlignedBitVector>& vectors) : data_(vectors) {
    if (data_.size() > 0) {
      auto number_of_columns = data_.at(0).GetSize();
      for (auto i = 1ull; i < data_.size(); ++i) {
        assert(data_.at(i).GetSize() == number_of_columns);
      }
      number_of_columns_ = number_of_columns;
    }
  }

  // XXX The copy and move constructors/assignments can set to default.
  // XXX Assignments do not return BitMatrix& and do not check for self-assignment.
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

  /// \brief Returns a const AlignedBitVector reference to row \p i of the matrix.
  /// \param i
  const AlignedBitVector& GetRow(std::size_t i) const { return data_.at(i); }

  /// \brief Returns a mutable AlignedBitVector reference to row \p i of the matrix.
  /// \note
  /// Changing the size of the underlying BitVector causes <b>Undefined Behaviour</b>.
  /// The underlying BitVector can be replaced completely by a BitVector of the same size.
  /// \param i
  AlignedBitVector& GetMutableRow(std::size_t i) { return data_.at(i); }

  /// \brief Get Bit at input position.
  /// \param row_i
  /// \param column_i
  bool Get(std::size_t row_i, std::size_t column_i) const { return data_.at(row_i).Get(column_i); }

  /// \brief Set or unset bit at input position.
  /// \param row_i
  /// \param column_i
  /// \param value
  void Set(std::size_t row_i, std::size_t column_i, bool value) {
    data_.at(row_i).Set(value, column_i);
  }

  /// \brief Appends a new row by copying the input bit_vector to the matrix.
  /// \param bit_vector The new row.
  /// \pre Size of \p bit_vector must be equal to the number of columns in the matrix.
  void AppendRow(const AlignedBitVector& bit_vector);

  /// \brief Appends a new row by moving the input bit_vector to the matrix.
  /// \param bit_vector The new row.
  /// \pre Size of \p bit_vector must be equal to the number of columns in the matrix.
  void AppendRow(AlignedBitVector&& bit_vector);

  /// \brief Appends a new column by copying the input bit_vector to the matrix.
  /// \param bit_vector The new column.
  /// \pre Size of \p bit_vector must be equal to the number of rows in the matrix.
  void AppendColumn(const AlignedBitVector& bit_vector);

  /// \brief Appends a new column by moving the input bit_vector to the matrix.
  /// \param bit_vector The new column.
  /// \pre Size of \p bit_vector must be equal to the number of rows in the matrix.
  void AppendColumn(AlignedBitVector&& bit_vector) { AppendColumn(bit_vector); }

  /// \brief Return a string representation of the BitMatrix.
  std::string AsString() const;

  /// \brief Force the number of columns to be equal to \p n.
  /// \param n
  void ForceSetNumColumns(std::size_t n) { number_of_columns_ = n; }

  /// \brief Transposes the matrix inplace.
  void Transpose();

  /// \brief Transposes a matrix with exactly 128 rows (faster).
  /// \pre The matrix has exactly 128 rows and at least 1 column.
  void Transpose128Rows();

  /// \brief Transposes a matrix with exactly 256 columns (faster).
  /// \pre The matrix has exactly 256 columns and at least 1 row.
  void Transpose256Columns();

  /// \brief Transposes a matrix of 128 rows and arbitrary column size inplace.
  /// \param matrix
  /// \param number_of_columns
  /// \pre All rows must be of equal size.
  static void Transpose128RowsInplace(std::array<std::byte*, 128>& matrix,
                                      std::size_t number_of_columns);

  /// \brief Transposes a matrix of 128 rows and arbitrary column size inplace using BitSlicing.
  /// \param matrix
  /// \param number_of_columns
  /// \pre All rows must be of size equal to number_of_colums.
  static void TransposeUsingBitSlicing(std::array<std::byte*, 128>& matrix,
                                       std::size_t number_of_columns);

  /// \brief Transposes a matrix of 128 rows and arbitrary column size and encrypts it for the
  /// sender role.
  /// \param matrix
  /// \param y0 The first correction.
  /// \param y1 The second correction.
  /// \param choices
  /// \param prg_fixed_key
  /// \param number_of_columns
  /// \param bitlengths
  /// \pre - All rows must be of size equal to number_of_columns
  ///      - const std::byte* in matrix is (number_of_columns)-bit aligned
  ///      - y0 and y1 must be of equal size
  static void SenderTranspose128AndEncrypt(const std::array<const std::byte*, 128>& matrix,
                                           std::vector<BitVector<>>& y0,
                                           std::vector<BitVector<>>& y1, const BitVector<> choices,
                                           primitives::Prg& prg_fixed_key,
                                           const std::size_t number_of_columns,
                                           const std::vector<std::size_t>& bitlengths);

  /// \brief Transposes a matrix of 128 rows and arbitrary column size and encrypts it for the
  /// recipient role.
  /// \param matrix
  /// \param[out] output Output from sender.
  /// \param choices
  /// \param prg_fixed_key
  /// \param number_of_columns
  /// \param bitlengths
  /// \pre - All rows must be of size equal to number_of_columns
  ///      - const std::byte* in matrix is (number_of_columns)-bit aligned
  static void ReceiverTranspose128AndEncrypt(const std::array<const std::byte*, 128>& matrix,
                                             std::vector<BitVector<>>& output,
                                             primitives::Prg& prg_fixed_key,
                                             const std::size_t number_of_columns,
                                             const std::vector<std::size_t>& bitlengths);

  /// \brief Transposes a matrix of 256 rows and arbitrary column size and encrypts it for the
  /// sender role.
  /// \param matrix
  /// \param y The corrections.
  /// \param choices
  /// \param x_a
  /// \param number_of_columns
  /// \param bitlengths
  /// \pre - All rows must be of size equal to number_of_columns
  ///      - const std::byte* in matrix is (number_of_columns)-bit aligned
  ///      - all vectors in y must be of equal size
  static void SenderTranspose256AndEncrypt(const std::array<const std::byte*, 256>& matrix,
                                           std::vector<std::vector<BitVector<>>>& y,
                                           const BitVector<> choices,
                                           std::vector<AlignedBitVector> x_a, primitives::Prg&,
                                           const std::size_t number_of_colums,
                                           const std::vector<std::size_t>& bitlengths);

  /// \brief Transposes a matrix of 256 rows and arbitrary column size and encrypts it for the
  /// recipient role.
  /// \param matrix
  /// \param[out] output Output from sender.
  /// \param number_of_columns
  /// \param bitlengths
  /// \pre - All rows must be of size equal to number_of_columns
  ///      - const std::byte* in matrix is (number_of_columns)-bit aligned
  static void ReceiverTranspose256AndEncrypt(const std::array<const std::byte*, 256>& matrix,
                                             std::vector<BitVector<>>& output,
                                             primitives::Prg& prg_fixed_key,
                                             const std::size_t number_of_columns,
                                             const std::vector<std::size_t>& bitlengths);

  /// \brief Compare with another BitMatrix for equality
  /// \param other
  bool operator==(const BitMatrix& other) const;

  /// \brief Compare with another BitMatrix for inequality
  /// \param other
  bool operator!=(const BitMatrix& other) const { return !(*this == other); }

  /// \brief Get number of rows in the BitMatrix
  auto GetNumRows() const noexcept { return data_.size(); }

  /// \brief Get number of columns in the BitMatrix
  auto GetNumColumns() const noexcept { return number_of_columns_; }

 private:
  std::vector<AlignedBitVector> data_;

  std::size_t number_of_columns_ = 0;

  // blockwise inplace
  void TransposeInternal();

  // blockwise inplace
  void Transpose128RowsInternal();

  void Transpose256ColumnsInternal();

  static void Transpose128x128InPlace(std::array<std::uint64_t*, 128>& rows_64_bit,
                                      std::array<std::uint32_t*, 128>& rows_32_bit);
};

}  // namespace encrypto::motion
