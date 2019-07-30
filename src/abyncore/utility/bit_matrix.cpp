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

#include "bit_matrix.h"

#include <cmath>
#include <iostream>

#include "omp.h"

#include "utility/helpers.h"

namespace ENCRYPTO {
void BitMatrix::Transpose() {
  std::size_t num_rows = data_.size();
  if (num_rows == 0 || num_columns_ == 0 || (num_rows == 1 && num_columns_ == 1)) {
    return;
  } else if (num_rows == 1) {
    for (auto i = 1ull; i < num_columns_; ++i) {
      data_.emplace_back(1, data_.at(0).Get(i));
    }
    data_.at(0).Resize(1);
    return;
  } else if (num_columns_ == 1) {
    for (auto i = 1ull; i < num_rows; ++i) {
      data_.at(0).Append(data_.at(i));
    }
    data_.resize(1);
    return;
  }

  const std::size_t block_size_unpadded = std::min(num_rows, num_columns_);
  const std::size_t block_size = static_cast<std::size_t>(pow(2, ceil(log2(block_size_unpadded))));
  const std::size_t initial_num_columns = num_columns_;
  const std::size_t initial_num_rows = data_.size();

  // pad to the block size
  if (num_columns_ % block_size > 0u) {
    for (auto& bv : data_) {
      bv.Resize(num_columns_ + block_size - (num_columns_ % block_size));
    }
  }

  if (data_.size() % block_size > 0u) {
    AlignedBitVector tmp(data_.at(0).GetSize());
    data_.resize(data_.size() + block_size - (data_.size() % block_size), tmp);
  }

  // move the first blocks manually to reduce the memory overhead - prevent padding to a square
  if (num_columns_ > num_rows) {
    for (auto i = block_size; i < num_columns_; i += block_size) {
#pragma omp for
      for (auto j = 0ull; j < block_size; ++j) {
        data_.emplace_back(data_.at(j).Subset(i, i + block_size));
      }
    }
#pragma omp for
    for (auto i = 0ull; i < block_size; ++i) {
      data_.at(i).Resize(block_size);
    }
  } else if (num_columns_ < num_rows) {
    for (auto i = block_size; i < data_.size(); i += block_size) {
#pragma omp for
      for (auto j = 0ull; j < block_size; ++j) {
        data_.at(j).Append(data_.at(i + j));
      }
    }
    data_.resize(block_size);
  }

  TransposeInplace();

  // remove padding
  data_.resize(initial_num_columns);

  for (auto& bv : data_) {
    bv.Resize(initial_num_rows);
  }

  num_columns_ = initial_num_rows;
}

void BitMatrix::TransposeInplace() {
  for (auto block_size = std::min(data_.size(), data_.at(0).GetSize()); block_size > 1u;
       block_size /= 2) {
    const auto subblock_size = block_size / 2;
    for (auto column_i = 0ull; column_i + subblock_size < data_.at(0).GetSize();
         column_i += block_size) {
      for (auto row_i = 0ull; row_i + subblock_size < data_.size(); row_i += block_size) {
        auto subblock_1_row_offset = row_i + subblock_size;
        auto subblock_1_column_offset = column_i;

        auto subblock_2_row_offset = row_i;
        auto subblock_2_column_offset = column_i + subblock_size;

        if (subblock_size > 1u) {
          for (auto i = 0ull; i < subblock_size; ++i) {
            BitVector block_1 =
                data_.at(subblock_1_row_offset + i)
                    .Subset(subblock_1_column_offset, subblock_1_column_offset + subblock_size);
            BitVector block_2 =
                data_.at(subblock_2_row_offset + i)
                    .Subset(subblock_2_column_offset, subblock_2_column_offset + subblock_size);

            data_.at(subblock_2_row_offset + i)
                .Copy(subblock_2_column_offset, subblock_2_column_offset + subblock_size, block_1);

            data_.at(subblock_1_row_offset + i)
                .Copy(subblock_1_column_offset, subblock_1_column_offset + subblock_size, block_2);
          }
        } else {
          bool bit_1 = Get(subblock_1_row_offset, subblock_1_column_offset);
          bool bit_2 = Get(subblock_2_row_offset, subblock_2_column_offset);
          Set(subblock_1_row_offset, subblock_1_column_offset, bit_2);
          Set(subblock_2_row_offset, subblock_2_column_offset, bit_1);
        }
      }
    }
  }
}

void BitMatrix::Transpose128Rows() {
  if constexpr (__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__) {
    throw std::runtime_error("Little endian encoding is required for BitMatrix::Transpose128");
  }

  std::size_t num_rows = data_.size();
  assert(num_rows == 128);
  assert(num_columns_ > 0);

  constexpr std::size_t block_size = 128;
  const std::size_t initial_num_columns = num_columns_;
  const std::size_t initial_num_rows = data_.size();

  // pad to the block size
  if (num_columns_ % block_size > 0u) {
    const auto padding_size = block_size - (num_columns_ % block_size);
    for (auto& bv : data_) {
      bv.Resize(num_columns_ + padding_size);
    }
  }

  // move the first blocks manually to reduce the memory overhead - prevent padding to a square
  if (num_columns_ > num_rows) {
    for (auto i = block_size; i < num_columns_; i += block_size) {
#pragma omp for
      for (auto j = 0ull; j < block_size; ++j) {
        data_.emplace_back(data_.at(j).Subset(i, i + block_size));
      }
    }
#pragma omp for
    for (auto i = 0ull; i < block_size; ++i) {
      data_.at(i).Resize(block_size);
    }
  } else if (num_columns_ < num_rows) {
    for (auto i = block_size; i < data_.size(); i += block_size) {
#pragma omp for
      for (auto j = 0ull; j < block_size; ++j) {
        data_.at(j).Append(data_.at(i + j));
      }
    }
    data_.resize(block_size);
  }

  Transpose128RowsInplace();

  // remove padding
  data_.resize(initial_num_columns);

  for (auto& bv : data_) {
    bv.Resize(initial_num_rows);
  }

  num_columns_ = initial_num_rows;
}

void BitMatrix::Transpose128RowsInplace() {
  for (auto block_offset = 0ull; block_offset < num_columns_; block_offset += 128) {
    std::array<std::uint64_t*, 128> rows_64;
    std::array<std::uint32_t*, 128> rows_32;
    std::array<std::uint64_t, 256> tmp_64_0, tmp_64_1;
    std::array<std::uint32_t, 128> tmp_32;
    for (auto i = 0; i < 128; ++i) {
      rows_64.at(i) =
          reinterpret_cast<std::uint64_t*>(data_.at(block_offset + i).GetMutableData().data());
      rows_32.at(i) =
          reinterpret_cast<std::uint32_t*>(data_.at(block_offset + i).GetMutableData().data());
    }

    {
      // block size = 128
      // swap the corresponding 64-bit blocks
      constexpr std::size_t block_size = 128;
      constexpr std::size_t subblock_size = block_size / 2;
      for (auto i = 0u; i < subblock_size; i += 16) {
        tmp_64_0.at(i + 0) = rows_64.at(0 + i + 0)[1];
        rows_64.at(0 + i + 0)[1] = rows_64.at(subblock_size + i + 0)[0];
        rows_64.at(subblock_size + i + 0)[0] = tmp_64_0.at(i + 0);
        tmp_64_0.at(i + 1) = rows_64.at(0 + i + 1)[1];
        rows_64.at(0 + i + 1)[1] = rows_64.at(subblock_size + i + 1)[0];
        rows_64.at(subblock_size + i + 1)[0] = tmp_64_0.at(i + 1);
        tmp_64_0.at(i + 2) = rows_64.at(0 + i + 2)[1];
        rows_64.at(0 + i + 2)[1] = rows_64.at(subblock_size + i + 2)[0];
        rows_64.at(subblock_size + i + 2)[0] = tmp_64_0.at(i + 2);
        tmp_64_0.at(i + 3) = rows_64.at(0 + i + 3)[1];
        rows_64.at(0 + i + 3)[1] = rows_64.at(subblock_size + i + 3)[0];
        rows_64.at(subblock_size + i + 3)[0] = tmp_64_0.at(i + 3);
        tmp_64_0.at(i + 4) = rows_64.at(0 + i + 4)[1];
        rows_64.at(0 + i + 4)[1] = rows_64.at(subblock_size + i + 4)[0];
        rows_64.at(subblock_size + i + 4)[0] = tmp_64_0.at(i + 4);
        tmp_64_0.at(i + 5) = rows_64.at(0 + i + 5)[1];
        rows_64.at(0 + i + 5)[1] = rows_64.at(subblock_size + i + 5)[0];
        rows_64.at(subblock_size + i + 5)[0] = tmp_64_0.at(i + 5);
        tmp_64_0.at(i + 6) = rows_64.at(0 + i + 6)[1];
        rows_64.at(0 + i + 6)[1] = rows_64.at(subblock_size + i + 6)[0];
        rows_64.at(subblock_size + i + 6)[0] = tmp_64_0.at(i + 6);
        tmp_64_0.at(i + 7) = rows_64.at(0 + i + 7)[1];
        rows_64.at(0 + i + 7)[1] = rows_64.at(subblock_size + i + 7)[0];
        rows_64.at(subblock_size + i + 7)[0] = tmp_64_0.at(i + 7);
        tmp_64_0.at(i + 8) = rows_64.at(0 + i + 8)[1];
        rows_64.at(0 + i + 8)[1] = rows_64.at(subblock_size + i + 8)[0];
        rows_64.at(subblock_size + i + 8)[0] = tmp_64_0.at(i + 8);
        tmp_64_0.at(i + 9) = rows_64.at(0 + i + 9)[1];
        rows_64.at(0 + i + 9)[1] = rows_64.at(subblock_size + i + 9)[0];
        rows_64.at(subblock_size + i + 9)[0] = tmp_64_0.at(i + 9);
        tmp_64_0.at(i + 10) = rows_64.at(0 + i + 10)[1];
        rows_64.at(0 + i + 10)[1] = rows_64.at(subblock_size + i + 10)[0];
        rows_64.at(subblock_size + i + 10)[0] = tmp_64_0.at(i + 10);
        tmp_64_0.at(i + 11) = rows_64.at(0 + i + 11)[1];
        rows_64.at(0 + i + 11)[1] = rows_64.at(subblock_size + i + 11)[0];
        rows_64.at(subblock_size + i + 11)[0] = tmp_64_0.at(i + 11);
        tmp_64_0.at(i + 12) = rows_64.at(0 + i + 12)[1];
        rows_64.at(0 + i + 12)[1] = rows_64.at(subblock_size + i + 12)[0];
        rows_64.at(subblock_size + i + 12)[0] = tmp_64_0.at(i + 12);
        tmp_64_0.at(i + 13) = rows_64.at(0 + i + 13)[1];
        rows_64.at(0 + i + 13)[1] = rows_64.at(subblock_size + i + 13)[0];
        rows_64.at(subblock_size + i + 13)[0] = tmp_64_0.at(i + 13);
        tmp_64_0.at(i + 14) = rows_64.at(0 + i + 14)[1];
        rows_64.at(0 + i + 14)[1] = rows_64.at(subblock_size + i + 14)[0];
        rows_64.at(subblock_size + i + 14)[0] = tmp_64_0.at(i + 14);
        tmp_64_0.at(i + 15) = rows_64.at(0 + i + 15)[1];
        rows_64.at(0 + i + 15)[1] = rows_64.at(subblock_size + i + 15)[0];
        rows_64.at(subblock_size + i + 15)[0] = tmp_64_0.at(i + 15);
      }
    }

    {
      constexpr std::size_t block_size = 64;
      constexpr std::size_t subblock_size = block_size / 2;
      // swap the corresponding 32-bit blocks
      for (auto i = 0; i < 128; i += block_size) {
        for (auto j = 0u; j < subblock_size; j += 8) {
          tmp_32.at(j + 0) = rows_32.at(0 + i + j + 0)[1];
          rows_32.at(0 + i + j + 0)[1] = rows_32.at(subblock_size + i + j + 0)[0];
          rows_32.at(subblock_size + i + j + 0)[0] = tmp_32.at(j + 0);
          tmp_32.at(2 * j + 0) = rows_32.at(0 + i + j + 0)[3];
          rows_32.at(0 + i + j + 0)[3] = rows_32.at(subblock_size + i + j + 0)[2];
          rows_32.at(subblock_size + i + j + 0)[2] = tmp_32.at(2 * j + 0);

          tmp_32.at(j + 1) = rows_32.at(0 + i + j + 1)[1];
          rows_32.at(0 + i + j + 1)[1] = rows_32.at(subblock_size + i + j + 1)[0];
          rows_32.at(subblock_size + i + j + 1)[0] = tmp_32.at(j + 1);
          tmp_32.at(2 * j + 1) = rows_32.at(0 + i + j + 1)[3];
          rows_32.at(0 + i + j + 1)[3] = rows_32.at(subblock_size + i + j + 1)[2];
          rows_32.at(subblock_size + i + j + 1)[2] = tmp_32.at(2 * j + 1);

          tmp_32.at(j + 2) = rows_32.at(0 + i + j + 2)[1];
          rows_32.at(0 + i + j + 2)[1] = rows_32.at(subblock_size + i + j + 2)[0];
          rows_32.at(subblock_size + i + j + 2)[0] = tmp_32.at(j + 2);
          tmp_32.at(2 * j + 2) = rows_32.at(0 + i + j + 2)[3];
          rows_32.at(0 + i + j + 2)[3] = rows_32.at(subblock_size + i + j + 2)[2];
          rows_32.at(subblock_size + i + j + 2)[2] = tmp_32.at(2 * j + 2);

          tmp_32.at(j + 3) = rows_32.at(0 + i + j + 3)[1];
          rows_32.at(0 + i + j + 3)[1] = rows_32.at(subblock_size + i + j + 3)[0];
          rows_32.at(subblock_size + i + j + 3)[0] = tmp_32.at(j + 3);
          tmp_32.at(2 * j + 3) = rows_32.at(0 + i + j + 3)[3];
          rows_32.at(0 + i + j + 3)[3] = rows_32.at(subblock_size + i + j + 3)[2];
          rows_32.at(subblock_size + i + j + 3)[2] = tmp_32.at(2 * j + 3);

          tmp_32.at(j + 4) = rows_32.at(0 + i + j + 4)[1];
          rows_32.at(0 + i + j + 4)[1] = rows_32.at(subblock_size + i + j + 4)[0];
          rows_32.at(subblock_size + i + j + 4)[0] = tmp_32.at(j + 4);
          tmp_32.at(2 * j + 4) = rows_32.at(0 + i + j + 4)[3];
          rows_32.at(0 + i + j + 4)[3] = rows_32.at(subblock_size + i + j + 4)[2];
          rows_32.at(subblock_size + i + j + 4)[2] = tmp_32.at(2 * j + 4);

          tmp_32.at(j + 5) = rows_32.at(0 + i + j + 5)[1];
          rows_32.at(0 + i + j + 5)[1] = rows_32.at(subblock_size + i + j + 5)[0];
          rows_32.at(subblock_size + i + j + 5)[0] = tmp_32.at(j + 5);
          tmp_32.at(2 * j + 5) = rows_32.at(0 + i + j + 5)[3];
          rows_32.at(0 + i + j + 5)[3] = rows_32.at(subblock_size + i + j + 5)[2];
          rows_32.at(subblock_size + i + j + 5)[2] = tmp_32.at(2 * j + 5);

          tmp_32.at(j + 6) = rows_32.at(0 + i + j + 6)[1];
          rows_32.at(0 + i + j + 6)[1] = rows_32.at(subblock_size + i + j + 6)[0];
          rows_32.at(subblock_size + i + j + 6)[0] = tmp_32.at(j + 6);
          tmp_32.at(2 * j + 6) = rows_32.at(0 + i + j + 6)[3];
          rows_32.at(0 + i + j + 6)[3] = rows_32.at(subblock_size + i + j + 6)[2];
          rows_32.at(subblock_size + i + j + 6)[2] = tmp_32.at(2 * j + 6);

          tmp_32.at(j + 7) = rows_32.at(0 + i + j + 7)[1];
          rows_32.at(0 + i + j + 7)[1] = rows_32.at(subblock_size + i + j + 7)[0];
          rows_32.at(subblock_size + i + j + 7)[0] = tmp_32.at(j + 7);
          tmp_32.at(2 * j + 7) = rows_32.at(0 + i + j + 7)[3];
          rows_32.at(0 + i + j + 7)[3] = rows_32.at(subblock_size + i + j + 7)[2];
          rows_32.at(subblock_size + i + j + 7)[2] = tmp_32.at(2 * j + 7);
        }
      }
    }

    {
      // block size = {32, 16}
      constexpr std::array<std::uint64_t, 2> mask0{0xFFFF0000FFFF0000ull, 0xFF00FF00FF00FF00ull};
      constexpr std::array<std::uint64_t, 2> mask1{~mask0.at(0), ~mask0.at(1)};
      for (auto block_size = 32, block_id = 0; block_size > 8; block_size >>= 1, ++block_id) {
        const std::size_t subblock_size = block_size >> 1;
        for (auto i = 0; i < 128; i += block_size) {
          for (auto j = 0u; j < subblock_size; j += 8) {
            tmp_64_0.at(2 * i + 0) =
                (rows_64.at(0 + i + j + 0)[0] & mask0.at(block_id)) >> subblock_size;
            tmp_64_0.at(2 * i + 1) =
                (rows_64.at(0 + i + j + 0)[1] & mask0.at(block_id)) >> subblock_size;
            tmp_64_0.at(2 * i + 2) =
                (rows_64.at(0 + i + j + 1)[0] & mask0.at(block_id)) >> subblock_size;
            tmp_64_0.at(2 * i + 3) =
                (rows_64.at(0 + i + j + 1)[1] & mask0.at(block_id)) >> subblock_size;
            tmp_64_0.at(2 * i + 4) =
                (rows_64.at(0 + i + j + 2)[0] & mask0.at(block_id)) >> subblock_size;
            tmp_64_0.at(2 * i + 5) =
                (rows_64.at(0 + i + j + 2)[1] & mask0.at(block_id)) >> subblock_size;
            tmp_64_0.at(2 * i + 6) =
                (rows_64.at(0 + i + j + 3)[0] & mask0.at(block_id)) >> subblock_size;
            tmp_64_0.at(2 * i + 7) =
                (rows_64.at(0 + i + j + 3)[1] & mask0.at(block_id)) >> subblock_size;
            tmp_64_0.at(2 * i + 8) =
                (rows_64.at(0 + i + j + 4)[0] & mask0.at(block_id)) >> subblock_size;
            tmp_64_0.at(2 * i + 9) =
                (rows_64.at(0 + i + j + 4)[1] & mask0.at(block_id)) >> subblock_size;
            tmp_64_0.at(2 * i + 10) =
                (rows_64.at(0 + i + j + 5)[0] & mask0.at(block_id)) >> subblock_size;
            tmp_64_0.at(2 * i + 11) =
                (rows_64.at(0 + i + j + 5)[1] & mask0.at(block_id)) >> subblock_size;
            tmp_64_0.at(2 * i + 12) =
                (rows_64.at(0 + i + j + 6)[0] & mask0.at(block_id)) >> subblock_size;
            tmp_64_0.at(2 * i + 13) =
                (rows_64.at(0 + i + j + 6)[1] & mask0.at(block_id)) >> subblock_size;
            tmp_64_0.at(2 * i + 14) =
                (rows_64.at(0 + i + j + 7)[0] & mask0.at(block_id)) >> subblock_size;
            tmp_64_0.at(2 * i + 15) =
                (rows_64.at(0 + i + j + 7)[1] & mask0.at(block_id)) >> subblock_size;

            tmp_64_1.at(2 * i + 0) = (rows_64.at(subblock_size + i + j + 0)[0] & mask1.at(block_id))
                                     << subblock_size;
            tmp_64_1.at(2 * i + 1) = (rows_64.at(subblock_size + i + j + 0)[1] & mask1.at(block_id))
                                     << subblock_size;
            tmp_64_1.at(2 * i + 2) = (rows_64.at(subblock_size + i + j + 1)[0] & mask1.at(block_id))
                                     << subblock_size;
            tmp_64_1.at(2 * i + 3) = (rows_64.at(subblock_size + i + j + 1)[1] & mask1.at(block_id))
                                     << subblock_size;
            tmp_64_1.at(2 * i + 4) = (rows_64.at(subblock_size + i + j + 2)[0] & mask1.at(block_id))
                                     << subblock_size;
            tmp_64_1.at(2 * i + 5) = (rows_64.at(subblock_size + i + j + 2)[1] & mask1.at(block_id))
                                     << subblock_size;
            tmp_64_1.at(2 * i + 6) = (rows_64.at(subblock_size + i + j + 3)[0] & mask1.at(block_id))
                                     << subblock_size;
            tmp_64_1.at(2 * i + 7) = (rows_64.at(subblock_size + i + j + 3)[1] & mask1.at(block_id))
                                     << subblock_size;
            tmp_64_1.at(2 * i + 8) = (rows_64.at(subblock_size + i + j + 4)[0] & mask1.at(block_id))
                                     << subblock_size;
            tmp_64_1.at(2 * i + 9) = (rows_64.at(subblock_size + i + j + 4)[1] & mask1.at(block_id))
                                     << subblock_size;
            tmp_64_1.at(2 * i + 10) =
                (rows_64.at(subblock_size + i + j + 5)[0] & mask1.at(block_id)) << subblock_size;
            tmp_64_1.at(2 * i + 11) =
                (rows_64.at(subblock_size + i + j + 5)[1] & mask1.at(block_id)) << subblock_size;
            tmp_64_1.at(2 * i + 12) =
                (rows_64.at(subblock_size + i + j + 6)[0] & mask1.at(block_id)) << subblock_size;
            tmp_64_1.at(2 * i + 13) =
                (rows_64.at(subblock_size + i + j + 6)[1] & mask1.at(block_id)) << subblock_size;
            tmp_64_1.at(2 * i + 14) =
                (rows_64.at(subblock_size + i + j + 7)[0] & mask1.at(block_id)) << subblock_size;
            tmp_64_1.at(2 * i + 15) =
                (rows_64.at(subblock_size + i + j + 7)[1] & mask1.at(block_id)) << subblock_size;

            rows_64.at(0 + i + j + 0)[0] =
                (rows_64.at(0 + i + j + 0)[0] & mask1.at(block_id)) | tmp_64_1.at(2 * i + 0);
            rows_64.at(0 + i + j + 0)[1] =
                (rows_64.at(0 + i + j + 0)[1] & mask1.at(block_id)) | tmp_64_1.at(2 * i + 1);
            rows_64.at(0 + i + j + 1)[0] =
                (rows_64.at(0 + i + j + 1)[0] & mask1.at(block_id)) | tmp_64_1.at(2 * i + 2);
            rows_64.at(0 + i + j + 1)[1] =
                (rows_64.at(0 + i + j + 1)[1] & mask1.at(block_id)) | tmp_64_1.at(2 * i + 3);
            rows_64.at(0 + i + j + 2)[0] =
                (rows_64.at(0 + i + j + 2)[0] & mask1.at(block_id)) | tmp_64_1.at(2 * i + 4);
            rows_64.at(0 + i + j + 2)[1] =
                (rows_64.at(0 + i + j + 2)[1] & mask1.at(block_id)) | tmp_64_1.at(2 * i + 5);
            rows_64.at(0 + i + j + 3)[0] =
                (rows_64.at(0 + i + j + 3)[0] & mask1.at(block_id)) | tmp_64_1.at(2 * i + 6);
            rows_64.at(0 + i + j + 3)[1] =
                (rows_64.at(0 + i + j + 3)[1] & mask1.at(block_id)) | tmp_64_1.at(2 * i + 7);
            rows_64.at(0 + i + j + 4)[0] =
                (rows_64.at(0 + i + j + 4)[0] & mask1.at(block_id)) | tmp_64_1.at(2 * i + 8);
            rows_64.at(0 + i + j + 4)[1] =
                (rows_64.at(0 + i + j + 4)[1] & mask1.at(block_id)) | tmp_64_1.at(2 * i + 9);
            rows_64.at(0 + i + j + 5)[0] =
                (rows_64.at(0 + i + j + 5)[0] & mask1.at(block_id)) | tmp_64_1.at(2 * i + 10);
            rows_64.at(0 + i + j + 5)[1] =
                (rows_64.at(0 + i + j + 5)[1] & mask1.at(block_id)) | tmp_64_1.at(2 * i + 11);
            rows_64.at(0 + i + j + 6)[0] =
                (rows_64.at(0 + i + j + 6)[0] & mask1.at(block_id)) | tmp_64_1.at(2 * i + 12);
            rows_64.at(0 + i + j + 6)[1] =
                (rows_64.at(0 + i + j + 6)[1] & mask1.at(block_id)) | tmp_64_1.at(2 * i + 13);
            rows_64.at(0 + i + j + 7)[0] =
                (rows_64.at(0 + i + j + 7)[0] & mask1.at(block_id)) | tmp_64_1.at(2 * i + 14);
            rows_64.at(0 + i + j + 7)[1] =
                (rows_64.at(0 + i + j + 7)[1] & mask1.at(block_id)) | tmp_64_1.at(2 * i + 15);

            rows_64.at(subblock_size + i + j + 0)[0] =
                (rows_64.at(subblock_size + i + j + 0)[0] & mask0.at(block_id)) |
                tmp_64_0.at(2 * i + 0);
            rows_64.at(subblock_size + i + j + 0)[1] =
                (rows_64.at(subblock_size + i + j + 0)[1] & mask0.at(block_id)) |
                tmp_64_0.at(2 * i + 1);
            rows_64.at(subblock_size + i + j + 1)[0] =
                (rows_64.at(subblock_size + i + j + 1)[0] & mask0.at(block_id)) |
                tmp_64_0.at(2 * i + 2);
            rows_64.at(subblock_size + i + j + 1)[1] =
                (rows_64.at(subblock_size + i + j + 1)[1] & mask0.at(block_id)) |
                tmp_64_0.at(2 * i + 3);
            rows_64.at(subblock_size + i + j + 2)[0] =
                (rows_64.at(subblock_size + i + j + 2)[0] & mask0.at(block_id)) |
                tmp_64_0.at(2 * i + 4);
            rows_64.at(subblock_size + i + j + 2)[1] =
                (rows_64.at(subblock_size + i + j + 2)[1] & mask0.at(block_id)) |
                tmp_64_0.at(2 * i + 5);
            rows_64.at(subblock_size + i + j + 3)[0] =
                (rows_64.at(subblock_size + i + j + 3)[0] & mask0.at(block_id)) |
                tmp_64_0.at(2 * i + 6);
            rows_64.at(subblock_size + i + j + 3)[1] =
                (rows_64.at(subblock_size + i + j + 3)[1] & mask0.at(block_id)) |
                tmp_64_0.at(2 * i + 7);
            rows_64.at(subblock_size + i + j + 4)[0] =
                (rows_64.at(subblock_size + i + j + 4)[0] & mask0.at(block_id)) |
                tmp_64_0.at(2 * i + 8);
            rows_64.at(subblock_size + i + j + 4)[1] =
                (rows_64.at(subblock_size + i + j + 4)[1] & mask0.at(block_id)) |
                tmp_64_0.at(2 * i + 9);
            rows_64.at(subblock_size + i + j + 5)[0] =
                (rows_64.at(subblock_size + i + j + 5)[0] & mask0.at(block_id)) |
                tmp_64_0.at(2 * i + 10);
            rows_64.at(subblock_size + i + j + 5)[1] =
                (rows_64.at(subblock_size + i + j + 5)[1] & mask0.at(block_id)) |
                tmp_64_0.at(2 * i + 11);
            rows_64.at(subblock_size + i + j + 6)[0] =
                (rows_64.at(subblock_size + i + j + 6)[0] & mask0.at(block_id)) |
                tmp_64_0.at(2 * i + 12);
            rows_64.at(subblock_size + i + j + 6)[1] =
                (rows_64.at(subblock_size + i + j + 6)[1] & mask0.at(block_id)) |
                tmp_64_0.at(2 * i + 13);
            rows_64.at(subblock_size + i + j + 7)[0] =
                (rows_64.at(subblock_size + i + j + 7)[0] & mask0.at(block_id)) |
                tmp_64_0.at(2 * i + 14);
            rows_64.at(subblock_size + i + j + 7)[1] =
                (rows_64.at(subblock_size + i + j + 7)[1] & mask0.at(block_id)) |
                tmp_64_0.at(2 * i + 15);
          }
        }
      }
    }

    // block size = 8
    // endianness madness
    // although we have little endianness here, integers are interpreted in a reversed order, i.e.,
    // std::byte[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07} is interpreted as
    // uint64_t 0x07060504030201
    // if we want to swap last 4 bits from 0x0F and the first 4 bits from 0xAC, we need to
    // perform left shift for the first and right shift to the latter, not as for the 16 and 32
    // block size, and the mask should be in the correct order from here on
    {
      constexpr std::size_t block_size = 8;
      constexpr std::uint64_t mask0{0x0F0F0F0F0F0F0F0Full};
      constexpr std::uint64_t mask1 = ~mask0;
      constexpr std::size_t subblock_size = block_size / 2;
      for (auto i = 0; i < 128; i += 2 * block_size) {
        tmp_64_0.at(2 * i + 0) = (rows_64.at(0 + i + 0)[0] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 1) = (rows_64.at(0 + i + 0)[1] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 2) = (rows_64.at(0 + i + 1)[0] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 3) = (rows_64.at(0 + i + 1)[1] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 4) = (rows_64.at(0 + i + 2)[0] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 5) = (rows_64.at(0 + i + 2)[1] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 6) = (rows_64.at(0 + i + 3)[0] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 7) = (rows_64.at(0 + i + 3)[1] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 8) = (rows_64.at(block_size + i + 0)[0] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 9) = (rows_64.at(block_size + i + 0)[1] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 10) = (rows_64.at(block_size + i + 1)[0] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 11) = (rows_64.at(block_size + i + 1)[1] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 12) = (rows_64.at(block_size + i + 2)[0] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 13) = (rows_64.at(block_size + i + 2)[1] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 14) = (rows_64.at(block_size + i + 3)[0] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 15) = (rows_64.at(block_size + i + 3)[1] & mask0) << subblock_size;

        tmp_64_1.at(2 * i + 0) = (rows_64.at(subblock_size + i + 0)[0] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 1) = (rows_64.at(subblock_size + i + 0)[1] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 2) = (rows_64.at(subblock_size + i + 1)[0] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 3) = (rows_64.at(subblock_size + i + 1)[1] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 4) = (rows_64.at(subblock_size + i + 2)[0] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 5) = (rows_64.at(subblock_size + i + 2)[1] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 6) = (rows_64.at(subblock_size + i + 3)[0] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 7) = (rows_64.at(subblock_size + i + 3)[1] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 8) =
            (rows_64.at(block_size + subblock_size + i + 0)[0] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 9) =
            (rows_64.at(block_size + subblock_size + i + 0)[1] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 10) =
            (rows_64.at(block_size + subblock_size + i + 1)[0] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 11) =
            (rows_64.at(block_size + subblock_size + i + 1)[1] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 12) =
            (rows_64.at(block_size + subblock_size + i + 2)[0] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 13) =
            (rows_64.at(block_size + subblock_size + i + 2)[1] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 14) =
            (rows_64.at(block_size + subblock_size + i + 3)[0] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 15) =
            (rows_64.at(block_size + subblock_size + i + 3)[1] & mask1) >> subblock_size;

        rows_64.at(0 + i + 0)[0] = (rows_64.at(0 + i + 0)[0] & mask1) | tmp_64_1.at(2 * i + 0);
        rows_64.at(0 + i + 0)[1] = (rows_64.at(0 + i + 0)[1] & mask1) | tmp_64_1.at(2 * i + 1);
        rows_64.at(0 + i + 1)[0] = (rows_64.at(0 + i + 1)[0] & mask1) | tmp_64_1.at(2 * i + 2);
        rows_64.at(0 + i + 1)[1] = (rows_64.at(0 + i + 1)[1] & mask1) | tmp_64_1.at(2 * i + 3);
        rows_64.at(0 + i + 2)[0] = (rows_64.at(0 + i + 2)[0] & mask1) | tmp_64_1.at(2 * i + 4);
        rows_64.at(0 + i + 2)[1] = (rows_64.at(0 + i + 2)[1] & mask1) | tmp_64_1.at(2 * i + 5);
        rows_64.at(0 + i + 3)[0] = (rows_64.at(0 + i + 3)[0] & mask1) | tmp_64_1.at(2 * i + 6);
        rows_64.at(0 + i + 3)[1] = (rows_64.at(0 + i + 3)[1] & mask1) | tmp_64_1.at(2 * i + 7);
        rows_64.at(block_size + i + 0)[0] =
            (rows_64.at(block_size + i + 0)[0] & mask1) | tmp_64_1.at(2 * i + 8);
        rows_64.at(block_size + i + 0)[1] =
            (rows_64.at(block_size + i + 0)[1] & mask1) | tmp_64_1.at(2 * i + 9);
        rows_64.at(block_size + i + 1)[0] =
            (rows_64.at(block_size + i + 1)[0] & mask1) | tmp_64_1.at(2 * i + 10);
        rows_64.at(block_size + i + 1)[1] =
            (rows_64.at(block_size + i + 1)[1] & mask1) | tmp_64_1.at(2 * i + 11);
        rows_64.at(block_size + i + 2)[0] =
            (rows_64.at(block_size + i + 2)[0] & mask1) | tmp_64_1.at(2 * i + 12);
        rows_64.at(block_size + i + 2)[1] =
            (rows_64.at(block_size + i + 2)[1] & mask1) | tmp_64_1.at(2 * i + 13);
        rows_64.at(block_size + i + 3)[0] =
            (rows_64.at(block_size + i + 3)[0] & mask1) | tmp_64_1.at(2 * i + 14);
        rows_64.at(block_size + i + 3)[1] =
            (rows_64.at(block_size + i + 3)[1] & mask1) | tmp_64_1.at(2 * i + 15);

        rows_64.at(subblock_size + i + 0)[0] =
            (rows_64.at(subblock_size + i + 0)[0] & mask0) | tmp_64_0.at(2 * i + 0);
        rows_64.at(subblock_size + i + 0)[1] =
            (rows_64.at(subblock_size + i + 0)[1] & mask0) | tmp_64_0.at(2 * i + 1);
        rows_64.at(subblock_size + i + 1)[0] =
            (rows_64.at(subblock_size + i + 1)[0] & mask0) | tmp_64_0.at(2 * i + 2);
        rows_64.at(subblock_size + i + 1)[1] =
            (rows_64.at(subblock_size + i + 1)[1] & mask0) | tmp_64_0.at(2 * i + 3);
        rows_64.at(subblock_size + i + 2)[0] =
            (rows_64.at(subblock_size + i + 2)[0] & mask0) | tmp_64_0.at(2 * i + 4);
        rows_64.at(subblock_size + i + 2)[1] =
            (rows_64.at(subblock_size + i + 2)[1] & mask0) | tmp_64_0.at(2 * i + 5);
        rows_64.at(subblock_size + i + 3)[0] =
            (rows_64.at(subblock_size + i + 3)[0] & mask0) | tmp_64_0.at(2 * i + 6);
        rows_64.at(subblock_size + i + 3)[1] =
            (rows_64.at(subblock_size + i + 3)[1] & mask0) | tmp_64_0.at(2 * i + 7);
        rows_64.at(block_size + subblock_size + i + 0)[0] =
            (rows_64.at(block_size + subblock_size + i + 0)[0] & mask0) | tmp_64_0.at(2 * i + 8);
        rows_64.at(block_size + subblock_size + i + 0)[1] =
            (rows_64.at(block_size + subblock_size + i + 0)[1] & mask0) | tmp_64_0.at(2 * i + 9);
        rows_64.at(block_size + subblock_size + i + 1)[0] =
            (rows_64.at(block_size + subblock_size + i + 1)[0] & mask0) | tmp_64_0.at(2 * i + 10);
        rows_64.at(block_size + subblock_size + i + 1)[1] =
            (rows_64.at(block_size + subblock_size + i + 1)[1] & mask0) | tmp_64_0.at(2 * i + 11);
        rows_64.at(block_size + subblock_size + i + 2)[0] =
            (rows_64.at(block_size + subblock_size + i + 2)[0] & mask0) | tmp_64_0.at(2 * i + 12);
        rows_64.at(block_size + subblock_size + i + 2)[1] =
            (rows_64.at(block_size + subblock_size + i + 2)[1] & mask0) | tmp_64_0.at(2 * i + 13);
        rows_64.at(block_size + subblock_size + i + 3)[0] =
            (rows_64.at(block_size + subblock_size + i + 3)[0] & mask0) | tmp_64_0.at(2 * i + 14);
        rows_64.at(block_size + subblock_size + i + 3)[1] =
            (rows_64.at(block_size + subblock_size + i + 3)[1] & mask0) | tmp_64_0.at(2 * i + 15);
      }
    }

    // block size = 4
    {
      constexpr std::size_t block_size = 4;
      constexpr std::uint64_t mask0{0x3333333333333333ull};
      constexpr std::uint64_t mask1 = ~mask0;
      constexpr std::size_t subblock_size = block_size / 2;
      for (auto i = 0; i < 128; i += 4 * block_size) {
        tmp_64_0.at(2 * i + 0) = (rows_64.at(0 + i + 0)[0] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 1) = (rows_64.at(0 + i + 0)[1] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 2) = (rows_64.at(0 + i + 1)[0] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 3) = (rows_64.at(0 + i + 1)[1] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 4) = (rows_64.at(block_size + 0 + i + 0)[0] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 5) = (rows_64.at(block_size + 0 + i + 0)[1] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 6) = (rows_64.at(block_size + 0 + i + 1)[0] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 7) = (rows_64.at(block_size + 0 + i + 1)[1] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 8) = (rows_64.at(2 * block_size + i + 0)[0] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 9) = (rows_64.at(2 * block_size + i + 0)[1] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 10) = (rows_64.at(2 * block_size + i + 1)[0] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 11) = (rows_64.at(2 * block_size + i + 1)[1] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 12) = (rows_64.at(3 * block_size + i + 0)[0] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 13) = (rows_64.at(3 * block_size + i + 0)[1] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 14) = (rows_64.at(3 * block_size + i + 1)[0] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 15) = (rows_64.at(3 * block_size + i + 1)[1] & mask0) << subblock_size;

        tmp_64_1.at(2 * i + 0) = (rows_64.at(subblock_size + i + 0)[0] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 1) = (rows_64.at(subblock_size + i + 0)[1] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 2) = (rows_64.at(subblock_size + i + 1)[0] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 3) = (rows_64.at(subblock_size + i + 1)[1] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 4) =
            (rows_64.at(block_size + subblock_size + i + 0)[0] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 5) =
            (rows_64.at(block_size + subblock_size + i + 0)[1] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 6) =
            (rows_64.at(block_size + subblock_size + i + 1)[0] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 7) =
            (rows_64.at(block_size + subblock_size + i + 1)[1] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 8) =
            (rows_64.at(2 * block_size + subblock_size + i + 0)[0] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 9) =
            (rows_64.at(2 * block_size + subblock_size + i + 0)[1] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 10) =
            (rows_64.at(2 * block_size + subblock_size + i + 1)[0] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 11) =
            (rows_64.at(2 * block_size + subblock_size + i + 1)[1] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 12) =
            (rows_64.at(3 * block_size + subblock_size + i + 0)[0] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 13) =
            (rows_64.at(3 * block_size + subblock_size + i + 0)[1] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 14) =
            (rows_64.at(3 * block_size + subblock_size + i + 1)[0] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 15) =
            (rows_64.at(3 * block_size + subblock_size + i + 1)[1] & mask1) >> subblock_size;

        rows_64.at(0 + i + 0)[0] = (rows_64.at(0 + i + 0)[0] & mask1) | tmp_64_1.at(2 * i + 0);
        rows_64.at(0 + i + 0)[1] = (rows_64.at(0 + i + 0)[1] & mask1) | tmp_64_1.at(2 * i + 1);
        rows_64.at(0 + i + 1)[0] = (rows_64.at(0 + i + 1)[0] & mask1) | tmp_64_1.at(2 * i + 2);
        rows_64.at(0 + i + 1)[1] = (rows_64.at(0 + i + 1)[1] & mask1) | tmp_64_1.at(2 * i + 3);
        rows_64.at(block_size + i + 0)[0] =
            (rows_64.at(block_size + i + 0)[0] & mask1) | tmp_64_1.at(2 * i + 4);
        rows_64.at(block_size + i + 0)[1] =
            (rows_64.at(block_size + i + 0)[1] & mask1) | tmp_64_1.at(2 * i + 5);
        rows_64.at(block_size + i + 1)[0] =
            (rows_64.at(block_size + i + 1)[0] & mask1) | tmp_64_1.at(2 * i + 6);
        rows_64.at(block_size + i + 1)[1] =
            (rows_64.at(block_size + i + 1)[1] & mask1) | tmp_64_1.at(2 * i + 7);
        rows_64.at(2 * block_size + i + 0)[0] =
            (rows_64.at(2 * block_size + i + 0)[0] & mask1) | tmp_64_1.at(2 * i + 8);
        rows_64.at(2 * block_size + i + 0)[1] =
            (rows_64.at(2 * block_size + i + 0)[1] & mask1) | tmp_64_1.at(2 * i + 9);
        rows_64.at(2 * block_size + i + 1)[0] =
            (rows_64.at(2 * block_size + i + 1)[0] & mask1) | tmp_64_1.at(2 * i + 10);
        rows_64.at(2 * block_size + i + 1)[1] =
            (rows_64.at(2 * block_size + i + 1)[1] & mask1) | tmp_64_1.at(2 * i + 11);
        rows_64.at(3 * block_size + i + 0)[0] =
            (rows_64.at(3 * block_size + i + 0)[0] & mask1) | tmp_64_1.at(2 * i + 12);
        rows_64.at(3 * block_size + i + 0)[1] =
            (rows_64.at(3 * block_size + i + 0)[1] & mask1) | tmp_64_1.at(2 * i + 13);
        rows_64.at(3 * block_size + i + 1)[0] =
            (rows_64.at(3 * block_size + i + 1)[0] & mask1) | tmp_64_1.at(2 * i + 14);
        rows_64.at(3 * block_size + i + 1)[1] =
            (rows_64.at(3 * block_size + i + 1)[1] & mask1) | tmp_64_1.at(2 * i + 15);

        rows_64.at(subblock_size + i + 0)[0] =
            (rows_64.at(subblock_size + i + 0)[0] & mask0) | tmp_64_0.at(2 * i + 0);
        rows_64.at(subblock_size + i + 0)[1] =
            (rows_64.at(subblock_size + i + 0)[1] & mask0) | tmp_64_0.at(2 * i + 1);
        rows_64.at(subblock_size + i + 1)[0] =
            (rows_64.at(subblock_size + i + 1)[0] & mask0) | tmp_64_0.at(2 * i + 2);
        rows_64.at(subblock_size + i + 1)[1] =
            (rows_64.at(subblock_size + i + 1)[1] & mask0) | tmp_64_0.at(2 * i + 3);
        rows_64.at(block_size + subblock_size + i + 0)[0] =
            (rows_64.at(block_size + subblock_size + i + 0)[0] & mask0) | tmp_64_0.at(2 * i + 4);
        rows_64.at(block_size + subblock_size + i + 0)[1] =
            (rows_64.at(block_size + subblock_size + i + 0)[1] & mask0) | tmp_64_0.at(2 * i + 5);
        rows_64.at(block_size + subblock_size + i + 1)[0] =
            (rows_64.at(block_size + subblock_size + i + 1)[0] & mask0) | tmp_64_0.at(2 * i + 6);
        rows_64.at(block_size + subblock_size + i + 1)[1] =
            (rows_64.at(block_size + subblock_size + i + 1)[1] & mask0) | tmp_64_0.at(2 * i + 7);
        rows_64.at(2 * block_size + subblock_size + i + 0)[0] =
            (rows_64.at(2 * block_size + subblock_size + i + 0)[0] & mask0) |
            tmp_64_0.at(2 * i + 8);
        rows_64.at(2 * block_size + subblock_size + i + 0)[1] =
            (rows_64.at(2 * block_size + subblock_size + i + 0)[1] & mask0) |
            tmp_64_0.at(2 * i + 9);
        rows_64.at(2 * block_size + subblock_size + i + 1)[0] =
            (rows_64.at(2 * block_size + subblock_size + i + 1)[0] & mask0) |
            tmp_64_0.at(2 * i + 10);
        rows_64.at(2 * block_size + subblock_size + i + 1)[1] =
            (rows_64.at(2 * block_size + subblock_size + i + 1)[1] & mask0) |
            tmp_64_0.at(2 * i + 11);
        rows_64.at(3 * block_size + subblock_size + i + 0)[0] =
            (rows_64.at(3 * block_size + subblock_size + i + 0)[0] & mask0) |
            tmp_64_0.at(2 * i + 12);
        rows_64.at(3 * block_size + subblock_size + i + 0)[1] =
            (rows_64.at(3 * block_size + subblock_size + i + 0)[1] & mask0) |
            tmp_64_0.at(2 * i + 13);
        rows_64.at(3 * block_size + subblock_size + i + 1)[0] =
            (rows_64.at(3 * block_size + subblock_size + i + 1)[0] & mask0) |
            tmp_64_0.at(2 * i + 14);
        rows_64.at(3 * block_size + subblock_size + i + 1)[1] =
            (rows_64.at(3 * block_size + subblock_size + i + 1)[1] & mask0) |
            tmp_64_0.at(2 * i + 15);
      }
    }

    // block size = 2
    {
      constexpr std::size_t block_size = 2;
      constexpr std::uint64_t mask0{0x5555555555555555ull};
      constexpr std::uint64_t mask1 = ~mask0;
      const std::size_t subblock_size = block_size >> 1;
      for (auto i = 0; i < 128; i += block_size * 8) {
        tmp_64_0.at(2 * i + 0) = (rows_64.at(i)[0] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 1) = (rows_64.at(i)[1] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 2) = (rows_64.at(block_size + i)[0] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 3) = (rows_64.at(block_size + i)[1] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 4) = (rows_64.at(2 * block_size + i)[0] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 5) = (rows_64.at(2 * block_size + i)[1] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 6) = (rows_64.at(3 * block_size + i)[0] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 7) = (rows_64.at(3 * block_size + i)[1] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 8) = (rows_64.at(4 * block_size + i)[0] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 9) = (rows_64.at(4 * block_size + i)[1] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 10) = (rows_64.at(5 * block_size + i)[0] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 11) = (rows_64.at(5 * block_size + i)[1] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 12) = (rows_64.at(6 * block_size + i)[0] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 13) = (rows_64.at(6 * block_size + i)[1] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 14) = (rows_64.at(7 * block_size + i)[0] & mask0) << subblock_size;
        tmp_64_0.at(2 * i + 15) = (rows_64.at(7 * block_size + i)[1] & mask0) << subblock_size;

        tmp_64_1.at(2 * i + 0) = (rows_64.at(i + 1)[0] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 1) = (rows_64.at(i + 1)[1] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 2) = (rows_64.at(block_size + i + 1)[0] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 3) = (rows_64.at(block_size + i + 1)[1] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 4) = (rows_64.at(2 * block_size + i + 1)[0] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 5) = (rows_64.at(2 * block_size + i + 1)[1] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 6) = (rows_64.at(3 * block_size + i + 1)[0] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 7) = (rows_64.at(3 * block_size + i + 1)[1] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 8) = (rows_64.at(4 * block_size + i + 1)[0] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 9) = (rows_64.at(4 * block_size + i + 1)[1] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 10) = (rows_64.at(5 * block_size + i + 1)[0] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 11) = (rows_64.at(5 * block_size + i + 1)[1] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 12) = (rows_64.at(6 * block_size + i + 1)[0] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 13) = (rows_64.at(6 * block_size + i + 1)[1] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 14) = (rows_64.at(7 * block_size + i + 1)[0] & mask1) >> subblock_size;
        tmp_64_1.at(2 * i + 15) = (rows_64.at(7 * block_size + i + 1)[1] & mask1) >> subblock_size;

        rows_64.at(0 + i + 0)[0] = (rows_64.at(i)[0] & mask1) | tmp_64_1.at(2 * i + 0);
        rows_64.at(0 + i + 0)[1] = (rows_64.at(i)[1] & mask1) | tmp_64_1.at(2 * i + 1);
        rows_64.at(block_size + i)[0] =
            (rows_64.at(block_size + i)[0] & mask1) | tmp_64_1.at(2 * i + 2);
        rows_64.at(block_size + i)[1] =
            (rows_64.at(block_size + i)[1] & mask1) | tmp_64_1.at(2 * i + 3);
        rows_64.at(2 * block_size + i)[0] =
            (rows_64.at(2 * block_size + i)[0] & mask1) | tmp_64_1.at(2 * i + 4);
        rows_64.at(2 * block_size + i)[1] =
            (rows_64.at(2 * block_size + i)[1] & mask1) | tmp_64_1.at(2 * i + 5);
        rows_64.at(3 * block_size + i)[0] =
            (rows_64.at(3 * block_size + i)[0] & mask1) | tmp_64_1.at(2 * i + 6);
        rows_64.at(3 * block_size + i)[1] =
            (rows_64.at(3 * block_size + i)[1] & mask1) | tmp_64_1.at(2 * i + 7);
        rows_64.at(4 * block_size + i)[0] =
            (rows_64.at(4 * block_size + i)[0] & mask1) | tmp_64_1.at(2 * i + 8);
        rows_64.at(4 * block_size + i)[1] =
            (rows_64.at(4 * block_size + i)[1] & mask1) | tmp_64_1.at(2 * i + 9);
        rows_64.at(5 * block_size + i)[0] =
            (rows_64.at(5 * block_size + i)[0] & mask1) | tmp_64_1.at(2 * i + 10);
        rows_64.at(5 * block_size + i)[1] =
            (rows_64.at(5 * block_size + i)[1] & mask1) | tmp_64_1.at(2 * i + 11);
        rows_64.at(6 * block_size + i)[0] =
            (rows_64.at(6 * block_size + i)[0] & mask1) | tmp_64_1.at(2 * i + 12);
        rows_64.at(6 * block_size + i)[1] =
            (rows_64.at(6 * block_size + i)[1] & mask1) | tmp_64_1.at(2 * i + 13);
        rows_64.at(7 * block_size + i)[0] =
            (rows_64.at(7 * block_size + i)[0] & mask1) | tmp_64_1.at(2 * i + 14);
        rows_64.at(7 * block_size + i)[1] =
            (rows_64.at(7 * block_size + i)[1] & mask1) | tmp_64_1.at(2 * i + 15);

        rows_64.at(i + 1)[0] = (rows_64.at(i + 1)[0] & mask0) | tmp_64_0.at(2 * i + 0);
        rows_64.at(i + 1)[1] = (rows_64.at(i + 1)[1] & mask0) | tmp_64_0.at(2 * i + 1);
        rows_64.at(block_size + i + 1)[0] =
            (rows_64.at(block_size + i + 1)[0] & mask0) | tmp_64_0.at(2 * i + 2);
        rows_64.at(block_size + i + 1)[1] =
            (rows_64.at(block_size + i + 1)[1] & mask0) | tmp_64_0.at(2 * i + 3);
        rows_64.at(2 * block_size + i + 1)[0] =
            (rows_64.at(2 * block_size + i + 1)[0] & mask0) | tmp_64_0.at(2 * i + 4);
        rows_64.at(2 * block_size + i + 1)[1] =
            (rows_64.at(2 * block_size + i + 1)[1] & mask0) | tmp_64_0.at(2 * i + 5);
        rows_64.at(3 * block_size + i + 1)[0] =
            (rows_64.at(3 * block_size + i + 1)[0] & mask0) | tmp_64_0.at(2 * i + 6);
        rows_64.at(3 * block_size + i + 1)[1] =
            (rows_64.at(3 * block_size + i + 1)[1] & mask0) | tmp_64_0.at(2 * i + 7);
        rows_64.at(4 * block_size + i + 1)[0] =
            (rows_64.at(4 * block_size + i + 1)[0] & mask0) | tmp_64_0.at(2 * i + 8);
        rows_64.at(4 * block_size + i + 1)[1] =
            (rows_64.at(4 * block_size + i + 1)[1] & mask0) | tmp_64_0.at(2 * i + 9);
        rows_64.at(5 * block_size + i + 1)[0] =
            (rows_64.at(5 * block_size + i + 1)[0] & mask0) | tmp_64_0.at(2 * i + 10);
        rows_64.at(5 * block_size + i + 1)[1] =
            (rows_64.at(5 * block_size + i + 1)[1] & mask0) | tmp_64_0.at(2 * i + 11);
        rows_64.at(6 * block_size + i + 1)[0] =
            (rows_64.at(6 * block_size + i + 1)[0] & mask0) | tmp_64_0.at(2 * i + 12);
        rows_64.at(6 * block_size + i + 1)[1] =
            (rows_64.at(6 * block_size + i + 1)[1] & mask0) | tmp_64_0.at(2 * i + 13);
        rows_64.at(7 * block_size + i + 1)[0] =
            (rows_64.at(7 * block_size + i + 1)[0] & mask0) | tmp_64_0.at(2 * i + 14);
        rows_64.at(7 * block_size + i + 1)[1] =
            (rows_64.at(7 * block_size + i + 1)[1] & mask0) | tmp_64_0.at(2 * i + 15);
      }
    }
  }
}

void BitMatrix::AppendRow(const AlignedBitVector& bv) {
  if (bv.GetSize() != num_columns_) {
    throw std::runtime_error("BitMatrix::AppendRow : bv.GetSize() != num_columns");
  }
  data_.push_back(bv);
}

void BitMatrix::AppendRow(AlignedBitVector&& bv) {
  if (bv.GetSize() != num_columns_) {
    throw std::runtime_error("BitMatrix::AppendRow : bv.GetSize() != num_columns");
  }
  data_.emplace_back(std::move(bv));
}

void BitMatrix::AppendColumn(const AlignedBitVector& bv) {
  if (bv.GetSize() != data_.size()) {
    throw std::runtime_error("BitMatrix::AppendColumn : bv.GetSize() != num_rows");
  }
  for (auto i = 0ull; i < data_.size(); ++i) {
    data_.at(i).Append(bv.Get(i));
  }
  ++num_columns_;
}

std::string BitMatrix::AsString() const {
  std::string s;
  for (auto i = 0ull; i < data_.size(); ++i) {
    s.append(data_.at(i).AsString() + "\n");
  }
  return s;
}

}  // namespace ENCRYPTO
