// MIT License
//
// Copyright (c) 2019-2021 Oleksandr Tkachenko, Arianne Roselina Prananto
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

#include <immintrin.h>
#include <omp.h>
#include <cmath>
#include <iostream>

#include "helpers.h"
#include "primitives/pseudo_random_generator.h"

namespace encrypto::motion {

void BitMatrix::Transpose() {
  std::size_t number_of_rows = data_.size();
  if (number_of_rows == 0 || number_of_columns_ == 0 ||
      (number_of_rows == 1 && number_of_columns_ == 1)) {
    return;
  } else if (number_of_rows == 1) {
    for (auto i = 1ull; i < number_of_columns_; ++i) {
      data_.emplace_back(1, data_.at(0).Get(i));
    }
    data_.at(0).Resize(1, true);
    return;
  } else if (number_of_columns_ == 1) {
    for (auto i = 1ull; i < number_of_rows; ++i) {
      data_.at(0).Append(data_.at(i));
    }
    data_.resize(1);
    return;
  }

  const std::size_t block_size_unpadded = std::min(number_of_rows, number_of_columns_);
  const std::size_t block_size = static_cast<std::size_t>(pow(2, ceil(log2(block_size_unpadded))));
  const std::size_t initial_number_of_columns = number_of_columns_;
  const std::size_t initial_number_of_rows = data_.size();

  // pad to the block size
  if (number_of_columns_ % block_size > 0u) {
    for (auto& block_vector : data_) {
      block_vector.Resize(number_of_columns_ + block_size - (number_of_columns_ % block_size),
                          true);
    }
  }

  if (data_.size() % block_size > 0u) {
    AlignedBitVector tmp(data_.at(0).GetSize());
    data_.resize(data_.size() + block_size - (data_.size() % block_size), tmp);
  }

  // move the first blocks manually to reduce the memory overhead - prevent padding to a square
  if (number_of_columns_ > number_of_rows) {
    for (auto i = block_size; i < number_of_columns_; i += block_size) {
#pragma omp for
      for (auto j = 0ull; j < block_size; ++j) {
        data_.emplace_back(data_.at(j).Subset(i, i + block_size));
      }
    }
#pragma omp for
    for (auto i = 0ull; i < block_size; ++i) {
      data_.at(i).Resize(block_size, true);
    }
  } else if (number_of_columns_ < number_of_rows) {
    for (auto i = block_size; i < data_.size(); i += block_size) {
#pragma omp for
      for (auto j = 0ull; j < block_size; ++j) {
        data_.at(j).Append(data_.at(i + j));
      }
    }
    data_.resize(block_size);
  }

  TransposeInternal();

  // remove padding
  data_.resize(initial_number_of_columns);

  for (auto& block_vector : data_) {
    block_vector.Resize(initial_number_of_rows, true);
  }

  number_of_columns_ = initial_number_of_rows;
}

void BitMatrix::TransposeInternal() {
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

  std::size_t number_of_rows = data_.size();
  assert(number_of_rows == 128);
  assert(number_of_columns_ > 0);

  constexpr std::size_t block_size = 128;
  const std::size_t initial_number_of_columns = number_of_columns_;
  const std::size_t initial_number_of_rows = data_.size();

  // pad to the block size
  if (number_of_columns_ % block_size > 0u) {
    const auto padding_size = block_size - (number_of_columns_ % block_size);
    for (auto& block_vector : data_) {
      block_vector.Resize(number_of_columns_ + padding_size);
    }
  }

  // move the first blocks manually to reduce the memory overhead - prevent padding to a square
  if (number_of_columns_ > number_of_rows) {
    for (auto i = block_size; i < number_of_columns_; i += block_size) {
#pragma omp for
      for (auto j = 0ull; j < block_size; ++j) {
        data_.emplace_back(data_.at(j).Subset(i, i + block_size));
      }
    }
#pragma omp for
    for (auto i = 0ull; i < block_size; ++i) {
      data_.at(i).Resize(block_size);
    }
  } else if (number_of_columns_ < number_of_rows) {
    for (auto i = block_size; i < data_.size(); i += block_size) {
#pragma omp for
      for (auto j = 0ull; j < block_size; ++j) {
        data_.at(j).Append(data_.at(i + j));
      }
    }
    data_.resize(block_size);
  }

  Transpose128RowsInternal();

  // remove padding
  data_.resize(initial_number_of_columns);

  for (auto& block_vector : data_) {
    block_vector.Resize(initial_number_of_rows);
  }

  number_of_columns_ = initial_number_of_rows;
}

void BitMatrix::Transpose256Columns() {
  std::size_t number_of_rows = data_.size();
  if (number_of_rows == 0 || number_of_columns_ != 256) {
    return;
  } else if (number_of_rows == 1) {
    for (std::size_t i = 1; i < number_of_columns_; i++) {
      data_.emplace_back(1, data_.at(0).Get(i));
    }
    data_.at(0).Resize(1, true);
    return;
  }

  constexpr std::size_t block_size = 256;
  const std::size_t initial_number_of_columns = number_of_columns_;
  const std::size_t initial_number_of_rows = data_.size();

  if (data_.size() % block_size > 0u) {
    AlignedBitVector tmp(block_size);
    data_.resize(data_.size() + block_size - (data_.size() % block_size), tmp);
  }

  std::size_t i, j;

  // move the first blocks manually to reduce the memory overhead - prevent padding to a square
  if (number_of_columns_ > number_of_rows) {
    for (i = block_size; i < number_of_columns_; i += block_size) {
#pragma omp for
      for (j = 0; j < block_size; ++j) {
        data_.emplace_back(data_.at(j).Subset(i, i + block_size));
      }
    }
#pragma omp for
    for (i = 0; i < block_size; ++i) {
      data_.at(i).Resize(block_size, true);
    }
  } else if (number_of_columns_ < number_of_rows) {
    for (i = block_size; i < data_.size(); i += block_size) {
#pragma omp for
      for (j = 0; j < block_size; ++j) {
        data_.at(j).Append(data_.at(i + j));
      }
    }
    data_.resize(block_size);
  }

  TransposeInternal();

  // remove padding
  data_.resize(initial_number_of_columns);

  for (auto& block_vector : data_) {
    block_vector.Resize(initial_number_of_rows, true);
  }

  number_of_columns_ = initial_number_of_rows;
}

void BitMatrix::Transpose128RowsInternal() {
  constexpr std::size_t kNumberOfColumns = 128;
  for (auto block_offset = 0u; block_offset < number_of_columns_;
       block_offset += kNumberOfColumns) {
    std::array<std::uint64_t*, kNumberOfColumns> rows_64_bit;
    std::array<std::uint32_t*, kNumberOfColumns> rows_32_bit;

    for (auto i = 0u; i < kNumberOfColumns; ++i) {
      rows_64_bit.at(i) =
          reinterpret_cast<std::uint64_t*>(data_.at(block_offset + i).GetMutableData().data());
      rows_32_bit.at(i) =
          reinterpret_cast<std::uint32_t*>(data_.at(block_offset + i).GetMutableData().data());
    }

    Transpose128x128InPlace(rows_64_bit, rows_32_bit);
  }
}

void BitMatrix::AppendRow(const AlignedBitVector& block_vector) {
  if (block_vector.GetSize() != number_of_columns_) {
    throw std::runtime_error("BitMatrix::AppendRow : block_vector.GetSize() != number_of_columns");
  }
  data_.push_back(block_vector);
}

void BitMatrix::AppendRow(AlignedBitVector&& block_vector) {
  if (block_vector.GetSize() != number_of_columns_) {
    throw std::runtime_error("BitMatrix::AppendRow : block_vector.GetSize() != number_of_columns");
  }
  data_.emplace_back(std::move(block_vector));
}

void BitMatrix::AppendColumn(const AlignedBitVector& block_vector) {
  if (block_vector.GetSize() != data_.size()) {
    throw std::runtime_error("BitMatrix::AppendColumn : block_vector.GetSize() != number_of_rows");
  }
  for (auto i = 0ull; i < data_.size(); ++i) {
    data_.at(i).Append(block_vector.Get(i));
  }
  ++number_of_columns_;
}

std::string BitMatrix::AsString() const {
  std::string s;
  for (auto i = 0ull; i < data_.size(); ++i) {
    s.append(data_.at(i).AsString() + "\n");
  }
  return s;
}

// XXX: adjust to little endian encoding in BitVector or remove, since we can use other methods via
// simde
void BitMatrix::Transpose128RowsInplace(std::array<std::byte*, 128>& matrix,
                                        std::size_t number_of_columns) {
  throw std::logic_error("Currently unusable; do not use");

  constexpr std::size_t kBlkSize = 128;
  constexpr std::size_t kBitsInByte = 8;

  for (auto block_offset = 0u; block_offset < number_of_columns; block_offset += kBlkSize) {
    std::array<std::uint64_t*, kBlkSize> rows_64_bit;
    std::array<std::uint32_t*, kBlkSize> rows_32_bit;

    for (auto i = 0u; i < kBlkSize; ++i) {
      rows_64_bit.at(i) =
          reinterpret_cast<std::uint64_t*>(matrix.at(i) + (block_offset / kBitsInByte));
      rows_32_bit.at(i) =
          reinterpret_cast<std::uint32_t*>(matrix.at(i) + (block_offset / kBitsInByte));
    }

    Transpose128x128InPlace(rows_64_bit, rows_32_bit);
  }
}

void BitMatrix::Transpose128x128InPlace(std::array<std::uint64_t*, 128>& rows_64_bit,
                                        std::array<std::uint32_t*, 128>& rows_32_bit) {
  constexpr std::size_t kBlkSize = 128;

  std::array<std::uint64_t, kBlkSize> tmp_64_0, tmp_64_1;

  {
    constexpr std::size_t kThisBlkSize = 128;
    constexpr std::size_t kThisNumberOfSubBlocks = kThisBlkSize / 64;
    constexpr std::size_t kThisSubBlockSize = kThisBlkSize / kThisNumberOfSubBlocks;
    // swap the corresponding 64-bit blocks
    for (auto i = 0u; i < kThisSubBlockSize; ++i) {
      std::swap(rows_64_bit.at(i)[1], rows_64_bit.at(kThisSubBlockSize + i)[0]);
    }
  }

  {
    constexpr std::size_t kThisBlkSize = 64;
    constexpr std::size_t kThisNumberOfSubBlocks = kThisBlkSize / 32;
    constexpr std::size_t kThisSubBlockSize = kThisBlkSize / kThisNumberOfSubBlocks;
    // swap the corresponding 32-bit blocks
    for (auto i = 0u; i < kBlkSize; i += kThisBlkSize) {
      for (auto j = 0u; j < kThisSubBlockSize; ++j) {
        std::swap(rows_32_bit.at(i + j)[1], rows_32_bit.at(kThisSubBlockSize + i + j)[0]);
        std::swap(rows_32_bit.at(i + j)[3], rows_32_bit.at(kThisSubBlockSize + i + j)[2]);
      }
    }
  }

  {
    // block size = {32, 16}
    constexpr std::array<std::uint64_t, 2> kMask0{0xFFFF0000FFFF0000ull, 0xFF00FF00FF00FF00ull};
    constexpr std::array<std::uint64_t, 2> kMask1{~kMask0.at(0), ~kMask0.at(1)};
    for (auto this_blk_size = 32, block_id = 0; this_blk_size > 8;
         this_blk_size >>= 1, ++block_id) {
      const std::size_t this_subblk_size = this_blk_size >> 1;
      for (auto i = 0u; i < kBlkSize; i += this_blk_size) {
        for (auto j = 0u; j < this_subblk_size; ++j) {
          tmp_64_0.at(i + j) = (rows_64_bit.at(i + j)[0] & kMask0.at(block_id)) >> this_subblk_size;
          tmp_64_0.at(i + this_subblk_size + j) =
              (rows_64_bit.at(i + j)[1] & kMask0.at(block_id)) >> this_subblk_size;

          tmp_64_1.at(i + j) = (rows_64_bit.at(this_subblk_size + i + j)[0] & kMask1.at(block_id))
                               << this_subblk_size;
          tmp_64_1.at(i + this_subblk_size + j) =
              (rows_64_bit.at(this_subblk_size + i + j)[1] & kMask1.at(block_id))
              << this_subblk_size;

          rows_64_bit.at(i + j)[0] =
              (rows_64_bit.at(i + j)[0] & kMask1.at(block_id)) | tmp_64_1.at(i + j);
          rows_64_bit.at(i + j)[1] = (rows_64_bit.at(i + j)[1] & kMask1.at(block_id)) |
                                     tmp_64_1.at(i + this_subblk_size + j);

          rows_64_bit.at(this_subblk_size + i + j)[0] =
              (rows_64_bit.at(this_subblk_size + i + j)[0] & kMask0.at(block_id)) |
              tmp_64_0.at(i + j);
          rows_64_bit.at(this_subblk_size + i + j)[1] =
              (rows_64_bit.at(this_subblk_size + i + j)[1] & kMask0.at(block_id)) |
              tmp_64_0.at(i + this_subblk_size + j);
        }
      }
    }
  }

  // block size in {8, 4, 2}
  // endianness madness
  // although we have little endianness here, integers are interpreted in a reversed order, i.e.,
  // std::byte[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07} is interpreted as
  // 0x07060504030201ull
  // if we want to swap last 4 bits from 0x0F and the first 4 bits from 0xAC, we need to
  // perform left shift for the first and right shift to the latter, not as for the 16 and 32
  // block size, and the mask should be in the correct order from here on

  {
    // block size = {8, 4, 2}
    constexpr std::array<std::uint64_t, 3> kMask0{0x0F0F0F0F0F0F0F0Full, 0x3333333333333333ull,
                                                  0x5555555555555555ull};
    constexpr std::array<std::uint64_t, 3> kMask1{~kMask0.at(0), ~kMask0.at(1), ~kMask0.at(2)};
    for (auto this_blk_size = 8, block_id = 0; this_blk_size > 1; this_blk_size >>= 1, ++block_id) {
      const std::size_t this_subblk_size = this_blk_size >> 1;
      for (auto i = 0u; i < kBlkSize; i += this_blk_size) {
        for (auto j = 0u; j < this_subblk_size; ++j) {
          tmp_64_0.at(i + j) = (rows_64_bit.at(i + j)[0] & kMask0.at(block_id)) << this_subblk_size;
          tmp_64_0.at(i + this_subblk_size + j) = (rows_64_bit.at(i + j)[1] & kMask0.at(block_id))
                                                  << this_subblk_size;

          tmp_64_1.at(i + j) =
              (rows_64_bit.at(this_subblk_size + i + j)[0] & kMask1.at(block_id)) >>
              this_subblk_size;
          tmp_64_1.at(i + this_subblk_size + j) =
              (rows_64_bit.at(this_subblk_size + i + j)[1] & kMask1.at(block_id)) >>
              this_subblk_size;

          rows_64_bit.at(i + j)[0] =
              (rows_64_bit.at(i + j)[0] & kMask1.at(block_id)) | tmp_64_1.at(i + j);
          rows_64_bit.at(i + j)[1] = (rows_64_bit.at(i + j)[1] & kMask1.at(block_id)) |
                                     tmp_64_1.at(i + this_subblk_size + j);

          rows_64_bit.at(this_subblk_size + i + j)[0] =
              (rows_64_bit.at(this_subblk_size + i + j)[0] & kMask0.at(block_id)) |
              tmp_64_0.at(i + j);
          rows_64_bit.at(this_subblk_size + i + j)[1] =
              (rows_64_bit.at(this_subblk_size + i + j)[1] & kMask0.at(block_id)) |
              tmp_64_0.at(i + this_subblk_size + j);
        }
      }
    }
  }
}

// BitMatrix::TransposeUsingBitSlicing(...)
//
// MIT License
//
// Copyright (c) 2018 Xiao Wang (wangxiao@gmail.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// Enquiries about further applications and development opportunities are
// welcome.

void BitMatrix::TransposeUsingBitSlicing(std::array<std::byte*, 128>& matrix,
                                         std::size_t number_of_colums) {
  auto inp = [&matrix](auto r, auto c) {
    return reinterpret_cast<const std::uint8_t* __restrict__>(
        __builtin_assume_aligned(matrix.at(r), 16))[c / 8];
  };

  constexpr std::uint64_t kNumberOfRows = 128;
  std::vector<std::uint8_t, boost::alignment::aligned_allocator<std::uint8_t, 16>> output(
      ((kNumberOfRows * number_of_colums) + 7) / 8, 0);

  auto out = [&output](auto r, auto c) { return &output[(r)*kNumberOfRows / 8 + (c) / 8]; };

  uint64_t rr, cc;
  int i;

  assert(kNumberOfRows % 8 == 0 && number_of_colums % 8 == 0);

  __m128i vec;
  // Do the main body in 16x8 blocks:
  for (rr = 0; rr <= kNumberOfRows - 16; rr += 16) {
    for (cc = 0; cc < number_of_colums; cc += 8) {
      vec = _mm_set_epi8(inp(rr + 15, cc), inp(rr + 14, cc), inp(rr + 13, cc), inp(rr + 12, cc),
                         inp(rr + 11, cc), inp(rr + 10, cc), inp(rr + 9, cc), inp(rr + 8, cc),
                         inp(rr + 7, cc), inp(rr + 6, cc), inp(rr + 5, cc), inp(rr + 4, cc),
                         inp(rr + 3, cc), inp(rr + 2, cc), inp(rr + 1, cc), inp(rr + 0, cc));
      for (i = 0; i < 8; vec = _mm_slli_epi64(vec, 1), ++i) {
        *(uint16_t* __restrict__)out(cc + 7 - i, rr) = _mm_movemask_epi8(vec);
      }
    }
  }

  for (auto j = 0ull; j < number_of_colums; ++j) {
    std::copy(reinterpret_cast<const std::uint8_t* __restrict__>(output.data()) + j * 16,
              reinterpret_cast<const std::uint8_t* __restrict__>(output.data()) + (j + 1) * 16,
              reinterpret_cast<std::uint8_t* __restrict__>(
                  __builtin_assume_aligned(matrix.at(j % kNumberOfRows), 16)) +
                  (j / kNumberOfRows) * 16);
  }
}

// TODO : All *TransposeAndEncrypt functions need to be restructured and modularized.
//  e.g. the matrix transposition should be moved to a separate (inline) function without adding
//  extra computation overhead and that the used functions need to be properly tested.
void BitMatrix::SenderTranspose128AndEncrypt(
    const std::array<const std::byte*, 128>& matrix, std::vector<BitVector<>>& y0,
    std::vector<BitVector<>>& y1, const BitVector<> choices, primitives::Prg& prg_fixed_key,
    const std::size_t number_of_colums, const std::vector<std::size_t>& bitlengths) {
  constexpr std::size_t kKappa{128}, kNumberOfRows{128};
  auto inp = [&matrix](auto r, auto c) {
    return reinterpret_cast<const std::uint8_t* __restrict__>(
        __builtin_assume_aligned(matrix.at(r), 16))[c / 8];
  };
  assert(y0.size() == y1.size());

  const std::size_t original_size{y0.size()}, difference{number_of_colums - original_size};
  if (difference) {
    y0.resize(number_of_colums);
    y1.resize(number_of_colums);
  }

  for (auto& block_vector : y0)
    block_vector = BitVector(std::vector<std::byte>(kKappa / 8), kKappa);

  std::uint64_t r{0}, c{0};
  int i{0};

  assert(kNumberOfRows % 8 == 0 && number_of_colums % 8 == 0);

  __m128i vec;
  primitives::Prg prg_var_key;
  // process 128x128 blocks
  while (c < number_of_colums) {
    auto c_old{c};
    for (r = 0; r <= kNumberOfRows - 16; r += 16) {
      for (c = c_old; c == c_old || (c % 128 != 0); c += 8) {
        vec = _mm_set_epi8(inp(r + 15, c), inp(r + 14, c), inp(r + 13, c), inp(r + 12, c),
                           inp(r + 11, c), inp(r + 10, c), inp(r + 9, c), inp(r + 8, c),
                           inp(r + 7, c), inp(r + 6, c), inp(r + 5, c), inp(r + 4, c),
                           inp(r + 3, c), inp(r + 2, c), inp(r + 1, c), inp(r + 0, c));
        for (i = 0; i < 8; vec = _mm_slli_epi64(vec, 1), ++i) {
          *reinterpret_cast<std::uint16_t* __restrict__>(y0[c + 7 - i].GetMutableData().data() +
                                                         r / 8) = _mm_movemask_epi8(vec);
        }
      }
    }
    for (; c_old < c && c_old < original_size; ++c_old) {
      auto& out0 = y0[c_old];
      auto& out1 = y1[c_old];

      // bit length of the OT
      const auto bitlength = bitlengths[c_old];

      out1 = choices ^ out0;
      assert(out0.GetSize() == 128);
      assert(out1.GetSize() == 128);
      // compute the sender outputs
      if (bitlength <= kKappa) {
        // the bit length is smaller than 128 bit
        prg_fixed_key.Mmo(out0.GetMutableData().data());
        prg_fixed_key.Mmo(out1.GetMutableData().data());
        out0.Resize(bitlength);
        out1.Resize(bitlength);
      } else {
        // string OT with bit length > 128 bit
        // -> do seed compression and send later only 128 bit seeds
        prg_fixed_key.Mmo(out0.GetMutableData().data());
        prg_fixed_key.Mmo(out1.GetMutableData().data());
        prg_var_key.SetKey(out0.GetData().data());
        out0 = BitVector<>(prg_var_key.Encrypt(BitsToBytes(bitlength)), bitlength);
        prg_var_key.SetKey(out1.GetData().data());
        out1 = BitVector<>(prg_var_key.Encrypt(BitsToBytes(bitlength)), bitlength);
      }
    }
  }
}

void BitMatrix::ReceiverTranspose128AndEncrypt(const std::array<const std::byte*, 128>& matrix,
                                               std::vector<BitVector<>>& output,
                                               primitives::Prg& prg_fixed_key,
                                               const std::size_t number_of_colums,
                                               const std::vector<std::size_t>& bitlengths) {
  constexpr std::size_t kKappa{128}, kNumberOfRows{128};
  auto inp = [&matrix](auto r, auto c) {
    return reinterpret_cast<const std::uint8_t* __restrict__>(
        __builtin_assume_aligned(matrix.at(r), 16))[c / 8];
  };

  const std::size_t original_size{output.size()}, difference{number_of_colums - original_size};
  if (difference) {
    output.resize(number_of_colums);
  }

  for (auto& block_vector : output)
    block_vector = BitVector(std::vector<std::byte>(kKappa / 8), kKappa);

  std::uint64_t r{0}, c{0};
  int i{0};

  assert(kNumberOfRows % 8 == 0 && number_of_colums % 8 == 0);

  __m128i vec;
  primitives::Prg prg_var_key;
  // process 128x128 blocks
  while (c < number_of_colums) {
    auto c_old{c};
    for (r = 0; r <= kNumberOfRows - 16; r += 16) {
      for (c = c_old; c == c_old || (c % 128 != 0); c += 8) {
        vec = _mm_set_epi8(inp(r + 15, c), inp(r + 14, c), inp(r + 13, c), inp(r + 12, c),
                           inp(r + 11, c), inp(r + 10, c), inp(r + 9, c), inp(r + 8, c),
                           inp(r + 7, c), inp(r + 6, c), inp(r + 5, c), inp(r + 4, c),
                           inp(r + 3, c), inp(r + 2, c), inp(r + 1, c), inp(r + 0, c));
        for (i = 0; i < 8; vec = _mm_slli_epi64(vec, 1), ++i) {
          *reinterpret_cast<std::uint16_t* __restrict__>(output[c + 7 - i].GetMutableData().data() +
                                                         r / 8) = _mm_movemask_epi8(vec);
        }
      }
    }
    for (; c_old < c && c_old < original_size; ++c_old) {
      auto& o = output[c_old];
      assert(o.GetSize() == 128);
      const std::size_t bitlength = bitlengths[c_old];

      if (bitlength <= kKappa) {
        prg_fixed_key.Mmo(o.GetMutableData().data());
        o.Resize(bitlength);
      } else {
        prg_fixed_key.Mmo(o.GetMutableData().data());
        prg_var_key.SetKey(o.GetData().data());
        o = BitVector<>(prg_var_key.Encrypt(BitsToBytes(bitlength)), bitlength);
      }
    }
  }
}

void BitMatrix::SenderTranspose256AndEncrypt(
    const std::array<const std::byte*, 256>& matrix, std::vector<std::vector<BitVector<>>>& y,
    const BitVector<> choices, std::vector<AlignedBitVector> x_a, primitives::Prg& prg_fixed_key,
    const std::size_t number_of_colums, const std::vector<std::size_t>& bitlengths) {
  std::size_t n;
  constexpr std::size_t kKappa{256}, kNumberOfRows{256};
  auto inp = [&matrix](auto r, auto c) {
    return reinterpret_cast<const std::uint8_t* __restrict__>(
        __builtin_assume_aligned(matrix.at(r), 16))[c / 8];
  };

  const std::size_t original_size = y.at(0).size();
  for (n = 1; n < y.size(); n++) {
    assert(original_size == y.at(n).size());
  }

  const std::size_t difference{number_of_colums - original_size};
  if (difference) {
    for (n = 0; n < y.size(); n++) {
      y.at(n).resize(number_of_colums);
    }
  }

  // do a bit wise AND between choices and the generated x_a
  std::vector<BitVector<>> choices_and_x_a;
  for (n = 0; n < x_a.size(); n++) {
    choices_and_x_a.push_back(choices & x_a.at(n));
  }

  for (auto& block_vector : y.at(0))
    block_vector = BitVector(std::vector<std::byte>(kKappa / 8), kKappa);

  std::uint64_t r{0}, c{0};
  int i{0};

  assert(kNumberOfRows % 8 == 0 && number_of_colums % 8 == 0);

  __m128i vec;
  primitives::Prg prg_var_key;
  // process 256x256 blocks
  while (c < number_of_colums) {
    auto c_old{c};
    for (r = 0; r <= kNumberOfRows - 16; r += 16) {
      for (c = c_old; c == c_old || (c % 256 != 0); c += 8) {
        vec = _mm_set_epi8(inp(r + 15, c), inp(r + 14, c), inp(r + 13, c), inp(r + 12, c),
                           inp(r + 11, c), inp(r + 10, c), inp(r + 9, c), inp(r + 8, c),
                           inp(r + 7, c), inp(r + 6, c), inp(r + 5, c), inp(r + 4, c),
                           inp(r + 3, c), inp(r + 2, c), inp(r + 1, c), inp(r + 0, c));
        for (i = 0; i < 8; vec = _mm_slli_epi64(vec, 1), ++i) {
          *reinterpret_cast<std::uint16_t* __restrict__>(
              y.at(0)[c + 7 - i].GetMutableData().data() + r / 8) = _mm_movemask_epi8(vec);
        }
      }
    }
    for (; c_old < c && c_old < original_size; ++c_old) {
      //  copy the content of y[0] to all y[n]
      for (n = 0; n < y.size() - 1; n++) {
        y.at(n + 1)[c_old] = y.at(n)[c_old];
      }

      for (n = 0; n < y.size(); n++) {
        y.at(n)[c_old] ^= choices_and_x_a.at(n);
        assert(y.at(n)[c_old].GetSize() == 256);
      }

      // bit length of the OT
      const auto bitlength = bitlengths[c_old];

      // compute the sender outputs
      if (bitlength <= kKappa) {
        for (n = 0; n < y.size(); n++) {
          // the bit length is smaller than 256 bit
          prg_fixed_key.Mmo(y.at(n)[c_old].GetMutableData().data());
          y.at(n)[c_old].Resize(bitlength);
        }
      } else {
        // string OT with bit length > 256 bit
        // -> do seed compression and send later only 256 bit seeds
        for (n = 0; n < y.size(); n++) {
          prg_fixed_key.Mmo(y.at(n)[c_old].GetMutableData().data());
          prg_var_key.SetKey(y.at(n)[c_old].GetData().data());
          y.at(n)[c_old] = BitVector<>(prg_var_key.Encrypt(BitsToBytes(bitlength)), bitlength);
        }
      }
    }
  }
}

void BitMatrix::ReceiverTranspose256AndEncrypt(const std::array<const std::byte*, 256>& matrix,
                                               std::vector<BitVector<>>& output,
                                               primitives::Prg& prg_fixed_key,
                                               const std::size_t number_of_columns,
                                               const std::vector<std::size_t>& bitlengths) {
  constexpr std::size_t kKappa{256}, kNumberOfRows{256};
  auto inp = [&matrix](auto r, auto c) {
    return reinterpret_cast<const std::uint8_t* __restrict__>(
        __builtin_assume_aligned(matrix.at(r), 16))[c / 8];
  };

  const std::size_t original_size{output.size()}, difference{number_of_columns - original_size};
  if (difference) {
    output.resize(number_of_columns);
  }

  for (auto& block_vector : output)
    block_vector = BitVector(std::vector<std::byte>(kKappa / 8), kKappa);

  std::uint64_t r{0}, c{0};
  int i{0};

  assert(kNumberOfRows % 8 == 0 && number_of_columns % 8 == 0);

  __m128i vec;
  primitives::Prg prg_var_key;
  // process 256x256 blocks
  while (c < number_of_columns) {
    auto c_old{c};
    for (r = 0; r <= kNumberOfRows - 16; r += 16) {
      for (c = c_old; c == c_old || (c % 256 != 0); c += 8) {
        vec = _mm_set_epi8(inp(r + 15, c), inp(r + 14, c), inp(r + 13, c), inp(r + 12, c),
                           inp(r + 11, c), inp(r + 10, c), inp(r + 9, c), inp(r + 8, c),
                           inp(r + 7, c), inp(r + 6, c), inp(r + 5, c), inp(r + 4, c),
                           inp(r + 3, c), inp(r + 2, c), inp(r + 1, c), inp(r + 0, c));
        for (i = 0; i < 8; vec = _mm_slli_epi64(vec, 1), ++i) {
          *reinterpret_cast<std::uint16_t* __restrict__>(output[c + 7 - i].GetMutableData().data() +
                                                         r / 8) = _mm_movemask_epi8(vec);
        }
      }
    }
    for (; c_old < c && c_old < original_size; ++c_old) {
      auto& o = output[c_old];
      assert(o.GetSize() == 256);
      const std::size_t bitlength = bitlengths[c_old];

      if (bitlength <= kKappa) {
        prg_fixed_key.Mmo(o.GetMutableData().data());
        o.Resize(bitlength);
      } else {
        prg_fixed_key.Mmo(o.GetMutableData().data());
        prg_var_key.SetKey(o.GetData().data());
        o = BitVector<>(prg_var_key.Encrypt(BitsToBytes(bitlength)), bitlength);
      }
    }
  }
}

bool BitMatrix::operator==(const BitMatrix& other) const {
  if (other.data_.size() != data_.size()) {
    return false;
  }

  for (auto i = 0ull; i < data_.size(); ++i) {
    if (data_.at(i) != other.data_.at(i)) {
      return false;
    }
  }

  return true;
}

}  // namespace encrypto::motion
