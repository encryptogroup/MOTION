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

#include <immintrin.h>
#include <omp.h>
#include <cmath>
#include <iostream>

#include "crypto/pseudo_random_generator.h"
#include "helpers.h"

namespace ENCRYPTO {
void BitMatrix::Transpose() {
  std::size_t num_rows = data_.size();
  if (num_rows == 0 || num_columns_ == 0 || (num_rows == 1 && num_columns_ == 1)) {
    return;
  } else if (num_rows == 1) {
    for (auto i = 1ull; i < num_columns_; ++i) {
      data_.emplace_back(1, data_.at(0).Get(i));
    }
    data_.at(0).Resize(1, true);
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
      bv.Resize(num_columns_ + block_size - (num_columns_ % block_size), true);
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
      data_.at(i).Resize(block_size, true);
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

  TransposeInternal();

  // remove padding
  data_.resize(initial_num_columns);

  for (auto& bv : data_) {
    bv.Resize(initial_num_rows, true);
  }

  num_columns_ = initial_num_rows;
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

  Transpose128RowsInternal();

  // remove padding
  data_.resize(initial_num_columns);

  for (auto& bv : data_) {
    bv.Resize(initial_num_rows);
  }

  num_columns_ = initial_num_rows;
}

void BitMatrix::Transpose128RowsInternal() {
  constexpr std::size_t num_columns = 128;
  for (auto block_offset = 0u; block_offset < num_columns_; block_offset += num_columns) {
    std::array<std::uint64_t*, num_columns> rows_64;
    std::array<std::uint32_t*, num_columns> rows_32;

    for (auto i = 0u; i < num_columns; ++i) {
      rows_64.at(i) =
          reinterpret_cast<std::uint64_t*>(data_.at(block_offset + i).GetMutableData().data());
      rows_32.at(i) =
          reinterpret_cast<std::uint32_t*>(data_.at(block_offset + i).GetMutableData().data());
    }

    Transpose128x128InPlace(rows_64, rows_32);
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

void BitMatrix::Transpose128RowsInplace(std::array<std::byte*, 128>& matrix,
                                        std::size_t num_columns) {
  constexpr std::size_t blk_size = 128;
  for (auto blk_offset = 0u; blk_offset < num_columns; blk_offset += blk_size) {
    std::array<std::uint64_t*, blk_size> rows_64;
    std::array<std::uint32_t*, blk_size> rows_32;

    for (auto i = 0u; i < blk_size; ++i) {
      rows_64.at(i) = reinterpret_cast<std::uint64_t*>(matrix.at(i) + (blk_offset >> 3));
      rows_32.at(i) = reinterpret_cast<std::uint32_t*>(matrix.at(i) + (blk_offset >> 3));
    }

    Transpose128x128InPlace(rows_64, rows_32);
  }
}

void BitMatrix::Transpose128x128InPlace(std::array<std::uint64_t*, 128>& rows_64,
                                        std::array<std::uint32_t*, 128>& rows_32) {
  constexpr std::size_t blk_size = 128;

  std::array<std::uint64_t, blk_size> tmp_64_0, tmp_64_1;

  {
    constexpr std::size_t this_blk_size = 128;
    // swap the corresponding 64-bit blocks
    constexpr std::size_t this_subblk_size = this_blk_size / 2;
    for (auto i = 0u; i < this_subblk_size; ++i) {
      std::swap(rows_64.at(i)[1], rows_64.at(this_subblk_size + i)[0]);
    }
  }

  {
    constexpr std::size_t this_blk_size = 64;
    constexpr std::size_t this_subblk_size = this_blk_size / 2;
    // swap the corresponding 32-bit blocks
    for (auto i = 0u; i < blk_size; i += this_blk_size) {
      for (auto j = 0u; j < this_subblk_size; ++j) {
        std::swap(rows_32.at(i + j)[1], rows_32.at(this_subblk_size + i + j)[0]);
        std::swap(rows_32.at(i + j)[3], rows_32.at(this_subblk_size + i + j)[2]);
      }
    }
  }

  {
    // block size = {32, 16}
    constexpr std::array<std::uint64_t, 2> mask0{0xFFFF0000FFFF0000ull, 0xFF00FF00FF00FF00ull};
    constexpr std::array<std::uint64_t, 2> mask1{~mask0.at(0), ~mask0.at(1)};
    for (auto this_blk_size = 32, block_id = 0; this_blk_size > 8;
         this_blk_size >>= 1, ++block_id) {
      const std::size_t this_subblk_size = this_blk_size >> 1;
      for (auto i = 0u; i < blk_size; i += this_blk_size) {
        for (auto j = 0u; j < this_subblk_size; ++j) {
          tmp_64_0.at(i + j) = (rows_64.at(i + j)[0] & mask0.at(block_id)) >> this_subblk_size;
          tmp_64_0.at(i + this_subblk_size + j) =
              (rows_64.at(i + j)[1] & mask0.at(block_id)) >> this_subblk_size;

          tmp_64_1.at(i + j) = (rows_64.at(this_subblk_size + i + j)[0] & mask1.at(block_id))
                               << this_subblk_size;
          tmp_64_1.at(i + this_subblk_size + j) =
              (rows_64.at(this_subblk_size + i + j)[1] & mask1.at(block_id)) << this_subblk_size;

          rows_64.at(i + j)[0] = (rows_64.at(i + j)[0] & mask1.at(block_id)) | tmp_64_1.at(i + j);
          rows_64.at(i + j)[1] =
              (rows_64.at(i + j)[1] & mask1.at(block_id)) | tmp_64_1.at(i + this_subblk_size + j);

          rows_64.at(this_subblk_size + i + j)[0] =
              (rows_64.at(this_subblk_size + i + j)[0] & mask0.at(block_id)) | tmp_64_0.at(i + j);
          rows_64.at(this_subblk_size + i + j)[1] =
              (rows_64.at(this_subblk_size + i + j)[1] & mask0.at(block_id)) |
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
    constexpr std::array<std::uint64_t, 3> mask0{0x0F0F0F0F0F0F0F0Full, 0x3333333333333333ull,
                                                 0x5555555555555555ull};
    constexpr std::array<std::uint64_t, 3> mask1{~mask0.at(0), ~mask0.at(1), ~mask0.at(2)};
    for (auto this_blk_size = 8, block_id = 0; this_blk_size > 1; this_blk_size >>= 1, ++block_id) {
      const std::size_t this_subblk_size = this_blk_size >> 1;
      for (auto i = 0u; i < blk_size; i += this_blk_size) {
        for (auto j = 0u; j < this_subblk_size; ++j) {
          tmp_64_0.at(i + j) = (rows_64.at(i + j)[0] & mask0.at(block_id)) << this_subblk_size;
          tmp_64_0.at(i + this_subblk_size + j) = (rows_64.at(i + j)[1] & mask0.at(block_id))
                                                  << this_subblk_size;

          tmp_64_1.at(i + j) =
              (rows_64.at(this_subblk_size + i + j)[0] & mask1.at(block_id)) >> this_subblk_size;
          tmp_64_1.at(i + this_subblk_size + j) =
              (rows_64.at(this_subblk_size + i + j)[1] & mask1.at(block_id)) >> this_subblk_size;

          rows_64.at(i + j)[0] = (rows_64.at(i + j)[0] & mask1.at(block_id)) | tmp_64_1.at(i + j);
          rows_64.at(i + j)[1] =
              (rows_64.at(i + j)[1] & mask1.at(block_id)) | tmp_64_1.at(i + this_subblk_size + j);

          rows_64.at(this_subblk_size + i + j)[0] =
              (rows_64.at(this_subblk_size + i + j)[0] & mask0.at(block_id)) | tmp_64_0.at(i + j);
          rows_64.at(this_subblk_size + i + j)[1] =
              (rows_64.at(this_subblk_size + i + j)[1] & mask0.at(block_id)) |
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

void BitMatrix::TransposeUsingBitSlicing(std::array<std::byte*, 128>& matrix, std::size_t ncols) {
#define INP(r, c)                                     \
  reinterpret_cast<const std::uint8_t* __restrict__>( \
      __builtin_assume_aligned(matrix.at(r), 16))[c / 8]
#define OUT(r, c) out[(r)*nrows / 8 + (c) / 8]

  constexpr std::uint64_t nrows = 128;
  std::vector<std::uint8_t, boost::alignment::aligned_allocator<std::byte, 16>> out(
      ((nrows * ncols) + 7) / 8, 0);

  uint64_t rr, cc;
  int i;

  assert(nrows % 8 == 0 && ncols % 8 == 0);

  // constexpr auto block_size = nrows * nrows;
  // const auto num_blocks = nrows * ncols / block_size;

//#define MOTION_AVX2
#if defined(MOTION_AVX512)
  // TODO: not tested yet
  __m512i vec;
  for (rr = 0; rr <= nrows - 32; rr += 8) {
    for (cc = 0; cc < ncols; cc += 64) {
      vec = _mm512_set_epi8(
          INP(rr + 56, cc), INP(rr + 57, cc), INP(rr + 58, cc), INP(rr + 59, cc), INP(rr + 60, cc),
          INP(rr + 61, cc), INP(rr + 62, cc), INP(rr + 63, cc), INP(rr + 48, cc), INP(rr + 49, cc),
          INP(rr + 50, cc), INP(rr + 51, cc), INP(rr + 52, cc), INP(rr + 53, cc), INP(rr + 54, cc),
          INP(rr + 55, cc), INP(rr + 39, cc), INP(rr + 40, cc), INP(rr + 41, cc), INP(rr + 42, cc),
          INP(rr + 43, cc), INP(rr + 44, cc), INP(rr + 45, cc), INP(rr + 46, cc), INP(rr + 32, cc),
          INP(rr + 33, cc), INP(rr + 34, cc), INP(rr + 35, cc), INP(rr + 36, cc), INP(rr + 37, cc),
          INP(rr + 38, cc), INP(rr + 39, cc), INP(rr + 24, cc), INP(rr + 25, cc), INP(rr + 26, cc),
          INP(rr + 27, cc), INP(rr + 28, cc), INP(rr + 29, cc), INP(rr + 30, cc), INP(rr + 31, cc),
          INP(rr + 16, cc), INP(rr + 17, cc), INP(rr + 18, cc), INP(rr + 19, cc), INP(rr + 20, cc),
          INP(rr + 21, cc), INP(rr + 22, cc), INP(rr + 23, cc), INP(rr + 8, cc), INP(rr + 9, cc),
          INP(rr + 10, cc), INP(rr + 11, cc), INP(rr + 12, cc), INP(rr + 13, cc), INP(rr + 14, cc),
          INP(rr + 15, cc), INP(rr + 0, cc), INP(rr + 1, cc), INP(rr + 2, cc), INP(rr + 3, cc),
          INP(rr + 4, cc), INP(rr + 5, cc), INP(rr + 6, cc), INP(rr + 7, cc));
      for (i = 0; i < 64; vec = _mm512_slli_epi64(vec, 1), ++i) {
        OUT(cc + i, rr) = _mm512_movepi64_mask(vec);
      }
    }
  }
#elif defined(MOTION_AVX2)
  __m256i vec;
  for (rr = 0; rr <= nrows - 32; rr += 32) {
    for (cc = 0; cc < ncols; cc += 8) {
      vec = _mm256_set_epi8(INP(rr + 24, cc), INP(rr + 25, cc), INP(rr + 26, cc), INP(rr + 27, cc),
                            INP(rr + 28, cc), INP(rr + 29, cc), INP(rr + 30, cc), INP(rr + 31, cc),
                            INP(rr + 16, cc), INP(rr + 17, cc), INP(rr + 18, cc), INP(rr + 19, cc),
                            INP(rr + 20, cc), INP(rr + 21, cc), INP(rr + 22, cc), INP(rr + 23, cc),
                            INP(rr + 8, cc), INP(rr + 9, cc), INP(rr + 10, cc), INP(rr + 11, cc),
                            INP(rr + 12, cc), INP(rr + 13, cc), INP(rr + 14, cc), INP(rr + 15, cc),
                            INP(rr + 0, cc), INP(rr + 1, cc), INP(rr + 2, cc), INP(rr + 3, cc),
                            INP(rr + 4, cc), INP(rr + 5, cc), INP(rr + 6, cc), INP(rr + 7, cc));
      for (i = 0; i < 8; vec = _mm256_slli_epi64(vec, 1), ++i) {
        *(uint32_t*)&OUT(cc + i, rr) = _mm256_movemask_epi8(vec);
        // const auto pos = ((cc + i) % nrows) * num_blocks * 16 + (cc / nrows) * 16 + rr / 8;
        //*(uint16_t*)&out[pos] = _mm_movemask_epi8(vec);
      }
    }
  }
#else
  __m128i vec;
  // Do the main body in 16x8 blocks:
  for (rr = 0; rr <= nrows - 16; rr += 16) {
    for (cc = 0; cc < ncols; cc += 8) {
      vec = _mm_set_epi8(INP(rr + 8, cc), INP(rr + 9, cc), INP(rr + 10, cc), INP(rr + 11, cc),
                         INP(rr + 12, cc), INP(rr + 13, cc), INP(rr + 14, cc), INP(rr + 15, cc),
                         INP(rr + 0, cc), INP(rr + 1, cc), INP(rr + 2, cc), INP(rr + 3, cc),
                         INP(rr + 4, cc), INP(rr + 5, cc), INP(rr + 6, cc), INP(rr + 7, cc));
      for (i = 0; i < 8; vec = _mm_slli_epi64(vec, 1), ++i) {
        *(uint16_t * __restrict__) & OUT(cc + i, rr) = _mm_movemask_epi8(vec);
        // const auto pos = ((cc + i) % nrows) * num_blocks * 16 + (cc / nrows) * 16 + rr / 8;
        //*(uint16_t*)&out[pos] = _mm_movemask_epi8(vec);
      }
    }
  }
#endif

  for (auto j = 0ull; j < ncols; ++j) {
    std::copy(reinterpret_cast<const std::uint8_t* __restrict__>(out.data()) + j * 16,
              reinterpret_cast<const std::uint8_t* __restrict__>(out.data()) + (j + 1) * 16,
              reinterpret_cast<std::uint8_t* __restrict__>(
                  __builtin_assume_aligned(matrix.at(j % nrows), 16)) +
                  (j / nrows) * 16);
  }

  // for (auto j = 0ull; j < nrows; ++j) {
  // std::copy(out.data() + j * 16 * num_blocks, out.data() + (j + 1) * 16 * num_blocks,
  //          reinterpret_cast<std::uint8_t*>(matrix.at(j)));
  // }
}

void BitMatrix::SenderTransposeAndEncrypt(const std::array<const std::byte*, 128>& matrix,
                                          std::vector<BitVector<>>& y0,
                                          std::vector<BitVector<>>& y1, const BitVector<> choices,
                                          PRG& prg_fixed_key, const std::size_t ncols,
                                          const std::vector<std::size_t>& bitlengths) {
  constexpr std::size_t kappa{128}, nrows{128};
#define INP(r, c)                                     \
  reinterpret_cast<const std::uint8_t* __restrict__>( \
      __builtin_assume_aligned(matrix.at(r), 16))[c / 8]
  assert(y0.size() == y1.size());

  const std::size_t original_size{y0.size()}, difference{ncols - original_size};
  if (difference) {
    y0.resize(ncols);
    y1.resize(ncols);
  }

  for (auto& bv : y0) bv = BitVector(std::vector<std::byte>(kappa / 8), kappa);

  std::uint64_t r{0}, c{0};
  int i{0};

  assert(nrows % 8 == 0 && ncols % 8 == 0);

//#define MOTION_AVX2
#if defined(MOTION_AVX512)
  // TODO: not tested yet
  __m512i vec;
  for (rr = 0; rr <= nrows - 32; rr += 8) {
    for (cc = 0; cc < ncols; cc += 64) {
      vec = _mm512_set_epi8(
          INP(rr + 56, cc), INP(rr + 57, cc), INP(rr + 58, cc), INP(rr + 59, cc), INP(rr + 60, cc),
          INP(rr + 61, cc), INP(rr + 62, cc), INP(rr + 63, cc), INP(rr + 48, cc), INP(rr + 49, cc),
          INP(rr + 50, cc), INP(rr + 51, cc), INP(rr + 52, cc), INP(rr + 53, cc), INP(rr + 54, cc),
          INP(rr + 55, cc), INP(rr + 39, cc), INP(rr + 40, cc), INP(rr + 41, cc), INP(rr + 42, cc),
          INP(rr + 43, cc), INP(rr + 44, cc), INP(rr + 45, cc), INP(rr + 46, cc), INP(rr + 32, cc),
          INP(rr + 33, cc), INP(rr + 34, cc), INP(rr + 35, cc), INP(rr + 36, cc), INP(rr + 37, cc),
          INP(rr + 38, cc), INP(rr + 39, cc), INP(rr + 24, cc), INP(rr + 25, cc), INP(rr + 26, cc),
          INP(rr + 27, cc), INP(rr + 28, cc), INP(rr + 29, cc), INP(rr + 30, cc), INP(rr + 31, cc),
          INP(rr + 16, cc), INP(rr + 17, cc), INP(rr + 18, cc), INP(rr + 19, cc), INP(rr + 20, cc),
          INP(rr + 21, cc), INP(rr + 22, cc), INP(rr + 23, cc), INP(rr + 8, cc), INP(rr + 9, cc),
          INP(rr + 10, cc), INP(rr + 11, cc), INP(rr + 12, cc), INP(rr + 13, cc), INP(rr + 14, cc),
          INP(rr + 15, cc), INP(rr + 0, cc), INP(rr + 1, cc), INP(rr + 2, cc), INP(rr + 3, cc),
          INP(rr + 4, cc), INP(rr + 5, cc), INP(rr + 6, cc), INP(rr + 7, cc));
      for (i = 0; i < 64; vec = _mm512_slli_epi64(vec, 1), ++i) {
        OUT(cc + i, rr) = _mm512_movepi64_mask(vec);
      }
    }
  }
#elif defined(MOTION_AVX2)
  __m256i vec;
  for (rr = 0; rr <= nrows - 32; rr += 32) {
    for (cc = 0; cc < ncols; cc += 8) {
      vec = _mm256_set_epi8(INP(rr + 24, cc), INP(rr + 25, cc), INP(rr + 26, cc), INP(rr + 27, cc),
                            INP(rr + 28, cc), INP(rr + 29, cc), INP(rr + 30, cc), INP(rr + 31, cc),
                            INP(rr + 16, cc), INP(rr + 17, cc), INP(rr + 18, cc), INP(rr + 19, cc),
                            INP(rr + 20, cc), INP(rr + 21, cc), INP(rr + 22, cc), INP(rr + 23, cc),
                            INP(rr + 8, cc), INP(rr + 9, cc), INP(rr + 10, cc), INP(rr + 11, cc),
                            INP(rr + 12, cc), INP(rr + 13, cc), INP(rr + 14, cc), INP(rr + 15, cc),
                            INP(rr + 0, cc), INP(rr + 1, cc), INP(rr + 2, cc), INP(rr + 3, cc),
                            INP(rr + 4, cc), INP(rr + 5, cc), INP(rr + 6, cc), INP(rr + 7, cc));
      for (i = 0; i < 8; vec = _mm256_slli_epi64(vec, 1), ++i) {
        *(uint32_t*)&OUT(cc + i, rr) = _mm256_movemask_epi8(vec);
        // const auto pos = ((cc + i) % nrows) * num_blocks * 16 + (cc / nrows) * 16 + rr / 8;
        //*(uint16_t*)&out[pos] = _mm_movemask_epi8(vec);
      }
    }
  }
#else
  __m128i vec;
  PRG prg_var_key;
  // process 128x128 blocks
  while (c < ncols) {
    auto c_old{c};
    for (r = 0; r <= nrows - 16; r += 16) {
      for (c = 0; c == 0 || (c % 128 != 0); c += 8) {
        vec = _mm_set_epi8(INP(r + 8, c), INP(r + 9, c), INP(r + 10, c), INP(r + 11, c),
                           INP(r + 12, c), INP(r + 13, c), INP(r + 14, c), INP(r + 15, c),
                           INP(r + 0, c), INP(r + 1, c), INP(r + 2, c), INP(r + 3, c),
                           INP(r + 4, c), INP(r + 5, c), INP(r + 6, c), INP(r + 7, c));
        for (i = 0; i < 8; vec = _mm_slli_epi64(vec, 1), ++i) {
          *reinterpret_cast<std::uint16_t* __restrict__>(y0[c + i].GetMutableData().data() +
                                                         r / 8) = _mm_movemask_epi8(vec);
        }
      }
    }
    // XXX
    for (; c_old < c && c_old < original_size; ++c_old) {
      // here we want to store the sender's outputs
      // XXX: why are the y0_, y1_ vectors resized every time new ots are registered?
      auto& out0 = y0[c_old];
      auto& out1 = y1[c_old];

      // bit length of the OT
      const auto bitlen = bitlengths[c_old];

      out1 = choices ^ out0;
      // compute the sender outputs
      if (bitlen <= kappa) {
        // the bit length is smaller than 128 bit
        out0 = BitVector<>(prg_fixed_key.FixedKeyAES(out0.GetData().data(), c_old), bitlen);
        out1 = BitVector<>(prg_fixed_key.FixedKeyAES(out1.GetData().data(), c_old), bitlen);
      } else {
        // string OT with bit length > 128 bit
        // -> do seed compression and send later only 128 bit seeds
        auto row = reinterpret_cast<std::byte*>(
            __builtin_assume_aligned(y0[c_old].GetMutableData().data(), MOTION::MOTION_ALIGNMENT));
        const auto seed0 = prg_fixed_key.FixedKeyAES(row, c_old);
        prg_var_key.SetKey(seed0.data());
        out0 =
            BitVector<>(prg_var_key.Encrypt(MOTION::Helpers::Convert::BitsToBytes(bitlen)), bitlen);
        const auto seed1 = prg_fixed_key.FixedKeyAES(out1.GetData().data(), c_old);
        prg_var_key.SetKey(seed1.data());
        out1 =
            BitVector<>(prg_var_key.Encrypt(MOTION::Helpers::Convert::BitsToBytes(bitlen)), bitlen);
      }
    }
  }
#endif
}

void BitMatrix::ReceiverTransposeAndEncrypt(const std::array<const std::byte*, 128>& matrix,
                                            std::vector<BitVector<>>& out, PRG& prg_fixed_key,
                                            const std::size_t ncols,
                                            const std::vector<std::size_t>& bitlengths) {
  constexpr std::size_t kappa{128}, nrows{128};
#define INP(r, c)                                     \
  reinterpret_cast<const std::uint8_t* __restrict__>( \
      __builtin_assume_aligned(matrix.at(r), 16))[c / 8]

  const std::size_t original_size{out.size()}, difference{ncols - original_size};
  if (difference) {
    out.resize(ncols);
  }

  for (auto& bv : out) bv = BitVector(std::vector<std::byte>(kappa / 8), kappa);

  std::uint64_t r{0}, c{0};
  int i{0};

  assert(nrows % 8 == 0 && ncols % 8 == 0);

//#define MOTION_AVX2
#if defined(MOTION_AVX512)
  // TODO: not tested yet
  __m512i vec;
  for (rr = 0; rr <= nrows - 32; rr += 8) {
    for (cc = 0; cc < ncols; cc += 64) {
      vec = _mm512_set_epi8(
          INP(rr + 56, cc), INP(rr + 57, cc), INP(rr + 58, cc), INP(rr + 59, cc), INP(rr + 60, cc),
          INP(rr + 61, cc), INP(rr + 62, cc), INP(rr + 63, cc), INP(rr + 48, cc), INP(rr + 49, cc),
          INP(rr + 50, cc), INP(rr + 51, cc), INP(rr + 52, cc), INP(rr + 53, cc), INP(rr + 54, cc),
          INP(rr + 55, cc), INP(rr + 39, cc), INP(rr + 40, cc), INP(rr + 41, cc), INP(rr + 42, cc),
          INP(rr + 43, cc), INP(rr + 44, cc), INP(rr + 45, cc), INP(rr + 46, cc), INP(rr + 32, cc),
          INP(rr + 33, cc), INP(rr + 34, cc), INP(rr + 35, cc), INP(rr + 36, cc), INP(rr + 37, cc),
          INP(rr + 38, cc), INP(rr + 39, cc), INP(rr + 24, cc), INP(rr + 25, cc), INP(rr + 26, cc),
          INP(rr + 27, cc), INP(rr + 28, cc), INP(rr + 29, cc), INP(rr + 30, cc), INP(rr + 31, cc),
          INP(rr + 16, cc), INP(rr + 17, cc), INP(rr + 18, cc), INP(rr + 19, cc), INP(rr + 20, cc),
          INP(rr + 21, cc), INP(rr + 22, cc), INP(rr + 23, cc), INP(rr + 8, cc), INP(rr + 9, cc),
          INP(rr + 10, cc), INP(rr + 11, cc), INP(rr + 12, cc), INP(rr + 13, cc), INP(rr + 14, cc),
          INP(rr + 15, cc), INP(rr + 0, cc), INP(rr + 1, cc), INP(rr + 2, cc), INP(rr + 3, cc),
          INP(rr + 4, cc), INP(rr + 5, cc), INP(rr + 6, cc), INP(rr + 7, cc));
      for (i = 0; i < 64; vec = _mm512_slli_epi64(vec, 1), ++i) {
        OUT(cc + i, rr) = _mm512_movepi64_mask(vec);
      }
    }
  }
#elif defined(MOTION_AVX2)
  __m256i vec;
  for (rr = 0; rr <= nrows - 32; rr += 32) {
    for (cc = 0; cc < ncols; cc += 8) {
      vec = _mm256_set_epi8(INP(rr + 24, cc), INP(rr + 25, cc), INP(rr + 26, cc), INP(rr + 27, cc),
                            INP(rr + 28, cc), INP(rr + 29, cc), INP(rr + 30, cc), INP(rr + 31, cc),
                            INP(rr + 16, cc), INP(rr + 17, cc), INP(rr + 18, cc), INP(rr + 19, cc),
                            INP(rr + 20, cc), INP(rr + 21, cc), INP(rr + 22, cc), INP(rr + 23, cc),
                            INP(rr + 8, cc), INP(rr + 9, cc), INP(rr + 10, cc), INP(rr + 11, cc),
                            INP(rr + 12, cc), INP(rr + 13, cc), INP(rr + 14, cc), INP(rr + 15, cc),
                            INP(rr + 0, cc), INP(rr + 1, cc), INP(rr + 2, cc), INP(rr + 3, cc),
                            INP(rr + 4, cc), INP(rr + 5, cc), INP(rr + 6, cc), INP(rr + 7, cc));
      for (i = 0; i < 8; vec = _mm256_slli_epi64(vec, 1), ++i) {
        *(uint32_t*)&OUT(cc + i, rr) = _mm256_movemask_epi8(vec);
        // const auto pos = ((cc + i) % nrows) * num_blocks * 16 + (cc / nrows) * 16 + rr / 8;
        //*(uint16_t*)&out[pos] = _mm_movemask_epi8(vec);
      }
    }
  }
#else
  __m128i vec;
  PRG prg_var_key;
  // process 128x128 blocks
  while (c < ncols) {
    auto c_old{c};
    for (r = 0; r <= nrows - 16; r += 16) {
      for (c = 0; c == 0 || (c % 128 != 0); c += 8) {
        vec = _mm_set_epi8(INP(r + 8, c), INP(r + 9, c), INP(r + 10, c), INP(r + 11, c),
                           INP(r + 12, c), INP(r + 13, c), INP(r + 14, c), INP(r + 15, c),
                           INP(r + 0, c), INP(r + 1, c), INP(r + 2, c), INP(r + 3, c),
                           INP(r + 4, c), INP(r + 5, c), INP(r + 6, c), INP(r + 7, c));
        for (i = 0; i < 8; vec = _mm_slli_epi64(vec, 1), ++i) {
          *reinterpret_cast<std::uint16_t* __restrict__>(out[c + i].GetMutableData().data() +
                                                         r / 8) = _mm_movemask_epi8(vec);
        }
      }
    }
    // XXX
    for (; c_old < c && c_old < original_size; ++c_old) {
        auto &o = out[c_old];

        //std::unique_lock lock(bitlengths_mutex_);
        const std::size_t bitlen = bitlengths[c_old];
        //lock.unlock();

        if (bitlen <= kappa) {
          o = BitVector<>(prg_fixed_key.FixedKeyAES(o.GetData().data(), c_old), bitlen);
        } else {
          auto seed = prg_fixed_key.FixedKeyAES(o.GetData().data(), c_old);
          prg_var_key.SetKey(seed.data());
          o = BitVector<>(prg_var_key.Encrypt(MOTION::Helpers::Convert::BitsToBytes(bitlen)), bitlen);
        }
    }
  }
#endif
}

bool BitMatrix::operator==(const BitMatrix& other) {
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

}  // namespace ENCRYPTO
