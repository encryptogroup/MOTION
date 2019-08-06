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

#include <random>

#include <gtest/gtest.h>

#include "utility/bit_matrix.h"

#include "test_constants.h"

#include <emmintrin.h>
#include <stdint.h>
#include <stdlib.h>

namespace {
TEST(BitMatrix, Transpose) {
  for (auto test_iterations = 0ull; test_iterations < TEST_ITERATIONS; ++test_iterations) {
    for (auto i = 0ull; i < 11u; ++i) {
      std::random_device rd;
      std::uniform_int_distribution<std::uint64_t> dist(0, 1ull << i);

      const std::size_t m = dist(rd), n = dist(rd);
      // const std::size_t m = 128, n = 16'777'216ull;
      // const  std::size_t m = 16'777'216ull, n = 128;
      std::vector<ENCRYPTO::AlignedBitVector> vectors(m);

      for (auto j = 0ull; j < m; ++j) {
        vectors.at(j) = ENCRYPTO::AlignedBitVector::Random(n);
      }

      ENCRYPTO::BitMatrix bm(vectors);
      auto bm_transposed = bm;
      bm_transposed.Transpose();

      for (auto column_i = 0ull; column_i < n; ++column_i) {
        for (auto row_i = 0ull; row_i < m; ++row_i) {
          ASSERT_EQ(bm.Get(row_i, column_i), bm_transposed.Get(column_i, row_i));
        }
      }
    }
  }
}

TEST(BitMatrix, Transpose128) {
  for (auto test_iterations = 0ull; test_iterations < TEST_ITERATIONS; ++test_iterations) {
    for (auto i = 7ull; i < 15u; ++i) {
      std::random_device rd;
      std::uniform_int_distribution<std::uint64_t> dist(1, 1ull << i);
      const std::size_t m = 128, n = dist(rd);
      // const std::size_t m = 128, n = 16'777'216ull; // 2^24
      std::vector<ENCRYPTO::AlignedBitVector> vectors(m);

      for (auto j = 0ull; j < m; ++j) {
        vectors.at(j) = ENCRYPTO::AlignedBitVector::Random(n);
      }

      const ENCRYPTO::BitMatrix bm(vectors);
      auto bm_transposed = bm;
      bm_transposed.Transpose128Rows();

      for (auto column_i = 0ull; column_i < n; ++column_i) {
        for (auto row_i = 0ull; row_i < m; ++row_i) {
          ASSERT_EQ(bm.Get(row_i, column_i), bm_transposed.Get(column_i, row_i));
        }
      }
    }
  }
}

TEST(BitMatrix, Transpose128InPlaceOnRawPointers) {
  for (auto test_iterations = 0ull; test_iterations < TEST_ITERATIONS; ++test_iterations) {
    for (auto i = 7ull; i < 15u; ++i) {
      const std::size_t m = 128, n = 1ull << i;
      // const std::size_t m = 128, n = 16'777'216ull; // 2^24
      std::vector<ENCRYPTO::AlignedBitVector> vectors(m);

      for (auto j = 0ull; j < m; ++j) {
        vectors.at(j) = ENCRYPTO::AlignedBitVector::Random(n);
      }

      ENCRYPTO::BitMatrix bm(vectors);
      bm.Transpose128Rows();

      std::array<std::byte *, 128> ptrs;
      for (auto j = 0u; j < ptrs.size(); ++j) {
        ptrs.at(j) = vectors.at(j).GetMutableData().data();
      }
      ENCRYPTO::BitMatrix::Transpose128RowsInplace(ptrs, n);

      std::vector<ENCRYPTO::AlignedBitVector> vectors_tr;
      constexpr auto bits_in_blk = m * m;
      for (auto j = 0ull; j < n * m; j += m) {
        const auto residue = j % bits_in_blk;
        const auto row_i = residue / m;
        const auto blk_offset = (16 * (j / bits_in_blk));
        auto ptr = ptrs.at(row_i) + blk_offset;
        vectors_tr.emplace_back(ptr, m);
      }

      assert(vectors_tr.size() == n);

      ENCRYPTO::BitMatrix bm_tr(vectors_tr);

      ASSERT_TRUE(bm == bm_tr);
    }
  }
}

TEST(BitMatrix, Transpose128InPlaceOnRawPointersBitSlicing) {
  for (auto test_iterations = 0ull; test_iterations < TEST_ITERATIONS; ++test_iterations) {
    for (auto i = 7ull; i < 15u; ++i) {
      const std::size_t m = 128, n = 1ull << i;
      // const std::size_t m = 128, n = 16'777'216ull; // 2^24
      std::vector<ENCRYPTO::AlignedBitVector> vectors(m);

      for (auto j = 0ull; j < m; ++j) {
        vectors.at(j) = ENCRYPTO::AlignedBitVector::Random(n);
      }

      ENCRYPTO::BitMatrix bm(vectors);
      bm.Transpose128Rows();

      std::array<std::byte *, 128> ptrs;
      for (auto j = 0u; j < ptrs.size(); ++j) {
        ptrs.at(j) = vectors.at(j).GetMutableData().data();
      }
      ENCRYPTO::BitMatrix::TransposeUsingBitSlicing(ptrs, n);

      std::vector<ENCRYPTO::AlignedBitVector> vectors_tr;
      constexpr auto bits_in_blk = m * m;
      for (auto j = 0ull; j < n * m; j += m) {
        const auto residue = j % bits_in_blk;
        const auto row_i = residue / m;
        const auto blk_offset = (16 * (j / bits_in_blk));
        auto ptr = ptrs.at(row_i) + blk_offset;
        vectors_tr.emplace_back(ptr, m);
      }

      assert(vectors_tr.size() == n);

      ENCRYPTO::BitMatrix bm_tr(vectors_tr);

      ASSERT_TRUE(bm == bm_tr);
    }
  }
}  // namespace
}  // namespace
