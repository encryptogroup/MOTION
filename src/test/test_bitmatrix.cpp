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
  for (auto test_iterations = 0ull; test_iterations < kTestIterations; ++test_iterations) {
    for (auto i = 0ull; i < 11u; ++i) {
      std::random_device random_generator;
      std::uniform_int_distribution<std::uint64_t> distribution(0, 1ull << i);

      const std::size_t m = distribution(random_generator), n = distribution(random_generator);
      // const std::size_t m = 128, n = 16'777'216ull;
      // const  std::size_t m = 16'777'216ull, n = 128;
      std::vector<encrypto::motion::AlignedBitVector> vectors(m);

      for (auto j = 0ull; j < m; ++j) {
        vectors.at(j) = encrypto::motion::AlignedBitVector::SecureRandom(n);
      }

      encrypto::motion::BitMatrix bit_matrix(vectors);
      auto bit_matrix_transposed = bit_matrix;
      bit_matrix_transposed.Transpose();

      for (auto column_i = 0ull; column_i < n; ++column_i) {
        for (auto row_i = 0ull; row_i < m; ++row_i) {
          ASSERT_EQ(bit_matrix.Get(row_i, column_i), bit_matrix_transposed.Get(column_i, row_i));
        }
      }
    }
  }
}

// XXX: adjust to little endian encoding in BitVector or remove, since we can use other methods via
// simde
/*
TEST(BitMatrix, Transpose128) {
  for (auto test_iterations = 0ull; test_iterations < kTestIterations; ++test_iterations) {
    for (auto i = 7ull; i < 15u; ++i) {
      std::random_device random_generator;
      std::uniform_int_distribution<std::uint64_t> distribution(1, 1ull << i);
      const std::size_t m = 128, n = distribution(random_generator);
      // const std::size_t m = 128, n = 16'777'216ull; // 2^24
      std::vector<encrypto::motion::AlignedBitVector> vectors(m);
      for (auto j = 0ull; j < m; ++j) {
        vectors.at(j) = encrypto::motion::AlignedBitVector::SecureRandom(n);
      }
      const encrypto::motion::BitMatrix bit_matrix(vectors);
      auto bit_matrix_transposed = bit_matrix;
      bit_matrix_transposed.Transpose128Rows();
      for (auto column_i = 0ull; column_i < n; ++column_i) {
        for (auto row_i = 0ull; row_i < m; ++row_i) {
          ASSERT_EQ(bit_matrix.Get(row_i, column_i), bit_matrix_transposed.Get(column_i, row_i));
        }
      }
    }
  }
}
 */

TEST(BitMatrix, DISABLED_Transpose128InPlaceOnRawPointers) {
  constexpr std::size_t kM = 128;
  constexpr auto kBitsInBlock = kM * kM;
  for (auto test_iterations = 0ull; test_iterations < kTestIterations; ++test_iterations) {
    for (auto i = 7ull; i < 15u; ++i) {
      const std::size_t n = 1ull << i;
      std::vector<encrypto::motion::AlignedBitVector> vectors(kM);

      for (auto j = 0ull; j < kM; ++j) {
        vectors.at(j) = encrypto::motion::AlignedBitVector::SecureRandom(n);
      }

      encrypto::motion::BitMatrix bit_matrix(vectors);
      bit_matrix.Transpose128Rows();

      std::array<std::byte*, 128> pointers;
      for (auto j = 0u; j < pointers.size(); ++j) {
        pointers.at(j) = vectors.at(j).GetMutableData().data();
      }
      encrypto::motion::BitMatrix::Transpose128RowsInplace(pointers, n);

      std::vector<encrypto::motion::AlignedBitVector> vectors_test_result;
      for (auto j = 0ull; j < n * kM; j += kM) {
        const auto residue = j % kBitsInBlock;
        const auto row_i = residue / kM;
        const auto block_offset = (16 * (j / kBitsInBlock));
        auto pointer = pointers.at(row_i) + block_offset;
        vectors_test_result.emplace_back(pointer, kM);
      }

      assert(vectors_test_result.size() == n);

      encrypto::motion::BitMatrix bit_matrix_test_result(vectors_test_result);

      ASSERT_TRUE(bit_matrix == bit_matrix_test_result);
    }
  }
}

// XXX: adjust to little endian encoding in BitVector or remove, since we can use other methods via
// simde
/*
TEST(BitMatrix, Transpose128InPlaceOnRawPointersBitSlicing) {
  constexpr std::size_t kM = 128;
  constexpr auto kBitsInBlock = kM * kM;
  for (auto test_iterations = 0ull; test_iterations < kTestIterations; ++test_iterations) {
    for (auto i = 7ull; i < 15u; ++i) {
      const std::size_t n = 1ull << i;
      std::vector<encrypto::motion::AlignedBitVector> vectors(kM);
      for (auto j = 0ull; j < kM; ++j) {
        vectors.at(j) = encrypto::motion::AlignedBitVector::SecureRandom(n);
      }
      encrypto::motion::BitMatrix bit_matrix(vectors);
      bit_matrix.Transpose128Rows();
      std::array<std::byte*, 128> pointers;
      for (auto j = 0u; j < pointers.size(); ++j) {
        pointers.at(j) = vectors.at(j).GetMutableData().data();
      }
      encrypto::motion::BitMatrix::TransposeUsingBitSlicing(pointers, n);
      std::vector<encrypto::motion::AlignedBitVector> vectors_test_result;
      for (auto j = 0ull; j < n * kM; j += kM) {
        const auto residue = j % kBitsInBlock;
        const auto row_i = residue / kM;
        const auto block_offset = (16 * (j / kBitsInBlock));
        auto pointer = pointers.at(row_i) + block_offset;
        vectors_test_result.emplace_back(pointer, kM);
      }
      assert(vectors_test_result.size() == n);
      encrypto::motion::BitMatrix bm_test_result(vectors_test_result);
      ASSERT_EQ(bit_matrix, bm_test_result);
    }
  }
}*/

}  // namespace
