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

#include <numeric>
#include <random>

#include <gtest/gtest.h>

#include "utility/bit_vector.h"

#include "test_constants.h"

namespace {

TEST(BitVector, Constructors) {
  {
    auto bit_vector = encrypto::motion::BitVector<>();
    EXPECT_EQ(bit_vector.GetSize(), 0);
  }
  {
    auto bit_vector = encrypto::motion::BitVector<>(1, true);
    EXPECT_EQ(bit_vector.GetSize(), 1);
    EXPECT_EQ(bit_vector.Get(0), true);
  }
}

TEST(BitVector, Random) {
  {
    std::vector<encrypto::motion::BitVector<>> bit_vectors;
    std::generate_n(std::back_inserter(bit_vectors), 100,
                    [] { return encrypto::motion::BitVector<>::SecureRandom(1); });
    auto all_size_1 = std::all_of(std::begin(bit_vectors), std::end(bit_vectors),
                                  [](auto bit_vector) { return bit_vector.GetSize() == 1; });
    EXPECT_TRUE(all_size_1);
    // all bits should be zero with very low probability
    auto all_zeros = std::all_of(std::begin(bit_vectors), std::end(bit_vectors),
                                 [](auto bit_vector) { return bit_vector.Get(0) == 0; });
    EXPECT_FALSE(all_zeros);
  }
  {
    auto bit_vector = encrypto::motion::BitVector<>::SecureRandom(120);
    EXPECT_EQ(bit_vector.GetSize(), 120);
    auto v = bit_vector.GetData();
    // all bits should be zero with very low probability
    bool all_zeros =
        std::all_of(std::begin(v), std::end(v), [](auto byte) { return byte == std::byte(0x00); });
    EXPECT_FALSE(all_zeros);
  }
  {
    auto bit_vector = encrypto::motion::BitVector<>::SecureRandom(128);
    EXPECT_EQ(bit_vector.GetSize(), 128);
    auto v = bit_vector.GetData();
    // all bits should be zero with very low probability
    bool all_zeros =
        std::all_of(std::begin(v), std::end(v), [](auto byte) { return byte == std::byte(0x00); });
    EXPECT_FALSE(all_zeros);
  }
}

TEST(BitVector, OutOfBoundsException) {
  std::mt19937_64 mersenne_twister(0);
  for (auto test_iterations = 0ull; test_iterations < kTestIterations; ++test_iterations) {
    for (auto i = 0ull, j = 1ull; i < 20u; ++i) {
      std::uniform_int_distribution<std::uint64_t> distribution(0ul, 1'000'000ul);

      auto should_throw_set = [&](std::size_t size) {
        encrypto::motion::BitVector<> bit_vector(size);
        bit_vector.Set(true, size + distribution(mersenne_twister));
      };

      auto should_throw_get = [&](std::size_t size) {
        encrypto::motion::BitVector<> bit_vector(size);
        bit_vector.Set(true, size + distribution(mersenne_twister));
      };

      ASSERT_ANY_THROW(should_throw_set(j));
      ASSERT_ANY_THROW(should_throw_get(j));

      j <<= 1;
    }
  }
}

TEST(BitVector, SingleBitOperations) {
  std::mt19937_64 mersenne_twister(0);
  for (auto test_iterations = 0ull; test_iterations < kTestIterations; ++test_iterations) {
    encrypto::motion::BitVector<> bit_vector(1);
    ASSERT_FALSE(bit_vector.Get(0));

    bit_vector.Set(true, 0);
    ASSERT_TRUE(bit_vector.Get(0));

    bit_vector.Set(false, 0);
    ASSERT_FALSE(bit_vector.Get(0));

    std::uniform_int_distribution<std::uint64_t> distribution(0ul, 1'000'000ul);
    std::size_t size = distribution(mersenne_twister);

    bit_vector.Resize(size, true);

    for (auto i = 0ull; i < 1000u; ++i) {
      std::size_t position0 = distribution(mersenne_twister) % size;
      std::size_t position1 = distribution(mersenne_twister) % size;
      while (position0 == position1) {
        position1 = distribution(mersenne_twister) % size;
      }

      bit_vector.Set(true, position0);
      ASSERT_TRUE(bit_vector.Get(position0));
      ASSERT_TRUE(bit_vector[position0]);
      bit_vector.Set(true, position1);
      ASSERT_TRUE(bit_vector.Get(position1));
      ASSERT_TRUE(bit_vector[position1]);

      bit_vector.Set(false, position0);
      ASSERT_FALSE(bit_vector.Get(position0));
      ASSERT_FALSE(bit_vector[position0]);
      bit_vector.Set(false, position1);
      ASSERT_FALSE(bit_vector.Get(position1));
      ASSERT_FALSE(bit_vector[position0]);
    }
  }
}

TEST(BitVector, AllBitsOperations) {
  std::mt19937_64 mersenne_twister(0);
  for (auto test_iterations = 0ull; test_iterations < kTestIterations; ++test_iterations) {
    for (auto size = 1ull; size <= 1'000'000u; size *= 10) {
      encrypto::motion::BitVector<> bit_vector(size);
      bit_vector.Set(true);

      ASSERT_TRUE(bit_vector.Get(0));
      ASSERT_TRUE(bit_vector.Get(bit_vector.GetSize() - 1));

      std::uniform_int_distribution<std::uint64_t> distribution(0, size);
      for (auto i = 0ull; i < 100u && i < size; ++i) {
        auto position = distribution(mersenne_twister) % bit_vector.GetSize();
        ASSERT_TRUE(bit_vector.Get(position));
      }

      bit_vector.Set(false);

      ASSERT_FALSE(bit_vector.Get(0));
      ASSERT_FALSE(bit_vector.Get(bit_vector.GetSize() - 1));

      for (auto i = 0ull; i < 100u && i < size; ++i) {
        auto position = distribution(mersenne_twister) % bit_vector.GetSize();
        ASSERT_FALSE(bit_vector.Get(position));
      }
    }
  }
}

TEST(BitVector, VectorVectorOperations) {
  std::mt19937_64 mersenne_twister(0);
  for (auto test_iterations = 0ull; test_iterations < kTestIterations; ++test_iterations) {
    for (auto size = 1ull; size <= 100'000u; size *= 10) {
      encrypto::motion::BitVector<> bit_vector0(size);
      encrypto::motion::BitVector<> bit_vector1(size);

      std::vector<bool> vector0(size, false), vector1(size, false), result_and(size, false),
          result_xor(size, false), result_or(size, false);
      std::uniform_int_distribution<uint64_t> distribution(0, 1);

      for (auto i = 0ull; i < size; ++i) {
        vector0.at(i) = distribution(mersenne_twister);
        vector1.at(i) = distribution(mersenne_twister);

        bit_vector0.Set(vector0.at(i), i);
        bit_vector1.Set(vector1.at(i), i);

        result_and.at(i) = vector0.at(i) & vector1.at(i);
        result_xor.at(i) = vector0.at(i) ^ vector1.at(i);
        result_or.at(i) = vector0.at(i) | vector1.at(i);
      }

      encrypto::motion::BitVector<> bit_vector_and = bit_vector0 & bit_vector1;
      encrypto::motion::BitVector<> bit_vector_xor = bit_vector0 ^ bit_vector1;
      encrypto::motion::BitVector<> bit_vector_or = bit_vector0 | bit_vector1;

      for (auto i = 0ull; i < size; ++i) {
        ASSERT_TRUE(result_and.at(i) == bit_vector_and.Get(i));
        ASSERT_TRUE(result_xor.at(i) == bit_vector_xor.Get(i));
        ASSERT_TRUE(result_or.at(i) == bit_vector_or.Get(i));
      }

      auto bit_vector_and_old = bit_vector_and;
      bit_vector_and &= bit_vector_and;

      bit_vector_xor ^= bit_vector_xor;
      encrypto::motion::BitVector<> bit_vector_zero(bit_vector_xor.GetSize(), false);

      auto bit_vector_or_old = bit_vector_or;
      bit_vector_or |= bit_vector_or;

      ASSERT_TRUE(bit_vector_and_old == bit_vector_and);
      ASSERT_TRUE(bit_vector_xor == bit_vector_zero);
      ASSERT_TRUE(bit_vector_or_old == bit_vector_or);

      auto bit_vector0_copy = bit_vector0;
      std::uniform_int_distribution<uint64_t> distribution_size(0, bit_vector0_copy.GetSize() - 1);
      for (auto i = 0ull; i < 10; ++i) {
        auto position = distribution_size(mersenne_twister);
        bool value = bit_vector0_copy.Get(position);

        ASSERT_TRUE(bit_vector0 == bit_vector0_copy);
        bit_vector0_copy.Set(!value, position);
        ASSERT_FALSE(bit_vector0 == bit_vector0_copy);
        bit_vector0_copy.Set(value, position);
        ASSERT_TRUE(bit_vector0 == bit_vector0_copy);
      }
    }
  }
}

TEST(BitVector, AndReduce) {
  for (auto size : {0, 1, 2, 15, 16, 17, 64, 65, 100}) {
    encrypto::motion::BitVector<> bit_vector(size, true);
    auto result = encrypto::motion::BitVector<>::AndReduceBitVector(bit_vector);
    EXPECT_TRUE(result);
  }
}

TEST(BitVector, Append) {
  std::mt19937_64 mersenne_twister(0);
  for (auto test_i = 0ull; test_i < kTestIterations; ++test_i) {
    std::vector<std::size_t> sizes;
    for (auto i = 1; i < 20; ++i) {
      sizes.push_back(i);
    }
    for (auto i = 128ull; i < 10'000; i *= 2) {
      sizes.push_back(i);
    }
    for (auto size : sizes) {
      std::uniform_int_distribution<uint64_t> distribution_number_of_vectors(2, 20);

      std::vector<std::vector<bool>> stl_vectors(distribution_number_of_vectors(mersenne_twister));
      std::vector<encrypto::motion::BitVector<>> bit_vectors(stl_vectors.size());

      std::uniform_int_distribution<uint64_t> distribution(0, 1);

      for (auto j = 0ull; j < stl_vectors.size(); ++j) {
        for (auto i = 0ull; i < size; ++i) {
          stl_vectors.at(j).push_back(distribution(mersenne_twister));
          bit_vectors.at(j).Append(stl_vectors.at(j).at(i));
          ASSERT_EQ(stl_vectors.at(j).at(i), bit_vectors.at(j).Get(i));
        }
      }

      std::vector<bool> stl_vector_result;
      encrypto::motion::BitVector<> bit_vector_result;

      for (auto i = 0ull; i < stl_vectors.size(); ++i) {
        stl_vector_result.insert(stl_vector_result.end(), stl_vectors.at(i).begin(),
                                 stl_vectors.at(i).end());
        bit_vector_result.Append(bit_vectors.at(i));
      }

      for (auto i = 0ull; i < stl_vector_result.size(); ++i) {
        ASSERT_EQ(stl_vector_result.at(i), bit_vector_result.Get(i));
      }

      ASSERT_EQ(stl_vector_result.size(), bit_vector_result.GetSize());
    }
  }
}

TEST(BitVector, Subset) {
  std::mt19937_64 mersenne_twister(0);
  for (std::size_t test_i = 0; test_i < kTestIterations; ++test_i) {
    std::vector<std::size_t> sizes;
    for (auto i = 1; i < 20; ++i) {
      sizes.push_back(i);
    }

    for (auto i = 4ull; i < 100'000; i *= 2) {
      sizes.push_back(i);
    }
    for (auto i : sizes) {
      std::vector<bool> stl_vector(i);
      encrypto::motion::BitVector<> bit_vector(i);

      std::uniform_int_distribution<uint64_t> distribution_from(0, i / 2);
      std::uniform_int_distribution<uint64_t> distribution_to(i / 2, i - 1);
      std::uniform_int_distribution<uint64_t> distribution_bool(0, 1);

      for (auto j = 0ull; j < stl_vector.size(); ++j) {
        stl_vector.at(j) = distribution_bool(mersenne_twister);
        bit_vector.Set(stl_vector.at(j), j);
      }

      auto from = distribution_from(mersenne_twister);
      auto to = distribution_to(mersenne_twister);

      std::vector<bool> stl_vector_subset(stl_vector.begin() + from, stl_vector.begin() + to);
      encrypto::motion::BitVector<> bit_vector_subset = bit_vector.Subset(from, to);

      for (auto j = 0ull; j < stl_vector_subset.size(); ++j) {
        ASSERT_EQ(stl_vector_subset.at(j), bit_vector_subset.Get(j));
      }

      ASSERT_EQ(stl_vector_subset.size(), bit_vector_subset.GetSize());
    }
  }
}

TEST(BitVector, AppendSubset) {
  std::mt19937_64 mersenne_twister(0);
  for (std::size_t test_i = 0; test_i < kTestIterations; ++test_i) {
    std::vector<std::size_t> sizes;
    for (auto i = 1; i < 20; ++i) {
      sizes.push_back(i);
    }
    for (auto i = 128ull; i < 10'000; i *= 2) {
      sizes.push_back(i);
    }
    for (auto size : sizes) {
      std::vector<bool> stl_vector_result;
      encrypto::motion::BitVector<> bit_vector_result;
      for (auto subset_i = 0ull; subset_i < 20u; ++subset_i) {
        std::vector<bool> stl_vector(size);
        encrypto::motion::BitVector<> bit_vector(size);

        std::uniform_int_distribution<uint64_t> distribution_from(0, size / 2);
        std::uniform_int_distribution<uint64_t> distribution_to(size / 2, size - 1);
        std::uniform_int_distribution<uint64_t> distribution_bool(0, 1);

        for (auto j = 0ull; j < stl_vector.size(); ++j) {
          stl_vector.at(j) = distribution_bool(mersenne_twister);
          bit_vector.Set(stl_vector.at(j), j);
        }

        auto from = distribution_from(mersenne_twister);
        auto to = distribution_to(mersenne_twister);

        std::vector<bool> stl_vector_subset(stl_vector.begin() + from, stl_vector.begin() + to);
        encrypto::motion::BitVector<> bit_vector_subset = bit_vector.Subset(from, to);

        for (auto j = 0ull; j < stl_vector_subset.size(); ++j) {
          ASSERT_EQ(stl_vector_subset.at(j), bit_vector_subset.Get(j));
        }

        stl_vector_result.insert(stl_vector_result.end(), stl_vector_subset.begin(),
                                 stl_vector_subset.end());
        bit_vector_result.Append(bit_vector_subset);
      }

      for (auto j = 0ull; j < stl_vector_result.size(); ++j) {
        ASSERT_EQ(stl_vector_result.at(j), bit_vector_result.Get(j));
      }
    }
  }
}

TEST(BitVector, AppendSpan) {
  std::mt19937_64 mersenne_twister(0);
  for (std::size_t test_i = 0; test_i < kTestIterations; ++test_i) {
    std::vector<std::size_t> sizes;
    for (auto i = 1; i < 20; ++i) {
      sizes.push_back(i);
    }
    for (auto i = 128ull; i < 10'000; i *= 2) {
      sizes.push_back(i);
    }
    for (auto size : sizes) {
      std::uniform_int_distribution<uint64_t> distribution_number_of_vectors(2, 20);

      std::vector<std::vector<bool>> stl_vectors(distribution_number_of_vectors(mersenne_twister));
      std::vector<encrypto::motion::BitVector<>> bit_vectors(stl_vectors.size());

      std::uniform_int_distribution<uint64_t> distribution(0, 1);

      for (auto j = 0ull; j < stl_vectors.size(); ++j) {
        for (auto i = 0ull; i < size; ++i) {
          stl_vectors.at(j).push_back(distribution(mersenne_twister));
          bit_vectors.at(j).Append(stl_vectors.at(j).at(i));
          ASSERT_EQ(stl_vectors.at(j).at(i), bit_vectors.at(j).Get(i));
        }
      }

      std::vector<bool> stl_vector_result;
      encrypto::motion::BitVector<> bit_vector_result;

      for (auto i = 0ull; i < stl_vectors.size(); ++i) {
        stl_vector_result.insert(stl_vector_result.end(), stl_vectors.at(i).begin(),
                                 stl_vectors.at(i).end());
        bit_vector_result.Append(encrypto::motion::BitSpan(bit_vectors.at(i)));
      }

      for (auto i = 0ull; i < stl_vector_result.size(); ++i) {
        ASSERT_EQ(stl_vector_result.at(i), bit_vector_result.Get(i));
      }

      ASSERT_EQ(stl_vector_result.size(), bit_vector_result.GetSize());
    }
  }
}

TEST(BitVector, Copy) {
  std::mt19937_64 mersenne_twister(0);
  for (std::size_t test_i = 0; test_i < kTestIterations; ++test_i) {
    const std::size_t size = 1'000'000;
    std::vector<bool> stl_vector(size, false);
    encrypto::motion::BitVector<> bit_vector(size, false);
    std::vector<std::size_t> sizes;
    for (auto i = 1; i < 20; ++i) {
      sizes.push_back(i);
    }

    for (auto i = 4ull; i < 100'000; i *= 2) {
      sizes.push_back(i);
    }

    for (auto i : sizes) {
      std::vector<bool> temporary_stl_vector(i);
      encrypto::motion::BitVector<> temporary_bit_vector(i);

      std::uniform_int_distribution<uint64_t> distribution_from(0, size - i);
      std::uniform_int_distribution<uint64_t> distribution_to(0, i - 1);
      std::uniform_int_distribution<uint64_t> distribution_bool(0, 1);

      for (auto j = 0ull; j < temporary_stl_vector.size(); ++j) {
        temporary_stl_vector.at(j) = distribution_bool(mersenne_twister);
        temporary_bit_vector.Set(temporary_stl_vector.at(j), j);
      }

      auto from = distribution_from(mersenne_twister);
      auto to = from + distribution_to(mersenne_twister);

      std::copy(temporary_stl_vector.begin(), temporary_stl_vector.begin() + to - from,
                stl_vector.begin() + from);
      bit_vector.Copy(from, to, temporary_bit_vector);
    }
    for (auto j = 0ull; j < stl_vector.size(); ++j) {
      EXPECT_EQ(stl_vector.at(j), bit_vector.Get(j));
    }
  }
}

TEST(BitSpan, SingleBitOperations) {
  std::mt19937_64 mersenne_twister(0);
  for (std::size_t test_i = 0; test_i < kTestIterations; ++test_i) {
    encrypto::motion::BitVector<> bit_vector1(1);
    encrypto::motion::BitSpan bit_span1(bit_vector1);
    ASSERT_FALSE(bit_span1.Get(0));

    bit_span1.Set(true, 0);
    ASSERT_TRUE(bit_span1.Get(0));

    bit_span1.Set(false, 0);
    ASSERT_FALSE(bit_span1.Get(0));

    ASSERT_EQ(bit_vector1, bit_span1);

    std::uniform_int_distribution<std::uint64_t> distribution(0ul, 1'000'000ul);
    std::size_t size = distribution(mersenne_twister);

    encrypto::motion::BitVector<> bit_vector(size);
    encrypto::motion::BitSpan bit_span(bit_vector);
    encrypto::motion::BitVector<> bit_vector_check(size);

    for (auto i = 0ull; i < 1000u; ++i) {
      std::size_t position0 = distribution(mersenne_twister) % size;
      std::size_t position1 = distribution(mersenne_twister) % size;
      while (position0 == position1) {
        position1 = distribution(mersenne_twister) % size;
      }

      bit_span.Set(true, position0);
      ASSERT_TRUE(bit_span[position0]);
      bit_span.Set(false, position1);
      ASSERT_FALSE(bit_span[position1]);
      bit_vector_check.Set(true, position0);
      bit_vector_check.Set(false, position1);
    }

    ASSERT_EQ(bit_span, bit_vector);
    ASSERT_EQ(bit_span, bit_vector_check);
  }
}

TEST(BitSpan, AllBitsOperations) {
  for (auto size = 1ull; size <= 1'000'000u; size *= 10) {
    encrypto::motion::BitVector<> bit_vector(size);
    encrypto::motion::BitSpan bit_span(bit_vector);
    auto bit_vector_check = bit_vector;

    bit_span.Set(true);
    bit_vector_check.Set(true);

    ASSERT_EQ(bit_span, bit_vector);
    ASSERT_EQ(bit_span, bit_vector_check);

    bit_span.Set(false);
    bit_vector_check.Set(false);

    ASSERT_EQ(bit_span, bit_vector);
    ASSERT_EQ(bit_span, bit_vector_check);
  }
}

TEST(BitSpan, SpanSpanOperations) {
  for (std::size_t test_i = 0; test_i < kTestIterations; ++test_i) {
    for (auto size = 1ull; size <= 100'000u; size *= 10) {
      auto bit_vector0(encrypto::motion::BitVector<>::RandomSeeded(size, size));
      auto bit_vector1(encrypto::motion::BitVector<>::RandomSeeded(size, size * 2));
      encrypto::motion::BitSpan bit_span0{bit_vector0};
      encrypto::motion::BitSpan bit_span1{bit_vector1};

      encrypto::motion::BitVector<> bit_vector_and = bit_vector0 & bit_vector1;
      encrypto::motion::BitVector<> bit_vector_or = bit_vector0 | bit_vector1;
      encrypto::motion::BitVector<> bit_vector_xor = bit_vector0 ^ bit_vector1;

      encrypto::motion::BitVector<> bit_vector_check;
      encrypto::motion::BitSpan bit_span_check;

      ASSERT_EQ(bit_vector_and, bit_span0 & bit_span1);
      ASSERT_EQ(bit_vector_and, bit_span0 & bit_vector1);
      ASSERT_EQ(bit_vector_and, bit_vector0 & bit_span1);

      bit_vector_check = bit_vector0;
      bit_vector_check &= bit_span1;
      ASSERT_EQ(bit_vector_and, bit_vector_check);
      bit_vector_check = bit_vector1;
      bit_vector_check &= bit_span0;
      ASSERT_EQ(bit_vector_and, bit_vector_check);
      bit_vector_check = bit_vector0;
      bit_span_check = bit_vector_check;
      bit_span_check &= bit_vector1;
      ASSERT_EQ(bit_vector_and, bit_span_check);
      bit_vector_check = bit_vector0;
      bit_span_check = bit_vector_check;
      bit_span_check &= bit_span1;
      ASSERT_EQ(bit_vector_and, bit_span_check);

      ASSERT_EQ(bit_vector_or, bit_span0 | bit_span1);
      ASSERT_EQ(bit_vector_or, bit_span0 | bit_vector1);
      ASSERT_EQ(bit_vector_or, bit_vector0 | bit_span1);

      bit_vector_check = bit_vector0;
      bit_vector_check |= bit_span1;
      ASSERT_EQ(bit_vector_or, bit_vector_check);
      bit_vector_check = bit_vector1;
      bit_vector_check |= bit_span0;
      ASSERT_EQ(bit_vector_or, bit_vector_check);
      bit_vector_check = bit_vector0;
      bit_span_check = bit_vector_check;
      bit_span_check |= bit_vector1;
      ASSERT_EQ(bit_vector_or, bit_span_check);
      bit_vector_check = bit_vector0;
      bit_span_check = bit_vector_check;
      bit_span_check |= bit_span1;
      ASSERT_EQ(bit_vector_or, bit_span_check);

      ASSERT_EQ(bit_vector_xor, bit_span0 ^ bit_span1);
      ASSERT_EQ(bit_vector_xor, bit_span0 ^ bit_vector1);
      ASSERT_EQ(bit_vector_xor, bit_vector0 ^ bit_span1);

      bit_vector_check = bit_vector0;
      bit_vector_check ^= bit_span1;
      ASSERT_EQ(bit_vector_xor, bit_vector_check);
      bit_vector_check = bit_vector1;
      bit_vector_check ^= bit_span0;
      ASSERT_EQ(bit_vector_xor, bit_vector_check);
      bit_vector_check = bit_vector0;
      bit_span_check = bit_vector_check;
      bit_span_check ^= bit_vector1;
      ASSERT_EQ(bit_vector_xor, bit_span_check);
      bit_vector_check = bit_vector0;
      bit_span_check = bit_vector_check;
      bit_span_check ^= bit_span1;
      ASSERT_EQ(bit_vector_xor, bit_span_check);

      ASSERT_EQ(~bit_vector_xor, ~bit_span_check);
    }
  }
}

TEST(BitSpan, Subset) {
  auto should_throw_function = []() { encrypto::motion::BitSpan().Subset(0, 1); };
  ASSERT_THROW(should_throw_function(), std::out_of_range);

  std::mt19937_64 mersenne_twister(1);

  for (auto i = 0ull; i < 10; ++i) {
    std::uniform_int_distribution<std::uint64_t> distribution_size(0, 10'000);
    const auto bit_size{distribution_size(mersenne_twister)};
    std::uniform_int_distribution<std::uint64_t> distribution_from(0, bit_size);
    const auto from{distribution_from(mersenne_twister)};
    std::uniform_int_distribution<std::uint64_t> distribution_to(from, bit_size);
    const auto to{distribution_to(mersenne_twister)};

    encrypto::motion::BitVector<> bit_vector(bit_size);
    encrypto::motion::BitSpan bit_span(bit_vector);

    ASSERT_EQ(bit_vector.Subset(from, to), bit_span.Subset(from, to));
  }
}

TEST(BitSpan, Copy) {
  std::mt19937_64 mersenne_twister(0);
  for (std::size_t test_i = 0; test_i < kTestIterations; ++test_i) {
    const std::size_t size = 1'000'000;
    encrypto::motion::BitVector<> bit_vector_buffer0(size, false);
    encrypto::motion::BitVector<> bit_vector_buffer1(size, false);
    encrypto::motion::BitVector<> bit_vector_check(size, false);

    encrypto::motion::BitSpan bit_span0(bit_vector_buffer0);
    encrypto::motion::BitSpan bit_span1(bit_vector_buffer1);

    std::vector<std::size_t> sizes;
    for (auto i = 1; i < 20; ++i) {
      sizes.push_back(i);
    }

    for (auto i = 4ull; i < 100'000; i *= 2) {
      sizes.push_back(i);
    }

    for (auto i : sizes) {
      encrypto::motion::BitVector<> temporary_bit_vector(i);

      std::uniform_int_distribution<uint64_t> distribution_from(0, size - i);
      std::uniform_int_distribution<uint64_t> distribution_to(0, i - 1);
      std::uniform_int_distribution<uint64_t> distribution_bool(0, 1);

      for (auto j = 0ull; j < i; ++j)
        temporary_bit_vector.Set(distribution_bool(mersenne_twister), j);

      const auto from = distribution_from(mersenne_twister);
      const auto to = from + distribution_to(mersenne_twister);

      bit_vector_check.Copy(from, to, temporary_bit_vector);
      bit_span0.Copy(from, to, temporary_bit_vector);
      bit_span1.Copy(from, to, encrypto::motion::BitSpan(temporary_bit_vector));
      EXPECT_EQ(bit_span0, bit_vector_check);
      EXPECT_EQ(bit_span1, bit_vector_check);
    }
  }
}

TEST(BitVectorAndSpan, HammingWeight) {
  std::mt19937_64 mersenne_twister(0);
  for (std::size_t size = 0; size < 100; ++size) {
    encrypto::motion::BitVector<> bit_vector(size);
    std::vector<bool> vector(size, false);
    std::uniform_int_distribution<uint64_t> distribution(0, 1);
    for (std::size_t i = 0; i < size; ++i) {
      vector.at(i) = distribution(mersenne_twister);
      bit_vector.Set(vector.at(i), i);
    }

    encrypto::motion::BitSpan bit_span(bit_vector);

    std::size_t expected_hw{std::accumulate(
        vector.begin(), vector.end(), std::size_t(0),
        [](std::size_t counter, bool bit) { return counter + static_cast<std::size_t>(bit); })};

    ASSERT_EQ(bit_vector.HammingWeight(), expected_hw);
    ASSERT_EQ(bit_span.HammingWeight(), expected_hw);

    for (std::size_t j = 0; j < size; ++j) {
      std::size_t expected_subspan_hw{std::accumulate(
          vector.begin(), vector.begin() + j, std::size_t(0),
          [](std::size_t counter, bool bit) { return counter + static_cast<std::size_t>(bit); })};
      encrypto::motion::BitSpan bit_subspan(bit_vector.GetMutableData().data(), j);
      ASSERT_EQ(bit_subspan.HammingWeight(), expected_subspan_hw);
    }
  }
}
}  // namespace
