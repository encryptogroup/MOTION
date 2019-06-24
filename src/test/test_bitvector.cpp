#include <random>

#include <gtest/gtest.h>

#include "utility/bit_vector.h"

#include "test_constants.h"

namespace {
TEST(BitVector, OutOfBoundsException) {
  for (auto test_iterations = 0ull; test_iterations < TEST_ITERATIONS; ++test_iterations) {
    for (auto i = 0ull, j = 1ull; i < 20; ++i) {
      std::random_device rd;
      std::uniform_int_distribution<std::uint64_t> dist(0ul, 1000000ul);

      auto should_throw_set = [&](std::size_t size) {
        ENCRYPTO::BitVector bv(size);
        bv.Set(true, size + dist(rd));
      };

      auto should_throw_get = [&](auto size) {
        ENCRYPTO::BitVector bv(size);
        bv.Set(true, size + dist(rd));
      };

      ASSERT_ANY_THROW(should_throw_set(j));
      ASSERT_ANY_THROW(should_throw_get(j));

      j <<= 1;
    }
  }
}

TEST(BitVector, SingleBitOperations) {
  for (auto test_iterations = 0ull; test_iterations < TEST_ITERATIONS; ++test_iterations) {
    ENCRYPTO::BitVector bv(1);
    ASSERT_FALSE(bv.Get(0));

    bv.Set(true, 0);
    ASSERT_TRUE(bv.Get(0));

    bv.Set(false, 0);
    ASSERT_FALSE(bv.Get(0));

    std::random_device rd;
    std::uniform_int_distribution<std::uint64_t> dist(0ul, 1000000ul);
    std::size_t size = dist(rd);

    bv.Resize(size);

    for (auto i = 0ull; i < 1000u; ++i) {
      std::size_t pos0 = dist(rd) % size;
      std::size_t pos1 = dist(rd) % size;
      while (pos0 == pos1) {
        pos1 = dist(rd) % size;
      }

      bv.Set(true, pos0);
      ASSERT_TRUE(bv.Get(pos0));
      ASSERT_TRUE(bv[pos0]);
      bv.Set(true, pos1);
      ASSERT_TRUE(bv.Get(pos1));
      ASSERT_TRUE(bv[pos1]);

      bv.Set(false, pos0);
      ASSERT_FALSE(bv.Get(pos0));
      ASSERT_FALSE(bv[pos0]);
      bv.Set(false, pos1);
      ASSERT_FALSE(bv.Get(pos1));
      ASSERT_FALSE(bv[pos0]);
    }
  }
}

TEST(BitVector, AllBitsOperations) {
  for (auto test_iterations = 0ull; test_iterations < TEST_ITERATIONS; ++test_iterations) {
    for (auto size = 1ull; size <= 1000000; size *= 10) {
      ENCRYPTO::BitVector bv(size);
      bv.Set(true);

      ASSERT_TRUE(bv.Get(0));
      ASSERT_TRUE(bv.Get(bv.GetSize() - 1));

      std::random_device rd("/dev/urandom");
      std::uniform_int_distribution<std::uint64_t> dist(0, size);
      for (auto i = 0ull; i < 100u && i < size; ++i) {
        auto pos = dist(rd) % bv.GetSize();
        ASSERT_TRUE(bv.Get(pos));
      }

      bv.Set(false);

      ASSERT_FALSE(bv.Get(0));
      ASSERT_FALSE(bv.Get(bv.GetSize() - 1));

      for (auto i = 0ull; i < 100u && i < size; ++i) {
        auto pos = dist(rd) % bv.GetSize();
        ASSERT_FALSE(bv.Get(pos));
      }
    }
  }
}

TEST(BitVector, VectorVectorOperations) {
  for (auto test_iterations = 0ull; test_iterations < TEST_ITERATIONS; ++test_iterations) {
    for (auto size = 1ull; size <= 100000; size *= 10) {
      ENCRYPTO::BitVector bv0(size);
      ENCRYPTO::BitVector bv1(size);

      std::vector<bool> v0(size, false), v1(size, false), result_and(size, false),
          result_xor(size, false), result_or(size, false);
      std::random_device rd("/dev/urandom");
      std::uniform_int_distribution<uint64_t> dist(0, 1);

      for (auto i = 0ull; i < size; ++i) {
        v0.at(i) = dist(rd);
        v1.at(i) = dist(rd);

        bv0.Set(v0.at(i), i);
        bv1.Set(v1.at(i), i);

        result_and.at(i) = v0.at(i) & v1.at(i);
        result_xor.at(i) = v0.at(i) ^ v1.at(i);
        result_or.at(i) = v0.at(i) | v1.at(i);
      }

      ENCRYPTO::BitVector bv_and = bv0 & bv1;
      ENCRYPTO::BitVector bv_xor = bv0 ^ bv1;
      ENCRYPTO::BitVector bv_or = bv0 | bv1;

      for (auto i = 0ull; i < size; ++i) {
        ASSERT_TRUE(result_and.at(i) == bv_and.Get(i));
        ASSERT_TRUE(result_xor.at(i) == bv_xor.Get(i));
        ASSERT_TRUE(result_or.at(i) == bv_or.Get(i));
      }

      auto bv0_copy = bv0;
      std::uniform_int_distribution<uint64_t> dist_size(0, bv0_copy.GetSize() - 1);
      for (auto i = 0ull; i < 10; ++i) {
        auto pos = dist_size(rd);
        bool value = bv0_copy.Get(pos);

        ASSERT_TRUE(bv0 == bv0_copy);
        bv0_copy.Set(!value, pos);
        ASSERT_FALSE(bv0 == bv0_copy);
        bv0_copy.Set(value, pos);
        ASSERT_TRUE(bv0 == bv0_copy);
      }
    }
  }
}  // namespace

TEST(BitVector, Append) {
  for (auto test_iterations = 0ull; test_iterations < TEST_ITERATIONS; ++test_iterations) {
    std::vector<std::size_t> sizes;
    for (auto i = 1; i < 20; ++i) {
      sizes.push_back(i);
    }
    for (auto i = 128ull; i < 10000; i *= 2) {
      sizes.push_back(i);
    }
    for (auto size : sizes) {
      std::random_device rd("/dev/urandom");
      std::uniform_int_distribution<uint64_t> dist_n_vectors(2, 20);

      std::vector<std::vector<bool>> stl_vectors(dist_n_vectors(rd));
      std::vector<ENCRYPTO::BitVector> bit_vectors(stl_vectors.size());

      std::uniform_int_distribution<uint64_t> dist(0, 1);

      for (auto j = 0ull; j < stl_vectors.size(); ++j) {
        for (auto i = 0ull; i < size; ++i) {
          stl_vectors.at(j).push_back(dist(rd));
          bit_vectors.at(j).Append(stl_vectors.at(j).at(i));
          ASSERT_EQ(stl_vectors.at(j).at(i), bit_vectors.at(j).Get(i));
        }
      }

      std::vector<bool> stl_vector_result;
      ENCRYPTO::BitVector bit_vector_result;

      for (auto i = 0ull; i < stl_vectors.size(); ++i) {
        stl_vector_result.insert(stl_vector_result.end(), stl_vectors.at(i).begin(),
                                 stl_vectors.at(i).end());
        bit_vector_result.Append(bit_vectors.at(i));
      }

      for (auto i = 0ull; i < stl_vectors.size(); ++i) {
        ASSERT_EQ(stl_vector_result.at(i), bit_vector_result.Get(i));
      }

      ASSERT_EQ(stl_vector_result.size(), bit_vector_result.GetSize());
    }
  }
}

TEST(BitVector, Subset) {
  for (auto test_iterations = 0ull; test_iterations < TEST_ITERATIONS; ++test_iterations) {
    std::vector<std::size_t> sizes;
    for (auto i = 1; i < 20; ++i) {
      sizes.push_back(i);
    }

    for (auto i = 4ull; i < 100000; i *= 2) {
      sizes.push_back(i);
    }
    for (auto i : sizes) {
      std::vector<bool> stl_vector(i);
      ENCRYPTO::BitVector bit_vector(i);

      std::random_device rd("/dev/urandom");
      std::uniform_int_distribution<uint64_t> dist_from(0, i / 2);
      std::uniform_int_distribution<uint64_t> dist_to(i / 2, i - 1);
      std::uniform_int_distribution<uint64_t> dist_bool(0, 1);

      for (auto j = 0ull; j < stl_vector.size(); ++j) {
        stl_vector.at(j) = dist_bool(rd);
        bit_vector.Set(stl_vector.at(j), j);
      }

      auto from = dist_from(rd);
      auto to = dist_to(rd);

      std::vector<bool> stl_vector_subset(stl_vector.begin() + from, stl_vector.begin() + to);
      ENCRYPTO::BitVector bit_vector_subset = bit_vector.Subset(from, to);

      for (auto j = 0ull; j < stl_vector_subset.size(); ++j) {
        ASSERT_EQ(stl_vector_subset.at(j), bit_vector_subset.Get(j));
      }

      ASSERT_EQ(stl_vector_subset.size(), bit_vector_subset.GetSize());
    }
  }
}

TEST(BitVector, AppendSubset) {
  for (auto test_iterations = 0ull; test_iterations < TEST_ITERATIONS; ++test_iterations) {
    std::vector<std::size_t> sizes;
    for (auto i = 1; i < 20; ++i) {
      sizes.push_back(i);
    }
    for (auto i = 128ull; i < 10000; i *= 2) {
      sizes.push_back(i);
    }
    for (auto size : sizes) {
      std::vector<bool> stl_vector_result;
      ENCRYPTO::BitVector bit_vector_result;
      for (auto subset_i = 0ull; subset_i < 20u; ++subset_i) {
        std::vector<bool> stl_vector(size);
        ENCRYPTO::BitVector bit_vector(size);

        std::random_device rd("/dev/urandom");
        std::uniform_int_distribution<uint64_t> dist_from(0, size / 2);
        std::uniform_int_distribution<uint64_t> dist_to(size / 2, size - 1);
        std::uniform_int_distribution<uint64_t> dist_bool(0, 1);

        for (auto j = 0ull; j < stl_vector.size(); ++j) {
          stl_vector.at(j) = dist_bool(rd);
          bit_vector.Set(stl_vector.at(j), j);
        }

        auto from = dist_from(rd);
        auto to = dist_to(rd);

        std::vector<bool> stl_vector_subset(stl_vector.begin() + from, stl_vector.begin() + to);
        ENCRYPTO::BitVector bit_vector_subset = bit_vector.Subset(from, to);

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
}