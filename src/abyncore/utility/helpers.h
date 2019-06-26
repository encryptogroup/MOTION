#pragma once

#include "flatbuffers/flatbuffers.h"

#include "bit_vector.h"
#include "typedefs.h"

namespace ENCRYPTO {
class BitVector;  // forward declaration
}

namespace ABYN::Helpers {

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
inline std::vector<std::uint8_t> ToByteVector(const std::vector<T> &values) {
  std::vector<std::uint8_t> result(
      reinterpret_cast<const std::uint8_t *>(values.data()),
      reinterpret_cast<const std::uint8_t *>(values.data()) + sizeof(T) * values.size());
  return std::move(result);
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
inline std::vector<T> FromByteVector(const std::vector<std::uint8_t> &buffer) {
  assert(buffer.size() % sizeof(T) == 0);  // buffer length is multiple of the element size
  std::vector<T> result(sizeof(T) * buffer.size());
  std::copy(buffer.data(), buffer.data() + buffer.size(),
            reinterpret_cast<std::uint8_t *>(result.data()));
  return std::move(result);
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
inline std::vector<T> FromByteVector(const flatbuffers::Vector<std::uint8_t> &buffer) {
  assert(buffer.size() % sizeof(T) == 0);  // buffer length is multiple of the element size
  std::vector<T> result(buffer.size() / sizeof(T));
  std::copy(buffer.data(), buffer.data() + buffer.size(),
            reinterpret_cast<std::uint8_t *>(result.data()));
  return std::move(result);
};

void WaitFor(const bool &condition);

template <typename T>
inline std::vector<T> AddVectors(std::vector<std::vector<T>> vectors) {
  if (vectors.size() == 0) {
    return {};
  }  // if empty input vector

  std::vector<T> result = vectors.at(0);

  for (auto i = 1ull; i < vectors.size(); ++i) {
    auto &v = vectors.at(i);
    assert(v.size() == result.size());  // expect the vectors to be of the same size
#pragma omp simd
    for (auto j = 0ull; j < result.size(); ++j) {
      result.at(j) += v.at(j);  // TODO: implement using AVX2 and AVX512
    }
  }
  return result;
}

template <typename T>
inline std::vector<T> AddVectors(std::vector<T> a, std::vector<T> b) {
  assert(a.size() == b.size());
  if (a.size() == 0) {
    return {};
  }  // if empty input vector
  std::vector<T> result = a;
#pragma omp simd
  for (auto j = 0ull; j < result.size(); ++j) {
    result.at(j) += b.at(j);  // TODO: implement using AVX2 and AVX512
  }
  return result;
}

template <typename T>
inline T SumReduction(const std::vector<T> &v) {
  if (v.size() == 0) {
    return 0;
  } else if (v.size() == 1) {
    return v.at(0);
  } else {
    T sum = 0;
#pragma omp parallel for reduction(+ : sum)
    for (auto i = 0ull; i < v.size(); ++i) {
      sum += v.at(i);
    }
    return sum;
  }
}

// +---------+--------------------------+
// | sum_0 = | v_00 + v_01 + ... + v_0m |
// |  ...    | ........................ |
// | sum_n = | v_n0 + v_n1 + ... + v_nm |
// +---------+--------------------------+

template <typename T>
inline std::vector<T> RowSumReduction(const std::vector<std::vector<T>> &v) {
  if (v.size() == 0) {
    return {};
  } else {
    std::vector<T> sum(v.at(0).size());
    for (auto i = 1ull; i < v.size(); ++i) {
      assert(v.at(0).size() == v.at(i).size());
    }
#pragma omp parallel for
    for (auto i = 0ull; i < sum.size(); ++i) {
      for (auto j = 0ull; j < v.size(); ++j) {
        sum.at(i) += v.at(j).at(i);
      }
    }
    return std::move(sum);
  }
}

inline bool XORReduceBitVector(const ENCRYPTO::BitVector &vector) {
  if (vector.GetSize() == 0) {
    return {};
  } else if (vector.GetSize() == 1) {
    return vector.Get(0);
  } else if (vector.GetSize() <= 64) {
    bool result = vector.Get(0);
    for (auto i = 1ull; i < vector.GetSize(); ++i) {
      result ^= vector.Get(i);
    }
    return result;
  } else {
    auto raw_vector = vector.GetData();
    std::byte b = raw_vector.at(0);
    for (auto i = 1ull; i < raw_vector.size(); ++i) {
      b ^= raw_vector.at(i);
    }
    ENCRYPTO::BitVector bv({b}, 8);
    bool result = bv.Get(0);

    for (auto i = 1; i < 8; ++i) {
      result ^= bv.Get(i);
    }

    return result;
  }
}

inline ENCRYPTO::BitVector XORBitVectors(const std::vector<ENCRYPTO::BitVector> &vectors) {
  if (vectors.size() == 0) {
    return {};
  } else if (vectors.size() == 1) {
    return vectors.at(0);
  } else {
    auto result = vectors.at(0);
    for (auto i = 1ull; i < vectors.size(); ++i) {
      result ^= vectors.at(i);
    }
    return result;
  }
}

inline std::vector<ENCRYPTO::BitVector> XORBitVectors(const std::vector<ENCRYPTO::BitVector> &a,
                                                      const std::vector<ENCRYPTO::BitVector> &b) {
  assert(a.size() == b.size());
  if (a.size() == 0) {
    return {};
  } else {
    std::vector<ENCRYPTO::BitVector> result(a.begin(), a.end());
    for (auto i = 0ull; i < a.size(); ++i) {
      result.at(i) ^= b.at(i);
    }
    return result;
  }
}

inline std::vector<ENCRYPTO::BitVector> XORBitVectors(
    const std::vector<std::vector<ENCRYPTO::BitVector>> &vectors) {
  if (vectors.size() == 0) {
    return {};
  } else if (vectors.size() == 1) {
    return vectors.at(0);
  } else {
    auto result = vectors.at(0);
    for (auto i = 1ull; i < vectors.size(); ++i) {
      result = XORBitVectors(result, vectors.at(i));
    }
    return result;
  }
}

namespace Print {
std::string Hex(const std::vector<std::uint8_t> &v);

inline std::string Hex(const std::vector<std::uint8_t> &&v) { return std::move(Hex(v)); }

std::string ToString(Protocol p);

template <typename T>
inline std::string ToString(std::vector<T> vector) {
  std::string result{""};
  for (auto &v : vector) {
    result.append(std::to_string(v) + " ");
  }
  return std::move(result);
}
}  // namespace Print

namespace Compare {
template <typename T>
inline bool Vectors(const std::vector<T> &a, const std::vector<T> &b) {
  if (a.size() != b.size()) {
    return false;
  }
  for (auto i = 0ull; i < a.size(); ++i) {
    if (a.at(i) != b.at(i)) {
      return false;
    }
  }
  return true;
}

template <typename T>
inline bool Dimensions(const std::vector<std::vector<T>> &v) {
  if (v.size() <= 1) {
    return true;
  } else {
    auto first_size = v.at(0).size();
    for (auto i = 1ull; i < v.size(); ++i) {
      if (first_size != v.at(i).size()) {
        return false;
      }
    }
  }
  return true;
}

bool Dimensions(const std::vector<ENCRYPTO::BitVector> &v);
}  // namespace Compare

std::size_t DivideAndCeil(std::size_t dividend, std::size_t divisor);

namespace Convert {
std::size_t BitsToBytes(std::size_t bits);
}  // namespace Convert
}  // namespace ABYN::Helpers
