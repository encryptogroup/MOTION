#pragma once

#include "flatbuffers/flatbuffers.h"
#include "fmt/format.h"
#include "typedefs.h"

#include "ENCRYPTO_utils/src/ENCRYPTO_utils/cbitvector.h"

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

inline void WaitFor(const bool &condition) {
  while (!condition) {
    std::this_thread::sleep_for(std::chrono::microseconds(100));
  }
}

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

namespace Print {
inline std::string Hex(const std::vector<std::uint8_t> &v) {
  std::string buffer("");
  for (auto i = 0ull; i < v.size(); ++i) {
    buffer.append(fmt::format("{0:#x} ", v.at(i)));
  }
  buffer.erase(buffer.end() - 1);  // remove the last whitespace
  return std::move(buffer);
}

inline std::string Hex(const std::vector<std::uint8_t> &&v) { return std::move(Hex(v)); }

inline std::string ToString(Protocol p) {
  std::string result{""};
  switch (p) {
    case Protocol::ArithmeticGMW:
      result.append("ArithmeticGMW");
      break;
    case Protocol::BooleanGMW:
      result.append("BooleanGMW");
      break;
    case Protocol::BMR:
      result.append("BMR");
      break;
    default:
      result.append(fmt::format("InvalidProtocol with value {}", static_cast<int>(p)));
      break;
  }
  return std::move(result);
};

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

inline bool Dimensions(const std::vector<CBitVector> &v) {
  if (v.size() <= 1) {
    return true;
  } else {
    auto first_size = v.at(0).GetSize();
    for (auto i = 1ull; i < v.size(); ++i) {
      if (first_size != v.at(i).GetSize()) {
        return false;
      }
    }
  }
  return true;
}
}  // namespace Compare

inline std::size_t DivideAndCeil(std::size_t dividend, std::size_t divisor) {
  assert(divisor != 0);
  return 1 + ((dividend - 1) / divisor);
}

namespace Convert {
inline std::size_t BitsToBytes(std::size_t bits) {
  const std::size_t bits_in_bytes = 8;
  return DivideAndCeil(bits, bits_in_bytes);
}
}  // namespace Convert
}  // namespace ABYN::Helpers
