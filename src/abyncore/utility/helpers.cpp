#include "helpers.h"

#include <chrono>
#include <thread>

#include "fmt/format.h"
#include "utility/bit_vector.h"

namespace ABYN::Helpers {

void WaitFor(const bool &condition) {
  while (!condition) {
    std::this_thread::sleep_for(std::chrono::microseconds(100));
  }
}

bool XORReduceBitVector(const ENCRYPTO::BitVector &vector) {
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

ENCRYPTO::BitVector XORBitVectors(const std::vector<ENCRYPTO::BitVector> &vectors) {
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

std::vector<ENCRYPTO::BitVector> XORBitVectors(const std::vector<ENCRYPTO::BitVector> &a,
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

std::vector<ENCRYPTO::BitVector> XORBitVectors(
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
std::string Hex(const std::vector<std::uint8_t> &v) {
  std::string buffer("");
  for (auto i = 0ull; i < v.size(); ++i) {
    buffer.append(fmt::format("{0:#x} ", v.at(i)));
  }
  buffer.erase(buffer.end() - 1);  // remove the last whitespace
  return std::move(buffer);
}

std::string ToString(MPCProtocol p) {
  std::string result{""};
  switch (p) {
    case MPCProtocol::ArithmeticGMW:
      result.append("ArithmeticGMW");
      break;
    case MPCProtocol::BooleanGMW:
      result.append("BooleanGMW");
      break;
    case MPCProtocol::BMR:
      result.append("BMR");
      break;
    default:
      result.append(fmt::format("InvalidProtocol with value {}", static_cast<int>(p)));
      break;
  }
  return std::move(result);
};

}  // namespace Print

namespace Compare {
bool Dimensions(const std::vector<ENCRYPTO::BitVector> &v) {
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

std::size_t DivideAndCeil(std::size_t dividend, std::size_t divisor) {
  assert(divisor != 0);
  return 1 + ((dividend - 1) / divisor);
}

namespace Convert {
std::size_t BitsToBytes(std::size_t bits) {
  constexpr std::size_t bits_in_bytes = 8;
  return DivideAndCeil(bits, bits_in_bytes);
}
}  // namespace Convert
}