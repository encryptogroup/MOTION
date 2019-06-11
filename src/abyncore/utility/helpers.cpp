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

namespace Print {
std::string Hex(const std::vector<std::uint8_t> &v) {
  std::string buffer("");
  for (auto i = 0ull; i < v.size(); ++i) {
    buffer.append(fmt::format("{0:#x} ", v.at(i)));
  }
  buffer.erase(buffer.end() - 1);  // remove the last whitespace
  return std::move(buffer);
}

std::string ToString(Protocol p) {
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