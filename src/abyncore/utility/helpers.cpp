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

#include "helpers.h"

#include <chrono>
#include <thread>

#include "condition.h"

namespace ABYN::Helpers {

void WaitFor(const bool &condition) {
  while (!condition) {
    std::this_thread::sleep_for(std::chrono::microseconds(100));
  }
}

void WaitFor(ENCRYPTO::Condition &condition) {
  while (!condition()) {
    condition.WaitFor(std::chrono::milliseconds(1));
  }
}

namespace Print {
std::string ToString(MPCProtocol p) {
  std::string result;
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
  return result;
}

}  // namespace Print

namespace Compare {}  // namespace Compare

std::size_t DivideAndCeil(std::size_t dividend, std::size_t divisor) {
  assert(divisor != 0);
  if (dividend == 0) {
    return 0;
  } else {
    return 1 + ((dividend - 1) / divisor);
  }
}

namespace Convert {
std::size_t BitsToBytes(std::size_t bits) {
  if ((bits & 0x07u) > 0u) {
    return (bits >> 3) + 1;
  } else {
    return bits >> 3;
  }
}
}  // namespace Convert
}