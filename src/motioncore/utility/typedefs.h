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

#pragma once

#include <cstdint>
#include <string>
#include <stdexcept>
#include <tuple>
#include <type_traits>

namespace ENCRYPTO {
enum class PrimitiveOperationType : std::uint8_t {
  IN,
  OUT,
  XOR,  // for Boolean circuit only
  AND,  // for Boolean circuit only
  MUX,  // for Boolean circuit only
  INV,  // for Boolean circuit only
  OR,   // for Boolean circuit only
  ADD,  // for arithmetic circuit only
  MUL,  // for arithmetic circuit only
  SQR,  // for arithmetic circuit only
  // conversions
  A2B,  // for arithmetic GMW only
  A2Y,  // for arithmetic GMW only
  B2A,  // for GMW only
  B2Y,  // for GMW only
  Y2A,  // for BMR only
  Y2B,  // for BMR only
  INVALID
};

inline std::string ToString(PrimitiveOperationType t) {
  switch (t) {
    case PrimitiveOperationType::XOR: {
      return "XOR";
    }
    case PrimitiveOperationType::AND: {
      return "AND";
    }
    case PrimitiveOperationType::MUX: {
      return "MUX";
    }
    case PrimitiveOperationType::INV: {
      return "INV";
    }
    case PrimitiveOperationType::OR: {
      return "OR";
    }
    case PrimitiveOperationType::ADD: {
      return "ADD";
    }
    case PrimitiveOperationType::MUL: {
      return "MUL";
    }
    case PrimitiveOperationType::SQR: {
      return "SQR";
    }
    case PrimitiveOperationType::IN: {
      return "IN";
    }
    case PrimitiveOperationType::OUT: {
      return "OUT";
    }
    case PrimitiveOperationType::A2B: {
      return "A2B";
    }
    case PrimitiveOperationType::A2Y: {
      return "A2Y";
    }
    case PrimitiveOperationType::B2A: {
      return "B2A";
    }
    case PrimitiveOperationType::B2Y: {
      return "B2Y";
    }
    case PrimitiveOperationType::Y2A: {
      return "Y2A";
    }
    case PrimitiveOperationType::Y2B: {
      return "Y2B";
    }
    default:
      throw std::invalid_argument("Invalid PrimitiveOperationType");
  }
}

enum class IntegerOperationType : unsigned int { ADD, DIV, GT, EQ, MUL, SUB, INVALID };

inline std::string ToString(IntegerOperationType p) {
  switch (p) {
    case IntegerOperationType::ADD: {
      return "INT_ADD";
    }
    case IntegerOperationType::DIV: {
      return "INT_DIV";
    }
    case IntegerOperationType::GT: {
      return "INT_GT";
    }
    case IntegerOperationType::EQ: {
      return "INT_EQ";
    }
    case IntegerOperationType::MUL: {
      return "INT_MUL";
    }
    case IntegerOperationType::SUB: {
      return "INT_SUB";
    }
    default:
      throw std::invalid_argument("Invalid IntegerOperationType");
  }
}
}  // namespace ENCRYPTO

// TODO: put MOTION namespace into ENCRYPTO namespace

namespace MOTION {

namespace Gates::Interfaces {}
namespace Gates::Arithmetic {}
namespace Gates::Boolean {}
namespace Gates::Yao {}
namespace Gates::Conversion {}

// fast-access aliases for Gates
namespace Arithmetic = Gates::Arithmetic;
namespace Boolean = Gates::Boolean;
namespace Conversion = Gates::Conversion;

enum class MPCProtocol : unsigned int {
  ArithmeticGMW,
  BooleanGMW,
  BMR,
  ArithmeticConstant,
  BooleanConstant,
  Invalid  // for checking whether the value is valid
};

inline std::string ToString(MPCProtocol p) {
  switch (p) {
    case MPCProtocol::ArithmeticGMW: {
      return "ArithmeticGMW";
    }
    case MPCProtocol::BMR: {
      return "BMR";
    }
    case MPCProtocol::BooleanGMW: {
      return "BooleanGMW";
    }
    default:
      throw std::invalid_argument("Invalid MPCProtocol");
  }
}

enum class CircuitType : unsigned int {
  Arithmetic,
  Boolean,
  Invalid  // for checking whether the value is valid
};

enum class Role : unsigned int {
  Server,
  Client,
  Invalid  // for checking whether the value is valid
};

enum class GateType : unsigned int { Input = 0, Interactive = 1, NonInteractive = 2, Invalid = 3 };

}  // namespace MOTION

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
using MultiplicationTriple = std::tuple<T, T, T>;

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
using MT = MultiplicationTriple<T>;
