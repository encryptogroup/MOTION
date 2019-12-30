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

#include <tuple>
#include <type_traits>

namespace ENCRYPTO {
enum PrimitiveOperationType : std::uint8_t {
  IN = 0,
  OUT = 1,
  XOR = 2,  // for Boolean circuit only
  AND = 3,  // for Boolean circuit only
  MUX = 4,  // for Boolean circuit only
  INV = 5,  // for Boolean circuit only
  OR = 6,   // for Boolean circuit only
  ADD = 7,  // for arithmetic circuit only
  MUL = 8,  // for arithmetic circuit only
  // conversions
  A2B = 9,  // for arithmetic GMW only
  A2Y = 10, // for arithmetic GMW only
  B2A = 11, // for GMW only
  B2Y = 12, // for GMW only
  Y2A = 13, // for BMR only
  Y2B = 14, // for BMR only
  INVALID_PrimitiveOperationType = 15
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

enum IntegerOperationType : unsigned int {
  INT_ADD = 0,
  INT_DIV = 1,
  INT_GT = 2,
  INT_EQ = 3,
  INT_MUL = 4,
  INT_SUB = 5,
  INT_INVALID = 6
};

inline std::string ToString(IntegerOperationType p) {
  switch (p) {
    case IntegerOperationType::INT_ADD: {
      return "INT_ADD";
    }
    case IntegerOperationType::INT_DIV: {
      return "INT_DIV";
    }
    case IntegerOperationType::INT_GT: {
      return "INT_GT";
    }
    case IntegerOperationType::INT_EQ: {
      return "INT_EQ";
    }
    case IntegerOperationType::INT_MUL: {
      return "INT_MUL";
    }
    case IntegerOperationType::INT_SUB: {
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

enum MPCProtocol : unsigned int {
  ArithmeticGMW = 0,
  BooleanGMW = 1,
  BMR = 2,
  ArithmeticConstant = 3,
  BooleanConstant = 4,
  InvalidProtocol = 5  // for checking whether the value is valid
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

enum CircuitType : unsigned int {
  ArithmeticCircuitType = 0,
  BooleanCircuitType = 1,
  InvalidCircuitType = 2  // for checking whether the value is valid
};

enum Role : unsigned int {
  Server = 0,
  Client = 1,
  InvalidRole = 2  // for checking whether the value is valid
};

enum GateType : unsigned int {
  InputGate = 0,
  InteractiveGate = 1,
  NonInteractiveGate = 2,
  InvalidGate = 3
};

}  // namespace MOTION

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
using MultiplicationTriple = std::tuple<T, T, T>;

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
using MT = MultiplicationTriple<T>;
