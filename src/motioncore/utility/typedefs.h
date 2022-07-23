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
#include <stdexcept>
#include <string>
#include <tuple>
#include <type_traits>

namespace encrypto::motion {

enum class PrimitiveOperationType : std::uint8_t {
  kIn,
  kOut,
  kXor,  // for Boolean circuit only
  kAnd,  // for Boolean circuit only
  kMux,  // for Boolean circuit only
  kInv,  // for Boolean circuit only
  kOr,   // for Boolean circuit only
  kAdd,  // for arithmetic circuit only
  kMul,  // for arithmetic circuit only
  kSqr,  // for arithmetic circuit only
  // conversions
  kA2B,  // for arithmetic GMW only
  kA2Y,  // for arithmetic GMW only
  kB2A,  // for GMW only
  kB2Y,  // for GMW only
  kY2A,  // for BMR only
  kY2B,  // for BMR only
  kInvalid
};

inline std::string to_string(PrimitiveOperationType t) {
  switch (t) {
    case PrimitiveOperationType::kXor: {
      return "XOR";
    }
    case PrimitiveOperationType::kAnd: {
      return "AND";
    }
    case PrimitiveOperationType::kMux: {
      return "MUX";
    }
    case PrimitiveOperationType::kInv: {
      return "INV";
    }
    case PrimitiveOperationType::kOr: {
      return "OR";
    }
    case PrimitiveOperationType::kAdd: {
      return "ADD";
    }
    case PrimitiveOperationType::kMul: {
      return "MUL";
    }
    case PrimitiveOperationType::kSqr: {
      return "SQR";
    }
    case PrimitiveOperationType::kIn: {
      return "IN";
    }
    case PrimitiveOperationType::kOut: {
      return "OUT";
    }
    case PrimitiveOperationType::kA2B: {
      return "A2B";
    }
    case PrimitiveOperationType::kA2Y: {
      return "A2Y";
    }
    case PrimitiveOperationType::kB2A: {
      return "B2A";
    }
    case PrimitiveOperationType::kB2Y: {
      return "B2Y";
    }
    case PrimitiveOperationType::kY2A: {
      return "Y2A";
    }
    case PrimitiveOperationType::kY2B: {
      return "Y2B";
    }
    default:
      throw std::invalid_argument("Invalid PrimitiveOperationType");
  }
}

enum class IntegerOperationType : unsigned int { kAdd, kDiv, kGt, kEq, kMul, kSub, kInvalid };

inline std::string to_string(IntegerOperationType p) {
  switch (p) {
    case IntegerOperationType::kAdd: {
      return "INT_ADD";
    }
    case IntegerOperationType::kDiv: {
      return "INT_DIV";
    }
    case IntegerOperationType::kGt: {
      return "INT_GT";
    }
    case IntegerOperationType::kEq: {
      return "INT_EQ";
    }
    case IntegerOperationType::kMul: {
      return "INT_MUL";
    }
    case IntegerOperationType::kSub: {
      return "INT_SUB";
    }
    default:
      throw std::invalid_argument("Invalid IntegerOperationType");
  }
}

enum class MpcProtocol : unsigned int {
  // MPC protocols
  kArithmeticGmw,
  kAstra,
  kBooleanGmw,
  kBmr,
  kGarbledCircuit,
  // Constants
  kArithmeticConstant,
  kBooleanConstant,
  kInvalid  // for checking whether the value is valid
};

inline std::string to_string(MpcProtocol p) {
  switch (p) {
    case MpcProtocol::kArithmeticGmw: {
      return "ArithmeticGMW";
    }
    case MpcProtocol::kAstra: {
      return "Astra";
    }
    case MpcProtocol::kBooleanGmw: {
      return "BooleanGMW";
    }
    case MpcProtocol::kBmr: {
      return "BMR";
    }
    case MpcProtocol::kGarbledCircuit: {
      return "GarbledCircuit";
    }
    default:
      return std::string("InvalidProtocol with value ") + std::to_string(static_cast<int>(p));
  }
}

enum class CircuitType : unsigned int {
  kArithmetic,
  kBoolean,
  kInvalid  // for checking whether the value is valid
};

enum class Role : unsigned int {
  kServer = 0,
  kClient = 1,
  kInvalid = 2  // for checking whether the value is valid
};

enum class GarbledCircuitRole : unsigned int {
  kGarbler = static_cast<unsigned int>(Role::kServer),
  kEvaluator = static_cast<unsigned int>(Role::kClient),
  kInvalid = 2  // for checking whether the value is valid
};

}  // namespace encrypto::motion
