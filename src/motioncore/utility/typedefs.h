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

enum class UnsignedIntegerOperationType : unsigned int {
  kAdd,
  kSub,
  kMul,
  kDiv,
  kLt,
  kGt,
  kEq,
  kGE,
  kLEQ,
  kEQZ,
  kMod,
  kInt2FL,
  kInt2Fx,

  kAddConstant,
  kSubConstant,
  kMulConstant,
  kDivConstant,
  kLtConstant,
  kGtConstant,
  kEqConstant,
  kModConstant,

  kInvalid
};

inline std::string to_string(UnsignedIntegerOperationType p) {
  switch (p) {
    case UnsignedIntegerOperationType::kAdd: {
      return "UINT_ADD";
    }
    case UnsignedIntegerOperationType::kSub: {
      return "UINT_SUB";
    }
    case UnsignedIntegerOperationType::kMul: {
      return "UINT_MUL";
    }
    case UnsignedIntegerOperationType::kDiv: {
      return "UINT_DIV";
    }
    case UnsignedIntegerOperationType::kLt: {
      return "UINT_LT";
    }
    case UnsignedIntegerOperationType::kGt: {
      return "UINT_GT";
    }
    case UnsignedIntegerOperationType::kEq: {
      return "UINT_EQ";
    }
    case UnsignedIntegerOperationType::kGE: {
      return "UINT_GE";
    }
    case UnsignedIntegerOperationType::kLEQ: {
      return "UINT_LEQ";
    }
    case UnsignedIntegerOperationType::kEQZ: {
      return "UINT_EQZ";
    }
    case UnsignedIntegerOperationType::kMod: {
      return "UINT_MOD";
    }
    case UnsignedIntegerOperationType::kInt2FL: {
      return "UINT_Int2FL";
    }
    case UnsignedIntegerOperationType::kInt2Fx: {
      return "UINT_Int2Fx";
    }
    case UnsignedIntegerOperationType::kAddConstant: {
      return "UINT_ADD_Constant";
    }
    case UnsignedIntegerOperationType::kSubConstant: {
      return "UINT_SUB_Constant";
    }
    case UnsignedIntegerOperationType::kMulConstant: {
      return "UINT_MUL_Constant";
    }
    case UnsignedIntegerOperationType::kDivConstant: {
      return "UINT_DIV_Constant";
    }
    case UnsignedIntegerOperationType::kLtConstant: {
      return "UINT_LT_Constant";
    }
    case UnsignedIntegerOperationType::kGtConstant: {
      return "UINT_GT_Constant";
    }
    case UnsignedIntegerOperationType::kEqConstant: {
      return "UINT_EQ_Constant";
    }
    case UnsignedIntegerOperationType::kModConstant: {
      return "UINT_MOD_Constant";
    }

    default:
      throw std::invalid_argument("Invalid UnsignedIntegerOperationType");
  }
}

enum class SignedIntegerOperationType : unsigned int {
  kAdd,
  kSub,
  kMul,
  kDiv,
  kLt,
  kGt,
  kEq,
  kGEQ,
  kLEQ,
  kInRange,
  kEQZ,
  kLTZ,

  kNeg,
  kNegCondition,

  kInt2FL,
  kInt2Fx,

  kInvalid
};

inline std::string to_string(SignedIntegerOperationType p) {
  switch (p) {
    case SignedIntegerOperationType::kAdd: {
      return "INT_ADD";
    }
    case SignedIntegerOperationType::kSub: {
      return "INT_SUB";
    }
    case SignedIntegerOperationType::kMul: {
      return "INT_MUL";
    }
    case SignedIntegerOperationType::kDiv: {
      return "INT_DIV";
    }
    case SignedIntegerOperationType::kLt: {
      return "INT_LT";
    }
    case SignedIntegerOperationType::kGt: {
      return "INT_GT";
    }
    case SignedIntegerOperationType::kEq: {
      return "INT_EQ";
    }
    case SignedIntegerOperationType::kGEQ: {
      return "INT_GEQ";
    }
    case SignedIntegerOperationType::kLEQ: {
      return "INT_LEQ";
    }
    case SignedIntegerOperationType::kInRange: {
      return "INT_InRange";
    }
    case SignedIntegerOperationType::kEQZ: {
      return "INT_EQZ";
    }
    case SignedIntegerOperationType::kLTZ: {
      return "INT_LTZ";
    }
    case SignedIntegerOperationType::kNeg: {
      return "INT_NEG";
    }
    case SignedIntegerOperationType::kNegCondition: {
      return "INT_NEG_CONDITION";
    }
    case SignedIntegerOperationType::kInt2FL: {
      return "INT_Int2FL";
    }
    case SignedIntegerOperationType::kInt2Fx: {
      return "INT_Int2Fx";
    }
    default:
      throw std::invalid_argument("Invalid SignedIntegerOperationType");
  }
}

}  // namespace encrypto::motion
