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

// TODO: remove later
// ! rename this as UnsignedIntegerOperationType and add new operations
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

enum class UnsignedIntegerOperationType : unsigned int {
  kAdd,
  kSub,
  kMul,
  kDiv,
  kLt,
  kGt,
  kEq,
  kGEQ,
  kLEQ,
  kEQZ,
  kMod,

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
    case UnsignedIntegerOperationType::kGEQ: {
      return "UINT_GEQ";
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

enum class FloatingPointOperationType : unsigned int {
  // boolean circuit based method
  kAdd_circuit,
  kSub_circuit,
  kMul_circuit,
  kDiv_circuit,
  kLt_circuit,
  kGt_circuit,
  kEq_circuit,
  kNeg_circuit,
  kEQZ_circuit,
  kLTZ_circuit,
  kAbs_circuit,
  kExp2_circuit,
  kLog2_circuit,
  kExp_circuit,
  kLn_circuit,
  kSqr_circuit,
  kSqrt_circuit,
  kSin_circuit,
  kCos_circuit,
  kCeil_circuit,
  kFloor_circuit,
  kFL2Int_circuit,
  kFL2Fx_circuit,
  // kInt2FL_circuit,
  // kFx2FL_circuit,
  kMulPow2m_circuit,
  kDivPow2m_circuit,
  kClampB_circuit,
  kRoundToNearestInt_circuit,

  // arithmetic GMW share based method
  kAdd_agmw,
  kSub_agmw,
  kMul_agmw,
  kDiv_agmw,
  kLt_agmw,
  kGt_agmw,
  kEq_agmw,
  kEQZ_agmw,
  kLTZ_agmw,
  kExp2_agmw,
  kLog2_agmw,
  kExp_agmw,
  kLn_agmw,
  kSqr_agmw,
  kSqrt_agmw,
  kCeil_agmw,
  kFloor_agmw,
  kNeg_agmw,
  kFL2Int_agmw,

  // TODO: implement
  kFL2Fx_agmw,

  // kInt2FL_agmw,
  // kFx2FL_agmw,

  kInvalid
};

inline std::string to_string(FloatingPointOperationType p) {
  switch (p) {
    case FloatingPointOperationType::kAdd_circuit: {
      return "FL_Add_circuit";
    }
    case FloatingPointOperationType::kSub_circuit: {
      return "FL_Sub_circuit";
    }
    case FloatingPointOperationType::kMul_circuit: {
      return "FL_Mul_circuit";
    }
    case FloatingPointOperationType::kDiv_circuit: {
      return "FL_Div_circuit";
    }
    case FloatingPointOperationType::kLt_circuit: {
      return "FL_Lt_circuit";
    }
    case FloatingPointOperationType::kGt_circuit: {
      return "FL_Gt_circuit";
    }
    case FloatingPointOperationType::kEq_circuit: {
      return "FL_Eq_circuit";
    }
    case FloatingPointOperationType::kNeg_circuit: {
      return "FL_Neg_circuit";
    }
    case FloatingPointOperationType::kEQZ_circuit: {
      return "FL_EQZ_circuit";
    }
    case FloatingPointOperationType::kLTZ_circuit: {
      return "FL_LTZ_circuit";
    }
    case FloatingPointOperationType::kAbs_circuit: {
      return "FL_Abs_circuit";
    }
    case FloatingPointOperationType::kExp2_circuit: {
      return "FL_Exp2_circuit";
    }
    case FloatingPointOperationType::kLog2_circuit: {
      return "FL_Log2_circuit";
    }
    case FloatingPointOperationType::kExp_circuit: {
      return "FL_Exp_circuit";
    }
    case FloatingPointOperationType::kLn_circuit: {
      return "FL_Ln_circuit";
    }
    case FloatingPointOperationType::kSqr_circuit: {
      return "FL_Sqr_circuit";
    }
    case FloatingPointOperationType::kSqrt_circuit: {
      return "FL_Sqrt_circuit";
    }
    case FloatingPointOperationType::kSin_circuit: {
      return "FL_Sin_circuit";
    }
    case FloatingPointOperationType::kCos_circuit: {
      return "FL_Cos_circuit";
    }
    case FloatingPointOperationType::kCeil_circuit: {
      return "FL_Ceil_circuit";
    }
    case FloatingPointOperationType::kFloor_circuit: {
      return "FL_Floor_circuit";
    }
    case FloatingPointOperationType::kFL2Int_circuit: {
      return "FL2Int_circuit";
    }
    case FloatingPointOperationType::kFL2Fx_circuit: {
      return "FL2Fx_circuit";
    }
    case FloatingPointOperationType::kMulPow2m_circuit: {
      return "FL_MulPow2m_circuit";
    }
    case FloatingPointOperationType::kDivPow2m_circuit: {
      return "FL_DivPow2m_circuit";
    }
    case FloatingPointOperationType::kClampB_circuit: {
      return "FL_ClampB_circuit";
    }
    case FloatingPointOperationType::kRoundToNearestInt_circuit: {
      return "FL_RoundToNearestInt_circuit";
    }
    case FloatingPointOperationType::kAdd_agmw: {
      return "FL_Add_agmw";
    }
    case FloatingPointOperationType::kSub_agmw: {
      return "FL_Sub_agmw";
    }
    case FloatingPointOperationType::kMul_agmw: {
      return "FL_Mul_agmw";
    }
    case FloatingPointOperationType::kDiv_agmw: {
      return "FL_Div_agmw";
    }
    case FloatingPointOperationType::kLt_agmw: {
      return "FL_Lt_agmw";
    }
    case FloatingPointOperationType::kGt_agmw: {
      return "FL_Gt_agmw";
    }
    case FloatingPointOperationType::kEq_agmw: {
      return "FL_Eq_agmw";
    }
    case FloatingPointOperationType::kEQZ_agmw: {
      return "FL_EQZ_agmw";
    }
    case FloatingPointOperationType::kLTZ_agmw: {
      return "FL_LTZ_agmw";
    }
    case FloatingPointOperationType::kExp2_agmw: {
      return "FL_Exp2_agmw";
    }
    case FloatingPointOperationType::kLog2_agmw: {
      return "FL_Log2_agmw";
    }
    case FloatingPointOperationType::kExp_agmw: {
      return "FL_Exp_agmw";
    }
    case FloatingPointOperationType::kLn_agmw: {
      return "FL_Ln_agmw";
    }
    case FloatingPointOperationType::kSqr_agmw: {
      return "FL_Sqr_agmw";
    }
    case FloatingPointOperationType::kSqrt_agmw: {
      return "FL_Sqrt_agmw";
    }
    case FloatingPointOperationType::kCeil_agmw: {
      return "FL_Ceil_agmw";
    }
    case FloatingPointOperationType::kFloor_agmw: {
      return "FL_Floor_agmw";
    }
    case FloatingPointOperationType::kNeg_agmw: {
      return "FL_Neg_agmw";
    }
    case FloatingPointOperationType::kFL2Int_agmw: {
      return "FL_FL2Int_agmw";
    }
    case FloatingPointOperationType::kFL2Fx_agmw: {
      return "FL_FL2Fx_agmw";
    }

    default:
      throw std::invalid_argument("Invalid FloatingPointOperationType");
  }
}

enum class FixedPointOperationType : unsigned int {
  // boolean circuit based method
  kAdd_circuit,
  kSub_circuit,
  kMul_circuit,
  kDiv_circuit,
  kDiv_Goldschmidt_circuit,
  kLt_circuit,
  kGt_circuit,
  kEq_circuit,
  kEQZ_circuit,
  kLTZ_circuit,
  kExp2_P1045_circuit,
  kExp2_P1045_Neg_0_1_circuit,
  kLog2_P2508_circuit,
  kExp_circuit,
  kLn_circuit,
  kSqrt_circuit,
  kSqrt_P0132_circuit,
  kCeil_circuit,
  kFloor_circuit,
  kFx2Int_circuit,
  kFx2FL_circuit,
  kNeg_circuit,
  kAbs_circuit,
  kSqr_circuit,
  kRoundedFx2Int_circuit,
  kSin_P3307_0_1_circuit,
  kSin_P3307_0_4_circuit,
  kCos_P3508_circuit,

  // arithmetic GMW share based method
  kAdd_agmw,
  kSub_agmw,
  kMul_agmw,
  kDiv_agmw,
  kDivConst_agmw,
  kLt_agmw,
  kGt_agmw,
  kRoundTowardsZero_agmw,
  kFx2IntWithRoundTowardsZero_agmw,
  kNeg_agmw,
  kAbs_agmw,
  kEq_agmw,
  kEQZ_agmw,
  kLTZ_agmw,
  kExp2_P1045_agmw,
  kLog2_P2508_agmw,
  kExp_agmw,
  kLn_agmw,
  kSqr_agmw,
  kSqrt_agmw,
  kSqrt_P0132_agmw,
  kCeil_agmw,
  kFloor_agmw,
  kFx2Int_agmw,
  kFx2FL_agmw,

  kInvalid
};

inline std::string to_string(FixedPointOperationType p) {
  switch (p) {
    case FixedPointOperationType::kAdd_circuit: {
      return "Fx_Add_circuit";
    }
    case FixedPointOperationType::kSub_circuit: {
      return "Fx_Sub_circuit";
    }
    case FixedPointOperationType::kMul_circuit: {
      return "Fx_Mul_circuit";
    }
    case FixedPointOperationType::kDiv_circuit: {
      return "Fx_Div_circuit";
    }
    case FixedPointOperationType::kDiv_Goldschmidt_circuit: {
      return "Fx_Div_Goldschmidt_circuit";
    }
    case FixedPointOperationType::kLt_circuit: {
      return "Fx_Lt_circuit";
    }
    case FixedPointOperationType::kGt_circuit: {
      return "Fx_Gt_circuit";
    }
    case FixedPointOperationType::kEq_circuit: {
      return "Fx_Eq_circuit";
    }
    case FixedPointOperationType::kEQZ_circuit: {
      return "Fx_EQZ_circuit";
    }
    case FixedPointOperationType::kLTZ_circuit: {
      return "Fx_LTZ_circuit";
    }
    case FixedPointOperationType::kExp2_P1045_circuit: {
      return "Fx_Exp2_P1045_circuit";
    }
    case FixedPointOperationType::kExp2_P1045_Neg_0_1_circuit: {
      return "Fx_Exp2_P1045_Neg_0_1_circuit";
    }
    case FixedPointOperationType::kLog2_P2508_circuit: {
      return "Fx_Log2_P2508_circuit";
    }
    case FixedPointOperationType::kExp_circuit: {
      return "Fx_Exp_circuit";
    }
    case FixedPointOperationType::kLn_circuit: {
      return "Fx_Ln_circuit";
    }
    case FixedPointOperationType::kSqrt_circuit: {
      return "Fx_Sqrt_circuit";
    }
    case FixedPointOperationType::kSqrt_P0132_circuit: {
      return "Fx_Sqrt_P0132_circuit";
    }
    case FixedPointOperationType::kCeil_circuit: {
      return "Fx_Ceil_circuit";
    }
    case FixedPointOperationType::kFloor_circuit: {
      return "Fx_Floor_circuit";
    }
    case FixedPointOperationType::kFx2Int_circuit: {
      return "Fx2Int_circuit";
    }
    case FixedPointOperationType::kFx2FL_circuit: {
      return "Fx2FL_circuit";
    }
    case FixedPointOperationType::kNeg_circuit: {
      return "Fx_Neg_circuit";
    }
    case FixedPointOperationType::kAbs_circuit: {
      return "Fx_Abs_circuit";
    }
    case FixedPointOperationType::kSqr_circuit: {
      return "Fx_Sqr_circuit";
    }
    case FixedPointOperationType::kRoundedFx2Int_circuit: {
      return "Fx_kRoundedFx2Int_circuit";
    }
    case FixedPointOperationType::kSin_P3307_0_1_circuit: {
      return "Fx_Sin_P3307_0_1_circuit";
    }
    case FixedPointOperationType::kSin_P3307_0_4_circuit: {
      return "Fx_Sin_P3307_0_4_circuit";
    }
    case FixedPointOperationType::kCos_P3508_circuit: {
      return "Fx_Cos_P3508_circuit";
    }
    case FixedPointOperationType::kAdd_agmw: {
      return "Fx_Add_agmw";
    }
    case FixedPointOperationType::kSub_agmw: {
      return "Fx_Sub_agmw";
    }
    case FixedPointOperationType::kMul_agmw: {
      return "Fx_Mul_agmw";
    }
    case FixedPointOperationType::kDiv_agmw: {
      return "Fx_Div_agmw";
    }
    case FixedPointOperationType::kDivConst_agmw: {
      return "Fx_DivConst_agmw";
    }
    case FixedPointOperationType::kLt_agmw: {
      return "Fx_Lt_agmw";
    }
    case FixedPointOperationType::kGt_agmw: {
      return "Fx_Gt_agmw";
    }
    case FixedPointOperationType::kRoundTowardsZero_agmw: {
      return "Fx_RoundTowardsZero_agmw";
    }
    case FixedPointOperationType::kFx2IntWithRoundTowardsZero_agmw: {
      return "Fx_Fx2IntWithRoundTowardsZero_agmw";
    }
    case FixedPointOperationType::kNeg_agmw: {
      return "Fx_Neg_agmw";
    }
    case FixedPointOperationType::kAbs_agmw: {
      return "Fx_Abs_agmw";
    }
    case FixedPointOperationType::kEq_agmw: {
      return "Fx_Eq_agmw";
    }
    case FixedPointOperationType::kEQZ_agmw: {
      return "Fx_EQZ_agmw";
    }
    case FixedPointOperationType::kLTZ_agmw: {
      return "Fx_LTZ_agmw";
    }
    case FixedPointOperationType::kExp2_P1045_agmw: {
      return "Fx_Exp2_P1045_agmw";
    }
    case FixedPointOperationType::kLog2_P2508_agmw: {
      return "Fx_Log2_P2508_agmw";
    }
    case FixedPointOperationType::kExp_agmw: {
      return "Fx_Exp_agmw";
    }
    case FixedPointOperationType::kLn_agmw: {
      return "Fx_Ln_agmw";
    }
    case FixedPointOperationType::kSqr_agmw: {
      return "Fx_Sqr_agmw";
    }
    case FixedPointOperationType::kSqrt_agmw: {
      return "Fx_Sqrt_agmw";
    }
    case FixedPointOperationType::kSqrt_P0132_agmw: {
      return "Fx_Sqrt_P0132_agmw";
    }
    case FixedPointOperationType::kCeil_agmw: {
      return "Fx_Ceil_agmw";
    }
    case FixedPointOperationType::kFloor_agmw: {
      return "Fx_Floor_agmw";
    }
    case FixedPointOperationType::kFx2Int_agmw: {
      return "Fx2Int_agmw";
    }
    case FixedPointOperationType::kFx2FL_agmw: {
      return "Fx_Fx2FL_agmw";
    }

    default:
      throw std::invalid_argument("Invalid FixedPointOperationType");
  }
}

}  // namespace encrypto::motion
