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

#include "benchmark_liangzhao_fixed_point_operation.h"

#include <openssl/rand.h>
#include <algorithm>
#include <limits>
#include <vector>
#include "algorithm/algorithm_description.h"
#include "protocols/share_wrapper.h"
// #include "secure_type/secure_fixed_point_agmw_CS.h"
#include "secure_type/secure_fixed_point_circuit_CBMC.h"
#include "secure_type/secure_unsigned_integer.h"
#include "statistics/analysis.h"
#include "statistics/run_time_statistics.h"
#include "utility/config.h"

template <typename T>
inline T Rand() {
  unsigned char buf[sizeof(T)];
  RAND_bytes(buf, sizeof(T));
  return *reinterpret_cast<T*>(buf);
}

template <typename T>
inline std::vector<T> RandomVector(std::size_t size) {
  std::vector<T> v(size);
  std::generate(v.begin(), v.end(), Rand<T>);
  return v;
}

namespace em = encrypto::motion;

em::RunTimeStatistics EvaluateProtocol(em::PartyPointer& party, std::size_t number_of_simd,
                                       std::size_t bit_size, em::MpcProtocol protocol,
                                       em::FixedPointOperationType operation_type) {
  em::SecureFixedPointCircuitCBMC fixed_point_boolean_gmw_share_CBMC_0;
  em::SecureFixedPointCircuitCBMC fixed_point_boolean_gmw_share_CBMC_1;

  em::SecureFixedPointCircuitCBMC fixed_point_bmr_share_CBMC_0;
  em::SecureFixedPointCircuitCBMC fixed_point_bmr_share_CBMC_1;

  em::SecureFixedPointCircuitCBMC fixed_point_gc_share_CBMC_0;
  em::SecureFixedPointCircuitCBMC fixed_point_gc_share_CBMC_1;

  // em::SecureFixedPointAgmwCS fixed_point_agmw_CS_0;
  // em::SecureFixedPointAgmwCS fixed_point_agmw_CS_1;

  // std::size_t k_agmw = 41;
  // std::size_t f_agmw = 20;

  std::size_t k_bgmw_gc_bmr = 64;
  std::size_t f_bgmw_gc_bmr = 16;

  std::vector<double> vector_of_input_1 = rand_range_double_vector(0, 1, number_of_simd);
  std::vector<double> vector_of_input_2 = rand_range_double_vector(0, 1, number_of_simd);

  fixed_point_boolean_gmw_share_CBMC_0 =
      em::SecureFixedPointCircuitCBMC(party->In<em::MpcProtocol::kBooleanGmw>(
          em::FixedPointToInput<std::uint64_t, std::int64_t>(vector_of_input_1, f_bgmw_gc_bmr), 0));
  fixed_point_boolean_gmw_share_CBMC_1 =
      em::SecureFixedPointCircuitCBMC(party->In<em::MpcProtocol::kBooleanGmw>(
          em::FixedPointToInput<std::uint64_t, std::int64_t>(vector_of_input_2, f_bgmw_gc_bmr), 0));

  fixed_point_gc_share_CBMC_0 =
      em::SecureFixedPointCircuitCBMC(party->In<em::MpcProtocol::kGarbledCircuit>(
          em::FixedPointToInput<std::uint64_t, std::int64_t>(vector_of_input_1, f_bgmw_gc_bmr), 0));
  fixed_point_gc_share_CBMC_1 =
      em::SecureFixedPointCircuitCBMC(party->In<em::MpcProtocol::kGarbledCircuit>(
          em::FixedPointToInput<std::uint64_t, std::int64_t>(vector_of_input_2, f_bgmw_gc_bmr), 0));

  fixed_point_bmr_share_CBMC_0 = em::SecureFixedPointCircuitCBMC(party->In<em::MpcProtocol::kBmr>(
      em::FixedPointToInput<std::uint64_t, std::int64_t>(vector_of_input_1, f_bgmw_gc_bmr), 0));
  fixed_point_bmr_share_CBMC_1 = em::SecureFixedPointCircuitCBMC(party->In<em::MpcProtocol::kBmr>(
      em::FixedPointToInput<std::uint64_t, std::int64_t>(vector_of_input_2, f_bgmw_gc_bmr), 0));

  // fixed_point_agmw_CS_0 = em::SecureFixedPointAgmwCS(
  //     party->InFixedPoint<em::MpcProtocol::kArithmeticGmw>(vector_of_input_1, k_agmw, f_agmw,
  //     0));
  // fixed_point_agmw_CS_1 = em::SecureFixedPointAgmwCS(
  //     party->InFixedPoint<em::MpcProtocol::kArithmeticGmw>(vector_of_input_2, k_agmw, f_agmw,
  //     0));

  if (protocol == em::MpcProtocol::kBooleanGmw) {
    switch (operation_type) {
      case em::FixedPointOperationType::kAdd_circuit: {
        fixed_point_boolean_gmw_share_CBMC_0 + fixed_point_boolean_gmw_share_CBMC_1;
        break;
      }
      case em::FixedPointOperationType::kSub_circuit: {
        fixed_point_boolean_gmw_share_CBMC_0 - fixed_point_boolean_gmw_share_CBMC_1;
        break;
      }
      case em::FixedPointOperationType::kMul_circuit: {
        fixed_point_boolean_gmw_share_CBMC_0* fixed_point_boolean_gmw_share_CBMC_1;
        break;
      }
      case em::FixedPointOperationType::kDiv_circuit: {
        fixed_point_boolean_gmw_share_CBMC_0 / fixed_point_boolean_gmw_share_CBMC_1;
        break;
      }
      // case em::FixedPointOperationType::kDiv_Goldschmidt_circuit: {
      //   fixed_point_boolean_gmw_share_CBMC_0.Div_Goldschmidt(fixed_point_boolean_gmw_share_CBMC_1);
      //   break;
      // }
      case em::FixedPointOperationType::kLt_circuit: {
        fixed_point_boolean_gmw_share_CBMC_0 < fixed_point_boolean_gmw_share_CBMC_1;
        break;
      }
      case em::FixedPointOperationType::kGt_circuit: {
        fixed_point_boolean_gmw_share_CBMC_0 > fixed_point_boolean_gmw_share_CBMC_1;
        break;
      }
      case em::FixedPointOperationType::kEq_circuit: {
        fixed_point_boolean_gmw_share_CBMC_0 == fixed_point_boolean_gmw_share_CBMC_1;
        break;
      }
      case em::FixedPointOperationType::kIsZero_circuit: {
        fixed_point_boolean_gmw_share_CBMC_0.IsZero();
        break;
      }
      case em::FixedPointOperationType::kIsNeg_circuit: {
        fixed_point_boolean_gmw_share_CBMC_0.IsNeg();
        break;
      }
      case em::FixedPointOperationType::kExp2_P1045_circuit: {
        fixed_point_boolean_gmw_share_CBMC_0.Exp2_P1045();
        break;
      }
      case em::FixedPointOperationType::kExp2_P1045_Neg_0_1_circuit: {
        fixed_point_boolean_gmw_share_CBMC_0.Exp2_P1045_Neg_0_1();
        break;
      }
      case em::FixedPointOperationType::kExp_circuit: {
        fixed_point_boolean_gmw_share_CBMC_0.Exp();
        break;
      }
      case em::FixedPointOperationType::kLog2_P2508_circuit: {
        fixed_point_boolean_gmw_share_CBMC_0.Log2_P2508();
        break;
      }
      case em::FixedPointOperationType::kLn_circuit: {
        fixed_point_boolean_gmw_share_CBMC_0.Ln();
        break;
      }
      // case em::FixedPointOperationType::kSqr_circuit: {
      //   fixed_point_boolean_gmw_share_CBMC_0.Sqr();
      //   break;
      // }
      // case em::FixedPointOperationType::kSqrt_circuit: {
      //   fixed_point_boolean_gmw_share_CBMC_0.Sqrt();
      //   break;
      // }
      case em::FixedPointOperationType::kSqrt_P0132_circuit: {
        fixed_point_boolean_gmw_share_CBMC_0.Sqrt_P0132();
        break;
      }
      case em::FixedPointOperationType::kCeil_circuit: {
        fixed_point_boolean_gmw_share_CBMC_0.Ceil();
        break;
      }
      case em::FixedPointOperationType::kFloor_circuit: {
        fixed_point_boolean_gmw_share_CBMC_0.Floor();
        break;
      }
      case em::FixedPointOperationType::kFx2Int_circuit: {
        fixed_point_boolean_gmw_share_CBMC_0.Fx2Int(64);
        break;
      }
      case em::FixedPointOperationType::kFx2FL_circuit: {
        fixed_point_boolean_gmw_share_CBMC_0.Fx2FL(64);
        break;
      }
      case em::FixedPointOperationType::kNeg_circuit: {
        fixed_point_boolean_gmw_share_CBMC_0.Neg();
        break;
      }
      case em::FixedPointOperationType::kAbs_circuit: {
        fixed_point_boolean_gmw_share_CBMC_0.Abs();
        break;
      }
      case em::FixedPointOperationType::kRoundedFx2Int_circuit: {
        fixed_point_boolean_gmw_share_CBMC_0.RoundedFx2Int();
        break;
      }
      case em::FixedPointOperationType::kSin_P3307_0_1_circuit: {
        fixed_point_boolean_gmw_share_CBMC_0.Sin_P3307_0_1();
        break;
      }
      default:
        throw std::invalid_argument("Unknown operation type");
    }
  }

  else if (protocol == em::MpcProtocol::kBmr) {
    switch (operation_type) {
      case em::FixedPointOperationType::kAdd_circuit: {
        fixed_point_bmr_share_CBMC_0 + fixed_point_bmr_share_CBMC_1;
        break;
      }
      case em::FixedPointOperationType::kSub_circuit: {
        fixed_point_bmr_share_CBMC_0 - fixed_point_bmr_share_CBMC_1;
        break;
      }
      case em::FixedPointOperationType::kMul_circuit: {
        fixed_point_bmr_share_CBMC_0* fixed_point_bmr_share_CBMC_1;
        break;
      }
      case em::FixedPointOperationType::kDiv_circuit: {
        fixed_point_bmr_share_CBMC_0 / fixed_point_bmr_share_CBMC_1;
        break;
      }
      // case em::FixedPointOperationType::kDiv_Goldschmidt_circuit: {
      //   fixed_point_bmr_share_CBMC_0.Div_Goldschmidt(fixed_point_bmr_share_CBMC_1);
      //   break;
      // }
      case em::FixedPointOperationType::kLt_circuit: {
        fixed_point_bmr_share_CBMC_0 < fixed_point_bmr_share_CBMC_1;
        break;
      }
      case em::FixedPointOperationType::kGt_circuit: {
        fixed_point_bmr_share_CBMC_0 > fixed_point_bmr_share_CBMC_1;
        break;
      }
      case em::FixedPointOperationType::kEq_circuit: {
        fixed_point_bmr_share_CBMC_0 == fixed_point_bmr_share_CBMC_1;
        break;
      }
      case em::FixedPointOperationType::kIsZero_circuit: {
        fixed_point_bmr_share_CBMC_0.IsZero();
        break;
      }
      case em::FixedPointOperationType::kIsNeg_circuit: {
        fixed_point_bmr_share_CBMC_0.IsNeg();
        break;
      }
      case em::FixedPointOperationType::kExp2_P1045_circuit: {
        fixed_point_bmr_share_CBMC_0.Exp2_P1045();
        break;
      }
      case em::FixedPointOperationType::kExp2_P1045_Neg_0_1_circuit: {
        fixed_point_bmr_share_CBMC_0.Exp2_P1045_Neg_0_1();
        break;
      }
      case em::FixedPointOperationType::kExp_circuit: {
        fixed_point_bmr_share_CBMC_0.Exp();
        break;
      }
      case em::FixedPointOperationType::kLog2_P2508_circuit: {
        fixed_point_bmr_share_CBMC_0.Log2_P2508();
        break;
      }
      case em::FixedPointOperationType::kLn_circuit: {
        fixed_point_bmr_share_CBMC_0.Ln();
        break;
      }
      // case em::FixedPointOperationType::kSqr_circuit: {
      //   fixed_point_bmr_share_CBMC_0.Sqr();
      //   break;
      // }
      // case em::FixedPointOperationType::kSqrt_circuit: {
      //   fixed_point_bmr_share_CBMC_0.Sqrt();
      //   break;
      // }
      case em::FixedPointOperationType::kSqrt_P0132_circuit: {
        fixed_point_bmr_share_CBMC_0.Sqrt_P0132();
        break;
      }
      case em::FixedPointOperationType::kCeil_circuit: {
        fixed_point_bmr_share_CBMC_0.Ceil();
        break;
      }
      case em::FixedPointOperationType::kFloor_circuit: {
        fixed_point_bmr_share_CBMC_0.Floor();
        break;
      }
      case em::FixedPointOperationType::kFx2Int_circuit: {
        fixed_point_bmr_share_CBMC_0.Fx2Int(64);
        break;
      }
      case em::FixedPointOperationType::kFx2FL_circuit: {
        fixed_point_bmr_share_CBMC_0.Fx2FL(64);
        break;
      }
      case em::FixedPointOperationType::kNeg_circuit: {
        fixed_point_bmr_share_CBMC_0.Neg();
        break;
      }
      case em::FixedPointOperationType::kAbs_circuit: {
        fixed_point_bmr_share_CBMC_0.Abs();
        break;
      }
      case em::FixedPointOperationType::kRoundedFx2Int_circuit: {
        fixed_point_bmr_share_CBMC_0.RoundedFx2Int();
        break;
      }
      case em::FixedPointOperationType::kSin_P3307_0_1_circuit: {
        fixed_point_bmr_share_CBMC_0.Sin_P3307_0_1();
        break;
      }
      default:
        throw std::invalid_argument("Unknown operation type");
    }
  }

  else if (protocol == em::MpcProtocol::kGarbledCircuit) {
    switch (operation_type) {
      case em::FixedPointOperationType::kAdd_circuit: {
        fixed_point_gc_share_CBMC_0 + fixed_point_gc_share_CBMC_1;
        break;
      }
      case em::FixedPointOperationType::kSub_circuit: {
        fixed_point_gc_share_CBMC_0 - fixed_point_gc_share_CBMC_1;
        break;
      }
      case em::FixedPointOperationType::kMul_circuit: {
        fixed_point_gc_share_CBMC_0* fixed_point_gc_share_CBMC_1;
        break;
      }
      case em::FixedPointOperationType::kDiv_circuit: {
        fixed_point_gc_share_CBMC_0 / fixed_point_gc_share_CBMC_1;
        break;
      }
      // case em::FixedPointOperationType::kDiv_Goldschmidt_circuit: {
      //   fixed_point_gc_share_CBMC_0.Div_Goldschmidt(fixed_point_gc_share_CBMC_1);
      //   break;
      // }
      case em::FixedPointOperationType::kLt_circuit: {
        fixed_point_gc_share_CBMC_0 < fixed_point_gc_share_CBMC_1;
        break;
      }
      case em::FixedPointOperationType::kGt_circuit: {
        fixed_point_gc_share_CBMC_0 > fixed_point_gc_share_CBMC_1;
        break;
      }
      case em::FixedPointOperationType::kEq_circuit: {
        fixed_point_gc_share_CBMC_0 == fixed_point_gc_share_CBMC_1;
        break;
      }
      case em::FixedPointOperationType::kIsZero_circuit: {
        fixed_point_gc_share_CBMC_0.IsZero();
        break;
      }
      case em::FixedPointOperationType::kIsNeg_circuit: {
        fixed_point_gc_share_CBMC_0.IsNeg();
        break;
      }
      case em::FixedPointOperationType::kExp2_P1045_circuit: {
        fixed_point_gc_share_CBMC_0.Exp2_P1045();
        break;
      }
      case em::FixedPointOperationType::kExp2_P1045_Neg_0_1_circuit: {
        fixed_point_gc_share_CBMC_0.Exp2_P1045_Neg_0_1();
        break;
      }
      case em::FixedPointOperationType::kExp_circuit: {
        fixed_point_gc_share_CBMC_0.Exp();
        break;
      }
      case em::FixedPointOperationType::kLog2_P2508_circuit: {
        fixed_point_gc_share_CBMC_0.Log2_P2508();
        break;
      }
      case em::FixedPointOperationType::kLn_circuit: {
        fixed_point_gc_share_CBMC_0.Ln();
        break;
      }
      // case em::FixedPointOperationType::kSqr_circuit: {
      //   fixed_point_gc_share_CBMC_0.Sqr();
      //   break;
      // }
      // case em::FixedPointOperationType::kSqrt_circuit: {
      //   fixed_point_gc_share_CBMC_0.Sqrt();
      //   break;
      // }
      case em::FixedPointOperationType::kSqrt_P0132_circuit: {
        fixed_point_gc_share_CBMC_0.Sqrt_P0132();
        break;
      }
      case em::FixedPointOperationType::kCeil_circuit: {
        fixed_point_gc_share_CBMC_0.Ceil();
        break;
      }
      case em::FixedPointOperationType::kFloor_circuit: {
        fixed_point_gc_share_CBMC_0.Floor();
        break;
      }
      case em::FixedPointOperationType::kFx2Int_circuit: {
        fixed_point_gc_share_CBMC_0.Fx2Int(64);
        break;
      }
      case em::FixedPointOperationType::kFx2FL_circuit: {
        fixed_point_gc_share_CBMC_0.Fx2FL(64);
        break;
      }
      case em::FixedPointOperationType::kNeg_circuit: {
        fixed_point_gc_share_CBMC_0.Neg();
        break;
      }
      case em::FixedPointOperationType::kAbs_circuit: {
        fixed_point_gc_share_CBMC_0.Abs();
        break;
      }
      case em::FixedPointOperationType::kRoundedFx2Int_circuit: {
        fixed_point_gc_share_CBMC_0.RoundedFx2Int();
        break;
      }
      case em::FixedPointOperationType::kSin_P3307_0_1_circuit: {
        fixed_point_gc_share_CBMC_0.Sin_P3307_0_1();
        break;
      }
      default:
        throw std::invalid_argument("Unknown operation type");
    }
  }

  // else if (protocol == em::MpcProtocol::kArithmeticGmw) {
  //   switch (operation_type) {
  //     case em::FixedPointOperationType::kAdd_agmw: {
  //       fixed_point_agmw_CS_0 + fixed_point_agmw_CS_1;
  //       break;
  //     }
  //     case em::FixedPointOperationType::kSub_agmw: {
  //       fixed_point_agmw_CS_0 - fixed_point_agmw_CS_1;
  //       break;
  //     }
  //     case em::FixedPointOperationType::kMul_agmw: {
  //       fixed_point_agmw_CS_0* fixed_point_agmw_CS_1;
  //       break;
  //     }
  //     case em::FixedPointOperationType::kDiv_agmw: {
  //       fixed_point_agmw_CS_0 / fixed_point_agmw_CS_1;
  //       break;
  //     }
  //     // case em::FixedPointOperationType::kDivConst_agmw: {
  //     //   fixed_point_agmw_CS_0.DivConst(3);
  //     //   break;
  //     // }
  //     case em::FixedPointOperationType::kLt_agmw: {
  //       fixed_point_agmw_CS_0 < fixed_point_agmw_CS_1;
  //       break;
  //     }
  //     case em::FixedPointOperationType::kGt_agmw: {
  //       fixed_point_agmw_CS_0 > fixed_point_agmw_CS_1;
  //       break;
  //     }
  //     case em::FixedPointOperationType::kRoundTowardsZero_agmw: {
  //       fixed_point_agmw_CS_0.RoundTowardsZero();
  //       break;
  //     }
  //     case em::FixedPointOperationType::kFx2IntWithRoundTowardsZero_agmw: {
  //       fixed_point_agmw_CS_0.Fx2IntWithRoundTowardsZero();
  //       break;
  //     }
  //     case em::FixedPointOperationType::kNeg_agmw: {
  //       fixed_point_agmw_CS_0.Neg();
  //       break;
  //     }
  //     case em::FixedPointOperationType::kAbs_agmw: {
  //       fixed_point_agmw_CS_0.Abs();
  //       break;
  //     }
  //     case em::FixedPointOperationType::kEq_agmw: {
  //       fixed_point_agmw_CS_0 == fixed_point_agmw_CS_1;
  //       break;
  //     }
  //     case em::FixedPointOperationType::kEQZ_agmw: {
  //       fixed_point_agmw_CS_0.EQZ();
  //       break;
  //     }
  //     case em::FixedPointOperationType::kLTZ_agmw: {
  //       fixed_point_agmw_CS_0.LTZ();
  //       break;
  //     }
  //     case em::FixedPointOperationType::kExp2_P1045_agmw: {
  //       fixed_point_agmw_CS_0.Exp2_P1045();
  //       break;
  //     }
  //     case em::FixedPointOperationType::kLog2_P2508_agmw: {
  //       fixed_point_agmw_CS_0.Log2_P2508();
  //       break;
  //     }
  //     case em::FixedPointOperationType::kExp_agmw: {
  //       fixed_point_agmw_CS_0.Exp();
  //       break;
  //     }
  //     case em::FixedPointOperationType::kLn_agmw: {
  //       fixed_point_agmw_CS_0.Ln();
  //       break;
  //     }
  //     // case em::FixedPointOperationType::kSqrt_agmw: {
  //     //   fixed_point_agmw_CS_0.Sqrt();
  //     //   break;
  //     // }
  //     case em::FixedPointOperationType::kSqrt_P0132_agmw: {
  //       fixed_point_agmw_CS_0.Sqrt_P0132();
  //       break;
  //     }
  //     case em::FixedPointOperationType::kFx2FL_agmw: {
  //       fixed_point_agmw_CS_0.Fx2FL(64, 53, 11);
  //       break;
  //     }
  //     default:
  //       throw std::invalid_argument("Unknown operation type");
  //   }
  // }

  else {
    throw std::invalid_argument("Invalid MPC protocol");
  }

  party->Run();
  party->Finish();
  const auto& statistics = party->GetBackend()->GetRunTimeStatistics();
  return statistics.front();
}