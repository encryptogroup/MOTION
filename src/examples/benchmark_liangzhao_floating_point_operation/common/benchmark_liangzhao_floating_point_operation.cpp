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

#include "benchmark_liangzhao_floating_point_operation.h"

#include <openssl/rand.h>
#include <algorithm>
#include <limits>
#include <vector>
#include "algorithm/algorithm_description.h"
#include "protocols/share_wrapper.h"
// #include "secure_type/secure_floating_point_agmw_ABZS.h"
#include "secure_type/secure_floating_point_circuit_ABY.h"
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
                                       em::FloatingPointOperationType operation_type) {
  em::SecureFloatingPointCircuitABY floating_point32_boolean_gmw_share_ABY_0;
  em::SecureFloatingPointCircuitABY floating_point32_boolean_gmw_share_ABY_1;
  // em::SecureFloatingPointCircuitABY floating_point32_gc_share_ABY_0;
  // em::SecureFloatingPointCircuitABY floating_point32_gc_share_ABY_1;
  em::SecureFloatingPointCircuitABY floating_point32_bmr_share_ABY_0;
  em::SecureFloatingPointCircuitABY floating_point32_bmr_share_ABY_1;

  em::SecureFloatingPointCircuitABY floating_point64_boolean_gmw_share_ABY_0;
  em::SecureFloatingPointCircuitABY floating_point64_boolean_gmw_share_ABY_1;
  // em::SecureFloatingPointCircuitABY floating_point64_gc_share_ABY_0;
  // em::SecureFloatingPointCircuitABY floating_point64_gc_share_ABY_1;
  em::SecureFloatingPointCircuitABY floating_point64_bmr_share_ABY_0;
  em::SecureFloatingPointCircuitABY floating_point64_bmr_share_ABY_1;

  em::SecureFloatingPointCircuitABY a;
  em::SecureFloatingPointCircuitABY b;

  // em::SecureFloatingPointAgmwABZS floating_point_agmw_ABZS_0;
  // em::SecureFloatingPointAgmwABZS floating_point_agmw_ABZS_1;

  std::size_t l = 53;
  std::size_t k = 11;

  std::size_t fixed_point_fraction_bit_size = 16;
  std::size_t integer_bit_length = 64;

  std::vector<float> vector_of_input_float = rand_range_float_vector(0, 1, number_of_simd);
  std::vector<double> vector_of_input_double = rand_range_double_vector(0, 1, number_of_simd);

  floating_point32_boolean_gmw_share_ABY_0 =
      em::SecureFloatingPointCircuitABY(party->In<em::MpcProtocol::kBooleanGmw>(
          em::ToInput<float, std::true_type>(vector_of_input_float), 0));
  floating_point32_boolean_gmw_share_ABY_1 =
      em::SecureFloatingPointCircuitABY(party->In<em::MpcProtocol::kBooleanGmw>(
          em::ToInput<float, std::true_type>(vector_of_input_float), 0));
  // floating_point32_gc_share_ABY_0 =
  //     em::SecureFloatingPointCircuitABY(party->In<em::MpcProtocol::kGarbledCircuit>(
  //         em::ToInput<float, std::true_type>(vector_of_input_float), 0));
  // floating_point32_gc_share_ABY_1 =
  //     em::SecureFloatingPointCircuitABY(party->In<em::MpcProtocol::kGarbledCircuit>(
  //         em::ToInput<float, std::true_type>(vector_of_input_float), 0));
  floating_point32_bmr_share_ABY_0 =
      em::SecureFloatingPointCircuitABY(party->In<em::MpcProtocol::kBmr>(
          em::ToInput<float, std::true_type>(vector_of_input_float), 0));
  floating_point32_bmr_share_ABY_1 =
      em::SecureFloatingPointCircuitABY(party->In<em::MpcProtocol::kBmr>(
          em::ToInput<float, std::true_type>(vector_of_input_float), 0));

  floating_point64_boolean_gmw_share_ABY_0 =
      em::SecureFloatingPointCircuitABY(party->In<em::MpcProtocol::kBooleanGmw>(
          em::ToInput<double, std::true_type>(vector_of_input_double), 0));
  floating_point64_boolean_gmw_share_ABY_1 =
      em::SecureFloatingPointCircuitABY(party->In<em::MpcProtocol::kBooleanGmw>(
          em::ToInput<double, std::true_type>(vector_of_input_double), 0));
  // floating_point64_gc_share_ABY_0 =
  //     em::SecureFloatingPointCircuitABY(party->In<em::MpcProtocol::kGarbledCircuit>(
  //         em::ToInput<double, std::true_type>(vector_of_input_double), 0));
  // floating_point64_gc_share_ABY_1 =
  //     em::SecureFloatingPointCircuitABY(party->In<em::MpcProtocol::kGarbledCircuit>(
  //         em::ToInput<double, std::true_type>(vector_of_input_double), 0));
  floating_point64_bmr_share_ABY_0 =
      em::SecureFloatingPointCircuitABY(party->In<em::MpcProtocol::kBmr>(
          em::ToInput<double, std::true_type>(vector_of_input_double), 0));
  floating_point64_bmr_share_ABY_1 =
      em::SecureFloatingPointCircuitABY(party->In<em::MpcProtocol::kBmr>(
          em::ToInput<double, std::true_type>(vector_of_input_double), 0));

  // floating_point_agmw_ABZS_0 = em::SecureFloatingPointAgmwABZS(
  //     party->InFloatingPoint<em::MpcProtocol::kArithmeticGmw>(vector_of_input_double, l, k, 0));
  // floating_point_agmw_ABZS_1 = em::SecureFloatingPointAgmwABZS(
  //     party->InFloatingPoint<em::MpcProtocol::kArithmeticGmw>(vector_of_input_double, l, k, 0));

  if (protocol == em::MpcProtocol::kBooleanGmw) {
    switch (bit_size) {
      case 32: {
        a = floating_point32_boolean_gmw_share_ABY_0;
        b = floating_point32_boolean_gmw_share_ABY_1;
        break;
      }
      case 64: {
        a = floating_point64_boolean_gmw_share_ABY_0;
        b = floating_point64_boolean_gmw_share_ABY_1;
        break;
      }
    }
  }

  // else if (protocol == em::MpcProtocol::kGarbledCircuit) {
  //   switch (bit_size) {
  //     case 32: {
  //       a = floating_point32_gc_share_ABY_0;
  //       b = floating_point32_gc_share_ABY_1;
  //       break;
  //     }
  //     case 64: {
  //       a = floating_point64_gc_share_ABY_0;
  //       b = floating_point64_gc_share_ABY_1;
  //       break;
  //     }
  //   }
  // }

  else if (protocol == em::MpcProtocol::kBmr) {
    switch (bit_size) {
      case 32: {
        a = floating_point32_bmr_share_ABY_0;
        b = floating_point32_bmr_share_ABY_1;
        break;
      }
      case 64: {
        a = floating_point64_bmr_share_ABY_0;
        b = floating_point64_bmr_share_ABY_1;
        break;
      }
    }
  }

  if (protocol == em::MpcProtocol::kBooleanGmw || protocol == em::MpcProtocol::kBmr ||
      protocol == em::MpcProtocol::kGarbledCircuit) {
    switch (operation_type) {
      case em::FloatingPointOperationType::kAdd_circuit: {
        a + b;
        break;
      }
      case em::FloatingPointOperationType::kSub_circuit: {
        a - b;
        break;
      }
      case em::FloatingPointOperationType::kMul_circuit: {
        a* b;
        break;
      }
      case em::FloatingPointOperationType::kDiv_circuit: {
        a / b;
        break;
      }
      case em::FloatingPointOperationType::kLt_circuit: {
        a < b;
        break;
      }
      case em::FloatingPointOperationType::kGt_circuit: {
        a > b;
        break;
      }
      case em::FloatingPointOperationType::kEq_circuit: {
        a == b;
        break;
      }
      case em::FloatingPointOperationType::kNeg_circuit: {
        a.Neg();
        break;
      }
      case em::FloatingPointOperationType::kIsZero_circuit: {
        a.IsZero();
        break;
      }
      case em::FloatingPointOperationType::kIsNeg_circuit: {
        a.IsNeg();
        break;
      }
      case em::FloatingPointOperationType::kAbs_circuit: {
        a.Abs();
        break;
      }
      case em::FloatingPointOperationType::kExp2_circuit: {
        a.Exp2();
        break;
      }
      case em::FloatingPointOperationType::kExp_circuit: {
        a.Exp();
        break;
      }
      case em::FloatingPointOperationType::kLog2_circuit: {
        a.Log2();
        break;
      }
      case em::FloatingPointOperationType::kLn_circuit: {
        a.Ln();
        break;
      }
      case em::FloatingPointOperationType::kSqr_circuit: {
        a.Sqr();
        break;
      }
      case em::FloatingPointOperationType::kSqrt_circuit: {
        a.Sqrt();
        break;
      }
      case em::FloatingPointOperationType::kSin_circuit: {
        a.Sin();
        break;
      }
      case em::FloatingPointOperationType::kCos_circuit: {
        a.Cos();
        break;
      }
      case em::FloatingPointOperationType::kCeil_circuit: {
        a.Ceil();
        break;
      }
      case em::FloatingPointOperationType::kFloor_circuit: {
        a.Floor();
        break;
      }
      case em::FloatingPointOperationType::kFL2Int_circuit: {
        a.FL2Int(integer_bit_length);
        break;
      }
      case em::FloatingPointOperationType::kFL2Fx_circuit: {
        a.FL2Fx(fixed_point_fraction_bit_size);
        break;
      }
      case em::FloatingPointOperationType::kMulPow2m_circuit: {
        a.MulPow2m(1);
        break;
      }
      case em::FloatingPointOperationType::kDivPow2m_circuit: {
        a.DivPow2m(1);
        break;
      }
      case em::FloatingPointOperationType::kClampB_circuit: {
        a.ClampB(1.0);
        break;
      }
      case em::FloatingPointOperationType::kRoundToNearestInt_circuit: {
        a.RoundToNearestInteger();
        break;
      }
      default:
        throw std::invalid_argument("Unknown operation type");
    }
  }

  // // test simd only with boolean circuit based methods
  // else if (protocol == em::MpcProtocol::kArithmeticGmw) {
  //   switch (operation_type) {
  //     case em::FloatingPointOperationType::kAdd_agmw: {
  //       floating_point_agmw_ABZS_0 + floating_point_agmw_ABZS_1;
  //       break;
  //     }
  //     case em::FloatingPointOperationType::kSub_agmw: {
  //       floating_point_agmw_ABZS_0 - floating_point_agmw_ABZS_1;
  //       break;
  //     }
  //     case em::FloatingPointOperationType::kMul_agmw: {
  //       floating_point_agmw_ABZS_0* floating_point_agmw_ABZS_1;
  //       break;
  //     }
  //     case em::FloatingPointOperationType::kDiv_agmw: {
  //       floating_point_agmw_ABZS_0 / floating_point_agmw_ABZS_1;
  //       break;
  //     }
  //     case em::FloatingPointOperationType::kLt_agmw: {
  //       floating_point_agmw_ABZS_0 < floating_point_agmw_ABZS_1;
  //       break;
  //     }
  //     case em::FloatingPointOperationType::kGt_agmw: {
  //       floating_point_agmw_ABZS_0 > floating_point_agmw_ABZS_1;
  //       break;
  //     }
  //     case em::FloatingPointOperationType::kEq_agmw: {
  //       floating_point_agmw_ABZS_0 == floating_point_agmw_ABZS_1;
  //       break;
  //     }
  //     case em::FloatingPointOperationType::kEQZ_agmw: {
  //       floating_point_agmw_ABZS_0.EQZ();
  //       break;
  //     }
  //     case em::FloatingPointOperationType::kLTZ_agmw: {
  //       floating_point_agmw_ABZS_0.LTZ();
  //       break;
  //     }
  //     case em::FloatingPointOperationType::kExp2_agmw: {
  //       floating_point_agmw_ABZS_0.Exp2();
  //       break;
  //     }
  //     case em::FloatingPointOperationType::kLog2_agmw: {
  //       floating_point_agmw_ABZS_0.Log2();
  //       break;
  //     }
  //     case em::FloatingPointOperationType::kExp_agmw: {
  //       floating_point_agmw_ABZS_0.Exp();
  //       break;
  //     }
  //     case em::FloatingPointOperationType::kLn_agmw: {
  //       floating_point_agmw_ABZS_0.Ln();
  //       break;
  //     }
  //     case em::FloatingPointOperationType::kSqrt_agmw: {
  //       floating_point_agmw_ABZS_0.Sqrt();
  //       break;
  //     }
  //     case em::FloatingPointOperationType::kCeil_agmw: {
  //       floating_point_agmw_ABZS_0.Ceil();
  //       break;
  //     }
  //     case em::FloatingPointOperationType::kFloor_agmw: {
  //       floating_point_agmw_ABZS_0.Floor();
  //       break;
  //     }
  //     case em::FloatingPointOperationType::kNeg_agmw: {
  //       floating_point_agmw_ABZS_0.Neg();
  //       break;
  //     }
  //     case em::FloatingPointOperationType::kFL2Int_agmw: {
  //       floating_point_agmw_ABZS_0.FL2Int<__uint128_t, __uint128_t>();
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