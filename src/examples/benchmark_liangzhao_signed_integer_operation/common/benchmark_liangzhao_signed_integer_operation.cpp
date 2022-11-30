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

#include "benchmark_liangzhao_signed_integer_operation.h"

#include <openssl/rand.h>
#include <algorithm>
#include <limits>
#include <vector>
#include "algorithm/algorithm_description.h"
#include "protocols/share_wrapper.h"
// #include "secure_type/secure_floating_point_agmw_ABZS.h"
#include "secure_type/secure_floating_point_circuit_ABY.h"
#include "secure_type/secure_signed_integer.h"
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
                                       em::SignedIntegerOperationType operation_type) {
  using U8 = std::uint8_t;
  using U16 = std::uint16_t;
  using U32 = std::uint32_t;
  using U64 = std::uint64_t;
  using U128 = __uint128_t;

  std::size_t floating_point_bit_length = 64;
  std::size_t fraction_bit_size = 16;

  em::SecureSignedInteger a;
  em::SecureSignedInteger b;

  em::SecureSignedInteger signed_integer_boolean_gmw_share_0_U8;
  em::SecureSignedInteger signed_integer_boolean_gmw_share_1_U8;
  em::SecureSignedInteger signed_integer_boolean_gmw_share_0_U16;
  em::SecureSignedInteger signed_integer_boolean_gmw_share_1_U16;
  em::SecureSignedInteger signed_integer_boolean_gmw_share_0_U32;
  em::SecureSignedInteger signed_integer_boolean_gmw_share_1_U32;
  em::SecureSignedInteger signed_integer_boolean_gmw_share_0_U64;
  em::SecureSignedInteger signed_integer_boolean_gmw_share_1_U64;
  em::SecureSignedInteger signed_integer_boolean_gmw_share_0_U128;
  em::SecureSignedInteger signed_integer_boolean_gmw_share_1_U128;

  em::SecureSignedInteger signed_integer_gc_share_0_U8;
  em::SecureSignedInteger signed_integer_gc_share_1_U8;
  em::SecureSignedInteger signed_integer_gc_share_0_U16;
  em::SecureSignedInteger signed_integer_gc_share_1_U16;
  em::SecureSignedInteger signed_integer_gc_share_0_U32;
  em::SecureSignedInteger signed_integer_gc_share_1_U32;
  em::SecureSignedInteger signed_integer_gc_share_0_U64;
  em::SecureSignedInteger signed_integer_gc_share_1_U64;
  em::SecureSignedInteger signed_integer_gc_share_0_U128;
  em::SecureSignedInteger signed_integer_gc_share_1_U128;

  em::SecureSignedInteger signed_integer_bmr_share_0_U8;
  em::SecureSignedInteger signed_integer_bmr_share_1_U8;
  em::SecureSignedInteger signed_integer_bmr_share_0_U16;
  em::SecureSignedInteger signed_integer_bmr_share_1_U16;
  em::SecureSignedInteger signed_integer_bmr_share_0_U32;
  em::SecureSignedInteger signed_integer_bmr_share_1_U32;
  em::SecureSignedInteger signed_integer_bmr_share_0_U64;
  em::SecureSignedInteger signed_integer_bmr_share_1_U64;
  em::SecureSignedInteger signed_integer_bmr_share_0_U128;
  em::SecureSignedInteger signed_integer_bmr_share_1_U128;

  std::vector<U8> vector_of_input_U8 = RandomVector<U8>(number_of_simd);
  std::vector<U16> vector_of_input_U16 = RandomVector<U16>(number_of_simd);
  std::vector<U32> vector_of_input_U32 = RandomVector<U32>(number_of_simd);
  std::vector<U64> vector_of_input_U64 = RandomVector<U64>(number_of_simd);
  std::vector<U128> vector_of_input_U128 = RandomVector<U128>(number_of_simd);

  signed_integer_boolean_gmw_share_0_U8 = em::SecureSignedInteger(
      party->In<em::MpcProtocol::kBooleanGmw>(em::ToInput<U8>(vector_of_input_U8), 0));
  signed_integer_boolean_gmw_share_1_U8 = em::SecureSignedInteger(
      party->In<em::MpcProtocol::kBooleanGmw>(em::ToInput<U8>(vector_of_input_U8), 0));
  signed_integer_boolean_gmw_share_0_U16 = em::SecureSignedInteger(
      party->In<em::MpcProtocol::kBooleanGmw>(em::ToInput<U16>(vector_of_input_U16), 0));
  signed_integer_boolean_gmw_share_1_U16 = em::SecureSignedInteger(
      party->In<em::MpcProtocol::kBooleanGmw>(em::ToInput<U16>(vector_of_input_U16), 0));
  signed_integer_boolean_gmw_share_0_U32 = em::SecureSignedInteger(
      party->In<em::MpcProtocol::kBooleanGmw>(em::ToInput<U32>(vector_of_input_U32), 0));
  signed_integer_boolean_gmw_share_1_U32 = em::SecureSignedInteger(
      party->In<em::MpcProtocol::kBooleanGmw>(em::ToInput<U32>(vector_of_input_U32), 0));
  signed_integer_boolean_gmw_share_0_U64 = em::SecureSignedInteger(
      party->In<em::MpcProtocol::kBooleanGmw>(em::ToInput<U64>(vector_of_input_U64), 0));
  signed_integer_boolean_gmw_share_1_U64 = em::SecureSignedInteger(
      party->In<em::MpcProtocol::kBooleanGmw>(em::ToInput<U64>(vector_of_input_U64), 0));
  signed_integer_boolean_gmw_share_0_U128 = em::SecureSignedInteger(
      party->In<em::MpcProtocol::kBooleanGmw>(em::ToInput<U128>(vector_of_input_U128), 0));
  signed_integer_boolean_gmw_share_1_U128 = em::SecureSignedInteger(
      party->In<em::MpcProtocol::kBooleanGmw>(em::ToInput<U128>(vector_of_input_U128), 0));

  signed_integer_gc_share_0_U8 = em::SecureSignedInteger(
      party->In<em::MpcProtocol::kGarbledCircuit>(em::ToInput<U8>(vector_of_input_U8), 0));
  signed_integer_gc_share_1_U8 = em::SecureSignedInteger(
      party->In<em::MpcProtocol::kGarbledCircuit>(em::ToInput<U8>(vector_of_input_U8), 0));
  signed_integer_gc_share_0_U16 = em::SecureSignedInteger(
      party->In<em::MpcProtocol::kGarbledCircuit>(em::ToInput<U16>(vector_of_input_U16), 0));
  signed_integer_gc_share_1_U16 = em::SecureSignedInteger(
      party->In<em::MpcProtocol::kGarbledCircuit>(em::ToInput<U16>(vector_of_input_U16), 0));
  signed_integer_gc_share_0_U32 = em::SecureSignedInteger(
      party->In<em::MpcProtocol::kGarbledCircuit>(em::ToInput<U32>(vector_of_input_U32), 0));
  signed_integer_gc_share_1_U32 = em::SecureSignedInteger(
      party->In<em::MpcProtocol::kGarbledCircuit>(em::ToInput<U32>(vector_of_input_U32), 0));
  signed_integer_gc_share_0_U64 = em::SecureSignedInteger(
      party->In<em::MpcProtocol::kGarbledCircuit>(em::ToInput<U64>(vector_of_input_U64), 0));
  signed_integer_gc_share_1_U64 = em::SecureSignedInteger(
      party->In<em::MpcProtocol::kGarbledCircuit>(em::ToInput<U64>(vector_of_input_U64), 0));
  signed_integer_gc_share_0_U128 = em::SecureSignedInteger(
      party->In<em::MpcProtocol::kGarbledCircuit>(em::ToInput<U128>(vector_of_input_U128), 0));
  signed_integer_gc_share_1_U128 = em::SecureSignedInteger(
      party->In<em::MpcProtocol::kGarbledCircuit>(em::ToInput<U128>(vector_of_input_U128), 0));

  signed_integer_bmr_share_0_U8 = em::SecureSignedInteger(
      party->In<em::MpcProtocol::kBmr>(em::ToInput<U8>(vector_of_input_U8), 0));
  signed_integer_bmr_share_1_U8 = em::SecureSignedInteger(
      party->In<em::MpcProtocol::kBmr>(em::ToInput<U8>(vector_of_input_U8), 0));
  signed_integer_bmr_share_0_U16 = em::SecureSignedInteger(
      party->In<em::MpcProtocol::kBmr>(em::ToInput<U16>(vector_of_input_U16), 0));
  signed_integer_bmr_share_1_U16 = em::SecureSignedInteger(
      party->In<em::MpcProtocol::kBmr>(em::ToInput<U16>(vector_of_input_U16), 0));
  signed_integer_bmr_share_0_U32 = em::SecureSignedInteger(
      party->In<em::MpcProtocol::kBmr>(em::ToInput<U32>(vector_of_input_U32), 0));
  signed_integer_bmr_share_1_U32 = em::SecureSignedInteger(
      party->In<em::MpcProtocol::kBmr>(em::ToInput<U32>(vector_of_input_U32), 0));
  signed_integer_bmr_share_0_U64 = em::SecureSignedInteger(
      party->In<em::MpcProtocol::kBmr>(em::ToInput<U64>(vector_of_input_U64), 0));
  signed_integer_bmr_share_1_U64 = em::SecureSignedInteger(
      party->In<em::MpcProtocol::kBmr>(em::ToInput<U64>(vector_of_input_U64), 0));
  signed_integer_bmr_share_0_U128 = em::SecureSignedInteger(
      party->In<em::MpcProtocol::kBmr>(em::ToInput<U128>(vector_of_input_U128), 0));
  signed_integer_bmr_share_1_U128 = em::SecureSignedInteger(
      party->In<em::MpcProtocol::kBmr>(em::ToInput<U128>(vector_of_input_U128), 0));

  if (protocol == encrypto::motion::MpcProtocol::kBooleanGmw) {
    switch (bit_size) {
      case 8: {
        a = signed_integer_boolean_gmw_share_0_U8;
        b = signed_integer_boolean_gmw_share_1_U8;
        break;
      }
      case 16: {
        a = signed_integer_boolean_gmw_share_0_U16;
        b = signed_integer_boolean_gmw_share_1_U16;
        break;
      }
      case 32: {
        a = signed_integer_boolean_gmw_share_0_U32;
        b = signed_integer_boolean_gmw_share_1_U32;
        break;
      }
      case 64: {
        a = signed_integer_boolean_gmw_share_0_U64;
        b = signed_integer_boolean_gmw_share_1_U64;
        break;
      }
      case 128: {
        a = signed_integer_boolean_gmw_share_0_U128;
        b = signed_integer_boolean_gmw_share_1_U128;
        break;
      }
      default:
        throw std::invalid_argument("Invalid bit size");
    }
  } else if (protocol == encrypto::motion::MpcProtocol::kBmr) {
    switch (bit_size) {
      case 8: {
        a = signed_integer_bmr_share_0_U8;
        b = signed_integer_bmr_share_1_U8;
        break;
      }
      case 16: {
        a = signed_integer_bmr_share_0_U16;
        b = signed_integer_bmr_share_1_U16;
        break;
      }
      case 32: {
        a = signed_integer_bmr_share_0_U32;
        b = signed_integer_bmr_share_1_U32;
        break;
      }
      case 64: {
        a = signed_integer_bmr_share_0_U64;
        b = signed_integer_bmr_share_1_U64;
        break;
      }
      case 128: {
        a = signed_integer_bmr_share_0_U128;
        b = signed_integer_bmr_share_1_U128;
        break;
      }
      default:
        throw std::invalid_argument("Invalid bit size");
    }
  } else if (protocol == encrypto::motion::MpcProtocol::kGarbledCircuit) {
    switch (bit_size) {
      case 8: {
        a = signed_integer_gc_share_0_U8;
        b = signed_integer_gc_share_1_U8;
        break;
      }
      case 16: {
        a = signed_integer_gc_share_0_U16;
        b = signed_integer_gc_share_1_U16;
        break;
      }
      case 32: {
        a = signed_integer_gc_share_0_U32;
        b = signed_integer_gc_share_1_U32;
        break;
      }
      case 64: {
        a = signed_integer_gc_share_0_U64;
        b = signed_integer_gc_share_1_U64;
        break;
      }
      case 128: {
        a = signed_integer_gc_share_0_U128;
        b = signed_integer_gc_share_1_U128;
        break;
      }
      default:
        throw std::invalid_argument("Invalid bit size");
    }
  } else {
    throw std::invalid_argument("Invalid MPC protocol");
  }

  if (bit_size == 8 || bit_size == 16) {
    switch (operation_type) {
      case em::SignedIntegerOperationType::kAdd: {
        a + b;
        break;
      }
      case em::SignedIntegerOperationType::kSub: {
        a - b;
        break;
      }
      case em::SignedIntegerOperationType::kMul: {
        a* b;
        break;
      }
      case em::SignedIntegerOperationType::kDiv: {
        a / b;
        break;
      }
      case em::SignedIntegerOperationType::kLt: {
        a < b;
        break;
      }
      case em::SignedIntegerOperationType::kGt: {
        a > b;
        break;
      }
      case em::SignedIntegerOperationType::kEq: {
        a == b;
        break;
      }
      case em::SignedIntegerOperationType::kIsZero: {
        a.IsZero();
        break;
      }
      case em::SignedIntegerOperationType::kIsNeg: {
        a.IsNeg();
        break;
      }
      case em::SignedIntegerOperationType::kNeg: {
        a.Neg();
        break;
      }
      case em::SignedIntegerOperationType::kGE: {
        a.GE(b);
        break;
      }
      case em::SignedIntegerOperationType::kLE: {
        a.LE(b);
        break;
      }
      case em::SignedIntegerOperationType::kInRange: {
        a.InRange(b);
        break;
      }
      default:
        throw std::invalid_argument("Unknown operation type");
    }
  }

  else if (bit_size == 32 || bit_size == 64 || bit_size == 128) {
    switch (operation_type) {
      case em::SignedIntegerOperationType::kAdd: {
        a + b;
        break;
      }
      case em::SignedIntegerOperationType::kSub: {
        a - b;
        break;
      }
      case em::SignedIntegerOperationType::kMul: {
        a* b;
        break;
      }
      case em::SignedIntegerOperationType::kDiv: {
        a / b;
        break;
      }
      case em::SignedIntegerOperationType::kLt: {
        a < b;
        break;
      }
      case em::SignedIntegerOperationType::kGt: {
        a > b;
        break;
      }
      case em::SignedIntegerOperationType::kEq: {
        a == b;
        break;
      }
      case em::SignedIntegerOperationType::kIsZero: {
        a.IsZero();
        break;
      }
      case em::SignedIntegerOperationType::kIsNeg: {
        a.IsNeg();
        break;
      }
      case em::SignedIntegerOperationType::kNeg: {
        a.Neg();
        break;
      }
      case em::SignedIntegerOperationType::kInt2FL: {
        a.Int2FL(floating_point_bit_length);
        break;
      }
      case em::SignedIntegerOperationType::kInt2Fx: {
        a.Int2Fx(fraction_bit_size);
        break;
      }
      case em::SignedIntegerOperationType::kGE: {
        a.GE(b);
        break;
      }
      case em::SignedIntegerOperationType::kLE: {
        a.LE(b);
        break;
      }
      case em::SignedIntegerOperationType::kInRange: {
        a.InRange(b);
        break;
      }
      default:
        throw std::invalid_argument("Unknown operation type");
    }
  } else {
    throw std::invalid_argument("Invalid bit size");
  }

  party->Run();
  party->Finish();
  const auto& statistics = party->GetBackend()->GetRunTimeStatistics();
  return statistics.front();
}