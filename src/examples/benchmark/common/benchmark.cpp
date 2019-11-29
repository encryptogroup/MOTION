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

#include "benchmark.h"

#include "algorithm/algorithm_description.h"
#include "share/share_wrapper.h"
#include "statistics/analysis.h"
#include "statistics/run_time_stats.h"
#include "utility/config.h"

MOTION::Statistics::RunTimeStats EvaluateProtocol(MOTION::PartyPtr& party, std::size_t num_simd,
                                                  std::size_t bit_size,
                                                  MOTION::MPCProtocol protocol,
                                                  ENCRYPTO::PrimitiveOperationType op_type) {
  const std::vector<ENCRYPTO::BitVector<>> tmp_bool(bit_size, ENCRYPTO::BitVector<>(num_simd));

  MOTION::Shares::ShareWrapper a, b;

  switch (protocol) {
    case MOTION::MPCProtocol::BooleanGMW: {
      a = party->IN<MOTION::MPCProtocol::BooleanGMW>(tmp_bool, 0);
      b = party->IN<MOTION::MPCProtocol::BooleanGMW>(tmp_bool, 0);
      break;
    }
    case MOTION::MPCProtocol::BMR: {
      a = party->IN<MOTION::MPCProtocol::BMR>(tmp_bool, 0);
      b = party->IN<MOTION::MPCProtocol::BMR>(tmp_bool, 0);
      break;
    }
    case MOTION::MPCProtocol::ArithmeticGMW: {
      switch (bit_size) {
        case 8u: {
          std::vector<std::uint8_t> tmp_arith(num_simd);
          a = party->IN<MOTION::MPCProtocol::ArithmeticGMW>(tmp_arith, 0);
          b = party->IN<MOTION::MPCProtocol::ArithmeticGMW>(tmp_arith, 0);
          break;
        }
        case 16u: {
          std::vector<std::uint8_t> tmp_arith(num_simd);
          a = party->IN<MOTION::MPCProtocol::ArithmeticGMW>(tmp_arith, 0);
          b = party->IN<MOTION::MPCProtocol::ArithmeticGMW>(tmp_arith, 0);
          break;
        }
        case 32u: {
          std::vector<std::uint8_t> tmp_arith(num_simd);
          a = party->IN<MOTION::MPCProtocol::ArithmeticGMW>(tmp_arith, 0);
          b = party->IN<MOTION::MPCProtocol::ArithmeticGMW>(tmp_arith, 0);
          break;
        }
        case 64u: {
          std::vector<std::uint8_t> tmp_arith(num_simd);
          a = party->IN<MOTION::MPCProtocol::ArithmeticGMW>(tmp_arith, 0);
          b = party->IN<MOTION::MPCProtocol::ArithmeticGMW>(tmp_arith, 0);
          break;
        }
        default:
          throw std::invalid_argument("Invalid bit size");
      }
      break;
    }
    default:
      throw std::invalid_argument("Invalid MPC protocol");
  }

  switch (op_type) {
    case ENCRYPTO::PrimitiveOperationType::XOR: {
      a ^ b;
      break;
    }
    case ENCRYPTO::PrimitiveOperationType::AND: {
      a& b;
      break;
    }
    case ENCRYPTO::PrimitiveOperationType::MUX: {
      const std::vector<ENCRYPTO::BitVector<>> tmp_s(1, ENCRYPTO::BitVector<>(num_simd));
      MOTION::Shares::ShareWrapper sel{protocol == MOTION::MPCProtocol::BooleanGMW
                                           ? party->IN<MOTION::MPCProtocol::BooleanGMW>(tmp_s, 0)
                                           : party->IN<MOTION::MPCProtocol::BMR>(tmp_s, 0)};
      sel.MUX(a, b);
      break;
    }
    case ENCRYPTO::PrimitiveOperationType::INV: {
      ~a;
      break;
    }
    case ENCRYPTO::PrimitiveOperationType::OR: {
      a | b;
      break;
    }
    case ENCRYPTO::PrimitiveOperationType::ADD: {
      a + b;
      break;
    }
    case ENCRYPTO::PrimitiveOperationType::MUL: {
      a* b;
      break;
    }
    default:
      throw std::invalid_argument("Unknown operation type");
  }

  party->Run();
  party->Finish();
  const auto& stats = party->GetBackend()->GetRunTimeStats();
  return stats.front();
}
