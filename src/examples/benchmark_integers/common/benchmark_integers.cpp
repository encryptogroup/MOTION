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

#include "benchmark_integers.h"

#include "algorithm/algorithm_description.h"
#include "protocols/share_wrapper.h"
#include "secure_type/secure_unsigned_integer.h"
#include "statistics/analysis.h"
#include "statistics/run_time_statistics.h"
#include "utility/config.h"

encrypto::motion::RunTimeStatistics EvaluateProtocol(
    encrypto::motion::PartyPointer& party, std::size_t number_of_simd, std::size_t bit_size,
    encrypto::motion::MpcProtocol protocol, encrypto::motion::IntegerOperationType operation_type) {
  const std::vector<encrypto::motion::BitVector<>> temporary_bool(
      bit_size, encrypto::motion::BitVector<>(number_of_simd));

  encrypto::motion::SecureUnsignedInteger a, b;

  switch (protocol) {
    case encrypto::motion::MpcProtocol::kBooleanGmw: {
      a = party->In<encrypto::motion::MpcProtocol::kBooleanGmw>(temporary_bool, 0);
      b = party->In<encrypto::motion::MpcProtocol::kBooleanGmw>(temporary_bool, 0);
      break;
    }
    case encrypto::motion::MpcProtocol::kBmr: {
      a = party->In<encrypto::motion::MpcProtocol::kBmr>(temporary_bool, 0);
      b = party->In<encrypto::motion::MpcProtocol::kBmr>(temporary_bool, 0);
      break;
    }
    default:
      throw std::invalid_argument("Invalid MPC protocol");
  }

  switch (operation_type) {
    case encrypto::motion::IntegerOperationType::kSub: {
      a - b;
      break;
    }
    case encrypto::motion::IntegerOperationType::kGt: {
      a > b;
      break;
    }
    case encrypto::motion::IntegerOperationType::kDiv: {
      a / b;
      break;
    }
    case encrypto::motion::IntegerOperationType::kMul: {
      a* b;
      break;
    }
    case encrypto::motion::IntegerOperationType::kAdd: {
      a + b;
      break;
    }
    case encrypto::motion::IntegerOperationType::kEq: {
      a == b;
      break;
    }

    default:
      throw std::invalid_argument("Unknown operation type");
  }

  party->Run();
  party->Finish();
  const auto& statistics = party->GetBackend()->GetRunTimeStatistics();
  return statistics.front();
}
