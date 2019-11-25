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

#include "aes128.h"

#include "algorithm/algorithm_description.h"
#include "share/share_wrapper.h"
#include "statistics/analysis.h"
#include "statistics/run_time_stats.h"
#include "utility/config.h"

MOTION::Statistics::RunTimeStats EvaluateProtocol(MOTION::PartyPtr& party, std::size_t num_simd,
                                                  MOTION::MPCProtocol protocol) {
  // TODO tests
  std::vector<ENCRYPTO::BitVector<>> tmp(256, ENCRYPTO::BitVector<>(num_simd));
  MOTION::Shares::ShareWrapper input{protocol == MOTION::MPCProtocol::BooleanGMW
                                         ? party->IN<MOTION::MPCProtocol::BooleanGMW>(tmp, 0)
                                         : party->IN<MOTION::MPCProtocol::BMR>(tmp, 0)};
  const auto algo_path{std::string(MOTION::MOTION_ROOT_DIR) + "/circuits/advanced/aes_128.bristol"};
  const auto aes_algo{ENCRYPTO::AlgorithmDescription::FromBristol(algo_path)};
  const auto result{input.Evaluate(aes_algo)};
  party->Run();
  party->Finish();
  const auto& stats = party->GetBackend()->GetRunTimeStats();
  return stats.front();
}
