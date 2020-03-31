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
#include "wire/boolean_gmw_wire.h"
#include "wire/bmr_wire.h"

static void check_correctness(MOTION::Shares::SharePtr output) {
  // #!/usr/bin/env python3
  // import pyaes
  // ct = pyaes.AES(bytes(16)).encrypt(bytes(16))
  // print(''.join(f'{b:08b}'[::-1] for b in reversed(ct)))
  const auto correct_bits =
      "01110100110101000010110001010011100110100101111100110010000100011101110000110100010100011111"
      "011100101011110100101001011101100110";
  auto wires = output->GetWires();
  auto num_simd = wires.at(0)->GetNumOfSIMDValues();
  auto protocol = wires.at(0)->GetProtocol();
  for (std::size_t i = 0; i < 128; ++i) {
    ENCRYPTO::BitVector<> values;
    if (protocol == MOTION::MPCProtocol::BooleanGMW) {
      auto w = std::dynamic_pointer_cast<MOTION::Wires::GMWWire>(wires.at(i));
      values = std::move(w->GetMutableValues());
    } else if (protocol == MOTION::MPCProtocol::BMR) {
      auto w = std::dynamic_pointer_cast<MOTION::Wires::BMRWire>(wires.at(i));
      values = std::move(w->GetMutablePublicValues());
    }
    for (std::size_t j = 0; j < num_simd; ++j) {
      auto computed_bit = values.Get(j);
      if ((correct_bits[i] == '1') != computed_bit) {
        std::cerr << fmt::format("Computation not correct at output bit {} and SIMD value {}\n", i,
                                 j);
        std::exit(EXIT_FAILURE);
      }
    }
  }
}

MOTION::Statistics::RunTimeStats EvaluateProtocol(MOTION::PartyPtr& party, std::size_t num_simd,
                                                  MOTION::MPCProtocol protocol, bool check) {
  // TODO tests
  std::vector<ENCRYPTO::BitVector<>> tmp(256, ENCRYPTO::BitVector<>(num_simd));
  MOTION::Shares::ShareWrapper input{protocol == MOTION::MPCProtocol::BooleanGMW
                                         ? party->IN<MOTION::MPCProtocol::BooleanGMW>(tmp, 0)
                                         : party->IN<MOTION::MPCProtocol::BMR>(tmp, 0)};
  const auto algo_path{std::string(MOTION::MOTION_ROOT_DIR) + "/circuits/advanced/aes_128.bristol"};
  const auto aes_algo{ENCRYPTO::AlgorithmDescription::FromBristol(algo_path)};
  const auto result{input.Evaluate(aes_algo)};
  MOTION::Shares::SharePtr output = nullptr;
  if (check) {
    output = result.Out();
  }
  party->Run();
  party->Finish();
  if (check) {
    check_correctness(output);
  }
  const auto& stats = party->GetBackend()->GetRunTimeStats();
  return stats.front();
}
