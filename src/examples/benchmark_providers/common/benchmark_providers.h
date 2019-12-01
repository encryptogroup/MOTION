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

#include "base/party.h"
#include "statistics/run_time_stats.h"
#include "utility/typedefs.h"

enum Provider : std::size_t {
  AMT = 0,
  BMT = 1,
  GOT = 2,
  XCOT = 3,
  ACOT = 4,
  ROT = 5,
  SB = 6,
  SP = 7
};

constexpr std::array PROVIDER_NAME{"AMT", "BMT", "GOT", "XCOT", "ACOT", "ROT", "SB", "SP"};

inline std::string ToString(Provider p) { return PROVIDER_NAME[p]; }

MOTION::Statistics::RunTimeStats BenchmarkProvider(MOTION::PartyPtr& party, std::size_t batch_size,
                                                  Provider provider, std::size_t bit_size = 0);
