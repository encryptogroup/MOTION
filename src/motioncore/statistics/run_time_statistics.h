// MIT License
//
// Copyright (c) 2019 Lennart Braun
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

#include <array>
#include <chrono>
#include <string>
#include <utility>

namespace encrypto::motion {

struct RunTimeStatistics {
  using ClockType = std::chrono::steady_clock;
  using TimePoint = std::chrono::time_point<ClockType>;
  using TimePointPair = std::pair<TimePoint, TimePoint>;

  enum class StatisticsId : std::size_t {
    kMtPresetup,
    kMtSetup,
    kSbPresetup,
    kSbSetup,
    kSpPresetup,
    kSpSetup,
    kOtExtensionSetup,
    kKK13OtExtensionSetup,
    kPreprocessing,  // MTs, OTs etc.
    kGatesSetup,
    kGatesOnline,
    kEvaluate,
    kBaseOts,
    kMax  // maximal value of this Enum, use as size
  };

  TimePoint GetTime() { return ClockType::now(); }

  template <StatisticsId Id>
  void RecordStart() {
    data[static_cast<std::size_t>(Id)].first = ClockType::now();
    // data.at(static_cast<std::size_t>(Id)).first = ClockType::now();
  }

  template <StatisticsId Id>
  void RecordEnd() {
    data[static_cast<std::size_t>(Id)].second = ClockType::now();
    // data.at(static_cast<std::size_t>(Id)).second = ClockType::now();
  }

  const TimePointPair& Get(StatisticsId id) const;

  std::string PrintHumanReadable() const;

  std::array<TimePointPair, static_cast<std::size_t>(StatisticsId::kMax) + 1> data;
};

}  // namespace encrypto::motion
