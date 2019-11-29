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
#include <utility>

namespace MOTION {
namespace Statistics {

struct RunTimeStats {
  using clock_type = std::chrono::steady_clock;
  using time_point = std::chrono::time_point<clock_type>;
  using time_point_pair = std::pair<time_point, time_point>;

  enum class StatID : std::size_t {
    mt_presetup,
    mt_setup,
    sb_presetup,
    sb_setup,
    sp_presetup,
    sp_setup,
    ot_extension_setup,
    preprocessing,  // MTs, OTs etc.
    gates_setup,
    gates_online,
    evaluate,
    base_ots,
    MAX  // maximal value of this Enum, use as size
  };

  time_point get_time() { return clock_type::now(); }

  template <StatID ID>
  void record_start() {
    data_[static_cast<std::size_t>(ID)].first = clock_type::now();
    // data_.at(static_cast<std::size_t>(ID)).first = clock_type::now();
  }

  template <StatID ID>
  void record_end() {
    data_[static_cast<std::size_t>(ID)].second = clock_type::now();
    // data_.at(static_cast<std::size_t>(ID)).second = clock_type::now();
  }

  const time_point_pair& get(StatID id) const;

  std::string print_human_readable() const;

  std::array<time_point_pair, static_cast<std::size_t>(StatID::MAX) + 1> data_;
};

}  // namespace Statistics
}  // namespace MOTION
