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

#include <fmt/format.h>
#include <cmath>
#include <sstream>
#include "analysis.h"

namespace MOTION {
namespace Statistics {

static double compute_duration(const RunTimeStats::time_point_pair& tpp) {
  std::chrono::duration<double, AccumulatedRunTimeStats::resolution> d = tpp.second - tpp.first;
  return d.count();
}

void AccumulatedRunTimeStats::add(const RunTimeStats& stats) {
  for (std::size_t i = 0; i <= static_cast<std::size_t>(RunTimeStats::StatID::MAX); ++i) {
    accumulators_[i](compute_duration(stats.data_[i]));
  }
  ++count_;
}

template <typename C>
static typename C::value_type at(const C& container, RunTimeStats::StatID id) {
  return container.at(static_cast<std::size_t>(id));
}

using StatID = RunTimeStats::StatID;

static std::string format_line(std::string name, std::string unit,
                               AccumulatedRunTimeStats::accumulator_type accumulator,
                               std::size_t field_width) {
  std::stringstream ss;
  ss << fmt::format("{:19s} ", name);
  ss << fmt::format("{:{}.3f} {:s} ", boost::accumulators::mean(accumulator), field_width, unit);
  ss << fmt::format("{:{}.3f} {:s} ", boost::accumulators::median(accumulator), field_width, unit);
  // uncorrected standard deviation
  ss << fmt::format("{:{}.3f} {:s}", std::sqrt(boost::accumulators::variance(accumulator)),
                    field_width, unit);
  ss << "\n";
  return ss.str();
}

std::string AccumulatedRunTimeStats::print_human_readable() const {
  std::size_t field_width = 10;
  std::stringstream ss;
  std::string unit = "ms";

  ss << "===========================================================================\n"
     << fmt::format("Run time statistics over {} iterations\n", count_)
     << "---------------------------------------------------------------------------\n"
     << fmt::format("                    {:>{}s}    {:>{}s}    {:>{}s}\n", "mean", field_width,
                    "median", field_width, "stddev", field_width)
     << "---------------------------------------------------------------------------\n"
     << format_line("MT Presetup", unit, at(accumulators_, StatID::mt_presetup), field_width)
     << format_line("MT Setup", unit, at(accumulators_, StatID::mt_setup), field_width)
     << format_line("SP Presetup", unit, at(accumulators_, StatID::sp_presetup), field_width)
     << format_line("SP Setup", unit, at(accumulators_, StatID::sp_setup), field_width)
     << format_line("SB Presetup", unit, at(accumulators_, StatID::sb_presetup), field_width)
     << format_line("SB Setup", unit, at(accumulators_, StatID::sb_setup), field_width)
     << format_line("OT Extension Setup", unit, at(accumulators_, StatID::ot_extension_setup),
                    field_width)
     << "---------------------------------------------------------------------------\n"
     << format_line("Preprocessing Total", unit, at(accumulators_, StatID::preprocessing),
                    field_width)
     << format_line("Gates Setup", unit, at(accumulators_, StatID::gates_setup), field_width)
     << format_line("Gates Online", unit, at(accumulators_, StatID::gates_online), field_width)
     << "---------------------------------------------------------------------------\n"
     << format_line("Circuit Evaluation", unit, at(accumulators_, StatID::evaluate), field_width)
     << "===========================================================================\n";

  return ss.str();
}

}  // namespace Statistics
}  // namespace MOTION
