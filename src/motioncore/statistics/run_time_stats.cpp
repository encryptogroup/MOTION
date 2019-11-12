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
#include "run_time_stats.h"

namespace MOTION {
namespace Statistics {

static double compute_ms(const RunTimeStats::time_point_pair& tpp) {
  std::chrono::duration<double, std::milli> ms = tpp.second - tpp.first;
  return ms.count();
}

const RunTimeStats::time_point_pair& RunTimeStats::get(StatID id) const {
  return data_.at(static_cast<std::size_t>(id));
}

template <typename C>
typename C::value_type at(const C& container, RunTimeStats::StatID id) {
  return container.at(static_cast<std::size_t>(id));
}

std::string RunTimeStats::print_human_readable() const {
  std::array<double, std::tuple_size_v<decltype(data_)>> ms;
  std::transform(data_.cbegin(), data_.cend(), ms.begin(), compute_ms);
  auto max = *std::max_element(ms.cbegin(), ms.cend());
  auto width = static_cast<std::size_t>(std::ceil(std::log10(max))) + 4;

  std::stringstream ss;
  ss << fmt::format("MT Presetup         {:{}.3f} ms\n", at(ms, StatID::mt_presetup), width)
     << fmt::format("MT Setup            {:{}.3f} ms\n", at(ms, StatID::mt_setup), width)
     << fmt::format("SP Presetup         {:{}.3f} ms\n", at(ms, StatID::sp_presetup), width)
     << fmt::format("SP Setup            {:{}.3f} ms\n", at(ms, StatID::sp_setup), width)
     << fmt::format("SB Presetup         {:{}.3f} ms\n", at(ms, StatID::sb_presetup), width)
     << fmt::format("SB Setup            {:{}.3f} ms\n", at(ms, StatID::sb_setup), width)
     << fmt::format("OT Extension Setup  {:{}.3f} ms\n", at(ms, StatID::ot_extension_setup), width)
     << fmt::format("-------------------------\n")
     << fmt::format("Preprocessing Total {:{}.3f} ms\n", at(ms, StatID::preprocessing), width)
     << fmt::format("Gates Setup         {:{}.3f} ms\n", at(ms, StatID::gates_setup), width)
     << fmt::format("Gates Online        {:{}.3f} ms\n", at(ms, StatID::gates_online), width)
     << fmt::format("-------------------------\n")
     << fmt::format("Circuit Evaluation  {:{}.3f} ms\n", at(ms, StatID::evaluate), width);
  return ss.str();
}

}  // namespace Statistics
}  // namespace MOTION
