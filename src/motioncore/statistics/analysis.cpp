// MIT License
//
// Copyright (c) 2019-2021 Lennart Braun, Arianne Roselina Prananto
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

#include "analysis.h"

#include <cmath>
#include <iostream>
#include <sstream>

#include <fmt/format.h>

#include "communication/transport.h"
#include "utility/runtime_info.h"
#include "utility/version.h"

namespace encrypto::motion {

static double ComputeDuration(const RunTimeStatistics::TimePointPair& tpp) {
  std::chrono::duration<double, AccumulatedRunTimeStatistics::Resolution> d =
      tpp.second - tpp.first;
  return d.count();
}

void AccumulatedRunTimeStatistics::Add(const RunTimeStatistics& statistics) {
  for (std::size_t i = 0; i <= static_cast<std::size_t>(RunTimeStatistics::StatisticsId::kMax);
       ++i) {
    accumulators_[i](ComputeDuration(statistics.data[i]));
  }
  ++count_;
}

template <typename C>
static typename C::value_type At(const C& container, RunTimeStatistics::StatisticsId id) {
  return container.at(static_cast<std::size_t>(id));
}

using StatId = RunTimeStatistics::StatisticsId;

static std::string FormatLine(std::string name, std::string unit,
                              AccumulatedRunTimeStatistics::AccumulatorType accumulator,
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

std::string AccumulatedRunTimeStatistics::PrintHumanReadable() const {
  constexpr std::size_t kFieldWidth = 10;
  std::stringstream ss;
  std::string unit = "ms";

  ss << fmt::format("Run time statistics over {} iterations\n", count_)
     << "---------------------------------------------------------------------------\n"
     << fmt::format("                    {:>{}s}    {:>{}s}    {:>{}s}\n", "mean", kFieldWidth,
                    "median", kFieldWidth, "stddev", kFieldWidth)
     << "---------------------------------------------------------------------------\n"
     << FormatLine("MT Presetup", unit, At(accumulators_, StatId::kMtPresetup), kFieldWidth)
     << FormatLine("MT Setup", unit, At(accumulators_, StatId::kMtSetup), kFieldWidth)
     << FormatLine("SP Presetup", unit, At(accumulators_, StatId::kSpPresetup), kFieldWidth)
     << FormatLine("SP Setup", unit, At(accumulators_, StatId::kSpSetup), kFieldWidth)
     << FormatLine("SB Presetup", unit, At(accumulators_, StatId::kSbPresetup), kFieldWidth)
     << FormatLine("SB Setup", unit, At(accumulators_, StatId::kSbSetup), kFieldWidth)
     << FormatLine("Base OTs", unit, At(accumulators_, StatId::kBaseOts), kFieldWidth)
     << FormatLine("OT Extension Setup", unit, At(accumulators_, StatId::kOtExtensionSetup),
                   kFieldWidth)
     << FormatLine("KK13 OT Extension Setup", unit, At(accumulators_, StatId::kKK13OtExtensionSetup),
                   kFieldWidth)
     << "---------------------------------------------------------------------------\n"
     << FormatLine("Preprocessing Total", unit, At(accumulators_, StatId::kPreprocessing),
                   kFieldWidth)
     << FormatLine("Gates Setup", unit, At(accumulators_, StatId::kGatesSetup), kFieldWidth)
     << FormatLine("Gates Online", unit, At(accumulators_, StatId::kGatesOnline), kFieldWidth)
     << "---------------------------------------------------------------------------\n"
     << FormatLine("Circuit Evaluation", unit, At(accumulators_, StatId::kEvaluate), kFieldWidth);

  return ss.str();
}

boost::json::object AccumulatedRunTimeStatistics::ToJson() const {
  const auto make_triple = [this](const auto& stat_id) {
    const auto& acc = At(accumulators_, stat_id);
    return boost::json::object({{"mean", boost::accumulators::mean(acc)},
                                {"median", boost::accumulators::median(acc)},
                                // uncorrected standard deviation
                                {"stddev", std::sqrt(boost::accumulators::variance(acc))}});
  };
  return {{"repetitions", count_},
          {"mt_presetup", make_triple(StatId::kMtPresetup)},
          {"mt_setup", make_triple(StatId::kMtSetup)},
          {"sp_presetup", make_triple(StatId::kSpPresetup)},
          {"sp_setup", make_triple(StatId::kSpSetup)},
          {"sb_presetup", make_triple(StatId::kSbPresetup)},
          {"sb_setup", make_triple(StatId::kSbSetup)},
          {"base_ots", make_triple(StatId::kBaseOts)},
          {"ot_extension_setup", make_triple(StatId::kOtExtensionSetup)},
          {"kk13_ot_extension_setup", make_triple(StatId::kKK13OtExtensionSetup)},
          {"preprocessing", make_triple(StatId::kPreprocessing)},
          {"gates_setup", make_triple(StatId::kGatesSetup)},
          {"gates_online", make_triple(StatId::kGatesOnline)},
          {"evaluate", make_triple(StatId::kEvaluate)}};
}

void AccumulatedCommunicationStatistics::Add(const communication::TransportStatistics& statistics) {
  accumulators_[kIdxNumberOfMessagesSent](statistics.number_of_messages_sent);
  accumulators_[kIdxNumberOfMessagesReceived](statistics.number_of_messages_received);
  accumulators_[kIdxNumberOfBytesSent](statistics.number_of_bytes_sent);
  accumulators_[kIdxNumberOfBytesReceived](statistics.number_of_bytes_received);
  ++count_;
}

void AccumulatedCommunicationStatistics::Add(
    const std::vector<communication::TransportStatistics>& statistics) {
  for (const auto& s : statistics) {
    Add(s);
  }
}

std::string AccumulatedCommunicationStatistics::PrintHumanReadable() const {
  std::stringstream ss;
  constexpr unsigned kMiB = 1024 * 1024;

  ss << "Communication with each other party:\n"
     << fmt::format("Sent: {:0.3f} MiB in {:d} messages\n",
                    boost::accumulators::mean(accumulators_[kIdxNumberOfBytesSent]) / kMiB,
                    static_cast<std::size_t>(
                        boost::accumulators::mean(accumulators_[kIdxNumberOfMessagesSent])))
     << fmt::format("Received: {:0.3f} MiB in {:d} messages\n",
                    boost::accumulators::mean(accumulators_[kIdxNumberOfBytesReceived]) / kMiB,
                    static_cast<std::size_t>(
                        boost::accumulators::mean(accumulators_[kIdxNumberOfMessagesReceived])));
  return ss.str();
}

boost::json::object AccumulatedCommunicationStatistics::ToJson() const {
  return {
      {"bytes_sent",
       static_cast<std::size_t>(boost::accumulators::mean(accumulators_[kIdxNumberOfBytesSent]))},
      {"num_messages_sent", static_cast<std::size_t>(boost::accumulators::mean(
                                accumulators_[kIdxNumberOfMessagesSent]))},
      {"bytes_received", static_cast<std::size_t>(
                             boost::accumulators::mean(accumulators_[kIdxNumberOfBytesReceived]))},
      {"num_messages_received", static_cast<std::size_t>(boost::accumulators::mean(
                                    accumulators_[kIdxNumberOfMessagesReceived]))}};
}

std::string PrintMotionInfo() {
  std::stringstream ss;
  ss << fmt::format("MOTION version: {} @ {}\n", GetGitVersion(), GetGitBranch())
     << fmt::format("invocation: {}\n", GetCmdLine())
     << fmt::format("by {}@{}, PID {}\n", GetUsername(), GetHostname(), GetPid());
  return ss.str();
}

std::string PrintStatistics(const std::string& experiment_name,
                            const AccumulatedRunTimeStatistics& execution_statistics,
                            const AccumulatedCommunicationStatistics& communication_statistics) {
  std::stringstream ss;
  ss << "===========================================================================\n"
     << experiment_name << "\n"
     << "===========================================================================\n"
     << PrintMotionInfo()
     << "===========================================================================\n"
     << execution_statistics.PrintHumanReadable()
     << "===========================================================================\n"
     << communication_statistics.PrintHumanReadable()
     << "===========================================================================\n";
  return ss.str();
}

}  // namespace encrypto::motion
