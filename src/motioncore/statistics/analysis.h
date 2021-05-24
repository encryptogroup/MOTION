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

#pragma once

#include <boost/accumulators/accumulators.hpp>
#include <boost/accumulators/statistics/count.hpp>
#include <boost/accumulators/statistics/mean.hpp>
#include <boost/accumulators/statistics/median.hpp>
#include <boost/accumulators/statistics/stats.hpp>
#include <boost/accumulators/statistics/variance.hpp>
#include <boost/json.hpp>
#include <list>
#include "run_time_statistics.h"

namespace encrypto::motion::communication {

struct TransportStatistics;

}  // namespace encrypto::motion::communication

namespace encrypto::motion {

class AccumulatedRunTimeStatistics {
 public:
  using ClockType = std::chrono::steady_clock;
  using Duration = ClockType::duration;
  using Resolution = std::milli;
  using AccumulatorType = boost::accumulators::accumulator_set<
      double,
      boost::accumulators::stats<boost::accumulators::tag::mean, boost::accumulators::tag::median,
                                 boost::accumulators::tag::lazy_variance>>;

  void Add(const RunTimeStatistics& statistics);

  std::string PrintHumanReadable() const;
 
  boost::json::object ToJson() const;

 private:
  std::size_t count_ = 0;
  std::array<AccumulatorType, static_cast<std::size_t>(RunTimeStatistics::StatisticsId::kMax) + 1>
      accumulators_;
};

class AccumulatedCommunicationStatistics {
 public:
  using AccumulatorType = boost::accumulators::accumulator_set<
      std::size_t,
      boost::accumulators::stats<boost::accumulators::tag::mean, boost::accumulators::tag::sum>>;

  static constexpr std::size_t kIdxNumberOfMessagesSent = 0;
  static constexpr std::size_t kIdxNumberOfMessagesReceived = 1;
  static constexpr std::size_t kIdxNumberOfBytesSent = 2;
  static constexpr std::size_t kIdxNumberOfBytesReceived = 3;

  void Add(const communication::TransportStatistics& statistics);

  void Add(const std::vector<communication::TransportStatistics>& statistics);

  std::string PrintHumanReadable() const;
 
  boost::json::object ToJson() const;

 private:
  std::size_t count_ = 0;
  std::array<AccumulatorType, 4> accumulators_;
};

std::string PrintStatistics(const std::string& experiment_name, const AccumulatedRunTimeStatistics&,
                            const AccumulatedCommunicationStatistics&);

}  // namespace encrypto::motion
