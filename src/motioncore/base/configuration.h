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

#include <boost/log/trivial.hpp>
#include <memory>

namespace encrypto::motion {

class Configuration {
 public:
  Configuration(std::size_t my_id, std::size_t number_of_parties);

  ~Configuration() = default;

  std::size_t GetNumOfThreads() const noexcept { return number_of_threads_; }

  void SetNumOfThreads(std::size_t n) { number_of_threads_ = n; }

  void SetLoggingSeverityLevel(boost::log::trivial::severity_level severity_level) {
    severity_level_ = severity_level;
  }

  bool GetOnlineAfterSetup() const noexcept { return online_after_setup_; }

  void SetOnlineAfterSetup(bool value);

  void SetLoggingEnabled(bool value = true) { logging_enabled_ = value; }

  bool GetLoggingEnabled() const noexcept { return logging_enabled_; }

  std::size_t GetMyId() const { return my_id_; }

  std::size_t GetNumOfParties() const { return number_of_parties_; }

  boost::log::trivial::severity_level GetLoggingSeverityLevel() const noexcept {
    return severity_level_;
  }

 private:
  std::size_t my_id_;
  std::size_t number_of_parties_;

  boost::log::trivial::severity_level severity_level_ = boost::log::trivial::info;

  bool logging_enabled_ = true;

  /// @param online_after_setup_ if set true, we wait for the setup phase to be finished completely
  /// until proceeding to the online phase
  bool online_after_setup_ = false;

  // determines how many worker threads are used in openmp, but not in
  // communication handlers! the latter always use at least 2 threads for each
  // communication channel to send and receive data to prevent the communication
  // becoming a bottleneck, e.g., in 10 Gbps networks.
  std::size_t number_of_threads_;
};

using ConfigurationPointer = std::shared_ptr<Configuration>;

}  // namespace encrypto::motion
