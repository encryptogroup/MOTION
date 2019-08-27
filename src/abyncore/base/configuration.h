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
#include <vector>

#include "utility/bit_vector.h"

namespace ABYN {

namespace Communication {
class Context;
using ContextPtr = std::shared_ptr<Context>;
}  // namespace Communication

class Configuration {
 public:
  Configuration() = delete;

  Configuration(const std::vector<Communication::ContextPtr> &contexts, std::size_t id);

  Configuration(std::vector<Communication::ContextPtr> &&contexts, std::size_t id)
      : Configuration(contexts, id) {}

  Configuration(const std::initializer_list<Communication::ContextPtr> &contexts, std::size_t id)
      : Configuration(std::vector(contexts), id) {}

  Configuration(std::initializer_list<Communication::ContextPtr> &&contexts, std::size_t id)
      : Configuration(std::vector(std::move(contexts)), id) {}

  ~Configuration() = default;

  std::size_t GetNumOfThreads() const noexcept { return num_threads_; }

  void SetNumOfThreads(std::size_t n) { num_threads_ = n; }

  std::vector<Communication::ContextPtr> &GetContexts() noexcept { return communication_contexts_; }

  std::size_t GetNumOfParties() const noexcept { return communication_contexts_.size(); }

  Communication::ContextPtr &GetCommunicationContext(uint i) {
    return communication_contexts_.at(i);
  }

  std::size_t GetMyId() const noexcept { return my_id_; }

  void SetLoggingSeverityLevel(boost::log::trivial::severity_level severity_level) {
    severity_level_ = severity_level;
  }

  bool GetOnlineAfterSetup() const noexcept { return online_after_setup_; }

  void SetOnlineAfterSetup(bool value);

  void SetLoggingEnabled(bool value = true) { logging_enabled_ = value; }

  bool GetLoggingEnabled() const noexcept { return logging_enabled_; }

  boost::log::trivial::severity_level GetLoggingSeverityLevel() const noexcept {
    return severity_level_;
  }

  const auto &GetMyFixedAESKeyShare() const noexcept { return fixed_key_aes_key_my_part_; }
  const auto &GetFixedAESKey() const noexcept { return fixed_key_aes_key_complete_; }
  bool IsFixedKeyAESKeyReady() const noexcept { return fixed_key_aes_key_is_ready_; }

  auto &GetMutableFixedKeyAESKey() { return fixed_key_aes_key_complete_; }
  void SetFixedKeyAESKeyReady() { fixed_key_aes_key_is_ready_ = true; }

 private:
  std::int64_t my_id_ = -1;
  std::vector<Communication::ContextPtr> communication_contexts_;
  boost::log::trivial::severity_level severity_level_ = boost::log::trivial::info;
  ENCRYPTO::AlignedBitVector fixed_key_aes_key_my_part_;
  ENCRYPTO::AlignedBitVector fixed_key_aes_key_complete_;
  bool fixed_key_aes_key_is_ready_ = false;

  bool logging_enabled_ = true;

  /// @param online_after_setup_ if set true, we wait for the setup phase to be finished completely
  /// until proceeding to the online phase
  bool online_after_setup_ = false;

  // determines how many worker threads are used in openmp, but not in
  // communication handlers! the latter always use at least 2 threads for each
  // communication channel to send and receive data to prevent the communication
  // becoming a bottleneck, e.g., in 10 Gbps networks.
  std::size_t num_threads_;
};

using ConfigurationPtr = std::shared_ptr<Configuration>;

}  // namespace ABYN
