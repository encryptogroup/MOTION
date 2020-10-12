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

#include <atomic>
#include <boost/log/sinks/sync_frontend.hpp>
#include <boost/log/sinks/text_file_backend.hpp>
#include <boost/log/sources/severity_channel_logger.hpp>
#include <boost/log/trivial.hpp>
#include <memory>
#include <mutex>

namespace encrypto::motion {

using LoggerType =
    boost::log::sources::severity_channel_logger<boost::log::trivial::severity_level, std::size_t>;

class Logger {
 public:
  // multiple instantiations of Logger in one application will cause duplicates
  // in logs
  Logger(std::size_t my_id, boost::log::trivial::severity_level severity_level);

  ~Logger();

  void Log(boost::log::trivial::severity_level severity_level, const std::string& message);

  void Log(boost::log::trivial::severity_level severity_level, std::string&& message);

  void LogTrace(const std::string& message);

  void LogTrace(std::string&& message);

  void LogInfo(const std::string& message);

  void LogInfo(std::string&& message);

  void LogDebug(const std::string& message);

  void LogDebug(std::string&& message);

  void LogError(const std::string& message);

  void LogError(std::string&& message);

  bool IsEnabled() { return logging_enabled_; }

  void SetEnabled(bool enable = true);

 private:
  boost::shared_ptr<boost::log::sinks::synchronous_sink<boost::log::sinks::text_file_backend>>
      g_file_sink_;
  std::unique_ptr<LoggerType> logger_;
  const std::size_t my_id_;
  std::atomic<bool> logging_enabled_ = true;
  std::mutex write_mutex_;

  // aquire this on calls to boost::log::core
  static std::mutex boost_log_core_mutex_;

  Logger() = delete;
};

using LoggerPointer = std::shared_ptr<Logger>;

}  // namespace encrypto::motion
