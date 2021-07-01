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

#define _POSIX_C_SOURCE 1

#include "logger.h"

#include <boost/log/attributes/scoped_attribute.hpp>
#include <boost/log/core/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sinks/text_multifile_backend.hpp>
#include <boost/log/sources/logger.hpp>
#include <boost/log/sources/record_ostream.hpp>
#include <boost/log/sources/severity_channel_logger.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/file.hpp>

#include <fmt/format.h>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/log/support/date_time.hpp>
#include <chrono>
#include <ctime>

#include "utility/constants.h"

namespace logging = boost::log;
namespace keywords = boost::log::keywords;
namespace src = boost::log::sources;
namespace sinks = boost::log::sinks;
namespace expr = boost::log::expressions;

BOOST_LOG_ATTRIBUTE_KEYWORD(id_channel, "Channel", std::size_t)

namespace encrypto::motion {

std::mutex Logger::boost_log_core_mutex_;

Logger::Logger(std::size_t my_id, boost::log::trivial::severity_level severity_level)
    : my_id_(my_id) {
  // immediately write messages to the log file to see them also if the
  // execution stalls
  constexpr auto kAutoFlush = kDebug ? true : false;
  const auto time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  std::stringstream stream;
  std::tm temporary_time;
  stream << std::put_time(localtime_r(&time, &temporary_time), "%Y.%m.%d--%H-%M-%S");
  const auto filename = fmt::format("log/id{}_{}_%N.log", my_id_, stream.str());

  std::lock_guard<std::mutex> lock(boost_log_core_mutex_);
  g_file_sink_ = logging::add_file_log(
      keywords::file_name = filename,
      keywords::format =
          (expr::stream << expr::format_date_time<boost::posix_time::ptime>("TimeStamp",
                                                                            "%Y-%m-%d %H:%M:%S.%f")
                        << ": <" << logging::trivial::severity << "> " << expr::smessage),
      keywords::filter = id_channel == my_id_, keywords::auto_flush = kAutoFlush,
      keywords::open_mode = std::ios_base::app | std::ios_base::out,
      keywords::rotation_size = 100 * kMb);

  // FIXME: set this filter for the sinks, otherwise its level is changed for
  // all Logger instances
  logging::core::get()->set_filter(logging::trivial::severity >= severity_level);
  logging::add_common_attributes();
  logger_ = std::make_unique<LoggerType>(keywords::channel = my_id);
}

Logger::~Logger() {
  std::lock_guard<std::mutex> lock(boost_log_core_mutex_);
  logging::core::get()->remove_sink(g_file_sink_);
  g_file_sink_.reset();
}

void Logger::Log(logging::trivial::severity_level severity_level, const std::string& message) {
  if (logging_enabled_) {
    std::scoped_lock<std::mutex> lock(write_mutex_);
    BOOST_LOG_SEV(*logger_, severity_level) << message;
  }
}

void Logger::Log(logging::trivial::severity_level severity_level, std::string&& message) {
  if (logging_enabled_) {
    std::scoped_lock<std::mutex> lock(write_mutex_);
    BOOST_LOG_SEV(*logger_, severity_level) << message;
  }
}

void Logger::LogTrace(const std::string& message) {
  if constexpr (kDebug && kVerboseDebug) {
    if (logging_enabled_) {
      std::scoped_lock<std::mutex> lock(write_mutex_);
      BOOST_LOG_SEV(*logger_, logging::trivial::trace) << message;
    }
  }
}

void Logger::LogTrace(std::string&& message) {
  if constexpr (kDebug && kVerboseDebug) {
    if (logging_enabled_) {
      std::scoped_lock<std::mutex> lock(write_mutex_);
      BOOST_LOG_SEV(*logger_, logging::trivial::trace) << message;
    }
  }
}

void Logger::LogInfo(const std::string& message) {
  if (logging_enabled_) {
    std::scoped_lock<std::mutex> lock(write_mutex_);
    BOOST_LOG_SEV(*logger_, logging::trivial::info) << message;
  }
}

void Logger::LogInfo(std::string&& message) {
  if (logging_enabled_) {
    std::scoped_lock<std::mutex> lock(write_mutex_);
    BOOST_LOG_SEV(*logger_, logging::trivial::info) << message;
  }
}

void Logger::LogDebug(const std::string& message) {
  if constexpr (kDebug) {
    if (logging_enabled_) {
      std::scoped_lock<std::mutex> lock(write_mutex_);
      BOOST_LOG_SEV(*logger_, logging::trivial::debug) << message;
    }
  }
}

void Logger::LogDebug(std::string&& message) {
  if constexpr (kDebug) {
    if (logging_enabled_) {
      std::scoped_lock<std::mutex> lock(write_mutex_);
      BOOST_LOG_SEV(*logger_, logging::trivial::debug) << message;
    }
  }
}

void Logger::LogError(const std::string& message) {
  if (logging_enabled_) {
    std::scoped_lock<std::mutex> lock(write_mutex_);
    BOOST_LOG_SEV(*logger_, logging::trivial::error) << message;
  }
}

void Logger::LogError(std::string&& message) {
  if (logging_enabled_) {
    std::scoped_lock<std::mutex> lock(write_mutex_);
    BOOST_LOG_SEV(*logger_, logging::trivial::error) << message;
  }
}

void Logger::SetEnabled(bool enable) {
  logging_enabled_ = enable;
  std::lock_guard<std::mutex> lock(boost_log_core_mutex_);
  boost::log::core::get()->set_logging_enabled(enable);
}

}  // namespace encrypto::motion
