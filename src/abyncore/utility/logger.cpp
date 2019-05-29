#include "logger.h"

#include <boost/log/attributes/scoped_attribute.hpp>
#include <boost/log/core/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sinks/text_file_backend.hpp>
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

#include "utility/constants.h"

namespace logging = boost::log;
namespace keywords = boost::log::keywords;
namespace src = boost::log::sources;
namespace sinks = boost::log::sinks;
namespace expr = boost::log::expressions;

BOOST_LOG_ATTRIBUTE_KEYWORD(id_channel, "Channel", std::size_t)

namespace ABYN {
Logger::Logger(std::size_t my_id, boost::log::trivial::severity_level severity_level)
    : my_id_(my_id) {
  // immediately write messages to the log file to see them also if the
  // execution stalls
  constexpr auto auto_flush = ABYN_DEBUG ? true : false;
  auto time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  std::stringstream stream;
  stream << std::put_time(std::localtime(&time), "%Y.%m.%d--%H:%M:%S");
  auto date = stream.str();

  boost::shared_ptr<sinks::text_multifile_backend> backend =
      boost::make_shared<sinks::text_multifile_backend>();

  logging::add_file_log(
      keywords::file_name = fmt::format("log/id{}_{}_%N.log", my_id_, date).c_str(),
      keywords::format =
          (expr::stream << expr::format_date_time<boost::posix_time::ptime>("TimeStamp",
                                                                            "%Y-%m-%d %H:%M:%S.%f")
                        << ": <" << logging::trivial::severity << "> " << expr::smessage),
      keywords::filter = id_channel == my_id, keywords::auto_flush = auto_flush,
      keywords::open_mode = std::ios_base::app | std::ios_base::out,
      keywords::rotation_size = 100 * MB);

  logging::core::get()->set_filter(logging::trivial::severity >= severity_level);
  logging::add_common_attributes();
  logger_ = logger_type(keywords::channel = my_id);
}

Logger::~Logger() {}

void Logger::Log(logging::trivial::severity_level severity_level, const std::string &msg) {
  if (logging_enabled_) {
    BOOST_LOG_SEV(logger_, severity_level) << msg;
  }
}

void Logger::Log(logging::trivial::severity_level severity_level, std::string &&msg) {
  if (logging_enabled_) {
    BOOST_LOG_SEV(logger_, severity_level) << msg;
  }
}

void Logger::LogTrace(const std::string &msg) {
  if constexpr (ABYN_DEBUG && ABYN_VERBOSE_DEBUG) {
    if (logging_enabled_) {
      BOOST_LOG_SEV(logger_, logging::trivial::trace) << msg;
    }
  }
}

void Logger::LogTrace(std::string &&msg) {
  if constexpr (ABYN_DEBUG && ABYN_VERBOSE_DEBUG) {
    if (logging_enabled_) {
      BOOST_LOG_SEV(logger_, logging::trivial::trace) << msg;
    }
  }
}

void Logger::LogInfo(const std::string &msg) {
  if (logging_enabled_) {
    BOOST_LOG_SEV(logger_, logging::trivial::info) << msg;
  }
}

void Logger::LogInfo(std::string &&msg) {
  if (logging_enabled_) {
    BOOST_LOG_SEV(logger_, logging::trivial::info) << msg;
  }
}

void Logger::LogDebug(const std::string &msg) {
  if constexpr (ABYN_DEBUG) {
    if (logging_enabled_) {
      BOOST_LOG_SEV(logger_, logging::trivial::debug) << msg;
    }
  }
}

void Logger::LogDebug(std::string &&msg) {
  if constexpr (ABYN_DEBUG) {
    if (logging_enabled_) {
      BOOST_LOG_SEV(logger_, logging::trivial::debug) << msg;
    }
  }
}

void Logger::LogError(const std::string &msg) {
  if (logging_enabled_) {
    BOOST_LOG_SEV(logger_, logging::trivial::error) << msg;
  }
}

void Logger::LogError(std::string &&msg) {
  if (logging_enabled_) {
    BOOST_LOG_SEV(logger_, logging::trivial::error) << msg;
  }
}
}