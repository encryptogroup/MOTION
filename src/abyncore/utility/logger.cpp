#include "logger.h"

#include <fmt/format.h>
#include <fmt/time.h>
#include <boost/log/support/date_time.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include "utility/constants.h"

namespace logging = boost::log;
namespace keywords = boost::log::keywords;
namespace src = boost::log::sources;
namespace sinks = boost::log::sinks;
namespace expr = boost::log::expressions;

namespace ABYN {
  Logger::Logger(size_t my_id, boost::log::trivial::severity_level severity_level) {
    auto time_now = std::time(nullptr);
    auto id = my_id;
    auto date = fmt::format("{:%Y.%m.%d--%H:%M:%S}.", *std::localtime(&time_now));
    logging::add_file_log(keywords::file_name = fmt::format("log/id{}_{}_%N.log", id, date).c_str(),
                          keywords::rotation_size = 100 * MB,
                          keywords::format =
                              (
                                  expr::stream
                                      << expr::format_date_time<boost::posix_time::ptime>("TimeStamp",
                                                                                          "%Y-%m-%d %H:%M:%S.%f")
                                      << ": <" << logging::trivial::severity
                                      << "> " << expr::smessage
                              )
    );

    logging::core::get()->set_filter(logging::trivial::severity >= severity_level);
    logging::add_common_attributes();
    logger_ = src::severity_logger<logging::trivial::severity_level>();
  }

  void Logger::Log(logging::trivial::severity_level severity_level, std::string &msg) {
    BOOST_LOG_SEV(logger_, severity_level) << msg;
  };

  void Logger::Log(logging::trivial::severity_level severity_level, std::string &&msg) {
    BOOST_LOG_SEV(logger_, severity_level) << msg;
  };

  void Logger::LogTrace(std::string &msg) {
    if constexpr(VERBOSE_DEBUG) {
      BOOST_LOG_SEV(logger_, logging::trivial::trace) << msg;
    }
  };

  void Logger::LogTrace(std::string &&msg) {
    if constexpr(VERBOSE_DEBUG) {
      BOOST_LOG_SEV(logger_, logging::trivial::trace) << msg;
    }
  };

  void Logger::LogInfo(std::string &msg) {
    BOOST_LOG_SEV(logger_, logging::trivial::info) << msg;
  };

  void Logger::LogInfo(std::string &&msg) {
    BOOST_LOG_SEV(logger_, logging::trivial::info) << msg;
  };

  void Logger::LogDebug(std::string &msg) {
    if constexpr(DEBUG) {
      BOOST_LOG_SEV(logger_, logging::trivial::debug) << msg;
    }
  };

  void Logger::LogDebug(std::string &&msg) {
    if constexpr(DEBUG) {
      BOOST_LOG_SEV(logger_, logging::trivial::debug) << msg;
    }
  };

  void Logger::LogError(std::string &msg) {
    BOOST_LOG_SEV(logger_, logging::trivial::error) << msg;
  };

  void Logger::LogError(std::string &&msg) {
    BOOST_LOG_SEV(logger_, logging::trivial::error) << msg;
  };
}