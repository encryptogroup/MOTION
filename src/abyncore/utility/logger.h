#pragma once

#define BOOST_LOG_DYN_LINK 1

#include <boost/log/sources/severity_channel_logger.hpp>
#include <boost/log/trivial.hpp>
#include <memory>
#include <mutex>

using logger_type =
    boost::log::sources::severity_channel_logger<boost::log::trivial::severity_level, std::size_t>;

namespace ABYN {
class Logger {
 public:
  // multiple instantiations of Logger in one application will cause duplicates
  // in logs
  Logger(std::size_t my_id, boost::log::trivial::severity_level severity_level);

  ~Logger();

  void Log(boost::log::trivial::severity_level severity_level, const std::string &msg);

  void Log(boost::log::trivial::severity_level severity_level, std::string &&msg);

  void LogTrace(const std::string &msg);

  void LogTrace(std::string &&msg);

  void LogInfo(const std::string &msg);

  void LogInfo(std::string &&msg);

  void LogDebug(const std::string &msg);

  void LogDebug(std::string &&msg);

  void LogError(const std::string &msg);

  void LogError(std::string &&msg);

  bool LoggingEnabled() { return logging_enabled_; }

  void Logging(bool enable) { logging_enabled_ = enable; }

 private:
  logger_type logger_;
  std::size_t my_id_;
  bool logging_enabled_ = true;
  std::mutex write_mutex_;

  Logger() = delete;
};

using LoggerPtr = std::shared_ptr<Logger>;
}  // namespace ABYN
