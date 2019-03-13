#ifndef LOGGER_H
#define LOGGER_H

#include <memory>
#include <boost/log/trivial.hpp>
#include <boost/log/sources/severity_channel_logger.hpp>

using logger_type = boost::log::sources::severity_channel_logger<boost::log::trivial::severity_level, std::size_t>;

namespace ABYN {
  class Logger {
  public:
//multiple instantiations of Logger in one application will cause duplicates in logs
    Logger(size_t my_id, boost::log::trivial::severity_level severity_level);

    ~Logger();

    void Log(boost::log::trivial::severity_level severity_level, std::string &msg);

    void Log(boost::log::trivial::severity_level severity_level, std::string &&msg);

    void LogTrace(std::string &msg);

    void LogTrace(std::string &&msg);

    void LogInfo(std::string &msg);

    void LogInfo(std::string &&msg);

    void LogDebug(std::string &msg);

    void LogDebug(std::string &&msg);

    void LogError(std::string &msg);

    void LogError(std::string &&msg);

    bool LoggingEnabled() { return logging_enabled_; }

    void Logging(bool enable) { logging_enabled_ = enable; }

  private:
    logger_type logger_;
    size_t my_id_;
    bool logging_enabled_ = true;

    Logger() = delete;
  };

  using LoggerPtr = std::shared_ptr<Logger>;
}

#endif //LOGGER_H
