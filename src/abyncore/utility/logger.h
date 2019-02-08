#ifndef LOGGER_H
#define LOGGER_H

#include <memory>

#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/core/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sources/logger.hpp>
#include <boost/log/sinks/text_file_backend.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/sources/record_ostream.hpp>

namespace ABYN {
  class Logger {
  public:

    Logger(size_t my_id, boost::log::trivial::severity_level severity_level);

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

  private:
    boost::log::sources::severity_logger<boost::log::trivial::severity_level> logger_;

    Logger() = delete;
  };

  using LoggerPtr = std::shared_ptr<Logger>;
}

#endif //LOGGER_H
