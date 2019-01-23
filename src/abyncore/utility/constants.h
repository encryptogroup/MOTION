#ifndef ABYN_CONSTANTS_H
#define ABYN_CONSTANTS_H

#include <string>

#include <boost/log/core/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sources/logger.hpp>
#include <boost/log/sinks/text_file_backend.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/sources/record_ostream.hpp>

namespace ABYN {

    const auto MAXIMUM_CONNECTION_TIMEOUT = 60;//seconds

    const std::string_view LOG_PATH("log_file");

    const auto MB = 1024 * 1024;


    const bool DEBUG = true;
    const bool VERBOSE_DEBUG = true;

}
#endif //ABYN_CONSTANTS_H
