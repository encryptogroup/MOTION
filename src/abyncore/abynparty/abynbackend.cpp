#include "abynbackend.h"

#define BOOST_FILESYSTEM_NO_DEPRECATED

//#include <boost/filesystem/path.hpp>


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

    void ABYNBackend::InitLogger() {
        auto time_now = std::time(nullptr);
        auto id = abyn_config_->GetMyId();
        auto date = fmt::format("{:%Y.%m.%d--%H:%M:%S}.", *std::localtime(&time_now));
        logging::add_file_log(keywords::file_name = fmt::format("id{}_{}_{}_%N.log", id, date, LOG_PATH).c_str(),
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

        logging::core::get()->set_filter(logging::trivial::severity >= abyn_config_->GetLoggingSeverityLevel());
        logging::add_common_attributes();
        logger_ = src::severity_logger<logging::trivial::severity_level>();
    }

    void ABYNBackend::Log(logging::trivial::severity_level severity_level, std::string &msg) {
        BOOST_LOG_SEV(logger_, severity_level) << msg;
    };

    void ABYNBackend::Log(logging::trivial::severity_level severity_level, std::string &&msg) {
        BOOST_LOG_SEV(logger_, severity_level) << msg;
    };

    void ABYNBackend::LogTrace(std::string &msg) {
        if constexpr(VERBOSE_DEBUG) {
            BOOST_LOG_SEV(logger_, logging::trivial::trace) << msg;
        }
    };

    void ABYNBackend::LogTrace(std::string &&msg) {
        if constexpr(VERBOSE_DEBUG) {
            BOOST_LOG_SEV(logger_, logging::trivial::trace) << msg;
        }
    };

    void ABYNBackend::LogInfo(std::string &msg) {
        BOOST_LOG_SEV(logger_, logging::trivial::info) << msg;
    };

    void ABYNBackend::LogInfo(std::string &&msg) {
        BOOST_LOG_SEV(logger_, logging::trivial::info) << msg;
    };

    void ABYNBackend::LogDebug(std::string &msg) {
        if constexpr(DEBUG) {
            BOOST_LOG_SEV(logger_, logging::trivial::debug) << msg;
        }
    };

    void ABYNBackend::LogDebug(std::string &&msg) {
        if constexpr(DEBUG) {
            BOOST_LOG_SEV(logger_, logging::trivial::debug) << msg;
        }
    };

    void ABYNBackend::LogError(std::string &msg) {
        BOOST_LOG_SEV(logger_, logging::trivial::error) << msg;
    };

    void ABYNBackend::LogError(std::string &&msg) {
        BOOST_LOG_SEV(logger_, logging::trivial::error) << msg;
    };

    size_t ABYNBackend::NextGateId(){
        return global_gate_id_++;
    };

}