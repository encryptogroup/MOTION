#ifndef ABYNCONFIGURATION_H
#define ABYNCONFIGURATION_H

#include <vector>
#include <cstdarg>
#include <memory>
#include <functional>

#include <boost/log/core/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sources/logger.hpp>
#include <boost/log/sinks/text_file_backend.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/sources/record_ostream.hpp>

#include "utility/party.h"
#include "utility/constants.h"

namespace ABYN {

  class ABYNConfiguration {
  private:
    ssize_t my_id_ = -1;
    std::vector<ABYN::PartyPtr> parties_;
    boost::log::trivial::severity_level severity_level_ = boost::log::trivial::info;

    ABYNConfiguration() {};

  public:
    ABYNConfiguration(std::vector<PartyPtr> &parties, size_t id) : my_id_(id), parties_(std::move(parties)) {
      if constexpr(ABYN::VERBOSE_DEBUG) {
        severity_level_ = boost::log::trivial::trace;
      } else if constexpr(ABYN::DEBUG) {
        severity_level_ = boost::log::trivial::debug;
      }
    };

    ABYNConfiguration(std::initializer_list<PartyPtr> &list_parties, size_t id) : my_id_(id) {
      if constexpr(ABYN::VERBOSE_DEBUG) {
        severity_level_ = boost::log::trivial::trace;
      } else if constexpr(ABYN::DEBUG) {
        severity_level_ = boost::log::trivial::debug;
      }
      for (auto &p : list_parties)
        parties_.push_back(p);
    };

    ~ABYNConfiguration() {};

    std::vector<PartyPtr> &GetParties() { return parties_; };

    size_t GetNumOfParties() { return parties_.size(); };

    PartyPtr &GetParty(uint i) { return parties_.at(i); };

    void AddParty(PartyPtr &party) { parties_.push_back(party); };

    size_t GetMyId() { return my_id_; }

    void SetLoggingSeverityLevel(boost::log::trivial::severity_level severity_level) {
      severity_level_ = severity_level;
    };

    boost::log::trivial::severity_level GetLoggingSeverityLevel() { return severity_level_; };
  };

  using ABYNConfigurationPtr = std::shared_ptr<ABYNConfiguration>;

}

#endif //ABYNCONFIGURATION_H
