#ifndef ABYNCONFIGURATION_H
#define ABYNCONFIGURATION_H

#include <vector>
#include <cstdarg>
#include <memory>
#include <functional>

#include "utility/party.h"
#include "utility/constants.h"

namespace ABYN {

  class ABYNConfiguration {
  private:
    ssize_t my_id_ = -1;
    std::vector<ABYN::Party> parties_;
    boost::log::trivial::severity_level severity_level_ = boost::log::trivial::info;

    ABYNConfiguration() {};

  public:
    ABYNConfiguration(std::vector<Party> &parties, size_t id) : my_id_(id), parties_(std::move(parties)) {
      if constexpr(ABYN::VERBOSE_DEBUG) {
        severity_level_ = boost::log::trivial::trace;
      } else if constexpr(ABYN::DEBUG) {
        severity_level_ = boost::log::trivial::debug;
      }
    };

    ABYNConfiguration(std::initializer_list<Party> &list_parties, size_t id) : my_id_(id) {
      if constexpr(ABYN::VERBOSE_DEBUG) {
        severity_level_ = boost::log::trivial::trace;
      } else if constexpr(ABYN::DEBUG) {
        severity_level_ = boost::log::trivial::debug;
      }
      for (auto &p : list_parties)
        parties_.push_back(p);
    };

    ~ABYNConfiguration() {};

    std::vector<Party> &GetParties() { return parties_; };

    size_t GetNumOfParties() { return parties_.size(); };

    Party &GetParty(uint i) { return parties_.at(i); };

    void AddParty(Party &party) { parties_.push_back(party); };

    size_t GetMyId() { return my_id_; }

    void SetLoggingSeverityLevel(boost::log::trivial::severity_level severity_level) {
      severity_level_ = severity_level;
    };

    boost::log::trivial::severity_level GetLoggingSeverityLevel() { return severity_level_; };
  };

  using ABYNConfigurationPtr = std::shared_ptr<ABYNConfiguration>;

}

#endif //ABYNCONFIGURATION_H
