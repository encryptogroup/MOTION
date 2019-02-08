#ifndef ABYNCONFIGURATION_H
#define ABYNCONFIGURATION_H

#include <vector>
#include <cstdarg>
#include <memory>
#include <functional>

#include "utility/party.h"
#include "utility/constants.h"
#include "utility/logger.h"

namespace ABYN {

  class ABYNConfiguration {
  private:
    ssize_t my_id_ = -1;
    std::vector<ABYN::PartyPtr> parties_;
    boost::log::trivial::severity_level severity_level_ = boost::log::trivial::info;

    ABYNConfiguration() {};

  public:
    ABYNConfiguration(std::vector<PartyPtr> &parties, size_t id) : my_id_(id) {
      parties_.resize(parties.size() + 1, nullptr);
      if constexpr(ABYN::VERBOSE_DEBUG) {
        severity_level_ = boost::log::trivial::trace;
      } else if constexpr(DEBUG) {
        severity_level_ = boost::log::trivial::debug;
      }

      for (auto &p : parties) {
        if (p->GetId() < 0) {
          throw (std::runtime_error(fmt::format("IDs should be positive integers, found: {}", p->GetId())));
        } else if (static_cast<size_t>(p->GetId()) >= parties.size() + 1) {
          throw (std::runtime_error("IDs should be in the range {0..N-1}, where N is the number of parties"));
        } else if (parties_.at(p->GetId())) {
          throw (std::runtime_error("You cannot have multiple parties with the same id"));
        }
        parties_.at(p->GetId()) = std::move(p);
      }

      if (parties_.at(my_id_) != nullptr) { throw (std::runtime_error("Someone else has my id")); }
    };

    ABYNConfiguration(std::vector<PartyPtr> &&parties, size_t id) :
        ABYNConfiguration(parties, id) {};

    ABYNConfiguration(const std::initializer_list<PartyPtr> &list_parties, size_t id) :
        ABYNConfiguration(std::vector(std::move(list_parties)), id) {};


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
