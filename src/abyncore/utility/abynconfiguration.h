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
  public:

    ABYNConfiguration(std::vector<PartyPtr> &parties, size_t id);

    ABYNConfiguration(std::vector<PartyPtr> &&parties, size_t id) :
        ABYNConfiguration(parties, id) {}

    ABYNConfiguration(const std::initializer_list<PartyPtr> &list_parties, size_t id) :
        ABYNConfiguration(std::vector(std::move(list_parties)), id) {}

    ~ABYNConfiguration() {}


    std::vector<PartyPtr> &GetParties() { return parties_; }

    size_t GetNumOfParties() { return parties_.size(); }

    PartyPtr &GetParty(uint i) { return parties_.at(i); }

    void AddParty(PartyPtr &party) { parties_.push_back(party); }

    size_t GetMyId() { return my_id_; }

    void SetLoggingSeverityLevel(boost::log::trivial::severity_level severity_level) {
      severity_level_ = severity_level;
    }

    bool OnlineAfterSetup(){return online_after_setup_;}

    boost::log::trivial::severity_level GetLoggingSeverityLevel() { return severity_level_; }

  private:
    ssize_t my_id_ = -1;
    std::vector<ABYN::PartyPtr> parties_;
    boost::log::trivial::severity_level severity_level_ = boost::log::trivial::info;

    bool online_after_setup_ = false;

    ABYNConfiguration() = delete;
  };

  using ABYNConfigurationPtr = std::shared_ptr<ABYNConfiguration>;

}

#endif //ABYNCONFIGURATION_H
