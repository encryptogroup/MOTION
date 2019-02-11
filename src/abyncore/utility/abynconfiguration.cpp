#include "abynconfiguration.h"

namespace ABYN {
  ABYNConfiguration::ABYNConfiguration(std::vector<PartyPtr> &parties, size_t id) : my_id_(id) {
      parties_.resize(parties.size() + 1, nullptr);
      if constexpr(ABYN::ABYN_VERBOSE_DEBUG) {
        severity_level_ = boost::log::trivial::trace;
      } else if constexpr(ABYN_DEBUG) {
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
}