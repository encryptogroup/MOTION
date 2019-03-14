#include "configuration.h"

namespace ABYN {
  Configuration::Configuration(const std::vector<CommunicationContextPtr> &contexts, size_t id) : my_id_(id) {
    communication_contexts_.resize(contexts.size() + 1, nullptr);
    if constexpr(ABYN::ABYN_VERBOSE_DEBUG) {
      severity_level_ = boost::log::trivial::trace;
    } else if constexpr(ABYN_DEBUG) {
      severity_level_ = boost::log::trivial::debug;
    }

    for (auto &p : contexts) {
      if (p->GetId() < 0) {
        throw (std::runtime_error(fmt::format("IDs should be positive integers, found: {}", p->GetId())));
      } else if (static_cast<size_t>(p->GetId()) >= contexts.size() + 1) {
        throw (std::runtime_error("IDs should be in the range {0..N-1}, where N is the number of parties"));
      } else if (communication_contexts_.at(p->GetId())) {
        throw (std::runtime_error("You cannot have multiple parties with the same id"));
      }
      communication_contexts_.at(p->GetId()) = p;
    }

    if (communication_contexts_.at(my_id_) != nullptr) { throw (std::runtime_error("Someone else has my id")); }
  };
}