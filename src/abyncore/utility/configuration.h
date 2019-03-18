#ifndef ABYNCONFIGURATION_H
#define ABYNCONFIGURATION_H

#include <vector>
#include <cstdarg>
#include <memory>
#include <functional>

#include "utility/communication_context.h"
#include "utility/constants.h"
#include "utility/logger.h"

namespace ABYN {

  class Configuration {
  public:

    Configuration(const std::vector<CommunicationContextPtr> &contexts, std::size_t id);

    Configuration(std::vector<CommunicationContextPtr> &&contexts, std::size_t id) :
        Configuration(contexts, id) {}

    Configuration(const std::initializer_list<CommunicationContextPtr> &contexts, std::size_t id) :
        Configuration(std::vector(contexts), id) {}

    Configuration(std::initializer_list<CommunicationContextPtr> &&contexts, std::size_t id) :
        Configuration(std::vector(std::move(contexts)), id) {}

    ~Configuration() {}

    std::size_t GetNumOfThreads() { return num_threads_; }

    void SetNumOfThreads(std::size_t n) { num_threads_ = n; }

    std::vector<CommunicationContextPtr> &GetParties() { return communication_contexts_; }

    std::size_t GetNumOfParties() { return communication_contexts_.size(); }

    CommunicationContextPtr &GetCommunicationContext(uint i) { return communication_contexts_.at(i); }

    std::size_t GetMyId() { return my_id_; }

    void SetLoggingSeverityLevel(boost::log::trivial::severity_level severity_level) {
      severity_level_ = severity_level;
    }

    bool OnlineAfterSetup() { return online_after_setup_; }

    boost::log::trivial::severity_level GetLoggingSeverityLevel() { return severity_level_; }

  private:
    std::int64_t my_id_ = -1;
    std::vector<ABYN::CommunicationContextPtr> communication_contexts_;
    boost::log::trivial::severity_level severity_level_ = boost::log::trivial::info;

    bool online_after_setup_ = false;

    //determines how many worker threads are used in openmp, but not in communication handlers!
    //the latter always use at least 2 threads for each communication channel to send and receive data to prevent
    //the communication become a bottleneck, e.g., in 10 Gbps networks.
    std::size_t num_threads_ = std::thread::hardware_concurrency();

    Configuration() = delete;
  };

  using ConfigurationPtr = std::shared_ptr<Configuration>;

}

#endif //ABYNCONFIGURATION_H
