#pragma once

#include <boost/log/trivial.hpp>

#include <memory>
#include <vector>

namespace ABYN {

namespace Communication {
class Context;
using ContextPtr = std::shared_ptr<Context>;
}  // namespace Communication

class Configuration {
 public:
  Configuration() = delete;

  Configuration(const std::vector<Communication::ContextPtr> &contexts,
                std::size_t id);

  Configuration(std::vector<Communication::ContextPtr> &&contexts, std::size_t id)
      : Configuration(contexts, id) {}

  Configuration(const std::initializer_list<Communication::ContextPtr> &contexts,
                std::size_t id)
      : Configuration(std::vector(contexts), id) {}

  Configuration(std::initializer_list<Communication::ContextPtr> &&contexts,
                std::size_t id)
      : Configuration(std::vector(std::move(contexts)), id) {}

  ~Configuration() = default;

  std::size_t GetNumOfThreads() { return num_threads_; }

  void SetNumOfThreads(std::size_t n) { num_threads_ = n; }

  std::vector<Communication::ContextPtr> &GetParties() {
    return communication_contexts_;
  }

  std::size_t GetNumOfParties() { return communication_contexts_.size(); }

  Communication::ContextPtr &GetCommunicationContext(uint i) {
    return communication_contexts_.at(i);
  }

  std::size_t GetMyId() { return my_id_; }

  void SetLoggingSeverityLevel(boost::log::trivial::severity_level severity_level) {
    severity_level_ = severity_level;
  }

  bool OnlineAfterSetup() { return online_after_setup_; }

  boost::log::trivial::severity_level GetLoggingSeverityLevel() { return severity_level_; }

 private:
  std::int64_t my_id_ = -1;
  std::vector<Communication::ContextPtr> communication_contexts_;
  boost::log::trivial::severity_level severity_level_ = boost::log::trivial::info;

  bool online_after_setup_ = false;

  // determines how many worker threads are used in openmp, but not in
  // communication handlers! the latter always use at least 2 threads for each
  // communication channel to send and receive data to prevent the communication
  // becoming a bottleneck, e.g., in 10 Gbps networks.
  std::size_t num_threads_;
};

using ConfigurationPtr = std::shared_ptr<Configuration>;

}  // namespace ABYN
