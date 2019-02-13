#ifndef ABYNCORE_H
#define ABYNCORE_H

#include <memory>

#include "utility/abynconfiguration.h"
#include "utility/logger.h"

namespace ABYN {
  class ABYNCore {
  public:
    ABYNCore(ABYNConfigurationPtr &abyn_config) : abyn_config_(abyn_config) {
      logger_ = std::make_shared<ABYN::Logger>(abyn_config_->GetMyId(),
                                               abyn_config_->GetLoggingSeverityLevel());
    }

    size_t NextGateId() { return global_gate_id_++; }

    size_t NextWireId() { return global_wire_id_++; }

    const LoggerPtr &GetLogger() { return logger_; }

    const ABYNConfigurationPtr &GetConfig() { return abyn_config_; }


  private:
    size_t global_gate_id_ = 0, global_wire_id_ = 0;

    ABYN::ABYNConfigurationPtr abyn_config_;
    ABYN::LoggerPtr logger_ = nullptr;

    ABYNCore() = delete;

    ABYNCore(ABYNCore &) = delete;

    ABYNCore(const ABYNCore &) = delete;
  };

  using ABYNCorePtr = std::shared_ptr<ABYNCore>;
}

#endif //ABYNCORE_H
