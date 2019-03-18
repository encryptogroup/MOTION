#ifndef ABYNCORE_H
#define ABYNCORE_H

#include <memory>
#include <queue>
#include <atomic>

#include "communication/communication_handler.h"

#include "utility/configuration.h"
#include "utility/logger.h"


namespace ABYN {

  namespace Gates::Interfaces {
    class Gate;

    using GatePtr = std::shared_ptr<Gate>;
  }

  namespace Wires {
    class Wire;
  }

  class Core {
  public:
    Core(ConfigurationPtr &config) : config_(config) {
      logger_ = std::make_shared<ABYN::Logger>(config_->GetMyId(),
                                               config_->GetLoggingSeverityLevel());
    }

    size_t NextGateId() { return global_gate_id_++; }

    size_t NextWireId() { return global_wire_id_++; }

    size_t NextArithmeticSharingId(size_t num_of_parallel_values) {
      assert(num_of_parallel_values != 0);
      auto old_id = global_arithmetic_sharing_id_;
      global_arithmetic_sharing_id_ += num_of_parallel_values;
      return old_id;
    }

    size_t NextBooleanGMWSharingId(size_t num_of_parallel_values) {
      assert(num_of_parallel_values != 0);
      auto old_id = global_gmw_sharing_id_;
      global_gmw_sharing_id_ += num_of_parallel_values;
      return old_id;
    }

    const LoggerPtr &GetLogger() { return logger_; }

    const ConfigurationPtr &GetConfig() { return config_; }

    void RegisterCommunicationHandlers(
        std::vector<ABYN::Communication::CommunicationHandlerPtr> &communication_handlers) {
      communication_handlers_ = communication_handlers;
    }

    void Send(size_t party_id, flatbuffers::FlatBufferBuilder &message) {
      if (party_id == config_->GetMyId()) { throw (std::runtime_error("Want to send message to myself")); }
      communication_handlers_.at(party_id)->SendMessage(message);
    }

    void RegisterNextGate(ABYN::Gates::Interfaces::Gate *gate) {
      assert(gate != nullptr);
      gates_.push_back(gate);
    }

    ABYN::Gates::Interfaces::Gate *GetGate(size_t gate_id) { return gates_.at(gate_id); }

    void UnregisterGate(size_t gate_id) { gates_.at(gate_id) = nullptr; }

    void RegisterNextWire(ABYN::Wires::Wire *wire) { wires_.push_back(wire); }

    ABYN::Wires::Wire *GetWire(size_t wire_id) { return wires_.at(wire_id); }

    void UnregisterWire(size_t wire_id) { wires_.at(wire_id) = nullptr; }

    void AddToActiveQueue(size_t gate_id) {
      std::scoped_lock lock(active_queue_mutex_);
      active_gates.push(gate_id);
      logger_->LogTrace(fmt::format("Added gate #{} to the active queue", gate_id));
    }

    ssize_t GetNextGateFromOnlineQueue() {
      if (active_gates.size() == 0) {
        return -1;
      } else {
        auto gate_id = active_gates.front();
        assert(gate_id < std::numeric_limits<ssize_t>::max());
        std::scoped_lock lock(active_queue_mutex_);
        active_gates.pop();
        return static_cast<size_t>(gate_id);
      }
    }

    void NotifyEvaluatedGate() { evaluated_gates++; }

    size_t GetNumOfEvaluatedGates() { return evaluated_gates; }

    size_t GetTotalNumOfGates() { return global_gate_id_; }

  private:
    size_t global_gate_id_ = 0,
        global_wire_id_ = 0,
        global_arithmetic_sharing_id_ = 0,
        global_gmw_sharing_id_ = 0; //don't need atomic, since only one thread has access to these

    std::atomic<size_t> evaluated_gates = 0;

    ABYN::ConfigurationPtr config_;
    ABYN::LoggerPtr logger_ = nullptr;

    std::queue<size_t> active_gates;
    std::mutex active_queue_mutex_;

    std::vector<ABYN::Gates::Interfaces::Gate *> gates_;

    std::vector<ABYN::Wires::Wire *> wires_;

    std::vector<ABYN::Communication::CommunicationHandlerPtr> communication_handlers_;

    Core() = delete;

    Core(Core &) = delete;

    Core(const Core &) = delete;
  };

  using CorePtr = std::shared_ptr<Core>;
}

#endif //ABYNCORE_H
