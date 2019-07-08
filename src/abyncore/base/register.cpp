#include "register.h"

#include "fmt/format.h"

#include "communication/handler.h"
#include "configuration.h"
#include "gate/gate.h"
#include "utility/logger.h"

namespace ABYN {

Register::Register(ConfigurationPtr &config) : config_(config) {
  logger_ = std::make_shared<ABYN::Logger>(config_->GetMyId(), config_->GetLoggingSeverityLevel());
  logger_->SetEnabled(config_->GetLoggingEnabled());
}

Register::~Register() {
  input_gates_.resize(0);
  gates_.resize(0);
  wires_.resize(0);
}

std::size_t Register::NextGateId() noexcept { return global_gate_id_++; }

std::size_t Register::NextWireId() noexcept { return global_wire_id_++; }

std::size_t Register::NextArithmeticSharingId(std::size_t num_of_parallel_values) {
  assert(num_of_parallel_values != 0);
  auto old_id = global_arithmetic_gmw_sharing_id_;
  global_arithmetic_gmw_sharing_id_ += num_of_parallel_values;
  return old_id;
}

std::size_t Register::NextBooleanGMWSharingId(std::size_t num_of_parallel_values) {
  assert(num_of_parallel_values != 0);
  auto old_id = global_boolean_gmw_sharing_id_;
  global_boolean_gmw_sharing_id_ += num_of_parallel_values;
  return old_id;
}

const LoggerPtr &Register::GetLogger() const noexcept { return logger_; }

const ConfigurationPtr &Register::GetConfig() const noexcept { return config_; }

void Register::RegisterCommunicationHandlers(
    std::vector<ABYN::Communication::HandlerPtr> &communication_handlers) {
  for (auto i = 0ull; i < communication_handlers.size(); ++i) {
    communication_handlers_.push_back(communication_handlers.at(i));
  }
}

void Register::Send(std::size_t party_id, flatbuffers::FlatBufferBuilder &message) {
  if (party_id == config_->GetMyId()) {
    throw(std::runtime_error("Trying to send message to myself"));
  }
  if (auto shared_ptr_comm_handler = communication_handlers_.at(party_id).lock()) {
    shared_ptr_comm_handler->SendMessage(message);
  } else {
    throw(std::runtime_error("Trying to use a destroyed communication handler"));
  }
}

void Register::RegisterNextGate(ABYN::Gates::GatePtr gate) {
  assert(gate != nullptr);
  gates_.push_back(gate);
}

void Register::RegisterNextInputGate(ABYN::Gates::GatePtr gate) {
  RegisterNextGate(gate);
  assert(gate != nullptr);
  input_gates_.push_back(gate);
}

void Register::AddToActiveQueue(std::size_t gate_id) {
  std::scoped_lock lock(active_queue_mutex_);
  active_gates_.push(gate_id);
  logger_->LogTrace(fmt::format("Added gate #{} to the active queue", gate_id));
}

std::int64_t Register::GetNextGateFromOnlineQueue() {
  if (active_gates_.size() == 0) {
    return -1;
  } else {
    auto gate_id = active_gates_.front();
    assert(gate_id < std::numeric_limits<std::size_t>::max());
    std::scoped_lock lock(active_queue_mutex_);
    active_gates_.pop();
    return static_cast<std::int64_t>(gate_id);
  }
}

void Register::Reset() {
  if (!gates_.empty()) {
    gate_id_offset_ = global_gate_id_;
  }

  if (!wires_.empty()) {
    wire_id_offset_ = global_wire_id_;
  }

  wires_.resize(0);
  gates_.resize(0);
  input_gates_.resize(0);

  assert(active_gates_.empty());

  evaluated_gates = 0;
}

void Register::Clear() {
  assert(active_gates_.empty());
  for (auto &gate : gates_) {
    gate->Clear();
  }
  evaluated_gates = 0;
}

}  // namespace ABYN
