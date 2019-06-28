#pragma once

#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

#include "utility/typedefs.h"

namespace ENCRYPTO {
class Condition;
}

namespace ABYN {
class Register;
}

namespace ABYN::Gates::Interfaces {
class Gate;  // forward declaration

using GatePtr = std::shared_ptr<Gate>;
}  // namespace ABYN::Gates::Interfaces

namespace ABYN::Wires {
class Wire {
 public:
  std::size_t GetNumOfParallelValues() const;

  virtual enum CircuitType GetCircuitType() const = 0;

  virtual enum Protocol GetProtocol() const = 0;

  virtual ~Wire();

  void RegisterWaitingGate(std::size_t gate_id);

  void SetOnlineFinished();

  const auto &GetWaitingGatesIds() const noexcept { return waiting_gate_ids_; }

  const bool &IsReady() const noexcept;

  std::shared_ptr<ENCRYPTO::Condition> GetIsReadyCondition() const noexcept {
    return is_done_condition_;
  }

  bool IsConstant() const { return is_constant_; }

  std::size_t GetWireId() const { return static_cast<std::size_t>(wire_id_); }

  std::weak_ptr<ABYN::Register> GetRegister() const { return register_; }

  static std::string PrintIds(const std::vector<std::shared_ptr<Wires::Wire>> &wires);

  virtual std::size_t GetBitLength() const = 0;

  Wire(const Wire &) = delete;

 protected:
  // number of values that are _logically_ processed in parallel
  std::size_t num_of_parallel_values_ = 0;

  // flagging variables as constants is useful, since this allows for tricks,
  // such as non-interactive multiplication by a constant in (arithmetic) GMW
  bool is_constant_ = false;

  // is ready flag is needed for callbacks, i.e.,
  // gates will wait for wires to be evaluated to proceed with their evaluation
  bool is_done_ = false;

  std::shared_ptr<ENCRYPTO::Condition> is_done_condition_;

  std::int64_t wire_id_ = -1;

  std::weak_ptr<ABYN::Register> register_;

  std::unordered_set<std::size_t> waiting_gate_ids_;

  Wire();

  static void UnregisterWireIdFromGate(std::size_t gate_id, std::size_t wire_id,
                                       std::weak_ptr<ABYN::Register> reg);

  void InitializationHelper();

 private:
  std::mutex mutex_;
};

using WirePtr = std::shared_ptr<Wire>;

class BooleanWire : public Wire {
 public:
  ~BooleanWire() override = default;

  CircuitType GetCircuitType() const final { return CircuitType::BooleanType; }

  Protocol GetProtocol() const override = 0;

  BooleanWire(BooleanWire &) = delete;

 protected:
  BooleanWire() = default;
};

using BooleanWirePtr = std::shared_ptr<BooleanWire>;

class BMRWire : BooleanWire {
 public:
  ~BMRWire() final = default;

  Protocol GetProtocol() const final { return Protocol::BMR; }

  BMRWire() = delete;

  BMRWire(BMRWire &) = delete;
};

using BMRWirePtr = std::shared_ptr<BMRWire>;

}  // namespace ABYN::Wires