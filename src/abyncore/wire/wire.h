#ifndef WIRE_H
#define WIRE_H

#include <cstdlib>
#include <string>
#include <vector>
#include <memory>
#include <unordered_set>

#include "ENCRYPTO_utils/src/ENCRYPTO_utils/cbitvector.h"

#include "utility/typedefs.h"
#include "abynparty/core.h"

//forward-declare Gate class
namespace ABYN::Gates::Interfaces {
  class Gate;

  using GatePtr = std::shared_ptr<Gate>;
}

namespace ABYN::Wires {
  class Wire {
  public:
    std::size_t GetNumOfParallelValues() const { return num_of_parallel_values_; }

    virtual enum CircuitType GetCircuitType() const = 0;

    virtual enum Protocol GetProtocol() const = 0;

    virtual ~Wire() {
      assert(wire_id_ >= 0);
      core_->UnregisterWire(static_cast<std::size_t>(wire_id_));
    }

    void RegisterWaitingGate(std::size_t gate_id) {
      std::scoped_lock lock(mutex_);
      waiting_gate_ids_.insert(gate_id);
    }

    void UnregisterWaitingGate(std::size_t gate_id) {
      std::scoped_lock lock(mutex_);
      waiting_gate_ids_.erase(gate_id);
    }

    void SetOnlineFinished() {
      if (is_done_) {
        throw (std::runtime_error(fmt::format("Marking wire #{} as \"online phase ready\" twice", wire_id_)));
      }
      is_done_ = true;
      assert(wire_id_ >= 0);
      for (auto gate_id: waiting_gate_ids_) {
        Wire::UnregisterWireIdFromGate(gate_id, static_cast<std::size_t>(wire_id_), core_);
      }
      waiting_gate_ids_.clear();
    }

    const auto &GetWaitingGatesIds() const { return waiting_gate_ids_; }

    const bool &IsReady() const { if (is_constant_) { return is_constant_; } else { return is_done_; }}

    bool IsConstant() const { return is_constant_; }

    std::size_t GetWireId() const {
      return static_cast<std::size_t>(wire_id_);
    }

    const CorePtr &GetCore() const { return core_; }

    static inline std::string PrintIds(const std::vector<std::shared_ptr<Wires::Wire>> &wires) {
      std::string result;
      for (auto &w : wires) { result.append(fmt::format("{} ", w->GetWireId())); }
      result.erase(result.end() - 1);
      return std::move(result);
    }

    virtual std::size_t GetBitLength() = 0;

    //virtual std::size_t GetNumSIMDValues() = 0;

    Wire(const Wire &) = delete;

    Wire(Wire &) = delete;

  protected:
    // number of values that are _logically_ processed in parallel
    std::size_t num_of_parallel_values_ = 0;

    // flagging variables as constants is useful, since this allows for tricks, such as non-interactive
    // multiplication by a constant in (arithmetic) GMW
    bool is_constant_ = false;

    // is ready flag is needed for callbacks, i.e.,
    // gates will wait for wires to be evaluated to proceed with their evaluation
    bool is_done_ = false;

    std::int64_t wire_id_ = -1;

    CorePtr core_;

    std::unordered_set<std::size_t> waiting_gate_ids_;

    Wire() = default;

    static void UnregisterWireIdFromGate(std::size_t gate_id, std::size_t wire_id, CorePtr &core);

    void InitializationHelper() {
      wire_id_ = core_->NextWireId();
      core_->RegisterNextWire(this);
    }

  private:

    std::mutex mutex_;
  };

  using WirePtr = std::shared_ptr<Wire>;


// Allow only unsigned integers for Arithmetic wires.
  template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  class ArithmeticWire : public Wire {
  public:

    ArithmeticWire(std::vector<T> &&values, const CorePtr &core, bool is_constant = false) {
      is_constant_ = is_constant;
      core_ = core;
      values_ = std::move(values);
      num_of_parallel_values_ = values_.size();
      InitializationHelper();
    }

    ArithmeticWire(const std::vector<T> &values, const CorePtr &core, bool is_constant = false) {
      is_constant_ = is_constant;
      core_ = core;
      values_ = values;
      num_of_parallel_values_ = values_.size();
      InitializationHelper();
    }

    ArithmeticWire(T t, const CorePtr &core, bool is_constant = false) {
      is_constant_ = is_constant;
      core_ = core;
      values_.push_back(t);
      num_of_parallel_values_ = 1;
      InitializationHelper();
    }

    ~ArithmeticWire() final = default;

    Protocol GetProtocol() const final { return Protocol::ArithmeticGMW; }

    CircuitType GetCircuitType() const final { return CircuitType::ArithmeticType; }

    const std::vector<T> &GetValuesOnWire() const { return values_; }

    std::vector<T> &GetMutableValuesOnWire() { return values_; }

    std::size_t GetBitLength() final { return sizeof(T) * 8; }

  private:
    std::vector<T> values_;
  };

  template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  using ArithmeticWirePtr = std::shared_ptr<ArithmeticWire<T>>;


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


  class GMWWire : public BooleanWire {
  public:
    GMWWire(std::vector<u8> &&values, const CorePtr &core, std::size_t parallel_values = 1, bool is_constant = false) {
      values_.AttachBuf(values.data(), Helpers::Convert::BitsToBytes(parallel_values));
      core_ = core;
      is_constant_ = is_constant;
      num_of_parallel_values_ = parallel_values;
      InitializationHelper();
    }

    GMWWire(const std::vector<u8> &values, const CorePtr &core, std::size_t parallel_values = 1,
            bool is_constant = false) {
      values_.Copy(values.data(), 0, Helpers::Convert::BitsToBytes(parallel_values));
      core_ = core;
      is_constant_ = is_constant;
      num_of_parallel_values_ = parallel_values;
      InitializationHelper();
    }

    GMWWire(bool value, const CorePtr &core, bool is_constant = false) {
      values_ = {value};
      core_ = core;
      is_constant_ = is_constant;
      num_of_parallel_values_ = 1;
      InitializationHelper();
    }

    ~GMWWire() final = default;

    Protocol GetProtocol() const final { return Protocol::BooleanGMW; }

    GMWWire() = delete;

    GMWWire(GMWWire &) = delete;

    std::size_t GetBitLength() final { return 1; }

    const CBitVector &GetValuesOnWire() const { return values_; }

    CBitVector &GetMutableValuesOnWire() { return values_; }

  private:
    CBitVector values_;
  };

  using GMWWirePtr = std::shared_ptr<GMWWire>;

  class BMRWire : BooleanWire {
  public:
    ~BMRWire() final = default;

    Protocol GetProtocol() const final { return Protocol::BMR; }

    BMRWire() = delete;

    BMRWire(BMRWire &) = delete;
  };

  using BMRWirePtr = std::shared_ptr<GMWWire>;

}

#endif //WIRE_H