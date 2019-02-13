#ifndef WIRE_H
#define WIRE_H

#include <cstdlib>
#include <string>
#include <vector>
#include <memory>
#include <unordered_set>

#include "utility/typedefs.h"
#include "abynparty/abyncore.h"

namespace ABYN::Gates::Interfaces {
  class Gate;

  using GatePtr = std::shared_ptr<Gate>;
}

namespace ABYN {
  namespace Wires {
    class Wire {
    public:
      size_t GetNumOfParallelValues() { return num_of_parallel_values_; }

      virtual enum CircuitType GetCircuitType() = 0;

      virtual enum Protocol GetProtocol() = 0;

      virtual ~Wire() {}

      void RegisterWaitingGate(size_t gate_id) { waiting_gate_ids_.insert(gate_id); }

      void UnregisterWaitingGate(size_t gate_id) { waiting_gate_ids_.erase(gate_id); }

      // ley the Gate class handle this to prevent cross-referencing
      const auto &GetWaitingGatesIds() const { return waiting_gate_ids_; }

      bool IsDone() { return is_constant_ || is_done_online_; };

    protected:
      // number of values that are _logically_ processed in parallel
      size_t num_of_parallel_values_ = 0;

      // flagging variables as constants is useful, since this allows for tricks, such as non-interactive
      // multiplication by a constant in (arithmetic) GMW
      bool is_constant_ = false;

      // is_done_* variables are needed for callbacks, i.e.,
      // gates will wait for wires to be evaluated to proceed with their evaluation
      bool is_done_setup_ = false;
      bool is_done_online_ = false;

      ssize_t id_ = -1;

      ABYNCorePtr core_;

      std::unordered_set<size_t> waiting_gate_ids_;

      Wire() {};

    private:

      Wire(const Wire &) = delete;

      Wire(Wire &) = delete;
    };

    using WirePtr = std::shared_ptr<Wire>;


// Allow only unsigned integers for Arithmetic wires.
    template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    class ArithmeticWire : public Wire {
    private:
      std::vector<T> values_;
    public:

      ArithmeticWire(std::initializer_list<T> &&values, const ABYNCorePtr &core, bool is_constant = false) {
        is_constant_ = is_constant;
        core_ = core;
        values_.emplace_back(std::move(values));
        num_of_parallel_values_ = values_.size();
        id_ = core_->NextWireId();
      }

      ArithmeticWire(std::initializer_list<T> &values, const ABYNCorePtr &core, bool is_constant = false) {
        is_constant_ = is_constant;
        core_ = core;
        values_.push_back(values);
        num_of_parallel_values_ = values_.size();
        id_ = core_->NextWireId();
      }

      ArithmeticWire(std::vector<T> &&values, const ABYNCorePtr &core, bool is_constant = false) {
        is_constant_ = is_constant;
        core_ = core;
        this->values_ = std::move(values);
        num_of_parallel_values_ = values_.size();
        id_ = core_->NextWireId();
      }

      ArithmeticWire(std::vector<T> &values, const ABYNCorePtr &core, bool is_constant = false) {
        is_constant_ = is_constant;
        core_ = core;
        this->values_ = values;
        num_of_parallel_values_ = values_.size();
        id_ = core_->NextWireId();
      }

      ArithmeticWire(T t, const ABYNCorePtr &core, bool is_constant = false) {
        is_constant_ = is_constant;
        core_ = core;
        values_.push_back(t);
        num_of_parallel_values_ = 1;
        id_ = core_->NextWireId();
      }

      virtual ~ArithmeticWire() {};

      virtual Protocol GetProtocol() final { return Protocol::ArithmeticGMW; };

      virtual CircuitType GetCircuitType() final { return CircuitType::ArithmeticType; };

      std::vector<T> &GetRawValues() { return values_; };
    };

    template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    using ArithmeticWirePtr = std::shared_ptr<ArithmeticWire<T>>;

    //TODO: implement boolean wires
    class BooleanWire : public Wire {
    public:
      virtual CircuitType GetCircuitType() final { return CircuitType::BooleanType; }

      virtual ~BooleanWire() {}

    private:
      BooleanWire() = delete;

      BooleanWire(BooleanWire &) = delete;
    };

    class GMWWire : public BooleanWire {
    public:
      virtual ~GMWWire() {}

    private:
      GMWWire() = delete;

      GMWWire(GMWWire &) = delete;
    };

    class BMRWire : BooleanWire {
    public:
      virtual ~BMRWire() {}

    private:
      BMRWire() = delete;

      BMRWire(BMRWire &) = delete;
    };

  } //namespace Wires
} //namespace ABYN

#endif //WIRE_H