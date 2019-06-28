#pragma once

#include <cstdlib>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

//#include "ENCRYPTO_utils/src/ENCRYPTO_utils/cbitvector.h"
//#include "cryptoTools/cryptoTools/Common/BitVector.h"

#include "base/register.h"
#include "utility/bit_vector.h"
#include "utility/typedefs.h"

// forward-declare Gate class
namespace ABYN::Gates::Interfaces {
class Gate;

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

  void UnregisterWaitingGate(std::size_t gate_id);

  void SetOnlineFinished();

  const auto &GetWaitingGatesIds() const { return waiting_gate_ids_; }

  const bool &IsReady() const;

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

  std::int64_t wire_id_ = -1;

  std::weak_ptr<ABYN::Register> register_;

  std::unordered_set<std::size_t> waiting_gate_ids_;

  Wire() = default;

  static void UnregisterWireIdFromGate(std::size_t gate_id, std::size_t wire_id,
                                       std::weak_ptr<ABYN::Register> reg);

  void InitializationHelper();

 private:
  std::mutex mutex_;
};

using WirePtr = std::shared_ptr<Wire>;

// Allow only unsigned integers for Arithmetic wires.
template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class ArithmeticWire : public Wire {
 public:
  ArithmeticWire(std::vector<T> &&values, std::weak_ptr<Register> reg, bool is_constant = false) {
    is_constant_ = is_constant;
    register_ = reg;
    values_ = std::move(values);
    num_of_parallel_values_ = values_.size();
    InitializationHelper();
  }

  ArithmeticWire(const std::vector<T> &values, std::weak_ptr<Register> reg,
                 bool is_constant = false) {
    is_constant_ = is_constant;
    register_ = reg;
    values_ = values;
    num_of_parallel_values_ = values_.size();
    InitializationHelper();
  }

  ArithmeticWire(T t, std::weak_ptr<Register> reg, bool is_constant = false) {
    is_constant_ = is_constant;
    register_ = reg;
    values_.push_back(t);
    num_of_parallel_values_ = 1;
    InitializationHelper();
  }

  ~ArithmeticWire() final = default;

  Protocol GetProtocol() const final { return Protocol::ArithmeticGMW; }

  CircuitType GetCircuitType() const final { return CircuitType::ArithmeticType; }

  const std::vector<T> &GetValuesOnWire() const { return values_; }

  std::vector<T> &GetMutableValuesOnWire() { return values_; }

  std::size_t GetBitLength() const final { return sizeof(T) * 8; }

 private:
  std::vector<T> values_;
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
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
  GMWWire(ENCRYPTO::BitVector &&values, std::weak_ptr<Register> reg, bool is_constant = false) {
    values_ = std::move(values);
    register_ = reg;
    is_constant_ = is_constant;
    num_of_parallel_values_ = values_.GetSize();
    InitializationHelper();
  }

  GMWWire(const ENCRYPTO::BitVector &values, std::weak_ptr<Register> reg,
          bool is_constant = false) {
    values_ = values;
    register_ = reg;
    is_constant_ = is_constant;
    num_of_parallel_values_ = values_.GetSize();
    InitializationHelper();
  }

  GMWWire(bool value, std::weak_ptr<Register> reg, bool is_constant = false) {
    values_.Append(value);
    register_ = reg;
    is_constant_ = is_constant;
    num_of_parallel_values_ = 1;
    InitializationHelper();
  }

  ~GMWWire() final = default;

  Protocol GetProtocol() const final { return Protocol::BooleanGMW; }

  GMWWire() = delete;

  GMWWire(GMWWire &) = delete;

  std::size_t GetBitLength() const final { return 1; }

  const ENCRYPTO::BitVector &GetValuesOnWire() const { return values_; }

  ENCRYPTO::BitVector &GetMutableValuesOnWire() { return values_; }

 private:
  ENCRYPTO::BitVector values_;
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

}  // namespace ABYN::Wires