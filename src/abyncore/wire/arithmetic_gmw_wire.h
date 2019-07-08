#pragma once

#include "wire.h"

namespace ABYN::Wires {

// Allow only unsigned integers for Arithmetic wires.
template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class ArithmeticWire : public Wire {
 public:
  ArithmeticWire(std::vector<T> &&values, std::weak_ptr<Backend> backend,
                 bool is_constant = false) {
    is_constant_ = is_constant;
    backend_ = backend;
    values_ = std::move(values);
    num_of_parallel_values_ = values_.size();
    InitializationHelper();
  }

  ArithmeticWire(const std::vector<T> &values, std::weak_ptr<Backend> backend,
                 bool is_constant = false) {
    is_constant_ = is_constant;
    backend_ = backend;
    values_ = values;
    num_of_parallel_values_ = values_.size();
    InitializationHelper();
  }

  ArithmeticWire(T t, std::weak_ptr<Backend> backend, bool is_constant = false) {
    is_constant_ = is_constant;
    backend_ = backend;
    values_.push_back(t);
    num_of_parallel_values_ = 1;
    InitializationHelper();
  }

  ~ArithmeticWire() final = default;

  MPCProtocol GetProtocol() const final { return MPCProtocol::ArithmeticGMW; }

  CircuitType GetCircuitType() const final { return CircuitType::ArithmeticType; }

  const std::vector<T> &GetValuesOnWire() const { return values_; }

  std::vector<T> &GetMutableValuesOnWire() { return values_; }

  std::size_t GetBitLength() const final { return sizeof(T) * 8; }

 private:
  std::vector<T> values_;
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
using ArithmeticWirePtr = std::shared_ptr<ArithmeticWire<T>>;

}