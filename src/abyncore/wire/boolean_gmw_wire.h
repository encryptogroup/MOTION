#pragma once

#include "wire.h"

#include "utility/bit_vector.h"

namespace ABYN::Wires {

class GMWWire : public BooleanWire {
 public:
  GMWWire(ENCRYPTO::BitVector &&values, std::weak_ptr<Register> reg, bool is_constant = false);

  GMWWire(const ENCRYPTO::BitVector &values, std::weak_ptr<Register> reg, bool is_constant = false);

  GMWWire(bool value, std::weak_ptr<Register> reg, bool is_constant = false);

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

}