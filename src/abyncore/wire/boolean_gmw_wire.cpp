#include "boolean_gmw_wire.h"

namespace ABYN::Wires {

GMWWire::GMWWire(ENCRYPTO::BitVector &&values, std::weak_ptr<Register> reg, bool is_constant) {
  values_ = std::move(values);
  register_ = reg;
  is_constant_ = is_constant;
  num_of_parallel_values_ = values_.GetSize();
  InitializationHelper();
}

GMWWire::GMWWire(const ENCRYPTO::BitVector &values, std::weak_ptr<Register> reg, bool is_constant) {
  values_ = values;
  register_ = reg;
  is_constant_ = is_constant;
  num_of_parallel_values_ = values_.GetSize();
  InitializationHelper();
}

GMWWire::GMWWire(bool value, std::weak_ptr<Register> reg, bool is_constant) {
  values_.Append(value);
  register_ = reg;
  is_constant_ = is_constant;
  num_of_parallel_values_ = 1;
  InitializationHelper();
}

}