#include "boolean_gmw_wire.h"

namespace ABYN::Wires {

GMWWire::GMWWire(ENCRYPTO::BitVector &&values, std::weak_ptr<Backend> backend, bool is_constant) {
  values_ = std::move(values);
  backend_ = backend;
  is_constant_ = is_constant;
  num_of_parallel_values_ = values_.GetSize();
  InitializationHelper();
}

GMWWire::GMWWire(const ENCRYPTO::BitVector &values, std::weak_ptr<Backend> backend, bool is_constant) {
  values_ = values;
  backend_ = backend;
  is_constant_ = is_constant;
  num_of_parallel_values_ = values_.GetSize();
  InitializationHelper();
}

GMWWire::GMWWire(bool value, std::weak_ptr<Backend> backend, bool is_constant) {
  values_.Append(value);
  backend_ = backend;
  is_constant_ = is_constant;
  num_of_parallel_values_ = 1;
  InitializationHelper();
}

}