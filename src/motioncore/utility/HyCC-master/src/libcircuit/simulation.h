#pragma once

#include "simple_circuit.h"
#include "runner.h"


std::unordered_map<std::string, TypedValue> simulate(
  simple_circuitt &circuit,
  std::unordered_map<std::string, TypedValue> const &input_values);

