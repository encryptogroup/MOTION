#pragma once

#include "arithmetic.h"
#include "boolean.h"

#include "goto-programs/goto_program.h"
#include "util/message.h"

#include <libcircuit/simple_circuit.h>


enum class circuit_target_kindt
{
  boolean,
  arithmetic,
};


simple_circuitt compile_function(
  circuit_target_kindt kind,
  goto_programt const &func,
  class goto_modulet &module,
  messaget &msg);


struct param_valuet
{
  param_valuet() = default;

  param_valuet(typet const &type) :
    type{type} {}

  param_valuet(constant_exprt const &value) :
    value{value} {}

  // Set EITHER type OR value
  typet type;
  constant_exprt value;
};

using param_specialzationst = std::unordered_map<std::string, param_valuet>;

simple_circuitt compile_specialized_circuit(
  circuit_target_kindt circuit_kind,
  goto_programt const &func,
  goto_modulet &module,
  param_specialzationst const &specializations,
  messaget &msg);


std::string build_func_name_suffix(code_typet const &func_type, param_specialzationst const &specializations);

