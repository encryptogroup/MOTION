#pragma once

#include "common.h"


// This exception is thrown if a function can't be compiled to an arithmetic circuit because it
// contains unsupported expressions
class non_arithmetic_expression_error : public std::runtime_error
{
public:
  non_arithmetic_expression_error() = default;

  non_arithmetic_expression_error(std::string const &msg) :
    std::runtime_error{msg} {}
};


// Compiles a function to an arithmetic circuit
simple_circuitt compile_arith(
  goto_programt const &func,
  class goto_modulet &module,
  class bmc_gct &bmc,
  boolbv_widtht const &boolbv_width);


optional<simple_circuitt> try_compile_arith(
  goto_programt const &func,
  class goto_modulet &module,
  class bmc_gct &bmc,
  boolbv_widtht const &boolbv_width);

