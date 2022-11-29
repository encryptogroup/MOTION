/*******************************************************************\

Module: C++ Language Module

Author: Daniel Kroening, kroening@cs.cmu.edu

\*******************************************************************/

#ifndef CPROVER_CPP_CPP_TYPE2NAME_H
#define CPROVER_CPP_CPP_TYPE2NAME_H

#include <string>

#include <util/type.h>

std::string cpp_type2name(const typet &type);
std::string cpp_expr2name(const exprt &expr);

#endif // CPROVER_CPP_CPP_TYPE2NAME_H
