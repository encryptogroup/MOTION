/*******************************************************************\

Module:

Author:

\*******************************************************************/

#ifndef CPROVER_CPP_CPP_UTIL_H
#define CPROVER_CPP_CPP_UTIL_H

#include <util/expr.h>
#include <util/symbol.h>

/*******************************************************************\

Function: cpp_symbol_expr

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

exprt cpp_symbol_expr(const symbolt &symbol);

/*******************************************************************\

Function: already_typechecked

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

inline void already_typechecked(irept &irep)
{
  exprt tmp("already_typechecked");
  tmp.copy_to_operands(static_cast<exprt &>(irep));
  irep.swap(tmp);
}

#endif // CPROVER_CPP_CPP_UTIL_H
