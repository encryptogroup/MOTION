/*******************************************************************\

Module: Expressions in JSON

Author: Peter Schrammel

\*******************************************************************/

#ifndef CPROVER_UTIL_JSON_EXPR_H
#define CPROVER_UTIL_JSON_EXPR_H

#include "json.h"

class source_locationt;
class typet;
class exprt;
class namespacet;

json_objectt json(
  const exprt &,
  const namespacet &);

json_objectt json(
  const typet &,
  const namespacet &);

json_objectt json(const source_locationt &);

#endif // CPROVER_UTIL_JSON_EXPR_H
