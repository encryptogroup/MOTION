/*******************************************************************\

Module: Traces of GOTO Programs

Author: Daniel Kroening

Date: November 2005

\*******************************************************************/

/// \file
/// Traces of GOTO Programs

#ifndef CPROVER_GOTO_PROGRAMS_XML_GOTO_TRACE_H
#define CPROVER_GOTO_PROGRAMS_XML_GOTO_TRACE_H

#include <util/xml.h>

#include "goto_trace.h"

void convert(
  const namespacet &ns,
  const goto_tracet &goto_trace,
  xmlt &xml);

#endif // CPROVER_GOTO_PROGRAMS_XML_GOTO_TRACE_H
