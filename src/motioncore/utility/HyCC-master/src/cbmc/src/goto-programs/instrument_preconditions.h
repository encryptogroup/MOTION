/*******************************************************************\

Module: Move preconditions of a function
        to the call-site of the function

Author: Daniel Kroening

Date:   September 2017

\*******************************************************************/

#ifndef CPROVER_GOTO_PROGRAMS_INSTRUMENT_PRECONDITIONS_H
#define CPROVER_GOTO_PROGRAMS_INSTRUMENT_PRECONDITIONS_H

#include <goto-programs/goto_model.h>

void instrument_preconditions(goto_modelt &);

#endif // CPROVER_GOTO_PROGRAMS_INSTRUMENT_PRECONDITIONS_H
