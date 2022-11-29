/*******************************************************************\

Module: Instrumenter

Author:

\*******************************************************************/

#ifndef CPROVER_GOTO_INSTRUMENT_WMM_INSTRUMENTER_PENSIEVE_H
#define CPROVER_GOTO_INSTRUMENT_WMM_INSTRUMENTER_PENSIEVE_H

#include "event_graph.h"
#include "goto2graph.h"

class symbol_tablet;
class goto_functionst;
class namespacet;

class instrumenter_pensievet:public instrumentert
{
public:
  instrumenter_pensievet(symbol_tablet &_symbol_table,
    goto_functionst &_goto_f, messaget &message)
    : instrumentert(_symbol_table, _goto_f, message)
  {
  }

  void collect_pairs_naive(namespacet &ns)
  {
    egraph.collect_pairs_naive(ns);
  }

  /* collects directly all the pairs in the graph */
  void collect_pairs(namespacet &ns)
  {
    egraph.collect_pairs(ns);
  }
};

#endif // CPROVER_GOTO_INSTRUMENT_WMM_INSTRUMENTER_PENSIEVE_H
