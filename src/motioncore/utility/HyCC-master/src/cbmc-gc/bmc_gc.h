#ifndef CPROVER_BMC_GC_PARSE_OPTIONS_H
#define CPROVER_BMC_GC_PARSE_OPTIONS_H

#include <solvers/prop/prop.h>
#include <solvers/sat/satcheck.h>
#include <langapi/language_ui.h>
#include <goto-symex/symex_target_equation.h>
#include <util/string_utils.h>
#include <util/string2int.h>

#include "cbmc_gc_symex.h"


class bmc_gct
{
public:
  bmc_gct(
    const optionst &_options,
    const symbol_tablet &orig_sym_table,
    const symbol_tablet &_symbol_table,
    messaget &msg) :
      options(_options),
      ns(_symbol_table, new_symbol_table),
      equation(ns),
      symex(ns, orig_sym_table, new_symbol_table, equation, msg),
      function_call_counter{0}
  {
    symex.constant_propagation=options.get_bool_option("propagation");
    symex.record_coverage=
      !options.get_option("symex-coverage-report").empty();
  }

  void setup_unwind()
  {
    const std::string &set=options.get_option("unwindset");
    std::vector<std::string> unwindset_loops;
    split_string(set, ',', unwindset_loops, true, true);

    for(auto &val : unwindset_loops)
    {
      unsigned thread_nr;
      bool thread_nr_set=false;

      if(!val.empty() &&
         isdigit(val[0]) &&
         val.find(":")!=std::string::npos)
      {
        std::string nr=val.substr(0, val.find(":"));
        thread_nr=unsafe_string2unsigned(nr);
        thread_nr_set=true;
        val.erase(0, nr.size()+1);
      }

      if(val.rfind(":")!=std::string::npos)
      {
        std::string id=val.substr(0, val.rfind(":"));
        long uw=unsafe_string2int(val.substr(val.rfind(":")+1));

        if(thread_nr_set)
          symex.set_unwind_thread_loop_limit(thread_nr, id, uw);
        else
          symex.set_unwind_loop_limit(id, uw);
      }
    }

    if(options.get_option("unwind")!="")
      symex.set_unwind_limit(options.get_unsigned_int_option("unwind"));
  }


  const optionst &options;
  symbol_tablet new_symbol_table;
  namespacet ns;
  symex_target_equationt equation;
  cbmc_gc_symext symex;

  // Counts each function call. This allows us to assign a unique and deterministic ID to each call
  // (useful for testing).
  int function_call_counter;
};


#endif
