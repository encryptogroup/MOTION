#include "goto_conversion_invocation.h"

#include <goto-programs/goto_convert_functions.h>
#include <goto-programs/remove_asm.h>
#include <goto-programs/link_to_library.h>
#include <goto-programs/string_instrumentation.h>
#include <goto-programs/remove_function_pointers.h>
#include <goto-programs/remove_virtual_functions.h>
#include <goto-programs/remove_vector.h>
#include <goto-programs/remove_complex.h>
#include <goto-programs/goto_inline.h>
#include <goto-programs/string_abstraction.h>
#include <goto-programs/remove_skip.h>
#include <analyses/goto_check.h>
#include <pointer-analysis/add_failed_symbols.h>
#include <util/config.h>
#include <util/cmdline.h>


namespace {

void set_global_config(cmdlinet const &args)
{
  config.set(args);

  if(args.isset("c89"))
    config.ansi_c.set_c89();

  if(args.isset("c99"))
    config.ansi_c.set_c99();

  if(args.isset("c11"))
    config.ansi_c.set_c11();

  if(args.isset("cpp98"))
    config.cpp.set_cpp98();

  if(args.isset("cpp03"))
    config.cpp.set_cpp03();

  if(args.isset("cpp11"))
    config.cpp.set_cpp11();

  if(!args.isset("function"))
    config.main = "mpc_main";
}


optionst options_from_cmdline(cmdlinet const &cmdline)
{
  optionst options;

  if(cmdline.isset("program-only"))
    options.set_option("program-only", true);

  if(cmdline.isset("show-vcc"))
    options.set_option("show-vcc", true);

  if(cmdline.isset("cover"))
    options.set_option("cover", cmdline.get_values("cover"));

  if(cmdline.isset("mm"))
    options.set_option("mm", cmdline.get_value("mm"));

  if(cmdline.isset("no-simplify"))
    options.set_option("simplify", false);
  else
    options.set_option("simplify", true);

  if(cmdline.isset("unwind"))
    options.set_option("unwind", cmdline.get_value("unwind"));

  if(cmdline.isset("depth"))
    options.set_option("depth", cmdline.get_value("depth"));

  if(cmdline.isset("debug-level"))
    options.set_option("debug-level", cmdline.get_value("debug-level"));

  if(cmdline.isset("unwindset"))
    options.set_option("unwindset", cmdline.get_value("unwindset"));

  // constant propagation
  if(cmdline.isset("no-propagation"))
    options.set_option("propagation", false);
  else
    options.set_option("propagation", true);

  // all checks supported by goto_check
  PARSE_OPTIONS_GOTO_CHECK(cmdline, options);

  // check assertions
  if(cmdline.isset("no-assertions"))
    options.set_option("assertions", false);
  else
    options.set_option("assertions", true);

  // use assumptions
  if(cmdline.isset("no-assumptions"))
    options.set_option("assumptions", false);
  else
    options.set_option("assumptions", true);

  // magic error label
  if(cmdline.isset("error-label"))
    options.set_option("error-label", cmdline.get_values("error-label"));

  // generate unwinding assertions
  if(cmdline.isset("cover"))
    options.set_option("unwinding-assertions", false);
  else
  {
    options.set_option(
      "unwinding-assertions",
      cmdline.isset("unwinding-assertions"));
  }

  // generate unwinding assumptions otherwise
  options.set_option(
    "partial-loops",
    cmdline.isset("partial-loops"));

  // remove unused equations
  options.set_option(
    "slice-formula",
    cmdline.isset("slice-formula"));

  // simplify if conditions and branches
  if(cmdline.isset("no-simplify-if"))
    options.set_option("simplify-if", false);
  else
    options.set_option("simplify-if", true);

  if(cmdline.isset("arrays-uf-always"))
    options.set_option("arrays-uf", "always");
  else if(cmdline.isset("arrays-uf-never"))
    options.set_option("arrays-uf", "never");
  else
    options.set_option("arrays-uf", "auto");

  if(cmdline.isset("dimacs"))
    options.set_option("dimacs", true);

  if(cmdline.isset("refine-arrays"))
  {
    options.set_option("refine", true);
    options.set_option("refine-arrays", true);
  }

  if(cmdline.isset("refine-arithmetic"))
  {
    options.set_option("refine", true);
    options.set_option("refine-arithmetic", true);
  }

  if(cmdline.isset("refine"))
  {
    options.set_option("refine", true);
    options.set_option("refine-arrays", true);
    options.set_option("refine-arithmetic", true);
  }

  if(cmdline.isset("max-node-refinement"))
    options.set_option(
      "max-node-refinement",
      cmdline.get_value("max-node-refinement"));

  if(cmdline.isset("aig"))
    options.set_option("aig", true);

  if(cmdline.isset("fpa"))
    options.set_option("fpa", true);


  if(cmdline.isset("no-sat-preprocessor"))
    options.set_option("sat-preprocessor", false);
  else
    options.set_option("sat-preprocessor", true);

  options.set_option(
    "pretty-names",
    !cmdline.isset("no-pretty-names"));

  if(cmdline.isset("outfile"))
    options.set_option("outfile", cmdline.get_value("outfile"));

  if(cmdline.isset("graphml-witness"))
  {
    options.set_option("graphml-witness", cmdline.get_value("graphml-witness"));
    options.set_option("stop-on-fail", true);
    options.set_option("trace", true);
  }


#ifdef CBMC_GC_USE_ABC
  // [CBMC-GC]
  if(cmdline.isset("abc"))
    options.set_option("abc", true);
  else
    options.set_option("abc", false);
#else
  if(cmdline.isset("abc"))
  {
    std::cerr << "Error: CBMC-GC has not been compiled with support for libabc." << std::endl;
    exit(1);
  }
#endif

  // [CBMC-GC]
  options.set_option("low-depth-bb", false);
  options.set_option("low-depth-expr", false);
  if(cmdline.isset("low-depth"))
  {
    options.set_option("low-depth-bb", true);
    options.set_option("low-depth-expr", true);
  }
  if(cmdline.isset("low-depth-bb"))
    options.set_option("low-depth-bb", true);
  if(cmdline.isset("low-depth-expr"))
    options.set_option("low-depth-expr", true);

  if(cmdline.isset("no-minimization"))
    options.set_option("minimize-circuit", false);
  else
    options.set_option("minimize-circuit", true);

  if(cmdline.isset("minimization-time-limit"))
    options.set_option("minimization-time-limit", atoi(cmdline.get_value("minimization-time-limit").c_str()));
  else
    options.set_option("minimization-time-limit", -1);

  return options;
}

}


//==================================================================================================
goto_modulet invoke_goto_compilation(cmdlinet const &args, ui_message_handlert &msg_handler)
{
  set_global_config(args);
  optionst options = options_from_cmdline(args);

  language_uit lang_ui{args, msg_handler};

  // Perform parsing and type-checking

  if(lang_ui.parse())
    throw std::runtime_error{"parsing failed"};

  if(lang_ui.typecheck())
    throw std::runtime_error{"typechecking failed"};

  // Generate __CPROVER_initialize
  if(lang_ui.language_files.generate_support_functions(lang_ui.symbol_table))
    throw std::runtime_error{"generate_support_functions failed"};

  if(lang_ui.final())
    throw std::runtime_error{"final failed"};

  // we no longer need any parse trees or language files
  lang_ui.clear_parse();

  // Convert functions to goto-programs
  goto_functionst goto_functions;
  goto_convert(lang_ui.symbol_table, goto_functions, msg_handler);


  // At this point, the information in the symbol table is pretty much what you would expect when
  // looking at the parsed C code, but now a couple of code transformations happen that will also
  // change the data in the symbol table (e.g. remove_returns() will remove all return-statements
  // and set the return type of all functions to void), so we need to save the current state.
  symbol_tablet orig_symbol_table = lang_ui.symbol_table;

  // CBMC only creates new return_value-variables for functions that have a body. To be
  // able to create the required INPUT/OUTPUT variables for external function (i.e.
  // function that are only forward-declared) we need those return_variables for EVERY
  // function, so we simply add a no-op instruction to empty functions.
  std::unordered_set<std::string> funcs_to_skip;
  for(auto &pair: goto_functions.function_map)
  {
    goto_functionst::goto_functiont &func = pair.second;
    if(should_not_be_inlined(pair.first.c_str()))
      continue;

    // We need to use the type from original symbol table where the return type has not been removed.
    code_typet func_type = to_code_type(orig_symbol_table.lookup(pair.first)->type);

    if(!func.body_available())
    {
      // We never look at the instructions of functions that were empty, so any instruction would do.
      func.body.add_instruction(goto_program_instruction_typet::END_FUNCTION);

      // Remember that the function was originally empty and that we want to skip its body.
      funcs_to_skip.insert(pair.first.c_str());
    }
  }


  messaget msg{msg_handler};
  namespacet ns(lang_ui.symbol_table);

  // Remove inline assembler; this needs to happen before
  // adding the library.
  remove_asm(goto_functions, lang_ui.symbol_table);

  // add the library
  link_to_library(lang_ui.symbol_table, goto_functions, msg_handler);

  if(args.isset("string-abstraction"))
    string_instrumentation(
      lang_ui.symbol_table, msg_handler, goto_functions);

  // remove function pointers
  msg.status() << "Removal of function pointers and virtual functions" << messaget::eom;
  remove_function_pointers(
    msg_handler,
    lang_ui.symbol_table,
    goto_functions,
    args.isset("pointer-check"));
  remove_virtual_functions(lang_ui.symbol_table, goto_functions);

  // do partial inlining
  msg.status() << "Partial Inlining" << messaget::eom;
  goto_partial_inline(goto_functions, ns, msg_handler);

  // remove returns, gcc vectors, complex
  remove_returns(lang_ui.symbol_table, goto_functions);
  remove_vector(lang_ui.symbol_table, goto_functions);
  remove_complex(lang_ui.symbol_table, goto_functions);

  // add generic checks
  msg.status() << "Generic Property Instrumentation" << messaget::eom;
  goto_check(ns, options, goto_functions);


  if(args.isset("string-abstraction"))
  {
    msg.status() << "String Abstraction" << messaget::eom;
    string_abstraction(
      lang_ui.symbol_table,
      msg_handler,
      goto_functions);
  }

  // add failed symbols
  // needs to be done before pointer analysis
  add_failed_symbols(lang_ui.symbol_table);

  // recalculate numbers, etc.
  goto_functions.update();

  // add loop ids
  goto_functions.compute_loop_numbers();

  // instrument cover goals

  // remove skips
  remove_skip(goto_functions);
  goto_functions.update();


  // For some reason, CBMC doesn't assign names to parameters of forward-declared functions, so we
  // need to do it manually.
  for(auto &pair: goto_functions.function_map)
  {
    goto_functionst::goto_functiont &func = pair.second;

    // The last instruction of a function stores the function name, but for forward declared
    // functions the name is not set.
    if(!func.body.empty())
      (--func.body.instructions.end())->function = pair.first;

    for(code_typet::parametert &param: func.type.parameters())
    {
      if(param.get_identifier() == irep_idt())
      {
        param.set_identifier(as_string(pair.first) + "::" + param.get_base_name().c_str());

        parameter_symbolt sym;
        sym.type = param.type();
        sym.name = param.get_identifier();
        sym.base_name = param.get_base_name();
        sym.base_name = param.get_base_name();
        sym.location = source_locationt::nil();

        lang_ui.symbol_table.add(sym);
      }
    }

    code_typet orig_func_type = to_code_type(orig_symbol_table.lookup(pair.first)->type);

    // Also update the type in the symbol table
    orig_symbol_table.get_writeable(pair.first)->type = func.type;

    // func.type has no return type anymolre (removed by remove_returns()). Restore it.
    to_code_type(orig_symbol_table.get_writeable(pair.first)->type).return_type() = orig_func_type.return_type();
  }


  return goto_modulet{
    std::move(orig_symbol_table),
    std::move(lang_ui.symbol_table),
    std::move(goto_functions),
    config.main,
    std::move(funcs_to_skip),
    std::move(options)
  };
}


//==================================================================================================
namespace
{

void prepare_function_calls(goto_programt &func, goto_modulet const &module)
{
  auto inst_it = func.instructions.begin();
  while(inst_it != func.instructions.end())
  {
    if(inst_it->type != goto_program_instruction_typet::FUNCTION_CALL)
    {
      ++inst_it;
      continue;
    }

    code_function_callt const &call = to_code_function_call(inst_it->code);
    irep_idt call_name = to_symbol_expr(call.function()).get_identifier();

    if(!module.is_external_call(as_string(call_name)))
    {
      ++inst_it;
      continue;
    }


    inst_it = func.instructions.erase(inst_it);
  }
}

}

void prepare_function_calls(goto_modulet &module)
{
  for(auto &pair: module.goto_functions().function_map)
    prepare_function_calls(pair.second.body, module);
}
