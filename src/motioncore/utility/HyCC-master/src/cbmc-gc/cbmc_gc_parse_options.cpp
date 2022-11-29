/*******************************************************************\

Module: CBMC Command Line Option Processing

Author: Daniel Kroening, kroening@kroening.com

\*******************************************************************/

#include <fstream>
#include <cstdlib> // exit()
#include <iostream>
#include <memory>

#include <util/string2int.h>
#include <util/config.h>
#include <util/expr_util.h>
#include <util/c_types.h>
#include <util/unicode.h>
#include <util/memory_info.h>

#include <ansi-c/c_preprocess.h>

#include <goto-programs/goto_convert_functions.h>
#include <goto-programs/remove_function_pointers.h>
#include <goto-programs/remove_virtual_functions.h>
#include <goto-programs/remove_returns.h>
#include <goto-programs/remove_vector.h>
#include <goto-programs/remove_complex.h>
#include <goto-programs/remove_asm.h>
#include <goto-programs/remove_unused_functions.h>
#include <goto-programs/goto_inline.h>
#include <goto-programs/show_properties.h>
#include <goto-programs/set_properties.h>
#include <goto-programs/read_goto_binary.h>
#include <goto-programs/string_abstraction.h>
#include <goto-programs/string_instrumentation.h>
#include <goto-programs/loop_ids.h>
#include <goto-programs/link_to_library.h>
#include <goto-programs/remove_skip.h>
#include <goto-programs/show_goto_functions.h>

#include <goto-instrument/full_slicer.h>
#include <goto-instrument/nondet_static.h>
#include <goto-instrument/cover.h>

#include <pointer-analysis/add_failed_symbols.h>

#include <analyses/dependence_graph.h>
#include <analyses/local_may_alias.h>
#include <analyses/natural_loops.h>
#include <pointer-analysis/value_set_analysis_fi.h>

#include <langapi/mode.h>
#include <cbmc/xml_interface.h>

#include "version.h"
#include "circuit_creator_default.h"
#include "cbmc_gc_parse_options.h"
#include "bmc_gc.h"
#include "boolean_expr_lowering.h"

#include "goto_conversion_invocation.h"

#include "compiler_flags.h"

#include <libcircuit/compiler_flags.h>
#include <libcircuit/parallel_execution_graph.h>

#ifdef CBMC_GC_USE_ABC
#include "circuit_creator_abc.h"
#endif

#include "cbmc_to_ir.h"
#include "ir/pointer_analysis.h"
#include "ir/reaching_definitions.h"
#include "ir/program_dependence_graph.h"
#include "ir/instruction_outliner.h"

#include "ir_to_cbmc.h"

#include <limits.h>


//==================================================================================================
cbmc_gc_parse_optionst::cbmc_gc_parse_optionst(int argc, const char **argv):
  parse_options_baset(CBMC_OPTIONS, argc, argv),
  xml_interfacet(cmdline),
  language_uit(cmdline, ui_message_handler),
  ui_message_handler(cmdline, "CBMC " CBMC_VERSION)
{
}

cbmc_gc_parse_optionst::cbmc_gc_parse_optionst(
  int argc,
  const char **argv,
  const std::string &extra_options):
  parse_options_baset(CBMC_OPTIONS+extra_options, argc, argv),
  xml_interfacet(cmdline),
  language_uit(cmdline, ui_message_handler),
  ui_message_handler(cmdline, "CBMC " CBMC_VERSION)
{
}

void cbmc_gc_parse_optionst::eval_verbosity()
{
  // this is our default verbosity
  
  // TODO For each unrolled loop iteration a message is printed to the console (using log-level
  //      M_STATISTICS). Slows down the whole process if the number of loop iterations is large.
  unsigned int v=messaget::M_STATISTICS;
  //unsigned int v=messaget::M_ERROR;

  if(cmdline.isset("verbosity"))
  {
    v=unsafe_string2unsigned(cmdline.get_value("verbosity"));
    if(v>10)
      v=10;
  }

  ui_message_handler.set_verbosity(v);
}


// Compiles a function to a circuit.
simple_circuitt cbmc_gc_parse_optionst::compile_func_by_name(
  circuit_target_kindt target,
  std::string const &func_name,
  goto_modulet &module,
  param_specialzationst const &specializations)
{
  // Find the function we are supposed to convert
  auto it = module.goto_functions().function_map.find(func_name);
  if(it == module.goto_functions().function_map.end())
    throw std::runtime_error{"Function not found: " + func_name};

  goto_programt const &func = it->second.body;

  if(specializations.empty())
    return compile_function(target, func, module, *this);
  else
    return compile_specialized_circuit(target, func, module, specializations, *this);
}

static void write_circuit_stats(simple_circuitt const &circuit, std::string const &name_ext = "")
{
  simple_circuitt::statst stats = circuit.query_stats();
  std::ofstream stats_file{circuit.name() + name_ext + ".stats"};

  stats_file << "non_xor_gates " << stats.num_non_xor_gates << '\n';
  stats_file << "and_gates " << stats.num_and_gates << '\n';
  stats_file << "or_gates " << stats.num_or_gates << '\n';
  stats_file << "xor_gates " << stats.num_xor_gates << '\n';
  stats_file << "not_gates " << stats.num_not_gates << '\n';
  stats_file << "non_xor_depth " << stats.non_xor_depth << '\n';

  stats_file << "mul_gates " << stats.num_mul_gates << '\n';
  stats_file << "add_gates " << stats.num_add_gates << '\n';
  stats_file << "sub_gates " << stats.num_sub_gates << '\n';
  stats_file << "neg_gates " << stats.num_neg_gates << '\n';
  stats_file << "mul_depth " << stats.mul_depth << '\n';

  stats_file << "total_gates " << stats.num_gates << '\n';
  stats_file << "total_depth " << stats.depth << '\n';
}

#define VERBOSE 1

// Main function of cbmc_gc_parse_optionst
int cbmc_gc_parse_optionst::doit()
{
  if(cmdline.isset("version"))
  {
    std::cout << CBMC_VERSION << std::endl;
    return 0; // should contemplate EX_OK from sysexits.h
  }

  if(cmdline.isset("compile-options"))
  {
    std::cout << "libcircuit: " << CIRCUIT_COMPILE_FLAGS << std::endl;
    std::cout << "cbmc-gc:    " << CBMC_GC_COMPILE_FLAGS << std::endl;
    exit(0);
  }

  //
  // command line options
  //

  /*optionst options;
  get_command_line_options(options);*/

  eval_verbosity();

  //
  // Print a banner
  //
  status() << "CBMC version " CBMC_VERSION " "
           << sizeof(void *)*8 << "-bit "
           << config.this_architecture() << " "
           << config.this_operating_system() << messaget::eom;

  register_languages();

  if(cmdline.isset("test-preprocessor"))
    return test_c_preprocessor(ui_message_handler)?8:0;

  if(cmdline.isset("preprocess"))
  {
    preprocessing();
    return 0; // should contemplate EX_OK from sysexits.h
  }


  //
  // [CBMC-GC]
  //
  
  default_logger().add_target<default_log_targett>();

  std::unordered_map<std::string, simple_circuitt> circuits_by_name;
  for(auto it = cmdline.args.begin(); it != cmdline.args.end();)
  {
    if(ends_with(*it, ".circ"))
    {
      simple_circuitt circuit{default_logger(), ""};
      std::ifstream file{*it};
      circuit.read(file);

      auto name = circuit.name();
      circuits_by_name.emplace(std::move(name), std::move(circuit));

      it = cmdline.args.erase(it);
    }
    else
      ++it;
  }

  goto_modulet module = invoke_goto_compilation(cmdline, ui_message_handler);


  if(cmdline.isset("test-pointer-analysis") || cmdline.isset("outline"))
  {
    namespacet ns{module.original_symbols()};

    ir::SymbolTable sym_table;

    // We will first add all functions to the symbol table before we are compiling them to ensure
    // that function calls can find the target function.
    for(auto const &pair: module.original_symbols())
    {
      symbolt const &sym = pair.second;
      if(sym.is_function())
      {
        if(starts_with(cstring_ref(sym.name.c_str()), "__CPROVER"))
          continue;

        sym_table.root_scope()->declare_func(sym.name.c_str(), sym.type);
      }
    }

    for(auto const &pair: sym_table.root_scope()->symbols())
    {
      ir::Decl *decl = pair.second.get();
      if(decl->kind() == ir::DeclKind::function)
      {
        std::cout << "Converting " << decl->name() << "\n" << std::endl;

#if VERBOSE
        module.goto_functions().function_map.at(decl->name()).body.output(ns, "", std::cout);
        std::cout << std::endl;
#endif

        auto ir_func = convert_to_ir(
          sym_table,
          ns,
          module.goto_functions().function_map.at(decl->name()));

#if VERBOSE
        ir::InstrNameMap names;
        ir_func->print(std::cout, &names);
        std::cout << std::endl;
#endif

        std::ofstream of{"basic_blocks_" + decl->name() + "_raw.dot"};
        ir::to_dot(*ir_func, of);
        of.flush();

        static_cast<ir::FuncDecl*>(decl)->set_function(std::move(ir_func));
      }
    }

    ir::InstrNameMap names;
    ir::Function *main_func = sym_table.root_scope()->lookup_func(module.main_function_name())->function();

    boolbv_widtht boolbv_width{ns};
    ir::PAContextSensitiveCallAnalyzer pa_ca{boolbv_width};
    std::cout << "Starting pointer analysis" << std::endl;

    pa_ca.analyze_entry_point(main_func);
    ir::PointsToMap pt_main = pa_ca.result_for({});

    std::cout << "\n";

    std::cout << "Starting reaching definitions analysis" << std::endl;
    ir::RDContextSensitiveCallAnalyzer rd_ca{&pa_ca, boolbv_width};
    rd_ca.analyze_entry_point(main_func);
    ir::ReachingDefinitions rd = rd_ca.result_for({});

    std::cout << "Starting program dependence graph analysis" << std::endl;
    ir::PDGContextSensitiveCallAnalyzer pdg_ca{&pa_ca, &rd_ca, boolbv_width};
    pdg_ca.analyze_entry_point(main_func);


    std::ofstream pdg_dot{"PDG_" + main_func->name() + ".dot"};
    pdg_ca.to_dot(pdg_dot, names);

    if (cmdline.isset("outline")) {
      ir::InstructionOutliner outliner(pdg_ca, names, sym_table, module);
      outliner.run(main_func);
    }

    for(auto const &pair: sym_table.root_scope()->symbols())
    {
      ir::Decl *decl = pair.second.get();

      if (decl->kind() != ir::DeclKind::function)
        continue;

      std::cout << "Converting \"" << decl->name() << "\" back to CBMC." << std::endl;

      goto_programt program;
      if (!convert_to_cbmc(static_cast<ir::FuncDecl*>(decl)->function(), program, ns)) {
        std::cout << "\n == Conversion failed! ==" << std::endl;
        continue;
      } else {
        std::cout << "\n Conversion successful." << std::endl;
      }

      // Replace original function.
      goto_programt& old_program = module.goto_functions().function_map.at(decl->name()).body;
      old_program.swap(program);

      module.goto_functions().update();

#if VERBOSE
      module.goto_functions().function_map.at(decl->name()).body.output(ns, "", std::cout);
      std::cout << std::endl;
#endif
    }
  }


#if 0
  {
    // Playground for different analyses offered by CBMC
    //--------------------------------------------------

    // Compute program dependence graph (PDG)
    namespacet ns{module.original_symbols()};

    /*rw_range_sett rw_set{ns};
    goto_rw(module.main_function(), rw_set);
    std::cout << rw_set << std::endl;*/

    /*reaching_definitions_analysist rd{ns};
    rd(module.goto_functions(), ns);
    rd.output(ns, module.goto_functions(), std::cout);*/

    /*natural_loopst loops;
    loops(module.main_function());
    loops.output(std::cout);*/

    /*dependence_grapht dep_graph{ns};
    dep_graph(module.goto_functions(), ns);
    dep_graph.output(ns, module.goto_functions(), std::cout);*/

    value_set_analysis_fit val_sets{ns};
    val_sets(module.goto_functions());
    val_sets.output(module.goto_functions(), std::cout);


    /*input_dependency_analyzert in_analyzer{module.goto_functions(), ns};
    auto instr_begin = module.main_function().instructions.begin();
    auto instr_end = module.main_function().instructions.end();
    while(instr_begin != instr_end)
    {

    std::cout << "**** " << instr_begin->location_number << " " << instr_begin->source_location << "\n";
    std::cout << " ### INPUT: " << in_analyzer.depends_on_input(instr_begin) << std::endl;
    module.main_function().output_instruction(ns, "", std::cout, *instr_begin);
    std::cout << "\n";
    ++instr_begin;
    }*/

    module.main_function().output(std::cout);

    return 0;
  }
#endif


  //------------------------------------------------------------------
  /*namespacet ns{module.original_symbols()};

  module.main_function().output(ns, "", std::cout);

  ir::SymbolTable sym_table;
  convert_to_ir(sym_table, ns, module.goto_functions().function_map.at(module.main_function_name()));

  return 0;*/
  //------------------------------------------------------------------


  if(cmdline.isset("all-variants"))
  {
    compile_all_variants(module);
    return 0;
  }

  // Find out which functions should be compiled separately
  std::unordered_map<std::string, circuit_target_kindt> separately_compiled;
  for(std::string const &func_name: cmdline.get_values("bool"))
    separately_compiled[func_name] = circuit_target_kindt::boolean;
  for(std::string const &func_name: cmdline.get_values("arith"))
    separately_compiled[func_name] = circuit_target_kindt::arithmetic;

  for(auto const &pair: separately_compiled)
  {
    std::string const &func_name = pair.first;
    module.make_external_call(func_name);
  }

  // If no target has been specified for the main function compile to a boolean circuit by default.
  separately_compiled.insert({config.main, circuit_target_kindt::boolean});

  // Compute how much minimization time each circuit gets
  int per_circuit_minimization_time = -1;
  int num_circuits = separately_compiled.size() + circuits_by_name.size();
  int total_minimization_time = module.options().get_signed_int_option("minimization-time-limit");
  if(total_minimization_time != -1)
    per_circuit_minimization_time = total_minimization_time / num_circuits;

  module.options().set_option("minimization-time-limit", per_circuit_minimization_time);


  // Compile all functions
  for(auto const &pair: separately_compiled)
  {
    std::string const &func_name = pair.first;
    circuit_target_kindt target = pair.second;
    if(circuits_by_name.find(func_name) != circuits_by_name.end())
    {
      debug() << '"' << func_name << "\" has been processed already. Ignoring.\n";
      continue;
    }

    if(!is_template_func(module.func_type(func_name)))
    {
      auto sub_circuit = compile_func_by_name(target, func_name, module);
      circuits_by_name.emplace(func_name, std::move(sub_circuit));
    }
  }

  auto &specializations = module.specializations();
  auto it = specializations.begin();
  while(it != specializations.end())
  {
    auto const &original_func_name = (*it)->second.first;
    auto const &specialized_func_name = (*it)->first;
    circuit_target_kindt circuit_kind = separately_compiled.at(original_func_name);

    circuits_by_name.emplace(specialized_func_name, compile_specialized_circuit(
      circuit_kind,
      module.function(original_func_name),
      module,
      (*it)->second.second,
      *this));

    separately_compiled.emplace(specialized_func_name, circuit_kind);

    it = specializations.erase(it);
  }

  simple_circuitt &main_circuit = circuits_by_name.at(config.main);
  if(cmdline.isset("merge") && circuits_by_name.size())
  {
    statistics() << eom;
    main_circuit.link(circuits_by_name);

    statistics() << "\nFinal stats" << eom;
    main_circuit.print_stats();

    std::ofstream os{main_circuit.name() + ".circ"};
    main_circuit.write(os);
    write_circuit_stats(main_circuit);
  }
  else
  {
    for(auto &pair: separately_compiled)
    {
      if(!is_template_func(module.func_type(pair.first)))
      {
        simple_circuitt &circ = circuits_by_name.at(pair.first);
        std::ofstream os{pair.first + ".circ"};
        circ.write(os);
        write_circuit_stats(circ);
      }
    }
  }



  /*mpc_io_mapping iom;
  main_circuit.write_circuit_files(options, iom);
  std::ofstream spec_file{options.get_option("outdir") + "/output.spec.txt"};
  for(auto const &var: main_circuit.variables)
    spec_file << var.first << ": " << export_type(var.second.type) << ";\n";*/

  if(cmdline.isset("dot"))
  {
    std::ofstream of{cmdline.get_value("dot")};
    main_circuit.write_dot(of, false, -1);

    for(auto &p: circuits_by_name)
    {
      std::ofstream of{p.first + ".dot"};
      p.second.write_dot(of, false, -1);
    }
  }

  // let's log some more statistics
  debug() << "Memory consumption:" << messaget::endl;
  memory_info(debug());
  debug() << messaget::eom;

  return 0;
}


void cbmc_gc_parse_optionst::compile_all_variants(goto_modulet &module)
{
  // TODO Only compile functions (transitively) called from the main function (right now all
  //      functions in the file are compiled)
  

  for(auto &pair: module.goto_functions().function_map)
  {
    if(!should_not_be_inlined(as_string(pair.first)))
      module.make_external_call(pair.first.c_str());
  }

  for(auto &pair: module.goto_functions().function_map)
  {
    std::string const &func_name = as_string(pair.first);
    if(should_not_be_inlined(func_name))
      continue;

    if(starts_with(func_name, "__CPROVER"))
      continue;

    code_typet const &func_type = pair.second.type;
    if(is_template_func(func_type))
      continue;

    compile_all_variants(module, func_name);
  }

  auto &specializations = module.specializations();
  auto it = specializations.begin();
  while(it != specializations.end())
  {
    auto const &original_func_name = (*it)->second.first;
    compile_all_variants(module, original_func_name, (*it)->second.second);

    it = specializations.erase(it);
  }
}


void cbmc_gc_parse_optionst::compile_all_variants(
  goto_modulet &module,
  std::string const &func_name,
  param_specialzationst const &specializations)
{
  {
    // Compile to boolean size-optimized
    module.options().set_option("low-depth-bb", false);
    module.options().set_option("low-depth-expr", false);
    auto circuit = compile_func_by_name(circuit_target_kindt::boolean, func_name, module, specializations);

    std::ofstream os{circuit.name() + "@bool_size.circ"};
    circuit.write(os);
    write_circuit_stats(circuit, "@bool_size");
  }

  {
    // Compile to boolean depth-optimized
    module.options().set_option("low-depth-bb", true);
    module.options().set_option("low-depth-expr", true);
    auto circuit = compile_func_by_name(circuit_target_kindt::boolean, func_name, module, specializations);

    std::ofstream os{circuit.name() + "@bool_depth.circ"};
    circuit.write(os);
    write_circuit_stats(circuit, "@bool_depth");
  }

  {
    // Compile to arithmetic (if possible)
    try
    {
      auto circuit = compile_func_by_name(circuit_target_kindt::arithmetic, func_name, module, specializations);

      std::ofstream os{circuit.name() + "@arith.circ"};
      circuit.write(os);
      write_circuit_stats(circuit, "@arith");
    }
    catch(non_arithmetic_expression_error const&) {}
  }
}


void cbmc_gc_parse_optionst::preprocessing()
{
  try
  {
    if(cmdline.args.size()!=1)
    {
      error() << "Please provide one program to preprocess" << messaget::eom;
      return;
    }

    std::string filename=cmdline.args[0];

    std::ifstream infile(filename);

    if(!infile)
    {
      error() << "failed to open input file" << messaget::eom;
      return;
    }

  std::unique_ptr<languaget> language=get_language_from_filename(filename);

    if(!language)
    {
      error() << "failed to figure out type of file" << messaget::eom;
      return;
    }

    language->set_message_handler(get_message_handler());

    if(language->preprocess(infile, filename, std::cout))
      error() << "PREPROCESSING ERROR" << messaget::eom;
  }

  catch(const char *e)
  {
    error() << e << messaget::eom;
  }

  catch(const std::string e)
  {
    error() << e << messaget::eom;
  }

  catch(int)
  {
  }

  catch(std::bad_alloc const&)
  {
    error() << "Out of memory" << messaget::eom;
  }
}


void cbmc_gc_parse_optionst::help()
{
  std::cout <<
    "\n"
    "* *   CBMC " CBMC_VERSION " - Copyright (C) 2001-2016 ";

  std::cout << "(" << (sizeof(void *)*8) << "-bit version)";

  std::cout << "   * *\n";

  std::cout <<
    "* *              Daniel Kroening, Edmund Clarke             * *\n"
    "* * Carnegie Mellon University, Computer Science Department * *\n"
    "* *                 kroening@kroening.com                   * *\n"
    "* *        Protected in part by U.S. patent 7,225,417       * *\n"
    "\n"
    "Usage:                       Purpose:\n"
    "\n"
    " cbmc [-?] [-h] [--help]      show help\n"
    " cbmc file.c ...              source file names\n"
    "\n"
    "Garbled circuit options:\n"
    " --no-minimization            do no try to minimize the circuit\n"
    " --minimization-time-limit t  limit minimization time to t seconds\n"
    " --low-depth                  same as specifying both --low-depth-bb and\n"
    "                              --low-depth-expr\n"
    " --low-depth-bb               use building blocks optimized for circuit depth\n"
    " --low-depth-expr             optimize expressions for circuit depth\n"
#ifdef CBMC_GC_USE_ABC
    " --abc                        use the ABC framework\n"
#endif
    "\n"
    "Analysis options:\n"
    " --show-properties            show the properties, but don't run analysis\n" // NOLINT(*)
    " --property id                only check one specific property\n"
    " --stop-on-fail               stop analysis once a failed property is detected\n" // NOLINT(*)
    " --trace                      give a counterexample trace for failed properties\n" //NOLINT(*)
    "\n"
    "C/C++ frontend options:\n"
    " -I path                      set include path (C/C++)\n"
    " -D macro                     define preprocessor macro (C/C++)\n"
    " --preprocess                 stop after preprocessing\n"
    " --16, --32, --64             set width of int\n"
    " --LP64, --ILP64, --LLP64,\n"
    "   --ILP32, --LP32            set width of int, long and pointers\n"
    " --little-endian              allow little-endian word-byte conversions\n"
    " --big-endian                 allow big-endian word-byte conversions\n"
    " --unsigned-char              make \"char\" unsigned by default\n"
    " --mm model                   set memory model (default: sc)\n"
    " --arch                       set architecture (default: "
                                   << configt::this_architecture() << ")\n"
    " --os                         set operating system (default: "
                                   << configt::this_operating_system() << ")\n"
    " --c89/99/11                  set C language standard (default: "
                                   << (configt::ansi_ct::default_c_standard()==
                                       configt::ansi_ct::c_standardt::C89?"c89":
                                       configt::ansi_ct::default_c_standard()==
                                       configt::ansi_ct::c_standardt::C99?"c99":
                                       configt::ansi_ct::default_c_standard()==
                                       configt::ansi_ct::c_standardt::C11?"c11":"") << ")\n" // NOLINT(*)
    " --cpp98/03/11                set C++ language standard (default: "
                                   << (configt::cppt::default_cpp_standard()==
                                       configt::cppt::cpp_standardt::CPP98?"cpp98": // NOLINT(*)
                                       configt::cppt::default_cpp_standard()==
                                       configt::cppt::cpp_standardt::CPP03?"cpp03": // NOLINT(*)
                                       configt::cppt::default_cpp_standard()==
                                       configt::cppt::cpp_standardt::CPP11?"cpp11":"") << ")\n" // NOLINT(*)
    #ifdef _WIN32
    " --gcc                        use GCC as preprocessor\n"
    #endif
    " --no-arch                    don't set up an architecture\n"
    " --no-library                 disable built-in abstract C library\n"
    " --round-to-nearest           rounding towards nearest even (default)\n"
    " --round-to-plus-inf          rounding towards plus infinity\n"
    " --round-to-minus-inf         rounding towards minus infinity\n"
    " --round-to-zero              rounding towards zero\n"
    " --function name              set main function name\n"
    "\n"
    "Program representations:\n"
    " --show-parse-tree            show parse tree\n"
    " --show-symbol-table          show symbol table\n"
    " --show-goto-functions        show goto program\n"
    "\n"
    "Program instrumentation options:\n"
    HELP_GOTO_CHECK
    " --no-assertions              ignore user assertions\n"
    " --no-assumptions             ignore user assumptions\n"
    " --error-label label          check that label is unreachable\n"
    " --cover CC                   create test-suite with coverage criterion CC\n" // NOLINT(*)
    " --mm MM                      memory consistency model for concurrent programs\n" // NOLINT(*)
    "\n"
    "Java Bytecode frontend options:\n"
    " --classpath dir/jar          set the classpath\n"
    " --main-class class-name      set the name of the main class\n"
    "\n"
    "Semantic transformations:\n"
    " --nondet-static              add nondeterministic initialization of variables with static lifetime\n" // NOLINT(*)
    "\n"
    "BMC options:\n"
    " --program-only               only show program expression\n"
    " --show-loops                 show the loops in the program\n"
    " --depth nr                   limit search depth\n"
    " --unwind nr                  unwind nr times\n"
    " --unwindset L:B,...          unwind loop L with a bound of B\n"
    "                              (use --show-loops to get the loop IDs)\n"
    " --show-vcc                   show the verification conditions\n"
    " --slice-formula              remove assignments unrelated to property\n"
    " --unwinding-assertions       generate unwinding assertions\n"
    " --partial-loops              permit paths with partial loops\n"
    " --no-pretty-names            do not simplify identifiers\n"
    " --graphml-witness filename   write the witness in GraphML format to filename\n" // NOLINT(*)
    "\n"
    "Backend options:\n"
    " --dimacs                     generate CNF in DIMACS format\n"
    " --beautify                   beautify the counterexample (greedy heuristic)\n" // NOLINT(*)
    " --localize-faults            localize faults (experimental)\n"
    " --smt1                       use default SMT1 solver (obsolete)\n"
    " --smt2                       use default SMT2 solver (Z3)\n"
    " --boolector                  use Boolector\n"
    " --mathsat                    use MathSAT\n"
    " --cvc4                       use CVC4\n"
    " --yices                      use Yices\n"
    " --z3                         use Z3\n"
    " --refine                     use refinement procedure (experimental)\n"
    " --outfile filename           output formula to given file\n"
    " --arrays-uf-never            never turn arrays into uninterpreted functions\n" // NOLINT(*)
    " --arrays-uf-always           always turn arrays into uninterpreted functions\n" // NOLINT(*)
    "\n"
    "Other options:\n"
    " --version                    show version and exit\n"
    " --xml-ui                     use XML-formatted output\n"
    " --xml-interface              bi-directional XML interface\n"
    " --json-ui                    use JSON-formatted output\n"
    "\n";
}

