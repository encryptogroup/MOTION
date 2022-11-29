/*******************************************************************\

Module: CBMC-GC Command Line Option Processing

Based on ../cbmc_parse_options.h

\*******************************************************************/

#ifndef CPROVER_CBMC_CBMC_PARSE_OPTIONS_H
#define CPROVER_CBMC_CBMC_PARSE_OPTIONS_H

#include <util/ui_message.h>
#include <util/parse_options.h>

#include <langapi/language_ui.h>

#include <analyses/goto_check.h>

#include <cbmc/xml_interface.h>

class bmc_gct;
class goto_functionst;
class optionst;

#define CBMC_OPTIONS \
  "(program-only)(function):(preprocess)(slice-by-trace):" \
  "(no-simplify)(unwind):(unwindset):(slice-formula)(full-slice)" \
  "(debug-level):(no-propagation)(no-simplify-if)" \
  "(document-subgoals)(outfile):(test-preprocessor)" \
  "D:I:(c89)(c99)(c11)(cpp89)(cpp99)(cpp11)" \
  "(classpath):(cp):(main-class):" \
  "(depth):(partial-loops)(no-unwinding-assertions)(unwinding-assertions)" \
  OPT_GOTO_CHECK \
  "(no-assertions)(no-assumptions)" \
  "(xml-ui)(xml-interface)(json-ui)" \
  "(smt1)(smt2)(fpa)(cvc3)(cvc4)(boolector)(yices)(z3)(opensmt)(mathsat)" \
  "(no-sat-preprocessor)" \
  "(no-pretty-names)(beautify)" \
  "(fixedbv)" \
  "(dimacs)(refine)(max-node-refinement):(refine-arrays)(refine-arithmetic)(aig)" \
  "(16)(32)(64)(LP64)(ILP64)(LLP64)(ILP32)(LP32)" \
  "(little-endian)(big-endian)" \
  "(show-goto-functions)(show-loops)" \
  "(show-symbol-table)(show-parse-tree)(show-vcc)" \
  "(show-claims)(claim):(show-properties)(show-reachable-properties)(property):" \
  "(stop-on-fail)(trace)" \
  "(error-label):(verbosity):(no-library)" \
  "(nondet-static)" \
  "(version)" \
  "(cover):" \
  "(mm):" \
  "(i386-linux)(i386-macos)(i386-win32)(win32)(winx64)(gcc)" \
  "(ppc-macos)(unsigned-char)" \
  "(arrays-uf-always)(arrays-uf-never)" \
  "(string-abstraction)(no-arch)(arch):" \
  "(round-to-nearest)(round-to-plus-inf)(round-to-minus-inf)(round-to-zero)" \
  "(graphml-witness):" \
  "(localize-faults)(localize-faults-method):" \
  "(floatbv)(all-claims)(all-properties)" /* legacy, and will eventually disappear */ \
  "(low-depth)(low-depth-bb)(low-depth-expr)(abc)(no-minimization)(minimization-time-limit):(outdir):"  // CBMC-GC

class cbmc_gc_parse_optionst:
  public parse_options_baset,
  public xml_interfacet,
  public language_uit
{
public:
  virtual int doit() override;
  virtual void help() override;

  cbmc_gc_parse_optionst(int argc, const char **argv);
  cbmc_gc_parse_optionst(
    int argc,
    const char **argv,
    const std::string &extra_options);

protected:
  ui_message_handlert ui_message_handler;
  virtual void register_languages();

  virtual void get_command_line_options(optionst &options);

  virtual int get_goto_program(
    const optionst &options,
    bmc_gct &bmc,
    goto_functionst &goto_functions);

  virtual bool process_goto_program(
    const optionst &options,
    goto_functionst &goto_functions);

  bool set_properties(goto_functionst &goto_functions);

  void eval_verbosity();

  // get any additional stuff before finalizing
  virtual int get_modules(bmc_gct &bmc)
  {
    (void)bmc;
    return -1; // continue
  }

  void preprocessing();
};

#endif // CPROVER_CBMC_CBMC_PARSE_OPTIONS_H
