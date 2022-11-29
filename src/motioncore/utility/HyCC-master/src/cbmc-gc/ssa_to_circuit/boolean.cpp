#include "boolean.h"

#include "../building_blocks/building_blocks.h"
#include "../bmc_gc.h"
#include "../boolean_expr_lowering.h"
#include "../circuit_creator_default.h"
#include "../goto_conversion_invocation.h"
#include "../sat_equivalence_checker.h"

#ifdef CBMC_GC_USE_ABC
#include "circuit_creator_abc.h"
#endif


// Converts a generic function call to a boolean function call. Must be called immediately
// after `handle_function_call()` because it creates a new symbol table entry for the return
// variable which will be needed by the next instruction that uses the return value.
bool_function_callt to_bool_function_call(
  generic_function_callt const &gen_call,
  boolean_expr_loweringt &bv_cbmc,
  goto_symex_statet &symex_state)
{
  bool_function_callt bool_call;
  bool_call.name = gen_call.name;
  bool_call.call_id = gen_call.call_id;

  for(auto const &arg: gen_call.args)
  {
    bool_call.args.push_back({
      arg.first,
      arg.second,
      bv_cbmc.get_map().mapping.at(arg.first.unique_name).literal_map
    });
  }

  for(auto const &ret: gen_call.returns)
  {
    // Since we skipped the function body the return value is never assigned to the return varable
    // which means we have to create the entry manually.
    auto &entry = bv_cbmc.get_map().mapping[ret.var.unique_name];
    entry.type = ret.type;
    entry.width = bv_cbmc.boolbv_width(ret.type);
    auto &lit_map = entry.literal_map;
    lit_map.resize(entry.width);

    // Create brand new literals for the return variable.
    for(auto &m: lit_map)
    {
      m.l = bv_cbmc.get_prop().new_variable();
      m.is_set = true;
    }

    bool_call.returns.push_back({
      ret.var,
      ret.type,
      entry.literal_map
    });


    if(ret.additional_return_target)
    {
      // This is an additional return which means that an argument is being overwritten (i.e. the 
      // argument was passed by-reference and modified inside the function). Above we created new
      // literals for the return value, now we copy them to the argument (but not without increasing
      // its SSA index before).


      // `old_arg_sym` is the SSA symbol that was passed by reference to the function
      ssa_exprt old_arg_sym = ret.additional_return_target->first;
      exprt arg_expr = ret.additional_return_target->second;

      // Since `old_arg_sym` was passed by reference it does not have a SSA index. Let's change
      // that.
      auto arg_l1_id = old_arg_sym.get_identifier();
      symex_state.level2.current_names.insert({old_arg_sym.get_identifier(), {old_arg_sym, 0}});
      old_arg_sym.set_level_2(symex_state.level2.current_count(old_arg_sym.get_identifier()));

      // Since we are going to overwrite the argument, we must increase its SSA index
      symex_state.level2.increase_counter(arg_l1_id);

      // `new_arg_sym` is the SSA symbol that contains the value that was written to the argument
      // by the function.
      ssa_exprt new_arg_sym = old_arg_sym;
      new_arg_sym.set_level_2(symex_state.level2.current_count(arg_l1_id));

      // `ret_sym` contains the output of the function that we will write to `new_arg_sym`
      symbol_exprt ret_sym{ret.var.unique_name, ret.type};

      if(arg_expr.id() == ID_symbol)
        bv_cbmc.set_to_true(equal_exprt{new_arg_sym, ret_sym});
      else
      {
        replace_subject_with(arg_expr, old_arg_sym);
        bv_cbmc.set_to_true(equal_exprt{new_arg_sym, with_exprt{old_arg_sym, arg_expr, ret_sym}});
      }
    }
  }

  return bool_call;
}


std::unique_ptr<circuit_creatort> new_circuit_creator(optionst const &options, message_handlert &msg)
{
  (void)options;

  std::unique_ptr<circuit_creatort> prop;

#ifdef CBMC_GC_USE_ABC
  if(options.get_bool_option("abc"))
    prop = std::unique_ptr<circuit_creatort>{new circuit_creator_abct()};
  else
    prop = std::unique_ptr<circuit_creatort>{new circuit_creator_defaultt()};
#else
  prop = std::unique_ptr<circuit_creatort>{new circuit_creator_defaultt()};
#endif

  prop->set_message_handler(msg);

  return prop;
}


bvt constant_to_bv(constant_exprt const &constant)
{
  if(constant.type().id() == ID_unsignedbv || constant.type().id() == ID_signedbv)
  {
    size_t width = to_bitvector_type(constant.type()).get_width();
    assert(width && constant.get_value().size() == width);

    bvt bv(width);
    for(size_t i = 0; i < width; ++i)
      bv[width - 1 - i] = const_literal(constant.get_value()[i] == '1');

    return bv;
  }
  else
    throw std::runtime_error{"cannot convert constant_exprt to literals"};
}


simple_circuitt compile_bool(
  goto_programt const &func,
  goto_modulet &module,
  bmc_gct &bmc,
  messaget& msg)
{
  std::string func_name = as_string(goto_programt::get_function_id(func));

  building_blockst bb = module.options().get_bool_option("low-depth-bb") ?
    get_lowdepth_building_blocks() : get_default_building_blocks();

  expr_optimizationt expr_opt = module.options().get_bool_option("low-depth-expr") ?
    expr_optimizationt::depth : expr_optimizationt::size;

  std::unique_ptr<circuit_creatort> prop = new_circuit_creator(module.options(), msg.get_message_handler());;
  boolean_expr_loweringt bv_cbmc{bmc.ns, *prop, bb, expr_opt};

  // Find the function we are supposed to convert
  auto it = module.goto_functions().function_map.find(func_name);
  if(it == module.goto_functions().function_map.end())
    throw std::runtime_error{"Function not found: " + func_name};

  std::unordered_map<irep_idt, typet, irep_id_hash> input_names;
  auto const &func_type = module.func_type(func_name);
  for(auto const &param: func_type.parameters())
    input_names.emplace(param.get_identifier(), param.type());


  // The __CPROVER_initialize function sets some variables internal to CBMC. I am not exactly sure
  // why, but if __CPROVER_threads_exited is not initialized (which is what __CPROVER_initialize
  // does, among other things) the generated circuit is not always correct.
  goto_symext::statet s1;
  bmc.symex.symex_with_state(s1, module.goto_functions(), module.goto_functions().function_map.at("__CPROVER_initialize").body);
  bmc.equation.convert_assignments(bv_cbmc);

  // now run symbolic execution step by step
  goto_symex_steppert stepper{bmc.symex, module.function_getter(), func};

  // convert to boolean formula
  //bmc.equation.output(std::cout);
  std::vector<bool_function_callt> func_calls;
  while(!stepper)
  {
    auto step_it = stepper.cur_instruction();

    // We only convert assignments because that's where all the side-effects take place.
    if(step_it->is_assignment() && !step_it->ignore)
    {
      // std::cout << step_it->cond_expr.pretty() << std::endl;
      // step_it->output(bmc.ns, std::cout);
      // std::cout << from_expr(bmc.ns, "", step_it->cond_expr) << std::endl;
      bv_cbmc.set_to_true(step_it->cond_expr);
      stepper.next_instruction();
    }
    else if(step_it->is_function_call())
    {
      if(auto func_call = handle_function_call(bmc, stepper, module))
      {
        // Convert the assignments of the arguments to the parameters
        for(exprt const &e: func_call->arg_to_param_assignments)
        {
          //std::cout << "ARG: " << from_expr(bmc.ns, "", e) << std::endl;
          //std::cout << "ARG: " << e.pretty() << std::endl;
          bv_cbmc.set_to_true(e);
        }

        func_calls.push_back(to_bool_function_call(*func_call, bv_cbmc, stepper.state()));
      }
    }
    else
      stepper.next_instruction();
  }


  msg.status() << "Converting function to circuit" << messaget::eom;

  /*for(auto &entry: bv_cbmc.get_map().mapping)
  {
	  std::cout << "Map entry: " << entry.first << std::endl;
  }*/

  // Convert boolean formula to circuit
  auto io_variables = get_input_output_variables(bv_cbmc.get_map().mapping, func_name, true);
  for(auto const &var: io_variables)
  {
    char const *inout = var.io_type == io_variable_typet::output ? "(out) " : "(in)  ";
    std::cout << inout << var.var.qualified_name << '(' << var.var.ssa_index << "): " << export_type(var.type) << ";\n";
    input_names.erase(str(var.var.qualified_name));
  }

  // input_names now only contains those INPUTs that where never used or optimzed out.
  for(auto const &input: input_names)
  {
    // Since this INPUT was not used and thus not created we have to add it manually.
    mpc_variable_infot vi;
    vi.var = extract_variable_info(input.first);
    vi.type = input.second;
    vi.io_type = extract_io_type(vi.var, true).value();
    assert(vi.io_type != io_variable_typet::output);

    auto width = bv_cbmc.boolbv_width(vi.type);
    for(size_t i = 0; i < width; ++i)
    {
      boolbv_mapt::map_bitt mb; mb.is_set = true; mb.l = prop->new_variable();
      vi.literals.push_back(mb);
    }

    io_variables.push_back(vi);

    std::cout << "Input " << vi.var.unqualified_name << " does not influence the output" << std::endl;

  }

  for(auto const &call: func_calls)
  {
    std::cout << "Function call to \"" << call.name << "\"\n";
    for(auto const var: call.args)
      std::cout << "(in)  " << var.var.qualified_name << '(' << var.var.ssa_index << "): " << export_type(var.type) << ";\n";
    for(auto const var: call.returns)
      std::cout << "(out) " << var.var.qualified_name << '(' << var.var.ssa_index << "): " << export_type(var.type) << ";\n";
  }

  simple_circuitt circuit{default_logger(), func_name};
  prop->create_circuit(io_variables, func_calls, circuit);

  if(module.options().get_bool_option("minimize-circuit"))
  {
    int minimization_time_limit = module.options().get_signed_int_option("minimization-time-limit");
    auto stats_before_minimization = circuit.query_stats();

	sat_equivalence_checkert checker;
    circuit.minimize(&checker, false, 0, minimization_time_limit, false);
	
	circuit.print_stats(stats_before_minimization);
    msg.status() << "After minimization:" << messaget::eom;
	circuit.print_stats();
  }
  else
	circuit.print_stats();

  return circuit;
}

