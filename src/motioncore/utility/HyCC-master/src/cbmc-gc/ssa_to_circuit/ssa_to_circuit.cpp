#include "ssa_to_circuit.h"

#include "../goto_conversion_invocation.h"
#include "../bmc_gc.h"

#include <util/c_types.h>


//==================================================================================================
simple_circuitt compile_function(
  circuit_target_kindt kind,
  goto_programt const &func,
  goto_modulet &module,
  messaget &msg)
{
  std::string func_name = as_string(goto_programt::get_function_id(func));
  msg.status() << "\nFunction \"" << func_name << '\"' << messaget::eom;
  msg.status() << "Time limit: " << module.options().get_signed_int_option("minimization-time-limit") << messaget::eom;

  bmc_gct bmc(module.options(), module.original_symbols(), module.transformed_symbols(), msg);

  // Tell the symbolic executer which function bodies we want to skip (i.e. treat as external
  // functions)
  for(auto const &func_name: module.funcs_to_skip())
	  bmc.symex.ignore_function_body.insert(func_name);

  // Setup symbolic execution
  bmc.symex.options=module.options();
  msg.status() << "Starting Bounded Model Checking" << messaget::eom;
  bmc.symex.last_source_location.make_nil();
  bmc.setup_unwind();

  namespacet ns{module.transformed_symbols()};
  boolbv_widtht boolbv_width{ns};

  switch(kind)
  {
    case circuit_target_kindt::boolean: return compile_bool(func, module, bmc, msg);
    case circuit_target_kindt::arithmetic: return compile_arith(func, module, bmc, boolbv_width);
  }

  assert(!"unreachable");
}


//==================================================================================================
namespace
{

std::string arg_to_string(typet const &type)
{
  std::stringstream ss;

  if(type.id() == ID_signedbv)
    ss << "int" << to_bitvector_type(type).get_width();
  else if(type.id() == ID_unsignedbv)
    ss << "uint" << to_bitvector_type(type).get_width();
  else if(type.id() == ID_array)
  {
    array_typet const &array_type = to_array_type(type);

    mp_integer size;
    if(to_integer(array_type.size(), size))
      throw std::runtime_error{"Array size must be a constant expression"};

    ss << arg_to_string(array_type.subtype()) << '[' << size << ']';
  }
  else
    throw std::runtime_error{"Cannot convert arg type to string"};

  return ss.str();
}

std::string arg_to_string(exprt const &arg)
{
  // TODO We probably should replace '<' and '>' with '{' and '}' because angle brackets are not
  //      valid filename characters on Windows

  std::stringstream ss;
  ss << arg_to_string(arg.type());
  if(arg.id() == ID_constant)
  {
    if(arg.type().id() == ID_bool)
      ss << "<" << (arg.is_true() ? "true" : "false") << ">";
    else
    {
      mp_integer value;
      if(to_integer(to_constant_expr(arg), value))
        throw std::runtime_error{"Getting constant value failed"};

      ss << "<" << value << ">";
    }
  }
  else
    throw std::runtime_error{"Cannot convert arg expr to string"};

  return ss.str();
}


symbolt add_parameter(
  goto_functionst::goto_functiont &wrapper_func,
  std::string const &wrapper_func_name,
  symbolt const &func_sym,
  std::string const &param_name,
  typet const &param_type,
  goto_modulet &module)
{
  parameter_symbolt wrapper_func_param;
  wrapper_func_param.module = func_sym.module;
  wrapper_func_param.base_name = param_name;
  wrapper_func_param.name = wrapper_func_name + "::" + param_name;
  wrapper_func_param.mode = func_sym.mode;
  wrapper_func_param.type = param_type;
  module.transformed_symbols().add(wrapper_func_param);

  // Add the parameter to the wrapper function type
  code_typet::parametert cp{wrapper_func_param.type};
  cp.set_identifier(wrapper_func_param.name);
  wrapper_func.type.parameters().push_back(cp);
  wrapper_func.parameter_identifiers.push_back(wrapper_func_param.name);

  return wrapper_func_param;
}

symbolt add_local_variable(
  std::string const &wrapper_func_name,
  symbolt const &func_sym,
  std::string const &var_name,
  typet const &var_type,
  goto_modulet &module)
{
  auxiliary_symbolt local_var_sym;
  local_var_sym.module = func_sym.module;
  local_var_sym.base_name = var_name;
  local_var_sym.name = wrapper_func_name + "::" + var_name;
  local_var_sym.mode = func_sym.mode;
  local_var_sym.type = var_type;
  module.original_symbols().add(local_var_sym);
  module.transformed_symbols().add(local_var_sym);

  return local_var_sym;
}

}

// Builds a (hopefully) unique function name suffix consisting of the types and potential constant
// values of its parameters specified in `specializations`.
std::string build_func_name_suffix(code_typet const &func_type, param_specialzationst const &specializations)
{
  // We need to be careful not to use any characters that are not recognized by extract_variable_info()
  // as a valid function name character

  std::vector<std::string> args;

  for(auto const &param: func_type.parameters())
  {
    assert(!param.get_identifier().empty());
    variable_infot var_info = extract_variable_info(param.get_identifier());
    auto it = specializations.find(str(var_info.unqualified_name));

    if(it != specializations.end())
    {
      auto const &param_val = it->second;

      if(!param_val.type.id().empty())
        args.push_back(arg_to_string(param_val.type));
      else if(!param_val.value.id().empty())
        args.push_back(arg_to_string(param_val.value));
      else
        assert(0);
    }
    else
      args.push_back(param.type().id().c_str());
  }

  return "<" + join(args, ",") + ">";
}


simple_circuitt compile_specialized_circuit(
  circuit_target_kindt circuit_kind,
  goto_programt const &func,
  goto_modulet &module,
  param_specialzationst const &specializations,
  messaget &msg)
{
  // Get some info about the function we want to specialize
  std::string func_name = as_string(goto_programt::get_function_id(func));
  symbolt const &func_sym = module.lookup(func_name);
  code_typet const &func_type = to_code_type(func_sym.type);

  // Create the call expression to the function we want to specialize
  code_function_callt call;
  call.function() = module.lookup(func_name).symbol_expr();

  // Create the wrapper function
  goto_functionst::goto_functiont wrapper_func;
  wrapper_func.type.return_type() = func_type.return_type();

  std::string wrapper_func_name = id2string(func_sym.base_name) + build_func_name_suffix(func_type, specializations);

  std::vector<std::pair<symbolt, bool>> output_variables;

  // Build the argument list for the call to the function we want to specialize
  for(auto const &param: func_type.parameters())
  {
    variable_infot var_info = extract_variable_info(param.get_identifier());
    auto it = specializations.find(str(var_info.unqualified_name));

    // Do we want to specialize this parameter?
    if(it != specializations.end())
    {
      auto const &param_val = it->second;

      // Do we want to specialize the type of the parameter?
      if(!param_val.type.id().empty())
      {
        if(param_val.type.id() != ID_array || param.type().id() != ID_pointer)
          throw std::runtime_error{"Type specialization is only allowed from pointer types to array types"};

        array_typet const &array_type = to_array_type(param_val.type);

        bool is_output = starts_with(var_info.unqualified_name, "OUTPUT") || starts_with(var_info.unqualified_name, "INOUT");
        bool is_input = !starts_with(var_info.unqualified_name, "OUTPUT");

        symbolt array_variable = is_input ?
          add_parameter(wrapper_func, wrapper_func_name, func_sym, str(var_info.unqualified_name), param_val.type, module) :
          add_local_variable(wrapper_func_name, func_sym, str(var_info.unqualified_name), param_val.type, module);

        // Get the address of the array (via &array[0]) and pass it to the
        // function we want to specialize
        symbol_exprt param_expr{array_variable.name, array_variable.type};
        index_exprt idx_expr{param_expr, from_integer(0, unsignedbv_typet{64})};
        address_of_exprt addr_expr{idx_expr, pointer_type(array_type.subtype())};
        call.arguments().push_back(addr_expr);

        if(is_output)
          output_variables.push_back({array_variable, is_input});
      }
      // Do we want to set the parameter to a constant value?
      else if(!param_val.value.id().empty())
      {
        // TODO Check type
        call.arguments().push_back(param_val.value);
      }
    }
    else
    {
      // Okay, no specialzation for this parameter. We will create a new parameter for the wrapper
      // function that is simply passed to the specialized function.

      // Create parameter symbol and insert it into the symbol table
      parameter_symbolt wrapper_func_param;
      wrapper_func_param.module = func_sym.module;
      wrapper_func_param.base_name = str(var_info.unqualified_name);
      wrapper_func_param.name = wrapper_func_name + "::" + var_info.unqualified_name;
      wrapper_func_param.mode = func_sym.mode;
      wrapper_func_param.type = param.type();
      module.transformed_symbols().add(wrapper_func_param);

      // Add the parameter to the wrapper function type
      code_typet::parametert cp{wrapper_func_param.type};
      cp.set_identifier(wrapper_func_param.name);
      wrapper_func.type.parameters().push_back(cp);
      wrapper_func.parameter_identifiers.push_back(wrapper_func_param.name);

      // Pass the parameter as an argument to the function we want to specialize
      symbol_exprt param_expr{wrapper_func_param.name, wrapper_func_param.type};
      call.arguments().push_back(param_expr);
    }
  }


  // Create a symbol for the wrapper function and insert it into the symbol table
  auxiliary_symbolt wrapper_func_sym;
  wrapper_func_sym.module = func_sym.module;
  wrapper_func_sym.base_name = wrapper_func_name;
  wrapper_func_sym.name = wrapper_func_name;
  wrapper_func_sym.mode = func_sym.mode;
  wrapper_func_sym.type = wrapper_func.type;
  module.original_symbols().add(wrapper_func_sym);
  module.transformed_symbols().add(wrapper_func_sym);

  // Add call instruction to the wrapper function
  wrapper_func.body.add_instruction(goto_program_instruction_typet::FUNCTION_CALL)->code = call;

  // If the specialized function returns a value then the wrapper will simply forward it
  if(func_type.return_type().id() != ID_empty)
  {
    auxiliary_symbolt return_lhs_sym;
    return_lhs_sym.module = func_sym.module;
    return_lhs_sym.base_name = wrapper_func_name + RETURN_VALUE_SUFFIX;
    return_lhs_sym.name = wrapper_func_name + RETURN_VALUE_SUFFIX;
    return_lhs_sym.mode = func_sym.mode;
    return_lhs_sym.type = func_type.return_type();
    module.transformed_symbols().add(return_lhs_sym);

    symbol_exprt return_lhs;
    return_lhs.type()=func_type.return_type();
    return_lhs.set_identifier(wrapper_func_name + RETURN_VALUE_SUFFIX);

    symbol_exprt return_rhs;
    return_rhs.type()=func_type.return_type();
    return_rhs.set_identifier(func_name+RETURN_VALUE_SUFFIX);

    wrapper_func.body.add_instruction(goto_program_instruction_typet::ASSIGN)->code = code_assignt{return_lhs, return_rhs};
  }

  // If a pointer is dereferenced for both reading and writing we need to create a additional output
  // variable
  for(auto const &out: output_variables)
  {
    bool is_input_and_output = out.second;
    if(is_input_and_output)
    {
      symbolt const &out_sym = out.first;
      symbol_exprt out_sym_expr{out_sym.name, out_sym.type};

      symbolt ret_sym = add_local_variable(wrapper_func_name, func_sym, as_string(out_sym.base_name) + ",return", out_sym.type, module);
      symbol_exprt ret_sym_expr{ret_sym.name, ret_sym.type};
      wrapper_func.body.add_instruction(goto_program_instruction_typet::ASSIGN)->code = code_assignt{ret_sym_expr, out_sym_expr};
    }
  }

  wrapper_func.body.add_instruction(goto_program_instruction_typet::END_FUNCTION)->function = wrapper_func_name;
  module.goto_functions().function_map[wrapper_func_name] = std::move(wrapper_func);

  // We don't want the call to the function to be skipped
  auto it = module.funcs_to_skip().find(func_name);
  bool readd_func_to_skip = false;
  if(it != module.funcs_to_skip().end())
  {
    module.funcs_to_skip().erase(it);
    readd_func_to_skip = true;
  }

  auto circuit = compile_function(
    circuit_kind,
    module.goto_functions().function_map[wrapper_func_name].body,
    module,
    msg);

  if(readd_func_to_skip)
    module.make_external_call(func_name);

  return circuit;
}
