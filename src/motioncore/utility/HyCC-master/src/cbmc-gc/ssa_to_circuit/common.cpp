#include "common.h"

#include "ssa_to_circuit.h"
#include "../bmc_gc.h"
#include "../goto_conversion_invocation.h"


namespace
{

bool is_template_param(code_typet::parametert const &param)
{
  return param.type().id() == ID_pointer;
}


// Handle function call where every argument is passed by value
generic_function_callt handle_normal_call(
  goto_symex_steppert &stepper,
  std::string const &func_name,
  int call_id,
  code_typet const &func_type)
{
  generic_function_callt func_call;
  func_call.name = func_name;
  func_call.call_id = call_id;

  // Get arguments and argument-to-parameter assignments
  int param_count = func_type.parameters().size();
  while(param_count-- > 0 && stepper.cur_instruction()->is_assignment() && !stepper.cur_instruction()->ignore)
  {
    // Remember the assignments to the parameters
    func_call.arg_to_param_assignments.push_back(stepper.cur_instruction()->cond_expr);

    exprt const &lhs = stepper.cur_instruction()->cond_expr.op0();
    assert(lhs.id() == ID_symbol);
    auto &identifier = to_symbol_expr(lhs).get_identifier();

    func_call.args.push_back({extract_variable_info(identifier), lhs.type()});

    stepper.next_instruction();
  }

  // We assume the function body is empty thanks to our implementation of
  // cbmc_gc_symext::symex_function_call_code() which means the next instruction is already the
  // assignment to the return variable (if the function has a return value).

  // Get the return value
  if(stepper.cur_instruction()->is_assignment())
  {
    exprt const &lhs = stepper.cur_instruction()->cond_expr.op0();
    auto &lhs_identifier = to_symbol_expr(lhs).get_identifier();
    assert(as_string(lhs_identifier).find(as_string(func_name) + RETURN_VALUE_SUFFIX) == 0);

    func_call.returns.push_back({extract_variable_info(lhs_identifier), lhs.type(), emptyopt});

    stepper.next_instruction();
  }

  assert(stepper.cur_instruction()->is_function_return());
  stepper.next_instruction();

  return func_call;
}


// Tries to find the symbol `expr` points to
ssa_exprt const& get_pointee(exprt const &expr)
{
  if(expr.id() == ID_symbol)
    return to_ssa_expr(expr);
  else if(expr.id() == ID_address_of)
    return get_pointee(to_address_of_expr(expr).object());
  else if(expr.id() == ID_index)
    return get_pointee(to_index_expr(expr).array());
  else if(expr.id() == ID_member)
    return get_pointee(to_member_expr(expr).compound());

  std::cout << expr.pretty() << std::endl;
  throw std::runtime_error{"Couldn't find pointee"};
}

// Returns the base object and byte offset
std::pair<address_of_exprt const*, ptrdiff_t> find_closest_address_of(exprt const &expr)
{
  ptrdiff_t offset = 0;
  exprt const *cur = &expr;

  if(cur->id() == ID_typecast)
    cur = &to_typecast_expr(*cur).op();

  if(cur->id() == ID_plus)
  {
    // Assume that pointer arithmetic is only performed on char*
    signedbv_typet const &subtype = to_signedbv_type(to_pointer_type(cur->type()).subtype());
    assert(subtype.get_width() == 8); // TODO Get number of char bits from CBMC

    plus_exprt const &plus = to_plus_expr(*cur);
    cur = &plus.op0();
    
    mp_integer mp_offset;
    if(to_integer(to_constant_expr(plus.op1()), mp_offset))
      throw std::runtime_error{"Expected constant"};

    offset = integer2size_t(mp_offset);
  }

  if(cur->id() == ID_typecast)
    cur = &to_typecast_expr(*cur).op();

  if(cur->id() == ID_address_of)
    return {&to_address_of_expr(*cur), offset};

  return {nullptr, 0};
}

exprt const& remove_zero_indexes(exprt const &expr)
{
  if(expr.id() != ID_index)
    return expr;

  index_exprt const &ie = to_index_expr(expr);
  if(!ie.index().is_zero())
    return expr;

  return remove_zero_indexes(ie.array());
}

// Returns true iff
// (1) the source and target type are the same or
// (2) the target is of pointer type, and a value of that type could point to a value of the source
//     type.
// 
// Examples:
// - int is compatible to int
// - int* is compatible to int
// - int* is compatible to int[5]
// - int* is not compatible to float
// - int* is not compatible to float[5]
bool type_compatible(typet const &target, typet const &source)
{
  if(target == source)
    return true;

  if(target.id() == ID_pointer)
  {
    pointer_typet const &target_ptr = to_pointer_type(target);
    if(target_ptr.subtype() == source)
      return true;

    if(source.id() == ID_array)
    {
      array_typet source_array = to_array_type(source);
      if(target_ptr.subtype() == source_array.subtype())
        return true;
    }
  }

  return false;
}

exprt byte_offset_to_element(
  namespacet const &ns,
  exprt const &object,
  size_t byte_offset,
  typet const &target_type)
{
  boolbv_widtht boolbv_width{ns};
  typet const &object_type = ns.follow(object.type());

  if(type_compatible(target_type, object_type) && byte_offset == 0)
    return object;

  if(object_type.id() == ID_array)
  {
    typet array_type = to_array_type(object_type);
    size_t element_bit_width = boolbv_width(array_type.subtype());
    assert(element_bit_width % 8 == 0);
    size_t element_byte_size = element_bit_width / 8; // TODO Get char width from CBMC

    size_t index = byte_offset / element_byte_size;
    size_t sub_offset = byte_offset % element_byte_size;

    exprt result_expr = index_exprt(object, from_integer(index, unsignedbv_typet{64}), array_type.subtype());
    return byte_offset_to_element(ns, result_expr, sub_offset, target_type);
  }
  else if(object_type.id() == ID_struct)
  {
    struct_typet const &struct_type = to_struct_type(object_type);
    const struct_typet::componentst &components = struct_type.components();

    for(struct_typet::componentt const &comp: components)
    {
      const typet &subtype = comp.type();
      size_t element_bit_width = boolbv_width(subtype);
      size_t element_byte_size = element_bit_width / 8; // TODO Get char width from CBMC

      if(byte_offset < element_byte_size)
      {
        exprt result_expr = member_exprt{object, comp.get_name(), subtype};
        return byte_offset_to_element(ns, result_expr, byte_offset, target_type);
      }

      assert(element_byte_size <= byte_offset);
      byte_offset -= element_byte_size;
    }

    throw std::runtime_error{"Invalid byte offset"};
  }
  else
    throw std::runtime_error{"Byte offset only applicable to arrays or structs, got " + object.pretty()};
}


// For each ssa_exprt: if no SSA index (level 2) has been set, set it to the most current one
class ssa_updatert : public expr_visitort
{
public:
  ssa_updatert(goto_symex_statet &state) :
    state{&state} {}

  virtual void operator()(exprt &expr) override
  {
    if(expr.id() == ID_symbol)
    {
      ssa_exprt &ssa_expr = to_ssa_expr(expr);
      if(ssa_expr.get_level_2().empty())
      {
        unsigned ssa_idx = state->level2.current_count(ssa_expr.get_identifier());
        ssa_expr.set_level_2(ssa_idx);
      }
    }
  }

  goto_symex_statet *state;
};


generic_function_callt handle_specialization_call(
  goto_symex_steppert &stepper,
  std::string const &func_name,
  int call_id,
  code_typet const &func_type,
  goto_modulet &module)
{
  param_specialzationst specializations;

  struct pointer_arg_assignmentt
  {
    ssa_exprt pointee;
    exprt arg_expr;
    code_typet::parametert param;
  };

  std::vector<pointer_arg_assignmentt> arg_assignments;

  struct additional_rett
  {
    irep_idt param_base_name;
    ssa_exprt arg;
    exprt arg_expr;
  };

  std::vector<additional_rett> additional_returns;

  namespacet ns{module.transformed_symbols()};

  // Get arguments and argument-to-parameter assignments
  int const param_count = func_type.parameters().size();
  int cur_param_idx = 0;
  while(cur_param_idx < param_count && stepper.cur_instruction()->is_assignment() && !stepper.cur_instruction()->ignore)
  {
    auto const &param = func_type.parameters()[cur_param_idx];

    exprt const &arg_expr = stepper.cur_instruction()->cond_expr.op1();

    // Pointer arguments need special treatment
    address_of_exprt const *addr_of_expr;
    ptrdiff_t addr_offset;
    std::tie(addr_of_expr, addr_offset) = find_closest_address_of(arg_expr);
    if(addr_of_expr)
    {
      ssa_exprt const &pointee = get_pointee(*addr_of_expr);

      // An address is passed to the function. Right now, the following cases are supported:
      //
      // (1) Passing a single value: `int a; foo(&a);`
      //     The deduced argument type should be `int`
      // (2) Passing a complete array: `int arr[5]; foo(arr);`
      //     The deduced argument type should be `int[5]`
      // (3) Passing an array element: `int arr[5][5]; foo(arr[5]);`
      //     The deduced argument type should be `int[5]`
      // (4) Passing a struct element: `foo(s.arr)` with `s.arr` being an array
      //     The deduced argument type should be the type of `s.arr`
      //
      // In cases (3) and (4) the problem is that instead of index_exprt/member_exprt pointer
      // arithmetic is used. For example, if we have `int arr[5][5]`, then instead of `arr[2]` we
      // get `(int*)((char*)&arr[0][0] + 40)`. We need to transform this back to `arr[2]`.
      exprt deduced_arg;

      // Cases (1) and (4)
      if(addr_of_expr->object().id() == ID_symbol)
        deduced_arg = byte_offset_to_element(ns, addr_of_expr->object(), addr_offset, param.type());
      // Cases (2) and (3)
      else if(addr_of_expr->object().id() == ID_index)
      {
        index_exprt const &ie = to_index_expr(addr_of_expr->object());
        deduced_arg = byte_offset_to_element(ns, remove_zero_indexes(ie.array()), addr_offset, param.type());
      }
      else
        throw std::runtime_error{"Unsupported case"};


      /*std::cout << "ORIGINAL: " << from_expr(arg_expr) << std::endl;
      std::cout << "ORIGINAL: " << arg_expr.pretty() << std::endl;
      std::cout << "DEDUCED: " << from_expr(deduced_arg) << std::endl;
      std::cout << "DEDUCED: " << deduced_arg.pretty() << std::endl;*/


      specializations[as_string(param.get_base_name())] = deduced_arg.type();

      std::string str_name = as_string(param.get_base_name());
      bool is_output = str_name.find("OUTPUT") == 0 || str_name.find("INOUT") == 0;
      bool is_input = str_name.find("OUTPUT") != 0;

      if(is_output)
        additional_returns.push_back({param.get_base_name(), pointee, deduced_arg});

      // We only need to pass an argument if it is used as an INPUT
      if(is_input)
        arg_assignments.push_back({pointee, deduced_arg, param});
    }
    else
    {
      exprt const &arg = stepper.cur_instruction()->cond_expr.op1();
      if(arg.id() != ID_constant)
      {
        std::cout << arg.pretty() << std::endl;
        throw std::runtime_error{
          "Right now, the arguments of functions that take a pointer must all be constant expressions."
        };
      }

      specializations[as_string(param.get_base_name())] = to_constant_expr(arg);
    }

    ++cur_param_idx;
    stepper.next_instruction();
  }

  module.add_specialization(func_name, specializations);

  auto specialized_func_name = as_string(func_name) + build_func_name_suffix(func_type, specializations);

  generic_function_callt func_call;
  func_call.name = specialized_func_name;
  func_call.call_id = call_id;

  for(auto &paa: arg_assignments)
  {
    // We also need to insert the symbol into the symbol table (but only if it doesn't exist yet)
    irep_idt param_id = specialized_func_name + "::" + as_string(paa.param.get_base_name()) + "@" + std::to_string(call_id);
    if(!module.transformed_symbols().has_symbol(param_id))
    {
      symbolt const &func_sym = module.lookup(func_name.c_str());
      parameter_symbolt param_sym;
      param_sym.module = func_sym.module;
      param_sym.base_name = paa.param.get_base_name();
      param_sym.name = param_id;
      param_sym.mode = func_sym.mode;
      param_sym.type = paa.arg_expr.type();
      module.transformed_symbols().add(param_sym);
    }

    symbol_exprt param_expr;
    param_expr.type() = paa.arg_expr.type();
    param_expr.set_identifier(param_id);


    // The argument was passed by reference to the function. Apparently, pointed-to symbols do not
    // get an SSA index, which is a problem. To work around this, we have to set the SSA index
    // manually.
    ssa_updatert ssa_updater{stepper.state()};
    paa.arg_expr.visit(ssa_updater);


    func_call.arg_to_param_assignments.push_back(equal_exprt{param_expr, paa.arg_expr});
    func_call.args.push_back({extract_variable_info(param_id), param_expr.type()});
  }


  // We assume the function body is empty thanks to our implementation of
  // cbmc_gc_symext::symex_function_call_code() which means the next instruction is already the
  // assignment to the return variable (if the function has a return value).

  // Get the return value
  if(stepper.cur_instruction()->is_assignment())
  {
    exprt const &lhs = stepper.cur_instruction()->cond_expr.op0();
    auto &lhs_identifier = to_symbol_expr(lhs).get_identifier();
    assert(as_string(lhs_identifier).find(as_string(func_name) + RETURN_VALUE_SUFFIX) == 0);

    func_call.returns.push_back({extract_variable_info(lhs_identifier), lhs.type(), emptyopt});

    stepper.next_instruction();
  }

  for(auto const &ret: additional_returns)
  {
    std::string var_name;
    if(starts_with(cstring_ref{ret.param_base_name.c_str()}, "INOUT"))
      var_name = specialized_func_name + "::" + ret.param_base_name.c_str() + ",return@" + std::to_string(call_id);
    else
      var_name = specialized_func_name + "::" + ret.param_base_name.c_str() + "@" + std::to_string(call_id);

    func_call.returns.push_back({extract_variable_info(var_name), ret.arg_expr.type(), {{ret.arg, ret.arg_expr}}});
  }

  assert(stepper.cur_instruction()->is_function_return());
  stepper.next_instruction();

  return func_call;
}

}


// If the instruction pointed to by `step_it` is a function call and the called function has
// an entry in `funcs_to_skip`, the list of arguments and return values will be returned.
optional<generic_function_callt> handle_function_call(
  bmc_gct &bmc,
  goto_symex_steppert &stepper,
  goto_modulet &module)
{
  assert(stepper.cur_instruction()->is_function_call());

  std::string func_name = stepper.cur_instruction()->identifier.c_str();

  bmc.function_call_counter++;
  stepper.next_instruction();

  if(!module.is_external_call(func_name))
    return emptyopt;

  int call_id = bmc.function_call_counter - 1;
  code_typet const &func_type = module.func_type(func_name);

  if(is_template_func(func_type))
    return handle_specialization_call(stepper, func_name, call_id, func_type, module);
  else
    return handle_normal_call(stepper, func_name, call_id, func_type);
}


bool is_template_func(code_typet const &func)
{
  for(auto const &param: func.parameters())
  {
    if(is_template_param(param))
      return true;
  }

  return false;
}


void replace_subject_with(exprt &expr, ssa_exprt const &new_subject)
{
	if(expr.id() == ID_symbol)
		expr = new_subject;
	else if(expr.id() == ID_index)
		replace_subject_with(expr.op0(), new_subject);
	else if(expr.id() == ID_member)
		replace_subject_with(expr.op0(), new_subject);
	else
	{
		std::cout << from_expr(expr) << std::endl;
		throw std::runtime_error{"replace_subject_with: unsupported expr"};
	}
}
