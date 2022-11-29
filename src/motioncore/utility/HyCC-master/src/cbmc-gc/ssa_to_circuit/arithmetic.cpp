#include "arithmetic.h"

#include "../bmc_gc.h"
#include "../goto_conversion_invocation.h"


//==================================================================================================
namespace {

template<typename Accu, typename Visitor, typename Merger>
void foldr_leaf_types(typet const &type, Accu &accu, Visitor &&visitor, Merger &&merger)
{
  if(type.id() ==  ID_array)
  {
    array_typet array_type = to_array_type(type);

    // Must have a finite size
    mp_integer array_size_mp;
    if(to_integer(array_type.size(), array_size_mp))
      throw "failed to convert array size";

    size_t array_size = integer2size_t(array_size_mp);

    Accu sub_accu{};
    foldr_leaf_types(array_type.subtype(), sub_accu, std::forward<Visitor>(visitor), std::forward<Merger>(merger));
    merger(accu, sub_accu, array_size);
  }
  else if(type.id() == ID_struct)
  {
    struct_typet struct_type = to_struct_type(type);
    auto const &comps = struct_type.components();

    for(size_t i = 0; i < comps.size(); ++i)
    {
      Accu sub_accu{};
      foldr_leaf_types(comps[i].type(), sub_accu, std::forward<Visitor>(visitor), std::forward<Merger>(merger));
      merger(accu, sub_accu, 1);
    }
  }
  else if(type.id() == ID_signedbv || type.id() == ID_unsignedbv)
    visitor(accu, type);
  else
	  assert(!"Invalid input type");
}

struct VectorMerger
{
  template<typename T, typename A>
  void operator () (std::vector<T, A> &accu, std::vector<T, A> const &sub_accu, size_t count)
  {
    while(count--)
      accu.insert(accu.end(), sub_accu.begin(), sub_accu.end());
  }
};


//==================================================================================================
struct arith_symbol_entryt
{
  typet type;
  std::vector<simple_circuitt::gatet*> gates;
};

// Maps SSA identifiers to their gates
using arith_symbol_tablet = std::unordered_map<irep_idt, arith_symbol_entryt, irep_id_hash>;

// Holds the state needed to compile SSA expressions to a circuit
struct arithmetic_comp_statet
{
  using gate_cachet = std::unordered_map<const exprt, std::vector<simple_circuitt::gatet*>, irep_hash>;

  arithmetic_comp_statet(namespacet const &ns, boolbv_widtht const &boolbv_width, simple_circuitt &circuit) :
    ns{ns},
    boolbv_width{boolbv_width},
    circuit{circuit} {}

  namespacet const &ns;
  boolbv_widtht const &boolbv_width;
  arith_symbol_tablet sym_table;
  simple_circuitt &circuit;
  gate_cachet gate_cache;
};

using GateVector = std::vector<simple_circuitt::gatet*>;


// Creates input gates for the given type
GateVector create_input_gates_from_type(
  simple_circuitt *circuit,
  typet const &type,
  boolbv_widtht const &boolbv_width)
{
  std::vector<size_t> input_widths;

  foldr_leaf_types(type, input_widths,
    // Visitor
    [&](std::vector<size_t> &accu, typet const &leaf)
    {
      accu.push_back(boolbv_width(leaf));
    },
    VectorMerger{}
  );

  GateVector inputs;
  inputs.reserve(input_widths.size());
  for(size_t width: input_widths)
    inputs.push_back(circuit->create_input_gate(std::to_string(circuit->num_inputs()), width));

  return inputs;
}

// Creates output gates for the given type
std::vector<simple_circuitt::gatet*> create_output_gates_from_type(
  simple_circuitt *circuit,
  typet const &type,
  boolbv_widtht const &boolbv_width)
{
  std::vector<size_t> output_widths;

  foldr_leaf_types(type, output_widths,
    // Visitor
    [&](std::vector<size_t> &accu, typet const &leaf)
    {
      accu.push_back(boolbv_width(leaf));
    },
    VectorMerger{}
  );

  GateVector outputs;
  outputs.reserve(output_widths.size());
  for(size_t width: output_widths)
    outputs.push_back(circuit->create_output_gate("", width));

  return outputs;
}

// Returns the number of primitive values (i.e., integers of any width) that are needed to represent
// an instance of the specified type.
size_t get_element_count(typet const &type)
{
  size_t count = 0;
  foldr_leaf_types(type, count,
    // Visitor
    [](size_t &accu, typet const&) { accu += 1; },
    // Merger
    [](size_t &accu, size_t sub_accu, int count) { accu += sub_accu * count; }
  );

  return count;
}


std::vector<simple_circuitt::gatet*> compile_arith_expr_uncached(
  arithmetic_comp_statet &state,
  exprt const &expr);


// Compiles a side-effect free epression.
std::vector<simple_circuitt::gatet*> compile_arith_expr(
  arithmetic_comp_statet &state,
  exprt const &expr)
{
  auto cache_res = state.gate_cache.insert({expr, {}});
  if(!cache_res.second)
    return cache_res.first->second;

  auto gates = compile_arith_expr_uncached(state, expr);
  cache_res.first->second = gates;

  return gates;
}


simple_circuitt::gatet* compile_arith_expr_scalar(
  arithmetic_comp_statet &state,
  exprt const &expr)
{
  auto gates = compile_arith_expr(state, expr);
  if(gates.size() != 1)
    throw std::runtime_error{"Expected scalar expression"};

  return gates.front();
}


std::vector<simple_circuitt::gatet*> compile_arith_with_expr(
  arithmetic_comp_statet &state,
  with_exprt const &with_expr)
{
  // TODO Handle any number of operands (see boolbvt::convert_with)
  assert(with_expr.operands().size() == 3);

  exprt const &old_value = with_expr.op0();
  exprt const &index = with_expr.op1();
  exprt const &new_value = with_expr.op2();

  typet const &type = old_value.type();

  if(type.id() == ID_struct)
  {
    auto old_gates = compile_arith_expr(state, old_value);
    auto new_gates = compile_arith_expr(state, new_value);

    struct_typet const &struct_type = to_struct_type(type);
    irep_idt const &component_name = index.get(ID_component_name);

    size_t offset=0;
    for(struct_typet::componentt const &comp: struct_type.components())
    {
      const typet &subtype = comp.type();
      std::size_t sub_elements = get_element_count(subtype);

      if(comp.get_name()==component_name)
      {
        assert(offset + sub_elements <= old_gates.size());
        assert(sub_elements == new_gates.size());

        for(std::size_t i=0; i<sub_elements; i++)
          old_gates[offset+i] = new_gates[i];

        return old_gates;
      }

      offset+=sub_elements;
    }

    throw std::runtime_error{"Invalid struct member name"};
  }
  else if(type.id() == ID_array)
  {
    auto old_gates = compile_arith_expr(state, old_value);
    auto new_gates = compile_arith_expr(state, new_value);

    array_typet const &array_type = to_array_type(type);

    // Must have a finite size
    mp_integer array_size_mp;
    if(to_integer(array_type.size(), array_size_mp))
      throw "failed to convert array size";
    size_t array_size = integer2size_t(array_size_mp);

    // see if the index address is constant
    mp_integer index_value_mp;
    if(to_integer(index, index_value_mp))
      throw non_arithmetic_expression_error{"Dynamic array access not supported in arithmetic circuits"};
    size_t index_value = integer2size_t(index_value_mp);

    if(index_value >= array_size)
      throw std::runtime_error{"Array index out of bounds"};

    size_t element_size = get_element_count(array_type.subtype());
    assert(array_size * element_size == old_gates.size());
    assert(element_size == new_gates.size());

    size_t offset = index_value * element_size;
    for(size_t i = 0; i < element_size; ++i)
      old_gates[offset + i] = new_gates[i];

    return old_gates;
  }

  throw std::runtime_error{"Expected array or struct in with_exprt"};
}

std::vector<simple_circuitt::gatet*> compile_arith_expr_uncached(
  arithmetic_comp_statet &state,
  exprt const &expr)
{
  int width = state.boolbv_width(expr.type());


  if(expr.type().id() == ID_pointer)
  {
    if(expr.id() == ID_address_of)
    {
      // TODO Get pointer width from CBMC (from config?)
      size_t pointer_width = 64;

      // TODO I don't know if this is correct
      static int addr_counter = 0;
      int address = addr_counter++;

      return {state.circuit.get_or_create_gate(simple_circuitt::CONST, pointer_width, address)};
    }
    else if(expr.id() == ID_typecast)
    {
      typecast_exprt cast_expr = to_typecast_expr(expr);
      return compile_arith_expr(state, cast_expr.op());
    }
    else if(expr.id() == ID_plus)
    {
      // TODO POINTER ARITHMETIC IS NOT IMPLEMENTED CORRECTLY YET!

      assert(expr.operands().size() == 2);

      auto op0 = compile_arith_expr_scalar(state, expr.op0());
      auto op1 = compile_arith_expr_scalar(state, expr.op1());
      auto add_gate = state.circuit.get_or_create_gate(simple_circuitt::ADD, width);
      add_gate->add_fanin(primary_output(op0), 0);
      add_gate->add_fanin(primary_output(op1), 1);

      return {add_gate};
    }
  }


  if(expr.type().id() != ID_unsignedbv &&
     expr.type().id() != ID_signedbv &&
     expr.type().id() != ID_array &&
     expr.type().id() != ID_struct)
  {
    std::cout << from_expr(state.ns, "", expr) << std::endl;
    std::cout << expr.pretty() << std::endl;
    throw non_arithmetic_expression_error{"Arithmetic circuits only support signed/unsigned integers, structs and arrays"};
  }

  if(expr.id() == ID_constant)
  {
    constant_exprt const_expr = to_constant_expr(expr);
    mp_integer value_mp;
    if(to_integer(const_expr, value_mp))
      throw non_arithmetic_expression_error{"Converting constant to integer failed."};

    size_t value = integer2size_t(value_mp);
    size_t width = state.boolbv_width(expr.type());

    return {state.circuit.get_or_create_gate(simple_circuitt::CONST, width, value)};
  }
  else if(expr.id() == ID_symbol)
  {
    symbol_exprt const &se = to_symbol_expr(expr);

    // Have we seen this variable before?
    auto it = state.sym_table.find(se.get_identifier());
    if(it != state.sym_table.end())
      return it->second.gates;

    // Okay, we haven't seen this symbol before.

    variable_infot vi = extract_variable_info(se.get_identifier());
    optional<io_variable_typet> io_type = extract_io_type(vi, true);

    // Check if it is an INPUT
    if(io_type && *io_type != io_variable_typet::output)
    {
      auto input_gates = create_input_gates_from_type(&state.circuit, expr.type(), state.boolbv_width);
      auto tmp = input_gates;

      state.circuit.add_variable(
        str(vi.unqualified_name),
        *io_type == io_variable_typet::input_a ? variable_ownert::input_alice : variable_ownert::input_bob,
        from_cbmc(expr.type()),
        std::move(input_gates)
      );

      state.sym_table[se.get_identifier()] = {expr.type(), tmp};

      return tmp;
    }
    else
    {
      // So it's not an INPUT which means there are two possible cases (that I can think of):
      //
      //   1) We are reading from an unitialized variable (which is an error)
      //   2) We are currently evaluating a with_exprt (or update_exprt) which creates the final
      //      value by combining the old and the new value. Since we don't have an old value yet,
      //      we return a vector with NULL gates. Note that we don't create an entry in the symbol
      //      table as we will never read from this symbol again (subsequent reads will refer to the
      //      target of the with_exprt)
      //
      // We should report an error for case 1), but because we can't differentiate between 1) and 2)
      // we will always do 2).
      
      return std::vector<simple_circuitt::gatet*>(get_element_count(expr.type()), nullptr);
    }

  }
  // Subtraction is addition with a negated operand
  else if(expr.id() == ID_plus)
  {
    std::vector<std::pair<simple_circuitt::gatet*, bool>> gate_ops;
    gate_ops.reserve(expr.operands().size());

    // Convert operands to gates
    // TODO To use as many SUB gates as possible and to reduce the number of NEG gates it would be
    //      good to sort the operands in such a way that we have alternating negated and unnegated
    //      gates.
    for(auto const &op: expr.operands())
    {
      if(expr.type() != op.type())
        throw "add/sub with mixed types";

      if(op.id() == ID_unary_minus)
        gate_ops.push_back({compile_arith_expr_scalar(state, op.op0()), true});
      else
        gate_ops.push_back({compile_arith_expr_scalar(state, op), false});
    }

    // Build ADD-tree
    auto sum_gate = build_tree(gate_ops, [&](std::pair<simple_circuitt::gatet*, bool> a, std::pair<simple_circuitt::gatet*, bool> b, int)
    {
      // If there is only one negated operand make sure it is the right one.
      if(a.second && !b.second)
        std::swap(a, b);

      simple_circuitt::gatet *left_gate = nullptr;
      if(a.second)
      {
        left_gate = state.circuit.get_or_create_gate(simple_circuitt::NEG, width);
        left_gate->add_fanin(primary_output(a.first), 0);
      }
      else
        left_gate = a.first;

      simple_circuitt::gatet *op_gate = nullptr;
      if(b.second)
        op_gate = state.circuit.get_or_create_gate(simple_circuitt::SUB, width);
      else
        op_gate = state.circuit.get_or_create_gate(simple_circuitt::ADD, width);

      op_gate->add_fanin(primary_output(left_gate), 0);
      op_gate->add_fanin(primary_output(b.first), 1);

      return std::make_pair(op_gate, false);
    }).first;

    return {sum_gate};
  }
  else if(expr.id() == ID_mult)
  {
    std::vector<simple_circuitt::gatet*> gate_ops;
    gate_ops.reserve(expr.operands().size());

    // Convert operands to gates
    for(auto const &op: expr.operands())
    {
      if(expr.type() != op.type())
        throw "add/sub with mixed types";

      gate_ops.push_back(compile_arith_expr_scalar(state, op));
    }

    // Build MUL-tree
    auto prod_gate = build_tree(gate_ops, [&](simple_circuitt::gatet *a, simple_circuitt::gatet *b, int)
    {
      auto mul_gate = state.circuit.get_or_create_gate(simple_circuitt::MUL, width);
      mul_gate->add_fanin(primary_output(a), 0);
      mul_gate->add_fanin(primary_output(b), 1);

      return mul_gate;
    });

    return {prod_gate};
  }
  else if(expr.id() == ID_index)
  {
    index_exprt array_expr = to_index_expr(expr);
    const exprt &array = array_expr.array();
    const exprt &index = array_expr.index();
    const typet &array_op_type=state.ns.follow(array.type());
    const array_typet &array_type = to_array_type(array_op_type);

    std::size_t width=state.boolbv_width(expr.type());
    assert(width != 0);

    // TODO
    // see if the array size is constant
    /*if(is_unbounded_array(array_type))
    {
      // [CBMC-GC] We don't support unbounded array.
      throw "Unbounded arrays not supported";
    }*/

    // Must have a finite size
    mp_integer array_size_mp;
    if(to_integer(array_type.size(), array_size_mp))
      throw "failed to convert array size";
    size_t array_size = integer2size_t(array_size_mp);

    // see if the index address is constant
    mp_integer index_value_mp;
    if(to_integer(index, index_value_mp))
      throw non_arithmetic_expression_error{"Dynamic array access not supported in arithmetic circuits"};
    size_t index_value = integer2size_t(index_value_mp);

    if(index_value >= array_size)
      throw std::runtime_error{"Array index out of bounds"};

    size_t element_size = get_element_count(array_type.subtype());
    auto array_gates = compile_arith_expr(state, array);
    assert(array_size * element_size == array_gates.size());

    std::vector<simple_circuitt::gatet*> selected_gates;
    size_t offset = index_value * element_size;
    for(size_t i = offset; i < offset + element_size; ++i)
      selected_gates.push_back(array_gates[i]);

    return selected_gates;
  }
  else if(expr.id() == ID_member)
  {
    member_exprt const &member_expr = to_member_expr(expr);
    exprt const &struct_op = member_expr.struct_op();
    typet const &struct_op_type = state.ns.follow(struct_op.type());

    if(struct_op_type.id() != ID_struct)
      throw non_arithmetic_expression_error{"Arithmetic circuits don't support unions yet"};

    const irep_idt &component_name = member_expr.get_component_name();
    const struct_typet::componentst &components = to_struct_type(struct_op_type).components();

    auto struct_gates = compile_arith_expr(state, struct_op);
    size_t offset=0;
    for(struct_typet::componentt const &comp: components)
    {
      const typet &subtype = comp.type();
      std::size_t sub_elements = get_element_count(subtype);

      if(comp.get_name()==component_name)
      {
        assert(offset + sub_elements <= struct_gates.size());

        std::vector<simple_circuitt::gatet*> selected_gates;
        for(std::size_t i=0; i<sub_elements; i++)
          selected_gates.push_back(struct_gates[offset+i]);

        return selected_gates;
      }

      offset+=sub_elements;
    }

    throw std::runtime_error{"Invalid struct member name"};
  }
  else if(expr.id() == ID_with)
  {
    return compile_arith_with_expr(state, to_with_expr(expr));
  }
  else if(expr.id() == ID_typecast)
  {
    throw non_arithmetic_expression_error{"In arithmetic circuits, typecasts are not allowed: all variables must be of the same width"};
  }
  else if(expr.id() == ID_byte_update_little_endian)
  {
    std::vector<simple_circuitt::gatet*> object = compile_arith_expr(state, expr.op0());

    // We require the byte offset to be constant
    if(expr.op1().id() != ID_constant)
      throw std::runtime_error{"Byte offset must be constant"};

    mp_integer mp_byte_offset;
    if(to_integer(to_constant_expr(expr.op1()), mp_byte_offset))
      throw std::runtime_error{"Converting to constant failed"};

    size_t byte_offset = integer2size_t(mp_byte_offset);
    size_t gate_offset = 0;
    size_t bit_offset = 0;
    for(; gate_offset < object.size(); ++gate_offset)
    {
      // Assume byte width of 8
      // TODO Get byte width from CBMC
      if(bit_offset == byte_offset * 8)
        break;

      bit_offset += object[gate_offset]->get_width();
    }
    assert(gate_offset < object.size());

    std::vector<simple_circuitt::gatet*> element_value = compile_arith_expr(state, expr.op2());
    assert(gate_offset + element_value.size() <= object.size());

    for(size_t i = 0; i < element_value.size(); ++i)
      object[i + gate_offset] = element_value[i];

    return object;
  }
  else if(expr.id() == ID_byte_extract_little_endian)
  {
    std::vector<simple_circuitt::gatet*> object = compile_arith_expr(state, expr.op0());

    // We require the byte offset to be constant
    if(expr.op1().id() != ID_constant)
      throw std::runtime_error{"Byte offset must be constant"};

    mp_integer mp_byte_offset;
    if(to_integer(to_constant_expr(expr.op1()), mp_byte_offset))
      throw std::runtime_error{"Converting to constant failed"};

    size_t byte_offset = integer2size_t(mp_byte_offset);
    size_t gate_offset = 0;
    size_t bit_offset = 0;
    for(; gate_offset < object.size(); ++gate_offset)
    {
      // Assume byte width of 8
      // TODO Get byte width from CBMC
      if(bit_offset == byte_offset * 8)
        break;

      bit_offset += object[gate_offset]->get_width();
    }
    assert(gate_offset < object.size());

    size_t element_bit_width = width;
    std::vector<simple_circuitt::gatet*> element_value;
    for(size_t i = gate_offset; i < object.size() && element_bit_width > 0; ++i)
    {
      element_value.push_back(object[i]);
      element_bit_width -= object[i]->get_width();
    }

    return element_value;
  }

  std::cout << from_expr(state.ns, "", expr) << std::endl;
  std::cout << expr.pretty() << std::endl;
  throw non_arithmetic_expression_error{"Unsupported operation for arithmetic circuit"};
}


// Compiles an assignment to arithmetic gates
void compile_arith_assign_expr(
  arithmetic_comp_statet &state,
  exprt const &expr,
  std::vector<variable_infot> &potential_outputs)
{
  assert(expr.id() == ID_equal);

  exprt const &lhs = expr.op0();
  exprt const &rhs = expr.op1();

  size_t width = state.boolbv_width(lhs.type());
  assert(width == state.boolbv_width(rhs.type()));

  if(lhs.id() == ID_symbol)
  {
    symbol_exprt const &se = to_symbol_expr(lhs);

    variable_infot vi = extract_variable_info(se.get_identifier());
    optional<io_variable_typet> io_type = extract_io_type(vi, true);

    auto rhs_gates = compile_arith_expr(state, rhs);
    auto ins = state.sym_table.insert({se.get_identifier(), {lhs.type(), rhs_gates}});
    assert(ins.second);

    if(vi.func_name == state.circuit.name() && io_type && *io_type == io_variable_typet::output)
    {
      // We don't create the output gates immediately because an OUTPUT may be assigned to multiple
      // times.
      potential_outputs.push_back(vi);
    }
  }
  else
    throw non_arithmetic_expression_error{"In arithmetic circuits, the LHS of an assignment must be a symbol"};
}


void arith_create_outputs(
  simple_circuitt *circuit,
  arith_symbol_tablet const &sym_table,
  std::vector<variable_infot> &potential_outputs)
{
  std::sort(potential_outputs.begin(), potential_outputs.end(), [](variable_infot const &a, variable_infot const &b)
  {
      // Sort outputs in descending order based on unique variable name and SSA index.
      return std::tie(a.qualified_name, a.ssa_index) > std::tie(b.qualified_name, b.ssa_index);
  });

  // Remove all but the first occurence of each variable. This leaves us the outputs with the
  // largest SSA index.
  auto new_end = std::unique(potential_outputs.begin(), potential_outputs.end(), [](variable_infot const &a, variable_infot const &b)
  {
    return a.qualified_name == b.qualified_name;
  });
  potential_outputs.erase(new_end, potential_outputs.end());

  for(variable_infot const &vi: potential_outputs)
  {
    std::vector<simple_circuitt::gatet*> output_gates;
    arith_symbol_entryt const &entry = sym_table.at(vi.unique_name);

    for(auto gate: entry.gates)
    {
      if(!gate)
        throw std::runtime_error{"OUTPUT variable has not been written to completely: " + as_string(vi.unique_name)};

      auto output_gate = circuit->create_output_gate("", gate->get_width());
      output_gate->add_fanin(primary_output(gate), 0);
      output_gates.push_back(output_gate);
    }

    circuit->add_variable(str(vi.unqualified_name), variable_ownert::output, from_cbmc(entry.type), std::move(output_gates));
  }
}


void handle_arith_function_call(
  simple_circuitt &circuit,
  goto_modulet &module,
  bmc_gct &bmc,
  goto_symex_steppert &stepper,
  arithmetic_comp_statet &state,
  std::vector<variable_infot> &potential_outputs,
  boolbv_widtht const &boolbv_width)
{
  assert(stepper.cur_instruction()->is_function_call());

  if(auto func_call = handle_function_call(bmc, stepper, module))
  {
    // Convert the assignments of the arguments to the parameters
    for(exprt const &e: func_call->arg_to_param_assignments)
      compile_arith_assign_expr(state, e, potential_outputs);

    simple_circuitt::function_callt circ_call;
    circ_call.name = as_string(func_call->name);
    circ_call.call_id = func_call->call_id;

    // The return values of the function call are inputs to our circuit so we will create INPUT
    // gates for them.
    for(auto const &ret: func_call->returns)
    {
      auto ret_gates = create_input_gates_from_type(&circuit, ret.type, boolbv_width);

      state.sym_table[ret.var.unique_name] = {ret.type, ret_gates};
      circ_call.returns.push_back({str(ret.var.unqualified_name), from_cbmc(ret.type), ret_gates});

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
        stepper.state().level2.current_names.insert({old_arg_sym.get_identifier(), {old_arg_sym, 0}});
        old_arg_sym.set_level_2(stepper.state().level2.current_count(old_arg_sym.get_identifier()));

        // Since we are going to overwrite the argument, we must increase its SSA index
        stepper.state().level2.increase_counter(arg_l1_id);

        // `new_arg_sym` is the SSA symbol that contains the value that was written to the argument
        // by the function.
        ssa_exprt new_arg_sym = old_arg_sym;
        new_arg_sym.set_level_2(stepper.state().level2.current_count(arg_l1_id));

        // `ret_sym` contains the output of the function that we will write to `new_arg_sym`
        symbol_exprt ret_sym{ret.var.unique_name, ret.type};

        if(arg_expr.id() == ID_symbol)
          compile_arith_assign_expr(state, equal_exprt{new_arg_sym, ret_sym}, potential_outputs);
        else
        {
          replace_subject_with(arg_expr, old_arg_sym);
          compile_arith_assign_expr(state, equal_exprt{new_arg_sym, with_exprt{old_arg_sym, arg_expr, ret_sym}}, potential_outputs);
        }
      }
    }

    for(auto const &arg: func_call->args)
    {
      auto arg_gates = create_output_gates_from_type(&circuit, arg.second, boolbv_width);
      auto const &output_fanins = state.sym_table.at(arg.first.unique_name);
      assert(arg_gates.size() == output_fanins.gates.size());
      for(size_t i = 0; i < arg_gates.size(); ++i)
        arg_gates[i]->add_fanin(primary_output(output_fanins.gates[i]), 0);

      circ_call.args.push_back({str(arg.first.unqualified_name), from_cbmc(arg.second), arg_gates});
    }

    circuit.add_function_call(std::move(circ_call));
  }
}

}


//==================================================================================================
simple_circuitt compile_arith(
  goto_programt const &func,
  goto_modulet &module,
  bmc_gct &bmc,
  boolbv_widtht const &boolbv_width)
{
  std::string func_name = as_string(goto_programt::get_function_id(func));

  // now run symbolic execution
  goto_symex_steppert stepper{bmc.symex, module.function_getter(), func};

  // convert assignments to arithmetic circuit

  simple_circuitt circuit{default_logger(), func_name};
  arithmetic_comp_statet state{bmc.ns, boolbv_width, circuit};
  std::vector<variable_infot> potential_outputs;

  std::vector<generic_function_callt> func_calls;
  while(!stepper)
  {
    auto step_it = stepper.cur_instruction();

    if(step_it->is_assignment() && !step_it->ignore)
    {
      //std::cout << from_expr(step_it->cond_expr) << std::endl;
      compile_arith_assign_expr(state, step_it->cond_expr, potential_outputs);
      stepper.next_instruction();
    }
    else if(step_it->is_function_call())
      handle_arith_function_call(circuit, module, bmc, stepper, state, potential_outputs, boolbv_width);
    else
      stepper.next_instruction();;
  }

  arith_create_outputs(&circuit, state.sym_table, potential_outputs);

  for(auto const &call: circuit.function_calls())
  {
    std::cout << "Function call to \"" << call.name << "\"\n";
    for(auto const var: call.args)
      std::cout << "(in)  " << var.name << ": " << var.type << ";\n";
    for(auto const var: call.returns)
      std::cout << "(out) " << var.name << ": " << var.type << ";\n";
  }

  // Print the INPUTs and OUTPUTs of the compiled circuit
  for(auto const &var: circuit.variables())
  {
      if(var.owner == variable_ownert::output)
          std::cout << "(out) ";
      else
          std::cout << "(in)  ";

      std::cout << var.name << ": " << var.type << std::endl;
  }

  // Remove unused gates.
  // This is (was?) especially necessary because multiplications are (were?) always forwarded which
  // would lead to code like this:
  // x = a*b
  // y = a*b      (here, a*b is used instead of x)
  // So x would never be used and thus can be removed.
  circuit.cleanup();

  circuit.print_stats();

  return circuit;
}


optional<simple_circuitt> try_compile_arith(
  goto_programt const &func,
  goto_modulet &module,
  class bmc_gct &bmc,
  boolbv_widtht const &boolbv_width)
{
  try {
    return compile_arith(func, module, bmc, boolbv_width);
  }
  catch(non_arithmetic_expression_error const &e) {
    return emptyopt;
  }
}
