#include "circuit_creator_default.h"

#include <unordered_set>


//==================================================================================================
namespace {

simple_circuitt::gatet* create_input_or_output(
  simple_circuitt::GATE_OP in_or_out,
  boolbv_mapt::map_bitt lit,
  std::unordered_map<int, simple_circuitt::gatet*> &literal_to_gate,
  int &counter,
  circuit_creator_defaultt &creator,
  simple_circuitt &circuit)
{
  if(in_or_out == simple_circuitt::INPUT)
  {
    auto gate = circuit.create_input_gate(std::to_string(counter++));
    literal_to_gate[lit.l.dimacs()] = gate;
    return gate;
  }
  else
  {
    auto gate = circuit.create_output_gate(std::to_string(lit.l.dimacs()));
    gate->add_fanin({convert_node(lit.l, literal_to_gate, creator, circuit), 0}, 0);
    return gate;
  }
}

using LiteralMapIt = boolbv_mapt::literal_mapt::const_iterator;

template<typename Func>
void foreach_leave_value(typet const &type, LiteralMapIt &lits_cur, LiteralMapIt lits_end, Func &&func)
{
  if(type.id() == ID_array)
  {
    array_typet array_type = to_array_type(type);

    // Must have a finite size
    mp_integer array_size_mp;
    if(to_integer(array_type.size(), array_size_mp))
      throw std::runtime_error{"failed to convert array size"};

    int array_size = integer2size_t(array_size_mp);
    for(int i = 0; i < array_size; ++i)
      foreach_leave_value(array_type.subtype(), lits_cur, lits_end, std::forward<Func>(func));
  }
  else if(type.id() == ID_struct)
  {
    struct_typet struct_type = to_struct_type(type);
    auto const &comps = struct_type.components();

    for(size_t i = 0; i < comps.size(); ++i)
      foreach_leave_value(comps[i].type(), lits_cur, lits_end, std::forward<Func>(func));
  }
  else if(type.id() == ID_signedbv || type.id() == ID_unsignedbv || type.id() == ID_c_bool)
  {
    int width = type.get_int("width");
    func(type, lits_cur, lits_cur + width);
    lits_cur += width;
  }
  else
  {
    std::cout << type.pretty() << std::endl;
    assert(!"Invalid input type");
  }
}

std::vector<simple_circuitt::gatet*> literals_to_io_gates(
  simple_circuitt::GATE_OP in_or_out,
  typet const &type,
  boolbv_mapt::literal_mapt const &literals,
  std::unordered_map<int, simple_circuitt::gatet*> &literal_to_gate,
  int &counter,
  circuit_creator_defaultt &creator,
  simple_circuitt &circuit)
{
  std::vector<simple_circuitt::gatet*> gates;

  auto lits_begin = literals.begin();
  foreach_leave_value(type, lits_begin, literals.end(), [&](typet const &leave_type, LiteralMapIt lits_b, LiteralMapIt lits_e)
  {
    if(leave_type.id() == ID_c_bool)
    {
      // Special treatment for booleans: We want booleans to use only a single INPUT/OUTPUT bit,
      // but according to the C standard, _Bool must have at least CHAR_BIT bits. However, since in a
      // well-behaved program the value read from a boolean variable is always zero or one, we take
      // the freedom and use only a single gate for all CHAR_BIT bits.

      auto gate = create_input_or_output(in_or_out, *lits_b, literal_to_gate, counter, creator, circuit);
      gates.push_back(gate);

      if(!lits_b->is_set)
        throw std::runtime_error{"Literal of INPUT/OUTPUT varialble is not set"};

      literal_to_gate[lits_b->l.dimacs()] = gate;

      // Map all except the first literal of the boolean value to zero
      while(++lits_b != lits_e)
        literal_to_gate[lits_b->l.dimacs()] = &circuit.get_zero_gate();
    }
    else
    {
      while(lits_b != lits_e)
      {
        if(!lits_b->is_set)
          throw std::runtime_error{"Literal of INPUT varialble is not set"};

        auto gate = create_input_or_output(in_or_out, *lits_b, literal_to_gate, counter, creator, circuit);
        gates.push_back(gate);

        ++lits_b;
      }
    }
  });

  assert(lits_begin == literals.end());

  return gates;
}

}

void circuit_creator_defaultt::create_circuit(
  std::vector<mpc_variable_infot> const &vars,
  std::vector<bool_function_callt> const &func_calls,
  simple_circuitt &circuit)
{
  std::unordered_map<int, simple_circuitt::gatet*> literal_to_gate;

  // Convert input variables
  int counter = 1;
  for(auto &&info: vars)
  {
    if(info.io_type != io_variable_typet::output)
    {
      std::vector<simple_circuitt::gatet*> gates = literals_to_io_gates(simple_circuitt::INPUT, info.type, info.literals, literal_to_gate, counter, *this, circuit);
      variable_ownert owner = variable_ownert::input_alice;
      if(info.io_type == io_variable_typet::input_b)
        owner = variable_ownert::input_bob;

      circuit.add_variable(str(info.var.unqualified_name), owner, from_cbmc(info.type), std::move(gates));
    }
  }

  // Convert inputs/outputs for function calls
  for(bool_function_callt const &call: func_calls)
  {
    simple_circuitt::function_callt circ_call;
    circ_call.name = as_string(call.name);
    circ_call.call_id = call.call_id;

    // The function's returns are our inputs
    for(auto const &var: call.returns)
    {
      std::vector<simple_circuitt::gatet*> gates = literals_to_io_gates(simple_circuitt::INPUT, var.type, var.literals, literal_to_gate, counter, *this, circuit);
      circ_call.returns.push_back({str(var.var.unqualified_name), from_cbmc(var.type), std::move(gates)});
    }

    // The function's arguments are our outputs
    for(auto const &var: call.args)
    {
      std::vector<simple_circuitt::gatet*> gates = literals_to_io_gates(simple_circuitt::OUTPUT, var.type, var.literals, literal_to_gate, counter, *this, circuit);
      circ_call.args.push_back({str(var.var.unqualified_name), from_cbmc(var.type), std::move(gates)});
    }

    circuit.add_function_call(std::move(circ_call));
  }

  // Convert circuit outputs
  for(auto &&info: vars)
  {
    if(info.io_type == io_variable_typet::output)
    {
      std::vector<simple_circuitt::gatet*> outs = literals_to_io_gates(simple_circuitt::OUTPUT, info.type, info.literals, literal_to_gate, counter, *this, circuit);
      circuit.add_variable(str(info.var.unqualified_name), variable_ownert::output, from_cbmc(info.type), std::move(outs));
    }
  }
}


//==================================================================================================
namespace {

char const* cstr(tmp_node_kindt kind)
{
  switch(kind)
  {
    case tmp_node_kindt::l_and: return "AND";
    case tmp_node_kindt::l_or: return "OR";
    case tmp_node_kindt::l_xor: return "XOR";
    case tmp_node_kindt::input: return "INPUT";
  }
}

void node_wires_to_dot(std::ostream &os, tmp_nodet const &node)
{
  switch(node.kind)
  {
    case tmp_node_kindt::l_and:
    case tmp_node_kindt::l_or:
    case tmp_node_kindt::l_xor:
      os << "\t\t" << node.input_left.dimacs() << " -> " << node.me.dimacs() << ";\n";
      os << "\t\t" << node.input_right.dimacs() << " -> " << node.me.dimacs() << ";\n";
      break;

    case tmp_node_kindt::input:
      // Nothing to do
      break;
  }
}

void scope_to_dot(
  std::ostream &os,
  circuit_creator_defaultt::scopet *scope,
  std::unordered_map<int, tmp_nodet> const& graph,
  std::unordered_set<int> &nodes_written)
{
  os << "\tsubgraph cluster_" << scope << " {\n";
  os << "\t\tlabel = \"" << scope->name << "\";\n";

  for(auto lit: scope->literals)
  {
    tmp_nodet const &node = graph.at(lit.dimacs());

    if(nodes_written.insert(lit.dimacs()).second)
    {
      // If the literal is negated we need to output a NOT gate first
      if(lit.sign())
      {
        literalt unsigned_lit = !lit;
        if(nodes_written.insert(unsigned_lit.dimacs()).second)
        {
          os << "\t\t" << unsigned_lit.dimacs() << " [label=\"" << cstr(node.kind) << "\"];\n";
          node_wires_to_dot(os, node);

          os << "\t\t" << lit.dimacs() << " [label=\"NOT\"];\n";
          os << "\t\t" << unsigned_lit.dimacs() << " -> " << lit.dimacs() << ";\n";
        }
      }
      else
      {
        os << "\t\t" << lit.dimacs() << " [label=\"" << cstr(node.kind) << "\"];\n";
        node_wires_to_dot(os, node);
      }
    }
  }

  for(auto const &child: scope->children)
    scope_to_dot(os, child.get(), graph, nodes_written);

  os << "\t}\n";
}

}

void circuit_creator_defaultt::scopes_to_dot(std::ostream &os)
{
  os << "digraph {\n";

  std::unordered_set<int> nodes_written;
  scope_to_dot(os, &m_root_scope, m_literal_to_node, nodes_written);

  os << "}\n";
}
