#include "circuit_creator_default.h"

void circuit_creator_defaultt::create_circuit(std::vector<mpc_variable_infot> const &vars, simple_circuitt &circuit)
{
  std::unordered_map<int, simple_circuitt::gatet*> literal_to_gate;

  // Convert input variables
  int counter = 1;
  for(auto &&info: vars)
  {
    if(info.io_type != io_variable_typet::output)
    {
      std::vector<simple_circuitt::gatet*> gates;
      for(auto lit: info.literals)
      {
        if(!lit.is_set)
          throw std::runtime_error{"Literal of INPUT varialble is not set"};

        auto gate = circuit.create_input_gate(std::to_string(counter++));
        literal_to_gate[lit.l.dimacs()] = gate;

        gates.push_back(gate);
      }

      if(info.io_type == io_variable_typet::input_a)
        circuit.input_a_variables[info.var_name] = gates;
      else if(info.io_type == io_variable_typet::input_b)
        circuit.input_b_variables[info.var_name] = gates;
    }
  }

  // Convert everything else
  for(auto &&info: vars)
  {
    if(info.io_type == io_variable_typet::output)
    {
      std::vector<simple_circuitt::gatet*> outs;
      for(auto maybe_lit: info.literals)
      {
        if(!maybe_lit.is_set)
          throw std::runtime_error{"Literal of OUTPUT varialble is not set"};

        auto gate = circuit.create_output_gate(std::to_string(maybe_lit.l.dimacs()));
        gate->add_fanin(*convert_node(maybe_lit.l, literal_to_gate, *this, circuit), 0);
        outs.push_back(gate);
      }

      circuit.output_variables[info.var_name] = outs;
    }
  }
}
