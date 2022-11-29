#include "simulation.h"



namespace {

using wire_endpointt = simple_circuitt::gatet::wire_endpointt;
using gate_valuest = std::unordered_map<simple_circuitt::gatet::wire_endpointt, uint64_t, wire_endpoint_hasht>;

void set_input_value(simple_circuitt::variablet &var, TypedValue const &value, gate_valuest &gate_values)
{
  assert(get_bit_width(value.type) == get_bit_width(var.type));

  int bit_idx = 0;
  for(auto *gate: var.gates)
  {
    assert(gate->get_width() <= 64);
    gate_values[{gate, 0}] = extract_bits(value.value, bit_idx, gate->get_width());
    bit_idx += gate->get_width();
  }

  assert(bit_idx == get_bit_width(var.type));
}

TypedValue get_output_value(simple_circuitt::variablet &var, gate_valuest const &gate_values)
{
  std::vector<bool> output_bits;

  for(auto *gate: var.gates)
  {
    assert(gate->get_width() <= 64);
    uint64_t value = gate_values.at({gate, 0});

    for(int i = 0; i < gate->get_width(); ++i)
      output_bits.push_back((value >> i) & 1);
  }

  return TypedValue{var.type, bits_to_raw_value(output_bits)};
}

}


std::unordered_map<std::string, TypedValue> simulate(
  simple_circuitt &circuit,
  std::unordered_map<std::string, TypedValue> const &input_values)
{
  gate_valuest values;
  for(auto *var: circuit.ordered_inputs())
    set_input_value(*var, input_values.at(var->name), values);

  values[{&circuit.get_one_gate(), 0}] = 1;
  values[{&circuit.get_zero_gate(), 0}] = 0;

  circuit.topological_traversal([&](simple_circuitt::gatet *gate)
  {
    switch(gate->get_operation())
    {
      case simple_circuitt::AND:
        values[{gate, 0}] = values[gate->fanin_range()[0]] & values[gate->fanin_range()[0]];
        break;

      case simple_circuitt::OR:
        values[{gate, 0}] = values[gate->fanin_range()[0]] | values[gate->fanin_range()[1]];
        break;

      case simple_circuitt::XOR:
        values[{gate, 0}] = values[gate->fanin_range()[0]] ^ values[gate->fanin_range()[1]];
        break;

      case simple_circuitt::NOT:
        values[{gate, 0}] = !values[gate->fanin_range()[0]];
        break;

      case simple_circuitt::ADD:
        values[{gate, 0}] = values[gate->fanin_range()[0]] + values[gate->fanin_range()[1]];
        break;

      case simple_circuitt::SUB:
        values[{gate, 0}] = values[gate->fanin_range()[0]] - values[gate->fanin_range()[1]];
        break;

      case simple_circuitt::MUL:
        values[{gate, 0}] = values[gate->fanin_range()[0]] * values[gate->fanin_range()[1]];
        break;

      case simple_circuitt::NEG:
        values[{gate, 0}] = !values[gate->fanin_range()[0]];
        break;

      case simple_circuitt::CONST:
        values[{gate, 0}] = gate->get_value();
        break;

      case simple_circuitt::LUT:
        assert(!"LUTs not supported");
        break;

      case simple_circuitt::ONE:
        // Nothing to do
        break;

      case simple_circuitt::INPUT:
        // Nothing to do
        break;

      case simple_circuitt::OUTPUT:
        values[{gate, 0}] = values[gate->fanin_range()[0]];
        break;

      case simple_circuitt::COMBINE:
      {
        uint64_t value = 0;
        int bit_idx = 0;
        for(auto fanin: gate->fanin_range())
        {
          value |= values[fanin] << bit_idx;
          bit_idx += fanin.gate->get_width();
        }

        assert(bit_idx == gate->get_width());
        values[{gate, 0}] = value;
      } break;

      case simple_circuitt::SPLIT:
      {
        uint64_t fanin_value = values[gate->fanin_range()[0]];
        for(unsigned i = 0; i < gate->get_fanouts().size(); ++i)
          values[{gate, i}] = (fanin_value >> i) & 1;
      } break;
    }
  });

  std::unordered_map<std::string, TypedValue> output_values;
  for(auto *var: circuit.ordered_outputs())
    output_values[var->name] = get_output_value(*var, values);

  return output_values;
}

