#include <circuit-utils/circuit_simulation.hpp>


namespace circ {

//==================================================================================================
SymbolTable create_symbol_table(Circuit const &c)
{
	SymbolTable table;
	for(auto &input: c.name_to_inputs)
		table[input.first] = {Type{input.second.type}, SymbolEntry::input};

	for(auto &output: c.name_to_outputs)
		table[output.first] = {Type{output.second.type}, SymbolEntry::output};

	return table;
}

EvaluationContext create_context(Circuit const &circuit)
{
	// Pre-define input and output variables

	EvaluationContext ctx;
	for(auto &input: circuit.name_to_inputs)
		ctx.add(input.first) = TypedValue{Type{input.second.type}};

	for(auto &output: circuit.name_to_outputs)
		ctx.add(output.first) = TypedValue{Type{output.second.type}};

	return ctx;
}


//==================================================================================================
static void simulate_gate(Circuit const &circ, GateID id, std::unordered_map<WireEndpoint, bool> &values)
{
	Gate const &gate = circ[id];
	switch(gate.kind)
	{
		case GateKind::one_gate:
		{
			assert(gate.num_fanins == 0);
			values[primary_endpoint(id)] = true;
		} break;

		case GateKind::not_gate:
		{
			assert(gate.num_fanins == 1);
			values[primary_endpoint(id)] = !values[gate.fanins[0]];
		} break;
		case GateKind::and_gate:
		{
			assert(gate.num_fanins == 2);
			auto in_a = gate.fanins[0];
			auto in_b = gate.fanins[1];
			values[primary_endpoint(id)] = values[in_a] & values[in_b];
		} break;
		case GateKind::or_gate:
		{
			assert(gate.num_fanins == 2);
			auto in_a = gate.fanins[0];
			auto in_b = gate.fanins[1];
			values[primary_endpoint(id)] = values[in_a] | values[in_b];
		} break;
		case GateKind::xor_gate:
		{
			assert(gate.num_fanins == 2);
			auto in_a = gate.fanins[0];
			auto in_b = gate.fanins[1];
			values[primary_endpoint(id)] = values[in_a] ^ values[in_b];
		} break;

		default:
			throw std::runtime_error{"simulate_gate: gate kind not supported yet"};
	}
}

static void simulate_element(Circuit const &circ, std::unordered_map<WireEndpoint, bool> &values, ElementID id)
{
	if(id.kind() == ElementID::Kind::gate)
		simulate_gate(circ, id.as_gate_id(), values);
	else if(id.kind() == ElementID::Kind::output)
		values[primary_endpoint(id)] = values.at(*circ.outputs[id.id()]);
}

static void set_input_value(
	InputVariable const &var, TypedValue const &value,
	std::unordered_map<WireEndpoint, bool> &circuit_values)
{
	size_t total_bit_width = get_bit_width(value.type);
	if(var.inputs.size() != total_bit_width)
	{
		throw std::runtime_error{
			"Bit width of input value (" + std::to_string(total_bit_width)
			+ ") different than specified in circuit for " + var.name + " (" + std::to_string(var.inputs.size()) + ")"};
	}

	for_each_bit(value, [&](int idx, bool bit)
	{
		circuit_values[primary_endpoint(var.inputs[idx])] = bit;
	});
}

std::unordered_map<WireEndpoint, bool> simulate(
	Circuit const &circ,
	std::unordered_map<std::string, TypedValue> const &input_values)
{
	std::unordered_map<WireEndpoint, bool> values;

	for(auto const &pair: input_values)
	{
		auto it = circ.name_to_inputs.find(pair.first);
		if(it == circ.name_to_inputs.end())
			throw std::runtime_error{"Invalid input variable: " + pair.first};

		set_input_value(it->second, pair.second, values);
	}

	topological_traversal(circ, [&](ElementID eid)
	{
		simulate_element(circ, values, eid);
	});

	return values;
}


//==================================================================================================
RawValue bits_to_raw_value(std::vector<bool> bits)
{
	uint64_t total_bits = bits.size();
	// Total number of bytes. The last byte may only partially be used.
	auto num_elements_total = (total_bits + 7) / 8;
	// Number of completely used bytes.
	auto num_elements_complete = total_bits / 8;

	RawValue value;
	value.reserve(num_elements_total);
	// Read complete bytes
	for(uint64_t i = 0; i < num_elements_complete; ++i)
	{
		uint8_t val = 0;
		for(int b = 0; b < 8; ++b)
			val |= bits[i * 8 + b] << b;

		value.push_back(val);
	}

	// Read the rest of the bits of the last byte
	if(total_bits % 8)
	{
		int last_idx = num_elements_complete;
		uint8_t val = 0;
		for(uint64_t b = 0; b < total_bits % 8; ++b)
			val |= bits[last_idx * 8 + b] << b;
		value.push_back(val);
	}

	return value;
}

}
