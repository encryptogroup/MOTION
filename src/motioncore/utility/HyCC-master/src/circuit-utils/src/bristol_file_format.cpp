#include <circuit-utils/circuit_io.hpp>

#include <unordered_set>


namespace circ {

// From <https://www.cs.bris.ac.uk/Research/CryptographySecurity/MPC/>:
//
// - A line defining the number of gates and then the number of wires in the circuit.
// - Then two numbers defining the number n1 and n2 of wires in the inputs to the function given by
//   the circuit.
//     - We assume the function has at most two inputs; since most of our examples do. If the 
//       function has only one input then the second inputs size is set to zero.
// - Then on the same line comes the number of wires in the output n3.
// - The wires are ordered so that the first n1 wires correspond to the first input value, the next
//   n2 wires correspond to the second input value. The last n3 wires correspond to the output of the circuit.
// - After this the gates are listed in the format:
//     - Number input wires
//     - Number output wires
//     - List of input wires
//     - List of output wires
//     - Gate operation (XOR, AND or INV). 
//   So for example
// 
//       2 1 3 4 5 XOR
// 
//   corresponds to
// 
//        w5=XOR(w3,w4).


// Reading
//==================================================================================================
namespace {

GateKind read_gate_kind(std::istream &file)
{
	std::string word;
	file >> word;

	if(word == "INV")
		return GateKind::not_gate;

	if(word == "AND")
		return GateKind::and_gate;

	if(word == "OR")
		return GateKind::or_gate;

	if(word == "XOR")
		return GateKind::xor_gate;

	throw std::runtime_error{"Bristol: Unsupported gate type: " + word};
}

using UInt64Range = std::pair<uint64_t, uint64_t>;

bool in_range(UInt64Range range, uint64_t val)
{
	return val >= range.first && val <= range.second;
}

class WireToIDConverter
{
public:
	WireToIDConverter(uint64_t num_wires, uint64_t num_input_wires, uint64_t num_output_wires) :
		m_input_range{0, num_input_wires - 1},
		m_output_range{num_wires - num_output_wires, num_wires - 1} {}

	ElementID operator () (uint64_t wire) const
	{
		if(in_range(m_input_range, wire))
			return InputID{wire};

		if(in_range(m_output_range, wire))
			return OutputID{wire - m_output_range.first};

		return GateID{wire - m_input_range.second - 1};
	}

private:
	UInt64Range m_input_range;
	UInt64Range m_output_range;
};

class ElementConnector
{
public:
	ElementConnector(Circuit &circuit) :
		m_circuit{circuit} {}

	void operator () (ElementID from, ElementID to)
	{
		// Since the Bristol circuit format uses wires instead of gates as its primary element it's
		// possible to have an output wire that is also a fan-in of a logic gate. We don't support
		// this in our circuit structure, so we need to handle this case specially.
		
		if(from.kind() == ElementID::Kind::output)
		{
			auto oid = from.as_output_id();

			// If the wire has already been assigned a fan-in we can use that instead of the output.
			// Otherwise, we have to delay the wiring until the end.
			if(m_circuit[oid])
				m_circuit.add_wire(*m_circuit[oid], next_endpoint(to));
			else
				m_to_be_wired.push_back({oid, to});
		}
		else
			m_circuit.add_wire(primary_endpoint(from), next_endpoint(to));
	}

	void add_remaining_wires()
	{
		for(auto const &wire: m_to_be_wired)
			m_circuit.add_wire(m_circuit[wire.first].value(), next_endpoint(wire.second));
	}

private:
	Circuit &m_circuit;
	std::vector<std::pair<OutputID, ElementID>> m_to_be_wired;
};

}

Circuit read_bristol_circuit(std::istream &file)
{
	uint64_t num_gates, num_wires;
	file >> num_gates >> num_wires;

	uint64_t num_input_a_wires, num_input_b_wires, num_output_wires;
	file >> num_input_a_wires >> num_input_b_wires >> num_output_wires;

	uint64_t num_input_wires = num_input_a_wires + num_input_b_wires;
	UInt64Range output_range{num_wires - num_output_wires, num_wires - 1};

	Circuit circuit;

	circuit.inputs.reserve(num_input_a_wires + num_input_b_wires);
	std::fill_n(std::back_inserter(circuit.inputs), num_input_a_wires, Input{Party::alice, uint8_t(1)});
	std::fill_n(std::back_inserter(circuit.inputs), num_input_b_wires, Input{Party::bob, uint8_t(1)});

	circuit.add_input_variable(Party::alice, "INPUT_A", InputID{0}, num_input_a_wires);
	circuit.add_input_variable(Party::bob, "INPUT_B", InputID{num_input_a_wires}, num_input_b_wires);

	circuit.outputs.resize(num_output_wires);
	circuit.add_output_variable("OUTPUT_res", OutputID{0}, num_output_wires);

	WireToIDConverter wire_to_id{num_wires, num_input_wires, num_output_wires};
	ElementConnector connector{circuit};

	circuit.gates.resize(num_gates);
	for(uint64_t i = 0; i < num_gates; ++i)
	{
		int num_inputs, num_outputs;
		file >> num_inputs >> num_outputs;

		if(num_outputs != 1)
			throw std::runtime_error{"Gates with more than one output not supported yet"};

		if(num_inputs == 1)
		{
			uint64_t fanin, fanout;
			file >> fanin >> fanout;
			if(read_gate_kind(file) != GateKind::not_gate)
				throw std::runtime_error{"Only inverters have a single fanin"};

			GateID gate_id{fanout - num_input_wires};
			circuit[gate_id] = Gate{GateKind::not_gate, 1, 1};
			connector(wire_to_id(fanin), gate_id);
			if(in_range(output_range, fanout))
				connector(gate_id, wire_to_id(fanout));
		}
		else if(num_inputs == 2)
		{
			uint64_t fanin0, fanin1, fanout;
			file >> fanin0 >> fanin1 >> fanout;
			GateKind kind = read_gate_kind(file);

			GateID gate_id{fanout - num_input_wires};
			circuit[gate_id] = Gate{kind, 2, 1};
			connector(wire_to_id(fanin0), gate_id);
			connector(wire_to_id(fanin1), gate_id);
			if(in_range(output_range, fanout))
				connector(gate_id, wire_to_id(fanout));
		}
		else
			throw std::runtime_error{"Gates with more than two fanins are not supported yet"};
	}

	if(!file)
		throw std::runtime_error{"Error reading file"};

	connector.add_remaining_wires();

	return circuit;
}

Circuit read_bristol_circuit(std::string const &filepath)
{
	std::ifstream file{filepath};
	if(!file)
		throw std::runtime_error{"Opening file failed: " + filepath};

	return read_bristol_circuit(file);
}


// Writing
//==================================================================================================
namespace {

std::pair<uint64_t, uint64_t> get_num_inputs(Circuit const &circuit)
{
	uint64_t num_inputs_a = 0, num_inputs_b = 0;
	for(auto const &input: circuit.inputs)
	{
		if(input.party == Party::alice)
			num_inputs_a++;
		else
			num_inputs_b++;
	}

	return {num_inputs_a, num_inputs_b};
}

char const* gate_kind_to_string(GateKind kind)
{
	switch(kind)
	{
		case GateKind::not_gate: return "INV";
		case GateKind::and_gate: return "AND";
		case GateKind::or_gate: return "OR";
		case GateKind::xor_gate: return "XOR";

		case GateKind::one_gate:
		case GateKind::add_gate:
		case GateKind::sub_gate:
		case GateKind::neg_gate:
		case GateKind::mul_gate:
		case GateKind::const_gate:
		case GateKind::combine_gate:
		case GateKind::split_gate:
			throw std::runtime_error{"Brsitol: unsupported gate kind"};
	}

	return nullptr;
}

// Returns true if the constant gate is used by a normal (i.e. non-output) gate
bool is_const_gate_used_by_normal_gates(Circuit const &circuit)
{
	// All gates can use the same constant gate.
	for(Gate const &gate: circuit.gates)
	{
		for(auto fanin: gate.fanins)
		{
			if(fanin.id.kind() == ElementID::Kind::gate && circuit[fanin.id.as_gate_id()].kind == GateKind::one_gate)
				return true;
		}
	}

	return false;
}

uint64_t count_const_gates_used_by_outputs(Circuit const &circuit)
{
	uint64_t count = 0;

	// Outputs all need their own constant gate.
	for(optional<WireEndpoint> const &fanin: circuit.outputs)
	{
		auto fanin_id = fanin.value().id;
		if(fanin_id.kind() == ElementID::Kind::gate && circuit[fanin_id.as_gate_id()].kind == GateKind::one_gate)
			count++;
	}

	return count;
}

uint64_t count_additional_gates_for_outputs(Circuit const &circuit)
{
	// If multiple outputs have the same gate as fan-in we need to duplicate the gate for each
	// output

	std::unordered_set<ElementID> unique_fanins;
	uint64_t additional_gates = 0;
	for(auto const &opt_fanin: circuit.outputs)
	{
		bool inserted = unique_fanins.insert(opt_fanin.value().id).second;
		if(!inserted) // duplicate
		{
			auto fanin_id = opt_fanin.value().id;

			// The additional gates required for a constant gate are already counted in
			// count_const_gates().
			if(fanin_id.kind() != ElementID::Kind::gate || circuit[fanin_id.as_gate_id()].kind != GateKind::one_gate)
				additional_gates += 1;
		}
	}

	return additional_gates;
}

class IDToWireConverter
{
public:
	IDToWireConverter(Circuit const &circuit) :
		m_gate_to_wire(circuit.gates.size(), -1),
		m_wire_counter{circuit.inputs.size()}
	{
		m_has_const_gate_used_by_normal_gate = is_const_gate_used_by_normal_gates(circuit);
		uint64_t num_const_gates_for_outputs = count_const_gates_used_by_outputs(circuit);
		uint64_t num_additional_gates_for_outputs = count_additional_gates_for_outputs(circuit);

		bool const_gate_used = m_has_const_gate_used_by_normal_gate || num_const_gates_for_outputs;

		m_num_gates = circuit.gates.size() - const_gate_used +
			// To build a constant-one wire we need a XOR and a NOT gate.
			2*m_has_const_gate_used_by_normal_gate +
			2*num_const_gates_for_outputs +
			num_additional_gates_for_outputs;
		m_num_wires = m_num_gates + circuit.inputs.size();

		uint64_t output_wire_offset = m_num_wires - circuit.outputs.size();
		for(uint64_t i = 0; i < circuit.outputs.size(); ++i)
		{
			ElementID fanin = circuit.outputs[i].value().id;
			if(fanin.kind() == ElementID::Kind::input)
				throw std::runtime_error{"Bristol doesn't support direct connections between inputs and outputs"};

			// Each output needs its own const gate
			bool fanin_is_one = fanin.kind() == ElementID::Kind::gate && circuit[fanin.as_gate_id()].kind == GateKind::one_gate;
			// If multiple outputs have the same gate as a fan-in we need to duplicate the gate
			// for each output.
			bool multiple_outputs_same_fanin = m_gate_to_wire[fanin.id()] != (uint64_t)-1;

			if(fanin_is_one || multiple_outputs_same_fanin)
				m_additional_output_wires.emplace_back(fanin, output_wire_offset + i);
			else
				m_gate_to_wire[fanin.id()] = output_wire_offset + i;
		}
	}

	bool has_const_gate_used_by_normal_gate() const { return m_has_const_gate_used_by_normal_gate; }

	uint64_t operator() (ElementID id)
	{
		switch(id.kind())
		{
			case ElementID::Kind::input: return id.id();
			case ElementID::Kind::gate:
				if(m_gate_to_wire[id.id()] == (uint64_t)-1)
					m_gate_to_wire[id.id()] = m_wire_counter++;

				return m_gate_to_wire[id.id()];

			default:
				assert(0);
				break;
		}
	}

	uint64_t new_wire() { return m_wire_counter++; }

	std::vector<std::pair<ElementID, uint64_t>> const& additional_output_wires() const
	{
		return m_additional_output_wires;
	}

	uint64_t num_gates() const { return m_num_gates; }
	uint64_t num_wires() const { return m_num_wires; }

private:
	std::vector<uint64_t> m_gate_to_wire;
	uint64_t m_num_gates;
	uint64_t m_num_wires;
	uint64_t m_wire_counter;
	bool m_has_const_gate_used_by_normal_gate;
	std::vector<std::pair<ElementID, uint64_t>> m_additional_output_wires;
};

ElementID get_any_element(Circuit const &circuit)
{
	if(circuit.inputs.size())
		return InputID{0};

	if(circuit.gates.size())
		return GateID{0};

	throw std::runtime_error{"A circuit with neither inputs nor gates?"};
}

void write_gate(IDToWireConverter &id_to_wire, Gate const &gate, uint64_t fanout, std::ostream &file)
{
	if(gate.kind == GateKind::not_gate)
		file << "1 1 " << id_to_wire(gate.fanins[0].id) << ' ' << fanout << " INV\n";
	else
	{
		file << "2 1 " << id_to_wire(gate.fanins[0].id) << ' ' << id_to_wire(gate.fanins[1].id)
			 << ' ' << fanout
			 << ' ' << gate_kind_to_string(gate.kind) << '\n';
	}
}

void write_constant(Circuit const &circuit, IDToWireConverter &id_to_wire, uint64_t fanout, std::ostream &file)
{
	// Bristol doesn't seem to support constant wires so we build them ourself
	ElementID elem = get_any_element(circuit);
	uint64_t xor_wire = id_to_wire.new_wire();
	file << "2 1 " << id_to_wire(elem) << ' ' << id_to_wire(elem) << ' ' << xor_wire << " XOR\n";
	file << "1 1 " << xor_wire << ' ' << fanout << " INV\n";
}

}

void write_bristol_circuit(Circuit const &circuit, std::ostream &file)
{
	IDToWireConverter id_to_wire{circuit};

	file << id_to_wire.num_gates() << ' ' << id_to_wire.num_wires() << '\n';

	auto num_inputs = get_num_inputs(circuit);
	file << num_inputs.first << ' ' << num_inputs.second << ' ' << circuit.outputs.size() << "\n\n";

	bool write_const_gate = id_to_wire.has_const_gate_used_by_normal_gate();

	// I am not sure the Bristol circuit format requires the gates to be sorted topologically but
	// the examples on the homepage (link at the top) seem to be.
	topological_traversal(circuit, [&](ElementID id)
	{
		if(id.kind() == ElementID::Kind::gate)
		{
			if(circuit[id.as_gate_id()].kind == GateKind::one_gate)
			{
				if(write_const_gate)
				{
					write_constant(circuit, id_to_wire, id_to_wire(id), file);
					write_const_gate = false;
				}
			}
			else
				write_gate(id_to_wire, circuit[id.as_gate_id()], id_to_wire(id), file);
		}
	});

	for(auto wire: id_to_wire.additional_output_wires())
	{
		ElementID from = wire.first;
		uint64_t to = wire.second;
		if(from.kind() == ElementID::Kind::gate)
		{
			if(circuit[from.as_gate_id()].kind == GateKind::one_gate)
				write_constant(circuit, id_to_wire, to, file);
			else
				write_gate(id_to_wire, circuit[from.as_gate_id()], to, file);
		}
		else { assert(!"Invalid element kind for output"); }
	}
}

void write_bristol_circuit(Circuit const &circuit, std::string const &filepath)
{
	std::ofstream file{filepath};
	if(!file)
		throw std::runtime_error{"Opening file failed: " + filepath};

	write_bristol_circuit(circuit, file);
}

}

