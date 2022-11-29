#include <circuit-utils/circuit_io.hpp>

#include <sstream>


namespace circ {

//==================================================================================================
// TODO When using constant gates Fairplay throws a NullPointerException. The error seems to be on
//      their side, because this happens even when running a circuit compiled by their own compiler.
// TODO When assigning INPUTs directly to OUTPUTs, only Alice sees the correct result. Should we do
//      something about it?
namespace {

char const* gate_kind_to_table(GateKind kind)
{
	switch(kind)
	{
		case GateKind::not_gate: return "[ 1 0 ]";
		case GateKind::or_gate: return "[ 0 1 1 1 ]";
		case GateKind::and_gate: return "[ 0 0 0 1 ]";
		case GateKind::xor_gate: return "[ 0 1 1 0 ]";
		case GateKind::one_gate: return "[ 1 ]";

		case GateKind::add_gate:
		case GateKind::sub_gate:
		case GateKind::neg_gate:
		case GateKind::mul_gate:
		case GateKind::const_gate:
		case GateKind::combine_gate:
		case GateKind::split_gate:
			throw std::runtime_error{"SHDL: unsupported gate kind"};
	}
}

class IDToWireConverter
{
public:
	IDToWireConverter(Circuit const &circuit) :
		m_gate_to_wire(circuit.gates.size(), -1),
		// Multiply by two because we need separate outputs for Alice and Bob. If Alice and Bob
		// share any outputs, Fairplay will complain about un-evaluated gates.
		m_output_to_wire(circuit.outputs.size() * 2, -1),
		m_wire_counter{circuit.inputs.size()}
	{

	}

	uint64_t operator () (ElementID id)
	{
		switch(id.kind())
		{
			case ElementID::Kind::input: return id.id();
			case ElementID::Kind::gate:
			{
				if(m_gate_to_wire[id.id()] != (uint64_t)-1)
					return m_gate_to_wire[id.id()];

				uint64_t cur_wire = m_wire_counter++;
				m_gate_to_wire[id.id()] = cur_wire;
				return cur_wire;
			}

			case ElementID::Kind::output:
			{
				if(m_output_to_wire[id.id()] != (uint64_t)-1)
					return m_output_to_wire[id.id()];

				uint64_t cur_wire = m_wire_counter++;
				m_output_to_wire[id.id()] = cur_wire;
				return cur_wire;
			}
		}
	}

	uint64_t num_outputs() const { return m_output_to_wire.size() / 2; }

private:
	std::vector<uint64_t> m_gate_to_wire;
	std::vector<uint64_t> m_output_to_wire;
	uint64_t m_wire_counter;
};

IDToWireConverter write_shdl_circuit_file(Circuit const &circuit, std::ostream &file)
{
	for(uint64_t i = 0; i < circuit.inputs.size(); ++i)
		file << i << " input\n";

	IDToWireConverter id_to_wire{circuit};
	topological_traversal(circuit, [&](ElementID id)
	{
		if(id.kind() == ElementID::Kind::gate)
		{
			Gate const &gate = circuit[id.as_gate_id()];
			file << id_to_wire(id) << " gate arity " << (int)gate.num_fanins
			     << " table " << gate_kind_to_table(gate.kind)
			     << " inputs [ ";

			for(int8_t i = 0; i < gate.num_fanins; ++i)
				file << id_to_wire(gate.fanins[i].id) << ' ';

			file << "]\n";
		}
		else if(id.kind() == ElementID::Kind::output)
		{
			// Create output for one party.
			ElementID fanin = circuit[id.as_output_id()].value().id;
			file << id_to_wire(id) << " output gate arity 1 table [ 0 1 ]"
			     << " inputs [ " << id_to_wire(fanin) << " ]\n";
		}
	});

	// Create outputs for other party. Fairplay doesn't support using the same outputs for both
	// parties (probably makes sense).
	for(uint64_t i = 0; i < circuit.outputs.size(); ++i)
	{
		OutputID id{i + circuit.outputs.size()};
		ElementID fanin = circuit[OutputID{i}].value().id;
		file << id_to_wire(id) << " output gate arity 1 table [ 0 1 ]"
		     << " inputs [ " << id_to_wire(fanin) << " ]\n";
	}

	return id_to_wire;
}

char const* party_to_string(Party party)
{
	return party == Party::alice ? "Alice" : "Bob";
}

void write_shdl_input_variable(InputVariable const &var, IDToWireConverter &id_to_wire, std::ostream &os)
{
	uint64_t cur_input = 0;
	walk_type_with_path(var.type, var.name, [&](std::string const &path, Type const &type)
	{
		assert(type.kind() == TypeKind::bits || type.kind() == TypeKind::integer);

		os << party_to_string(var.party) << " input integer \"" << path << "=\" [ ";
		for(uint64_t i = 0; i < (uint64_t)get_bit_width(type); ++i)
			os << id_to_wire(var.inputs[cur_input++]) << ' ';
		os << "]\n";
	});
}

void write_shdl_output_variable(OutputVariable const &var, IDToWireConverter &id_to_wire, std::ostream &os)
{
	uint64_t cur_output = 0;
	walk_type_with_path(var.type, var.name, [&](std::string const &path, Type const &type)
	{
		assert(type.kind() == TypeKind::bits || type.kind() == TypeKind::integer);

		os << "Alice output integer \"" << path << "=\" [ ";
		for(uint64_t i = 0; i < (uint64_t)get_bit_width(type); ++i)
			os << id_to_wire(var.outputs[cur_output++]) << ' ';
		os << "]\n";

		os << "Bob output integer \"" << path << "=\" [ ";
		for(uint64_t i = 0; i < var.outputs.size(); ++i)
		{
			OutputID id{var.outputs[i].value + id_to_wire.num_outputs()};
			os << id_to_wire(id) << ' ';
		}
		os << "]\n";
	});
}

void write_shdl_format_file(Circuit const &circuit, IDToWireConverter &id_to_wire, std::ofstream &file)
{
	for(auto const pair: circuit.name_to_inputs)
	{
		InputVariable const &var = pair.second;
		write_shdl_input_variable(var, id_to_wire, file);
	}

	for(auto const pair: circuit.name_to_outputs)
	{
		OutputVariable const &var = pair.second;
		write_shdl_output_variable(var, id_to_wire, file);
	}
}

}

void write_shdl_circuit(Circuit const &circuit, std::string const &filepath)
{
	std::ofstream circuit_file{filepath + ".Opt.circuit"};
	if(!circuit_file)
		throw std::runtime_error{"Opening file failed: " + filepath + ".Opt.circuit"};

	IDToWireConverter id_to_wire = write_shdl_circuit_file(circuit, circuit_file);

	std::ofstream format_file{filepath + ".Opt.fmt"};
	if(!circuit_file)
		throw std::runtime_error{"Opening file failed: " + filepath + ".Opt.fmt"};

	write_shdl_format_file(circuit, id_to_wire, format_file);
}

}
