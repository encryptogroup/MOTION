#include "circuit.hpp"


namespace circ {

// Various circuit file formats
//==================================================================================================
Circuit read_cbmc_circuit(std::string const &path);

Circuit read_bristol_circuit(std::ifstream &file);
Circuit read_bristol_circuit(std::string const &filepath);
void write_bristol_circuit(Circuit const &circuit, std::ofstream &file);
void write_bristol_circuit(Circuit const &circuit, std::string const &filepath);

void write_shdl_circuit(Circuit const &circuit, std::string const &filepath);

void write_scd_circuit(Circuit const &circuit, std::string const &filepath);


//------------------------------------------------------------------------------
enum class CircuitFileFormat
{
	cbmc_gc,
	bristol,
	shdl,
	scd,
};

inline char const* cstr(CircuitFileFormat f)
{
	switch(f)
	{
		case CircuitFileFormat::cbmc_gc: return "CBMC-GC";
		case CircuitFileFormat::bristol: return "Bristol";
		case CircuitFileFormat::shdl: return "SHDL";
		case CircuitFileFormat::scd: return "SCD";
	}
}

inline Circuit read_circuit(std::string const &path, CircuitFileFormat fmt)
{
	Circuit circuit;
	switch(fmt)
	{
		case CircuitFileFormat::cbmc_gc: circuit = read_cbmc_circuit(path); break;
		case CircuitFileFormat::bristol: circuit = read_bristol_circuit(path); break;
		default:
			throw std::runtime_error{std::string{"Reading from "} + cstr(fmt) + " file not yet supported"};
	}

	validate(circuit);
	return circuit;
}

inline void remove_or_gates(Circuit &circ) 
{
	std::cout << "Replacing all (A or B) gates by -(-A and -B)\n";
	std::cout << "Number of gates before: " << circ.gates.size() << "\n";
	
	
	unsigned count_or = 0;
	for(size_t id = 0; id < circ.gates.size(); ++id)
	{
		if(circ.gates[id].kind == GateKind::or_gate)
			count_or++;
	}
	
	auto original_circuit_size = circ.gates.size();
	auto next_gate_id = original_circuit_size;
	circ.gates.resize(original_circuit_size + 3*count_or); // create space for additional gates	
	
	
	for(size_t id = 0; id < original_circuit_size; ++id)
	{
		Gate &gate = circ.gates[id];
		if(gate.kind == GateKind::or_gate)
		{
			if(gate.num_fanins != 2)
			{
				throw std::runtime_error{"Invalid number of inputs: " + std::to_string(gate.num_fanins) + ", expected 2 (id=" + std::to_string(id) + ")"};
			} else 
			{
				// Create not A
				circ.gates[next_gate_id].kind = GateKind::not_gate;
				circ.add_wire(gate.fanins[0], ElementID(GateID{next_gate_id}));
				// Create not B
				circ.gates[next_gate_id+1].kind = GateKind::not_gate;
				circ.add_wire(gate.fanins[1], ElementID(GateID{next_gate_id+1}));
				// (not A_ and (not B)
				circ.gates[next_gate_id+2].kind = GateKind::and_gate;
				circ.add_wire(ElementID(GateID{next_gate_id}), ElementID(GateID{next_gate_id+2}));
				circ.add_wire(ElementID(GateID{next_gate_id+1}), ElementID(GateID{next_gate_id+2}));
				// Substitute OR by INV
		    circ.gates[id].kind=GateKind::not_gate;
		    circ.gates[id].num_fanins = 0; // empty fanins
		    circ.add_wire(ElementID(GateID{next_gate_id+2}), ElementID(GateID{id}));
		    next_gate_id+=3;
			}
		}
	}
	std::cout << "Number of gates after: " << circ.gates.size() << "\n";
}

// *.dot export
//==================================================================================================
inline std::string elem_id_to_string(ElementID id)
{
	switch(id.kind())
	{
		case ElementID::Kind::gate: return std::to_string(id.id());
		case ElementID::Kind::const_one: return "const_one";
		case ElementID::Kind::input: return "in_" + std::to_string(id.id());
		case ElementID::Kind::output: return "out_" + std::to_string(id.id());
		default: throw std::logic_error{"Invalid element kind: " + std::to_string((uint64_t)id.kind())};
	}
}

inline void to_dot(std::ostream &os, Circuit const &circ)
{
	os << "digraph {\n";

	for(size_t id = 0; id < circ.gates.size(); ++id)
	{
		Gate const &gate = circ.gates[id];
		os << '\t' << id << " [label=\"[" << id << "] " << to_string(gate.kind) << "\"];\n";
	}

	for(size_t id = 0; id < circ.inputs.size(); ++id)
	{
		os << '\t' << elem_id_to_string(InputID{id})
		   << " [label=\"in_" << to_string(circ.inputs[id]) << "_" << id << "\"];\n";
	}

	for(size_t id = 0; id < circ.gates.size(); ++id)
	{
		Gate const &gate = circ.gates[id];
		for(int i = 0; i < gate.num_fanins; ++i)
			os << '\t' << elem_id_to_string(gate.fanins[i]) << " -> " << elem_id_to_string(GateID{id}) << ";\n";
	}

	for(size_t id = 0; id < circ.outputs.size(); ++id)
		os << '\t' << elem_id_to_string(*circ.outputs[id]) << " -> " << elem_id_to_string(OutputID{id}) << ";\n";

	os << "}\n";
}

inline void to_dot(std::ostream &&os, Circuit const &circ)
{
	to_dot(os, circ);
}


//==================================================================================================
void to_c_code(std::ostream &os, Circuit const &circ, std::string const &func_name);

inline void to_c_code(std::ostream &&os, Circuit const &circ, std::string const &func_name)
{
	to_c_code(os, circ, func_name);
}


}
