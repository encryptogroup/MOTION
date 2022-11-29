#include "circuit.hpp"


namespace circ {

// Various circuit file formats
//==================================================================================================
Circuit read_cbmc_circuit(std::string const &path);
Circuit read_cbmc_legacy_circuit(std::string const &path);

Circuit read_bristol_circuit(std::istream &file);
Circuit read_bristol_circuit(std::string const &filepath);
void write_bristol_circuit(Circuit const &circuit, std::ostream &file);
void write_bristol_circuit(Circuit const &circuit, std::string const &filepath);

void write_shdl_circuit(Circuit const &circuit, std::string const &filepath);

void write_scd_circuit(Circuit const &circuit, std::string const &filepath);


//------------------------------------------------------------------------------
enum class CircuitFileFormat
{
	cbmc_gc,
	cbmc_gc_legacy,
	bristol,
	shdl,
	scd,
};

inline char const* cstr(CircuitFileFormat f)
{
	switch(f)
	{
		case CircuitFileFormat::cbmc_gc: return "CBMC-GC";
		case CircuitFileFormat::cbmc_gc_legacy: return "CBMC-GC Legacy";
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
		//case CircuitFileFormat::cbmc_gc_legacy: circuit = read_cbmc_legacy_circuit(path); break;
		case CircuitFileFormat::bristol: circuit = read_bristol_circuit(path); break;
		default:
			throw std::runtime_error{std::string{"Reading from "} + cstr(fmt) + " file not yet supported"};
	}

	validate(circuit);
	return circuit;
}


// *.dot export
//==================================================================================================
inline std::string elem_id_to_string(ElementID id)
{
	switch(id.kind())
	{
		case ElementID::Kind::gate: return std::to_string(id.id());
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
		   << " [label=\"in_" << to_string(circ.inputs[id].party) << "_" << id << "\"];\n";
	}

	for(size_t id = 0; id < circ.gates.size(); ++id)
	{
		Gate const &gate = circ.gates[id];
		for(auto fanin: gate.fanins)
			os << '\t' << elem_id_to_string(fanin.id) << " -> " << elem_id_to_string(GateID{id}) << ";\n";
	}

	for(size_t id = 0; id < circ.outputs.size(); ++id)
		os << '\t' << elem_id_to_string(circ.outputs[id]->id) << " -> " << elem_id_to_string(OutputID{id}) << ";\n";

	for(auto const &call: circ.function_calls)
	{
		for(auto const &arg: call.args)
		{
			for(OutputID out: arg.outputs)
			{
				for(auto const &ret: call.returns)
				{
					for(InputID in: ret.inputs)
						os << '\t' << elem_id_to_string(out) << " -> " << elem_id_to_string(in) << " [style=dashed; color=gray];\n";
				}
			}
		}
	}

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
