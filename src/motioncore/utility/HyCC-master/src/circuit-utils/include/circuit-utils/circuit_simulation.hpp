#pragma once

#include "circuit.hpp"

#include <libcircuit/runner.h>


namespace circ {

//==================================================================================================
SymbolTable create_symbol_table(Circuit const &c);
EvaluationContext create_context(circ::Circuit const &circuit);


//==================================================================================================
std::unordered_map<WireEndpoint, bool> simulate(
	Circuit const &circ,
	std::unordered_map<std::string, TypedValue> const &input_values);


//==================================================================================================
RawValue bits_to_raw_value(std::vector<bool> bits);


inline RawValue extract_output_value(
	OutputVariable const &ov,
	std::unordered_map<WireEndpoint, bool> const &circuit_values)
{
	std::vector<bool> bit_vals;
	for(auto id: ov.outputs)
		bit_vals.push_back(circuit_values.at(primary_endpoint(id)));

	return bits_to_raw_value(bit_vals);
}


}
