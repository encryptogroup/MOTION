/*
 * simple_circuit_dot.cpp
 *
 *  Created on: 07.10.2013
 *      Author: andreas
 */

#include "simple_circuit.h"
#include "LUT_gate.h"

#include <stdlib.h>

#include <string>
#include <cassert>
#include <fstream>
#include <sstream>

#define DOT_DETAILED_NODES



#ifdef DOT_DETAILED_NODES
void write_gate_node_dot(
	::std::ostream& dotfile,
	simple_circuitt::gatet* lGate,
	::std::map< simple_circuitt::gatet*,
	unsigned >& gate_indices,
	simple_circuitt::non_linear_level_mapt *nldepth = nullptr) 
{
	assert(gate_indices.find(lGate) != gate_indices.end());

	unsigned id = gate_indices[lGate];

	dotfile << "  node [shape=record];" << ::std::endl;
	dotfile << "  gate" << id << " [label=\"{";

	dotfile << "{";

	LUT_gatet* l_gate = NULL;

	switch (lGate->get_operation()) {
	case simple_circuitt::NOT:
	case simple_circuitt::NEG:
	case simple_circuitt::OUTPUT:
		dotfile << "<i0>";
		break;
	case simple_circuitt::OR:
	case simple_circuitt::AND:
	case simple_circuitt::XOR:
	case simple_circuitt::ADD:
	case simple_circuitt::SUB:
	case simple_circuitt::MUL:
		dotfile << "<i0>|<i1>";
		break;
	case simple_circuitt::LUT:
		l_gate = dynamic_cast<LUT_gatet*>(lGate);
		if (l_gate->get_fanins()->size() != 0)
			dotfile << "<i0>";
		for (unsigned i = 1; i < l_gate->get_fanins()->size(); i++)
			dotfile << "|<i" << i <<">";
		break;
	default:
		break;
	}

	dotfile << "}|" << lGate->to_string();
	if(nldepth)
		dotfile << " (nldepth=" << (*nldepth)[lGate].non_xor_depth << ")";
    if(lGate->get_width() != 1)
      dotfile << "#" << lGate->get_width();


	dotfile << "}\"];" << ::std::endl;
}
#else
void write_gate_node_dot(::std::ostream& dotfile, simple_circuitt::gatet* lGate, ::std::map< simple_circuitt::gatet*, unsigned >& gate_indices) {
	assert(gate_indices.find(lGate) != gate_indices.end());

	unsigned id = gate_indices[lGate];

	dotfile << "  node [shape=box];" << ::std::endl;
	dotfile << "  gate" << id << " [label=\"";
	dotfile << lGate->to_string();
	dotfile << "\"];" << ::std::endl;
}
#endif

void simple_circuitt::write_transitions_dot(::std::ostream& dotfile, simple_circuitt::gatet* lGate, ::std::map< simple_circuitt::gatet*, unsigned >& gate_indices, bool leveling, unsigned level_limit, simple_circuit_level_mapt level_map) {
	for (simple_circuitt::gatet::fanoutst::iterator fanout_it = lGate->fanouts.begin(); fanout_it != lGate->fanouts.end(); ++fanout_it) {
		simple_circuitt::gatet::fanoutt* fanout = *fanout_it;

		assert(gate_indices.find(lGate) != gate_indices.end());
		// ToDo: fix this
		assert(gate_indices.find(fanout->second.gate) != gate_indices.end());

		if (leveling) {
			if (level_map[lGate] <= level_limit) {
				if (level_map[fanout->second.gate] <= level_limit || fanout->second.gate->get_operation() == OUTPUT) {
#ifdef DOT_DETAILED_NODES
					dotfile << "  gate" << gate_indices[lGate] << " -> gate" << gate_indices[fanout->second.gate] << ":i" << fanout->second.pin << ";" << ::std::endl;
#else
					dotfile << "  gate" << gate_indices[lGate] << " -> gate" << gate_indices[fanout->second.gate] << ";" << ::std::endl;
#endif
				}
			}
		}
		else {
#ifdef DOT_DETAILED_NODES
			dotfile << "  gate" << gate_indices[lGate] << " -> gate" << gate_indices[fanout->second.gate] << ":i" << fanout->second.pin << ";" << ::std::endl;
#else
			dotfile << "  gate" << gate_indices[lGate] << " -> gate" << gate_indices[fanout->second.gate] << ";" << ::std::endl;
#endif
		}
	}
}

void simple_circuitt::write_dot(::std::ostream& dotfile, bool leveling, unsigned level_limit) {
	::std::cout << "[WRITE_DOT] start" << ::std::endl;

	simple_circuit_level_mapt level_map;
	simple_circuit_level_sett level_set;

	::std::map< gatet*, unsigned > gate_indices;

	if (is_one_gate_actually_used()) {
		gate_indices[ONE_GATE] = 0;
	}

	if (!ZERO_GATE->fanouts.empty()) {
		unsigned id = gate_indices.size();
		// wegen dem ZERO_GATE hat das ONE_GATE einen ausgang!
		gate_indices[ZERO_GATE] = id;
	}

	for (gatet* gate = input_gates_HEAD; gate != NULL; gate = gate->next) {
		// assign id
		unsigned id = gate_indices.size();
		gate_indices[gate] = id;
	}

	for (gatet* gate = output_gates_HEAD; gate != NULL; gate = gate->next) {
		// assign id
		unsigned id = gate_indices.size();
		gate_indices[gate] = id;
	}

	// determine level and assign gate id
	for (gatet* gate = gates_HEAD; gate != NULL; gate = gate->next) {
		// assign id
		unsigned id = gate_indices.size();
		gate_indices[gate] = id;

		// determine level
		simple_circuit_get_depth(gate, level_map, &level_set);
	}

	dotfile << "digraph circuit" << ::std::endl;
	dotfile << "{" << ::std::endl;

	dotfile << "subgraph level_0 {" << ::std::endl;
	dotfile << "  rank = same;" << ::std::endl;

	// gates
	if (is_one_gate_actually_used()) {
		write_gate_node_dot(dotfile, ONE_GATE, gate_indices);
	}

	if (!ZERO_GATE->fanouts.empty()) {
		write_gate_node_dot(dotfile, ZERO_GATE, gate_indices);
	}

	for (gatet* gate = input_gates_HEAD; gate != NULL; gate = gate->next) {
		write_gate_node_dot(dotfile, gate, gate_indices);
	}

	dotfile << "}" << ::std::endl;

	dotfile << "subgraph level_" << (level_set.size() + 1) << " {" << ::std::endl;
	dotfile << "  rank = same;" << ::std::endl;

    non_linear_level_mapt nldepth_map;
	for (gatet* gate = output_gates_HEAD; gate != NULL; gate = gate->next)
      get_non_linear_depth(gate, nldepth_map);

	for (gatet* gate = output_gates_HEAD; gate != NULL; gate = gate->next) {
		write_gate_node_dot(dotfile, gate, gate_indices, &nldepth_map);
	}

	dotfile << "}" << ::std::endl;

	//unsigned sum = 0;

	for (simple_circuit_level_sett::iterator it = level_set.begin(); it != level_set.end() && it->first <= level_limit; ++it) {

		::std::cout << "level " << it->first << ::std::endl;

		//sum += it->second->size();

		dotfile << "subgraph level_" << it->first << " {" << ::std::endl;
		dotfile << "  rank = same;" << ::std::endl;

		for (::std::set< gatet* >::iterator gate_it = it->second.gates->begin(); gate_it != it->second.gates->end(); ++gate_it) {
			write_gate_node_dot(dotfile, *gate_it, gate_indices);
		}

		dotfile << "}" << ::std::endl;
	}

	::std::cout << "printing transitions" << ::std::endl;

	//assert(sum == get_number_of_gates());

	::std::cout << "one transitions" << ::std::endl;

	// transitions
	if (is_one_gate_actually_used()) {
		write_transitions_dot(dotfile, ONE_GATE, gate_indices, leveling, level_limit, level_map);
	}
	if (!ZERO_GATE->fanouts.empty()) {
		write_transitions_dot(dotfile, ZERO_GATE, gate_indices, leveling, level_limit, level_map);
	}

	::std::cout << "input transitions" << ::std::endl;

	for (gatet* gate = input_gates_HEAD; gate != NULL; gate = gate->next) {
		write_transitions_dot(dotfile, gate, gate_indices, leveling, level_limit, level_map);
	}

	::std::cout << "output transitions" << ::std::endl;

	for (gatet* gate = output_gates_HEAD; gate != NULL; gate = gate->next) {
		write_transitions_dot(dotfile, gate, gate_indices, leveling, level_limit, level_map);
	}

	/*for (gatet* gate = gates_HEAD; gate != NULL; gate = gate->next) {
		write_transitions_dot(dotfile, gate, gate_indices, leveling, level_limit, level_map);
	}*/

	::std::cout << "gate transitions" << ::std::endl;

	for (simple_circuit_level_sett::iterator it = level_set.begin(); it != level_set.end() && it->first <= level_limit; ++it) {

		::std::cout << "level " << it->first << ::std::endl;

		//sum += it->second->size();

		for (::std::set< gatet* >::iterator gate_it = it->second.gates->begin(); gate_it != it->second.gates->end(); ++gate_it) {
			write_transitions_dot(dotfile, *gate_it, gate_indices, leveling, level_limit, level_map);
		}

		// we do not need it->second anymore, so delete it
		delete (it->second.gates);
	}

	dotfile << "}" << ::std::endl;

	::std::cout << "[WRITE_DOT] end" << ::std::endl;
}


