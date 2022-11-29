/*
 * simple_circuit_theorems.cpp
 *
 *  Created on: 10.08.2015
 *      Author:
 *    Function: Structurizing. Try to exchange cascades with trees to achieve a better depth
 */

#include "simple_circuit.h"

/*******************************************************************
 Function: simple_circuitt::structurize

 Inputs: actual gate and a boolean for the optimization priority (not needed here)

 Outputs: true if we can change the structure to achieve better depth

 Purpose: helper function for calling structurize pattern

 \*******************************************************************/
bool simple_circuitt::structurize(gatet* gate, bool round2) {

	bool changed_circuit = false;

	if (structural_minimize(*gate, AND) || structural_minimize(*gate, OR) || structural_minimize(*gate, XOR))
		changed_circuit = true;

	return changed_circuit;
}

bool simple_circuitt::structural_minimize(gatet& gate, GATE_OP op) {

	gatet* act_gate = &gate;
	std::list<gatet*> act_list, new_list;

	// collect gate outputs of cascade
	while (act_gate->get_operation() == op && act_gate->fanouts.size() == 1) {
		if (act_gate->get_fanin(0)->get_operation() == op && act_gate->get_fanin(1)->get_operation() != op) {
			act_list.push_back(act_gate->get_fanin(1));
			act_gate = act_gate->get_fanin(0);
		}
		else if (act_gate->get_fanin(0)->get_operation() != op && act_gate->get_fanin(1)->get_operation() == op) {
			act_list.push_back(act_gate->get_fanin(0));
			act_gate = act_gate->get_fanin(1);
		}
		else {
			act_list.push_back(act_gate->get_fanin(0));
			act_list.push_back(act_gate->get_fanin(1));
			break;
		}
	}
	unsigned size = act_list.size();
	if (size <= 3)
		return false;

	for (unsigned i = 0; (i < size && act_list.size() != 1); i++) {
		gatet *first, *second;
		// try to build pairs of two, if we have not enough, fill up with zero-gates
		while (act_list.size() != 0) {
			first = act_list.front();
			act_list.pop_front();

			if (act_list.size() != 0) {
				second = act_list.front();
				act_list.pop_front();
			}
			else second = (op == AND? ONE_GATE : ZERO_GATE);
			gatet* new_gate = create_this_gate(second, first, op);

			new_list.push_back(new_gate);
		}
		act_list = new_list;
		new_list.clear();
	}
	gate.replace_by(act_list.front());
	return true;
}
