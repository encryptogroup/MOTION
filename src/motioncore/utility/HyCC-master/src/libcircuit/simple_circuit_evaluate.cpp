/*
 * simple_circuit_evaluate.cpp
 *
 *  Created on: 08.05.2016
 *      Author: alina
 */

#include "simple_circuit.h"
#include "LUT_gate.h"

/*******************************************************************
 Function: simple_circuitt::verify_LUT_circuit

 Inputs: vector of results for the old circuit

 Outputs: true if circuit are equivalent

 Purpose: checks if new LUT circuit is equivalent to the circuit before clustering

 \*******************************************************************/
bool simple_circuitt::verify_LUT_circuit(std::vector<std::string*>* before) {
	std::vector<std::string*>* after = evaluate_simple_circuit();
	bool same = true;

	for(unsigned i = 0; i < after->size(); i++)
		if(*(before->at(i)) != *(after->at(i)))
			same = false;

	return same;
}

/*******************************************************************
 Function: simple_circuitt::evaluate_simple_circuit

 Inputs: -

 Outputs: vector of evaluation strings for all output gates

 Purpose: evaluates whole circuit and returns a vector containing results for the output gates for all input combinations

 \*******************************************************************/
std::vector<std::string*>* simple_circuitt::evaluate_simple_circuit() {
	std::set< gatet* >* inputs = new std::set< gatet*>;
	std::vector<std::string*>* out = new std::vector<std::string*>;

	for (gatet* it = input_gates_HEAD; it != NULL; it = it->next)
		inputs->insert(it);

	for (gatet* it = output_gates_HEAD; it != NULL; it = it->next)
		out->push_back(evaluate(it, inputs));

	inputs->clear();
	delete inputs;

	return out;
}

/*******************************************************************
 Function: simple_circuitt::evaluate

 Inputs: root gate and input gates of a subcircuit

 Outputs: string with the result of the evaluation for all combinations of the input gates

 Purpose: evaluates subcircuit with output gate "root" for all combinations of the given input gates

 \*******************************************************************/
std::string* simple_circuitt::evaluate(gatet* root, ::std::set< gatet* >* inputs) {
	std::string* out = new std::string;

	for (unsigned i = 0; i < (unsigned)(2 << (inputs->size()-1)); i++) {
		std::map< gatet*, bool >* eval_map = new std::map< gatet*, bool>;

		// binary count of inputs
		unsigned loop_count = i;
		for (std::set< gatet* >::reverse_iterator it = inputs->rbegin(); it != inputs->rend(); ++it) {
			(*eval_map)[*it] = (loop_count%2 != 0);
			loop_count = loop_count >> 1;
		}

		bool result = evaluate_rec(root, eval_map);
		(*eval_map)[root] = result;

		if (result)
			out->append("1");
		else out->append("0");

		delete eval_map; // ToDo: would be much faster if circuit would only be evaluated for changed input value
	}

	return out;
}

/*******************************************************************
 Function:

 Inputs:

 Outputs:

 Purpose:

 \*******************************************************************/
bool simple_circuitt::evaluate_rec(gatet* gate, std::map< gatet*, bool >* eval_map) {
	if (gate->operation == LUT)
		return evaluate_LUT(gate, eval_map);

	bool fanin0 = false;
	bool fanin1 = false;

	for(auto &fanin_ep: gate->fanins)
	{
		gatet *fanin = fanin_ep.gate;
		if(!fanin) continue;

		std::map< gatet*, bool >::iterator map_it = eval_map->find(fanin);
		if (map_it == eval_map->end())
			fanin0 = evaluate_rec(fanin, eval_map);
		else fanin0 = (*map_it).second;
	}

	return evaluate_gate(gate, fanin0, fanin1);
}

/*******************************************************************
 Function: simple_circuitt::evaluate_gate

 Inputs: gate to be evaluated, bools for the inputs

 Outputs: true if gate is evaluated to "1", false otherwise

 Purpose: evaluates given gates for input booleans

 \*******************************************************************/
bool simple_circuitt::evaluate_gate(gatet* gate, bool fanin0, bool fanin1) {
	assert(gate->operation != INPUT);

	switch (gate->operation) {
	case AND:
		return fanin0 && fanin1;
	case OR:
		return fanin0 || fanin1;
	case NOT:
		return !fanin0;
	case XOR:
		if ((fanin0 == true && fanin1 == false) || (fanin0 == false && fanin1 == true))
			return true;
		else return false;
	case OUTPUT:
		return fanin0;

	default:
		std::cout << "no known operation for evaluation" << gate->operation << std::endl;
		return false;
	}
}

/*******************************************************************
 Function:

 Inputs:

 Outputs:

 Purpose:

 \*******************************************************************/
bool simple_circuitt::evaluate_LUT(gatet* gate, std::map< gatet*, bool >* eval_map) {
	bool result;
	LUT_gatet* l_gate = dynamic_cast<LUT_gatet*>(gate);
	assert(l_gate);

	unsigned index = 0;
	unsigned round = l_gate->get_fanins()->size()-1;
	for (std::set< std::pair< gatet*, unsigned > >::iterator it = l_gate->get_fanins()->begin(); it != l_gate->get_fanins()->end(); ++it, round--) {
		std::map< gatet*, bool >::iterator map_it = eval_map->find((*it).first);
		bool in = false;

		if (map_it == eval_map->end())
			in = evaluate_rec((*it).first, eval_map);
		else in = (*map_it).second;

		if (in) {
			if (round == 0)
				index += 1;
			else index += 2 << (round-1);
		}
	}

	if (l_gate->get_outString()->at(index) == '1')
		result = 1;
	else result = 0;

	(*eval_map)[gate] = result;
	return result;
}
