/*
 * simple_circuit_rewriting.cpp
 *
 *  Created on: 05.10.2013
 *      Author: andreas
 *      Update: 10.08.2015 (original pattern are now in simple_circuit_rewriting_old)
 */

#include "simple_circuit.h"

#include <stack>

bool simple_circuitt::rewrite(timeout_datat& data, bool (*func)(gatet* gate, bool round2, simple_circuitt* obj), bool round2) {

	bool changed_circuit = false;

	if (m_logger->level() >= log_levelt::debug) {
		::std::cout << "[REWRITING] start" << ::std::endl;
		::std::cout << "#gates (start) = " << get_number_of_gates() << ::std::endl;
	}

	typedef ::std::vector< gatet* > gatest;
	gatest worklist;

	simple_circuit_level_mapt level_map;
	simple_circuit_level_sett level_set;

	for (gatet* gate_it = gates_HEAD; gate_it != NULL; gate_it = gate_it->next) {
		if (timeout(data)) 
			return false;

		// determine level
		simple_circuit_get_depth(gate_it, level_map, &level_set);
	}

    for(auto it = level_set.rbegin(); it != level_set.rend(); ++it) {
		::std::set< simple_circuitt::gatet* >* set = it->second.gates;

		assert(set);

		for (::std::set< simple_circuitt::gatet* >::iterator it = set->begin(); it != set->end(); ++it) {
			if (timeout(data)) {
				return false;
			}

			if (*it != ZERO_GATE) {
				worklist.push_back(*it);
			}
		}

		// we do not need this set anymore, so let us free the memory
		delete set;
	}

	// we do not need level_set anymore
	level_set.clear();

	assert(get_number_of_gates() == worklist.size());

	unsigned counter = 1;

	for (gatest::iterator it = worklist.begin(); it != worklist.end() && !timeout(data); ++it) {
		counter++;

		if (m_logger->level() >= log_levelt::debug) {
			if (counter % 10000 == 0) {
				::std::cout << (counter + 1) << "/" << worklist.size() << ::std::endl;
			}
		}

		/** call of minimizing procedure **/
		changed_circuit = func(*it, round2, this);

	}

	if (m_logger->level() >= log_levelt::debug) {
		::std::cout << "[REWRITE] done rewriting, starting cleanup ..." << ::std::endl;
	}

	level_map.clear();

	if (cleanup()) {
		changed_circuit = true;
	}

	if (m_logger->level() >= log_levelt::debug) {
		::std::cout << "[REWRITING] end" << ::std::endl;
	}

	return changed_circuit;
}

bool simple_circuitt::cleanup() {
	bool changed_circuit = false;

	simple_circuit_level_mapt level_map;
	simple_circuit_level_sett level_set;

	if (m_logger->level() >= log_levelt::debug)
		::std::cout << "determine level" << ::std::endl;

	// determine level
	for (gatet* gate_it = gates_HEAD; gate_it != NULL; gate_it = gate_it->next)
		simple_circuit_get_depth(gate_it, level_map, &level_set);

	if (m_logger->level() >= log_levelt::debug)
		::std::cout << "fill stack" << ::std::endl;

	::std::stack< gatet* > stack;
    for(auto &pair: level_set) {
		::std::set< simple_circuitt::gatet* >* set = pair.second.gates;
		assert(set);

		for (::std::set< simple_circuitt::gatet* >::iterator it = set->begin(); it != set->end(); ++it) {
			if (*it != ZERO_GATE)
				stack.push(*it);
		}

		// we do not need the set anymore, so delete it
		delete set;
	}
    
	assert(get_number_of_gates() == stack.size());

	if (m_logger->level() >= log_levelt::debug)
		::std::cout << "remove elements" << ::std::endl;

	unsigned tasks = get_number_of_gates();

	while (!stack.empty()) {
		if (m_logger->level() >= log_levelt::debug) {
			if (stack.size() % 100 == 0)
				::std::cout << (tasks - stack.size()) << "/" << tasks << ::std::endl;
		}

		gatet* gate = stack.top();
		stack.pop();
		if (gate->fanouts.empty()) {
			remove(gate);

			changed_circuit = true;
		}
	}

	if (m_logger->level() >= log_levelt::debug)
		::std::cout << "#gates (end) = " << get_number_of_gates() << ::std::endl;

	return changed_circuit;
}

/*
 *  computes some statistics of the actual circuit (can be called within rewriting method)
 */
simple_circuitt::statst simple_circuitt::query_stats(simple_circuit_level_sett *level_set) const {
	simple_circuit_level_mapt level_map;
	non_linear_level_mapt level_nXmap;
	non_linear_deptht non_linear_depth;
	statst stats;

	for (gatet* gate_it = gates_HEAD; gate_it != NULL; gate_it = gate_it->next)
	{
		if(is_boolean_non_const_op(gate_it->get_operation()))
		{
			stats.num_gates++;
			stats.num_boolean_gates++;

			if(gate_it->get_operation() != XOR && gate_it->get_operation() != NOT)
				stats.num_non_xor_gates++;

			if(gate_it->get_operation() == AND)
				stats.num_and_gates++;
			if(gate_it->get_operation() == OR)
				stats.num_or_gates++;
			if(gate_it->get_operation() == XOR)
				stats.num_xor_gates++;
			if(gate_it->get_operation() == NOT)
				stats.num_not_gates++;
			else if(gate_it->get_operation() == LUT)
				stats.num_luts++;
		}
		else if(is_arithmetic_non_const_op(gate_it->get_operation()))
		{
			stats.num_gates++;
			stats.num_arith_gates++;

			if(gate_it->get_operation() == MUL)
				stats.num_mul_gates++;
			else if(gate_it->get_operation() == ADD)
				stats.num_add_gates++;
			else if(gate_it->get_operation() == SUB)
				stats.num_sub_gates++;
			else if(gate_it->get_operation() == NEG)
				stats.num_neg_gates++;
		}

		// determine level
		stats.depth = std::max(
			simple_circuit_get_depth(gate_it, level_map, level_set),
			stats.depth
		);

		non_linear_depth = max(get_non_linear_depth(gate_it, level_nXmap), non_linear_depth);
	}

	stats.non_xor_depth = non_linear_depth.non_xor_depth;
	stats.mul_depth = non_linear_depth.mul_depth;

	level_map.clear();
	level_nXmap.clear();

	return stats;
}

void simple_circuitt::print_stats(statst const &stats)
{
	m_logger->statistics()
		<< "Total:      gates: " << stats.num_gates << ", depth: " << stats.depth
		<< "\nBoolean:    gates: " << stats.num_boolean_gates << ", Non-XOR gates: " << stats.num_non_xor_gates
		<< ", Non-XOR depth: " << stats.non_xor_depth << ", LUTs: " << stats.num_luts
		<< "\nArithmetic: gates: " << stats.num_arith_gates << ", Mul gates: " << stats.num_mul_gates
		<< ", Mul depth: " << stats.mul_depth << eom;
}

void simple_circuitt::print_stats() {
  print_stats(query_stats());
}

/**
 * returns the other input of gate, where input0 is one of gate's inputs
 * only use with 2-input gates!
 */
simple_circuitt::gatet* simple_circuitt::get_other_input(gatet& gate, gatet* input0) {
	if (is_same_gate(gate.get_fanin(0), input0))
		return gate.get_fanin(1);
	else return gate.get_fanin(0);
}

/**
 * creates a gate with operator op and fanin0 and fanin1 as inputs if it does not already exist
 */
simple_circuitt::gatet* simple_circuitt::create_this_gate(gatet*& fanin0, gatet*& fanin1, GATE_OP op) {
	assert(fanin0);
	assert(fanin1);

	gatet* this_gate;
	if (has_this_fanout(fanin0, fanin1, op, this_gate))
        return this_gate;

	this_gate = get_or_create_gate(op);
	this_gate->add_fanin(primary_output(fanin0), 0);
	this_gate->add_fanin(primary_output(fanin1), 1);

	return this_gate;
}

/**
 * creates a NOT gate with fanin0 as input if it does not already exist
 */
simple_circuitt::gatet* simple_circuitt::create_this_NOT_gate(gatet*& fanin0) {
	assert(fanin0);

	gatet* this_gate;
	if (has_NOT_fanout(*fanin0, this_gate))
		return this_gate;

	this_gate = get_or_create_gate(NOT);
	this_gate->add_fanin(primary_output(fanin0), 0);
	return this_gate;
}

/**
 * checks if gate and other_gate are the same (have the same address or the same input gates)
 */
bool simple_circuitt::is_same_gate(gatet* gate, gatet* other_gate) {

	// ToDo: should not happen but it does sometimes?
	if (gate == NULL || other_gate == NULL)
		return false;

	if (gate == other_gate)
		return true;

	if (gate->get_operation() == other_gate->get_operation()) {
		if (!is_boolean_non_const_op(gate->get_operation()))
			return false;

		assert(gate->get_fanin(0));
		assert(other_gate->get_fanin(0));

		if (gate->get_operation() == NOT)
			return gate->get_fanin(0) == other_gate->get_fanin(0);

		else {
			assert(gate->get_fanin(1));
			assert(other_gate->get_fanin(1));

			if (gate->get_fanin(0) == other_gate->get_fanin(0) && gate->get_fanin(1) == other_gate->get_fanin(1))
				return true;

			if (gate->get_fanin(0) == other_gate->get_fanin(1) && gate->get_fanin(1) == other_gate->get_fanin(0))
				return true;
		}
	}
	return false;
}

/**
 * checks if gate and other_gate are the inverse of each other (one of them has to be a NOT gate)
 */
bool simple_circuitt::is_NOT_same_gate(gatet* gate, gatet* other_gate) {

	// ToDo: should not happen but it does sometimes?
	if (gate == NULL || other_gate == NULL)
		return false;

	if (gate->get_operation() == NOT && gate->get_fanin(0) == other_gate)
		return true;

	if (other_gate->get_operation() == NOT && other_gate->get_fanin(0) == gate)
		return true;

	return false;
}

/**
 * checks if gate "gate" already has a NOT gate as fanout and returns it as not_gate if so
 */
bool simple_circuitt::has_NOT_fanout(gatet& gate, gatet*& not_gate) {
	for (gatet::fanoutst::iterator fanout_it = gate.fanouts.begin(); fanout_it != gate.fanouts.end(); ++fanout_it) {
		 gatet::fanoutt* fan_out = *fanout_it;
		 not_gate = fan_out->second.gate;

		 if (not_gate->get_operation() == NOT)
			 return true;
	}
	return false;
}

/**
 * checks if gate fanin0 has a fanout gate with operator op where the other fanin is same gate as fanin1
 */
bool simple_circuitt::has_this_fanout(gatet*& fanin0, gatet*& fanin1, GATE_OP op, gatet*& this_gate) {
	for (gatet::fanoutst::iterator fanout_it = (*fanin0).fanouts.begin(); fanout_it != (*fanin0).fanouts.end(); ++fanout_it) {
		gatet::fanoutt* fan_out = *fanout_it;
        gatet* fanout_gate = fan_out->second.gate;

		if (fan_out->second.gate->get_operation() == op && 
            ((fanout_gate->get_fanin(0) == fanin0 && fanout_gate->get_fanin(1) == fanin1) ||
             (fanout_gate->get_fanin(0) == fanin1 && fanout_gate->get_fanin(1) == fanin0))) {
			this_gate = fan_out->second.gate;
			return true;
		}
	}
	return false;
}

/**
 * checks if gate fanin0 has a fanout gate with operator op where the other fanin is same gate as NOT(fanin1)
 */
bool simple_circuitt::has_this_NOT_fanout(gatet*& fanin0, gatet*& fanin1, GATE_OP op, gatet*& this_gate) {
	for (gatet::fanoutst::iterator fanout_it = (*fanin0).fanouts.begin(); fanout_it != (*fanin0).fanouts.end(); ++fanout_it) {
		gatet::fanoutt* fan_out = *fanout_it;

		if (fan_out->second.gate->get_operation() == op) {
			if (fan_out->second.gate->get_fanin(0)->get_operation() == NOT && fanin1 == fan_out->second.gate->get_fanin(0)->get_fanin(0)) {

				this_gate = fan_out->second.gate;
				return true;
			}
			if (fan_out->second.gate->get_fanin(0)->get_operation() == NOT && fanin1 == fan_out->second.gate->get_fanin(0)->get_fanin(0)) {

				this_gate = fan_out->second.gate;
				return true;
			}
		}
	}
	return false;
}

/**
 * checks if searched_gate is a parent of act_gate
 * only use with 2-input gates!
 */
bool simple_circuitt::is_one_of(gatet* act_gate, gatet* searched_gate, GATE_OP op) {
	if (act_gate->get_operation() == op)
		return is_same_gate(searched_gate, act_gate->get_fanin(0)) || is_same_gate(searched_gate, act_gate->get_fanin(1));
	return false;
}

/**
 * one of the old pattern but now with a new signature
 */
bool simple_circuitt::simplify15(gatet& gate, gatet*& fanin0_out) {
	if (gate.get_operation() == OR) {

		if (gate.get_fanin(0)->get_operation() == AND && gate.get_fanin(0)->fanouts.size() == 1 && gate.get_fanin(1)->get_operation() == NOT && gate.get_fanin(1)->fanouts.size() == 1 && gate.get_fanin(1)->get_fanin(0)->get_operation() == OR && gate.get_fanin(1)->get_fanin(0)->fanouts.size() == 1) {
			gatet* or_gate = gate.get_fanin(1)->get_fanin(0);

			gatet* a_pin = gate.get_fanin(0)->get_fanin(0);
			gatet* b_pin = gate.get_fanin(0)->get_fanin(1);

			if ((a_pin == or_gate->get_fanin(0) && b_pin == or_gate->get_fanin(1)) || (a_pin == or_gate->get_fanin(1) && b_pin == or_gate->get_fanin(0))) {
				fanin0_out = create_this_gate(a_pin, b_pin, XOR);
				return true;
			}
		}
		if (gate.get_fanin(1)->get_operation() == AND && gate.get_fanin(1)->fanouts.size() == 1 && gate.get_fanin(0)->get_operation() == NOT && gate.get_fanin(0)->fanouts.size() == 1 && gate.get_fanin(0)->get_fanin(0)->get_operation() == OR && gate.get_fanin(0)->get_fanin(0)->fanouts.size() == 1) {
			gatet* or_gate = gate.get_fanin(0)->get_fanin(0);

			gatet* a_pin = gate.get_fanin(1)->get_fanin(0);
			gatet* b_pin = gate.get_fanin(1)->get_fanin(1);

			if ((a_pin == or_gate->get_fanin(0) && b_pin == or_gate->get_fanin(1)) || (a_pin == or_gate->get_fanin(1) && b_pin == or_gate->get_fanin(0))) {
				fanin0_out = create_this_gate(a_pin, b_pin, XOR);
				return true;
			}
		}

	}
	return false;
}

/**
 * one of the old pattern but now with a new signature
 */
bool simple_circuitt::simplify17(gatet& gate, gatet*& fanin0_out) {
	if (gate.get_operation() == XOR) {
		if (gate.get_fanin(0)->get_operation() == NOT && gate.get_fanin(0)->fanouts.size() == 1) {

			fanin0_out = create_this_gate(gate.get_fanin(0)->get_fanin(0), gate.get_fanin(1), XOR);
			return true;
		}

		if (gate.get_fanin(1)->get_operation() == NOT && gate.get_fanin(1)->fanouts.size() == 1) {

			fanin0_out = create_this_gate(gate.get_fanin(1)->get_fanin(0), gate.get_fanin(0), XOR);
			return true;
		}
	}

	return false;
}
