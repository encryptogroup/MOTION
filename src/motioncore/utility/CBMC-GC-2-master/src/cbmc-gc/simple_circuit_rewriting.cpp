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

	if (message_handler.get_message_handler().get_verbosity() >= 9) {
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
		simple_circuit_get_depth(*this, gate_it, level_map, &level_set);
	}

	for (unsigned i = level_set.size(); i > 0; i--) {
		::std::set< simple_circuitt::gatet* >* set = level_set[i];

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

		if (message_handler.get_message_handler().get_verbosity() >= 9) {
			if (counter % 10000 == 0) {
				::std::cout << (counter + 1) << "/" << worklist.size() << ::std::endl;
			}
		}

		/** call of minimizing procedure **/
		changed_circuit = func(*it, round2, this);

	}

	if (message_handler.get_message_handler().get_verbosity() >= 9) {
		::std::cout << "[REWRITE] done rewriting, starting cleanup ..." << ::std::endl;
	}

	level_map.clear();

	if (cleanup()) {
		changed_circuit = true;
	}

	if (message_handler.get_message_handler().get_verbosity() >= 9) {
		::std::cout << "[REWRITING] end" << ::std::endl;
	}

	return changed_circuit;
}

bool simple_circuitt::cleanup() {
	bool changed_circuit = false;

	simple_circuit_level_mapt level_map;
	simple_circuit_level_sett level_set;

	if (message_handler.get_message_handler().get_verbosity() >= 9)
		::std::cout << "determine level" << ::std::endl;

	// determine level
	for (gatet* gate_it = gates_HEAD; gate_it != NULL; gate_it = gate_it->next)
		simple_circuit_get_depth(*this, gate_it, level_map, &level_set);

	if (message_handler.get_message_handler().get_verbosity() >= 9)
		::std::cout << "fill stack" << ::std::endl;

	::std::stack< gatet* > stack;
	for (unsigned i = 1; i <= level_set.size(); i++) {
		::std::set< simple_circuitt::gatet* >* set = level_set[i];
		assert(set);

		for (::std::set< simple_circuitt::gatet* >::iterator it = set->begin(); it != set->end(); ++it) {
			if (*it != ZERO_GATE)
				stack.push(*it);
		}

		// we do not need the set anymore, so delete it
		delete set;
	}
	assert(get_number_of_gates() == stack.size());

	if (message_handler.get_message_handler().get_verbosity() >= 9)
		::std::cout << "remove elements" << ::std::endl;

	unsigned tasks = get_number_of_gates();

	while (!stack.empty()) {
		if (message_handler.get_message_handler().get_verbosity() >= 9) {
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

	if (message_handler.get_message_handler().get_verbosity() >= 9)
		::std::cout << "#gates (end) = " << get_number_of_gates() << ::std::endl;

	return changed_circuit;
}

/*
 *  prints some statistics of the actual circuit (can be called within rewriting method)
 */
#define PRINT_DEPTH
simple_circuitt::statst simple_circuitt::query_stats() {
	int count = 0, nXcount = 0, LUTcount = 0;
#ifdef PRINT_DEPTH
	simple_circuit_level_mapt level_map, level_nXmap;
	simple_circuit_level_sett level_set;
	int circuit_depth = 0, new_depth = 0, circuit_nXdepth = 0, new_nXdepth = 0;

	for (gatet* gate_it = gates_HEAD; gate_it != NULL; gate_it = gate_it->next) {
		// determine level
		new_depth = simple_circuit_get_depth(*this, gate_it, level_map, &level_set);
		circuit_depth = (new_depth > circuit_depth)? new_depth : circuit_depth;

		new_nXdepth = simple_circuit_get_depth_nXOR(*this, gate_it, level_nXmap);
		circuit_nXdepth = (new_nXdepth > circuit_nXdepth)? new_nXdepth : circuit_nXdepth;
	}

	for (unsigned i = level_set.size(); i > 0; i--) {
		::std::set< simple_circuitt::gatet* >* set = level_set[i];
		assert(set);

		for (::std::set< simple_circuitt::gatet* >::iterator it = set->begin(); it != set->end(); ++it) {
			if (*it != ZERO_GATE && (*it)->get_operation() != INPUT && (*it)->get_operation() != OUTPUT) {
				count++;
				if ((*it)->get_operation() != XOR && (*it)->get_operation() != NOT)
					nXcount++;
				if ((*it)->get_operation() == LUT)
					LUTcount++;
			}
		}
		// we do not need this set anymore, so let us free the memory
		delete set;
	}
	level_set.clear();
	level_map.clear();
	level_nXmap.clear();

	statst stats;
	stats.num_gates = count;
	stats.num_non_xor_gates = nXcount;
	stats.depth = circuit_depth;
	stats.non_xor_depth = circuit_nXdepth;
	stats.num_luts = LUTcount;
	return stats;
#else
  for (gatet* gate_it = gates_HEAD; gate_it != NULL; gate_it = gate_it->next) {
    count++;
      if ((gate_it)->get_operation() != XOR && (gate_it)->get_operation() != NOT) {
					nXcount++;
			}
		if ((gate_it)->get_operation() == LUT)
			LUTcount++;
  }
	statst stats;
	stats.num_gates = count;
	stats.num_non_xor_gates = nXcount;
	stats.depth = -1;
	stats.non_xor_depth = -1;
	stats.num_luts = LUTcount;
	return stats;
#endif
  
}

void simple_circuitt::print_stats(statst const &stats) {
	std::cout << "Gates: " << stats.num_gates <<" with " << stats.num_non_xor_gates << " Non-XOR and "
	          << stats.num_luts << " LUTs" << std::endl;
  
#ifdef PRINT_DEPTH
	std::cout << "Depth: " << stats.depth << " with " << stats.non_xor_depth << " Non-XOR" << std::endl;
#endif
}

void simple_circuitt::print_stats() {
  print_stats(query_stats());
}

/**
 * returns the other input of gate, where input0 is one of gate's inputs
 * only use with 2-input gates!
 */
simple_circuitt::gatet* simple_circuitt::get_other_input(gatet& gate, gatet* input0) {
	if (is_same_gate(gate.fanin0, input0))
		return gate.fanin1;
	else return gate.fanin0;
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
	this_gate->add_fanin(*fanin0, 0);
	this_gate->add_fanin(*fanin1, 1);
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
	this_gate->add_fanin(*fanin0, 0);
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
		if (gate->get_operation() == INPUT ||gate->get_operation() == OUTPUT || gate->get_operation() == ONE)
			return false;

		assert(gate->fanin0);
		assert(other_gate->fanin0);

		if (gate->get_operation() == NOT)
			return gate->fanin0 == other_gate->fanin0;

		else {
			assert(gate->fanin1);
			assert(other_gate->fanin1);

			if (gate->fanin0 == other_gate->fanin0 && gate->fanin1 == other_gate->fanin1)
				return true;

			if (gate->fanin0 == other_gate->fanin1 && gate->fanin1 == other_gate->fanin0)
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

	if (gate->get_operation() == NOT && gate->fanin0 == other_gate)
		return true;

	if (other_gate->get_operation() == NOT && other_gate->fanin0 == gate)
		return true;

	return false;
}

/**
 * checks if gate "gate" already has a NOT gate as fanout and returns it as not_gate if so
 */
bool simple_circuitt::has_NOT_fanout(gatet& gate, gatet*& not_gate) {
	for (gatet::fanoutst::iterator fanout_it = gate.fanouts.begin(); fanout_it != gate.fanouts.end(); ++fanout_it) {
		 gatet::fanoutt* fan_out = *fanout_it;
		 not_gate = fan_out->first;

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
        gatet* fanout_gate = fan_out->first;

		if (fan_out->first->get_operation() == op && 
            ((fanout_gate->fanin0 == fanin0 && fanout_gate->fanin1 == fanin1) ||
             (fanout_gate->fanin0 == fanin1 && fanout_gate->fanin1 == fanin0))) {
			this_gate = fan_out->first;
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

		if (fan_out->first->get_operation() == op) {
			if (fan_out->first->fanin0->get_operation() == NOT && fanin1 == fan_out->first->fanin0->fanin0) {

				this_gate = fan_out->first;
				return true;
			}
			if (fan_out->first->fanin0->get_operation() == NOT && fanin1 == fan_out->first->fanin0->fanin0) {

				this_gate = fan_out->first;
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
		return is_same_gate(searched_gate, act_gate->fanin0) || is_same_gate(searched_gate, act_gate->fanin1);
	return false;
}

/**
 * one of the old pattern but now with a new signature
 */
bool simple_circuitt::simplify15(gatet& gate, gatet*& fanin0_out) {
	if (gate.get_operation() == OR) {

		if (gate.fanin0->get_operation() == AND && gate.fanin0->fanouts.size() == 1 && gate.fanin1->get_operation() == NOT && gate.fanin1->fanouts.size() == 1 && gate.fanin1->fanin0->get_operation() == OR && gate.fanin1->fanin0->fanouts.size() == 1) {
			gatet* or_gate = gate.fanin1->fanin0;

			gatet* a_pin = gate.fanin0->fanin0;
			gatet* b_pin = gate.fanin0->fanin1;

			if ((a_pin == or_gate->fanin0 && b_pin == or_gate->fanin1) || (a_pin == or_gate->fanin1 && b_pin == or_gate->fanin0)) {
				fanin0_out = create_this_gate(a_pin, b_pin, XOR);
				return true;
			}
		}
		if (gate.fanin1->get_operation() == AND && gate.fanin1->fanouts.size() == 1 && gate.fanin0->get_operation() == NOT && gate.fanin0->fanouts.size() == 1 && gate.fanin0->fanin0->get_operation() == OR && gate.fanin0->fanin0->fanouts.size() == 1) {
			gatet* or_gate = gate.fanin0->fanin0;

			gatet* a_pin = gate.fanin1->fanin0;
			gatet* b_pin = gate.fanin1->fanin1;

			if ((a_pin == or_gate->fanin0 && b_pin == or_gate->fanin1) || (a_pin == or_gate->fanin1 && b_pin == or_gate->fanin0)) {
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
		if (gate.fanin0->get_operation() == NOT && gate.fanin0->fanouts.size() == 1) {

			fanin0_out = create_this_gate(gate.fanin0->fanin0, gate.fanin1, XOR);
			return true;
		}

		if (gate.fanin1->get_operation() == NOT && gate.fanin1->fanouts.size() == 1) {

			fanin0_out = create_this_gate(gate.fanin1->fanin0, gate.fanin0, XOR);
			return true;
		}
	}

	return false;
}
