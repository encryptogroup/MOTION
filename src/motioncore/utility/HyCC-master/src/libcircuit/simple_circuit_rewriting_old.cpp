/*
 * simple_circuit_rewriting.cpp
 *
 *  Created on: 05.10.2013
 *      Author: andreas
 */

#include "simple_circuit.h"

#include <stack>

bool simple_circuitt::rewrite_old(gatet* gate, bool round2) {

	bool changed_circuit = false;
	gatet* fanin0 = NULL;
	gatet* fanin1 = NULL;
	gatet* fanin2 = NULL;

	if (propagate_zero(*gate))
		changed_circuit = true;

	if (propagate_one(*gate))
		changed_circuit = true;

	if (simplify_trivial(*gate))
		changed_circuit = true;

	if (structural_hashing_NOT(*gate) || structural_hashing_AND(*gate) || structural_hashing_OR(*gate) || structural_hashing_XOR(*gate))
		changed_circuit = true;

	if (replace_by_zero(*gate) || replace_by_zero2(*gate)) {
		gate->replace_by(ZERO_GATE);

		changed_circuit = true;
	}

	if (can_be_easily_removed(*gate, fanin0) || can_be_less_easily_removed(*gate, fanin0) || can_be_easily_removed2(*gate, fanin0) || can_be_easily_removed3(*gate, fanin0) || can_be_easily_removed4(*gate, fanin0) || can_be_easily_removed5(*gate, fanin0) || can_be_easily_removed6(*gate, fanin0)) {
		assert(fanin0);

		gate->replace_by(fanin0);
		changed_circuit = true;
	}

	fanin0 = NULL;
	fanin1 = NULL;

	if (can_be_easily_replaced_by_or(*gate, fanin0, fanin1) || can_be_less_easily_replaced_by_or(*gate, fanin0, fanin1) || simplify13(*gate, fanin0, fanin1) || simplify12(*gate, fanin0, fanin1) || simplify7(*gate, fanin0, fanin1) || simplify3(*gate, fanin0, fanin1)) {
		assert(fanin0);
		assert(fanin1);

		// OR(fanin0, fanin1)

		gatet* or_gate = get_or_create_gate(OR);
		or_gate->add_fanin(primary_output(fanin0), 0);
		or_gate->add_fanin(primary_output(fanin1), 1);

		gate->replace_by(or_gate);

		changed_circuit = true;
	}

	fanin0 = NULL;
	fanin1 = NULL;

	if (can_be_easily_replaced_by_or_not(*gate, fanin0, fanin1) || simplify14(*gate, fanin0, fanin1) || simplify6(*gate, fanin0, fanin1)) {
		assert(fanin0);
		assert(fanin1);

		// OR(fanin0, NOT(fanin1))

		gatet* not_gate = get_or_create_gate(::simple_circuitt::NOT);
		not_gate->add_fanin(primary_output(fanin1), 0);

		gatet* or_gate = get_or_create_gate(OR);
		or_gate->add_fanin(primary_output(fanin0), 0);
		or_gate->add_fanin(primary_output(not_gate), 1);

		gate->replace_by(or_gate);

		changed_circuit = true;
	}

	fanin0 = NULL;
	fanin1 = NULL;

	if (can_be_easily_replaced_by_not_or(*gate, fanin0, fanin1)) {
		assert(fanin0);
		assert(fanin1);

		// NOT(OR(fanin0, fanin1))

		gatet* not_gate = get_or_create_gate(NOT);

		gatet* or_gate = get_or_create_gate(OR);

		not_gate->add_fanin(primary_output(or_gate), 0);

		or_gate->add_fanin(primary_output(fanin0), 0);
		or_gate->add_fanin(primary_output(fanin1), 1);

		gate->replace_by(not_gate);

		changed_circuit = true;
	}

	fanin0 = NULL;
	fanin1 = NULL;

	if (can_be_easily_replaced_by_xor(*gate, fanin0, fanin1) || can_be_less_easily_replaced_by_xor(*gate, fanin0, fanin1) || can_be_less_easily_replaced_by_xor2(*gate, fanin0, fanin1) || can_be_less_easily_replaced_by_xor3(*gate, fanin0, fanin1) || simplify16(*gate, fanin0, fanin1)) {
		assert(fanin0);
		assert(fanin1);

		gatet* xor_gate = get_or_create_gate(XOR);

		xor_gate->add_fanin(primary_output(fanin0), 0);
		xor_gate->add_fanin(primary_output(fanin1), 1);

		gate->replace_by(xor_gate);

		changed_circuit = true;
	}

	fanin0 = NULL;
	fanin1 = NULL;
	fanin2 = NULL;

	bool fanin_flag;

	if (can_be_simplified(*gate, fanin0, fanin1, fanin2, fanin_flag)) {
		// TODO now it shouldn't be dependent on the structure of the original cicuit anymore!!!
		assert(gate->get_operation() == OR); // This assertion is just a reminder that this rewriting is dependent on the structure of the original subcircuit

		gatet* or_gate = get_or_create_gate(OR);

		if (fanin_flag) {
			or_gate->add_fanin(primary_output(gate->get_fanin(0)), 0);
			or_gate->add_fanin(primary_output(fanin0), 1);
		}
		else {
			or_gate->add_fanin(primary_output(fanin0), 0);
			or_gate->add_fanin(primary_output(gate->get_fanin(1)), 1);
		}

		gate->replace_by(or_gate);

		changed_circuit = true;
	}

	fanin0 = NULL;
	fanin1 = NULL;
	fanin2 = NULL;

	if (can_be_less_easily_replaced_by_and(*gate, fanin0, fanin1) || simplify4(*gate, fanin0, fanin1) || simplify2(*gate, fanin0, fanin1) || simplify18(*gate, fanin0, fanin1)) {
		assert(fanin0);
		assert(fanin1);

		gatet* and_gate = get_or_create_gate(AND);

		and_gate->add_fanin(primary_output(fanin0), 0);
		and_gate->add_fanin(primary_output(fanin1), 1);

		gate->replace_by(and_gate);

		changed_circuit = true;
	}

	if (simplify(*gate) || simplify5(*gate) || simplify8(*gate) || simplify9(*gate) || simplify10(*gate) || simplify11(*gate)) {
		changed_circuit = true;
	}

	if (simplify15(*gate, fanin0) || simplify17(*gate, fanin0)) {

		// NOT(fanin0)
		gate->replace_by(create_this_NOT_gate(fanin0));

		changed_circuit = true;
	}

	return changed_circuit;
}
bool simple_circuitt::rewrite_no_state_machine(timeout_datat& data) {

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
		if (timeout(data)) {
			return false;
		}

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

		gatet* gate = *it;

		gatet* fanin0 = NULL;
		gatet* fanin1 = NULL;
		gatet* fanin2 = NULL;

		if (propagate_zero(*gate)) {
			changed_circuit = true;
			continue;
		}

		if (propagate_one(*gate)) {
			changed_circuit = true;
			continue;
		}

		if (simplify_trivial(*gate)) {
			changed_circuit = true;
			continue;
		}

		if (structural_hashing_NOT(*gate) || structural_hashing_AND(*gate) || structural_hashing_OR(*gate) || structural_hashing_XOR(*gate)) {
			changed_circuit = true;
			continue;
		}

		if (replace_by_zero(*gate) || replace_by_zero2(*gate)) {
			gate->replace_by(ZERO_GATE);

			changed_circuit = true;
			continue;
		}

		if (can_be_easily_removed(*gate, fanin0) || can_be_less_easily_removed(*gate, fanin0) || can_be_easily_removed2(*gate, fanin0) || can_be_easily_removed3(*gate, fanin0) || can_be_easily_removed4(*gate, fanin0) || can_be_easily_removed5(*gate, fanin0) || can_be_easily_removed6(*gate, fanin0)) {
			assert(fanin0);

			gate->replace_by(fanin0);

			changed_circuit = true;

			continue; // TODO remove the continues again!!!
		}

		fanin0 = NULL;
		fanin1 = NULL;

		if (can_be_easily_replaced_by_or(*gate, fanin0, fanin1) || can_be_less_easily_replaced_by_or(*gate, fanin0, fanin1) || simplify13(*gate, fanin0, fanin1) || simplify12(*gate, fanin0, fanin1) || simplify7(*gate, fanin0, fanin1) || simplify3(*gate, fanin0, fanin1)) {
			assert(fanin0);
			assert(fanin1);

			// OR(fanin0, fanin1)

			gatet* or_gate = get_or_create_gate(OR);
			or_gate->add_fanin(primary_output(fanin0), 0);
			or_gate->add_fanin(primary_output(fanin1), 1);

			gate->replace_by(or_gate);

			changed_circuit = true;

			continue; // TODO remove the continues again!!!
		}

		fanin0 = NULL;
		fanin1 = NULL;

		if (can_be_easily_replaced_by_or_not(*gate, fanin0, fanin1) || simplify14(*gate, fanin0, fanin1) || simplify6(*gate, fanin0, fanin1)) {
			assert(fanin0);
			assert(fanin1);

			// OR(fanin0, NOT(fanin1))

			gatet* not_gate = get_or_create_gate(::simple_circuitt::NOT);
			not_gate->add_fanin(primary_output(fanin1), 0);

			gatet* or_gate = get_or_create_gate(OR);
			or_gate->add_fanin(primary_output(fanin0), 0);
			or_gate->add_fanin(primary_output(not_gate), 1);

			gate->replace_by(or_gate);

			changed_circuit = true;

			continue; // TODO remove the continues again!!!
		}

		fanin0 = NULL;
		fanin1 = NULL;

		if (can_be_easily_replaced_by_not_or(*gate, fanin0, fanin1)) {
			assert(fanin0);
			assert(fanin1);

			// NOT(OR(fanin0, fanin1))

			gatet* not_gate = get_or_create_gate(NOT);

			gatet* or_gate = get_or_create_gate(OR);

			not_gate->add_fanin(primary_output(or_gate), 0);

			or_gate->add_fanin(primary_output(fanin0), 0);
			or_gate->add_fanin(primary_output(fanin1), 1);

			gate->replace_by(not_gate);

			changed_circuit = true;

			continue; // TODO remove the continues again!!!
		}

		fanin0 = NULL;
		fanin1 = NULL;

		if (can_be_easily_replaced_by_xor(*gate, fanin0, fanin1) || can_be_less_easily_replaced_by_xor(*gate, fanin0, fanin1) || can_be_less_easily_replaced_by_xor2(*gate, fanin0, fanin1) || can_be_less_easily_replaced_by_xor3(*gate, fanin0, fanin1) || simplify16(*gate, fanin0, fanin1)) {
			assert(fanin0);
			assert(fanin1);

			gatet* xor_gate = get_or_create_gate(XOR);

			xor_gate->add_fanin(primary_output(fanin0), 0);
			xor_gate->add_fanin(primary_output(fanin1), 1);

			gate->replace_by(xor_gate);

			changed_circuit = true;

			continue;
		}

		fanin0 = NULL;
		fanin1 = NULL;
		fanin2 = NULL;

		bool fanin_flag;

		if (can_be_simplified(*gate, fanin0, fanin1, fanin2, fanin_flag)) {
			// TODO now it shouldn't be dependent on the structure of the original cicuit anymore!!!
			assert(gate->get_operation() == OR); // This assertion is just a reminder that this rewriting is dependent on the structure of the original subcircuit

			gatet* or_gate = get_or_create_gate(OR);

			if (fanin_flag) {
				or_gate->add_fanin(primary_output(gate->get_fanin(0)), 0);
				or_gate->add_fanin(primary_output(fanin0), 1);
			}
			else {
				or_gate->add_fanin(primary_output(fanin0), 0);
				or_gate->add_fanin(primary_output(gate->get_fanin(1)), 1);
			}

			gate->replace_by(or_gate);

			changed_circuit = true;

			continue; // TODO remove the continues again!!!
		}

		fanin0 = NULL;
		fanin1 = NULL;
		fanin2 = NULL;

		if (can_be_less_easily_replaced_by_and(*gate, fanin0, fanin1) || simplify4(*gate, fanin0, fanin1) || simplify2(*gate, fanin0, fanin1) || simplify18(*gate, fanin0, fanin1)) {
			assert(fanin0);
			assert(fanin1);

			gatet* and_gate = get_or_create_gate(AND);

			and_gate->add_fanin(primary_output(fanin0), 0);
			and_gate->add_fanin(primary_output(fanin1), 1);

			gate->replace_by(and_gate);

			changed_circuit = true;

			continue; // TODO remove the continues again!!!
		}

		if (simplify(*gate) || simplify5(*gate) || simplify8(*gate) || simplify9(*gate) || simplify10(*gate) || simplify11(*gate)) {
			changed_circuit = true;
			continue;
		}

		if (simplify15(*gate, fanin0, fanin1) || simplify17(*gate, fanin0, fanin1)) {
			assert(fanin0);
			assert(fanin1);

			// NOT(XOR(fanin0, fanin1))

			gatet* xor_gate = get_or_create_gate(XOR);
			gatet* new_not_gate = get_or_create_gate(NOT);

			xor_gate->add_fanin(primary_output(fanin0), 0);
			xor_gate->add_fanin(primary_output(fanin1), 1);

			new_not_gate->add_fanin(primary_output(xor_gate), 0);

			gate->replace_by(new_not_gate);

			changed_circuit = true;
			continue;
		}
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

bool simple_circuitt::can_be_easily_replaced_by_or(simple_circuitt::gatet& gate, simple_circuitt::gatet*& fanin0_out, simple_circuitt::gatet*& fanin1_out) {
	// NOT(AND(NOT(x), NOT(y))) with restrictions

	if (gate.get_operation() == simple_circuitt::NOT) {

		assert(!gate.get_fanin(1));

		simple_circuitt::gatet* fanin0 = gate.get_fanin(0);

		if (fanin0->get_operation() == simple_circuitt::AND && fanin0->fanouts.size() == 1) {

			if (fanin0->get_fanin(0)->get_operation() == simple_circuitt::NOT && fanin0->get_fanin(1)->get_operation() == simple_circuitt::NOT && fanin0->get_fanin(0)->fanouts.size() == 1 && fanin0->get_fanin(1)->fanouts.size() == 1) {

				fanin0_out = fanin0->get_fanin(0)->get_fanin(0);
				fanin1_out = fanin0->get_fanin(1)->get_fanin(0);

				return true;
			}
		}
	}

	return false;
}

bool simple_circuitt::can_be_less_easily_replaced_by_or(simple_circuitt::gatet& gate, simple_circuitt::gatet*& fanin0_out, simple_circuitt::gatet*& fanin1_out) {
	// NOT(AND(NOT(x), NOT(y))) with lesser restrictions

	if (gate.get_operation() == simple_circuitt::NOT) {
		simple_circuitt::gatet* fanin0 = gate.get_fanin(0);

		if (fanin0->get_operation() == simple_circuitt::AND && fanin0->fanouts.size() == 1) {

			if (fanin0->get_fanin(0)->get_operation() == simple_circuitt::NOT && fanin0->get_fanin(1)->get_operation() == simple_circuitt::NOT) {

				fanin0_out = fanin0->get_fanin(0)->get_fanin(0);
				fanin1_out = fanin0->get_fanin(1)->get_fanin(0);

				return true;
			}
		}
	}

	return false;
}

bool simple_circuitt::can_be_easily_replaced_by_not_or(simple_circuitt::gatet& gate, simple_circuitt::gatet*& fanin0_out, simple_circuitt::gatet*& fanin1_out) {
	// AND(NOT(x), NOT(y)) with restrictions

	if (gate.get_operation() == simple_circuitt::AND) {

		simple_circuitt::gatet* fanin0 = gate.get_fanin(0);
		simple_circuitt::gatet* fanin1 = gate.get_fanin(1);

		if ((fanin0->get_operation() == simple_circuitt::NOT) && (fanin0->fanouts.size() == 1) && (fanin1->get_operation() == simple_circuitt::NOT) && (fanin1->fanouts.size() == 1)) {

			assert(!fanin0->get_fanin(1));
			assert(!fanin1->get_fanin(1));

			fanin0_out = fanin0->get_fanin(0);
			fanin1_out = fanin1->get_fanin(0);

			return true;
		}

	}

	return false;
}

bool simple_circuitt::can_be_easily_replaced_by_or_not(simple_circuitt::gatet& gate, simple_circuitt::gatet*& fanin0_out, simple_circuitt::gatet*& fanin1_out) {
	// NOT(AND(NOT(x), y)) and NOT(AND(x, NOT(y)))

	if (gate.get_operation() == simple_circuitt::NOT) {

		simple_circuitt::gatet* fanin0 = gate.get_fanin(0);

		if ((fanin0->get_operation() == simple_circuitt::AND) && (fanin0->fanouts.size() == 1)) {
			if (fanin0->get_fanin(0)->get_operation() == simple_circuitt::NOT && fanin0->get_fanin(0)->fanouts.size() == 1) {
				fanin0_out = fanin0->get_fanin(0)->get_fanin(0);
				fanin1_out = fanin0->get_fanin(1);

				return true;
			}
			else if (fanin0->get_fanin(1)->get_operation() == simple_circuitt::NOT && fanin0->get_fanin(1)->fanouts.size() == 1) {
				fanin0_out = fanin0->get_fanin(1)->get_fanin(0);
				fanin1_out = fanin0->get_fanin(0);

				return true;
			}
		}
	}

	return false;
}

bool simple_circuitt::can_be_easily_removed(simple_circuitt::gatet& gate, simple_circuitt::gatet*& fanin0_out) {
	// NOT(NOT(x)) ... why do we need this method given the existence of can_be_less_easily_removed

	if (gate.get_operation() == simple_circuitt::NOT) {

		simple_circuitt::gatet* fanin0 = gate.get_fanin(0);

		if ((fanin0->get_operation() == simple_circuitt::NOT) && (fanin0->fanouts.size() == 1)) {

			fanin0_out = fanin0->get_fanin(0);

			return true;
		}

	}

	return false;
}

bool simple_circuitt::can_be_less_easily_removed(simple_circuitt::gatet& gate, simple_circuitt::gatet*& fanin0_out) {
	// NOT(NOT(x))

	if (gate.get_operation() == simple_circuitt::NOT) {

		simple_circuitt::gatet* fanin0 = gate.get_fanin(0);

		if (fanin0->get_operation() == simple_circuitt::NOT) {

			fanin0_out = fanin0->get_fanin(0);

			return true;
		}

	}

	return false;
}

bool simple_circuitt::can_be_easily_removed2(gatet& gate, gatet*& fanin0_out) {
	// a = AND(b, c) ... OR(AND(x, a) , a)

	if (gate.get_operation() == simple_circuitt::OR) {
		if (gate.get_fanin(0)->get_operation() == simple_circuitt::AND && gate.get_fanin(1)->get_operation() == simple_circuitt::AND) {

			if (gate.get_fanin(0)->get_fanin(0) == gate.get_fanin(1) || gate.get_fanin(0)->get_fanin(1) == gate.get_fanin(1)) {

				fanin0_out = gate.get_fanin(1);

				return true;
			}

			if (gate.get_fanin(1)->get_fanin(0) == gate.get_fanin(0) || gate.get_fanin(1)->get_fanin(1) == gate.get_fanin(0)) {

				fanin0_out = gate.get_fanin(0);

				return true;
			}

		}
	}

	return false;
}

bool simple_circuitt::matches(simple_circuitt::gatet* gate, simple_circuitt::gatet* a, simple_circuitt::gatet* b) {
	assert(gate->get_operation() == simple_circuitt::AND && gate->fanouts.size() == 1);

	if (gate->get_fanin(0)->get_operation() == simple_circuitt::NOT) {
		if (a == gate->get_fanin(1) && b == gate->get_fanin(0)->get_fanin(0)) {
			return true;
		}
	}

	if (gate->get_fanin(1)->get_operation() == simple_circuitt::NOT) {
		if (a == gate->get_fanin(0) && b == gate->get_fanin(1)->get_fanin(0)) {
			return true;
		}
	}

	return false;
}

bool simple_circuitt::can_be_easily_replaced_by_xor(simple_circuitt::gatet& gate, simple_circuitt::gatet*& fanin0_out, simple_circuitt::gatet*& fanin1_out) {
	// OR(AND(?) , AND(?))
    
    if(gate.get_fanin(0) == gate.get_fanin(1))
      return false;

	if (gate.get_operation() == simple_circuitt::OR) {

		assert(gate.get_fanin(0) != gate.get_fanin(1));

		simple_circuitt::gatet* fanin0 = gate.get_fanin(0);
		simple_circuitt::gatet* fanin1 = gate.get_fanin(1);

		if ((fanin0->get_operation() == simple_circuitt::AND) && (fanin0->fanouts.size() == 1) && (fanin1->get_operation() == simple_circuitt::AND) && (fanin1->fanouts.size() == 1)) {

			if (fanin0->get_fanin(0)->get_operation() == simple_circuitt::NOT) {
				simple_circuitt::gatet* a = fanin0->get_fanin(0)->get_fanin(0);
				simple_circuitt::gatet* b = fanin0->get_fanin(1);

				if (matches(fanin1, a, b)) {
					fanin0_out = a;
					fanin1_out = b;

					return true;
				}
			}

			if (fanin0->get_fanin(1)->get_operation() == simple_circuitt::NOT) {
				simple_circuitt::gatet* a = fanin0->get_fanin(1)->get_fanin(0);
				simple_circuitt::gatet* b = fanin0->get_fanin(0);

				if (matches(fanin1, a, b)) {
					fanin0_out = a;
					fanin1_out = b;

					return true;
				}
			}
		}
	}

	return false;
}

bool simple_circuitt::can_be_less_easily_replaced_by_xor(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	if (gate.get_operation() == simple_circuitt::OR) {
		if (gate.get_fanin(0)->get_operation() == simple_circuitt::NOT && gate.get_fanin(0)->fanouts.size() == 1 && gate.get_fanin(1)->get_operation() == simple_circuitt::AND && gate.get_fanin(1)->fanouts.size() == 1) {
			if (gate.get_fanin(0)->get_fanin(0)->get_operation() == simple_circuitt::OR/* && gate.get_fanin(0)->get_fanin(0)->fanouts.size() == 1*/) {
				if (gate.get_fanin(0)->get_fanin(0)->get_fanin(0) == gate.get_fanin(1)->get_fanin(0)) {
					if (gate.get_fanin(0)->get_fanin(0)->get_fanin(1) == gate.get_fanin(1)->get_fanin(1)) {
						if (gate.get_fanin(0)->get_fanin(0)->get_fanin(0)->get_operation() == simple_circuitt::NOT) {
							fanin0_out = gate.get_fanin(0)->get_fanin(0)->get_fanin(1);
							fanin1_out = gate.get_fanin(0)->get_fanin(0)->get_fanin(0)->get_fanin(0);

							return true;
						}
						else if (gate.get_fanin(0)->get_fanin(0)->get_fanin(1)->get_operation() == simple_circuitt::NOT) {
							fanin0_out = gate.get_fanin(0)->get_fanin(0)->get_fanin(0);
							fanin1_out = gate.get_fanin(0)->get_fanin(0)->get_fanin(1)->get_fanin(0);

							return true;
						}
					}
				}
				else if (gate.get_fanin(0)->get_fanin(0)->get_fanin(0) == gate.get_fanin(1)->get_fanin(1)) {
					if (gate.get_fanin(0)->get_fanin(0)->get_fanin(1) == gate.get_fanin(1)->get_fanin(0)) {
						if (gate.get_fanin(0)->get_fanin(0)->get_fanin(0)->get_operation() == simple_circuitt::NOT) {
							fanin0_out = gate.get_fanin(0)->get_fanin(0)->get_fanin(1);
							fanin1_out = gate.get_fanin(0)->get_fanin(0)->get_fanin(0)->get_fanin(0);

							return true;
						}
						else if (gate.get_fanin(0)->get_fanin(0)->get_fanin(1)->get_operation() == simple_circuitt::NOT) {
							fanin0_out = gate.get_fanin(0)->get_fanin(0)->get_fanin(0);
							fanin1_out = gate.get_fanin(0)->get_fanin(0)->get_fanin(1)->get_fanin(0);

							return true;
						}
					}
				}
			}
		}
		else if (gate.get_fanin(1)->get_operation() == ::simple_circuitt::NOT && gate.get_fanin(1)->fanouts.size() == 1 && gate.get_fanin(0)->get_operation() == ::simple_circuitt::AND && gate.get_fanin(0)->fanouts.size() == 1) {
			if (gate.get_fanin(1)->get_fanin(0)->get_operation() == ::simple_circuitt::OR/* && gate.get_fanin(1)->get_fanin(0)->fanouts.size() == 1*/) {


				if (gate.get_fanin(1)->get_fanin(0)->get_fanin(0) == gate.get_fanin(0)->get_fanin(0)) {
					if (gate.get_fanin(1)->get_fanin(0)->get_fanin(1) == gate.get_fanin(0)->get_fanin(1)) {
						if (gate.get_fanin(1)->get_fanin(0)->get_fanin(0)->get_operation() == simple_circuitt::NOT) {
							fanin0_out = gate.get_fanin(1)->get_fanin(0)->get_fanin(1);
							fanin1_out = gate.get_fanin(1)->get_fanin(0)->get_fanin(0)->get_fanin(0);

							return true;
						}
						else if (gate.get_fanin(1)->get_fanin(0)->get_fanin(1)->get_operation() == simple_circuitt::NOT) {
							fanin0_out = gate.get_fanin(1)->get_fanin(0)->get_fanin(0);
							fanin1_out = gate.get_fanin(1)->get_fanin(0)->get_fanin(1)->get_fanin(0);

							return true;
						}
					}
				}
				else if (gate.get_fanin(1)->get_fanin(0)->get_fanin(0) == gate.get_fanin(0)->get_fanin(1)) {
					if (gate.get_fanin(1)->get_fanin(0)->get_fanin(1) == gate.get_fanin(0)->get_fanin(0)) {
						if (gate.get_fanin(1)->get_fanin(0)->get_fanin(0)->get_operation() == simple_circuitt::NOT) {
							fanin0_out = gate.get_fanin(1)->get_fanin(0)->get_fanin(1);
							fanin1_out = gate.get_fanin(1)->get_fanin(0)->get_fanin(0)->get_fanin(0);

							return true;
						}
						else if (gate.get_fanin(1)->get_fanin(0)->get_fanin(1)->get_operation() == simple_circuitt::NOT) {
							fanin0_out = gate.get_fanin(1)->get_fanin(0)->get_fanin(0);
							fanin1_out = gate.get_fanin(1)->get_fanin(0)->get_fanin(1)->get_fanin(0);

							return true;
						}
					}
				}



			}
		}
	}

	return false;
}

bool simple_circuitt::can_be_less_easily_replaced_by_xor2(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	if (gate.get_operation() == simple_circuitt::AND) {
		if (gate.get_fanin(0)->get_operation() == simple_circuitt::NOT && gate.get_fanin(0)->fanouts.size() == 1 && gate.get_fanin(1)->get_operation() == simple_circuitt::OR && gate.get_fanin(1)->fanouts.size() == 1) {
			if (gate.get_fanin(0)->get_fanin(0)->get_operation() == simple_circuitt::AND/* && gate.get_fanin(0)->get_fanin(0)->fanouts.size() == 1*/) {
				if (gate.get_fanin(0)->get_fanin(0)->get_fanin(0) == gate.get_fanin(1)->get_fanin(0)) {
					if (gate.get_fanin(0)->get_fanin(0)->get_fanin(1) == gate.get_fanin(1)->get_fanin(1)) {

						fanin0_out = gate.get_fanin(1)->get_fanin(0);
						fanin1_out = gate.get_fanin(1)->get_fanin(1);

						return true;

					}
				}
				else if (gate.get_fanin(0)->get_fanin(0)->get_fanin(0) == gate.get_fanin(1)->get_fanin(1)) {
					if (gate.get_fanin(0)->get_fanin(0)->get_fanin(1) == gate.get_fanin(1)->get_fanin(0)) {

						fanin0_out = gate.get_fanin(1)->get_fanin(1);
						fanin1_out = gate.get_fanin(1)->get_fanin(0);

						return true;

					}
				}
			}
		}
		else if (gate.get_fanin(1)->get_operation() == ::simple_circuitt::NOT && gate.get_fanin(1)->fanouts.size() == 1 && gate.get_fanin(0)->get_operation() == ::simple_circuitt::OR && gate.get_fanin(0)->fanouts.size() == 1) {
			if (gate.get_fanin(1)->get_fanin(0)->get_operation() == ::simple_circuitt::AND/* && gate.get_fanin(1)->get_fanin(0)->fanouts.size() == 1*/) {
				if (gate.get_fanin(1)->get_fanin(0)->get_fanin(0) == gate.get_fanin(0)->get_fanin(0)) {
					if (gate.get_fanin(1)->get_fanin(0)->get_fanin(1) == gate.get_fanin(0)->get_fanin(1)) {

						fanin0_out = gate.get_fanin(0)->get_fanin(0);
						fanin1_out = gate.get_fanin(0)->get_fanin(1);

						return true;

					}
				}
				else if (gate.get_fanin(1)->get_fanin(0)->get_fanin(0) == gate.get_fanin(0)->get_fanin(1)) {
					if (gate.get_fanin(1)->get_fanin(0)->get_fanin(1) == gate.get_fanin(0)->get_fanin(0)) {

						fanin0_out = gate.get_fanin(0)->get_fanin(1);
						fanin1_out = gate.get_fanin(0)->get_fanin(0);

						return true;

					}
				}
			}
		}
	}

	return false;
}

bool simple_circuitt::can_be_less_easily_replaced_by_xor3(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	if (gate.get_operation() == simple_circuitt::XOR) {
		if (gate.get_fanin(0)->get_operation() == simple_circuitt::NOT && gate.get_fanin(1)->get_operation() == simple_circuitt::NOT) {
			fanin0_out = gate.get_fanin(0)->get_fanin(0);
			fanin1_out = gate.get_fanin(1)->get_fanin(0);

			return true;
		}
	}

	return false;
}

bool simple_circuitt::can_be_simplified(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out, gatet*& fanin2_out, bool& fanin_flag) {
	if (gate.get_operation() == simple_circuitt::OR) {
		if (gate.get_fanin(0)->get_operation() == simple_circuitt::AND && gate.get_fanin(1)->get_operation() == simple_circuitt::AND) {

			if (gate.get_fanin(0)->get_fanin(0)->get_operation() == simple_circuitt::NOT) {
				if (gate.get_fanin(0)->get_fanin(0)->get_fanin(0) == gate.get_fanin(1)) {
					fanin0_out = gate.get_fanin(0)->get_fanin(1);
					fanin1_out = gate.get_fanin(1)->get_fanin(0);
					fanin2_out = gate.get_fanin(1)->get_fanin(1);

					fanin_flag = false;

					return true;
				}
			}

			if (gate.get_fanin(0)->get_fanin(1)->get_operation() == simple_circuitt::NOT) {
				if (gate.get_fanin(0)->get_fanin(1)->get_fanin(0) == gate.get_fanin(1)) {
					fanin0_out = gate.get_fanin(0)->get_fanin(0);
					fanin1_out = gate.get_fanin(1)->get_fanin(0);
					fanin2_out = gate.get_fanin(1)->get_fanin(1);

					fanin_flag = false;

					return true;
				}
			}

			if (gate.get_fanin(1)->get_fanin(0)->get_operation() == simple_circuitt::NOT) {
				if (gate.get_fanin(1)->get_fanin(0)->get_fanin(0) == gate.get_fanin(0)) {
					fanin0_out = gate.get_fanin(1)->get_fanin(1);
					fanin1_out = gate.get_fanin(0)->get_fanin(0);
					fanin2_out = gate.get_fanin(0)->get_fanin(1);

					fanin_flag = true;

					return true;
				}
			}

			if (gate.get_fanin(1)->get_fanin(1)->get_operation() == simple_circuitt::NOT) {
				if (gate.get_fanin(1)->get_fanin(1)->get_fanin(0) == gate.get_fanin(0)) {
					fanin0_out = gate.get_fanin(1)->get_fanin(0);
					fanin1_out = gate.get_fanin(0)->get_fanin(0);
					fanin2_out = gate.get_fanin(0)->get_fanin(1);

					fanin_flag = true;

					return true;
				}
			}

		}
	}

	return false;
}

bool simple_circuitt::can_be_less_easily_replaced_by_and(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	// (a XOR (a AND (a XOR b))) == a AND b

	if (gate.get_operation() == simple_circuitt::XOR) {
		if (gate.get_fanin(0)->get_operation() == simple_circuitt::AND && gate.get_fanin(0)->fanouts.size() == 1) {
			if (gate.get_fanin(0)->get_fanin(0)->get_operation() == simple_circuitt::XOR) {

				if (gate.get_fanin(1) == gate.get_fanin(0)->get_fanin(1)) {
					if (gate.get_fanin(1) == gate.get_fanin(0)->get_fanin(0)->get_fanin(0) || gate.get_fanin(1) == gate.get_fanin(0)->get_fanin(0)->get_fanin(1)) {

						fanin0_out = gate.get_fanin(0)->get_fanin(0)->get_fanin(0);
						fanin1_out = gate.get_fanin(0)->get_fanin(0)->get_fanin(1);

						return true;
					}
				}

			}

			if (gate.get_fanin(0)->get_fanin(1)->get_operation() == simple_circuitt::XOR) {

				if (gate.get_fanin(1) == gate.get_fanin(0)->get_fanin(0)) {
					if (gate.get_fanin(1) == gate.get_fanin(0)->get_fanin(1)->get_fanin(0) || gate.get_fanin(1) == gate.get_fanin(0)->get_fanin(1)->get_fanin(1)) {

						fanin0_out = gate.get_fanin(0)->get_fanin(1)->get_fanin(0);
						fanin1_out = gate.get_fanin(0)->get_fanin(1)->get_fanin(1);

						return true;
					}
				}

			}
		}

		if (gate.get_fanin(1)->get_operation() == simple_circuitt::AND && gate.get_fanin(1)->fanouts.size() == 1) {
			if (gate.get_fanin(1)->get_fanin(0)->get_operation() == simple_circuitt::XOR) {

				if (gate.get_fanin(0) == gate.get_fanin(1)->get_fanin(1)) {
					if (gate.get_fanin(0) == gate.get_fanin(1)->get_fanin(0)->get_fanin(0) || gate.get_fanin(0) == gate.get_fanin(1)->get_fanin(0)->get_fanin(1)) {

						fanin0_out = gate.get_fanin(1)->get_fanin(0)->get_fanin(0);
						fanin1_out = gate.get_fanin(1)->get_fanin(0)->get_fanin(1);

						return true;
					}
				}

			}

			if (gate.get_fanin(1)->get_fanin(1)->get_operation() == simple_circuitt::XOR) {

				if (gate.get_fanin(0) == gate.get_fanin(1)->get_fanin(0)) {
					if (gate.get_fanin(0) == gate.get_fanin(1)->get_fanin(1)->get_fanin(0) || gate.get_fanin(0) == gate.get_fanin(1)->get_fanin(1)->get_fanin(1)) {

						fanin0_out = gate.get_fanin(1)->get_fanin(1)->get_fanin(0);
						fanin1_out = gate.get_fanin(1)->get_fanin(1)->get_fanin(1);

						return true;
					}
				}

			}
		}
	}

	return false;
}

bool simple_circuitt::can_be_easily_removed3(gatet& gate, gatet*& fanin0_out) {
	if (gate.get_operation() == AND) {

		if (gate.get_fanin(0)->get_operation() == NOT) {
			if (gate.get_fanin(0)->get_fanin(0)->get_operation() == AND) {
				if (gate.get_fanin(1)->get_operation() == AND) {
					if (gate.get_fanin(1)->get_fanin(0)->get_operation() == NOT) {
						// d == gate.get_fanin(1)->get_fanin(1)
						if (gate.get_fanin(1)->get_fanin(0)->get_fanin(0)->get_operation() == AND) {
							if (gate.get_fanin(0)->get_fanin(0)->get_fanin(0) == gate.get_fanin(1)->get_fanin(0)->get_fanin(0) || gate.get_fanin(0)->get_fanin(0)->get_fanin(1) == gate.get_fanin(1)->get_fanin(0)->get_fanin(0)) {

								fanin0_out = gate.get_fanin(1);

								return true;
							}
						}
					}

					if (gate.get_fanin(1)->get_fanin(1)->get_operation() == NOT) {
						// d == gate.get_fanin(1)->get_fanin(0)
						if (gate.get_fanin(1)->get_fanin(1)->get_fanin(0)->get_operation() == AND) {
							if (gate.get_fanin(0)->get_fanin(0)->get_fanin(0) == gate.get_fanin(1)->get_fanin(1)->get_fanin(0) || gate.get_fanin(0)->get_fanin(0)->get_fanin(1) == gate.get_fanin(1)->get_fanin(1)->get_fanin(0)) {

								fanin0_out = gate.get_fanin(1);

								return true;
							}
						}
					}
				}
			}
		}

		if (gate.get_fanin(1)->get_operation() == NOT) {
			if (gate.get_fanin(1)->get_fanin(0)->get_operation() == AND) {
				if (gate.get_fanin(0)->get_operation() == AND) {
					if (gate.get_fanin(0)->get_fanin(0)->get_operation() == NOT) {
						// d == gate.get_fanin(0)->get_fanin(1)
						if (gate.get_fanin(0)->get_fanin(0)->get_fanin(0)->get_operation() == AND) {
							if (gate.get_fanin(1)->get_fanin(0)->get_fanin(0) == gate.get_fanin(0)->get_fanin(0)->get_fanin(0) || gate.get_fanin(1)->get_fanin(0)->get_fanin(1) == gate.get_fanin(0)->get_fanin(0)->get_fanin(0)) {

								fanin0_out = gate.get_fanin(0);

								return true;
							}
						}
					}

					if (gate.get_fanin(0)->get_fanin(1)->get_operation() == NOT) {
						// d == gate.get_fanin(0)->get_fanin(0)
						if (gate.get_fanin(0)->get_fanin(1)->get_fanin(0)->get_operation() == AND) {
							if (gate.get_fanin(1)->get_fanin(0)->get_fanin(0) == gate.get_fanin(0)->get_fanin(1)->get_fanin(0) || gate.get_fanin(1)->get_fanin(0)->get_fanin(1) == gate.get_fanin(0)->get_fanin(1)->get_fanin(0)) {

								fanin0_out = gate.get_fanin(0);

								return true;
							}
						}
					}
				}
			}
		}

	}

	return false;
}

bool simple_circuitt::can_be_simplified2(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out, gatet*& fanin2_out, bool& fanin_flag) {
	if (gate.get_operation() == XOR) {
		if (gate.get_fanin(0)->get_operation() == AND && gate.get_fanin(1)->get_operation() == AND) {
			if (gate.get_fanin(0)->get_fanin(0) == gate.get_fanin(1) && gate.get_fanin(0)->fanouts.size() == 1) {
				fanin0_out = gate.get_fanin(1)->get_fanin(0);
				fanin1_out = gate.get_fanin(1)->get_fanin(1);
				fanin2_out = gate.get_fanin(0)->get_fanin(1);

				fanin_flag = false;

				return true;
			}

			if (gate.get_fanin(0)->get_fanin(1) == gate.get_fanin(1) && gate.get_fanin(0)->fanouts.size() == 1) {
				fanin0_out = gate.get_fanin(1)->get_fanin(0);
				fanin1_out = gate.get_fanin(1)->get_fanin(1);
				fanin2_out = gate.get_fanin(0)->get_fanin(0);

				fanin_flag = false;

				return true;
			}

			if (gate.get_fanin(1)->get_fanin(0) == gate.get_fanin(0) && gate.get_fanin(1)->fanouts.size() == 1) {
				fanin0_out = gate.get_fanin(0)->get_fanin(0);
				fanin1_out = gate.get_fanin(0)->get_fanin(1);
				fanin2_out = gate.get_fanin(1)->get_fanin(1);

				fanin_flag = true;

				return true;
			}

			if (gate.get_fanin(1)->get_fanin(1) == gate.get_fanin(0) && gate.get_fanin(1)->fanouts.size() == 1) {
				fanin0_out = gate.get_fanin(0)->get_fanin(0);
				fanin1_out = gate.get_fanin(0)->get_fanin(1);
				fanin2_out = gate.get_fanin(1)->get_fanin(0);

				fanin_flag = true;

				return true;
			}
		}
	}

	return false;
}

bool simple_circuitt::can_be_easily_removed4(gatet& gate, gatet*& fanin0_out) {
	if (gate.get_operation() == AND) {
		if (gate.get_fanin(0)->get_operation() == OR) {
			if (gate.get_fanin(0)->get_fanin(0) == gate.get_fanin(1) || gate.get_fanin(0)->get_fanin(1) == gate.get_fanin(1)) {
				fanin0_out = gate.get_fanin(1);

				return true;
			}
		}

		if (gate.get_fanin(1)->get_operation() == OR) {
			if (gate.get_fanin(1)->get_fanin(0) == gate.get_fanin(0) || gate.get_fanin(1)->get_fanin(1) == gate.get_fanin(0)) {
				fanin0_out = gate.get_fanin(0);

				return true;
			}
		}
	}

	return false;
}

bool simple_circuitt::detect_or_not_not(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	if (gate.get_operation() == OR) {
		if (gate.get_fanin(0)->get_operation() == NOT && gate.get_fanin(0)->fanouts.size() == 1 && gate.get_fanin(1)->get_operation() == NOT && gate.get_fanin(1)->fanouts.size() == 1) {
			fanin0_out = gate.get_fanin(0)->get_fanin(0);
			fanin1_out = gate.get_fanin(1)->get_fanin(0);

			return true;
		}
	}

	return false;
}

bool simple_circuitt::can_be_easily_removed5(gatet& gate, gatet*& fanin0_out) {
	if (gate.get_operation() == AND) {
		if (gate.get_fanin(0)->get_operation() == AND) {
			if (gate.get_fanin(0)->get_fanin(0) == gate.get_fanin(1) || gate.get_fanin(0)->get_fanin(1) == gate.get_fanin(1)) {
				fanin0_out = gate.get_fanin(0);

				return true;
			}
		}

		if (gate.get_fanin(1)->get_operation() == AND) {
			if (gate.get_fanin(1)->get_fanin(0) == gate.get_fanin(0) || gate.get_fanin(1)->get_fanin(1) == gate.get_fanin(0)) {
				fanin0_out = gate.get_fanin(1);

				return true;
			}
		}
	}

	return false;
}

bool simple_circuitt::simplify(gatet& gate) {
	if (gate.get_operation() == XOR) {
		if (gate.get_fanin(0)->get_operation() == AND && gate.get_fanin(1)->get_operation() == AND) {
			gatet* fanin0 = gate.get_fanin(0);
			gatet* fanin1 = gate.get_fanin(1);

			if (fanin1->fanouts.size() == 1) {
				if (fanin0 == fanin1->get_fanin(0)) {
					if (fanin1->get_fanin(1)->get_operation() == NOT/* && fanin1->get_fanin(1)->fanouts.size() == 1*/) {
						// we keep fanin0
						// we change gate into an AND gate
						// we connect fanin1->get_fanin(1)->get_fanin(0) to gate

						gatet* and_gate = get_or_create_gate(AND);
						and_gate->add_fanin(primary_output(gate.get_fanin(0)), 0);
						and_gate->add_fanin(primary_output(fanin1->get_fanin(1)->get_fanin(0)), 1);

						gate.replace_by(and_gate);

						return true;
					}
				}

				if (fanin0 == fanin1->get_fanin(1)) {
					if (fanin1->get_fanin(0)->get_operation() == NOT/* && fanin1->get_fanin(0)->fanouts.size() == 1*/) {
						// we keep fanin0
						// we change gate into an AND gate
						// we connect fanin1->get_fanin(0)->get_fanin(0) to gate

						gatet* and_gate = get_or_create_gate(AND);
						and_gate->add_fanin(primary_output(gate.get_fanin(0)), 0);
						and_gate->add_fanin(primary_output(fanin1->get_fanin(0)->get_fanin(0)), 1);

						gate.replace_by(and_gate);

						return true;
					}
				}
			}

			if (fanin0->fanouts.size() == 1) {
				if (fanin1 == fanin0->get_fanin(0)) {
					if (fanin0->get_fanin(1)->get_operation() == NOT/* && fanin0->get_fanin(1)->fanouts.size() == 1*/) {
						// we keep fanin1
						// we change gate into an AND gate
						// we connect fanin0->get_fanin(1)->get_fanin(0) to gate

						gatet* and_gate = get_or_create_gate(AND);
						and_gate->add_fanin(primary_output(fanin0->get_fanin(1)->get_fanin(0)), 0);
						and_gate->add_fanin(primary_output(gate.get_fanin(1)), 1);

						gate.replace_by(and_gate);

						return true;
					}
				}

				if (fanin1 == fanin0->get_fanin(1)) {
					if (fanin0->get_fanin(0)->get_operation() == NOT/* && fanin0->get_fanin(0)->fanouts.size() == 1*/) {
						// we keep fanin1
						// we change gate into an AND gate
						// we connect fanin0->get_fanin(0)->get_fanin(0) to gate

						gatet* and_gate = get_or_create_gate(AND);
						and_gate->add_fanin(primary_output(fanin0->get_fanin(0)->get_fanin(0)), 0);
						and_gate->add_fanin(primary_output(gate.get_fanin(1)), 1);

						gate.replace_by(and_gate);

						return true;
					}
				}
			}
		}
	}

	return false;
}

bool simple_circuitt::replace_by_zero(gatet& gate) {
	if (gate.get_operation() == AND) {
		if (gate.get_fanin(0)->get_operation() == NOT && gate.get_fanin(0)->get_fanin(0)->get_operation() == AND && gate.get_fanin(1)->get_operation() == AND) {
			gatet* target_gate = gate.get_fanin(0)->get_fanin(0);

			// we have to search for gate.get_fanin(0)->get_fanin(0) along gate.get_fanin(1)

			if (target_gate == gate.get_fanin(1)) {
				return true;
			}

			if (gate.get_fanin(1)->get_fanin(0) == target_gate || gate.get_fanin(1)->get_fanin(1) == target_gate) {
				return true;
			}

			if (gate.get_fanin(1)->get_fanin(0)->get_operation() == AND && (gate.get_fanin(1)->get_fanin(0)->get_fanin(0) == target_gate || gate.get_fanin(1)->get_fanin(0)->get_fanin(1) == target_gate)) {
				return true;
			}

			if (gate.get_fanin(1)->get_fanin(1)->get_operation() == AND && (gate.get_fanin(1)->get_fanin(1)->get_fanin(0) == target_gate || gate.get_fanin(1)->get_fanin(1)->get_fanin(1) == target_gate)) {
				return true;
			}
		}

		if (gate.get_fanin(0)->get_operation() == AND && gate.get_fanin(1)->get_operation() == NOT && gate.get_fanin(1)->get_fanin(0)->get_operation() == AND) {
			gatet* target_gate = gate.get_fanin(1)->get_fanin(0);

			// we have to search for gate.get_fanin(1)->get_fanin(0) along gate.get_fanin(0)

			if (target_gate == gate.get_fanin(0)) {
				return true;
			}

			if (gate.get_fanin(0)->get_fanin(0) == target_gate || gate.get_fanin(0)->get_fanin(1) == target_gate) {
				return true;
			}

			if (gate.get_fanin(0)->get_fanin(0)->get_operation() == AND && (gate.get_fanin(0)->get_fanin(0)->get_fanin(0) == target_gate || gate.get_fanin(0)->get_fanin(0)->get_fanin(1) == target_gate)) {
				return true;
			}

			if (gate.get_fanin(0)->get_fanin(1)->get_operation() == AND && (gate.get_fanin(0)->get_fanin(1)->get_fanin(0) == target_gate || gate.get_fanin(0)->get_fanin(1)->get_fanin(1) == target_gate)) {
				return true;
			}
		}
	}

	return false;
}

bool match_replace_by_zero2(simple_circuitt::gatet* not_gate, simple_circuitt::gatet* and_gate) {
	if (not_gate->get_operation() == simple_circuitt::NOT && and_gate->get_operation() == simple_circuitt::AND) {
		if (not_gate->get_fanin(0)->get_operation() == simple_circuitt::OR) {
			simple_circuitt::gatet* a_pin = not_gate->get_fanin(0)->get_fanin(0);
			simple_circuitt::gatet* b_pin = not_gate->get_fanin(0)->get_fanin(1);

			if (and_gate->get_fanin(0)->get_operation() == simple_circuitt::XOR) {
				if ((and_gate->get_fanin(0)->get_fanin(0) == a_pin && and_gate->get_fanin(0)->get_fanin(1) == b_pin) || (and_gate->get_fanin(0)->get_fanin(1) == a_pin && and_gate->get_fanin(0)->get_fanin(0) == b_pin)) {
					return true;
				}
			}

			if (and_gate->get_fanin(1)->get_operation() == simple_circuitt::XOR) {
				if ((and_gate->get_fanin(1)->get_fanin(0) == a_pin && and_gate->get_fanin(1)->get_fanin(1) == b_pin) || (and_gate->get_fanin(1)->get_fanin(1) == a_pin && and_gate->get_fanin(1)->get_fanin(0) == b_pin)) {
					return true;
				}
			}
		}
	}

	return false;
}

bool simple_circuitt::replace_by_zero2(gatet& gate) {
	if (gate.get_operation() == AND) {
		if (match_replace_by_zero2(gate.get_fanin(0), gate.get_fanin(1))) {
			return true;
		}

		return match_replace_by_zero2(gate.get_fanin(1), gate.get_fanin(0));
	}

	return false;
}

bool simple_circuitt::simplify2(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	// AND(a, OR(NOT(a), b)) = AND(a, b)
	if (gate.get_operation() == AND) {
		if (gate.get_fanin(0)->get_operation() == OR) {
			if (gate.get_fanin(0)->get_fanin(0)->get_operation() == NOT) {
				if (gate.get_fanin(1) == gate.get_fanin(0)->get_fanin(0)->get_fanin(0)) {
					// simplify

					gatet* b = gate.get_fanin(0)->get_fanin(1);

					fanin0_out = gate.get_fanin(1);
					fanin1_out = b;

					return true;
				}
			}

			if (gate.get_fanin(0)->get_fanin(1)->get_operation() == NOT) {
				if (gate.get_fanin(1) == gate.get_fanin(0)->get_fanin(1)->get_fanin(0)) {
					// simplify

					gatet* b = gate.get_fanin(0)->get_fanin(0);

					fanin0_out = gate.get_fanin(1);
					fanin1_out = b;

					return true;
				}
			}
		}

		if (gate.get_fanin(1)->get_operation() == OR) {
			if (gate.get_fanin(1)->get_fanin(0)->get_operation() == NOT) {
				if (gate.get_fanin(0) == gate.get_fanin(1)->get_fanin(0)->get_fanin(0)) {
					// simplify

					gatet* b = gate.get_fanin(1)->get_fanin(1);

					fanin0_out = gate.get_fanin(0);
					fanin1_out = b;

					return true;
				}
			}

			if (gate.get_fanin(1)->get_fanin(1)->get_operation() == NOT) {
				if (gate.get_fanin(0) == gate.get_fanin(1)->get_fanin(1)->get_fanin(0)) {
					// simplify

					gatet* b = gate.get_fanin(1)->get_fanin(0);

					fanin0_out = gate.get_fanin(0);
					fanin1_out = b;

					return true;
				}
			}
		}
	}

	return false;
}

bool simple_circuitt::simplify3(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	// OR(a, AND(NOT(a), XOR(a, b))) = OR(a, b)
	if (gate.get_operation() == OR) {
		if (gate.get_fanin(0)->get_operation() == AND) {
			gatet* and_gate = gate.get_fanin(0);

			if (and_gate->get_fanin(0)->get_operation() == NOT && and_gate->get_fanin(1)->get_operation() == XOR) {
				gatet* not_gate = and_gate->get_fanin(0);
				gatet* xor_gate = and_gate->get_fanin(1);

				gatet* a_gate = not_gate->get_fanin(0);

				if (a_gate == gate.get_fanin(1)) {
					if (a_gate == xor_gate->get_fanin(0)) {
						// b = xor_gate->get_fanin(1)

						fanin0_out = gate.get_fanin(1);
						fanin1_out = xor_gate->get_fanin(1);

						return true;
					}

					if (a_gate == xor_gate->get_fanin(1)) {
						// b = xor_gate->get_fanin(0)

						fanin0_out = gate.get_fanin(1);
						fanin1_out = xor_gate->get_fanin(0);

						return true;
					}
				}
			}

			if (and_gate->get_fanin(1)->get_operation() == NOT && and_gate->get_fanin(0)->get_operation() == XOR) {
				gatet* not_gate = and_gate->get_fanin(1);
				gatet* xor_gate = and_gate->get_fanin(0);

				gatet* a_gate = not_gate->get_fanin(0);

				if (a_gate == gate.get_fanin(1)) {
					if (a_gate == xor_gate->get_fanin(0)) {
						// b = xor_gate->get_fanin(1)

						fanin0_out = gate.get_fanin(1);
						fanin1_out = xor_gate->get_fanin(1);

						return true;
					}

					if (a_gate == xor_gate->get_fanin(1)) {
						// b = xor_gate->get_fanin(0)

						fanin0_out = gate.get_fanin(1);
						fanin1_out = xor_gate->get_fanin(0);

						return true;
					}
				}
			}
		}

		if (gate.get_fanin(1)->get_operation() == AND) {
			gatet* and_gate = gate.get_fanin(1);

			if (and_gate->get_fanin(0)->get_operation() == NOT && and_gate->get_fanin(1)->get_operation() == XOR) {
				gatet* not_gate = and_gate->get_fanin(0);
				gatet* xor_gate = and_gate->get_fanin(1);

				gatet* a_gate = not_gate->get_fanin(0);

				if (a_gate == gate.get_fanin(0)) {
					if (a_gate == xor_gate->get_fanin(0)) {
						// b = xor_gate->get_fanin(1)

						fanin0_out = gate.get_fanin(0);
						fanin1_out = xor_gate->get_fanin(1);

						return true;
					}

					if (a_gate == xor_gate->get_fanin(1)) {
						// b = xor_gate->get_fanin(0)

						fanin0_out = gate.get_fanin(0);
						fanin1_out = xor_gate->get_fanin(0);

						return true;
					}
				}
			}

			if (and_gate->get_fanin(1)->get_operation() == NOT && and_gate->get_fanin(0)->get_operation() == XOR) {
				gatet* not_gate = and_gate->get_fanin(1);
				gatet* xor_gate = and_gate->get_fanin(0);

				gatet* a_gate = not_gate->get_fanin(0);

				if (a_gate == gate.get_fanin(0)) {
					if (a_gate == xor_gate->get_fanin(0)) {
						// b = xor_gate->get_fanin(1)

						fanin0_out = gate.get_fanin(0);
						fanin1_out = xor_gate->get_fanin(1);

						return true;
					}

					if (a_gate == xor_gate->get_fanin(1)) {
						// b = xor_gate->get_fanin(0)

						fanin0_out = gate.get_fanin(0);
						fanin1_out = xor_gate->get_fanin(0);

						return true;
					}
				}
			}
		}
	}

	return false;
}

bool simple_circuitt::simplify4(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	// AND(AND(a, b), NOT(AND(AND(a, b), XOR(AND(a, b), c)))) = AND(AND(a, b), c)
	if (gate.get_operation() == AND) {
		if (gate.get_fanin(0)->get_operation() == AND && gate.get_fanin(1)->get_operation() == NOT) {
			gatet* ab_and_gate = gate.get_fanin(0);
			gatet* not_gate = gate.get_fanin(1);

			gatet* and_gate2 = not_gate->get_fanin(0);

			if (and_gate2->get_operation() == AND) {
				if (and_gate2->get_fanin(0) == ab_and_gate) {
					gatet* xor_gate = and_gate2->get_fanin(1);

					if (xor_gate->get_operation() == XOR) {

						if (xor_gate->get_fanin(0) == ab_and_gate) {
							// c = xor_gate->get_fanin(1)

							fanin0_out = ab_and_gate;
							fanin1_out = xor_gate->get_fanin(1);

							return true;
						}

						if (xor_gate->get_fanin(1) == ab_and_gate) {
							// c = xor_gate->get_fanin(0)

							fanin0_out = ab_and_gate;
							fanin1_out = xor_gate->get_fanin(0);

							return true;
						}

					}
				}

				if (and_gate2->get_fanin(1) == ab_and_gate) {
					gatet* xor_gate = and_gate2->get_fanin(0);

					if (xor_gate->get_operation() == XOR) {
						if (xor_gate->get_fanin(0) == ab_and_gate) {
							// c = xor_gate->get_fanin(1)

							fanin0_out = ab_and_gate;
							fanin1_out = xor_gate->get_fanin(1);

							return true;
						}

						if (xor_gate->get_fanin(1) == ab_and_gate) {
							// c = xor_gate->get_fanin(0)

							fanin0_out = ab_and_gate;
							fanin1_out = xor_gate->get_fanin(0);

							return true;
						}
					}
				}
			}
		}

		if (gate.get_fanin(1)->get_operation() == AND && gate.get_fanin(0)->get_operation() == NOT) {
			gatet* ab_and_gate = gate.get_fanin(1);
			gatet* not_gate = gate.get_fanin(0);

			gatet* and_gate2 = not_gate->get_fanin(0);

			if (and_gate2->get_operation() == AND) {
				if (and_gate2->get_fanin(0) == ab_and_gate) {
					gatet* xor_gate = and_gate2->get_fanin(1);

					if (xor_gate->get_operation() == XOR) {

						if (xor_gate->get_fanin(0) == ab_and_gate) {
							// c = xor_gate->get_fanin(1)

							fanin0_out = ab_and_gate;
							fanin1_out = xor_gate->get_fanin(1);

							return true;
						}

						if (xor_gate->get_fanin(1) == ab_and_gate) {
							// c = xor_gate->get_fanin(0)

							fanin0_out = ab_and_gate;
							fanin1_out = xor_gate->get_fanin(0);

							return true;
						}

					}
				}

				if (and_gate2->get_fanin(1) == ab_and_gate) {
					gatet* xor_gate = and_gate2->get_fanin(0);

					if (xor_gate->get_operation() == XOR) {
						if (xor_gate->get_fanin(0) == ab_and_gate) {
							// c = xor_gate->get_fanin(1)

							fanin0_out = ab_and_gate;
							fanin1_out = xor_gate->get_fanin(1);

							return true;
						}

						if (xor_gate->get_fanin(1) == ab_and_gate) {
							// c = xor_gate->get_fanin(0)

							fanin0_out = ab_and_gate;
							fanin1_out = xor_gate->get_fanin(0);

							return true;
						}
					}
				}
			}
		}
	}

	return false;
}

bool simple_circuitt::simplify5(gatet& gate) {
	// AND(NOT(a), NOT(b)) = NOT(OR(a, b))
	if (gate.get_operation() == AND) {
		if (gate.get_fanin(0)->get_operation() == NOT && gate.get_fanin(1)->get_operation() == NOT) {
			gatet* a_not_gate, *b_not_gate;
			bool found = false;

			if (gate.get_fanin(0)->fanouts.size() == 1) {
				a_not_gate = gate.get_fanin(0);
				b_not_gate = gate.get_fanin(1);
				found = true;
			}

			if (!found && gate.get_fanin(1)->fanouts.size() == 1) {
				a_not_gate = gate.get_fanin(1);
				b_not_gate = gate.get_fanin(0);
				found = true;
			}

			if (found) {
				assert(a_not_gate);
				assert(b_not_gate);

				gatet* a = a_not_gate->get_fanin(0);
				gatet* b = b_not_gate->get_fanin(0);

				gatet* or_gate = get_or_create_gate(OR);

				or_gate->add_fanin(primary_output(a), 0);
				or_gate->add_fanin(primary_output(b), 1);

				gatet* not_gate = get_or_create_gate(NOT);

				not_gate->add_fanin(primary_output(or_gate), 0);

				gate.replace_by(not_gate);

				return true;
			}
		}
	}

	return false;
}

bool simple_circuitt::match_simplify6(gatet* or_gate, gatet* not_gate, gatet*& a_pin) {
	if (or_gate->get_operation() == OR) {
		if (not_gate->get_operation() == NOT && not_gate->fanouts.size() == 1) {
			if (not_gate->get_fanin(0)->get_operation() == OR) {
				if (not_gate->get_fanin(0)->get_fanin(0) == or_gate) {
					a_pin = not_gate->get_fanin(0)->get_fanin(1);

					return true;
				}

				if (not_gate->get_fanin(0)->get_fanin(1) == or_gate) {
					a_pin = not_gate->get_fanin(0)->get_fanin(0);

					return true;
				}
			}
		}
	}

	return false;
}

bool simple_circuitt::simplify6(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	// OR(OR(b, c), NOT(OR(OR(b, c), a))) = OR(OR(b, c), NOT(a))
	if (gate.get_operation() == OR) {
		if (match_simplify6(gate.get_fanin(0), gate.get_fanin(1), fanin1_out)) {
			fanin0_out = gate.get_fanin(0);

			return true;
		}

		if (match_simplify6(gate.get_fanin(1), gate.get_fanin(0), fanin1_out)) {
			fanin0_out = gate.get_fanin(1);

			return true;
		}
	}

	return false;
}

bool simple_circuitt::simplify7(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	// OR(NOT(OR(NOT(a), AND(NOT(a), b))), AND(NOT(a), b)) = OR(a, b)
	if (gate.get_operation() == OR) {
		gatet* a_pin = NULL;
		gatet* b_pin = NULL;

		if (match_simplify7(gate.get_fanin(0), gate.get_fanin(1), a_pin, b_pin) || match_simplify7(gate.get_fanin(1), gate.get_fanin(0), a_pin, b_pin)) {
			fanin0_out = a_pin;
			fanin1_out = b_pin;

			return true;
		}
	}

	return false;
}

bool simple_circuitt::match_simplify7(gatet* not_gate, gatet* and_gate, gatet*& a_pin, gatet*& b_pin) {
	if (not_gate->get_operation() == NOT && and_gate->get_operation() == AND) {
		gatet* or_gate = not_gate->get_fanin(0);

		if (or_gate->get_operation() == OR) {
			gatet* not_gate2 = or_gate->get_fanin(0);

			if (not_gate2->get_operation() == NOT && or_gate->get_fanin(1) == and_gate) {
				a_pin = not_gate2->get_fanin(0);

				if (and_gate->get_fanin(0) == not_gate2) {
					b_pin = and_gate->get_fanin(1);

					return true;
				}

				if (and_gate->get_fanin(1) == not_gate2) {
					b_pin = and_gate->get_fanin(0);

					return true;
				}
			}

			not_gate2 = or_gate->get_fanin(1);

			if (not_gate2->get_operation() == NOT && or_gate->get_fanin(0) == and_gate) {
				a_pin = not_gate2->get_fanin(0);

				if (and_gate->get_fanin(0) == not_gate2) {
					b_pin = and_gate->get_fanin(1);

					return true;
				}

				if (and_gate->get_fanin(1) == not_gate2) {
					b_pin = and_gate->get_fanin(0);

					return true;
				}
			}
		}
	}

	return false;
}

bool simple_circuitt::simplify8(gatet& gate) {
	// NOT(XOR(NOT(a), b)) = XOR(a, b)
	if (gate.get_operation() == NOT) {
		gatet* xor_gate = gate.get_fanin(0);

		if (xor_gate->get_operation() == XOR) {
			gatet* a_pin = NULL;
			gatet* b_pin = NULL;
			bool found = false;

			if (xor_gate->get_fanin(0)->get_operation() == NOT) {
				a_pin = xor_gate->get_fanin(1);
				b_pin = xor_gate->get_fanin(0)->get_fanin(0);
				found = true;
			}

			if (!found && xor_gate->get_fanin(1)->get_operation() == NOT) {
				a_pin = xor_gate->get_fanin(0);
				b_pin = xor_gate->get_fanin(1)->get_fanin(0);
				found = true;
			}

			if (found) {
				gatet* new_xor_gate = get_or_create_gate(XOR);
				new_xor_gate->add_fanin(primary_output(a_pin), 0);
				new_xor_gate->add_fanin(primary_output(b_pin), 1);

				gate.replace_by(new_xor_gate);

				return true;
			}
		}
	}

	return false;
}

bool simple_circuitt::simplify9(gatet& gate) {
	// OR(NOT(a), NOT(b)) = NOT(AND(a, b))
	if (gate.get_operation() == OR) {
		if (gate.get_fanin(0)->get_operation() == NOT && gate.get_fanin(1)->get_operation() == NOT && (gate.get_fanin(0)->fanouts.size() == 1 || gate.get_fanin(1)->fanouts.size() == 1)) {
			gatet* a_pin = gate.get_fanin(0)->get_fanin(0);
			gatet* b_pin = gate.get_fanin(1)->get_fanin(0);

			gatet* and_gate = get_or_create_gate(AND);
			gatet* not_gate = get_or_create_gate(NOT);

			and_gate->add_fanin(primary_output(a_pin), 0);
			and_gate->add_fanin(primary_output(b_pin), 1);

			not_gate->add_fanin(primary_output(and_gate), 0);

			gate.replace_by(not_gate);

			return true;
		}
	}

	return false;
}

bool match_simplify10(simple_circuitt::gatet* or_gate1, simple_circuitt::gatet* or_gate2) {
	assert(or_gate1->get_operation() == simple_circuitt::OR);
	assert(or_gate2->get_operation() == simple_circuitt::OR);

	if (or_gate2->get_fanin(0) == or_gate1 || or_gate2->get_fanin(1) == or_gate1) {
		return true;
	}

	return false;
}

bool simple_circuitt::simplify10(gatet& gate) {
	// OR(OR(a, b), OR(OR(a, b), c)) = OR(OR(a, b), c)
	if (gate.get_operation() == OR && gate.get_fanin(0)->get_operation() == OR && gate.get_fanin(1)->get_operation() == OR) {
		if (match_simplify10(gate.get_fanin(0), gate.get_fanin(1))) {
			gate.replace_by(gate.get_fanin(1));

			return true;
		}

		if (match_simplify10(gate.get_fanin(1), gate.get_fanin(0))) {
			gate.replace_by(gate.get_fanin(0));

			return true;
		}
	}

	return false;
}

bool simple_circuitt::match_simplify11(gatet* xor_gate, gatet* a_pin, gatet* b_pin, gatet*& not_xor_gate) {
	for (gatet::fanoutst::iterator it = a_pin->fanouts.begin(); it != a_pin->fanouts.end(); ++it) {
		gatet::fanoutt* fanout = *it;

		if (fanout->second.gate != xor_gate && fanout->second.gate->get_operation() == XOR) {
			if (fanout->second.pin == 0) {
				if (fanout->second.gate->get_fanin(1)->get_operation() == NOT && fanout->second.gate->get_fanin(1)->get_fanin(0) == b_pin) {
					not_xor_gate = fanout->second.gate;

					return true;
				}
			}
			else {
				if (fanout->second.gate->get_fanin(0)->get_operation() == NOT && fanout->second.gate->get_fanin(0)->get_fanin(0) == b_pin) {
					not_xor_gate = fanout->second.gate;

					return true;
				}
			}
		}
	}

	return false;
}

bool simple_circuitt::simplify11(gatet& gate) {
	// "structural hashing" XOR(NOT(a), b) = NOT(XOR(a, b))
	if (gate.get_operation() == XOR) {
		gatet* not_xor_gate = NULL;

		if (match_simplify11(&gate, gate.get_fanin(0), gate.get_fanin(1), not_xor_gate) || match_simplify11(&gate, gate.get_fanin(1), gate.get_fanin(0), not_xor_gate)) {
			assert(not_xor_gate);

			gatet* not_gate = get_or_create_gate(NOT);

			not_gate->add_fanin(primary_output(&gate), 0);

			not_xor_gate->replace_by(not_gate);

			return true;
		}
	}

	return false;
}

bool match_simplify12(simple_circuitt::gatet* a_pin, simple_circuitt::gatet* and_gate, simple_circuitt::gatet*& b_pin) {
	if (and_gate->get_operation() == simple_circuitt::AND) {
		if (and_gate->get_fanin(0)->get_operation() == simple_circuitt::NOT && and_gate->get_fanin(0)->get_fanin(0) == a_pin) {
			b_pin = and_gate->get_fanin(1);

			return true;
		}

		if (and_gate->get_fanin(1)->get_operation() == simple_circuitt::NOT && and_gate->get_fanin(1)->get_fanin(0) == a_pin) {
			b_pin = and_gate->get_fanin(0);

			return true;
		}
	}

	return false;
}

bool simple_circuitt::simplify12(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	// OR(a, AND(NOT(a), b)) = OR(a, b)
	if (gate.get_operation() == OR) {
		gatet* b_pin = NULL;
		if (match_simplify12(gate.get_fanin(0), gate.get_fanin(1), b_pin)) {
			fanin0_out = gate.get_fanin(0);
			fanin1_out = b_pin;

			return true;
		}

		if (match_simplify12(gate.get_fanin(1), gate.get_fanin(0), b_pin)) {
			fanin0_out = gate.get_fanin(1);
			fanin1_out = b_pin;

			return true;
		}
	}

	return false;
}

bool simple_circuitt::simplify13(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	// OR(a, XOR(a, b)) = OR(a, b)
	if (gate.get_operation() == OR) {
		gatet* a_pin = gate.get_fanin(0);
		gatet* xor_gate = gate.get_fanin(1);

		if (xor_gate->get_operation() == XOR) {
			if (xor_gate->get_fanin(0) == a_pin) {
				gatet* b_pin = xor_gate->get_fanin(1);

				fanin0_out = a_pin;
				fanin1_out = b_pin;

				return true;
			}

			if (xor_gate->get_fanin(1) == a_pin) {
				gatet* b_pin = xor_gate->get_fanin(0);

				fanin0_out = a_pin;
				fanin1_out = b_pin;

				return true;
			}
		}

		a_pin = gate.get_fanin(1);
		xor_gate = gate.get_fanin(0);

		if (xor_gate->get_operation() == XOR) {
			if (xor_gate->get_fanin(0) == a_pin) {
				gatet* b_pin = xor_gate->get_fanin(1);

				fanin0_out = a_pin;
				fanin1_out = b_pin;

				return true;
			}

			if (xor_gate->get_fanin(1) == a_pin) {
				gatet* b_pin = xor_gate->get_fanin(0);

				fanin0_out = a_pin;
				fanin1_out = b_pin;

				return true;
			}
		}
	}

	return false;
}

bool simple_circuitt::match_simplify14(gatet* a_pin, gatet* not_gate, gatet*& b_pin) {
	if (not_gate->get_operation() == NOT && not_gate->fanouts.size() == 1 && not_gate->get_fanin(0)->get_operation() == OR) {
		gatet* or_gate = not_gate->get_fanin(0);

		if (or_gate->get_fanin(0) == a_pin) {
			b_pin = or_gate->get_fanin(1);
			return true;
		}

		if (or_gate->get_fanin(1) == a_pin) {
			b_pin = or_gate->get_fanin(0);
			return true;
		}
	}

	return false;
}

bool simple_circuitt::simplify14(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	// OR(a, NOT(OR(a, b))) = OR(a, NOT(b))
	if (gate.get_operation() == OR) {
		gatet* b_pin = NULL;

		if (match_simplify14(gate.get_fanin(0), gate.get_fanin(1), b_pin)) {
			fanin0_out = gate.get_fanin(0);
			fanin1_out = b_pin;

			return true;
		}

		if (match_simplify14(gate.get_fanin(1), gate.get_fanin(0), b_pin)) {
			fanin0_out = gate.get_fanin(1);
			fanin1_out = b_pin;

			return true;
		}
	}

	return false;
}

bool simple_circuitt::simplify15(gatet& gate, gatet*& a_pin, gatet*& b_pin) {
	if (gate.get_operation() == OR) {
		return (match_simplify15(gate.get_fanin(0), gate.get_fanin(1), a_pin, b_pin) || match_simplify15(gate.get_fanin(1), gate.get_fanin(0), a_pin, b_pin));
	}

	return false;
}

bool simple_circuitt::match_simplify15(gatet* and_gate, gatet* not_gate, gatet*& a_pin, gatet*& b_pin) {
	assert(and_gate);
	assert(not_gate);

	if (and_gate->get_operation() == AND && and_gate->fanouts.size() == 1 && not_gate->get_operation() == NOT && not_gate->fanouts.size() == 1 && not_gate->get_fanin(0)->get_operation() == OR && not_gate->get_fanin(0)->fanouts.size() == 1) {
		gatet* or_gate = not_gate->get_fanin(0);

		a_pin = and_gate->get_fanin(0);
		b_pin = and_gate->get_fanin(1);

		if ((a_pin == or_gate->get_fanin(0) && b_pin == or_gate->get_fanin(1)) || (a_pin == or_gate->get_fanin(1) && b_pin == or_gate->get_fanin(0))){
			return true;
		}
	}

	return false;
}

bool simple_circuitt::simplify16(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	if (gate.get_operation() == OR) {
		gatet* and_gate1 = gate.get_fanin(0);
		gatet* and_gate2 = gate.get_fanin(1);

		if (and_gate1->get_operation() == AND && and_gate2->get_operation() == AND) {

			bool a_pin_side = false;
			gatet* a_pin = and_gate1->get_fanin(a_pin_side);

			gatet* not_gate2 = and_gate2->get_fanin(false);
			gatet* not_gate1 = and_gate1->get_fanin(!a_pin_side);

			if (not_gate2->get_operation() == NOT && not_gate2->get_fanin(false) == a_pin) {
				gatet* b_pin = and_gate2->get_fanin(1);

				if (not_gate1->get_operation() == NOT && not_gate1->get_fanin(false) == b_pin) {
					fanin0_out = a_pin;
					fanin1_out = b_pin;

					return true;
				}
			}

			not_gate2 = and_gate2->get_fanin(true);

			if (not_gate2->get_operation() == NOT && not_gate2->get_fanin(false) == a_pin) {
				gatet* b_pin = and_gate2->get_fanin(0);

				if (not_gate1->get_operation() == NOT && not_gate1->get_fanin(false) == b_pin) {
					fanin0_out = a_pin;
					fanin1_out = b_pin;

					return true;
				}
			}

			not_gate2 = and_gate2->get_fanin(false);

			a_pin_side = !a_pin_side;
			a_pin = and_gate1->get_fanin(a_pin_side);
			not_gate1 = and_gate1->get_fanin(!a_pin_side);


			if (not_gate2->get_operation() == NOT && not_gate2->get_fanin(false) == a_pin) {
				gatet* b_pin = and_gate2->get_fanin(1);

				if (not_gate1->get_operation() == NOT && not_gate1->get_fanin(false) == b_pin) {
					fanin0_out = a_pin;
					fanin1_out = b_pin;

					return true;
				}
			}

			not_gate2 = and_gate2->get_fanin(true);

			if (not_gate2->get_operation() == NOT && not_gate2->get_fanin(false) == a_pin) {
				gatet* b_pin = and_gate2->get_fanin(0);

				if (not_gate1->get_operation() == NOT && not_gate1->get_fanin(false) == b_pin) {
					fanin0_out = a_pin;
					fanin1_out = b_pin;

					return true;
				}
			}
		}
	}

	return false;
}

bool simple_circuitt::simplify17(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	if (gate.get_operation() == XOR) {
		if (gate.get_fanin(0)->get_operation() == NOT && gate.get_fanin(0)->fanouts.size() == 1) {
			fanin0_out = gate.get_fanin(0)->get_fanin(0);
			fanin1_out = gate.get_fanin(1);

			return true;
		}

		if (gate.get_fanin(1)->get_operation() == NOT && gate.get_fanin(1)->fanouts.size() == 1) {
			fanin0_out = gate.get_fanin(1)->get_fanin(0);
			fanin1_out = gate.get_fanin(0);

			return true;
		}
	}

	return false;
}

bool simple_circuitt::simplify18(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	return false; // TODO reactivate again (produced bigger circuits on nikos5)

	// AND(AND(a, b), AND(b, c)) = AND(a, AND(b, c))
	if (gate.get_operation() == AND) {
		if (gate.get_fanin(0)->get_operation() == AND && gate.get_fanin(1)->get_operation() == AND) {
			gatet* and_gate1 = gate.get_fanin(0);
			gatet* and_gate2 = gate.get_fanin(1);

			if (and_gate1->get_fanin(0) == and_gate2->get_fanin(0)) {
				// a0 == a1
				fanin0_out = and_gate1;
				fanin1_out = and_gate2->get_fanin(1);

				return true;
			}
			else if (and_gate1->get_fanin(0) == and_gate2->get_fanin(1)) {
				// a0 == b1
				fanin0_out = and_gate1;
				fanin1_out = and_gate2->get_fanin(0);

				return true;
			}
			else if (and_gate1->get_fanin(1) == and_gate2->get_fanin(0)) {
				// b0 == a1
				fanin0_out = and_gate1;
				fanin1_out = and_gate2->get_fanin(1);

				return true;
			}
			else if (and_gate1->get_fanin(1) == and_gate2->get_fanin(1)) {
				// b0 == b1
				fanin0_out = and_gate1;
				fanin1_out = and_gate2->get_fanin(0);

				return true;
			}
		}
	}

	return false;
}

bool match2(simple_circuitt::gatet* a_pin, simple_circuitt::gatet* not_gate, simple_circuitt::gatet* b_pin, simple_circuitt::gatet*& fanin0_out) {
	if (not_gate->get_operation() == simple_circuitt::NOT) {
		if (not_gate->get_fanin(0) == b_pin) {
			fanin0_out = a_pin;

			return true;
		}
	}

	return false;
}

bool simple_circuitt::can_be_easily_removed6(gatet& gate, gatet*& fanin0_out) {
	if (gate.get_operation() == OR) {
		if (gate.get_fanin(0)->get_operation() == AND && gate.get_fanin(1)->get_operation() == AND) {

			gatet* and_gate1 = gate.get_fanin(0);
			gatet* and_gate2 = gate.get_fanin(1);

			gatet* a_pin = and_gate1->get_fanin(0);

			if (a_pin == and_gate2->get_fanin(0)) {
				gatet* not_gate = and_gate1->get_fanin(1);
				gatet* b_pin = and_gate2->get_fanin(1);

				if (match2(a_pin, not_gate, b_pin, fanin0_out)) {
					return true;
				}

				if (match2(a_pin, b_pin, not_gate, fanin0_out)) {
					return true;
				}
			}

			if (a_pin == and_gate2->get_fanin(1)) {
				gatet* not_gate = and_gate1->get_fanin(1);
				gatet* b_pin = and_gate2->get_fanin(0);

				if (match2(a_pin, not_gate, b_pin, fanin0_out)) {
					return true;
				}

				if (match2(a_pin, b_pin, not_gate, fanin0_out)) {
					return true;
				}
			}

			a_pin = and_gate1->get_fanin(1);

			if (a_pin == and_gate2->get_fanin(0)) {
				gatet* not_gate = and_gate1->get_fanin(0);
				gatet* b_pin = and_gate2->get_fanin(1);

				if (match2(a_pin, not_gate, b_pin, fanin0_out)) {
					return true;
				}

				if (match2(a_pin, b_pin, not_gate, fanin0_out)) {
					return true;
				}
			}

			if (a_pin == and_gate2->get_fanin(1)) {
				gatet* not_gate = and_gate1->get_fanin(0);
				gatet* b_pin = and_gate2->get_fanin(0);

				if (match2(a_pin, not_gate, b_pin, fanin0_out)) {
					return true;
				}

				if (match2(a_pin, b_pin, not_gate, fanin0_out)) {
					return true;
				}
			}

		}
	}

	return false;
}

bool simple_circuitt::simplify_trivial(gatet& gate) {
	if ((gate.get_operation() == OR || gate.get_operation() == AND) && gate.get_fanin(0) == gate.get_fanin(1)) {
		gate.replace_by(gate.get_fanin(0));

		return true;
	}

	if (gate.get_operation() == XOR && gate.get_fanin(0) == gate.get_fanin(1)) {
		gate.replace_by(ZERO_GATE);

		return true;
	}

	return false;
}

bool simple_circuitt::structural_hashing_NOT(gatet& gate) {
	if (gate.get_operation() == NOT) {
		gatet* fanin = gate.get_fanin(0);

		for (gatet::fanoutst::iterator it = fanin->fanouts.begin(); it != fanin->fanouts.end(); ++it) {
			gatet::fanoutt* fanout = *it;

			if (fanout->second.gate->get_operation() == NOT && fanout->second.gate != &gate) {
				gate.replace_by(fanout->second.gate);

				return true;
			}
		}
	}

	return false;
}

bool simple_circuitt::structural_hashing_BINOP(gatet& gate, GATE_OP operation) {
	if (gate.get_operation() == operation) {
		gatet* fanin0 = gate.get_fanin(0);
		gatet* fanin1 = gate.get_fanin(1);

		// TODO replace the iterations by a map?

		for (gatet::fanoutst::iterator it = fanin0->fanouts.begin(); it != fanin0->fanouts.end(); ++it) {
			gatet::fanoutt* fanout = *it;

			assert(fanout);
			assert(fanout->second.gate);

			if (fanout->second.gate->get_operation() == operation && fanout->second.gate != &gate) {
				for (gatet::fanoutst::iterator it2 = fanin1->fanouts.begin(); it2 != fanin1->fanouts.end(); ++it2) {
					gatet::fanoutt* fanout2 = *it2;

					if (fanout2->second.gate->get_operation() == operation && fanout2->second.gate != &gate) {
						if (fanout->second.gate == fanout2->second.gate) {
							gate.replace_by(fanout->second.gate);

							return true;
						}
					}
				}
			}
		}
	}

	return false;
}

bool simple_circuitt::structural_hashing_AND(gatet& gate) {
	return structural_hashing_BINOP(gate, AND);
}

bool simple_circuitt::structural_hashing_OR(gatet& gate) {
	return structural_hashing_BINOP(gate, OR);
}

bool simple_circuitt::structural_hashing_XOR(gatet& gate){
	return structural_hashing_BINOP(gate, XOR);
}


