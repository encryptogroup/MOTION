/*
 * simple_circuit_sweep.cpp
 *
 *  Created on: 08.10.2013
 *      Author: andreas
 */

#include "simple_circuit.h"

#include <solvers/sat/satcheck.h>
#include <solvers/prop/prop.h>

#include <map>

bool simple_circuitt::check_gate(gatet*& gate, bool boolean_value, interpretationt& tmp_interpretation) {
	gate->was_checked_for_being_constant = true;

	bool canceled = false;

	// deactivated cancel for the moment!
	if (evaluates_to_constant_(gate, !boolean_value, tmp_interpretation, canceled)) {
		// gate has the constant value boolean_value
		return true;
	}

	return false;
}

bool simple_circuitt::sweep(gatet*& constant_gate, bool& value, interpretationt interpretation) {
	message_handler.status() << "[SIMULATION] ..." << messaget::eom;

	// we have to rerun the simulation because gate addresses might have been reused
	simulate(interpretation);

	message_handler.status() << "[SWEEP] start" << messaget::eom;

	unsigned counter = 0;

	simple_circuit_level_mapt level_map;
	simple_circuit_level_sett level_set;

	for (gatet* gate_it = gates_HEAD; gate_it != NULL; gate_it = gate_it->next) {
		// determine level
		simple_circuit_get_depth(*this, gate_it, level_map, &level_set);
	}

	for (unsigned i = 1; i <= level_set.size(); i++) {
		::std::set< gatet* >* set = level_set[i];

		assert(set);

		for (::std::set< gatet* >::iterator it = set->begin(); it != set->end(); ++it) {
			counter++;

			gatet* gate = *it;

			if (!gate->was_checked_for_being_constant) {
				if (gate->get_operation() != NOT) {
					gate->was_checked_for_being_constant = true;

					interpretationt::iterator sim_it = interpretation.find(gate);

					assert(sim_it != interpretation.end());

					interpretationt tmp_interpretation;

					bool canceled = false;

					if (evaluates_to_constant_(gate, !(sim_it->second), tmp_interpretation, canceled)) {
						// gate has the constant value sim_it->second
						value = sim_it->second;

						constant_gate = gate;

						return true;
					}
					else if (!canceled) {
						simulate(tmp_interpretation);

						for (unsigned j = i; j <= level_set.size(); j++) {
							::std::set< gatet* >* set_j = level_set[j];

							assert(set_j);

							for (::std::set< gatet* >::iterator it_j = set_j->begin(); it_j != set_j->end(); ++it_j) {
								gatet* gate_j = *it_j;

								if (!gate_j->was_checked_for_being_constant) {
									if (interpretation[gate_j] != tmp_interpretation[gate_j]) {
										gate_j->was_checked_for_being_constant = true;
									}
								}
							}
						}
					}
					else {
						message_handler.status() << "[SWEEP] end" << messaget::eom;

						return false;
					}

#if 0
					if (evaluates_to_constant(*gate, value)) {
						constant_gate = gate;

						return true;
					}
#endif
				}
				else {
					gate->was_checked_for_being_constant = true;
				}
			}

			if (message_handler.get_message_handler().get_verbosity() >= 9) {
				if (counter % 100 == 0) {
					::std::cout << counter << "/" << get_number_of_gates() << ::std::endl;
				}
			}
		}
	}

	// cleanup
	for (unsigned i = 1; i <= level_set.size(); i++) {
		::std::set< gatet* >* set = level_set[i];

		delete set;
	}

#if 0
	for (gatet* gate = gates_HEAD; gate != NULL; gate = gate->next) {
		counter++;

		if (!gate->was_checked_for_being_constant) {
			if (gate->get_operation() != NOT) {
				gate->was_checked_for_being_constant = true;

				if (evaluates_to_constant(*gate, value)) {
					constant_gate = gate;

					return true;
				}
			}
		}

		if (counter % 100 == 0) {
			::std::cout << counter << "/" << get_number_of_gates() << ::std::endl;
		}
	}
#endif

	message_handler.status() << "[SWEEP] end" << messaget::eom;

	return false;
}

typedef ::std::map< simple_circuitt::gatet* , literalt > gate2literal_mapt;

void translate_gate(satcheckt& cnf, simple_circuitt::gatet* gate, gate2literal_mapt& gate2literal_map) {
	if (gate2literal_map.find(gate) != gate2literal_map.end()) {
		return;
	}

	switch (gate->get_operation()) {

	case simple_circuitt::ONE:
	{
		gate2literal_map[gate] = const_literal(true);
		break;
	}
	case simple_circuitt::INPUT:
	{
		gate2literal_map[gate] = cnf.new_variable();
		break;
	}
	case simple_circuitt::OUTPUT:
	{
		assert(false);
		break;
	}
	case simple_circuitt::NOT:
	{
		translate_gate(cnf, gate->fanin0, gate2literal_map);
		assert(gate2literal_map.find(gate->fanin0) != gate2literal_map.end());
		literalt lit = gate2literal_map[gate->fanin0];

		// CAUTION: if you want to use this translation to obtain values by a SAT solver, you have to use lxor instead of lnot!!!
		gate2literal_map[gate] = neg(lit);

		/*
			literalt o = cnf.new_variable();
			cnf.lxor(lit, cnf.constant(true), o);
			gate2literal_map[gate] = o;
		*/

		break;
	}
	case simple_circuitt::XOR:
	{
		translate_gate(cnf, gate->fanin0, gate2literal_map);
		translate_gate(cnf, gate->fanin1, gate2literal_map);
		assert(gate2literal_map.find(gate->fanin0) != gate2literal_map.end());
		assert(gate2literal_map.find(gate->fanin1) != gate2literal_map.end());
		literalt lit_0 = gate2literal_map[gate->fanin0];
		literalt lit_1 = gate2literal_map[gate->fanin1];
		gate2literal_map[gate] = cnf.lxor(lit_0, lit_1);
		break;
	}
	case simple_circuitt::AND:
	{
		translate_gate(cnf, gate->fanin0, gate2literal_map);
		translate_gate(cnf, gate->fanin1, gate2literal_map);
		assert(gate2literal_map.find(gate->fanin0) != gate2literal_map.end());
		assert(gate2literal_map.find(gate->fanin1) != gate2literal_map.end());
		literalt lit_0 = gate2literal_map[gate->fanin0];
		literalt lit_1 = gate2literal_map[gate->fanin1];
		gate2literal_map[gate] = cnf.land(lit_0, lit_1);
		break;
	}
	case simple_circuitt::OR:
	{
		translate_gate(cnf, gate->fanin0, gate2literal_map);
		translate_gate(cnf, gate->fanin1, gate2literal_map);
		assert(gate2literal_map.find(gate->fanin0) != gate2literal_map.end());
		assert(gate2literal_map.find(gate->fanin1) != gate2literal_map.end());
		literalt lit_0 = gate2literal_map[gate->fanin0];
		literalt lit_1 = gate2literal_map[gate->fanin1];
		gate2literal_map[gate] = cnf.lor(lit_0, lit_1);
		break;
	}
	default:
	{
		assert(0);
	}
	}
}

bool simple_circuitt::are_equivalent(gatet* gate1, gatet* gate2, interpretationt& interpretation) {
	message_handler.status() << "Running SAT-based equivalence check" << messaget::eom;

	satcheckt cnf;

	gate2literal_mapt gate2literal_map;

	translate_gate(cnf, gate1, gate2literal_map);
	translate_gate(cnf, gate2, gate2literal_map);

	literalt lit1 = gate2literal_map[gate1];
	literalt lit2 = gate2literal_map[gate2];

	literalt lit_equal = cnf.lequal(lit1, lit2);

	cnf.l_set_to(lit_equal, false);

	propt::resultt result = cnf.prop_solve();

	if (result == propt::P_SATISFIABLE) {
		interpretation[ONE_GATE] = true;
		interpretation[ZERO_GATE] = false;

		for (gatet* gate_it = input_gates_HEAD; gate_it != NULL; gate_it = gate_it->next) {
			gate2literal_mapt::iterator jt = gate2literal_map.find(gate_it);

			if (jt == gate2literal_map.end()) {
				// gate does not depend on this input gate
				interpretation[gate_it] = true;
			}
			else {
				tvt result = cnf.l_get(jt->second);

				if (result.is_true()) {
					interpretation[gate_it] = true;
				}
				else if (result.is_false()) {
					interpretation[gate_it] = false;
				}
				else {
					::std::cerr << "ERROR: " << __FILE__ << "@" << __LINE__ << ::std::endl;
					exit(EXIT_FAILURE);
				}
			}
		}
	}

	assert(result != propt::P_ERROR);

	return (result == propt::P_UNSATISFIABLE);
}

// checks whether gate1 implies gate2
bool simple_circuitt::implication(gatet* gate1, gatet* gate2, interpretationt& interpretation) {
	satcheckt cnf;

	gate2literal_mapt gate2literal_map;

	translate_gate(cnf, gate1, gate2literal_map);
	translate_gate(cnf, gate2, gate2literal_map);

	literalt lit1 = gate2literal_map[gate1];
	literalt lit2 = gate2literal_map[gate2];

	literalt lit_implies = cnf.limplies(lit1, lit2);

	cnf.l_set_to(lit_implies, false);

	propt::resultt result = cnf.prop_solve();

	if (result == propt::P_SATISFIABLE) {
		interpretation[ONE_GATE] = true;
		interpretation[ZERO_GATE] = false;

		for (gatet* gate_it = input_gates_HEAD; gate_it != NULL; gate_it = gate_it->next) {
			gate2literal_mapt::iterator jt = gate2literal_map.find(gate_it);

			if (jt == gate2literal_map.end()) {
				// gate does not depend on this input gate
				interpretation[gate_it] = true;
			}
			else {
				tvt result = cnf.l_get(jt->second);

				if (result.is_true()) {
					interpretation[gate_it] = true;
				}
				else if (result.is_false()) {
					interpretation[gate_it] = false;
				}
				else {
					::std::cerr << "ERROR: " << __FILE__ << "@" << __LINE__ << ::std::endl;
					exit(EXIT_FAILURE);
				}
			}
		}
	}

	return (result == propt::P_UNSATISFIABLE);
}

bool simple_circuitt::evaluates_to_constant_(gatet* gate, bool constant_value, interpretationt& interpretation, bool& canceled) {
	satcheckt cnf;

	gate2literal_mapt gate2literal_map;

	translate_gate(cnf, gate, gate2literal_map);

	/*if (gate2literal_map.size() > 5000) {
		canceled = true;
		return false;
	}*/

	assert(gate2literal_map.find(gate) != gate2literal_map.end());

	literalt lit = gate2literal_map[gate];

	cnf.l_set_to(lit, constant_value);

	propt::resultt result = cnf.prop_solve();

	if (result == propt::P_SATISFIABLE) {
		interpretation[ONE_GATE] = true;
		interpretation[ZERO_GATE] = false;

		for (gatet* gate_it = input_gates_HEAD; gate_it != NULL; gate_it = gate_it->next) {
			gate2literal_mapt::iterator jt = gate2literal_map.find(gate_it);

			if (jt == gate2literal_map.end()) {
				// gate does not depend on this input gate
				interpretation[gate_it] = true;
			}
			else {
				tvt result = cnf.l_get(jt->second);

				if (result.is_true()) {
					interpretation[gate_it] = true;
				}
				else if (result.is_false()) {
					interpretation[gate_it] = false;
				}
				else {
					::std::cerr << "ERROR: " << __FILE__ << "@" << __LINE__ << ::std::endl;
					exit(EXIT_FAILURE);
				}
			}
		}
	}

	return (result == propt::P_UNSATISFIABLE);
}

bool simple_circuitt::evaluates_to_constant(gatet& gate, bool& value) {
	assert(false);

#if 0
	if (evaluates_to_constant_(&gate, true)) {
		value = false;

		return true;
	}
	else if (evaluates_to_constant_(&gate, false)) {
		value = true;

		return true;
	}
#endif

	return false;
}

void simple_circuitt::initialize_interpretation(interpretationt& interpretation) {
	interpretation[ONE_GATE] = true;
	interpretation[ZERO_GATE] = false;

	// initializes all inputs to false
	for (gatet* gate = input_gates_HEAD; gate != NULL; gate = gate->next) {
		interpretation[gate] = false;
	}
}

void simple_circuitt::simulate(interpretationt& interpretation) {
	// we assume that the interpretation has initialized ONE, ZERO and all inputs
	assert(interpretation.find(ONE_GATE) != interpretation.end());
	//assert(interpretation.find(ZERO_GATE) != interpretation.end());

	for (gatet* gate = input_gates_HEAD; gate != NULL; gate = gate->next) {
		assert(interpretation.find(gate) != interpretation.end());
	}


	// perform simulation

	simple_circuit_level_mapt level_map;
	simple_circuit_level_sett level_set;

	for (gatet* gate_it = gates_HEAD; gate_it != NULL; gate_it = gate_it->next) {
		// determine level
		simple_circuit_get_depth(*this, gate_it, level_map, &level_set);
	}

	for (unsigned i = 1; i <= level_set.size(); i++) {
		::std::set< gatet* >* set = level_set[i];

		assert(set);

		for (::std::set< gatet* >::iterator it = set->begin(); it != set->end(); ++it) {
			gatet* gate = *it;

			assert(interpretation.find(gate) == interpretation.end());

			switch (gate->get_operation()) {
			case INPUT:
			case OUTPUT:
			case ONE:
				assert(false);
				break;
			case AND:
			{
				interpretationt::iterator fanin0_it = interpretation.find(gate->fanin0);
				interpretationt::iterator fanin1_it = interpretation.find(gate->fanin1);
				assert(fanin0_it != interpretation.end());
				assert(fanin1_it != interpretation.end());
				interpretation[gate] = (fanin0_it->second && fanin1_it->second);
				break;
			}
			case OR:
			{
				interpretationt::iterator fanin0_it = interpretation.find(gate->fanin0);
				interpretationt::iterator fanin1_it = interpretation.find(gate->fanin1);
				assert(fanin0_it != interpretation.end());
				assert(fanin1_it != interpretation.end());
				interpretation[gate] = (fanin0_it->second || fanin1_it->second);
				break;
			}
			case NOT:
			{
				interpretationt::iterator fanin0_it = interpretation.find(gate->fanin0);
				assert(fanin0_it != interpretation.end());
				interpretation[gate] = !(fanin0_it->second);
				break;
			}
			case XOR:
			{
				interpretationt::iterator fanin0_it = interpretation.find(gate->fanin0);
				interpretationt::iterator fanin1_it = interpretation.find(gate->fanin1);
				assert(fanin0_it != interpretation.end());
				assert(fanin1_it != interpretation.end());
				interpretation[gate] = (fanin0_it->second != fanin1_it->second);
				break;
			}
			}
		}

		// we do not need set anymore, so delete it
		delete set;
	}
}

void simple_circuitt::simulate_2(interpretationt& interpretation, simple_circuit_level_sett level_set, timeout_datat& data) {
	// we assume that the interpretation has initialized ONE, ZERO and all inputs
	assert(interpretation.find(ONE_GATE) != interpretation.end());
	//assert(interpretation.find(ZERO_GATE) != interpretation.end());

	for (gatet* gate = input_gates_HEAD; gate != NULL; gate = gate->next) {
		assert(interpretation.find(gate) != interpretation.end());
	}

	for (unsigned i = 1; i <= level_set.size() && !timeout(data); i++) {
		::std::set< gatet* >* set = level_set[i];

		assert(set);

		for (::std::set< gatet* >::iterator it = set->begin(); it != set->end() && !timeout(data); ++it) {
			gatet* gate = *it;

			assert(interpretation.find(gate) == interpretation.end());

			switch (gate->get_operation()) {
			case INPUT:
			case OUTPUT:
			case ONE:
				assert(false);
				break;
			case AND:
			{
				interpretationt::iterator fanin0_it = interpretation.find(gate->fanin0);
				interpretationt::iterator fanin1_it = interpretation.find(gate->fanin1);
				assert(fanin0_it != interpretation.end());
				assert(fanin1_it != interpretation.end());
				interpretation[gate] = (fanin0_it->second && fanin1_it->second);
				break;
			}
			case OR:
			{
				interpretationt::iterator fanin0_it = interpretation.find(gate->fanin0);
				interpretationt::iterator fanin1_it = interpretation.find(gate->fanin1);
				assert(fanin0_it != interpretation.end());
				assert(fanin1_it != interpretation.end());
				interpretation[gate] = (fanin0_it->second || fanin1_it->second);
				break;
			}
			case NOT:
			{
				interpretationt::iterator fanin0_it = interpretation.find(gate->fanin0);
				assert(fanin0_it != interpretation.end());
				interpretation[gate] = !(fanin0_it->second);
				break;
			}
			case XOR:
			{
				interpretationt::iterator fanin0_it = interpretation.find(gate->fanin0);
				interpretationt::iterator fanin1_it = interpretation.find(gate->fanin1);
				assert(fanin0_it != interpretation.end());
				assert(fanin1_it != interpretation.end());
				interpretation[gate] = (fanin0_it->second != fanin1_it->second);
				break;
			}
			}
		}
	}
}

void simple_circuitt::stupid_simulation(::std::set< gatet* >& subcircuit, interpretationt& interpretation) {
	::std::list< gatet* > worklist;

	for (::std::set< gatet* >::iterator it = subcircuit.begin(); it != subcircuit.end(); ++it) {
		gatet* gate = *it;

		worklist.push_back(gate);
	}

	while (!worklist.empty()) {
		gatet* gate = worklist.front();
		worklist.pop_front();

		if (interpretation.find(gate) != interpretation.end()) {
			continue;
		}

		switch (gate->get_operation()) {
		case INPUT:
		case OUTPUT:
		case ONE:
			assert(false);
			break;
		case AND:
		{
			interpretationt::iterator fanin0_it = interpretation.find(gate->fanin0);
			interpretationt::iterator fanin1_it = interpretation.find(gate->fanin1);
			if (fanin0_it == interpretation.end() || fanin1_it == interpretation.end()) {
				worklist.push_back(gate);
				continue;
			}
			interpretation[gate] = (fanin0_it->second && fanin1_it->second);
			break;
		}
		case OR:
		{
			interpretationt::iterator fanin0_it = interpretation.find(gate->fanin0);
			interpretationt::iterator fanin1_it = interpretation.find(gate->fanin1);
			if (fanin0_it == interpretation.end() || fanin1_it == interpretation.end()) {
				worklist.push_back(gate);
				continue;
			}
			interpretation[gate] = (fanin0_it->second || fanin1_it->second);
			break;
		}
		case NOT:
		{
			interpretationt::iterator fanin0_it = interpretation.find(gate->fanin0);
			if (fanin0_it == interpretation.end()) {
				worklist.push_back(gate);
				continue;
			}
			interpretation[gate] = !(fanin0_it->second);
			break;
		}
		case XOR:
		{
			interpretationt::iterator fanin0_it = interpretation.find(gate->fanin0);
			interpretationt::iterator fanin1_it = interpretation.find(gate->fanin1);
			if (fanin0_it == interpretation.end() || fanin1_it == interpretation.end()) {
				worklist.push_back(gate);
				continue;
			}
			interpretation[gate] = (fanin0_it->second != fanin1_it->second);
			break;
		}
		}
	}
}
