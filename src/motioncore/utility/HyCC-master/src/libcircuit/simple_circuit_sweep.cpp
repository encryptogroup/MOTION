/*
 * simple_circuit_sweep.cpp
 *
 *  Created on: 08.10.2013
 *      Author: andreas
 */

#include "simple_circuit.h"
#include "equivalence_checker.h"

#include <map>

bool simple_circuitt::check_gate(equivalence_checkert *checker, gatet*& gate, bool boolean_value, interpretationt& tmp_interpretation) {
	gate->was_checked_for_being_constant = true;

	bool canceled = false;

	// deactivated cancel for the moment!
	if (evaluates_to_constant_(checker, gate, boolean_value, tmp_interpretation, canceled)) {
		// gate has the constant value boolean_value
		return true;
	}

	return false;
}

bool simple_circuitt::sweep(equivalence_checkert *checker, gatet*& constant_gate, bool& value, interpretationt interpretation) {
	m_logger->info() << "[SIMULATION] ..." << eom;

	// we have to rerun the simulation because gate addresses might have been reused
	simulate(interpretation);

	m_logger->info() << "[SWEEP] start" << eom;

	unsigned counter = 0;

	simple_circuit_level_mapt level_map;
	simple_circuit_level_sett level_set;

	for (gatet* gate_it = gates_HEAD; gate_it != NULL; gate_it = gate_it->next) {
		// determine level
		simple_circuit_get_depth(gate_it, level_map, &level_set);
	}

    for(auto level_it = level_set.begin(); level_it != level_set.end(); ++level_it) {
		::std::set< gatet* >* set = level_it->second.gates;

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

					if (evaluates_to_constant_(checker, gate, (sim_it->second), tmp_interpretation, canceled)) {
						// gate has the constant value sim_it->second
						value = sim_it->second;

						constant_gate = gate;

						return true;
					}
					else if (!canceled) {
						simulate(tmp_interpretation);

						for (auto j = level_it; j != level_set.end(); ++j) {
							::std::set< gatet* >* set_j = j->second.gates;

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
						m_logger->info() << "[SWEEP] end" << eom;

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

			if (m_logger->level() >= log_levelt::debug) {
				if (counter % 100 == 0) {
					::std::cout << counter << "/" << get_number_of_gates() << ::std::endl;
				}
			}
		}
	}

	// cleanup
	for (unsigned i = 1; i <= level_set.size(); i++) {
		::std::set< gatet* >* set = level_set[i].gates;

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

	m_logger->info() << "[SWEEP] end" << eom;

	return false;
}



bool simple_circuitt::are_equivalent(equivalence_checkert *checker, gatet* gate1, gatet* gate2, interpretationt& interpretation) {
	m_logger->info() << "Running SAT-based equivalence check" << eom;

	auto result = checker->equals(gate1, gate2);

	if (!result->success()) {
		interpretation[ONE_GATE] = true;
		interpretation[ZERO_GATE] = false;

		for (gatet* gate_it = input_gates_HEAD; gate_it != NULL; gate_it = gate_it->next) {
			if(auto value = result->find_value(gate_it)) {
				if (*value == tri_true) {
					interpretation[gate_it] = true;
				}
				else if (*value == tri_false) {
					interpretation[gate_it] = false;
				}
				else {
					::std::cerr << "ERROR: " << __FILE__ << "@" << __LINE__ << ::std::endl;
					exit(EXIT_FAILURE);
				}
			}
			else {
				// gate does not depend on this input gate
				interpretation[gate_it] = true;
			}

		}
	}

	return result->success();
}

// checks whether gate1 implies gate2
/*bool simple_circuitt::implication(gatet* gate1, gatet* gate2, interpretationt& interpretation) {
	satcheckt cnf;

	gate2literal_mapt gate2literal_map;

	translate_gate(cnf, gate1, gate2literal_map);
	translate_gate(cnf, gate2, gate2literal_map);

	literalt lit1 = gate2literal_map[gate1];
	literalt lit2 = gate2literal_map[gate2];

	literalt lit_implies = cnf.limplies(lit1, lit2);

	cnf.l_set_to(lit_implies, false);

	propt::resultt result = cnf.prop_solve();

	if (result == propt::resultt::P_SATISFIABLE) {
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

	return (result == propt::resultt::P_UNSATISFIABLE);
}*/

bool simple_circuitt::evaluates_to_constant_(equivalence_checkert *checker, gatet* gate, bool constant_value, interpretationt& interpretation, bool& canceled) {

	/*if (gate2literal_map.size() > 5000) {
		canceled = true;
		return false;
	}*/

	auto result = checker->equals(gate, !constant_value);

	if (!result->success()) {
		interpretation[ONE_GATE] = true;
		interpretation[ZERO_GATE] = false;

		for (gatet* gate_it = input_gates_HEAD; gate_it != NULL; gate_it = gate_it->next) {
			if(auto value = result->find_value(gate_it)) {
				if (*value == tri_true) {
					interpretation[gate_it] = true;
				}
				else if (*value == tri_false) {
					interpretation[gate_it] = false;
				}
				else {
					::std::cerr << "ERROR: " << __FILE__ << "@" << __LINE__ << ::std::endl;
					exit(EXIT_FAILURE);
				}
			}
			else {
				// gate does not depend on this input gate
				interpretation[gate_it] = true;
			}
		}
	}

	return result->success();
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
		simple_circuit_get_depth(gate_it, level_map, &level_set);
	}

    for(auto &pair: level_set) {
		::std::set< gatet* >* set = pair.second.gates;

		assert(set);

		for (::std::set< gatet* >::iterator it = set->begin(); it != set->end(); ++it) {
			gatet* gate = *it;

			assert(interpretation.find(gate) == interpretation.end());

			switch (gate->get_operation()) {
				default:
				assert(false);
				break;
			case AND:
			{
				interpretationt::iterator fanin0_it = interpretation.find(gate->get_fanin(0));
				interpretationt::iterator fanin1_it = interpretation.find(gate->get_fanin(1));
				assert(fanin0_it != interpretation.end());
				assert(fanin1_it != interpretation.end());
				interpretation[gate] = (fanin0_it->second && fanin1_it->second);
				break;
			}
			case OR:
			{
				interpretationt::iterator fanin0_it = interpretation.find(gate->get_fanin(0));
				interpretationt::iterator fanin1_it = interpretation.find(gate->get_fanin(1));
				assert(fanin0_it != interpretation.end());
				assert(fanin1_it != interpretation.end());
				interpretation[gate] = (fanin0_it->second || fanin1_it->second);
				break;
			}
			case NOT:
			{
				interpretationt::iterator fanin0_it = interpretation.find(gate->get_fanin(0));
				assert(fanin0_it != interpretation.end());
				interpretation[gate] = !(fanin0_it->second);
				break;
			}
			case XOR:
			{
				interpretationt::iterator fanin0_it = interpretation.find(gate->get_fanin(0));
				interpretationt::iterator fanin1_it = interpretation.find(gate->get_fanin(1));
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
		::std::set< gatet* >* set = level_set[i].gates;

		assert(set);

		for (::std::set< gatet* >::iterator it = set->begin(); it != set->end() && !timeout(data); ++it) {
			gatet* gate = *it;

			assert(interpretation.find(gate) == interpretation.end());

			switch (gate->get_operation()) {
				default:
				assert(false);
				break;
			case AND:
			{
				interpretationt::iterator fanin0_it = interpretation.find(gate->get_fanin(0));
				interpretationt::iterator fanin1_it = interpretation.find(gate->get_fanin(1));
				assert(fanin0_it != interpretation.end());
				assert(fanin1_it != interpretation.end());
				interpretation[gate] = (fanin0_it->second && fanin1_it->second);
				break;
			}
			case OR:
			{
				interpretationt::iterator fanin0_it = interpretation.find(gate->get_fanin(0));
				interpretationt::iterator fanin1_it = interpretation.find(gate->get_fanin(1));
				assert(fanin0_it != interpretation.end());
				assert(fanin1_it != interpretation.end());
				interpretation[gate] = (fanin0_it->second || fanin1_it->second);
				break;
			}
			case NOT:
			{
				interpretationt::iterator fanin0_it = interpretation.find(gate->get_fanin(0));
				assert(fanin0_it != interpretation.end());
				interpretation[gate] = !(fanin0_it->second);
				break;
			}
			case XOR:
			{
				interpretationt::iterator fanin0_it = interpretation.find(gate->get_fanin(0));
				interpretationt::iterator fanin1_it = interpretation.find(gate->get_fanin(1));
				assert(fanin0_it != interpretation.end());
				assert(fanin1_it != interpretation.end());
				interpretation[gate] = (fanin0_it->second != fanin1_it->second);
				break;
			}
			}
		}
	}
}

