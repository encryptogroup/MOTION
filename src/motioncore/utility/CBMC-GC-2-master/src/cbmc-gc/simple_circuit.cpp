/*
 * simple_circuit.cpp
 *
 *  Created on: 25.09.2013
 *      Author: andreas
 */

#include "simple_circuit.h"
#include "LUT_gate.h"

#include <fstream>
#include <sstream>

#include <set>
#include <stack>
#include <list>
#include <vector>

#include <ctime>
#include <climits>

// use them if you want to check out structurization or AIG conversion (experimental)
//#define STRUCTURIZE
//#define CONVERT_AIG

int simple_circuitt::simple_circuit_get_depth(simple_circuitt& circuit, simple_circuitt::gatet* gate, simple_circuitt::simple_circuit_level_mapt& level_map, simple_circuit_level_sett* level_set) {
	simple_circuitt::simple_circuit_level_mapt::iterator it = level_map.find(gate);

    if (it != level_map.end()) {
        return it->second;
    }

    // @David: Just for debugging
	/*std::cout << gate->to_string() << " = " << gate->label;
    if (gate->fanin0) {
	    std::cout << '[' << gate->fanin0->to_string() << " = " << gate->fanin0->label << ']';
    }
    if (gate->fanin1) {
	    std::cout << '[' << gate->fanin1->to_string() << " = " << gate->fanin1->label << ']';
    }
	std::cout << std::endl;*/

    int depth = 0;
    int fanin0_depth = -1;
    int fanin1_depth = -1;

    if (gate->fanin0) {
    	fanin0_depth = simple_circuit_get_depth(circuit, gate->fanin0, level_map, level_set);
    }

    if (gate->fanin1) {
    	fanin1_depth = simple_circuit_get_depth(circuit, gate->fanin1, level_map, level_set);
    }

	if (fanin0_depth > fanin1_depth) {
		depth = fanin0_depth + 1;
	}
	else {
		depth = fanin1_depth + 1;
	}

    if (gate->get_operation() == LUT) {
    	LUT_gatet* l_gate = dynamic_cast<LUT_gatet*> (gate);
    	assert(l_gate);
    	int new_depth = -1;

    	for(std::set< std::pair< gatet*, unsigned > >::iterator fanin_it = l_gate->get_fanins()->begin(); fanin_it != l_gate->get_fanins()->end(); ++fanin_it) {
   			new_depth = simple_circuit_get_depth(circuit, (*fanin_it).first, level_map, level_set) + 1;
   			depth = (new_depth > depth)? new_depth : depth;
    	}
    }

	assert(depth >= 0);

	if (depth == 0) {
		assert(gate->get_operation() == simple_circuitt::INPUT || gate->get_operation() == simple_circuitt::ONE);

		// we do not store inputs in our level_map/level_set
		return depth;
	}

	level_map[gate] = depth;

	if (level_set) {
		simple_circuit_level_sett::iterator set_it = level_set->find(depth);

		::std::set< simple_circuitt::gatet* >* set;

		if (set_it == level_set->end()) {
			set = new ::std::set< simple_circuitt::gatet* >;
			(*level_set)[depth] = set;
		}
		else {
			set = set_it->second;
		}

		set->insert(gate);
	}

    return depth;
}

int simple_circuitt::simple_circuit_get_depth_nXOR(simple_circuitt& circuit, simple_circuitt::gatet* gate, simple_circuitt::simple_circuit_level_mapt& level_map) {
	simple_circuitt::simple_circuit_level_mapt::iterator it = level_map.find(gate);

	if (it != level_map.end())
		return it->second;

	int depth = 0;
	int fanin0_depth = -1;
	int fanin1_depth = -1;

	if (gate->fanin0)
		fanin0_depth = simple_circuit_get_depth_nXOR(circuit, gate->fanin0, level_map);

	if (gate->fanin1)
		fanin1_depth = simple_circuit_get_depth_nXOR(circuit, gate->fanin1, level_map);

	if (fanin0_depth > fanin1_depth)
		depth = fanin0_depth;

	else depth = fanin1_depth;

	if (gate->get_operation() != NOT && gate->get_operation() != XOR)
		depth++;

	if (gate->get_operation() == LUT) {
		LUT_gatet* l_gate = dynamic_cast<LUT_gatet*> (gate);
		assert(l_gate);
		int new_depth = -1;

		for(std::set< std::pair< gatet*, unsigned > >::iterator fanin_it = l_gate->get_fanins()->begin(); fanin_it != l_gate->get_fanins()->end(); ++fanin_it) {
			new_depth = simple_circuit_get_depth_nXOR(circuit, (*fanin_it).first, level_map);
			depth = (new_depth > depth)? new_depth : depth;
		}
	}

	assert(depth >= 0);

	// we do not store inputs in our level_map/level_set
	if (depth == 0)
		return depth;

	level_map[gate] = depth;

	return depth;
}

simple_circuitt::simple_circuitt(messaget& p_message_handler) : message_handler(p_message_handler), input_gates_HEAD(NULL), input_gates_TAIL(NULL), input_gates_SIZE(0), output_gates_HEAD(NULL), output_gates_TAIL(NULL), output_gates_SIZE(0), gates_HEAD(NULL), gates_TAIL(NULL), gates_SIZE(0) {
	ONE_GATE = new gatet(this, ONE);
	ZERO_GATE = new gatet(this, NOT);
	ZERO_GATE->add_fanin(*ONE_GATE, 0);
	clustering = 0;
	LUT_gates = new std::vector<gatet*>;
}

simple_circuitt::~simple_circuitt() {

	delete ZERO_GATE;
	delete ONE_GATE;

	gatet* gate = input_gates_HEAD;

	while (gate != NULL) {
		gatet* tmp_gate = gate->next;

		delete gate;

		gate = tmp_gate;
	}

	gate = output_gates_HEAD;

	while (gate != NULL) {
		gatet* tmp_gate = gate->next;

		delete gate;

		gate = tmp_gate;
	}

	gate = gates_HEAD;

	while (gate != NULL) {
		gatet* tmp_gate = gate->next;

		delete gate;

		gate = tmp_gate;
	}
}

simple_circuitt::gatet* simple_circuitt::get_or_create_zero_gate() {
	return ZERO_GATE;
}

simple_circuitt::gatet* simple_circuitt::get_or_create_gate(GATE_OP operation) {
	if (operation == ONE) {
		return ONE_GATE;
	}

	assert(operation != INPUT && operation != OUTPUT);

	gatet* gate;
	if (operation == LUT) {
		gate = new LUT_gatet(this, operation);
		LUT_gates->push_back(gate);
	}

	else gate = new gatet(this, operation);

	if (gates_HEAD == NULL) {
		assert(!gates_TAIL);

		gates_HEAD = gate;
		gates_TAIL = gate;
		gate->previous = NULL;
		gate->next = NULL;
	}
	else {
		assert(gates_TAIL);

		gate->previous = gates_TAIL;
		gates_TAIL->next = gate;
		gate->next = NULL;

		gates_TAIL = gate;
	}

	gates_SIZE++;

	assert(gates_HEAD && gates_TAIL);

	return gate;
}

simple_circuitt::gatet* simple_circuitt::create_input_gate(::std::string label) {
	gatet* gate = new gatet(this, INPUT);

	if (input_gates_HEAD == NULL) {
		assert(!input_gates_TAIL);

		input_gates_HEAD = gate;
		input_gates_TAIL = gate;
		gate->previous = NULL;
		gate->next = NULL;
	}
	else {
		assert(input_gates_TAIL);

		gate->previous = input_gates_TAIL;
		input_gates_TAIL->next = gate;
		gate->next = NULL;

		input_gates_TAIL = gate;
	}

	input_gates_SIZE++;

	gate->label = label;

	return gate;
}

simple_circuitt::gatet* simple_circuitt::create_output_gate(::std::string label) {
	gatet* gate = new gatet(this, OUTPUT);

	if (output_gates_HEAD == NULL) {
		assert(!output_gates_TAIL);

		output_gates_HEAD = gate;
		output_gates_TAIL = gate;
		gate->previous = NULL;
		gate->next = NULL;
	}
	else {
		assert(output_gates_TAIL);

		gate->previous = output_gates_TAIL;
		output_gates_TAIL->next = gate;
		gate->next = NULL;

		output_gates_TAIL = gate;
	}

	output_gates_SIZE++;

	gate->label = label;

	return gate;
}

unsigned simple_circuitt::get_number_of_gates() {
	return gates_SIZE;
}

simple_circuitt::gatet& simple_circuitt::get_one_gate() {
	return *ONE_GATE;
}

simple_circuitt::gatet& simple_circuitt::get_zero_gate() {
	return *ZERO_GATE;
}

void simple_circuitt::remove(gatet* gate) {
	assert(gate != ONE_GATE);
	assert(gate->get_operation() != INPUT);
	assert(gate->get_operation() != OUTPUT);

	if (gate->get_operation() == LUT) {
		LUT_gatet* l_gate = dynamic_cast<LUT_gatet*>(gate);
		assert(l_gate);

		for(unsigned index = 0; index < l_gate->get_fanins()->size(); index++)
			l_gate->remove_fanin_LUT(index);

		std::vector<gatet*>::iterator it2;
		for(std::vector<gatet*>::iterator it = LUT_gates->begin(); it != LUT_gates->end(); ++it) {
			if((*it) == l_gate) {
				it2 = it+1;
				LUT_gates->erase(it);
				it = it2;
			}
		}
	}

	else {
		gate->remove_fanin0();

		if (gate->fanin1)
			gate->remove_fanin1();
	}

	gate->remove_fanouts();

	if (gate->previous != NULL) {
		if (gate->next != NULL) {
			gate->previous->next = gate->next;
			gate->next->previous = gate->previous;
		}
		else { // gate->next == NULL
			assert(gate == gates_TAIL);

			gate->previous->next = NULL;
			gates_TAIL = gate->previous;
		}
	}
	else if (gate->next != NULL) { // gate->previous == NULL
		assert(gate == gates_HEAD);

		gate->next->previous = NULL;
		gates_HEAD = gate->next;
	}
	else {
		gates_HEAD = NULL;
		gates_TAIL = NULL;
	}

	gates_SIZE--;

	delete gate;
	gate = NULL;
}

bool simple_circuitt::zero_gate_is_used() {
	return !(ZERO_GATE->fanouts.empty());
}

bool simple_circuitt::is_one_gate_actually_used() {
	assert(ONE_GATE->fanouts.size() >= 1); // we are always connected to ZERO_GATE

	if (ZERO_GATE->fanouts.size() > 0) { // ONE_GATE is used transitively used via used ZERO_GATE
		return true;
	}

	for (gatet::fanoutst::iterator it = ONE_GATE->fanouts.begin(); it != ONE_GATE->fanouts.end(); ++it) {
		gatet::fanoutt* fanout = *it;

		if (fanout->first != ZERO_GATE) {
			return true;
		}
	}

	// return false if there are no fanouts or the only fanout is going to ZERO_GATE and ZERO_GATE has no fanouts
	return false;
}

bool simple_circuitt::refine_bins(binst& bins, interpretationt& interpretation) {
	binst tmp_bins;

	for (binst::iterator it = bins.begin(); it != bins.end(); /*++it*/) {
		bint* bin = *it;

		assert(!bin->empty());

		bint* new_bin = NULL;

		bint::iterator bin_it = bin->begin();
		gatet* representing_gate = *bin_it;

		interpretationt::iterator rg_sim_it = interpretation.find(representing_gate);

		assert(rg_sim_it != interpretation.end());

		bin_it++;

		for (; bin_it != bin->end(); ) {
			interpretationt::iterator sim_it = interpretation.find(*bin_it);

			assert(sim_it != interpretation.end());

			if (rg_sim_it->second != sim_it->second) {
				if (!new_bin) {
					new_bin = new bint;
					tmp_bins.push_back(new_bin);
				}

				new_bin->push_back(sim_it->first);
				bin_it = bin->erase(bin_it);
			}
			else {
				++bin_it;
			}
		}

		assert(!bin->empty());

		if (bin->size() == 1) {
			bin->front()->was_checked_for_being_constant = true;
			// we will not use this bin anymore in later stages, so we can delete it
			it = bins.erase(it);
			delete bin;
		}
		else {
			++it;
		}
	}
	if (!tmp_bins.empty()) {
		for (binst::iterator it = tmp_bins.begin(); it != tmp_bins.end(); ++it) {
			// the moment a bin is stored in bins, we only remove elements, so we can not store all bins which contain only one element
			bint* bin = *it;

			if (bin->size() > 1) {
				bins.push_back(bin);
			}
			else {
				bin->front()->was_checked_for_being_constant = true;
				delete bin;
			}
		}

		return true;
	}

	return false;
}

void simple_circuitt::determine_structural_redundancy(binst& bins, interpretationst& interpretations, timeout_datat& data) {
	message_handler.status() << "Approximating structural redundancy..." << messaget::eom;

	int threshold = 0;

#define USE_SIMULATE_2 1

#if USE_SIMULATE_2
	simple_circuit_level_mapt level_map;
	simple_circuit_level_sett level_set;

	for (gatet* gate_it = gates_HEAD; gate_it != NULL; gate_it = gate_it->next) {
		if (timeout(data)) {
			// clean up level_set
			for (unsigned i = 1; i <= level_set.size(); i++) {
				::std::set< gatet* >* set = level_set[i];

				delete set;
			}

			return;
		}

		// determine level
		simple_circuit_get_depth(*this, gate_it, level_map, &level_set);
	}
#endif

	if (timeout(data)) {
#if USE_SIMULATE_2
		// clean up level_set
		for (unsigned i = 1; i <= level_set.size(); i++) {
			::std::set< gatet* >* set = level_set[i];

			delete set;
		}
#endif

		return;
	}

	do {
		if (message_handler.get_message_handler().get_verbosity() >= 9) {
			::std::cout << "." << ::std::flush;
		}
		interpretationt interpretation;

		interpretation[ONE_GATE] = true;
		interpretation[ZERO_GATE] = false;

		// initializes all inputs to false
		for (gatet* gate = input_gates_HEAD; gate != NULL; gate = gate->next) {
			interpretation[gate] = (rand()%2 == 0);
		}

		interpretationt* stored_interpretation = new interpretationt(interpretation);

#if USE_SIMULATE_2
		simulate_2(interpretation, level_set, data);
#else
		simulate(interpretation);
#endif

		if (!timeout(data) && refine_bins(bins, interpretation)) {
			interpretations.push_back(stored_interpretation);
			threshold = 0;
		}
		else {
			delete stored_interpretation; // interpretation didn't show a new behavior, so we can skip it
			threshold++;
		}
	} while (threshold < 10 && !timeout(data));

#if USE_SIMULATE_2
	// clean up level_set
	for (unsigned i = 1; i <= level_set.size(); i++) {
		::std::set< gatet* >* set = level_set[i];

		delete set;
	}
#endif

	message_handler.status() << "Done approximating structural redundancy!" << messaget::eom;
}

#if 0
class depth_comparator {
public:
	simple_circuitt::simple_circuit_level_mapt& level_map;

	bool compare(simple_circuitt::gatet* gate1, simple_circuitt::gatet* gate2) {

		return false;
	}
};
#endif

void simple_circuitt::init_timeout_data(bool check_timeout, double time_budget, timeout_datat& data) {
	data.check_timeout = check_timeout;
	data.time_budget = time_budget;
	data.start_time = time(NULL);
	data.stopping_because_of_timeout = false;
}

bool simple_circuitt::timeout(timeout_datat& data) { //bool check_timeout, time_t start_time, double time_budget, bool& stopping_because_of_timeout) {
	if (data.stopping_because_of_timeout) { // if we are already stopping because of timeout then we don't have to check anymore
		return true;
	}

	if (!data.check_timeout) {
		data.stopping_because_of_timeout = false;
		return false;
	}

	time_t current_time = time(NULL);
	double seconds = difftime(current_time, data.start_time);

	if (seconds > data.time_budget) {
		data.stopping_because_of_timeout = true;
		return true;
	}
	else {
		data.stopping_because_of_timeout = false;
		return false;
	}
}

void simple_circuitt::order_bin(bint::iterator begin, bint::iterator end, simple_circuit_level_mapt& level_map, bint& ordered_bin /* out */) {
	// TODO use binary search instead of linear search?

	for (bint::iterator b_it = begin; b_it != end; ++b_it) {

		bint::iterator iter = ordered_bin.begin();

		for ( ; iter != ordered_bin.end(); ++iter) {
			if (level_map[*iter] > level_map[*b_it]) {
				break;
			}
		}

		ordered_bin.insert(iter, *b_it);
	}
}

bool simple_circuitt::equivalence_check_process_constants_bin(gatet* representative_gate, bint::iterator begin, bint::iterator end, simple_circuit_level_mapt& level_map, interpretationst& interpretations, timeout_datat& data) {
	bool changed_circuit = false;

	bint ordered_bin;

	order_bin(begin, end, level_map, ordered_bin);

	for (bint::iterator b_it = ordered_bin.begin(); b_it != ordered_bin.end() && !timeout(data); ++b_it) {

		interpretationt tmp_interpretation;

		if (check_gate(*b_it, false, tmp_interpretation)) {
			(*b_it)->replace_by(representative_gate);
			//break;
		}
		else {
			// TODO actually, this should be in the first bin ... (singleton bins should have been removed already!)
			// TODO it would be great if we could immediately refine the bins based on tmp_interpretation
			interpretationt* stored_interpretation = new interpretationt(tmp_interpretation);
			interpretations.push_back(stored_interpretation);

			// TODO replace by a more meaningful variable name (we want to refine bins)
			changed_circuit = true;
			break;
		}
	}

	return changed_circuit;
}

bool simple_circuitt::equivalence_check_process_regular_bin(bint::iterator begin, bint::iterator end, simple_circuit_level_mapt& level_map, interpretationst& interpretations, timeout_datat& data) {
	bool changed_circuit = false;

	bint ordered_bin;

	order_bin(begin, end, level_map, ordered_bin);

	if (message_handler.get_message_handler().get_verbosity() >= 9) {
		::std::cout << "iterating over ordered bin" << ::std::endl;
		::std::cout << "#elements in ordered bin: " << ordered_bin.size() << ::std::endl;
	}

	gatet* representative_gate = *(ordered_bin.begin());

	for (bint::iterator b_it = ++ordered_bin.begin(); b_it != ordered_bin.end() && !timeout(data); ++b_it) {

		interpretationt tmp_interpretation;

		if (are_equivalent(representative_gate, *b_it, tmp_interpretation)) {
			(*b_it)->replace_by(representative_gate);
			changed_circuit = true;
			//break;
		}
		else {
			// TODO actually, this should be in the first bin ... (singleton bins should have been removed already!)
			// TODO it would be great if we could immediately refine the bins based on tmp_interpretation
			interpretationt* stored_interpretation = new interpretationt(tmp_interpretation);
			interpretations.push_back(stored_interpretation);

			// TODO replace by a more meaningful variable name (we want to refine bins)
			changed_circuit = true;
			break;
		}
	}

	return changed_circuit;
}

void simple_circuitt::create_bins(interpretationst& interpretations, binst& bins /* out */, timeout_datat& data) {
	// TODO hmm, it would be nice if we could reuse the bins, but actually we might have changes in the circuit after checking for being constant
	bint* initial_bin = new bint;

	initial_bin->push_back(ONE_GATE);
	initial_bin->push_back(ZERO_GATE);

	// TODO äquivalenz mit input gates wird nicht geprüft: das könnte noch einiges bringen
	// TODO !!!!!!!!!!!
	// TODO !!!!!!!!!!!
	// TODO !!!!!!!!!!!
	// TODO !!!!!!!!!!!
	// TODO !!!!!!!!!!!
	// TODO !!!!!!!!!!!
	// TODO !!!!!!!!!!!
	// TODO !!!!!!!!!!!
	for (gatet* gate_it = gates_HEAD; gate_it != NULL && !timeout(data); gate_it = gate_it->next) {
		//if (!gate_it->was_checked_for_being_constant) { // do we miss some equivalences due to this optimization?
		initial_bin->push_back(gate_it);
		//}
	}

	bins.push_back(initial_bin);

	for (interpretationst::iterator it = interpretations.begin(); it != interpretations.end() && !timeout(data); ++it) {
		interpretationt* p_interpretation = *it;

		interpretationt interpretation(*p_interpretation);

		simulate(interpretation);

		refine_bins(bins, interpretation);

		//delete p_interpretation;
	}
}

bool simple_circuitt::equivalence_check_process_bin(bint& bin, simple_circuit_level_mapt& level_map, interpretationst& interpretations, timeout_datat& data) {
	assert(!bin.empty());

	if (bin.size() <= 1) {
		return false;
	}

	gatet* front_gate = bin.front();

	if (front_gate == ZERO_GATE || front_gate == ONE_GATE) {
		message_handler.print(9, "There are possible constant gates!");

		// TODO we should perform these checks ordered by the depth of the gates!
		return equivalence_check_process_constants_bin(front_gate, (++bin.begin()), bin.end(), level_map, interpretations, data);
	}
	else {
		if (message_handler.get_message_handler().get_verbosity() >= 9) {
			::std::cout << "investigating duplicated function" << ::std::endl;
			::std::cout << "#elements in bin: " << bin.size() << ::std::endl;
		}

		return equivalence_check_process_regular_bin(bin.begin(), bin.end(), level_map, interpretations, data);
	}

	return false;
}

/**
 * helper function to call use_theorems (needed because this is a member function)
 */
bool pointer_use_theorems(simple_circuitt::gatet* gate, bool round2, simple_circuitt* obj) {
	return obj->use_theorems(gate, round2);
}

/**
 * helper function to call convert_AIG (needed because this is a member function)
 */
bool pointer_convert_AIG(simple_circuitt::gatet* gate, bool round2, simple_circuitt* obj) {
	return obj->convert_AIG(gate, round2);
}

/**
 * helper function to call structurize (needed because this is a member function)
 */
bool pointer_structurize(simple_circuitt::gatet* gate, bool round2, simple_circuitt* obj) {
	return obj->structurize(gate, round2);
}

/**
 * helper function to call rewrite_old (needed because this is a member function)
 */
bool pointer_rewrite_old(simple_circuitt::gatet* gate, bool round2, simple_circuitt* obj) {
	return obj->rewrite_old(gate, round2);
}

/**
 * state machine used for choosing the next minimization method
 */
bool simple_circuitt::minimizing_state_machine(timeout_datat &data, MINIMIZER *min_op, bool *structure) {

	bool changed_circuit;

	switch (*min_op) {
	case OLD:
		if(!rewrite(data, &pointer_rewrite_old, false))
			*min_op = THEOREMS;
		break;
	case AIG:
		if(!rewrite(data, &pointer_convert_AIG, false))
			*min_op = THEOREMS;
		break;
	case THEOREMS:
		if(!rewrite(data, &pointer_use_theorems, false))
			*min_op = THEOREMS2;
		break;
	case THEOREMS2:
		if(!rewrite(data, &pointer_use_theorems, true)) {
			if(*structure)
				*min_op = STRUCTURE;
			else return false;
		}
		break;
	case STRUCTURE:
		if(!rewrite(data, &pointer_structurize, false)) {
			*min_op = THEOREMS;
			*structure = false;
		}
	}
	return true;
}

void simple_circuitt::minimize(bool limit_sat_iterations, int num_sat_iterations, double minimization_time_budget /* seconds */, bool no_state_machine) {

	interpretationst interpretations;

	interpretationt* interpretation = new interpretationt;
	initialize_interpretation(*interpretation);

	interpretations.push_back(interpretation);

	int nr_of_performed_sat_iterations = 0;

	time_t start_time = time(NULL);

	timeout_datat data;
	init_timeout_data((minimization_time_budget >= 0), minimization_time_budget, data);

	bool mode_rewrite = true;
	MINIMIZER min = THEOREMS;
	bool structure = false;
#ifdef STRUCTURIZE
	structure = true;
#endif
#ifdef CONVERT_AIG
	min = AIG;
#endif

	while (!timeout(data)) {
		message_handler.status() << "Start circuit rewriting..." << messaget::eom;

		if(no_state_machine)
			mode_rewrite = rewrite_no_state_machine(data);
		else
			mode_rewrite = minimizing_state_machine(data, &min, &structure);

		if (timeout(data)) {
			break;
		}

		message_handler.status() << "Done circuit rewriting." << messaget::eom;

		if (!mode_rewrite) {

			if (limit_sat_iterations && (nr_of_performed_sat_iterations >= num_sat_iterations)) {
				break;
			}

			nr_of_performed_sat_iterations++;

			::std::stringstream iteration_strstr;
			iteration_strstr << "SAT-based minimization iteration #" << nr_of_performed_sat_iterations << ".";
			message_handler.status() << iteration_strstr.str() << messaget::eom;

			bool changed_circuit = false;

			simple_circuit_level_mapt level_map;

			for (gatet* gate_it = gates_HEAD; gate_it != NULL && !timeout(data); gate_it = gate_it->next) {
				// determine level
				simple_circuit_get_depth(*this, gate_it, level_map, NULL);
			}

			if (timeout(data)) {
				break;
			}

			binst bins;
			create_bins(interpretations, bins, data);

			if (timeout(data)) {
				break;
			}

			determine_structural_redundancy(bins, interpretations, data);

			int cases = 0;

			if (message_handler.get_message_handler().get_verbosity() >= 9) {
				::std::cout << "Number of bins: " << bins.size() << ::std::endl;
			}

			unsigned bin_id = 0;

			for (binst::iterator it = bins.begin(); it != bins.end() && !timeout(data) /* && !changed_circuit*/; ++it) {

				if (message_handler.get_message_handler().get_verbosity() >= 9) {
					::std::cout << "bin #" << bin_id << "/" << bins.size() << ::std::endl;
				}

				bin_id++;

				bint* bin = *it;

				if (equivalence_check_process_bin(*bin, level_map, interpretations, data)) {
					changed_circuit = true;
				}

				cases++;
			}

			for (binst::iterator it = bins.begin(); it != bins.end(); ++it) {
				bint* bin = *it;
				delete bin;
			}

			if (message_handler.get_message_handler().get_verbosity() >= 9) {
				::std::cout << "We have " << cases << " possible cases of duplicated functions!" << ::std::endl;
			}

			if (!changed_circuit) {

#if 0 // something is wrong here!!!
				// TODO experimental feature
				::std::cout << "Experimental feature: subcircuits.." << ::std::endl;

				for (gatet* gate = gates_HEAD; gate != NULL && !changed_circuit; gate = gate->next) {

					//assert(//gate->get_operation)

					::std::cout << "." << ::std::flush;

					if (gate->get_operation() == NOT) {
						continue;
					}

					::std::set< gatet* > coi;

					//::std::cout << "<" << ::std::flush;
					assert(gate->fanin0);
					assert(gate->fanin1);
					cone_of_influence(gate->fanin0, coi);

					//if (gate->get_operation() != NOT) {
						cone_of_influence(gate->fanin1, coi);
					//}

					//::std::cout << ">" << ::std::flush;

					bool found = false;

					for (::std::set< gatet* >::iterator it = coi.begin(); it != coi.end() && !changed_circuit; ++it) {
						gatet* other_gate = *it;

						for (::std::set< gatet* >::iterator it2 = coi.begin(); it2 != coi.end() && !changed_circuit; ++it2) {
							gatet* other_gate2 = *it2;

							if ((gate->fanin0 == other_gate && gate->fanin1 == other_gate2) || (gate->fanin1 == other_gate && gate->fanin0 == other_gate2)) {
								continue;
							}

							if (is_two_dominator(gate, other_gate, other_gate2)) {
								found = true;

								::std::set< gatet* > subcircuit;
								get_subcircuit(gate, other_gate, other_gate2, subcircuit);

								// koennte es sein, dass ZERO_GATE/ONE_GATE dominator sind???? koennte das eine Fehlerquelle sein
								// TODO !!!!!!!!!!!
								// TODO !!!!!!!!!!!
								// TODO !!!!!!!!!!!
								// TODO !!!!!!!!!!!
								// TODO !!!!!!!!!!!
								// TODO !!!!!!!!!!!
								// TODO !!!!!!!!!!!
								// TODO !!!!!!!!!!!
								// TODO !!!!!!!!!!!
								// TODO !!!!!!!!!!!
								// TODO !!!!!!!!!!!
								// TODO !!!!!!!!!!!
								// TODO !!!!!!!!!!!
								// TODO !!!!!!!!!!!
								// TODO !!!!!!!!!!!


								//::std::cout << "********************************************" << ::std::endl;

								interpretationt interpretation;
								interpretation[other_gate] = false;
								interpretation[other_gate2] = false;
								interpretation[ONE_GATE] = true;
								interpretation[ZERO_GATE] = false;

								stupid_simulation(subcircuit, interpretation);

								assert(interpretation.find(gate) != interpretation.end());

								//::std::cout << "result: " << interpretation[gate] << ::std::endl;

								interpretationt interpretation2;
								interpretation2[other_gate] = false;
								interpretation2[other_gate2] = true;
								interpretation2[ONE_GATE] = true;
								interpretation2[ZERO_GATE] = false;

								stupid_simulation(subcircuit, interpretation2);

								assert(interpretation2.find(gate) != interpretation2.end());

								//::std::cout << "result: " << interpretation2[gate] << ::std::endl;

								interpretationt interpretation3;
								interpretation3[other_gate] = true;
								interpretation3[other_gate2] = false;
								interpretation3[ONE_GATE] = true;
								interpretation3[ZERO_GATE] = false;

								stupid_simulation(subcircuit, interpretation3);

								assert(interpretation3.find(gate) != interpretation3.end());

								//::std::cout << "result: " << interpretation3[gate] << ::std::endl;

								interpretationt interpretation4;
								interpretation4[other_gate] = true;
								interpretation4[other_gate2] = true;
								interpretation4[ONE_GATE] = true;
								interpretation4[ZERO_GATE] = false;

								stupid_simulation(subcircuit, interpretation4);

								assert(interpretation4.find(gate) != interpretation4.end());

								//::std::cout << "result: " << interpretation4[gate] << ::std::endl;

								//::std::cout << subcircuit.size() << ::std::endl;
								//::std::cout << ::std::endl;

								if (!interpretation[gate] && !interpretation4[gate] && interpretation2[gate] && interpretation3[gate]) {
									// XOR(other_gate, other_gate2)
									gatet* xor_gate = get_or_create_gate(XOR);
									xor_gate->add_fanin(*other_gate, 0);
									xor_gate->add_fanin(*other_gate2, 1);

									gate->replace_by(xor_gate);

									changed_circuit = true;
								}
								else if (!interpretation[gate] && interpretation2[gate] && interpretation3[gate] && interpretation4[gate]) {
									// OR(other_gate, other_gate2)
									if (gate->get_operation() != XOR) {
										assert(gate->get_operation() != NOT);

										gatet* or_gate = get_or_create_gate(OR);
										or_gate->add_fanin(*other_gate, 0);
										or_gate->add_fanin(*other_gate2, 1);

										gate->replace_by(or_gate);

										changed_circuit = true;

										//::std::cout << "I think we should replace this gate!" << ::std::endl;
									}
									/*bool only_xors = true;
									for (::std::set< gatet* >::iterator sc_it = subcircuit.begin(); sc_it != subcircuit.end(); ++sc_it) {
										if ((*sc_it)->get_operation() != XOR && (*sc_it)->get_operation() != NOT) {
											only_xors = false;
										}
									}*/
								}
								else if (!interpretation[gate] && !interpretation2[gate] && interpretation3[gate] && interpretation4[gate]) {
									//assert(false);

									// other_gate
									// TODO this case shouldn't happen since it should have been detected during the functional equality test!
									gate->replace_by(other_gate);

									changed_circuit = true;
								}
								else if (!interpretation[gate] && interpretation2[gate] && !interpretation3[gate] && interpretation4[gate]) {
									//assert(false);

									// other_gate2
									// TODO this case shouldn't happen since it should have been detected during the functional equality test!
									gate->replace_by(other_gate2);

									changed_circuit = true;
								}
								else if (interpretation[gate] && interpretation2[gate] && interpretation3[gate] && interpretation4[gate]) {
									gate->replace_by(ONE_GATE);

									changed_circuit = true;
								}
								else if (!interpretation[gate] && !interpretation2[gate] && !interpretation3[gate] && !interpretation4[gate]) {
									gate->replace_by(ZERO_GATE);

									changed_circuit = true;
								}
							}
						}
					}
				}

				::std::cout << ::std::endl;
#endif

				if (!changed_circuit && this->clustering) {
					print_stats();
					std::cout << std::endl;
					std::cout << "It's time to cluster some subcircuits :-)" << std::endl;
					std::cout << std::endl;

					std::vector<std::string*>* before = evaluate_simple_circuit();
					cluster();
					assert(verify_LUT_circuit(before));
					std::cout << "Built equivalent LUT circuit - WUHZA" << std::endl;
					std::cout << std::endl;
				}

				if (!changed_circuit) {
					break;
				}
				else {
					cleanup();
				}
			}
			else {
				cleanup();
			}

		}
	}

	if (data.stopping_because_of_timeout) {
		message_handler.status() << "Stopping minimization due to time out." << messaget::eom;
	}

	for (interpretationst::iterator it = interpretations.begin(); it != interpretations.end(); ++it) {
		interpretationt* interpretation = *it;
		delete interpretation;
	}

#if 0
	// TODO experimental feature
	::std::cout << "Experimental feature: subcircuits.." << ::std::endl;
	unsigned two_dom_counter = 0;
	for (gatet* gate = gates_HEAD; gate != NULL; gate = gate->next) {

		if (gate->get_operation() == NOT) {
			continue;
		}

		::std::set< gatet* > coi;

		cone_of_influence(gate->fanin0, coi);

		if (gate->get_operation() != NOT) {
			cone_of_influence(gate->fanin1, coi);
		}

		bool found = false;

		for (::std::set< gatet* >::iterator it = coi.begin(); it != coi.end(); ++it) {
			gatet* other_gate = *it;

			for (::std::set< gatet* >::iterator it2 = coi.begin(); it2 != coi.end(); ++it2) {
				gatet* other_gate2 = *it2;

				if ((gate->fanin0 == other_gate && gate->fanin1 == other_gate2) || (gate->fanin1 == other_gate && gate->fanin0 == other_gate2)) {
					continue;
				}

				if (is_two_dominator(gate, other_gate, other_gate2)) {
					found = true;

					::std::set< gatet* > subcircuit;
					get_subcircuit(gate, other_gate, other_gate2, subcircuit);

					::std::cout << "********************************************" << ::std::endl;

					interpretationt interpretation;
					interpretation[other_gate] = false;
					interpretation[other_gate2] = false;
					interpretation[ONE_GATE] = true;
					interpretation[ZERO_GATE] = false;

					stupid_simulation(subcircuit, interpretation);

					assert(interpretation.find(gate) != interpretation.end());

					::std::cout << "result: " << interpretation[gate] << ::std::endl;

					interpretationt interpretation2;
					interpretation2[other_gate] = false;
					interpretation2[other_gate2] = true;
					interpretation2[ONE_GATE] = true;
					interpretation2[ZERO_GATE] = false;

					stupid_simulation(subcircuit, interpretation2);

					assert(interpretation2.find(gate) != interpretation2.end());

					::std::cout << "result: " << interpretation2[gate] << ::std::endl;

					interpretationt interpretation3;
					interpretation3[other_gate] = true;
					interpretation3[other_gate2] = false;
					interpretation3[ONE_GATE] = true;
					interpretation3[ZERO_GATE] = false;

					stupid_simulation(subcircuit, interpretation3);

					assert(interpretation3.find(gate) != interpretation3.end());

					::std::cout << "result: " << interpretation3[gate] << ::std::endl;

					interpretationt interpretation4;
					interpretation4[other_gate] = true;
					interpretation4[other_gate2] = true;
					interpretation4[ONE_GATE] = true;
					interpretation4[ZERO_GATE] = false;

					stupid_simulation(subcircuit, interpretation4);

					assert(interpretation4.find(gate) != interpretation4.end());

					::std::cout << "result: " << interpretation4[gate] << ::std::endl;

					::std::cout << subcircuit.size() << ::std::endl;
					::std::cout << ::std::endl;
				}
			}
		}

		if (found) {
			two_dom_counter++;
		}
	}

	::std::cout << "two_dom_counter = " << two_dom_counter << ::std::endl;
#endif

	// TODO experimental feature
#if 0
	::std::cout << "Experimental feature: subcircuit identification" << ::std::endl;

	::std::cout << "a) determine depth" << ::std::endl;

	simple_circuit_level_mapt level_map;
	simple_circuit_level_sett level_set;

	for (gatet* gate_it = gates_HEAD; gate_it != NULL; gate_it = gate_it->next) {
		// determine level
		simple_circuit_get_depth(*this, gate_it, level_map, level_set);
	}

	::std::cout << "b) identify isolated subcircuits" << ::std::endl;

	for (gatet* gate_it = gates_HEAD; gate_it != NULL; gate_it = gate_it->next) {
		unsigned depth_of_dominator = level_map[gate_it];

		typedef ::std::set< gatet* > subcircuitt;
		typedef ::std::stack< gatet* > worklistt;

		subcircuitt subcircuit;
		subcircuit.insert(gate_it);

		worklistt worklist;
		worklist.push(gate_it);

		while (!worklist.empty()) {
			gatet* worklist_gate = worklist.top();
			worklist.pop();

			if (worklist_gate != gate_it) {
				if (is_postdominator(worklist_gate->fanin0, gate_it, level_map, depth_of_dominator)) {
					subcircuit.insert(worklist_gate->fanin0);
					worklist.push(worklist_gate->fanin0);
				}

				if (worklist_gate->get_operation() != NOT) {
					if (is_postdominator(worklist_gate->fanin1, gate_it, level_map, depth_of_dominator)) {
						subcircuit.insert(worklist_gate->fanin1);
						worklist.push(worklist_gate->fanin1);
					}
				}
			}
		}

		if (subcircuit.size() > 1) {
			::std::cout << "found some subcircuit to investigate" << ::std::endl;
		}
	}
#endif

	// TODO experimental feature
#if 0
	::std::cout << "Experimental feature: Implication check" << ::std::endl;
	for (gatet* gate_it = gates_HEAD; gate_it != NULL; gate_it = gate_it->next) {
		// determine level
		if (gate_it->operation == OR) {
			interpretationt tmp_interpretation;
			if (implication(gate_it->fanin0, gate_it->fanin1, tmp_interpretation)) {
				::std::cout << "OR: implication!!!" << ::std::endl;
			}
			else if (implication(gate_it->fanin1, gate_it->fanin0, tmp_interpretation)) {
				::std::cout << "OR: implication!!!" << ::std::endl;
			}
		}
		else if (gate_it->operation == AND) {
			interpretationt tmp_interpretation;
			if (implication(gate_it->fanin0, gate_it->fanin1, tmp_interpretation)) {
				::std::cout << "AND: implication!!!" << ::std::endl;
			}
			else if (implication(gate_it->fanin1, gate_it->fanin0, tmp_interpretation)) {
				::std::cout << "AND: implication!!!" << ::std::endl;
			}
		}
	}
#endif
}

void simple_circuitt::cone_of_influence(gatet* gate, ::std::set< gatet* >& coi) {
	assert(gate);

	if (coi.find(gate) != coi.end()) {
		return;
	}

	if (gate->get_operation() == INPUT || gate->get_operation() == ONE) {
		return;
	}

	assert(gate->get_operation() == AND || gate->get_operation() == OR || gate->get_operation() == NOT || gate->get_operation() == XOR);

	coi.insert(gate);

	assert(gate->fanin0);
	cone_of_influence(gate->fanin0, coi);

	if (gate->get_operation() != NOT) {
		assert(gate->fanin1);
		cone_of_influence(gate->fanin1, coi);
	}
}

void simple_circuitt::get_subcircuit(gatet* gate, gatet* dominator1, gatet* dominator2, ::std::set< gatet* >& subcircuit) {

	if (gate == dominator1) {
		return;
	}

	if (gate == dominator2) {
		return;
	}

	subcircuit.insert(gate);

	get_subcircuit(gate->fanin0, dominator1, dominator2, subcircuit);

	if (gate->get_operation() != NOT) {
		get_subcircuit(gate->fanin1, dominator1, dominator2, subcircuit);
	}
}

bool simple_circuitt::is_two_dominator(gatet* gate, gatet* dominator1, gatet* dominator2) {
	if (gate == dominator1 || gate == dominator2) {
		return true;
	}

	if (gate->get_operation() == INPUT || gate->get_operation() == ONE) {
		return false;
	}

	if (!is_two_dominator(gate->fanin0, dominator1, dominator2)) {
		return false;
	}

	if (gate->get_operation() != NOT) {
		if (!is_two_dominator(gate->fanin1, dominator1, dominator2)) {
			return false;
		}
	}

	return true;
}

bool simple_circuitt::is_postdominator(gatet* gate, gatet* dominator, simple_circuit_level_mapt& level_map, unsigned depth_of_dominator) {
	if (gate == dominator) {
		return true;
	}

	if (level_map[gate] >= depth_of_dominator || gate->fanouts.empty()) {
		return false;
	}

	for (gatet::fanoutst::iterator it = gate->fanouts.begin(); it != gate->fanouts.end(); ++it) {
		gatet::fanoutt* fanout = *it;

		if (!is_postdominator(fanout->first, dominator, level_map, depth_of_dominator)) {
			return false;
		}
	}

	return true;
}

void simple_circuitt::write_circuit_files(optionst& _options, mpc_io_mapping &variable_mapping) {
	::std::ofstream out, out_one, out_inputs, out_gates, out_bmec;
	out.open(_options.get_option("outdir") + "/output.numberofgates.txt");

	unsigned number_of_gates = get_number_of_gates();
	if (zero_gate_is_used()) {
		number_of_gates++;
	}

	out << number_of_gates << ::std::endl;
	out.close();

	out_one.open(_options.get_option("outdir") + "/output.constants.txt");
	out_inputs.open(_options.get_option("outdir") + "/output.inputs.txt");
	out_gates.open(_options.get_option("outdir") + "/output.gate.txt");
	
	translate(out_one, out_inputs, out_gates);
	// Conversion BMECC  
	if(_options.get_bool_option("bmec")) {
        throw std::runtime_error("bmec output currently disabled");
		/*out_bmec.open("output.bmec");
		mpc_framework_adapter convert_bmec; 
		translate_to_bmec(convert_bmec, variable_mapping, out_bmec, _options.get_bool_option("bmec-parallel"));*/
	}
	out_one.close();
	out_inputs.close();
	out_gates.close();

	statst stats = query_stats();
	std::ofstream stats_file{_options.get_option("outdir") + "/output.stats.txt"};
	stats_file << "non_xor_gates " << stats.num_non_xor_gates << '\n';
	stats_file << "non_xor_depth " << stats.non_xor_depth << '\n';
	stats_file << "total_gates " << stats.num_gates << '\n';
	stats_file << "total_depth " << stats.depth << '\n';

	std::ofstream outputs_file{_options.get_option("outdir") + "/output.mapping.txt"};
    for(auto &output: output_variables)
    {
      outputs_file << output.first << " INT" << output.second.size();
      for(auto gate: output.second)
        outputs_file << " " << gate->label.substr(1); // remove leading '-'

      outputs_file << '\n';
    }

	std::ofstream inputs_a_file{_options.get_option("outdir") + "/output.inputs.partyA.txt"};
    for(auto &input: input_a_variables)
    {
      inputs_a_file << input.first << " " << input.second.front()->label << ' ' << input.second.size();
      inputs_a_file << '\n';
    }

	std::ofstream inputs_b_file{_options.get_option("outdir") + "/output.inputs.partyB.txt"};
    for(auto &input: input_b_variables)
    {
      inputs_b_file << input.first << " " << input.second.front()->label << ' ' << input.second.size();
      inputs_b_file << '\n';
    }
}

void simple_circuitt::conditionally_write_dot_file(optionst& _options) {
	::std::ofstream out_dot;

	//if (andis_circuit.get_number_of_gates() < 1000) {
	if (_options.get_bool_option("print-circuit")) {
		unsigned int max_level = UINT_MAX;

		::std::string circuit_depth_str = _options.get_option("circuit-depth");
		if (!circuit_depth_str.empty()) {
			max_level = atoi(circuit_depth_str.c_str());
		}

		out_dot.open("output.circuit.dot");
		write_dot(out_dot, !circuit_depth_str.empty(), max_level);
		out_dot.close();
	}
	/*}
		else {
			::std::cerr << "[WARNING] Didn't write out dot file output.circuit.dot!" << ::std::endl;
		}*/
}

