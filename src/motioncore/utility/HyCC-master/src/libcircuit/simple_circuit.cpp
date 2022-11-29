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

int simple_circuitt::simple_circuit_get_depth(
	gatet* gate,
	simple_circuit_level_mapt& level_map,
	simple_circuit_level_sett* level_set) const
{
	simple_circuitt::simple_circuit_level_mapt::iterator it = level_map.find(gate);

    if (it != level_map.end()) {
      if(it->second == (unsigned)-1)
      {
        std::cout << gate->to_string() << " = " << gate << std::endl;
        throw std::logic_error{"Cycle in circuit"};
      }

        return it->second;
    }
    
	// we do not store inputs in our level_map/level_set
    if(gate->get_operation() != simple_circuitt::INPUT && gate->get_operation() != simple_circuitt::ONE)
      level_map[gate] = -1;

    // @David: Just for debugging
	/*std::cout << gate->to_string() << " = " << gate;
    if (gate->fanin0) {
	    std::cout << '[' << gate->fanin0->to_string() << " = " << gate->fanin0 << ']';
    }
    if (gate->fanin1) {
	    std::cout << '[' << gate->fanin1->to_string() << " = " << gate->fanin1 << ']';
    }
	std::cout << std::endl;*/

    int depth = -1;
	for(auto const &endpoint: gate->fanin_range())
    	depth = std::max(simple_circuit_get_depth(endpoint.gate, level_map, level_set), depth);

	depth++;

    if (gate->get_operation() == LUT) {
    	LUT_gatet* l_gate = dynamic_cast<LUT_gatet*> (gate);
    	assert(l_gate);
    	int new_depth = -1;

    	for(std::set< std::pair< gatet*, unsigned > >::iterator fanin_it = l_gate->get_fanins()->begin(); fanin_it != l_gate->get_fanins()->end(); ++fanin_it) {
   			new_depth = simple_circuit_get_depth((*fanin_it).first, level_map, level_set) + 1;
   			depth = (new_depth > depth)? new_depth : depth;
    	}
    }

	assert(depth >= 0);

	// We DO put CONST gates into level_map so they get cleaned up if they are not used
	if (depth == 0 && gate->get_operation() != simple_circuitt::CONST) {
		assert(gate->get_operation() == simple_circuitt::INPUT || gate->get_operation() == simple_circuitt::ONE);

		// we do not store inputs in our level_map/level_set
		return depth;
	}

	level_map[gate] = depth;

	if (level_set) {
		level_infot &level_info = (*level_set)[depth];

		if (level_info.gates == nullptr)
			level_info.gates = new ::std::set< simple_circuitt::gatet* >;

		level_info.gates->insert(gate);
		if(gate->get_operation() == AND)
			level_info.num_and_gates++;
		if(gate->get_operation() == MUL)
			level_info.num_mul_gates++;
	}

    return depth;
}

simple_circuitt::non_linear_deptht simple_circuitt::get_non_linear_depth(
	gatet* gate,
	non_linear_level_mapt& level_map) const
{
	auto it = level_map.find(gate);
	if (it != level_map.end())
		return it->second;

    non_linear_deptht depth;
	for(auto const &endpoint: gate->fanin_range())
    	depth = max(get_non_linear_depth(endpoint.gate, level_map), depth);

	if(is_boolean_non_const_op(gate->get_operation()))
	{
		if(gate->get_operation() != NOT && gate->get_operation() != XOR)
			depth.non_xor_depth++;
	}
	else if(is_arithmetic_non_const_op(gate->get_operation()))
	{
		if(gate->get_operation() == MUL)
			depth.mul_depth++;
	}

	if(gate->get_operation() == LUT)
	{
		LUT_gatet* l_gate = dynamic_cast<LUT_gatet*> (gate);
		assert(l_gate);
		non_linear_deptht new_depth;

		for(std::set< std::pair< gatet*, unsigned > >::iterator fanin_it = l_gate->get_fanins()->begin(); fanin_it != l_gate->get_fanins()->end(); ++fanin_it) {
			new_depth = get_non_linear_depth((*fanin_it).first, level_map);
			depth = (new_depth.non_xor_depth > depth.non_xor_depth)? new_depth : depth;
		}
	}

	// we do not store inputs in our level_map/level_set
	if(depth.non_xor_depth == 0 && depth.mul_depth == 0)
		return depth;

	level_map[gate] = depth;

	return depth;
}

simple_circuitt::simple_circuitt(loggert& logger, std::string const &name) :
	m_logger(&logger),
	m_name{name},
	input_gates_HEAD(NULL),
	input_gates_TAIL(NULL),
	input_gates_SIZE(0),
	output_gates_HEAD(NULL),
	output_gates_TAIL(NULL),
	output_gates_SIZE(0),
	gates_HEAD(NULL),
	gates_TAIL(NULL),
	gates_SIZE(0)
{
	ONE_GATE = new gatet(ONE, 0, 1);
	ZERO_GATE = new gatet(NOT, 1, 1);
	ZERO_GATE->add_fanin(primary_output(ONE_GATE), 0);
	clustering = 0;

	m_root_gates.insert(ONE_GATE);
}

simple_circuitt::simple_circuitt(simple_circuitt &&rhs) :
	m_logger(rhs.m_logger),
	m_name{std::move(rhs.m_name)},
	m_variables{std::move(rhs.m_variables)},
	m_ordered_inputs{std::move(rhs.m_ordered_inputs)},
	m_ordered_outputs{std::move(rhs.m_ordered_outputs)},
	m_function_calls{std::move(rhs.m_function_calls)},
	ONE_GATE(rhs.ONE_GATE),
	ZERO_GATE(rhs.ZERO_GATE),
	input_gates_HEAD(rhs.input_gates_HEAD),
	input_gates_TAIL(rhs.input_gates_TAIL),
	input_gates_SIZE(rhs.input_gates_SIZE),
	output_gates_HEAD(rhs.output_gates_HEAD),
	output_gates_TAIL(rhs.output_gates_TAIL),
	output_gates_SIZE(rhs.output_gates_SIZE),
	gates_HEAD(rhs.gates_HEAD),
	gates_TAIL(rhs.gates_TAIL),
	gates_SIZE(rhs.gates_SIZE),
	m_root_gates{std::move(rhs.m_root_gates)},
	clustering{rhs.clustering}
{
	rhs.input_gates_HEAD = nullptr;
	rhs.input_gates_TAIL = nullptr;
	rhs.input_gates_SIZE = 0;
	rhs.output_gates_HEAD = nullptr;
	rhs.output_gates_TAIL = nullptr;
	rhs.output_gates_SIZE = 0;
	rhs.gates_HEAD = nullptr;
	rhs.gates_TAIL = nullptr;
	rhs.gates_SIZE = 0;
	rhs.ONE_GATE = nullptr;
	rhs.ZERO_GATE = nullptr;
}

static std::vector<simple_circuitt::gatet*> copy_gates(
	std::vector<simple_circuitt::gatet*> const &src,
	std::unordered_map<simple_circuitt::gatet const*, simple_circuitt::gatet*> const &gate_translation)
{
	std::vector<simple_circuitt::gatet*> dest;
	dest.reserve(src.size());
	for(auto gate: src)
		dest.push_back(gate_translation.at(gate));

	return dest;
}

simple_circuitt::simple_circuitt(simple_circuitt const &rhs) :
	simple_circuitt{*rhs.m_logger, rhs.m_name}
{
	clustering = rhs.clustering;

	std::unordered_map<gatet const*, gatet*> gate_translation;
	std::stack<std::pair<gatet*, gatet const*>> work_list;
	for(auto rhs_gate: rhs.m_root_gates)
	{
		if(rhs_gate->operation == ONE)
		{
			work_list.push({ONE_GATE, rhs_gate});
			gate_translation[rhs_gate] = ONE_GATE;
		}
		else
		{
			auto lhs_gate = copy_gate_only(rhs_gate);
			gate_translation[rhs_gate] = lhs_gate;
			work_list.push({lhs_gate, rhs_gate});
		}
	}

	while(work_list.size())
	{
		gatet *lhs_gate;
		gatet const *rhs_gate;
		std::tie(lhs_gate, rhs_gate) = work_list.top(); work_list.pop();

		for(auto rhs_fanout: rhs_gate->fanouts)
		{
			gatet const* rhs_fanout_gate = rhs_fanout->second.gate;
			auto insert_pair = gate_translation.insert({rhs_fanout_gate, nullptr});
			if(insert_pair.second)
			{
				if(rhs_fanout_gate->operation == OUTPUT)
					insert_pair.first->second = copy_gate_only(rhs_fanout_gate);
				else if(rhs_fanout_gate == rhs.ZERO_GATE)
				{
					insert_pair.first->second = ZERO_GATE;
					work_list.push({insert_pair.first->second, rhs_fanout_gate});
				}
				else
				{
					insert_pair.first->second = copy_gate_only(rhs_fanout_gate);
					work_list.push({insert_pair.first->second, rhs_fanout_gate});
				}
			}

			if(insert_pair.first->second != ZERO_GATE)
				lhs_gate->add_fanout(rhs_fanout->first, {insert_pair.first->second, rhs_fanout->second.pin});
		}
	}


	for(auto const &var_pair: rhs.m_variables)
	{
		auto const &other_var = var_pair.second;
        m_variables.insert({
			other_var.name, 
			{other_var.name, other_var.owner, other_var.type, copy_gates(other_var.gates, gate_translation)}
		});
	}

	for(auto var: rhs.m_ordered_inputs)
		m_ordered_inputs.push_back(&m_variables.at(var->name));

	for(auto var: rhs.m_ordered_outputs)
		m_ordered_outputs.push_back(&m_variables.at(var->name));

	for(auto const &rhs_call: rhs.m_function_calls)
	{
		function_callt lhs_call;
		lhs_call.name = rhs_call.name;
		lhs_call.args.reserve(rhs_call.args.size());
		lhs_call.returns.reserve(rhs_call.returns.size());

		for(auto const &rhs_arg: rhs_call.args)
			lhs_call.args.push_back({rhs_arg.name, rhs_arg.type, copy_gates(rhs_arg.gates, gate_translation)});

		for(auto const &rhs_return: rhs_call.returns)
			lhs_call.args.push_back({rhs_return.name, rhs_return.type, copy_gates(rhs_return.gates, gate_translation)});
	}
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

simple_circuitt::gatet* simple_circuitt::get_or_create_gate(GATE_OP operation, int width, uint64_t value) {
	if (operation == ONE) {
		return ONE_GATE;
	}

	assert(operation != INPUT && operation != OUTPUT);

	gatet* gate;
	if (operation == LUT) {
		gate = new LUT_gatet(operation);
	}

	else {
		int num_input_pins = get_pin_counts(operation, width).first;
		assert(num_input_pins != -1);

		if(operation == SPLIT)
		{
			// We assume that we always split into boolean gates (of width 1)
			width = 1;
		}

		gate = new gatet(operation, num_input_pins, width, value);
	}

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

	if(get_pin_counts(gate->operation, gate->width).first == 0)
		m_root_gates.insert(gate);

	return gate;
}

simple_circuitt::gatet* simple_circuitt::create_input_gate(::std::string label, int width) {
	gatet* gate = new gatet(INPUT, 0, width);

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

	m_root_gates.insert(gate);

	return gate;
}

simple_circuitt::gatet* simple_circuitt::create_output_gate(::std::string label, int width) {
	gatet* gate = new gatet(OUTPUT, 1, width);

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

simple_circuitt::gatet* simple_circuitt::copy_gate_only(simple_circuitt::gatet const *gate)
{
	gatet *new_gate = nullptr;
	switch(gate->operation)
	{
		case INPUT:
			new_gate = create_input_gate(gate->label, gate->width);
			break;

		case OUTPUT:
			new_gate = create_output_gate(gate->label, gate->width);
			break;

		default:
			new_gate = get_or_create_gate(gate->operation, gate->width, gate->value);
	}

	new_gate->user = gate->user;
	return new_gate;
}

unsigned simple_circuitt::get_number_of_gates() const {
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

	if (gate->get_operation() == LUT) {
		LUT_gatet* l_gate = dynamic_cast<LUT_gatet*>(gate);
		assert(l_gate);

		for(unsigned index = 0; index < l_gate->get_fanins()->size(); index++)
			l_gate->remove_fanin_LUT(index);
	}

	else {
		for(unsigned i = 0; i < gate->num_fanins(); ++i)
			gate->remove_fanin(i);
	}

	gate->remove_fanouts();

	remove_gate_from_list(gate);
}

void simple_circuitt::remove_gate_from_list(gatet* gate) {
	assert(gate != ONE_GATE);
	assert(gate != ZERO_GATE);

	// Find out in which list the gate is stored
	gatet **head, **tail;
	if(gate->get_operation() == INPUT)
	{
		head = &input_gates_HEAD;
		tail = &input_gates_TAIL;
		input_gates_SIZE--;
	}
	else if(gate->get_operation() == OUTPUT)
	{
		head = &output_gates_HEAD;
		tail = &output_gates_TAIL;
		output_gates_SIZE--;
	}
	else
	{
		head = &gates_HEAD;
		tail = &gates_TAIL;
		gates_SIZE--;
	}

	// Remove the gate from the list
	if (gate->previous != NULL) {
		if (gate->next != NULL) {
			gate->previous->next = gate->next;
			gate->next->previous = gate->previous;
		}
		else { // gate->next == NULL
			assert(gate == *tail);

			gate->previous->next = NULL;
			*tail = gate->previous;
		}
	}
	else if (gate->next != NULL) { // gate->previous == NULL
		assert(gate == *head);

		gate->next->previous = NULL;
		*head = gate->next;
	}
	else {
		*head = NULL;
		*tail = NULL;
	}

	// If the gate has no fanins remove it from `m_root_gates`
	if(get_pin_counts(gate->operation, gate->width).first == 0)
		m_root_gates.erase(gate);

	delete gate;
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

		if (fanout->second.gate != ZERO_GATE) {
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
	m_logger->info() << "Approximating structural redundancy..." << eom;

	int threshold = 0;

#define USE_SIMULATE_2 1

#if USE_SIMULATE_2
	simple_circuit_level_mapt level_map;
	simple_circuit_level_sett level_set;

	for (gatet* gate_it = gates_HEAD; gate_it != NULL; gate_it = gate_it->next) {
		if (timeout(data)) {
			// clean up level_set
			for (unsigned i = 1; i <= level_set.size(); i++) {
				::std::set< gatet* >* set = level_set[i].gates;

				delete set;
			}

			return;
		}

		// determine level
		simple_circuit_get_depth(gate_it, level_map, &level_set);
	}
#endif

	if (timeout(data)) {
#if USE_SIMULATE_2
		// clean up level_set
		for(auto &pair: level_set) {
			::std::set< gatet* >* set = pair.second.gates;

			delete set;
		}
#endif

		return;
	}

	do {
		if (m_logger->level() >= log_levelt::debug) {
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
	for(auto &pair: level_set) {
		::std::set< gatet* >* set = pair.second.gates;

		delete set;
	}
#endif

	m_logger->info() << "Done approximating structural redundancy!" << eom;
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

bool simple_circuitt::equivalence_check_process_constants_bin(equivalence_checkert *checker, gatet* representative_gate, bint::iterator begin, bint::iterator end, simple_circuit_level_mapt& level_map, interpretationst& interpretations, timeout_datat& data) {
	bool changed_circuit = false;

	bint ordered_bin;

	order_bin(begin, end, level_map, ordered_bin);

	for (bint::iterator b_it = ordered_bin.begin(); b_it != ordered_bin.end() && !timeout(data); ++b_it) {

		interpretationt tmp_interpretation;

		if (check_gate(checker, *b_it, false, tmp_interpretation)) {
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

bool simple_circuitt::equivalence_check_process_regular_bin(equivalence_checkert *checker, bint::iterator begin, bint::iterator end, simple_circuit_level_mapt& level_map, interpretationst& interpretations, timeout_datat& data) {
	bool changed_circuit = false;

	bint ordered_bin;

	order_bin(begin, end, level_map, ordered_bin);

	if (m_logger->level() >= log_levelt::debug) {
		::std::cout << "iterating over ordered bin" << ::std::endl;
		::std::cout << "#elements in ordered bin: " << ordered_bin.size() << ::std::endl;
	}

	gatet* representative_gate = *(ordered_bin.begin());

	for (bint::iterator b_it = ++ordered_bin.begin(); b_it != ordered_bin.end() && !timeout(data); ++b_it) {

		interpretationt tmp_interpretation;

		if (are_equivalent(checker, representative_gate, *b_it, tmp_interpretation)) {
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

bool simple_circuitt::equivalence_check_process_bin(equivalence_checkert *checker, bint& bin, simple_circuit_level_mapt& level_map, interpretationst& interpretations, timeout_datat& data) {
	assert(!bin.empty());

	if (bin.size() <= 1) {
		return false;
	}

	gatet* front_gate = bin.front();

	if (front_gate == ZERO_GATE || front_gate == ONE_GATE) {
		m_logger->debug() << "There are possible constant gates!" << eom;

		// TODO we should perform these checks ordered by the depth of the gates!
		return equivalence_check_process_constants_bin(checker, front_gate, (++bin.begin()), bin.end(), level_map, interpretations, data);
	}
	else {
		if (m_logger->level() >= log_levelt::debug) {
			::std::cout << "investigating duplicated function" << ::std::endl;
			::std::cout << "#elements in bin: " << bin.size() << ::std::endl;
		}

		return equivalence_check_process_regular_bin(checker, bin.begin(), bin.end(), level_map, interpretations, data);
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

void simple_circuitt::minimize(equivalence_checkert *checker, bool limit_sat_iterations, int num_sat_iterations, double minimization_time_budget /* seconds */, bool no_state_machine) {

	interpretationst interpretations;

	interpretationt* interpretation = new interpretationt;
	initialize_interpretation(*interpretation);

	interpretations.push_back(interpretation);

	int nr_of_performed_sat_iterations = 0;

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
		m_logger->info() << "Start circuit rewriting..." << eom;

		if(no_state_machine)
			mode_rewrite = rewrite_no_state_machine(data);
		else
			mode_rewrite = minimizing_state_machine(data, &min, &structure);

		if (timeout(data)) {
			break;
		}

		m_logger->info() << "Done circuit rewriting." << eom;

		if (!mode_rewrite) {

			if (limit_sat_iterations && (nr_of_performed_sat_iterations >= num_sat_iterations)) {
				break;
			}

			nr_of_performed_sat_iterations++;

			::std::stringstream iteration_strstr;
			iteration_strstr << "SAT-based minimization iteration #" << nr_of_performed_sat_iterations << ".";
			m_logger->info() << iteration_strstr.str() << eom;

			bool changed_circuit = false;

			simple_circuit_level_mapt level_map;

			for (gatet* gate_it = gates_HEAD; gate_it != NULL && !timeout(data); gate_it = gate_it->next) {
				// determine level
				simple_circuit_get_depth(gate_it, level_map, NULL);
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

			if (m_logger->level() >= log_levelt::debug) {
				::std::cout << "Number of bins: " << bins.size() << ::std::endl;
			}

			unsigned bin_id = 0;

			for (binst::iterator it = bins.begin(); it != bins.end() && !timeout(data) /* && !changed_circuit*/; ++it) {

				if (m_logger->level() >= log_levelt::debug) {
					::std::cout << "bin #" << bin_id << "/" << bins.size() << ::std::endl;
				}

				bin_id++;

				bint* bin = *it;

				if (equivalence_check_process_bin(checker, *bin, level_map, interpretations, data)) {
					changed_circuit = true;
				}

				cases++;
			}

			for (binst::iterator it = bins.begin(); it != bins.end(); ++it) {
				bint* bin = *it;
				delete bin;
			}

			if (m_logger->level() >= log_levelt::debug) {
				::std::cout << "We have " << cases << " possible cases of duplicated functions!" << ::std::endl;
			}

			if (!changed_circuit) {
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
		m_logger->info() << "Stopping minimization due to time out." << eom;
	}

	for (interpretationst::iterator it = interpretations.begin(); it != interpretations.end(); ++it) {
		interpretationt* interpretation = *it;
		delete interpretation;
	}
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

	assert(gate->get_fanin(0));
	cone_of_influence(gate->get_fanin(0), coi);

	if (gate->get_operation() != NOT) {
		assert(gate->get_fanin(1));
		cone_of_influence(gate->get_fanin(1), coi);
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

	get_subcircuit(gate->get_fanin(0), dominator1, dominator2, subcircuit);

	if (gate->get_operation() != NOT) {
		get_subcircuit(gate->get_fanin(1), dominator1, dominator2, subcircuit);
	}
}

bool simple_circuitt::is_two_dominator(gatet* gate, gatet* dominator1, gatet* dominator2) {
	if (gate == dominator1 || gate == dominator2) {
		return true;
	}

	if (gate->get_operation() == INPUT || gate->get_operation() == ONE) {
		return false;
	}

	if (!is_two_dominator(gate->get_fanin(0), dominator1, dominator2)) {
		return false;
	}

	if (gate->get_operation() != NOT) {
		if (!is_two_dominator(gate->get_fanin(1), dominator1, dominator2)) {
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

		if (!is_postdominator(fanout->second.gate, dominator, level_map, depth_of_dominator)) {
			return false;
		}
	}

	return true;
}

/*void simple_circuitt::conditionally_write_dot_file(optionst& _options) {
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
	//}
	//	else {
	//		::std::cerr << "[WARNING] Didn't write out dot file output.circuit.dot!" << ::std::endl;
	//	}
}*/

