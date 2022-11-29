/*
 * simple_circuit_clustering.cpp
 *
 *  Created on: 29.03.2016
 *      Author: alina
 */

#include "simple_circuit.h"
#include "LUT_gate.h"
#include <math.h>
#include <algorithm>
#define INTER_CLUSTER_DELAY 1 // costs of a LUT
#define LUT_SIZE 6 // # inputs of a LUT

//#define PRIORITY // try to use AND and OR gates first

/*******************************************************************
 Function:

 Inputs:

 Outputs:

 Purpose:

 \*******************************************************************/
bool simple_circuitt::cluster() { // ToDo: zusammenfassen mit Rewrite Funktion?
	bool changed_circuit = false;
	gatest worklist;

	simple_circuit_level_mapt level_map;
	simple_circuit_level_sett level_set;

	for (gatet* gate_it = gates_HEAD; gate_it != NULL; gate_it = gate_it->next)
		simple_circuit_get_depth(gate_it, level_map, &level_set);

    for(auto it = level_set.rbegin(); it != level_set.rend(); ++it) {
		::std::set< simple_circuitt::gatet* >* set = it->second.gates;
		assert(set);

		for (::std::set< simple_circuitt::gatet* >::iterator it = set->begin(); it != set->end(); ++it) {
			if (*it != ZERO_GATE)
				worklist.push_back(*it);
		}

		// we do not need this set anymore, so let us free the memory
		delete set;
	}

	// we do not need level_set anymore
	level_set.clear();
	assert(get_number_of_gates() == worklist.size());

	/** labeling process **/
	std::cout << "starting labeling process" << std::endl;
	labeling_phase(worklist);

	/** clustering phase **/
	std::cout << "starting clustering phase" << std::endl;
	clusterst* clusters = new clusterst;
	clustering_phase(clusters);

	/** evaluate the clusters **/
	std::cout << "starting cluster evaluation" << std::endl;
	std::vector<std::string*>* outstrings = new std::vector<std::string*>;
	for (clusterst::iterator it = clusters->begin(); it != clusters->end(); ++it)
		outstrings->push_back(evaluate((*it).first, (*it).second));

	/** clean up worklist **/
	unsigned i = 0;
	std::cout << "replace clusters with LUTs" << std::endl;
	for (clusterst::iterator it = clusters->begin(); it != clusters->end(); ++it)
		replace_with_LUT((*it).first, (*it).second, outstrings->at(i++));

	/** cleaning phase **/
	std::cout << "starting cleaning phase" << std::endl;
	for (gatest::iterator it = worklist.begin(); it != worklist.end(); ++it) {
		(*it)->cluster->clear();
		(*it)->preds->clear();
	}

	outstrings->clear();
	delete outstrings;
	clusters->clear();
	delete clusters;
	level_map.clear();

	std::cout << "finished clustering" << std::endl;
	std::cout << std::endl;

	if (cleanup())
		changed_circuit = true;

	return changed_circuit;
}

/*												Labeling Process											*/
/*******************************************************************
 Function: simple_circuitt::labeling_phase

 Inputs: vector of all circuit gates excluding inputs, outputs and constant gates

 Outputs: void

 Purpose: labels all circuit gates excluding constant gates, starts with inputs

 \*******************************************************************/
void simple_circuitt::labeling_phase(::std::vector< gatet* > worklist) {
	typedef ::std::vector< gatet* > gatest;

	// set all input labels to zero
	// ToDo: split big circuits and set the label of inputs for the subcircuit to their corresponding depth
	for (gatet* it = input_gates_HEAD; it != NULL; it = it->next) {
		it->gate_label = 0;
		it->cluster->insert(it); // cluster of a input contains only itself
	}

	// start from the inputs and label each node of the worklist (topological order)
	for (gatest::reverse_iterator it = worklist.rbegin(); it != worklist.rend(); ++it)
		label_node(*it);

	// label the outputs
	for (gatet* it = output_gates_HEAD; it != NULL; it = it->next)
		label_node(it);
}

/*******************************************************************
 Function: simple_circuitt::label_node

 Inputs: gate to be labeled

 Outputs: void

 Purpose: calculate label of given gate

 \*******************************************************************/
void simple_circuitt::label_node(gatet* gate) {
	// compute subgraph rooted at *it that includes all predecessors of this gate and their delay to this gate
	// sets the attribute "preds" of the given gate
	collect_predecessors(gate);

	// use a vec for computation of the cluster as it is possible to sort it (preds attribute as vec)
	std::vector<std::pair< gatet*, unsigned>* >* c_vec  = new std::vector<std::pair< gatet*, unsigned>* >;
	for (std::map< simple_circuitt::gatet*, unsigned >::iterator it = gate->preds->begin(); it != gate->preds->end(); ++it) {
		std::pair< gatet*, unsigned>* p = new std::pair< gatet*, unsigned>;
		p->first = (*it).first;
		p->second = (*it).second; // delay between given gate and its predecessor
		c_vec->push_back(p);
	}

	// compute the label for the given gate
	gate->gate_label = compute_cluster(gate, c_vec);

	// clean up
	c_vec->clear();
	delete c_vec;
}

/*******************************************************************
 Function: simple_circuitt::collect_predecessors

 Inputs: gate whose predecessors are computed

 Outputs: void

 Purpose: sets the attribute "preds" of the given gate which contains pairs of the predecessor gate and the corresponding delay value

 \*******************************************************************/
void simple_circuitt::collect_predecessors(gatet* gate) {

	// use delay value 1 for a Non-XOR gate and 0 otherwise
	unsigned gate_delay = (gate->operation == OR || gate->operation == AND)? 1 : 0;

	// calculate G_v and corresponding l_v values (algorithm step 1 and 2)
	for(auto &fanin_ep: gate->fanins)
	{
		gatet *fanin = fanin_ep.gate;
		if(!fanin)
			continue;

		calculate_delay_entry(gate, fanin, (gate_delay + fanin->gate_label));

		// l_v for all indirect predecessors (i.e. G_v of the direct predecessor)
		for (gatet::predst::iterator it = fanin->preds->begin(); it != fanin->preds->end(); ++it)
			calculate_delay_entry(gate, (*it).first, ((*it).second + gate_delay));
	}
}

/*******************************************************************
 Function: calculate_delay_entry

 Inputs: gate whose predecessors are computed, actual predecessor gate and new delay value

 Outputs: void

 Purpose: sets the l_v delay of the predecessor gate to the greatest actually known value (longest path delay + label)

 \*******************************************************************/
void simple_circuitt::calculate_delay_entry(gatet* gate, gatet* predecessor, unsigned delay) {

	// is this gate already contained in the predecessor map?
	gatet::predst::iterator it2 = gate->preds->find(predecessor);

	// if not or the old delay is less than the new one -> set delay value
	if (it2 == gate->preds->end() || (*it2).second < delay)
		(*gate->preds)[predecessor] = delay;
}

/*******************************************************************
 Function: sort_pair

 Inputs: two pairs of gatet* (predecessor), unsigned (path delay l_v)

 Outputs: true if l_v of p1 is greather than l_v of p2

 Purpose: used for sorting predecessor vec in decreasing order

 \*******************************************************************/
bool sort_pair(std::pair<simple_circuitt::gatet*, unsigned>* p1, std::pair<simple_circuitt::gatet*, unsigned>* p2) { return (p1->second > p2->second); }

/*******************************************************************
 Function: simple_circuitt::can_insert

 Inputs: root gate of subcircuit, gate that is going to be inserted, set of current cluster input gates

 Outputs: true if gate can be inserted into predecessor map

 Purpose: check if gate could be inserted into cluster without violating the LUT size constraint

 \*******************************************************************/
bool simple_circuitt::can_insert(gatet* root, gatet* gate, std::set<gatet*>* inputs) {
	unsigned fanins = 0;

	// check if gate has only outputs that are members of the cluster
	/*if(gate != root) {
		for(gatet::fanoutst::iterator it = gate->fanouts.begin(); it != gate->fanouts.end(); ++it)
			if(root->cluster->find((*it)->first) == root->cluster->end())
				return false;
	}*/
	if(gate->fanouts.size() > 1)
		return false;

	// check LUT input size constraint
	for(auto &fanin_ep: gate->fanins)
	{
		gatet *fanin = fanin_ep.gate;
		if(!fanin) continue;

		// fanin gate is not already contained in the cluster and also not in the input set -> new input
		if (root->cluster->find(fanin) == root->cluster->end() && inputs->find(fanin) == inputs->end())
			fanins++;
	}

	unsigned new_size = inputs->size() + fanins;

	// if the gate is no INPUT it won't be a cluster input itself anymore
	if (inputs->find(gate) != inputs->end() && gate->get_operation() != INPUT)
		new_size--;

	return new_size <= LUT_SIZE;
}

/*******************************************************************
 Function: simple_circuitt::insert_gate

 Inputs: root gate of cluster, gate that is going to be inserted, current set of cluster-input gates

 Outputs: void

 Purpose: inserts a gate into the root-cluster and sets inputs accordingly

 \*******************************************************************/
void simple_circuitt::insert_gate(gatet* root, gatet* gate, std::set<gatet*>* inputs) {
	root->cluster->insert(gate);

	// the gate is not a cluster input anymore
	if(gate->get_operation() != INPUT)
		inputs->erase(gate);

	for(auto &fanin_ep: gate->fanins)
	{
		gatet *fanin = fanin_ep.gate;
		if(fanin && root->cluster->find(fanin) == root->cluster->end())
			inputs->insert(fanin);
	}
}

/*******************************************************************
 Function: simple_circuitt::compute_cluster

 Inputs: root gate and set of predecessor, delay pairs

 Outputs: unsigned gate label

 Purpose: calculates cluster (with priority consideration) and the gate label max(l1,l2)

 \*******************************************************************/
unsigned simple_circuitt::compute_cluster(gatet* gate, std::vector<std::pair< gatet*, unsigned>* >* set) {
	unsigned l1 = 0, l2 = 0;
	std::set<gatet*>* inputs = new std::set<gatet*>;

	// insert the gate itself into its own cluster and its inputs into the input set
	insert_gate(gate, gate, inputs);

	// sort set S in decreasing order of their l_v values (bigger l_v = current gate is on one of the longest paths from the inputs to the given gate)
	std::stable_sort(set->begin(), set->end(), sort_pair);

#ifdef PRIORITY
	// first use AND and OR gates for clustering
	for (std::vector<std::pair< gatet*, unsigned>* >::iterator it = set->begin(); it != set->end(); ++it) {
		if (can_insert(gate, (*it)->first, inputs) && ((*it)->first->operation == AND || (*it)->first->operation == OR)) {
			insert_gate(gate, (*it)->first, inputs);
			it = set->erase(it);
			if (it == set->end())
				break;
		}
	}

	// we do not want clusters with less than 2 AND gates
	if(gate->cluster->size() < 2)
		gate->cluster->clear();

	else {
		// fill up with XOR and INPUT gates
		for (std::vector<std::pair< gatet*, unsigned>* >::iterator it = set->begin(); it != set->end() && can_insert(gate, (*it)->first, inputs); ++it) {
			if ((*it)->first->operation == INPUT && l1 < (*it)->second)
				l1 = (*it)->second;
			insert_gate(gate, (*it)->first, inputs);

			it = set->erase(it);
			if (it == set->end())
				break;
		}
	}

	// calculate l2
	l2 = (*set->begin())->second + INTER_CLUSTER_DELAY;

#else
	for (std::vector<std::pair< gatet*, unsigned>* >::iterator it = set->begin(); it != set->end(); ++it) {

		// check LUT input constraint and if gate has only outputs within cluster
		if (can_insert(gate, (*it)->first, inputs)) {
			if ((*it)->first->operation == INPUT && l1 < (*it)->second)
				l1 = (*it)->second;

			insert_gate(gate, (*it)->first, inputs);
		}
		else if (l2 < ((*it)->second + INTER_CLUSTER_DELAY))
				l2 = (*it)->second + INTER_CLUSTER_DELAY;
	}
#endif

	return fmax(l1, l2);
}


/*												Clustering Phase											*/
/*******************************************************************
 Function:

 Inputs:

 Outputs:

 Purpose:

 \*******************************************************************/
void simple_circuitt::clustering_phase(clusterst* clusters) {
	typedef ::std::set< simple_circuitt::gatet* > gate_sett;
	gate_sett* set_L = new gate_sett;
	::std::set< gatet::clustert* >* set_S = new ::std::set< gatet::clustert* >;

	// put all input nodes of the POs in a set L
	// we do not want to build clusters with POs as root!
	for (gatet* gate_it = output_gates_HEAD; gate_it != NULL; gate_it = gate_it->next)
		set_L->insert(gate_it->get_fanin(0));

	gatet* c_gate;

	// remove node from L and form its cluster
	while (!set_L->empty()) {
		gate_sett* set_I = new gate_sett;
		gate_sett* set_inputs = new gate_sett;
		c_gate = *(set_L->begin());

		set_S->insert(c_gate->cluster);

		// compute the set of input nodes for the cluster -> set_I
		compute_inputs(c_gate->cluster, set_I, set_inputs);

		// check constraints
		if (set_inputs->size() == LUT_SIZE && AND_constraint(c_gate, clusters))
			clusters->insert(std::make_pair(c_gate, set_inputs));

		set_L->erase(c_gate);
		// remove node x from set_I and add it to set_L if we have not formed the cluster for x yet
		for(gate_sett::iterator it = set_I->begin(); it != set_I->end(); ++it) {
			if (set_S->find((*it)->cluster) == set_S->end())
				set_L->insert(*it);
		}
		set_I->clear();
		delete set_I;
	}
	std::cout << "#cluster: " << set_S->size() << " #cluster mit " << LUT_SIZE << " Inputs: " << clusters->size() << std::endl;

	/** clean up **/
	set_L->clear();
	delete set_L;
	set_S->clear();
	delete set_S;
}

/*******************************************************************
 Function: simple_circuitt::compute_inputs

 Inputs: cluster of which inputs will be computed, input set excluding INPUTS and input set including INPUTS

 Outputs: void

 Purpose: calculates the set of cluster inputs

 \*******************************************************************/
void simple_circuitt::compute_inputs(gatet::clustert* cluster, gate_sett* set_I, gate_sett* set_inputs) {
	for(gate_sett::iterator it = cluster->begin(); it != cluster->end(); ++it) {

		for(auto &fanin_ep: (*it)->fanins)
		{
			gatet *fanin = fanin_ep.gate;
			if(!fanin) continue;

			if (cluster->find(fanin) == cluster->end())
				set_I->insert(fanin);

			// we also need INPUTs as LUT fanins but we do not want to build a cluster for them
			if (fanin->operation == INPUT)
				set_inputs->insert(fanin);
		}

		set_inputs->insert(set_I->begin(), set_I->end());
	}
}

/*******************************************************************
 Function: simple_circuitt::AND_constraint

 Inputs: current gate, set of already computed clusters

 Outputs: true if new cluster reduces AND costs

 Purpose: checks if cluster would reduce costs

 \*******************************************************************/
bool simple_circuitt::AND_constraint(gatet* c_gate, clusterst* clusters) {
	unsigned AND_count = 0;
	for(gatet::clustert::iterator it2 = c_gate->cluster->begin(); it2 != c_gate->cluster->end(); ++it2) {
		// check if this AND gate is already contained in a cluster
		if ((*it2) != c_gate && ((*it2)->get_operation() == AND || (*it2)->get_operation() == OR)) {
			bool found = false;
			for(clusterst::iterator it = clusters->begin(); it != clusters->end(); ++it)
				found = (*it).first->cluster->find(*it2) != (*it).first->cluster->end();

			// if not or the gate is root-gate the costs will be reduced by one
			if(!found)
				AND_count++;
		}
	}
	return AND_count >= 1;
}

/*******************************************************************
 Function: simple_circuitt::replace_with_LUT

 Inputs: root of subcircuit, inputs of the cluster and the corresponding results

 Outputs: void

 Purpose: replaces the subcircuit at a given root gate with a LUT

 \*******************************************************************/
void simple_circuitt::replace_with_LUT(gatet* root, std::set< gatet* >* inputs, std::string* result) {
	LUT_gatet* LUT_gate = dynamic_cast<LUT_gatet*> (get_or_create_gate(LUT));
	assert(LUT_gate);
	std::set< std::pair< gatet*, unsigned > >* fanins = new std::set< std::pair< gatet*, unsigned > >;
	LUT_gate->set_outString(result);

	unsigned input_count = 0;
	for(std::set< gatet* >::iterator it = inputs->begin(); it != inputs->end(); ++it) {
		fanins->insert(std::make_pair(*it, input_count));
		(*it)->add_LUT_fanout({LUT_gate, input_count++});
	}
	LUT_gate->set_fanins(fanins);
	root->replace_by(LUT_gate);
}
