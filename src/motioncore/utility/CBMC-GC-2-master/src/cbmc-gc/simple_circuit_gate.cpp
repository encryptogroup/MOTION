/*
 * simple_circuit_gate.cpp
 *
 *  Created on: 01.10.2013
 *      Author: andreas
 */

#include "simple_circuit.h"
#include "LUT_gate.h"

#include <cstdlib>
#include <signal.h>

simple_circuitt::gatet::gatet(simple_circuitt* circuit, GATE_OP operation) : circuit(*circuit), operation(operation), fanin0(NULL), fanin1(NULL), previous(NULL), next(NULL), was_checked_for_being_constant(false) {
	cluster = new clustert;
	preds = new predst;
	gate_label = 0;
}

simple_circuitt::gatet::~gatet() {
	for (fanoutst::iterator it = fanouts.begin(); it != fanouts.end(); ++it) {
		fanoutt* fanout = *it;
		delete fanout;
	}
}

void simple_circuitt::gatet::add_fanin(gatet& input_gate, unsigned index) {
	assert(this->operation != LUT);
	input_gate.add_fanout(*this, index);
}

simple_circuitt::gatet* simple_circuitt::gatet::get_fanin(bool fanin_one) {
	if (fanin_one) {
		assert(fanin1);
		return fanin1;
	}
	else {
		assert(fanin0);
		return fanin0;
	}
}

void simple_circuitt::gatet::add_fanout(gatet& target_gate, unsigned index) {
	if (target_gate.operation == LUT) {
		add_LUT_fanout (target_gate, index);
		return;
	}

	if (index == 0) {
		assert(target_gate.fanin0 == NULL);
		assert(target_gate.operation != INPUT);
		assert(target_gate.operation != ONE);
		target_gate.fanin0 = this;
	}
	else if (index == 1) {
		assert(target_gate.fanin1 == NULL);
		assert(target_gate.operation != NOT);
		assert(target_gate.operation != INPUT);
		assert(target_gate.operation != ONE);
		target_gate.fanin1 = this;
	}
	else {
		::std::cerr << "[ERROR] index has to be 0 or 1 (" << __FILE__ << ", " << __LINE__ << ")" << ::std::endl;
		exit(-1);
	}

	fanoutt* fanout = new fanoutt(&target_gate, index);
	fanouts.push_back(fanout);
}

void simple_circuitt::gatet::add_LUT_fanout(gatet& target_gate, unsigned index) {

	LUT_gatet* l_gate = dynamic_cast<LUT_gatet*>(&target_gate);
	l_gate->get_fanins()->insert(std::make_pair(this, index));
	fanoutt* fanout = new fanoutt(&target_gate, index);
	fanouts.push_back(fanout);
}

void simple_circuitt::gatet::remove_fanouts() {
	for (fanoutst::iterator it = fanouts.begin(); it != fanouts.end(); ++it) {
		fanoutt* fanout = *it;

		if (fanout->first->get_operation() == LUT) {
			std::cout << "hier könnte das Problem liegen" << std::endl;
			LUT_gatet* l_gate = dynamic_cast<LUT_gatet*>(fanout->first);

			for(std::set< std::pair< simple_circuitt::gatet*, unsigned > >::iterator it = l_gate->get_fanins()->begin(); it != l_gate->get_fanins()->end(); ++it) {
				const std::pair< simple_circuitt::gatet*, unsigned >* fanin = &(*it);

				if((*it).second == fanout->second) {
					l_gate->get_fanins()->erase(it);
					delete fanin;
					fanin = NULL;
				}
			}
		}
		else if (fanout->second == 0) {
			fanout->first->fanin0 = NULL;
		}
		else { // fanout->second == 1
			fanout->first->fanin1 = NULL;
		}

		delete fanout;
		fanout = NULL;
	}

	fanouts.clear();
}

void simple_circuitt::gatet::remove_fanin(unsigned index) {

	if (this->operation == LUT)
		remove_fanin_LUT(index);

	else {
		assert(index == 0 || index == 1);

		if (index == 0) {
			remove_fanin0();
		}
		else {
			remove_fanin1();
		}
	}
}

void simple_circuitt::gatet::remove_fanin_LUT(unsigned index) {
	LUT_gatet* l_gate = dynamic_cast<LUT_gatet*> (this);
	assert(l_gate);

	// look for fanin that has to be removed
	std::set< std::pair< gatet*, unsigned > >::iterator fanin;
	for(fanin = l_gate->get_fanins()->begin(); fanin != l_gate->get_fanins()->end(); fanin++) {
		if ((*fanin).second == index)
			break;
	}
	unsigned old_size = (*fanin).first->fanouts.size();

	// durchsuche fanout liste des fanin gates
	for (fanoutst::iterator fanout = (*fanin).first->fanouts.begin(); fanout != (*fanin).first->fanouts.end(); ++fanout) {
		fanoutt* f_out = *fanout;

		// wenn fanout dieses gate ist und der index richtig ist
		if ((*fanout)->first == this && (*fanout)->second == index) {
			(*fanin).first->fanouts.erase(fanout);
			delete f_out;
			f_out = NULL;

			break;
		}
	}
	assert(old_size == ((*fanin).first->fanouts.size() + 1));
	l_gate->get_fanins()->erase(*fanin);
}

void simple_circuitt::gatet::remove_fanin0() {
	if (fanin0 == NULL)
		std::cout << this->operation << std::endl;

	assert(fanin0);
	assert(!fanin0->fanouts.empty());

	unsigned old_size = fanin0->fanouts.size();

	for (fanoutst::iterator it = fanin0->fanouts.begin(); it != fanin0->fanouts.end(); ++it) {
		fanoutt* fanout = *it;

		if (fanout->first == this && fanout->second == 0) {
			fanin0->fanouts.erase(it);
			delete fanout;
			fanout = NULL;

			break;
		}
	}

	assert(old_size == (fanin0->fanouts.size() + 1));

	fanin0 = NULL;
}

void simple_circuitt::gatet::remove_fanin1() {
	assert(fanin1);
	assert(!fanin1->fanouts.empty());

	unsigned old_size = fanin1->fanouts.size();

	for (fanoutst::iterator it = fanin1->fanouts.begin(); it != fanin1->fanouts.end(); ++it) {
		fanoutt* fanout = *it;

		if (fanout->first == this && fanout->second == 1) {
			fanin1->fanouts.erase(it);
			delete fanout;
			fanout = NULL;

			break;
		}
	}

	assert(old_size == (fanin1->fanouts.size() + 1));

	fanin1 = NULL;
}

simple_circuitt::GATE_OP simple_circuitt::gatet::get_operation() const {
	return operation;
}

::std::string simple_circuitt::gatet::to_string() {
	switch (operation) {
	case XOR:
		return "XOR";
	case AND:
		return "AND";
	case ONE:
		return "ONE";
	case OR:
		return "OR";
	case NOT:
		return "NOT";
	case INPUT:
		return "INPUT";
	case OUTPUT:
		return "OUTPUT";
	case LUT:
		return "LUT";
	}

	exit(-1);
}

void simple_circuitt::gatet::replace_by(gatet* gate) {
	assert(this != gate);

	while (!fanouts.empty()) {
		fanoutt* fanout = fanouts[0];

		gatet* target_gate = fanout->first;
		unsigned index = fanout->second;

		target_gate->remove_fanin(index);

		gate->add_fanout(*target_gate, index);
	}

	if (was_checked_for_being_constant) {
		gate->was_checked_for_being_constant = true;
	}
}

LUT_gatet::LUT_gatet(simple_circuitt* circuit, simple_circuitt::GATE_OP operation) : gatet(circuit, operation){
	fanins = new std::set< std::pair< gatet*, unsigned > >;
	outString = NULL;
}

LUT_gatet::~LUT_gatet() {
	fanins->clear();
	delete fanins;
	delete outString;
}

void LUT_gatet::set_outString(std::string* result) {
	outString = result;
}

void LUT_gatet::set_fanins(std::set< std::pair< gatet*, unsigned > >* inputs) {
	LUT_gatet* l_gate = dynamic_cast<LUT_gatet*>(this);
	for (std::set< std::pair< gatet*, unsigned > >::iterator it = inputs->begin(); it != inputs->end(); ++it)
		assert(l_gate != (*it).first);

	fanins = inputs;
}

std::string* LUT_gatet::get_outString() {
	return outString;
}

std::set< std::pair< simple_circuitt::gatet*, unsigned > >* LUT_gatet::get_fanins() {
	return fanins;
}
