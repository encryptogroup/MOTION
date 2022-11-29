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

simple_circuitt::gatet::gatet(GATE_OP operation, int input_pins, int width, uint64_t value) :
	fanins(input_pins),
	user{0},
	operation(operation),
	width{width},
	value{value},
	was_checked_for_being_constant(false),
	previous(NULL),
	next(NULL) {
		cluster = new clustert;
		preds = new predst;
		gate_label = 0;
		fanouts.reserve(4);
}

simple_circuitt::gatet::~gatet() {
	for (fanoutst::iterator it = fanouts.begin(); it != fanouts.end(); ++it) {
		fanoutt* fanout = *it;
		delete fanout;
	}
}

void simple_circuitt::gatet::add_fanin(wire_endpointt input_gate, unsigned index) {
	assert(this->operation != LUT);
    assert(input_gate.gate);
	input_gate.gate->add_fanout(input_gate.pin, wire_endpointt{this, index});
}

simple_circuitt::gatet*& simple_circuitt::gatet::get_fanin(unsigned index) {
	assert(index < fanins.size());
	return fanins.at(index).gate;
}

simple_circuitt::gatet* const& simple_circuitt::gatet::get_fanin(unsigned index) const {
	assert(index < fanins.size());
	return fanins.at(index).gate;
}

void simple_circuitt::gatet::add_fanout(unsigned from_pin, wire_endpointt target) {

	assert(target.gate);

	if (target.gate->operation == LUT) {
		add_LUT_fanout (from_pin, target);
		return;
	}

    assert(width == target.gate->width || target.gate->operation == SPLIT || target.gate->operation == COMBINE);
    assert(operation != COMBINE || (target.gate->width == width || target.gate->operation == SPLIT));
    assert(operation != SPLIT || (target.gate->width == 1 || target.gate->operation == COMBINE));

    // If neither of the gates is a COMBINE or SPLIT gate, then their bit-widths have to match.
    assert(
        (is_combine_or_split_op(target.gate->operation) || is_combine_or_split_op(operation))
        || (width == target.gate->width)
    );

	assert(target.gate->fanins.size() > target.pin);
	assert(target.gate->fanins[target.pin].gate == nullptr);
	assert(target.gate->operation != INPUT);
	assert(target.gate->operation != ONE);
	assert(target.gate->operation != CONST);
	target.gate->fanins[target.pin] = wire_endpointt{this, from_pin};

	fanoutt* fanout = new fanoutt(from_pin, target);
	fanouts.push_back(fanout);
}

void simple_circuitt::gatet::add_LUT_fanout(unsigned from_pin, wire_endpointt target) {
	LUT_gatet* l_gate = dynamic_cast<LUT_gatet*>(target.gate);
	l_gate->get_fanins()->insert(std::make_pair(this, target.pin));
	fanoutt* fanout = new fanoutt(from_pin, target);
	fanouts.push_back(fanout);
}

// Adds the fanout to the primary output pin
void simple_circuitt::gatet::add_LUT_fanout(wire_endpointt target) {
	add_LUT_fanout(0, target);
}

void simple_circuitt::gatet::remove_fanouts() {
	for (fanoutst::iterator it = fanouts.begin(); it != fanouts.end(); ++it) {
		fanoutt* fanout = *it;

		if (fanout->second.gate->get_operation() == LUT) {
			std::cout << "hier könnte das Problem liegen" << std::endl;
			LUT_gatet* l_gate = dynamic_cast<LUT_gatet*>(fanout->second.gate);

			for(std::set< std::pair< simple_circuitt::gatet*, unsigned > >::iterator it = l_gate->get_fanins()->begin(); it != l_gate->get_fanins()->end(); ++it) {
				const std::pair< simple_circuitt::gatet*, unsigned >* fanin = &(*it);

				if((*it).second == fanout->first) {
					l_gate->get_fanins()->erase(it);
					delete fanin;
					fanin = NULL;
				}
			}
		}
		else {
			fanout->second.gate->fanins[fanout->second.pin].gate = nullptr;
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
		assert(index < fanins.size());
		assert(fanins[index].gate);
		assert(!fanins[index].gate->fanouts.empty());

		unsigned old_size = fanins[index].gate->fanouts.size();

		for (fanoutst::iterator it = fanins[index].gate->fanouts.begin(); it != fanins[index].gate->fanouts.end(); ++it) {
			fanoutt* fanout = *it;

			if (fanout->second.gate == this && fanout->second.pin == index) {
				fanins[index].gate->fanouts.erase(it);
				delete fanout;
				fanout = NULL;

				break;
			}
		}

		assert(old_size == (fanins[index].gate->fanouts.size() + 1));

		fanins[index].gate = NULL;
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
		if ((*fanout)->second.gate == this && (*fanout)->second.pin == index) {
			(*fanin).first->fanouts.erase(fanout);
			delete f_out;
			f_out = NULL;

			break;
		}
	}
	assert(old_size == ((*fanin).first->fanouts.size() + 1));
	l_gate->get_fanins()->erase(*fanin);
}

simple_circuitt::GATE_OP simple_circuitt::gatet::get_operation() const {
	return operation;
}

::std::string simple_circuitt::gatet::to_string() const {
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
	case ADD:
		return "ADD";
	case SUB:
		return "SUB";
	case MUL:
		return "MUL";
	case COMBINE:
		return "COMBINE";
	case SPLIT:
		return "SPLIT";
	case NEG:
		return "NEG";
	case CONST:
		return "CONST";
	}

	exit(-1);
}

void simple_circuitt::gatet::replace_by(gatet* gate) {
	assert(this != gate);
	assert(width == gate->width);

	while (!fanouts.empty()) {
		fanoutt fanout = *fanouts[0];

		gatet* target_gate = fanout.second.gate;
		unsigned index = fanout.second.pin;

		target_gate->remove_fanin(index);

		gate->add_fanout(fanout.first, fanout.second);
	}

	if (was_checked_for_being_constant) {
		gate->was_checked_for_being_constant = true;
	}
}

void simple_circuitt::gatet::replace_by(wire_endpointt ep) {
	assert(this != ep.gate);
	assert(width == ep.gate->width);

	while (!fanouts.empty()) {
		fanoutt fanout = *fanouts[0];

		gatet* target_gate = fanout.second.gate;
		unsigned index = fanout.second.pin;

		target_gate->remove_fanin(index);

		ep.gate->add_fanout(ep.pin, fanout.second);
	}

	if (was_checked_for_being_constant) {
		ep.gate->was_checked_for_being_constant = true;
	}
}

void simple_circuitt::gatet::replace_pin_by(unsigned pin, wire_endpointt gate) {
	assert(this != gate.gate);

	size_t i = 0;
	while(i < fanouts.size()) {
		fanoutt fanout = *fanouts[i];

		if(fanout.first == pin)
		{
			gatet* target_gate = fanout.second.gate;
			unsigned index = fanout.second.pin;

			target_gate->remove_fanin(index);

			gate.gate->add_fanout(gate.pin, fanout.second);
		}
		else
			++i;
	}

	if (was_checked_for_being_constant) {
		gate.gate->was_checked_for_being_constant = true;
	}
}

LUT_gatet::LUT_gatet(simple_circuitt::GATE_OP operation) : gatet(operation, 0, 1){
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
