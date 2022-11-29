/*
 * simple_circuit_converting.cpp
 *
 *  Created on: 10.08.2015
 *      Author:
 *    Function: AIG Conversion
 */
#include "simple_circuit.h"

bool simple_circuitt::convert_NOR(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	if (gate.get_operation() == AND) {
		if (gate.get_fanin(0)->get_operation() == NOT && gate.get_fanin(1)->get_operation() == NOT) {
			fanin0_out = gate.get_fanin(0)->get_fanin(0);
			fanin1_out = gate.get_fanin(1)->get_fanin(0);
			return true;
		}
	}
	return false;
}

bool simple_circuitt::convert_OR(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	if (gate.get_operation() == NOT)
		return convert_NOR(*(gate.get_fanin(0)), fanin0_out, fanin1_out);
	return false;
}

bool simple_circuitt::convert_XNOR2(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	gatet* nor0 = NULL;
	gatet* nor1 = NULL;
	if (convert_NOR(gate, nor0, nor1)) {
		if(nor0->get_operation() == AND && nor1->get_operation() == AND) {
			if (nor0->get_fanin(0)->get_operation() == NOT) {
				if (nor1->get_fanin(0)->get_operation() == NOT && nor0->get_fanin(0)->get_fanin(0) == nor1->get_fanin(1) && nor0->get_fanin(1) == nor1->get_fanin(0)->get_fanin(0)) {
					fanin0_out = nor0->get_fanin(0)->get_fanin(0);
					fanin1_out = nor0->get_fanin(1);
					return true;
				}
				else if (nor1->get_fanin(1)->get_operation() == NOT && nor0->get_fanin(0)->get_fanin(0) == nor1->get_fanin(0) && nor0->get_fanin(1) == nor1->get_fanin(1)->get_fanin(0)) {
					fanin0_out = nor0->get_fanin(0)->get_fanin(0);
					fanin1_out = nor0->get_fanin(1);
					return true;
				}
			}
			if (nor0->get_fanin(1)->get_operation() == NOT) {
				//ToDo: might be a bug. There is a segmentation fault when used with recursive XOR if clause 2
				/*if (nor1->get_fanin(0)->get_operation() == NOT && nor0->get_fanin(1)->get_fanin(0) == nor1->get_fanin(1) && nor0->get_fanin(0) == nor1->get_fanin(0)->get_fanin(0)) {
					fanin0_out = nor0->get_fanin(1)->get_fanin(0);
					fanin1_out = nor0->get_fanin(0);
					return true;
				}
				else*/ if (nor1->get_fanin(1)->get_operation() == NOT && nor0->get_fanin(1)->get_fanin(0) == nor1->get_fanin(0) && nor0->get_fanin(0) == nor1->get_fanin(1)->get_fanin(0)) {
					fanin0_out = nor0->get_fanin(1)->get_fanin(0);
					fanin1_out = nor0->get_fanin(0);
					return true;
				}
			}
		}
	}
	return false;
}

bool simple_circuitt::convert_XNOR1(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	// NOT(AND(NOT(AND(x,y)),NOT(AND(NOT(x),NOT(y))))) = a XNOR b
	if (gate.get_operation() == NOT)
		return convert_XOR2(*(gate.get_fanin(0)), fanin0_out, fanin1_out);

	return false;
}

bool simple_circuitt::convert_XOR1(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	if (gate.get_operation() == NOT)
		return convert_XNOR2(*(gate.get_fanin(0)), fanin0_out, fanin1_out);

	return false;
}

bool simple_circuitt::convert_XOR2(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	// AND(NOT(AND(x,y)),NOT(AND(NOT(x),NOT(y)))) = a XOR b
	gatet* nor0 = NULL;
	gatet* nor1 = NULL;

	if (convert_NOR(gate, nor0, nor1)) {
		//AND(x,y) und (AND(NOT(x),NOT(y))
		if (nor0->get_operation() == AND && nor1->get_operation() == AND) {
			if (nor0->get_fanin(0)->get_operation() == NOT && nor0->get_fanin(1)->get_operation() == NOT) {
				if ((nor0->get_fanin(0)->get_fanin(0) == nor1->get_fanin(0) && nor0->get_fanin(1)->get_fanin(0) == nor1->get_fanin(1))
					||(nor0->get_fanin(0)->get_fanin(0) == nor1->get_fanin(1) && nor0->get_fanin(1)->get_fanin(0) == nor1->get_fanin(0))) {
					fanin0_out = nor1->get_fanin(0);
					fanin1_out = nor1->get_fanin(1);
					return true;
				}
			}
			if (nor1->get_fanin(0)->get_operation() == NOT && nor1->get_fanin(1)->get_operation() == NOT) {
				if ((nor1->get_fanin(0)->get_fanin(0) == nor0->get_fanin(0) && nor1->get_fanin(1)->get_fanin(0) == nor0->get_fanin(1))
					||(nor1->get_fanin(0)->get_fanin(0) == nor0->get_fanin(1) && nor1->get_fanin(1)->get_fanin(0) == nor0->get_fanin(0))) {
					fanin0_out = nor0->get_fanin(0);
					fanin1_out = nor0->get_fanin(1);
					return true;
				}
			}
		}
	}
	return false;
}

bool simple_circuitt::convert_XOR3(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	if (gate.get_operation() == NOT)
		return convert_XNOR3(*(gate.get_fanin(0)), fanin0_out, fanin1_out);

	return false;
}

bool simple_circuitt::convert_XNOR_NAND(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	if (gate.get_operation() == NOT && gate.get_fanin(0)->get_operation() == AND)

		return (fanin0_out == gate.get_fanin(0)->get_fanin(0) && fanin1_out == gate.get_fanin(0)->get_fanin(1)) || (fanin0_out == gate.get_fanin(0)->get_fanin(1) && fanin1_out == gate.get_fanin(0)->get_fanin(0));

	return false;
}

bool simple_circuitt::convert_XNOR3(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	gatet* nor0 = NULL;
	gatet* nor1 = NULL;

	if (convert_NOR(gate, nor0, nor1)) {
		if (nor0->get_operation() == AND && nor1->get_operation() == AND) {
			if (convert_XNOR_NAND(*(nor0->get_fanin(0)), nor0->get_fanin(1), nor1->get_fanin(1)) && nor0->get_fanin(0) == nor1->get_fanin(0)) {
				fanin0_out = nor0->get_fanin(1);
				fanin0_out = nor1->get_fanin(1);
				return true;
			}
			if (convert_XNOR_NAND(*(nor0->get_fanin(0)), nor0->get_fanin(1), nor1->get_fanin(0)) && nor0->get_fanin(0) == nor1->get_fanin(1)) {
				fanin0_out = nor0->get_fanin(1);
				fanin0_out = nor1->get_fanin(0);
				return true;
			}
			if (convert_XNOR_NAND(*(nor0->get_fanin(1)), nor0->get_fanin(0), nor1->get_fanin(1)) && nor0->get_fanin(1) == nor1->get_fanin(0)) {
				fanin0_out = nor0->get_fanin(0);
				fanin0_out = nor1->get_fanin(1);
				return true;
			}
			if (convert_XNOR_NAND(*(nor0->get_fanin(1)), nor0->get_fanin(0), nor1->get_fanin(0)) && nor0->get_fanin(1) == nor1->get_fanin(1)) {
				fanin0_out = nor0->get_fanin(0);
				fanin0_out = nor1->get_fanin(0);
				return true;
			}
		}
	}
	return false;
}

/**
 * checks if there would be a X(N)OR when we place a NOT there
 */
bool simple_circuitt::check_for_XOR(gatet* gate, gatet* fin0, gatet* fin1) {
	gatet* in0 = NULL;
	gatet* in1 = NULL;
	if(convert_XOR2(*fin0, in0, in1) || convert_XNOR2(*fin0, in0, in1)) {
		gatet* not_gate;
		if(!has_NOT_fanout(*fin0, not_gate)) {
			not_gate = get_or_create_gate(NOT);
			not_gate->add_fanin(primary_output(fin0), 0);
		}
		gate->replace_by(create_this_gate(not_gate, fin1, XOR));
		return true;
	}
	return false;
}

/*******************************************************************
 Function: simple_circuitt::place_NOT

 Inputs: actual gate and two input gates

 Outputs: void

 Purpose: tries to find a good position for a NOT gate

 \*******************************************************************/
void simple_circuitt::place_NOT(gatet* gate, gatet* fanin0, gatet* fanin1) {
	// 1. could there be a additional X(N)OR if we place the NOT there?
	if (!check_for_XOR(gate, fanin0, fanin1)) {
		if(!check_for_XOR(gate, fanin1, fanin0)) {
			// 2. Is this a Input gate?
			if(fanin0->get_operation() == INPUT) {
				gatet* not_gate;
				if(!has_NOT_fanout(*fanin0, not_gate)) {
					not_gate = get_or_create_gate(NOT);
					not_gate->add_fanin(primary_output(fanin0), 0);
				}
				gate->replace_by(create_this_gate(not_gate, fanin1, XOR));
			}
			else if(fanin1->get_operation() == INPUT) {
				gatet* not_gate;
				if(!has_NOT_fanout(*fanin1, not_gate)) {
					not_gate = get_or_create_gate(NOT);
					not_gate->add_fanin(primary_output(fanin1), 0);
				}
				gate->replace_by(create_this_gate(not_gate, fanin0, XOR));
			}
			// 3. place this NOT behind the XOR
			else {
				gatet* not_gate = get_or_create_gate(NOT);
				gatet* xor_gate = create_this_gate(fanin0, fanin1, XOR);

				not_gate->add_fanin(primary_output(xor_gate), 0);
				gate->replace_by(not_gate);
			}
		}
	}
}

/*******************************************************************
 Function: simple_circuitt::convert_AIG

 Inputs: actual gate and a boolean for the optimization priority

 Outputs: true if we can use one of our patterns

 Purpose: helper function for calling AIG pattern

 \*******************************************************************/
bool simple_circuitt::convert_AIG(gatet* gate, bool round2) {

	bool changed_circuit = false;
	gatet* fanin0 = NULL;
	gatet* fanin1 = NULL;

	// XOR(fanin0, fanin1)
	if(convert_XOR1(*gate, fanin0, fanin1) || convert_XOR2(*gate, fanin0, fanin1) || convert_XOR3(*gate, fanin0, fanin1)) {

		gate->replace_by(create_this_gate(fanin0, fanin1, XOR));
		changed_circuit = true;
	}

	// NOT(XOR(fanin0, fanin1))
	if(convert_XNOR1(*gate, fanin0, fanin1) || convert_XNOR2(*gate, fanin0, fanin1) || convert_XNOR3(*gate, fanin0, fanin1)) {

		place_NOT(gate, fanin0, fanin1);
		changed_circuit = true;
	}

	// OR(fanin0, fanin1)
	if(convert_OR(*gate, fanin0, fanin1)) {

		gate->replace_by(create_this_gate(fanin0, fanin1, OR));
		changed_circuit = true;
	}

	return changed_circuit;
}

/**
 * not used at the moment. but might be a approach to overcome conversion issues with additional NOT gates causing XOR duplicates
 */
bool simple_circuitt::propagate_NOT(gatet& gate) {
	if (gate.get_operation() == XOR) {
		gatet* this_gate;

		// gibt es ein anderes Gate das gleich ist nur ein NOT am einen Fanin hat?
		if (has_this_NOT_fanout(gate.get_fanin(0), gate.get_fanin(1), XOR, this_gate) && gate.get_fanin(0)->get_operation() != INPUT && gate.get_fanin(1)->get_operation() != INPUT) {
			// hat unser Gate ein fanout Gate mit dem gleichen anderen fanin wie ein fanout Gate des gefundenen?
			for (gatet::fanoutst::iterator fanout_it = (*gate.get_fanin(0)).fanouts.begin(); fanout_it != (*gate.get_fanin(0)).fanouts.end(); ++fanout_it) {
				gatet::fanoutt* act_gate = *fanout_it; // aktuelles fanout Gate
				gatet* new_gate; // gleiches fanout Gate des anderen
				gatet* input1 = get_other_input(*(act_gate->second.gate), gate.get_fanin(0)); // anderer Input des aktuellen fanout Gates
				has_this_fanout(this_gate, input1, XOR, new_gate); //finde gleiches Gate
				// gehe weiter nach unten mit new_gate und act_gate
			}
		}
		if (has_this_NOT_fanout(gate.get_fanin(1), gate.get_fanin(0), XOR, this_gate) && gate.get_fanin(0)->get_operation() != INPUT && gate.get_fanin(1)->get_operation() != INPUT) {

			//...
		}
	}
	return false;
}
