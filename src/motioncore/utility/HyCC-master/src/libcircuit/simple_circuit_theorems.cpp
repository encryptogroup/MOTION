/*
 * simple_circuit_theorems.cpp
 *
 *  Created on: 10.08.2015
 *      Author:
 *    Function: Boolean Theorems
 */

#include "simple_circuit.h"

#define MAX_STEPS 10

/*******************************************************************
 Function: simple_circuitt::use_theorems

 Inputs: actual gate and a boolean for the optimization priority

 Outputs: true if we can use one of our theorems

 Purpose: helper function for calling theorem pattern

 \*******************************************************************/
bool simple_circuitt::use_theorems(gatet* gate, bool round2) {
	bool changed_circuit = false;
	gatet* fanin0 = NULL;
	gatet* fanin1 = NULL;

	if (propagate_zero(*gate) || propagate_one(*gate) || transform_XOR5(*gate, fanin0) || transform3(*gate, fanin0))
		changed_circuit = true;

	fanin0 = NULL;
	unsigned counter1 = 0;
	unsigned counter2 = 0;
	gatet* searched_parent = gate;

	if (gate->get_operation() == OR || gate->get_operation() == XOR ) { // || gate->get_operation() == AND 
		if (transform_rek(*(gate->get_fanin(0)), gate->get_fanin(1), searched_parent, gate->get_operation(), round2, &counter1) || transform_rek(*(gate->get_fanin(1)), gate->get_fanin(0), searched_parent, gate->get_operation(), round2, &counter2))
			changed_circuit = true;
	}

	fanin0 = NULL;

	if (transform4(*gate, fanin0) || transform5(*gate, fanin0) || transform12_1(*gate, fanin0) || transform12_2(*gate, fanin0)) {

		assert(fanin0);
		gate->replace_by(fanin0);

		changed_circuit = true;
	}

	fanin0 = NULL;

	if (structural_hashing_NOT(*gate) || structural_hashing_BINOP(*gate, AND) || structural_hashing_BINOP(*gate, OR) || structural_hashing_BINOP(*gate, XOR))
		changed_circuit = true;

	if (transform8_2(*gate, fanin0, fanin1) || can_be_less_easily_replaced_by_or(*gate, fanin0, fanin1) || simplify13(*gate, fanin0, fanin1) || transform_inv9_2(*gate, fanin0, fanin1) || transform11_1(*gate, fanin0, fanin1)) {
		// OR(fanin0, fanin1)
		gate->replace_by(create_this_gate(fanin0, fanin1, OR));
		changed_circuit = true;
	}

	fanin0 = NULL;
	fanin1 = NULL;
	if (transform_XOR1(*gate, fanin0, fanin1) || can_be_less_easily_replaced_by_xor(*gate, fanin0, fanin1) || can_be_less_easily_replaced_by_xor2(*gate, fanin0, fanin1) || transform_XOR2N(*gate, fanin0, fanin1)) {

		// XOR(fanin0, fanin1)
		gate->replace_by(create_this_gate(fanin0, fanin1, XOR));
		changed_circuit = true;
	}

	fanin0 = NULL;
	fanin1 = NULL;

	if (transform8_1(*gate, fanin0, fanin1) || transform11_2(*gate, fanin0, fanin1) || transform_inv9_1(*gate, fanin0, fanin1) || transform_XOR3(*gate, fanin0, fanin1) || transform_XOR_Absorption(*gate, fanin0, fanin1) || transform_XOR_Absorption2(*gate, fanin0, fanin1)) {

		// AND (fanin0, fanin1)
		gate->replace_by(create_this_gate(fanin0, fanin1, AND));
		changed_circuit = true;
	}

	if (simplify11(*gate))
		changed_circuit = true;

	fanin0 = NULL;

	if (transform9_1(*gate, fanin0, round2) || simplify15(*gate, fanin0) || simplify17(*gate, fanin0) || transform9_2(*gate, fanin0, round2)) {

		// NOT(fanin0)
		gate->replace_by(create_this_NOT_gate(fanin0));
		changed_circuit = true;
	}

	return changed_circuit;
}

/**
 * Constant Propagation for Zero Gates
 * T1 Identität: x+0 = x
 * T2' Nullelement: x*0 = 0
 * T4' Involution: NOT(0) = 1
 * XOR 6: XOR(x, 0) = x
 */
bool simple_circuitt::propagate_zero(gatet& gate) {
	switch (gate.get_operation()) {
		default:
		break;
	case NOT:
		if (gate.get_fanin(0) == ZERO_GATE) {
			gate.replace_by(ONE_GATE);
			return true;
		}
		break;
	case AND:
		if (gate.get_fanin(0) == ZERO_GATE || gate.get_fanin(1) == ZERO_GATE) {
			gate.replace_by(ZERO_GATE);
			return true;
		}
		break;
	case XOR:
	case OR:
		if (gate.get_fanin(0) == ZERO_GATE) {
			gate.replace_by(gate.get_fanin(1));
			return true;
		}
		if (gate.get_fanin(1) == ZERO_GATE) {
			gate.replace_by(gate.get_fanin(0));
			return true;
		}
		break;
	}
	return false;
}

/**
 * Constant Propagation for One Gates
 * T1' Identität: x*1 = x
 * T2 Einselement: x+1 = 1
 * T4' Involution: NOT(1) = 0
 * XOR 4: XOR(x, 1) = NOT(x)
 */
bool simple_circuitt::propagate_one(gatet& gate) {
	switch(gate.get_operation()) {
		case INPUT:
		case OUTPUT:
		case ONE:
		case NOT:
			if (gate.get_fanin(0) == ONE_GATE && (&gate != ZERO_GATE)) {
				gate.replace_by(ZERO_GATE);
				return true;
			}
			break;
		case AND:
			if (gate.get_fanin(0) == ONE_GATE) {
				gate.replace_by(gate.get_fanin(1));
				return true;
			}
			if (gate.get_fanin(1) == ONE_GATE) {
				gate.replace_by(gate.get_fanin(0));
				return true;
			}
			break;
		case OR:
			if (gate.get_fanin(0) == ONE_GATE || gate.get_fanin(1) == ONE_GATE) {
				gate.replace_by(ONE_GATE);
				return true;
			}
			break;
		case XOR:
			if (gate.get_fanin(0) == ONE_GATE) {
				gate.replace_by(create_this_NOT_gate(gate.get_fanin(1)));
				return true;
			}
			if (gate.get_fanin(1) == ONE_GATE) {
				gate.replace_by(create_this_NOT_gate(gate.get_fanin(0)));
				return true;
			}
			break;

		case LUT:
			// TODO Should we do anything here?
			break;

		case ADD:
		case SUB:
		case NEG:
		case MUL:
		case CONST:
			// Nothing to do
			break;

		case COMBINE:
		case SPLIT:
			// TODO Should we do anything here?
			break;
	}

	return false;
}

/**
 * T3 & T3': Idempotenz
 * OR(x, x) = x
 * AND(x, x) = x
 */
bool simple_circuitt::transform3(gatet& gate, gatet*& fanin0_out) {

	GATE_OP op = gate.get_operation();
	if (op == OR || op == AND) {

		if (is_same_gate(gate.get_fanin(0), gate.get_fanin(1))) {
			gate.replace_by(gate.get_fanin(0));
			return true;
		}
	}
	return false;
}

/**
 * T4: Involution
 * NOT(NOT(x))
 */
bool simple_circuitt::transform4(gatet& gate, gatet*& fanin0_out) {

	if(gate.get_operation() == NOT && gate.get_fanin(0)->get_operation() == NOT) {
		fanin0_out = gate.get_fanin(0)->get_fanin(0);
		return true;
	}
	return false;
}

/**
 * T5 & T5': Komplement
 * OR(x, NOT(x)) = 1
 * AND(x, NOT(x)) = 0
 */
bool simple_circuitt::transform5(gatet& gate, gatet*& fanin0_out) {

	if (gate.get_operation() == OR || gate.get_operation() == AND) {

		if (gate.get_operation() == OR)
			fanin0_out = ONE_GATE;
		else fanin0_out = ZERO_GATE;

		return (is_NOT_same_gate(gate.get_fanin(0), gate.get_fanin(1)));
	}
	return false;
}

/**
 * T8: Distributivität
 * OR(AND(x, y), AND(x, z)) = AND(x, OR(y, z))
 */
bool simple_circuitt::transform8_1(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	if (gate.get_operation() == OR) {
		if (gate.get_fanin(0)->get_operation() == AND && gate.get_fanin(1)->get_operation() == AND && gate.get_fanin(0)->fanouts.size() == 1 && gate.get_fanin(1)->fanouts.size() == 1) {

			if(gate.get_fanin(0)->get_fanin(0) == gate.get_fanin(1)->get_fanin(0)) {
				fanin0_out = create_this_gate(gate.get_fanin(0)->get_fanin(1), gate.get_fanin(1)->get_fanin(1), OR);
				fanin1_out = gate.get_fanin(0)->get_fanin(0);
				return true;
			}
			if(gate.get_fanin(0)->get_fanin(0) == gate.get_fanin(1)->get_fanin(1)) {
				fanin0_out = create_this_gate(gate.get_fanin(0)->get_fanin(1), gate.get_fanin(1)->get_fanin(0), OR);
				fanin1_out = gate.get_fanin(0)->get_fanin(0);
				return true;
			}
			if(gate.get_fanin(0)->get_fanin(1) == gate.get_fanin(1)->get_fanin(0)) {
				fanin0_out = create_this_gate(gate.get_fanin(0)->get_fanin(0), gate.get_fanin(1)->get_fanin(1), OR);
				fanin1_out = gate.get_fanin(0)->get_fanin(1);
				return true;
			}
			if(gate.get_fanin(0)->get_fanin(1) == gate.get_fanin(1)->get_fanin(1)) {
				fanin0_out = create_this_gate(gate.get_fanin(0)->get_fanin(0), gate.get_fanin(1)->get_fanin(0), OR);
				fanin1_out = gate.get_fanin(0)->get_fanin(1);
				return true;
			}
		}
	}

	return false;
}

/**
 * T8': Distributivität
 * AND(OR(x, y), OR(x, z)) = OR(x, AND(y, z))
 */
bool simple_circuitt::transform8_2(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	if (gate.get_operation() == AND) {
		if (gate.get_fanin(0)->get_operation() == OR && gate.get_fanin(1)->get_operation() == OR) {
			if(gate.get_fanin(0)->get_fanin(0) == gate.get_fanin(1)->get_fanin(0)) {
				fanin0_out = create_this_gate(gate.get_fanin(0)->get_fanin(1), gate.get_fanin(1)->get_fanin(1), AND);
				fanin1_out = gate.get_fanin(0)->get_fanin(0);
				return true;
			}
			if(gate.get_fanin(0)->get_fanin(0) == gate.get_fanin(1)->get_fanin(1)) {
				fanin0_out = create_this_gate(gate.get_fanin(0)->get_fanin(1), gate.get_fanin(1)->get_fanin(0), AND);
				fanin1_out = gate.get_fanin(0)->get_fanin(0);
				return true;
			}
			if(gate.get_fanin(0)->get_fanin(1) == gate.get_fanin(1)->get_fanin(0)) {
				fanin0_out = create_this_gate(gate.get_fanin(0)->get_fanin(0), gate.get_fanin(1)->get_fanin(1), AND);
				fanin1_out = gate.get_fanin(0)->get_fanin(1);
				return true;
			}
			if(gate.get_fanin(0)->get_fanin(1) == gate.get_fanin(1)->get_fanin(1)) {
				fanin0_out = create_this_gate(gate.get_fanin(0)->get_fanin(0), gate.get_fanin(1)->get_fanin(0), AND);
				fanin1_out = gate.get_fanin(0)->get_fanin(1);
				return true;
			}
		}
	}
	return false;
}

/**
 * T9: De Morgan
 * AND(NOT(x), NOT(y)) = NOT(OR(x, y))
 */
bool simple_circuitt::transform9_1(gatet& gate, gatet*& fanin0_out, bool round2) {
	if (gate.get_operation() == AND) {
		if (gate.get_fanin(0)->get_operation() == NOT && gate.get_fanin(0)->fanouts.size() == 1 && gate.get_fanin(1)->get_operation() == NOT && gate.get_fanin(1)->fanouts.size() == 1) {
			fanin0_out = create_this_gate(gate.get_fanin(0)->get_fanin(0), gate.get_fanin(1)->get_fanin(0), OR);
			return true;
		}

		// ToDo: round2 does not work...
		if (gate.get_fanin(0)->get_operation() == NOT && gate.get_fanin(1)->get_operation() == NOT) {
			if (gate.get_fanin(0)->fanouts.size() == 1 || gate.get_fanin(1)->fanouts.size() == 1 /*|| round2*/) {
				fanin0_out = create_this_gate(gate.get_fanin(0)->get_fanin(0), gate.get_fanin(1)->get_fanin(0), OR);
				return true;
			}
		}
	}
	return false;
}

/**
 * T9: De Morgan inverse
 * if we have 2 NOT Gates together with OR we can get a better version with using an AND Gate with one NOT gate
 * NOT(OR(NOT(x), y)) = AND(x, NOT(y))
 */
bool simple_circuitt::transform_inv9_1(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	if (gate.get_operation() == NOT && gate.get_fanin(0)->get_operation() == OR && gate.get_fanin(0)->fanouts.size() == 1) {
		if (gate.get_fanin(0)->get_fanin(0)->get_operation() == NOT && gate.get_fanin(0)->get_fanin(0)->fanouts.size() == 1) {
			fanin0_out = gate.get_fanin(0)->get_fanin(0)->get_fanin(0);
			fanin1_out = create_this_NOT_gate(gate.get_fanin(0)->get_fanin(1));
			return true;
		}
		if (gate.get_fanin(0)->get_fanin(1)->get_operation() == NOT && gate.get_fanin(0)->get_fanin(0)->fanouts.size() == 1) {
			fanin0_out = create_this_NOT_gate(gate.get_fanin(0)->get_fanin(0));
			fanin1_out = gate.get_fanin(0)->get_fanin(1)->get_fanin(0);
			return true;
		}
	}
	return false;
}

/**
 * T9': De Morgan
 * OR(NOT(x), NOT(y)) = NOT(AND(x, y))
 */
bool simple_circuitt::transform9_2(gatet& gate, gatet*& fanin0_out, bool round2) {
	if (gate.get_operation() == OR) {
		if (gate.get_fanin(0)->get_operation() == NOT && gate.get_fanin(1)->get_operation() == NOT && (gate.get_fanin(0)->fanouts.size() == 1 || gate.get_fanin(1)->fanouts.size() == 1 || round2)) {
			fanin0_out = create_this_gate(gate.get_fanin(0)->get_fanin(0), gate.get_fanin(1)->get_fanin(0), AND);
			return true;
		}
	}
	return false;
}

/**
 * T9': De Morgan inverse
 * if we have 2 NOT Gates together with OR we can get a better version with using an AND Gate with one NOT gate
 * NOT(AND(NOT(x), y)) = OR(x, NOT(y))
 */
bool simple_circuitt::transform_inv9_2(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	if (gate.get_operation() == NOT && gate.get_fanin(0)->get_operation() == AND && gate.get_fanin(0)->fanouts.size() == 1) {
		if (gate.get_fanin(0)->get_fanin(0)->get_operation() == NOT && gate.get_fanin(0)->get_fanin(0)->fanouts.size() == 1) {

			fanin0_out = gate.get_fanin(0)->get_fanin(0)->get_fanin(0);
			fanin1_out = create_this_NOT_gate(gate.get_fanin(0)->get_fanin(1));
			return true;
		}
		if (gate.get_fanin(0)->get_fanin(1)->get_operation() == NOT && gate.get_fanin(0)->get_fanin(1)->fanouts.size() == 1) {

			fanin0_out = create_this_NOT_gate(gate.get_fanin(0)->get_fanin(0));
			fanin1_out = gate.get_fanin(0)->get_fanin(1)->get_fanin(0);
			return true;
		}
	}
	return false;
}

/**
 * T11: Absorption 1
 * OR(x, AND(NOT(x), y)) = OR(x, y)
 * DeMorgan: OR(x, NOT(OR(x, y)))
 */
bool simple_circuitt::transform11_1(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	if (gate.get_operation() == OR) {
		// OR(x, AND(NOT(x), y)) = OR(x, y)
		if (gate.get_fanin(0)->get_operation() == AND) {
			if (is_NOT_same_gate(gate.get_fanin(0)->get_fanin(0), gate.get_fanin(1))) {
				fanin0_out = gate.get_fanin(1);
				fanin1_out = gate.get_fanin(0)->get_fanin(1);
				return true;
			}
			if (is_NOT_same_gate(gate.get_fanin(0)->get_fanin(1), gate.get_fanin(1))) {
				fanin0_out = gate.get_fanin(1);
				fanin1_out = gate.get_fanin(0)->get_fanin(0);
				return true;
			}
		}
		if (gate.get_fanin(1)->get_operation() == AND) {
			if (is_NOT_same_gate(gate.get_fanin(1)->get_fanin(0), gate.get_fanin(0))) {
				fanin0_out = gate.get_fanin(0);
				fanin1_out = gate.get_fanin(1)->get_fanin(1);
				return true;
			}
			if (is_NOT_same_gate(gate.get_fanin(1)->get_fanin(1), gate.get_fanin(0))) {
				fanin0_out = gate.get_fanin(0);
				fanin1_out = gate.get_fanin(1)->get_fanin(0);
				return true;
			}
		}
		// OR(x, NOT(OR(x, y)))
		if (gate.get_fanin(0)->get_operation() == NOT && gate.get_fanin(0)->get_fanin(0)->get_operation() == OR) {
			if (gate.get_fanin(1) == gate.get_fanin(0)->get_fanin(0)->get_fanin(0)) {
				fanin0_out = gate.get_fanin(0)->get_fanin(0)->get_fanin(0);
				fanin1_out = create_this_NOT_gate(gate.get_fanin(0)->get_fanin(0)->get_fanin(1));
				return true;
			}
			if  (gate.get_fanin(1) == gate.get_fanin(0)->get_fanin(0)->get_fanin(1)) {
				fanin0_out = create_this_NOT_gate(gate.get_fanin(0)->get_fanin(0)->get_fanin(0));
				fanin1_out = gate.get_fanin(0)->get_fanin(0)->get_fanin(1);
				return true;
			}
		}
		if (gate.get_fanin(1)->get_operation() == NOT && gate.get_fanin(1)->get_fanin(0)->get_operation() == OR) {
			if (gate.get_fanin(0) == gate.get_fanin(1)->get_fanin(0)->get_fanin(0)) {
				fanin0_out = gate.get_fanin(1)->get_fanin(0)->get_fanin(0);
				fanin1_out = create_this_NOT_gate(gate.get_fanin(1)->get_fanin(0)->get_fanin(1));
				return true;
			}

			if (gate.get_fanin(0) == gate.get_fanin(1)->get_fanin(0)->get_fanin(1)) {
				fanin0_out = create_this_NOT_gate(gate.get_fanin(1)->get_fanin(0)->get_fanin(0));
				fanin1_out = gate.get_fanin(1)->get_fanin(0)->get_fanin(1);
				return true;
			}
		}
	}
	return false;
}

/**
 * T11': Absorption 1
 * AND(x, OR(NOT(x), y)) = AND(x, y)
 */
bool simple_circuitt::transform11_2(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	if (gate.get_operation() == AND) {
		if (gate.get_fanin(0)->get_operation() == OR) {
			if (is_NOT_same_gate(gate.get_fanin(0)->get_fanin(0), gate.get_fanin(1))) {
				fanin0_out = gate.get_fanin(1);
				fanin1_out = gate.get_fanin(0)->get_fanin(1);
				return true;
			}
			if (is_NOT_same_gate(gate.get_fanin(0)->get_fanin(1), gate.get_fanin(1))) {
				fanin0_out = gate.get_fanin(1);
				fanin1_out = gate.get_fanin(0)->get_fanin(0);
				return true;
			}
		}
		if (gate.get_fanin(1)->get_operation() == OR) {
			if (is_NOT_same_gate(gate.get_fanin(1)->get_fanin(0), gate.get_fanin(0))) {
				fanin0_out = gate.get_fanin(0);
				fanin1_out = gate.get_fanin(1)->get_fanin(1);
				return true;
			}
			if (is_NOT_same_gate(gate.get_fanin(1)->get_fanin(1), gate.get_fanin(0))) {
				fanin0_out = gate.get_fanin(0);
				fanin1_out = gate.get_fanin(1)->get_fanin(0);
				return true;
			}
		}

		// AND (x, NOT(AND(x, y)) = AND(x, NOT(y))
		if (gate.get_fanin(0)->get_operation() == NOT && gate.get_fanin(0)->get_fanin(0)->get_operation() == AND && gate.get_fanin(0)->fanouts.size() == 1 && gate.get_fanin(0)->get_fanin(0)->fanouts.size() == 1) {
			if (gate.get_fanin(1) == gate.get_fanin(0)->get_fanin(0)->get_fanin(0)) {
				fanin0_out = gate.get_fanin(0)->get_fanin(0)->get_fanin(0);
				fanin1_out = create_this_NOT_gate(gate.get_fanin(0)->get_fanin(0)->get_fanin(1));
				return true;
			}
			if  (gate.get_fanin(1) == gate.get_fanin(0)->get_fanin(0)->get_fanin(1)) {
				fanin0_out = create_this_NOT_gate(gate.get_fanin(0)->get_fanin(0)->get_fanin(0));
				fanin1_out = gate.get_fanin(0)->get_fanin(0)->get_fanin(1);
				return true;
			}
		}
		if (gate.get_fanin(1)->get_operation() == NOT && gate.get_fanin(1)->get_fanin(0)->get_operation() == AND && gate.get_fanin(1)->fanouts.size() == 1 && gate.get_fanin(1)->get_fanin(0)->fanouts.size() == 1) {
			if (gate.get_fanin(0) == gate.get_fanin(1)->get_fanin(0)->get_fanin(0)) {
				fanin0_out = gate.get_fanin(1)->get_fanin(0)->get_fanin(0);
				fanin1_out = create_this_NOT_gate(gate.get_fanin(1)->get_fanin(0)->get_fanin(1));

				return true;
			}

			if (gate.get_fanin(0) == gate.get_fanin(1)->get_fanin(0)->get_fanin(1)) {
				fanin0_out = create_this_NOT_gate(gate.get_fanin(1)->get_fanin(0)->get_fanin(0));
				fanin1_out = gate.get_fanin(1)->get_fanin(0)->get_fanin(1);
				return true;
			}
		}
	}
	return false;
}

/**
 * T12: Absorption 2
 * OR(AND(x, y), x) = x
 */
bool simple_circuitt::transform12_1(gatet& gate, gatet*& fanin0_out) {
	if (gate.get_operation() == OR) {

		if (is_one_of(gate.get_fanin(0), gate.get_fanin(1), AND) && gate.get_fanin(0)->fanouts.size() == 1) {
			fanin0_out = gate.get_fanin(1);
			return true;
		}
		if (is_one_of(gate.get_fanin(1), gate.get_fanin(0), AND) && gate.get_fanin(1)->fanouts.size() == 1) {
			fanin0_out = gate.get_fanin(0);
			return true;
		}
	}
	return false;
}

/**
 * T12': Absorption 2
 * AND(x, OR(x, y)) = x
 */
bool simple_circuitt::transform12_2(gatet& gate, gatet*& fanin0_out) {
	if (gate.get_operation() == AND) {

		if (is_one_of(gate.get_fanin(0), gate.get_fanin(1), OR)) {
			fanin0_out = gate.get_fanin(1);
			return true;
		}

		if (is_one_of(gate.get_fanin(1), gate.get_fanin(0), OR)) {
			fanin0_out = gate.get_fanin(0);
			return true;
		}
	}
	return false;
}

/**
 * T13: Konsensus
 */
bool simple_circuitt::transform13_1(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {

	if (gate.get_operation() == OR) {
		if (gate.get_fanin(0)->get_operation() == OR && gate.get_fanin(1)->get_operation() == AND && gate.get_fanin(0)->get_fanin(0)->get_operation() == AND && gate.get_fanin(0)->get_fanin(1)->get_operation() == AND) {
			// x, y
			if (gate.get_fanin(0)->get_fanin(0)->get_fanin(0)->get_operation() == NOT && gate.get_fanin(1)->get_fanin(0) == gate.get_fanin(0)->get_fanin(0)->get_fanin(0)->get_fanin(0) && gate.get_fanin(1)->get_fanin(1) == gate.get_fanin(0)->get_fanin(1)->get_fanin(0)) {
				// z
				if (gate.get_fanin(0)->get_fanin(0)->get_fanin(1) == gate.get_fanin(0)->get_fanin(1)->get_fanin(1)) {
					gate.get_fanin(0)->replace_by(gate.get_fanin(0)->get_fanin(0));
					return true;
				}
			}
		}
	}

	return false;
}

/**
 * OR(AND(NOT(x), y), AND(NOT(y), x)) = XOR(x, y)
 */
bool simple_circuitt::transform_XOR1(gatet const& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	if (gate.get_operation() == OR) {
		if (gate.get_fanin(0)->get_operation() == AND && gate.get_fanin(1)->get_operation() == AND) {
			if (gate.get_fanin(0)->get_fanin(0)->get_operation() == NOT && gate.get_fanin(1)->get_fanin(0)->get_operation() == NOT) {
				if (gate.get_fanin(0)->get_fanin(0)->get_fanin(0) == gate.get_fanin(1)->get_fanin(1) && gate.get_fanin(1)->get_fanin(0)->get_fanin(0) == gate.get_fanin(0)->get_fanin(1)) {
					fanin0_out = gate.get_fanin(0)->get_fanin(1);
					fanin1_out = gate.get_fanin(1)->get_fanin(1);
					return true;
				}
			}
			if (gate.get_fanin(0)->get_fanin(1)->get_operation() == NOT && gate.get_fanin(1)->get_fanin(0)->get_operation() == NOT) {
				if (gate.get_fanin(0)->get_fanin(1)->get_fanin(0) == gate.get_fanin(1)->get_fanin(1) && gate.get_fanin(1)->get_fanin(0)->get_fanin(0) == gate.get_fanin(0)->get_fanin(0)) {
					fanin0_out = gate.get_fanin(1)->get_fanin(1);
					fanin1_out = gate.get_fanin(0)->get_fanin(0);
					return true;
				}
			}
			if (gate.get_fanin(0)->get_fanin(0)->get_operation() == NOT && gate.get_fanin(1)->get_fanin(1)->get_operation() == NOT) {
				if (gate.get_fanin(0)->get_fanin(0)->get_fanin(0) == gate.get_fanin(1)->get_fanin(0) && gate.get_fanin(1)->get_fanin(1)->get_fanin(0) == gate.get_fanin(0)->get_fanin(1)) {
					fanin0_out = gate.get_fanin(1)->get_fanin(0);
					fanin1_out = gate.get_fanin(0)->get_fanin(1);
					return true;
				}
			}
			if (gate.get_fanin(0)->get_fanin(1)->get_operation() == NOT && gate.get_fanin(1)->get_fanin(1)->get_operation() == NOT) {
				if (gate.get_fanin(0)->get_fanin(1)->get_fanin(0) == gate.get_fanin(1)->get_fanin(0) && gate.get_fanin(1)->get_fanin(1)->get_fanin(0) == gate.get_fanin(0)->get_fanin(0)) {
					fanin0_out = gate.get_fanin(1)->get_fanin(0);
					fanin1_out = gate.get_fanin(0)->get_fanin(0);
					return true;
				}
			}
		}
		// OR(AND(NOT(x), NOT(y)), AND(x, y)) = OR(NOT(OR(x, y)), AND(x, y)) = XOR(NOT(x), y)
		// ToDo: produces bigger circuits
		/*if (gate.get_fanin(0)->fanouts.size() == 1 && gate.get_fanin(1)->fanouts.size() == 1) {
			if (gate.get_fanin(0)->get_operation() == AND && check_for_t9_1(*(gate.get_fanin(1)), gate.get_fanin(0)->get_fanin(0), gate.get_fanin(0)->get_fanin(1))) {
				fanin0_out = create_this_NOT_gate(gate.get_fanin(0)->get_fanin(0));
				fanin1_out = gate.get_fanin(0)->get_fanin(1);
				std::cout << "XOR 1" << std::endl;
				return true;
			}
			if (gate.get_fanin(1)->get_operation() == AND && check_for_t9_1(*(gate.get_fanin(0)), gate.get_fanin(1)->get_fanin(0), gate.get_fanin(1)->get_fanin(1))) {
				fanin0_out = create_this_NOT_gate(gate.get_fanin(1)->get_fanin(0));
				fanin1_out = gate.get_fanin(1)->get_fanin(1);
				std::cout << "XOR 1" << std::endl;
				return true;
			}
		}*/
	}
	return false;
}

/**
 * (XOR(XOR(x, AND(x, y)), y)
 */
bool simple_circuitt::transform_XOR2(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {

	if (gate.get_operation() == XOR) {
		if (gate.get_fanin(0)->get_operation() == XOR) {
			if (gate.get_fanin(0)->get_fanin(1)->get_operation() == AND) {
				if (gate.get_fanin(1) == gate.get_fanin(0)->get_fanin(1)->get_fanin(1) && gate.get_fanin(0)->get_fanin(0) == gate.get_fanin(0)->get_fanin(1)->get_fanin(0)) {
					fanin0_out = gate.get_fanin(1);
					fanin1_out = gate.get_fanin(0)->get_fanin(0);
					return true;
				}
				if (gate.get_fanin(1) == gate.get_fanin(0)->get_fanin(1)->get_fanin(0) && gate.get_fanin(0)->get_fanin(0) == gate.get_fanin(0)->get_fanin(1)->get_fanin(1)) {
					fanin0_out = gate.get_fanin(1);
					fanin1_out = gate.get_fanin(0)->get_fanin(0);
					return true;
				}
			}
		}
	}
	return false;
}

/**
 * XOR(AND(x, y), AND(x, z)) = AND(x, XOR(y, z))
 */
bool simple_circuitt::transform_XOR3(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	if (gate.get_operation() == XOR) {
		if (gate.get_fanin(0)->get_operation() == AND && gate.get_fanin(1)->get_operation() == AND) {
			if(gate.get_fanin(0)->get_fanin(0) == gate.get_fanin(1)->get_fanin(0)) {

				fanin0_out = create_this_gate(gate.get_fanin(0)->get_fanin(1), gate.get_fanin(1)->get_fanin(1), XOR);
				fanin1_out = gate.get_fanin(0)->get_fanin(0);
				return true;
			}
			if(gate.get_fanin(0)->get_fanin(0) == gate.get_fanin(1)->get_fanin(1)) {

				fanin0_out = create_this_gate(gate.get_fanin(0)->get_fanin(1), gate.get_fanin(1)->get_fanin(0), XOR);
				fanin1_out = gate.get_fanin(0)->get_fanin(0);
				return true;
			}
			if(gate.get_fanin(0)->get_fanin(1) == gate.get_fanin(1)->get_fanin(0)) {

				fanin0_out = create_this_gate(gate.get_fanin(0)->get_fanin(0), gate.get_fanin(1)->get_fanin(1), XOR);
				fanin1_out = gate.get_fanin(0)->get_fanin(1);
				return true;
			}
			if(gate.get_fanin(0)->get_fanin(1) == gate.get_fanin(1)->get_fanin(1)) {

				fanin0_out = create_this_gate(gate.get_fanin(0)->get_fanin(0), gate.get_fanin(1)->get_fanin(0), XOR);
				fanin1_out = gate.get_fanin(0)->get_fanin(1);
				return true;
			}
		}
	}
	return false;
}

/**
 * XOR(x, x) = 0
 * XOR(x, NOT(x)) = 1
 */
bool simple_circuitt::transform_XOR5(gatet& gate, gatet*& fanin0_out) {

	if (gate.get_operation() == XOR) {
		if (is_same_gate(gate.get_fanin(0), gate.get_fanin(1))) {
			gate.replace_by(ZERO_GATE);
			return true;
		}
		if (is_NOT_same_gate(gate.get_fanin(0), gate.get_fanin(1))) {
			gate.replace_by(ONE_GATE);
			return true;
		}
	}
	return false;
}

/**
 * XOR(AND(x, y), x) = AND(x, NOT(y))
 * T12 für XOR
 */
bool simple_circuitt::transform_XOR_Absorption(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	if (gate.get_operation() == XOR) {
		if (gate.get_fanin(0)->get_operation() == AND) {
			if(gate.get_fanin(0)->get_fanin(0) == gate.get_fanin(1)) {

				fanin0_out = create_this_NOT_gate(gate.get_fanin(0)->get_fanin(1));
				fanin1_out = gate.get_fanin(1);
				return true;
			}
			if(gate.get_fanin(0)->get_fanin(1) == gate.get_fanin(1)) {

				fanin0_out = create_this_NOT_gate(gate.get_fanin(0)->get_fanin(0));
				fanin1_out = gate.get_fanin(1);
				return true;
			}
		}
		if (gate.get_fanin(1)->get_operation() == AND) {
			if(gate.get_fanin(1)->get_fanin(0) == gate.get_fanin(0)) {

				fanin0_out = create_this_NOT_gate(gate.get_fanin(1)->get_fanin(1));
				fanin1_out = gate.get_fanin(0);
				return true;
			}
			if(gate.get_fanin(1)->get_fanin(1) == gate.get_fanin(0)) {

				fanin0_out = create_this_NOT_gate(gate.get_fanin(1)->get_fanin(0));
				fanin1_out = gate.get_fanin(0);
				return true;
			}
		}
	}
	return false;
}

/**
 * AND(x, XOR(x, y)) = AND(x, NOT(y))
 * T12' für XOR
 */
bool simple_circuitt::transform_XOR_Absorption2(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	if (gate.get_operation() == AND) {
		if (gate.get_fanin(0)->get_operation() == XOR && gate.get_fanin(0)->fanouts.size() == 1) {
			if(gate.get_fanin(0)->get_fanin(0) == gate.get_fanin(1)) {

				fanin0_out = create_this_NOT_gate(gate.get_fanin(0)->get_fanin(1));
				fanin1_out = gate.get_fanin(1);
				return true;
			}
			if(gate.get_fanin(0)->get_fanin(1) == gate.get_fanin(1)) {

				fanin0_out = create_this_NOT_gate(gate.get_fanin(0)->get_fanin(0));
				fanin1_out = gate.get_fanin(1);
				return true;
			}
		}
		if (gate.get_fanin(1)->get_operation() == XOR && gate.get_fanin(1)->fanouts.size() == 1) {
			if(gate.get_fanin(1)->get_fanin(0) == gate.get_fanin(0)) {

				fanin0_out = create_this_NOT_gate(gate.get_fanin(1)->get_fanin(1));
				fanin1_out = gate.get_fanin(0);
				return true;
			}
			if(gate.get_fanin(1)->get_fanin(1) == gate.get_fanin(0)) {

				fanin0_out = create_this_NOT_gate(gate.get_fanin(1)->get_fanin(0));
				fanin1_out = gate.get_fanin(0);
				return true;
			}
		}
	}
	return false;
}

/**
 * XOR(NOT(x), NOT(y)) = XOR(x, y)
 * NOT(XOR(x, NOT(y))) = XOR(x, y)
 * NOT(XOR(NOT(x), y)) = XOR(x, y)
 */
bool simple_circuitt::transform_XOR2N(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out) {
	if (gate.get_operation() == XOR) {
		if (gate.get_fanin(0)->get_operation() == NOT && gate.get_fanin(1)->get_operation() == NOT) {
			fanin0_out = gate.get_fanin(0)->get_fanin(0);
			fanin1_out = gate.get_fanin(1)->get_fanin(0);
			return true;
		}
	}
	if (gate.get_operation() == NOT && gate.get_fanin(0)->get_operation() == XOR) {
		if (gate.get_fanin(0)->get_fanin(0)->get_operation() == NOT) {
			fanin0_out = gate.get_fanin(0)->get_fanin(0)->get_fanin(0);
			fanin1_out = gate.get_fanin(0)->get_fanin(1);
			return true;
		}
		if (gate.get_fanin(0)->get_fanin(1)->get_operation() == NOT) {
			fanin0_out = gate.get_fanin(0)->get_fanin(1)->get_fanin(0);
			fanin1_out = gate.get_fanin(0)->get_fanin(0);
			return true;
		}
	}
	return false;
}

/*******************************************************************
 Function: simple_circuitt::transform_rek

 Inputs: gate we are looking for, act_gate our recursive method operates on, searched_parent as the parent of the "gate", counter used for our recursion step-limit

 Outputs: true if we can use one of our generalized theorems

 Purpose: generalizes some of the theorems to also operate on cascades or trees

 \*******************************************************************/
bool simple_circuitt::transform_rek(gatet& gate, gatet* act_gate, gatet* searched_parent, GATE_OP op, bool round2, unsigned* counter) {

	if (*counter > MAX_STEPS)
		return false;

	if (act_gate->get_operation() == XOR && op == XOR) {
		if (act_gate->fanouts.size() != 1)
			return false;

		if (is_same_gate(act_gate->get_fanin(0), &gate)) {
			act_gate->replace_by(act_gate->get_fanin(1));
			searched_parent->replace_by(get_other_input(*searched_parent, &gate));
			return true;
		}
		if (is_same_gate(act_gate->get_fanin(1), &gate)) {
			act_gate->replace_by(act_gate->get_fanin(0));
			searched_parent->replace_by(get_other_input(*searched_parent, &gate));
			return true;
		}
		if (is_NOT_same_gate(act_gate->get_fanin(0), &gate) && gate.fanouts.size() == 1) {
			act_gate->replace_by(act_gate->get_fanin(1));
			gate.replace_by(ONE_GATE);
			return true;
		}
		if (is_NOT_same_gate(act_gate->get_fanin(1), &gate) && gate.fanouts.size() == 1) {
			act_gate->replace_by(act_gate->get_fanin(0));
			gate.replace_by(ONE_GATE);
			return true;
		}

	}
	else if (op != XOR) {

		// T1 & T1'
		if (is_same_gate(act_gate, &gate)) {
			searched_parent->replace_by(get_other_input(*searched_parent, &gate));
			return true;
		}

		// A4 & A4', priority 2
		if (is_NOT_same_gate(act_gate, &gate) && round2) {
			if (op == OR)
				searched_parent->replace_by(ONE_GATE);
			else searched_parent->replace_by(ZERO_GATE);

			return true;
		}
	}

	bool found = false;

	// traverse cascade if the actual gate has the same operator as the gate we've started with
	if (act_gate->get_operation() == op) {
		*counter = *counter + 1;
		found = transform_rek(gate, act_gate->get_fanin(0), searched_parent, op, round2, counter);
		if (!found)
			found = transform_rek(gate, act_gate->get_fanin(1), searched_parent, op, round2, counter);

		// traverse tree if the gate we started with has a child with the same operator
		if (!found && gate.get_operation() == op && op != XOR) {
			searched_parent = &gate;
			*counter = *counter + 1;
			found = transform_rek(*(gate.get_fanin(0)), act_gate, searched_parent, op, round2, counter);
			if (!found)
				found = transform_rek(*(gate.get_fanin(1)), act_gate, searched_parent, op, round2, counter);
		}
	}
	return found;
}

/*******************************************************************
 Function: simple_circuitt::transform_rek_test

 Inputs: gate we are looking for, act_gate our recursive method operates on, searched_parent as the parent of the "gate", counter used for our recursion step-limit

 Outputs: true if there are duplicates within the circuit

 Purpose: looks for duplicates (is not used atm.)

 \*******************************************************************/
bool simple_circuitt::transform_rek_test(gatet& gate, gatet* act_gate, gatet* searched_parent, unsigned* counter) {

	if (&gate != act_gate && is_same_gate(act_gate, &gate)) {
		act_gate->replace_by(&gate);
		return true;
	}
	if (searched_parent != act_gate && is_same_gate(searched_parent, act_gate)) {
		act_gate->replace_by(searched_parent);
		return true;
	}

	if (*counter > MAX_STEPS)
		return false;

	bool found = false;

	if (act_gate->get_operation() == XOR || act_gate->get_operation() == OR || act_gate->get_operation() == AND || act_gate->get_operation() == NOT) {
		*counter = *counter + 1;
		found = transform_rek_test(gate, act_gate->get_fanin(0), searched_parent, counter);
		if (!found && act_gate->get_operation() != NOT)
			found = transform_rek_test(gate, act_gate->get_fanin(1), searched_parent, counter);

		if (!found && (gate.get_operation() == XOR || gate.get_operation() == OR || gate.get_operation() == AND || gate.get_operation() == NOT)) {
			*counter = *counter + 1;
			searched_parent = &gate;
			found = transform_rek_test(*(gate.get_fanin(0)), act_gate, searched_parent, counter);
			if (!found && gate.get_operation() != NOT)
				found = transform_rek_test(*(gate.get_fanin(1)), act_gate, searched_parent, counter);
		}
	}
	return found;
}
