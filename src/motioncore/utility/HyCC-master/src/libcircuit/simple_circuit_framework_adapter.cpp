/*
 * simple_circuit_framework_adapter.cpp
 *
 *  Created on: 23.04.2013
 *      Author: niklas
 */

#if 0
#include "simple_circuit.h"

#include <stdlib.h>

#include <string>
#include <cassert>
#include <fstream>
#include <sstream>
#include <iostream>
#include <climits>

#include "mpc_framework_adapter.h"
#include "gate_node.h"

/*
 Translates the IR representation into the bmec file format for the ME_SFE 
 * framework, https://code.google.com/p/me-sfe/ by Henecka and Schneider
 *
 * Major differences to the FastGC framework is the idea of using a register 
 * based representation instead of a graph. Thus, the circuit is 'evaluated'
 * to allocate new registers for upcoming wires and to free those that are not
 * used any more.
 * 
 */
void simple_circuitt::translate_to_bmec(mpc_framework_adapter &framework_adapter, mpc_io_mapping &variable_mapping, ::std::ofstream& out, bool parallelize) {
  cout << "Translating circuit into the BMEC format" << endl;
  // reassign labels
	unsigned i;
  unsigned starting_count;
  if (zero_gate_is_used()) {
    starting_count = 1;
    ZERO_GATE->label = "1"; 
  } else {
    starting_count = 0;
  }
  
  i = starting_count;
  
  for (gatet* gate = gates_HEAD; gate != NULL; gate = gate->next, i++) {
    // Existing
    ::std::stringstream sstr;
    sstr << (i + 1);
    gate->label = sstr.str();

    // New
    gate_node_t *gate_p = new gate_node_t();
    framework_adapter.init_gate(gate_p);
    gate_p->label = (i + 1);
    
    
    switch(gate->get_operation()) {
      case AND:
        gate_p->type=gate_node_t::AND_TT;
        break;
      case OR:
        gate_p->type=gate_node_t::OR_TT;
        break;
      case NOT:
       gate_p->type=gate_node_t::NOT_TT;
       break;
      case XOR:
        gate_p->type=gate_node_t::XOR_TT;
        break;
      default:
        ::std::cerr << gate->to_string() << "\n";
        ::std::cerr << "[ERROR] unsupported gate type (" << __FILE__ << ", " << __LINE__ << ")" << ::std::endl;
        exit(-1);
		}
    framework_adapter.add_gate(gate_p);
	}
  //cout << framework_adapter.INPUT_OFFSET << " " << framework_adapter.ONE_LABEL << " " << framework_adapter.ZERO_LABEL << endl;

	//translate_inputs(out_inputs);
	//translate_zero(out_gates);
  cout << "Translating IR to framework adapter...\n";
  //cout << "Translate_inputs_gates" << endl;
  translate_inputs_framework_adapter(framework_adapter);
  //cout << "translate_const_gates" << endl;
  translate_const_gates_framework_adapter(framework_adapter);
  //cout << "translate_all_fanouts_gates" << endl;
	translate_all_fanouts_framework_adapter(framework_adapter,starting_count);  
  
  //translate_outputs_framework_adapter(framework_adapter);
  
  cout << "Evaluating and translating to BMECC..." << endl;
  framework_adapter.translate_to_BMECC(out, parallelize);
  framework_adapter.clear();  
}


void simple_circuitt::translate_all_fanouts_framework_adapter(mpc_framework_adapter &adapter, unsigned int starting_count) {
	// write fanouts
  
  unsigned int i = starting_count;
  for (gatet* gate = gates_HEAD; gate != NULL; gate = gate->next) {
    i++;
    translate_gate_fanouts_framework_adapter(adapter, gate, i);
  }  
}


void simple_circuitt::translate_gate_fanouts_framework_adapter(mpc_framework_adapter &adapter, gatet* gate, int out_label) {
	// write fanouts
  for (gatet::fanoutst::iterator fanout_it = gate->fanouts.begin(); fanout_it != gate->fanouts.end(); ++fanout_it) {
    const gatet::fanoutt* fanout = *fanout_it;
   
    if (fanout->first == ONE_GATE || fanout->first == ZERO_GATE ) {
      continue;
    } else {
      int connect_to_gate = atoi(fanout->first->label.c_str());
      if(connect_to_gate >= 0) {
        adapter.link_gate(out_label, connect_to_gate, !fanout->second);
//        
      } else {
        adapter.link_output_gate(( -connect_to_gate  -1), out_label);
      }
    }
  }
  if(gate->get_operation() == NOT) {
    adapter.change_not_to_xor(out_label);
  }
}

bool simple_circuitt::translate_not_gate_fanouts_framework_adapter(mpc_framework_adapter &adapter, gatet* gate, int out_label) {
	// write fanouts
  bool done = true;
  for (gatet::fanoutst::iterator fanout_it = gate->fanouts.begin(); fanout_it != gate->fanouts.end(); ++fanout_it) {
    const gatet::fanoutt* fanout = *fanout_it;
   
    if (fanout->first == ZERO_GATE && ZERO_GATE->fanouts.empty()) {
      continue;
    } else {
      int connect_to_gate = atoi(fanout->first->label.c_str());
      if(connect_to_gate >= 0) {
        done &= adapter.link_not_gate(out_label, connect_to_gate, !fanout->second);
//        adapter.change_not_to_xnor(out_label);
      }  // TODO OUTPUT GATE
    }
  }
  return done;
}



void simple_circuitt::translate_const_gates_framework_adapter(mpc_framework_adapter &adapter) {
 
  // if(zero_gate_is_used() || !ONE_GATE->fanouts.empty()) {
      if( ZERO_GATE->fanouts.size() > 0) {
        std::cout << "Zero gate is in use" << endl;
        std::cout << "Fanout is " << ZERO_GATE->fanouts.size() << endl;
      }
      gate_node_t *gate_p = new gate_node_t();
      adapter.init_gate(gate_p);
      gate_p->label = adapter.ZERO_LABEL;
      gate_p->type = gate_node_t::XOR_TT;
      adapter.add_gate(gate_p);
      // last added input gate is used to XOR to zero
      adapter.link_gate(adapter.INPUT_OFFSET, adapter.ZERO_LABEL, true);
      adapter.link_gate(adapter.INPUT_OFFSET, adapter.ZERO_LABEL, false);
      translate_gate_fanouts_framework_adapter(adapter, ZERO_GATE, gate_p->label );
//  }
  
  
  //if(!ONE_GATE->fanouts.empty()) {
            // Hack to convert Zero gate into one gate
//      if( ONE_GATE->fanouts.size() > 0) {
//        std::cout << "One gate is in use" << endl;
//        std::cout << "Fanout is " << ONE_GATE->fanouts.size() << endl;
//      }
    	gate_p = new gate_node_t();
      adapter.init_gate(gate_p);
      gate_p->label = adapter.ONE_LABEL;
      gate_p->type = gate_node_t::XNOR_TT; 
      adapter.add_gate(gate_p);
      
//      *gate_p = new GateP();
//      adapter.init_gate(gate_p);
//      gate_p->label = adapter.ONE_LABEL_XNOR;
//      gate_p->type = GateP::XNOR_TT; 
//      adapter.add_gate(gate_p);
      
      adapter.link_gate(adapter.ZERO_LABEL, gate_p->label, false);
      adapter.link_gate(adapter.ZERO_LABEL, gate_p->label, true);
      
     // translate_gate_fanouts_framework_adapter(adapter, ONE_GATE, gate_p->label);
      // One gate is NOT zero gate. Thus linking
      translate_gate_fanouts_framework_adapter(adapter, ONE_GATE, gate_p->label);
      
 // } 
  
  
}

void simple_circuitt::translate_inputs_framework_adapter(mpc_framework_adapter &adapter) {
  //int input_label_counter_creator = 0; 
  //int input_label_counter_evaluator = 0; 
  //cout << "translate input parallel()" << endl;
  int i = adapter.INPUT_OFFSET;
	for (gatet* gate = input_gates_HEAD; gate != NULL; gate = gate->next) {
    //std::cout << "Input Label" << gate->label << std::endl;
    
    // Creates an Empty Gate, used as input gate
		gate_node_t *gate_p = new gate_node_t();
    // Counting starts at 2, if constant gates are used.
    // Thus, unique label is created here
    adapter.init_gate(gate_p);
    gate_p->label = i++;//adapter.get_number_of_gates() + LONG_MAX *3/4;
    //cout << "Input gate label is " << gate_p->label << endl;
    // Empty type indicates input gate
    gate_p->type = 0;
    adapter.add_gate(gate_p);
    
		translate_gate_fanouts_framework_adapter(adapter, gate, gate_p->label);
    if (gate->label.at(0) == 'A') {
      adapter.link_input_gate(gate_p, true);
      //input_label_counter_creator++;
    } else {
      adapter.link_input_gate(gate_p, false);
      //input_label_counter_evaluator++;
    } 
	}
  //cout << "translate input parallel() done" << endl;
}

// Do i need extra gates?
void simple_circuitt::translate_outputs_framework_adapter(mpc_framework_adapter &adapter) {
  int output_label_counter = 0; 
	for (gatet* gate = output_gates_HEAD; gate != NULL; gate = gate->next) {
    
    //cout << "Output gate label " << gate->label << " " << endl;
    
    // Creates an Empty Gate, used as input gate
		//GateP *gate_p = new GateP();
    
    // Counting starts at 2, if constant gates are used.
    //gate_p->label = atoi(gate->label.c_str());
    //gate_p->type = 0;
    //o_parallelizer.add_gate(gate_p);
		//translate_gate_fanouts_parallel(o_parallelizer, gate, gate_p->label);
    //adapter.link_output_gate(output_label_counter, gate_p->label);
    adapter.link_output_gate(output_label_counter, atoi(gate->label.c_str()));
    output_label_counter++;
	}
}

#endif
