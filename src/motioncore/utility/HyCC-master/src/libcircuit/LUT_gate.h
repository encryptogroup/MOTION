/*
 * LUT_gate.h
 *
 *  Created on: 07.04.2016
 *      Author: alina
 */

#ifndef SRC_CBMC_GC_SRC_CBMC_LUT_GATE_H_
#define SRC_CBMC_GC_SRC_CBMC_LUT_GATE_H_

#include "simple_circuit.h"

class LUT_gatet : public simple_circuitt::gatet{
public:
	LUT_gatet(simple_circuitt::GATE_OP operation);
	virtual ~LUT_gatet();
	void set_fanins(std::set< std::pair< gatet*, unsigned > >* inputs);
	void add_LUT_fanin(gatet& input_gate, unsigned index);
	void set_outString(std::string* result);
	std::string* get_outString();
	std::set< std::pair< gatet*, unsigned > >* get_fanins();

private:
	std::set< std::pair< gatet*, unsigned > >* fanins;
	std::string* outString;
};


#endif /* SRC_CBMC_GC_SRC_CBMC_LUT_GATE_H_ */
