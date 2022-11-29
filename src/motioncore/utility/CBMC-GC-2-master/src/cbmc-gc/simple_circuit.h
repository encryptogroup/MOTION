/*
 * simple_circuit.h
 *
 *  Created on: 25.09.2013
 *      Author: andreas, niklas
 */

#ifndef SIMPLE_CIRCUIT_H_
#define SIMPLE_CIRCUIT_H_

#include <util/message.h>

#include <map>
#include <set>
#include <string>
#include <vector>
#include <cstdlib>
#include <cassert>
#include <utility>
#include <iostream>

#include <util/options.h>

//#include "mpc_framework_adapter.h"
#include "mpc_io_mapping.h"

class simple_circuitt
{
public:

	enum GATE_OP { INPUT, OUTPUT, ONE, OR, AND, XOR, NOT, LUT };

	class gatet {
	public:
		typedef ::std::pair< gatet*, unsigned > fanoutt;
		typedef ::std::vector< fanoutt* > fanoutst;
		typedef ::std::map < simple_circuitt::gatet*, unsigned > predst; // type of predecessor map
		typedef ::std::set < simple_circuitt::gatet* > clustert;

	private:
		simple_circuitt& circuit;

		const GATE_OP operation;

	public: // TODO make private again and make get_depth a method of this class
		// each gate has at most 2 fanins
		gatet* fanin0;
		gatet* fanin1;

		::std::string label;
	private:
		fanoutst fanouts;

		unsigned gate_label;

		clustert* cluster;
		predst* preds;

	protected:
		gatet(simple_circuitt* circuit, GATE_OP operation);

	public:
		virtual ~gatet();

		void add_fanout(gatet& target_gate, unsigned index);
		void add_LUT_fanout(gatet& target_gate, unsigned index);
		void remove_fanouts();

		void add_fanin(gatet& input_gate, unsigned index);
		gatet* get_fanin(bool fanin_one);
		void remove_fanin(unsigned index);
		void remove_fanin0();
		void remove_fanin1();
		void remove_fanin_LUT(unsigned index);

		GATE_OP get_operation() const;
		::std::string to_string();

		void replace_by(gatet* gate);

	protected:
	    gatet* previous;
	    gatet* next;

		bool was_checked_for_being_constant;

	public:
		friend class simple_circuitt;
	};

	typedef ::std::vector< gatet* > gatest;
    struct timeout_datat {
    	bool check_timeout;
    	time_t start_time;
    	double time_budget;
    	bool stopping_because_of_timeout;
    };

    struct set_comp {
      bool operator() (const ::std::pair <simple_circuitt::gatet*, unsigned >& lhs, const ::std::pair <simple_circuitt::gatet*, unsigned >& rhs) const
      {return lhs.second<rhs.second;}
    };

	simple_circuitt(messaget& p_message_handler);
    virtual ~simple_circuitt();

    messaget& message_handler;

    gatet* get_or_create_gate(GATE_OP operation);
    gatet* get_or_create_zero_gate();
    gatet* create_input_gate(::std::string label);
    gatet* create_output_gate(::std::string label);

    unsigned get_number_of_gates();
    bool zero_gate_is_used();
    gatet& get_one_gate();
    gatet& get_zero_gate();

    void minimize(bool limit_sat_iterations, int num_sat_iterations, double minimization_time_budget /* seconds */, bool not_state_machine);

    typedef ::std::map< simple_circuitt::gatet* , bool > interpretationt;
    typedef ::std::vector< interpretationt* > interpretationst;

    typedef ::std::list< gatet* > bint;
    typedef ::std::list< bint* > binst;
    void determine_structural_redundancy(binst& bins, interpretationst& interpretations, timeout_datat& data);
    bool refine_bins(binst& bins, interpretationt& interpretation);

    enum MINIMIZER {OLD, AIG, THEOREMS, THEOREMS2, STRUCTURE};

    // set of pairs of clusters and their input gates
    typedef ::std::set< ::std::pair< gatet*, ::std::set < gatet* >* > > clusterst;

    /**** clustering methods ****/
    bool clustering; // ToDo: highly experimental feature
    typedef ::std::set< simple_circuitt::gatet* > gate_sett;
    bool cluster();
    void collect_predecessors(gatet* gate);
    unsigned compute_cluster(gatet* gate, std::vector<std::pair< gatet*, unsigned>* >* set);
    void labeling_phase(::std::vector< gatet* > worklist);
    void label_node(gatet* gate);
    bool can_insert(gatet* root, gatet* gate, std::set<gatet*>* inputs);
    void insert_gate(gatet* root, gatet* gate, std::set<gatet*>* inputs);
    void clustering_phase(clusterst* clusters);
    void compute_inputs(gatet::clustert* cluster, gate_sett* set_I, gate_sett* set_inputs);
    bool AND_constraint(gatet* c_gate, clusterst* clusters);
	void replace_with_LUT(gatet* root, std::set< gatet* >* inputs, std::string* result);
	void do_checks(std::string caller);
	void calculate_delay_entry(gatet* gate, gatet* predecessor, unsigned delay);

	/**** evaluation methods ****/
    std::string* evaluate(gatet* root, std::set< gatet* >* inputs);
    bool evaluate_rec(gatet* gate, std::map< gatet*, bool >* eval_map);
    bool evaluate_gate(gatet* gate, bool fanin0, bool fanin1);
    bool evaluate_LUT(gatet* gate, std::map< gatet*, bool >* eval_map);
    bool verify_LUT_circuit(std::vector<std::string*>* before);
    std::vector<std::string*>* evaluate_simple_circuit();

    bool rewrite(timeout_datat& data, bool (*func)(gatet* gate, bool round2, simple_circuitt* obj), bool round2);
    bool rewrite_no_state_machine(timeout_datat& data);
    bool minimizing_state_machine(timeout_datat &data, MINIMIZER *min_op, bool *structure);

    bool rewrite_old(gatet* gate, bool round2);
    bool structurize(gatet* gate, bool round2);
    bool convert_AIG(gatet* gate, bool round2);
    bool use_theorems(gatet* gate, bool round2);

    bool check_gate(gatet*& gate, bool boolean_value, interpretationt& tmp_interpretation);
    bool sweep(gatet*& constant_gate, bool& value, interpretationt interpretation);
    bool evaluates_to_constant(gatet& gate, bool& value);
    bool evaluates_to_constant_(gatet* gate, bool constant_value, interpretationt& interpretation, bool& canceled);

    bool are_equivalent(gatet* gate1, gatet* gate2, interpretationt& interpretation);
    bool implication(gatet* gate1, gatet* gate2, interpretationt& interpretation);

    void cone_of_influence(gatet* gate, ::std::set< gatet* >& coi);
    bool is_two_dominator(gatet* gate, gatet* dominator1, gatet* dominator2);
    void get_subcircuit(gatet* gate, gatet* dominator1, gatet* dominator2, ::std::set< gatet* >& subcircuit);
    void stupid_simulation(::std::set< gatet* >& subcircuit, interpretationt& interpretation);

    void remove(gatet* gate);

    bool cleanup();

    void translate(::std::ofstream& out_one, ::std::ofstream& out_inputs, ::std::ofstream& out_gates);


    struct statst
	{
		int num_gates;
		int num_non_xor_gates;
		int num_luts;
		int depth;
		int non_xor_depth;
	};

	statst query_stats();
	void print_stats(statst const &stats);
	void print_stats();

private:

    void translate_inputs(::std::ofstream& out);
    void translate_one(::std::ofstream& out);
    void translate_zero(::std::ofstream& out);
    void translate_gates(::std::ofstream& out);
    void translate_fanouts(::std::ofstream& out, gatet& gate);

    // Parallelization/Streaming Transformation
    /*void translate_to_bmec(mpc_framework_adapter &framework_adapter, mpc_io_mapping &variable_mapping, ::std::ofstream& out, bool parallelize);
    void translate_all_fanouts_framework_adapter(mpc_framework_adapter &o_parallelizer, unsigned int starting_count);
    void translate_gate_fanouts_framework_adapter(mpc_framework_adapter &o_parallelizer, gatet* gate, int out_label);
    bool translate_not_gate_fanouts_framework_adapter(mpc_framework_adapter &o_parallelizer, gatet* gate, int out_label);
    void translate_inputs_framework_adapter(mpc_framework_adapter &o_parallelizer);
    void translate_outputs_framework_adapter(mpc_framework_adapter &o_parallelizer);
    void translate_const_gates_framework_adapter(mpc_framework_adapter &o_parallelizer);*/

    bool can_be_easily_replaced_by_or(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
    bool can_be_less_easily_replaced_by_or(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
    bool can_be_easily_replaced_by_not_or(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
    bool can_be_easily_replaced_by_or_not(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
    bool can_be_easily_removed(gatet& gate, gatet*& fanin0_out);
    bool can_be_less_easily_removed(gatet& gate, gatet*& fanin0_out);
    bool can_be_easily_removed2(gatet& gate, gatet*& fanin0_out);
    bool can_be_easily_removed3(gatet& gate, gatet*& fanin0_out);
    bool can_be_easily_removed4(gatet& gate, gatet*& fanin0_out);
    bool can_be_easily_removed5(gatet& gate, gatet*& fanin0_out);
    bool can_be_easily_removed6(gatet& gate, gatet*& fanin0_out);
    bool matches(gatet* gate, gatet* a, gatet* b);
    bool can_be_easily_replaced_by_xor(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
    bool can_be_less_easily_replaced_by_xor(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
    bool can_be_less_easily_replaced_by_xor2(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
    bool can_be_less_easily_replaced_by_xor3(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
    bool can_be_less_easily_replaced_by_and(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
    bool can_be_simplified(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out, gatet*& fanin2_out, bool& fanin_flag);
    bool can_be_simplified2(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out, gatet*& fanin2_out, bool& fanin_flag);

    bool simplify(gatet& gate);
    bool simplify2(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
    bool simplify3(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
    bool simplify4(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
    bool simplify5(gatet& gate);

    bool simplify6(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
    bool match_simplify6(simple_circuitt::gatet* or_gate, simple_circuitt::gatet* not_gate, gatet*& a_pin);

    bool simplify7(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
    bool match_simplify7(gatet* not_gate, gatet* and_gate, gatet*& a_pin, gatet*& b_pint);

    bool simplify8(gatet& gate);
    bool simplify9(gatet& gate);
    bool simplify10(gatet& gate);
    bool simplify11(gatet& gate);
    bool match_simplify11(gatet* xor_gate, gatet* a_pin, gatet* b_pin, gatet*& not_xor_gate);
    bool simplify12(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
    bool simplify13(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
    bool simplify14(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
    bool match_simplify14(gatet* a_pin, gatet* not_gate, gatet*& b_pin);
    bool simplify15(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
    bool match_simplify15(gatet* and_gate, gatet* not_gate, gatet*& a_pin, gatet*& b_pin);
    bool simplify16(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);

    bool simplify17(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
    bool simplify18(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);

    bool simplify_trivial(gatet& gate);

    bool structural_hashing_NOT(gatet& gate);
    bool structural_hashing_AND(gatet& gate);
    bool structural_hashing_OR(gatet& gate);
    bool structural_hashing_XOR(gatet& gate);
    bool structural_hashing_BINOP(gatet& gate, GATE_OP operation);

    bool detect_or_not_not(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);

    bool replace_by_zero(gatet& gate); // sweeping
    bool replace_by_zero2(gatet& gate);

    bool propagate_zero(gatet& gate);
    bool propagate_one(gatet& gate);

    bool convert_XOR1(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
    bool convert_XOR2(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
    bool convert_XOR3(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
    bool convert_XNOR1(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
    bool convert_XNOR2(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
    bool convert_XNOR3(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
    bool convert_XOR4(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
    bool convert_NOR(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
    bool convert_OR(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
    bool convert_XNOR_NAND(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);

    bool check_for_XOR(gatet* gate, gatet* fin0, gatet* fin1);
    void place_NOT(gatet* gate, gatet* fanin0, gatet* fanin1);
    bool propagate_NOT(gatet& gate);

    bool has_NOT_fanout(gatet& gate, gatet*& not_gate);
	bool has_this_fanout(gatet*& fanin0, gatet*& fanin1, GATE_OP op, gatet*& this_gate);
	bool has_this_NOT_fanout(gatet*& fanin0, gatet*& fanin1, GATE_OP op, gatet*& this_gate);
	gatet* create_this_gate(gatet*& fanin0, gatet*& fanin1, GATE_OP op);
	gatet* create_this_NOT_gate(gatet*& fanin0);
	gatet* get_other_input(gatet& gate, gatet* input0);

	bool transform3(gatet& gate, gatet*& fanin0_out);
	bool transform4(gatet& gate, gatet*& fanin0_out);
	bool transform5(gatet& gate, gatet*& fanin0_out);
	bool transform8_1(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
	bool transform8_2(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
	bool transform9_1(gatet& gate, gatet*& fanin0_out, bool round2);
	bool transform_inv9_1(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
	bool transform9_2(gatet& gate, gatet*& fanin0_out, bool round2);
	bool transform_inv9_2(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
	bool transform11_1(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
	bool transform11_2(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
	bool transform12_1(gatet& gate, gatet*& fanin0_out);
	bool transform12_2(gatet& gate, gatet*& fanin0_out);
	bool transform13_1(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
	bool transform13_2(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);

	bool transform_XOR1(gatet const& gate, gatet*& fanin0_out, gatet*& fanin1_out);
	bool transform_XOR2(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
	bool transform_XOR3(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
	bool transform_XOR5(gatet& gate, gatet*& fanin0_out);
	bool transform_XOR2N(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
	bool transform_XOR_Absorption(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);
	bool transform_XOR_Absorption2(gatet& gate, gatet*& fanin0_out, gatet*& fanin1_out);

	bool transform_rek(gatet& gate, gatet* act_gate, gatet* searched_parent, GATE_OP op, bool round2, unsigned* counter);
	bool transform_rek_test(gatet& gate, gatet* act_gate, gatet* searched_parent, unsigned* counter);
	bool is_same_gate(gatet* gate, gatet* other_gate);
	bool is_NOT_same_gate(gatet* gate, gatet* other_gate);
	bool is_one_of(gatet* act_gate, gatet* searched_gate, GATE_OP op);

	bool simplify15(gatet& gate, gatet*& fanin0_out);
	bool simplify17(gatet& gate, gatet*& fanin0_out);
	bool structural_minimize(gatet& gate, GATE_OP op);

public:
    typedef ::std::map< unsigned, ::std::set< simple_circuitt::gatet* >* > simple_circuit_level_sett;
    typedef ::std::map< simple_circuitt::gatet* , unsigned > simple_circuit_level_mapt;
private:

    int simple_circuit_get_depth(simple_circuitt& circuit, simple_circuitt::gatet* gate, simple_circuit_level_mapt& level_map, simple_circuit_level_sett* level_set);
    int simple_circuit_get_depth_nXOR(simple_circuitt& circuit, simple_circuitt::gatet* gate, simple_circuitt::simple_circuit_level_mapt& level_map);

    bool is_postdominator(gatet* gate, gatet* dominator, simple_circuit_level_mapt& level_map, unsigned depth_of_dominator);


    bool is_one_gate_actually_used();

public:

    void write_dot(::std::ostream& out, bool leveling, unsigned level_limit);

    // write standardized files
    void write_circuit_files(optionst& _options, mpc_io_mapping &variable_mapping);
    void conditionally_write_dot_file(optionst& _options);

    // TODO make private
    std::map<std::string, std::vector<gatet*>> input_a_variables;
    std::map<std::string, std::vector<gatet*>> input_b_variables;
    std::map<std::string, std::vector<gatet*>> output_variables;

private:
    void write_transitions_dot(::std::ostream& dotfile, gatet* lGate, ::std::map< gatet*, unsigned >& gate_indices, bool leveling, unsigned level_limit, simple_circuit_level_mapt level_map);

    // simulation

    void initialize_interpretation(interpretationt& interpretation);
    void simulate(interpretationt& interpretation);
    void simulate_2(interpretationt& interpretation, simple_circuit_level_sett level_set, timeout_datat& data);

    void order_bin(bint::iterator begin, bint::iterator end, simple_circuit_level_mapt& level_map, bint& ordered_bin /* out */);
    bool equivalence_check_process_constants_bin(gatet* representative_gate, bint::iterator begin, bint::iterator end, simple_circuit_level_mapt& level_map, interpretationst& interpretations, timeout_datat& data);
    bool equivalence_check_process_regular_bin(bint::iterator begin, bint::iterator end, simple_circuit_level_mapt& level_map, interpretationst& interpretations, timeout_datat& data);

    void create_bins(interpretationst& interpretations, binst& bins /* out */, timeout_datat& data);
    bool equivalence_check_process_bin(bint& bin, simple_circuit_level_mapt& level_map, interpretationst& interpretations, timeout_datat& data);

    void init_timeout_data(bool check_timeout, double time_budget, timeout_datat& data);
    bool timeout(timeout_datat& data);

protected:

    gatet* ONE_GATE;
    gatet* ZERO_GATE;

    gatet* input_gates_HEAD;
    gatet* input_gates_TAIL;
    unsigned input_gates_SIZE;

    gatet* output_gates_HEAD;
    gatet* output_gates_TAIL;
    unsigned output_gates_SIZE;

    gatet* gates_HEAD;
    gatet* gates_TAIL;
    unsigned gates_SIZE;
    std::vector<gatet*>* LUT_gates; // ToDo: only for debugging, can be removed
};

#endif /* SIMPLE_CIRCUIT_H_ */
