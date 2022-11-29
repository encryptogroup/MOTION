/*
 * simple_circuit.h
 *
 *  Created on: 25.09.2013
 *      Author: andreas, niklas
 */

#ifndef SIMPLE_CIRCUIT_H_
#define SIMPLE_CIRCUIT_H_

#include <map>
#include <set>
#include <string>
#include <vector>
#include <list>
#include <unordered_map>
#include <unordered_set>
#include <cstdlib>
#include <cassert>
#include <utility>
#include <iostream>
#include <fstream>

//#include "mpc_framework_adapter.h"
#include "mpc_io_mapping.h"
#include "utils.h"
#include "type.h"
#include "logger.h"

enum class variable_ownert
{
	input_alice,
	input_bob,
	output,
};

class simple_circuitt
{
public:
	enum GATE_OP
	{
		INPUT,
		OUTPUT,

		// Boolean gates
		ONE,
		OR,
		AND,
		XOR,
		NOT,
		LUT,

		// Arithmetic gates
		ADD,
		SUB,
		NEG,
		MUL,
		CONST,

		COMBINE,
		// TODO Replace SPLIT with EXTRACT which can extract one or more consecutive bits from its
		//      fanin. SPLIT has the disadvantage that all its fanouts have the same width.
		SPLIT,
	};

	class gatet
	{
		friend class simple_circuitt;

	public:
		struct wire_endpointt
		{
			wire_endpointt() :
				gate{nullptr},
				pin{0} {}

			wire_endpointt(gatet *gate, unsigned pin) :
				gate{gate},
				pin{pin} {}

			gatet *gate;
			unsigned pin;
		};

		typedef ::std::pair< unsigned, wire_endpointt > fanoutt;
		typedef ::std::vector< fanoutt* > fanoutst;
		typedef ::std::map < simple_circuitt::gatet*, unsigned > predst; // type of predecessor map
		typedef ::std::set < simple_circuitt::gatet* > clustert;

	public:
        // TODO make private again and make get_depth a method of this class
		std::vector<wire_endpointt> fanins;

		::std::string label;

		// Can be used to associate custom data with each gate
		union
		{
			void *ptr_val;
			int64_t int_val;
			uint64_t uint_val;
		} user;

	private:
		const GATE_OP operation;
		fanoutst fanouts;

		unsigned gate_label;

		clustert* cluster;
		predst* preds;

        // For arithmetic gates: bit width
        int width;

        // For CONST gate: value
        uint64_t value;

	protected:
		bool was_checked_for_being_constant;

		gatet* previous;
		gatet* next;

		gatet(GATE_OP operation, int input_pins, int width, uint64_t value = 0);

	public:
		virtual ~gatet();
		gatet(gatet const &rhs) = delete;

		gatet& operator = (gatet const &rhs) = delete;

		void add_fanout(unsigned index, wire_endpointt target);
		void add_LUT_fanout(unsigned index, wire_endpointt target_gate);
		void add_LUT_fanout(wire_endpointt target);
		void remove_fanouts();

		fanoutst const& get_fanouts() const { return fanouts; }

		void add_fanin(wire_endpointt input_gate, unsigned index);
		gatet*& get_fanin(unsigned index);
		gatet* const& get_fanin(unsigned index) const;
		unsigned num_fanins() const { return fanins.size(); }
		void remove_fanin(unsigned index);
		void remove_fanin_LUT(unsigned index);

		GATE_OP get_operation() const;
		::std::string to_string() const;

		void replace_by(gatet* gate);
		void replace_by(wire_endpointt ep);
		void replace_pin_by(unsigned pin, wire_endpointt gate);

		std::vector<wire_endpointt> const& fanin_range() const { return fanins; }

		int get_width() const { return width; }
		uint64_t get_value() const { return value; }
		unsigned get_label() const { return gate_label; }
	};

	class gate_const_iterator
	{
	public:
		using difference_type = ptrdiff_t;
		using value_type = gatet;
		using pointer = gatet const*;
		using reference = gatet const&;
		using iterator_category = std::bidirectional_iterator_tag;

		gate_const_iterator(gatet const *gate) :
			gate{gate} {}

		gate_const_iterator& operator ++ ()
		{
			gate = gate->next;
			return *this;
		}

		gate_const_iterator& operator -- ()
		{
			gate = gate->previous;
			return *this;
		}

		gatet const* operator -> () const { return gate; }
		gatet const& operator * () const { return *gate; }

		friend bool operator == (gate_const_iterator a, gate_const_iterator b) { return a.gate == b.gate; }
		friend bool operator != (gate_const_iterator a, gate_const_iterator b) { return a.gate != b.gate; }

	private:
		gatet const *gate;
	};

    // TODO Remove duplication with gate_const_iterator
	class gate_iterator
	{
	public:
		using difference_type = ptrdiff_t;
		using value_type = gatet;
		using pointer = gatet*;
		using reference = gatet&;
		using iterator_category = std::bidirectional_iterator_tag;

		gate_iterator(gatet *gate) :
			gate{gate} {}

		gate_iterator& operator ++ ()
		{
			gate = gate->next;
			return *this;
		}

		gate_iterator& operator -- ()
		{
			gate = gate->previous;
			return *this;
		}

		gatet* operator -> () const { return gate; }
		gatet& operator * () const { return *gate; }

		friend bool operator == (gate_iterator a, gate_iterator b) { return a.gate == b.gate; }
		friend bool operator != (gate_iterator a, gate_iterator b) { return a.gate != b.gate; }

	private:
		gatet *gate;
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

	simple_circuitt(loggert &logger, std::string const &name);
	simple_circuitt(simple_circuitt &&rhs);
	simple_circuitt(simple_circuitt const &rhs);
	virtual ~simple_circuitt();

	gatet* get_or_create_gate(GATE_OP operation, int width = 1, uint64_t value = 0);
	gatet* get_or_create_zero_gate();
	gatet* create_input_gate(::std::string label, int width = 1);
	gatet* create_output_gate(::std::string label, int width = 1);

	gatet* copy_gate_only(gatet const *gate);

	unsigned get_number_of_gates() const;
	bool zero_gate_is_used();
	gatet& get_one_gate();
	gatet& get_zero_gate();

	void minimize(class equivalence_checkert *checker, bool limit_sat_iterations, int num_sat_iterations, double minimization_time_budget /* seconds */, bool not_state_machine);

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

    bool check_gate(class equivalence_checkert *checker, gatet*& gate, bool boolean_value, interpretationt& tmp_interpretation);
    bool sweep(class equivalence_checkert *checker, gatet*& constant_gate, bool& value, interpretationt interpretation);
    bool evaluates_to_constant_(class equivalence_checkert *checker, gatet* gate, bool constant_value, interpretationt& interpretation, bool& canceled);

    bool are_equivalent(class equivalence_checkert *checker, gatet* gate1, gatet* gate2, interpretationt& interpretation);
    bool implication(gatet* gate1, gatet* gate2, interpretationt& interpretation);

    void cone_of_influence(gatet* gate, ::std::set< gatet* >& coi);
    bool is_two_dominator(gatet* gate, gatet* dominator1, gatet* dominator2);
    void get_subcircuit(gatet* gate, gatet* dominator1, gatet* dominator2, ::std::set< gatet* >& subcircuit);

    void remove(gatet* gate);
    void remove_gate_from_list(gatet* gate);

    bool cleanup();


private:
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
	struct level_infot
	{
		::std::set< simple_circuitt::gatet* > *gates = nullptr;
		unsigned num_and_gates = 0;
		unsigned num_mul_gates = 0;
	};

    typedef ::std::map< unsigned, level_infot> simple_circuit_level_sett;
    typedef ::std::map< simple_circuitt::gatet* , unsigned > simple_circuit_level_mapt;

	struct non_linear_deptht
	{
		non_linear_deptht() :
			non_xor_depth{0},
			mul_depth{0} {}

		non_linear_deptht(unsigned non_xor_depth, unsigned mul_depth) :
			non_xor_depth{non_xor_depth},
			mul_depth{mul_depth} {}

		unsigned non_xor_depth;
		unsigned mul_depth;
	};
    typedef ::std::map< simple_circuitt::gatet* , non_linear_deptht > non_linear_level_mapt;

    int simple_circuit_get_depth(gatet* gate, simple_circuit_level_mapt& level_map, simple_circuit_level_sett* level_set) const;
    non_linear_deptht get_non_linear_depth(gatet* gate, non_linear_level_mapt& level_map) const;


    struct statst
	{
		// Total
		int num_gates = 0;
		int depth = 0;

		// Boolean
		int num_boolean_gates = 0;
		int num_non_xor_gates = 0;
		int num_and_gates = 0;
		int num_or_gates = 0;
		int num_xor_gates = 0;
		int num_not_gates = 0;
		int num_luts = 0;
		int non_xor_depth = 0;

		// Arithmetic
		int num_arith_gates = 0;
		int num_mul_gates = 0;
		int num_add_gates = 0;
		int num_sub_gates = 0;
		int num_neg_gates = 0;
		int mul_depth = 0;
	};

	statst query_stats(simple_circuit_level_sett *level_set = nullptr) const;
	void print_stats(statst const &stats);
	void print_stats();


    bool is_postdominator(gatet* gate, gatet* dominator, simple_circuit_level_mapt& level_map, unsigned depth_of_dominator);
    bool is_one_gate_actually_used();

public:
    void write_dot(::std::ostream& out, bool leveling, unsigned level_limit);
    //void conditionally_write_dot_file(optionst& _options);

	void write(std::ostream &out);
	void read(std::istream &in);

	template<typename Func>
	void topological_traversal(Func &&func);

private:
	enum class traversal_markt { temp, perm };

	template<typename Func>
	void topological_traversal_visit(gatet *gate, std::unordered_map<gatet*, traversal_markt> &marks, Func &&func);

    void write_transitions_dot(::std::ostream& dotfile, gatet* lGate, ::std::map< gatet*, unsigned >& gate_indices, bool leveling, unsigned level_limit, simple_circuit_level_mapt level_map);

    // simulation

    void initialize_interpretation(interpretationt& interpretation);
    void simulate(interpretationt& interpretation);
    void simulate_2(interpretationt& interpretation, simple_circuit_level_sett level_set, timeout_datat& data);

    void order_bin(bint::iterator begin, bint::iterator end, simple_circuit_level_mapt& level_map, bint& ordered_bin /* out */);
    bool equivalence_check_process_constants_bin(class equivalence_checkert *checker, gatet* representative_gate, bint::iterator begin, bint::iterator end, simple_circuit_level_mapt& level_map, interpretationst& interpretations, timeout_datat& data);
    bool equivalence_check_process_regular_bin(class equivalence_checkert *checker, bint::iterator begin, bint::iterator end, simple_circuit_level_mapt& level_map, interpretationst& interpretations, timeout_datat& data);

    void create_bins(interpretationst& interpretations, binst& bins /* out */, timeout_datat& data);
    bool equivalence_check_process_bin(class equivalence_checkert *checker, bint& bin, simple_circuit_level_mapt& level_map, interpretationst& interpretations, timeout_datat& data);

    void init_timeout_data(bool check_timeout, double time_budget, timeout_datat& data);
	bool timeout(timeout_datat& data);

public:
	struct variablet
	{
		std::string name;
		variable_ownert owner;
		Type type;
		std::vector<gatet*> gates;
	};

	struct function_callt
	{
		struct vart
		{
			std::string name;
			Type type;
			std::vector<gatet*> gates;
		};
		
		std::string name;
        int call_id;
		std::vector<vart> args;
		std::vector<vart> returns;
	};

	void add_variable(std::string const &name, variable_ownert owner, Type const &type, std::vector<gatet*> &&gates)
	{
		auto res = m_variables.insert({name, {name, owner, type, std::move(gates)}});

		if(owner == variable_ownert::output)
			m_ordered_outputs.push_back(&res.first->second);
		else
			m_ordered_inputs.push_back(&res.first->second);
	}

	void add_function_call(function_callt &&call)
	{
		m_function_calls.push_back(std::move(call));
	}

	using function_call_iterator = std::list<function_callt>::const_iterator;

	bool merge_circuit_if_called(simple_circuitt &&other);
	void merge_circuit(simple_circuitt &&other);
	function_call_iterator merge_circuit(function_call_iterator call, simple_circuitt &&other);

	std::string const& name() const { return m_name; }
	unsigned num_inputs() const { return input_gates_SIZE; }
	unsigned num_outputs() const { return output_gates_SIZE; }

	using FunctionCallConstRange = IteratorRange<std::list<function_callt>::const_iterator>;
	using FunctionCallRange = IteratorRange<std::list<function_callt>::iterator>;

	FunctionCallRange function_calls() { return {m_function_calls.begin(), m_function_calls.end()}; }
	FunctionCallConstRange function_calls() const { return {m_function_calls.begin(), m_function_calls.end()}; }

	using VariableConstRange = IteratorRange<PairSecondIterator<std::map<std::string, variablet>::const_iterator>>;
	using VariableRange = IteratorRange<PairSecondIterator<std::map<std::string, variablet>::iterator>>;
	VariableConstRange variables() const { return {m_variables.begin(), m_variables.end()}; }
	VariableRange variables() { return {m_variables.begin(), m_variables.end()}; }

	using GateConstRange = IteratorRange<gate_const_iterator>;
	using GateRange = IteratorRange<gate_iterator>;

	GateRange gates() { return {gates_HEAD, nullptr}; }
	GateConstRange gates() const { return {gates_HEAD, nullptr}; }

	GateRange inputs() { return {input_gates_HEAD, nullptr}; }
	GateConstRange inputs() const { return {input_gates_HEAD, nullptr}; }
	GateRange outputs() { return {output_gates_HEAD, nullptr}; }
	GateConstRange outputs() const { return {output_gates_HEAD, nullptr}; }

	using GateVectorRange = IteratorRange<std::unordered_set<gatet*>::const_iterator>;
	GateVectorRange root_gates() const { return {m_root_gates.begin(), m_root_gates.end()}; }

    std::vector<variablet*> const& ordered_inputs() const { return m_ordered_inputs; }
    std::vector<variablet*> const& ordered_outputs() const { return m_ordered_outputs; }


	// Recursively merge called circuits into their callees.
	void link(std::unordered_map<std::string, simple_circuitt> &other_circuits)
	{
		auto cur_call = m_function_calls.cbegin();
		while(cur_call != m_function_calls.end())
		{
			auto it = other_circuits.find(cur_call->name);
			if(it == other_circuits.end())
				throw std::runtime_error{"Cannot find circuit: " + cur_call->name};

			simple_circuitt &sub = it->second;
			sub.link(other_circuits);

			m_logger->info() << "Merging \"" << sub.name() << "\" into \"" << m_name << "\"" << eom;
			cur_call = merge_circuit(cur_call, simple_circuitt{sub});
		}

		// After merging we may find out that some gates are no longer used. Remove them.
		cleanup();
	}

private:
	loggert* m_logger;

	std::string m_name;

	std::map<std::string, variablet> m_variables;
	std::vector<variablet*> m_ordered_inputs;
	std::vector<variablet*> m_ordered_outputs;
	std::list<function_callt> m_function_calls;

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

	// Contains all gates that have no fanins, i.e. INPUT, ONE and CONST gates
	std::unordered_set<gatet*> m_root_gates;

	bool clustering; // ToDo: highly experimental feature
};


template<typename Func>
void simple_circuitt::topological_traversal(Func &&func)
{
	std::unordered_map<gatet*, traversal_markt> marks;
	for(gatet *out = output_gates_HEAD; out; out = out->next)
		topological_traversal_visit(out, marks, std::forward<Func>(func));
}

template<typename Func>
void simple_circuitt::topological_traversal_visit(gatet *gate, std::unordered_map<gatet*, traversal_markt> &marks, Func &&func)
{
	auto res = marks.insert({gate, traversal_markt::temp});
	if(!res.second) // gate already has a mark?
	{
		if(res.first->second == traversal_markt::temp)
			throw std::runtime_error{"Cycle in circuit"};

		return;
	}

	for(auto fanin: gate->fanins)
		topological_traversal_visit(fanin.gate, marks, std::forward<Func>(func));

	func(gate);
	marks[gate] = traversal_markt::perm;
}


template<typename Func>
void for_each_circuit_output(simple_circuitt const &circuit, Func &&func)
{
	for(auto const &var: circuit.variables())
	{
		if(var.owner == variable_ownert::output)
		{
			for(auto gate: var.gates)
				func(gate);
		}
	}
}


inline std::pair<int, int> get_pin_counts(simple_circuitt::GATE_OP op, int width)
{
	switch (op) {
		case simple_circuitt::XOR: return {2, 1};
		case simple_circuitt::AND: return {2, 1};
		case simple_circuitt::ONE: return {0, 1};
		case simple_circuitt::OR: return {2, 1};
		case simple_circuitt::NOT: return {1, 1};
		case simple_circuitt::INPUT: return {0, 1};
		case simple_circuitt::OUTPUT: return {1, 0};
		case simple_circuitt::ADD: return {2, 1};
		case simple_circuitt::SUB: return {2, 1};
		case simple_circuitt::MUL: return {2, 1};
		case simple_circuitt::NEG: return {1, 1};
		case simple_circuitt::CONST: return {0, 1};
		case simple_circuitt::COMBINE: return {width, 1};
		case simple_circuitt::SPLIT: return {1, width};
		default: return {-1, -1};
	}
}

inline simple_circuitt::gatet::wire_endpointt primary_output(simple_circuitt::gatet *gate)
{
	if(get_pin_counts(gate->get_operation(), gate->get_width()).second != 1)
		throw std::runtime_error{gate->to_string() + " has no primary output pin"};

	return {gate, 0};
}

inline bool is_boolean_non_const_op(simple_circuitt::GATE_OP op)
{
	switch (op) {
		case simple_circuitt::XOR:
		case simple_circuitt::AND:
		case simple_circuitt::OR:
		case simple_circuitt::NOT:
		case simple_circuitt::LUT:
			return true;
		default:
			return false;
	}
}

inline bool is_boolean_op(simple_circuitt::GATE_OP op)
{
	return op == simple_circuitt::ONE || is_boolean_non_const_op(op);
}

inline bool is_arithmetic_non_const_op(simple_circuitt::GATE_OP op)
{
	switch (op) {
		case simple_circuitt::ADD:
		case simple_circuitt::SUB:
		case simple_circuitt::NEG:
		case simple_circuitt::MUL:
			return true;
		default:
			return false;
	}
}

inline bool is_arithmetic_op(simple_circuitt::GATE_OP op)
{
	return op == simple_circuitt::CONST || is_arithmetic_non_const_op(op);
}

inline bool is_non_linear_op(simple_circuitt::GATE_OP op)
{
	switch (op) {
		case simple_circuitt::AND:
		case simple_circuitt::OR:
		case simple_circuitt::MUL:
			return true;
		default:
			return false;
	}
}

inline bool is_combine_or_split_op(simple_circuitt::GATE_OP op)
{
	switch (op) {
		case simple_circuitt::COMBINE:
		case simple_circuitt::SPLIT:
			return true;
		default:
			return false;
	}

}

inline simple_circuitt::non_linear_deptht max(
	simple_circuitt::non_linear_deptht a,
	simple_circuitt::non_linear_deptht b)
{
	return {std::max(a.non_xor_depth, b.non_xor_depth), std::max(a.mul_depth, b.mul_depth)};
}


struct wire_endpoint_hasht
{
	size_t operator () (simple_circuitt::gatet::wire_endpointt we) const
	{
		size_t h = 0;
		hash_combine(h, we.pin);
		hash_combine(h, we.gate);

		return h;
	}
};

inline bool operator == (simple_circuitt::gatet::wire_endpointt a, simple_circuitt::gatet::wire_endpointt b)
{
	return a.gate == b.gate && a.pin == b.pin;
}


inline simple_circuitt read_circuit(std::istream &is, loggert &log)
{
	simple_circuitt circuit{log, ""};
	circuit.read(is);

	return circuit;
}

inline simple_circuitt read_circuit(std::string const &filename, loggert &log)
{
	std::ifstream file{filename};
	return read_circuit(file, log);
}


#endif /* SIMPLE_CIRCUIT_H_ */
