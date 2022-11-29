#pragma once

#include "simple_circuit.h"
#include "sorted_vector.h"

#include <unordered_set>
#include <memory>


// List of gates (and their corresponding blocks) that are inputs to a block. A gate `g` is a block
// input to a block `b` if one of `g`'s fanouts  is part of `b`, but not `g` itself.
using block_inputst = std::unordered_map<
	simple_circuitt::gatet const*,
	class execution_blockt const*
>;


enum class block_kindt
{
	gate,
	call,
};

// An execution_blockt is a node in a parallel_execution_grapht.
class execution_blockt
{
public:
	explicit execution_blockt(int id, block_kindt kind, int closest_input_depth) :
		m_closest_input_depth{closest_input_depth},
		m_kind{kind},
		m_id{id} {}

	// No virtual destructor necessary because all derived classes are stored in separate lists

	void add_fanin(execution_blockt *fanin) { m_fanins.insert(fanin); }
	std::unordered_set<execution_blockt*> const& fanins() const{ return m_fanins; }

	// The depth of the closest input any gate in this block depends on
	int closest_input_depth() const { return m_closest_input_depth; }

	int id() const { return m_id; }
	block_kindt kind() const { return m_kind; }

	block_inputst const& block_inputs() const { return m_block_inputs; }

	void reduce_fanins(bitset const &transitive_fanins)
	{
		auto it = m_fanins.begin();
		while(it != m_fanins.end())
		{
			if(transitive_fanins.test((*it)->id()))
				it = m_fanins.erase(it);
			else
				++it;
		}
	}

protected:
	// Only allow derived classes to be copied to prevent slicing
    execution_blockt(execution_blockt const &rhs) = default;
    execution_blockt(execution_blockt &&rhs) = default;

    execution_blockt& operator = (execution_blockt const &rhs) = default;
    execution_blockt& operator = (execution_blockt &&rhs) = default;

	// Stores gates that are not part of this block but are fanins to gates that are.
	// These block input gates are stored together with the block they belong to.
	block_inputst m_block_inputs;

private:
	std::unordered_set<execution_blockt*> m_fanins;
	int m_closest_input_depth;
	block_kindt m_kind;
	int m_id;
};


using depth_sett = sorted_vector<int, true>;

inline depth_sett make_depth_set(int depth)
{
	depth_sett depths;
	depths.insert(depth);

	return depths;
}


using gate_to_blockt = std::unordered_map<simple_circuitt::gatet const*, execution_blockt*>;


// Can contain any kind of gate, except INPUTs and OUTPUTs that belong to a function call
// (circuit-level INPUTs and OUTPUTs are allowed, though).
//
// Only gates that have (1) the same closest_input_depth and (2) the same output_depths are put into
// the same block,
// (1) is necessary so we don't increase the depth of blocks that depend on a gate with a smaller
//     closest_input_depth.
// (2) is necessary so we don't increase the height of the block for a gate that is only
//     used by some successors of the block.
class gate_blockt : public execution_blockt
{
private:
	using GateStore = std::unordered_map<simple_circuitt::gatet const*, int>;

public:
	using GateRange = IteratorRange<PairFirstIterator<GateStore::const_iterator>>;

	gate_blockt(int id, int closest_input_depth, depth_sett const &output_depths) :
		execution_blockt{id, block_kindt::gate, closest_input_depth},
		m_output_depths{output_depths},
		m_non_linear_gates{0},
		m_non_linear_height{0} {}

	// Elements must be added in pre-order: first a gate's fanins, then the gate itself
	void add_element(simple_circuitt::gatet const *gate, gate_to_blockt const &gate_blocks)
	{
		int element_depth = 0;
		for(auto fanin: gate->fanin_range())
		{
			auto it = m_local_gate_depths.find(fanin.gate);
			if(it == m_local_gate_depths.end())
			{
				// The fanin does not exist in this block, so it can been seen as a block input.
				// (Since gates are added in pre-order we don't need to worry that it will be added
				// later.)
				m_block_inputs[fanin.gate] = gate_blocks.at(fanin.gate);
			}
			else
				element_depth = std::max(element_depth, it->second);
		}

		if(is_non_linear_op(gate->get_operation()))
		{
			element_depth++;
			m_non_linear_gates++;
		}

		m_local_gate_depths.insert({gate, element_depth});
		m_non_linear_height = std::max(m_non_linear_height, element_depth);
	}

	depth_sett const& output_depths() const { return m_output_depths; }
	int non_linear_height() const { return m_non_linear_height; }

	int num_gates() const { return m_local_gate_depths.size(); }
	int num_non_linear_gates() const { return m_non_linear_gates; }
	GateRange gates() const { return {m_local_gate_depths.begin(), m_local_gate_depths.end()}; }



	// This method exists solely for testing. The height is automatically computed when calling
	// `add_element()` so don't call this in normal code.
	void set_non_linear_height(int height) { m_non_linear_height = height; }

private:
	// Gate-depths local to this block
	GateStore m_local_gate_depths;

	// Contains the depths of all OUTPUTs influenced by gates in this block
	depth_sett m_output_depths;

	int m_non_linear_gates;
	int m_non_linear_height;
};


struct gate_block_keyt
{
	gate_block_keyt() = default;

	gate_block_keyt(int closest_input_depth, depth_sett const &output_depths) :
		closest_input_depth{closest_input_depth},
		output_depths{output_depths} {}

	// The depth of the closest input any gate in the block depends on
	int closest_input_depth;

	// Contains the depths of all OUTPUTs influenced by gates in this block
	depth_sett output_depths;

	struct hasht
	{
		size_t operator () (gate_block_keyt const &p) const
		{
			size_t hash = SortedVectorHash{}(p.output_depths);
			hash_combine(hash, p.closest_input_depth);

			return hash;
		}
	};
};

inline bool operator == (gate_block_keyt a, gate_block_keyt b)
{
	return a.closest_input_depth == b.closest_input_depth && a.output_depths == b.output_depths;
}


// Represents a function call. Does not contain any gates except the INPUTs and OUTPUTs of its
// arguments and return values
class function_call_blockt : public execution_blockt
{
public:
	explicit function_call_blockt(
		int id, int closest_input_depth, std::string const &func_name, int call_id,
		block_inputst const &block_inputs
	) :
		execution_blockt{id, block_kindt::call, closest_input_depth},
		m_func_name{func_name},
		m_call_id{call_id}
	{
		m_block_inputs = block_inputs;
	}

	std::string const& func_name() const { return m_func_name; }
	int call_id() const { return m_call_id; }

	block_inputst const& block_inputs() const { return m_block_inputs; }

private:
    std::string m_func_name;
    int m_call_id;
};


// Motivation: When optimizing the circuits of multiple functions, we would like to spend our often
// limited time on those functions that have the biggest impact on the depth of the final circuit
// (i.e. the circuit we get after merging all functions back into the main circuit).
//
// For example, if we have two function calls, one to function `a` and one to function `b`, that can
// be executed in parallel (i.e. `a` does not depend on the output of `b` and vice versa), we would
// like to spend more time on optimizing the function with the greater depth.
//
// Another example:
//
// int main(...)
// {
//     int x = foo(...);
//
//     int y = <complex computation that is NOT using x>
//
//     return x + y;
// }
//
// Here, since <complex computation> is not using `x` it can be ran in parallel to the call to
// `foo`. Now, if the depth of `foo` is, say, 10, and the depth of <complex computation> is e.g.
// 100, it would make sense to spend more time on optimizing `main` than on `foo`.
//
// To divide our optimization time intelligently, we need to know which gates and which function
// calls can be run in parallel.
class parallel_execution_grapht
{
public:
	using GateBlockStore = std::unordered_map<gate_block_keyt, gate_blockt, gate_block_keyt::hasht>;
	using CallBlockStore = std::unordered_map<int, function_call_blockt>;

	using GateBlockRange = IteratorRange<PairSecondIterator<GateBlockStore::const_iterator>>;
	using CallBlockRange = IteratorRange<PairSecondIterator<CallBlockStore::const_iterator>>;


	parallel_execution_grapht() :
		m_id_counter{0},
		m_root{new gate_blockt{m_id_counter++, 0, make_depth_set(std::numeric_limits<int>::max())}},
		m_leaf{new gate_blockt{m_id_counter++, 0, make_depth_set(std::numeric_limits<int>::max())}} {}


	gate_blockt* get_gate_block(int closest_input_depth, depth_sett const &output_depths)
	{
		gate_block_keyt key{closest_input_depth, output_depths};
		auto it = m_gate_blocks.find(key);
		if(it != m_gate_blocks.end())
			return &it->second;

		// If we can't reuse an existing block we need to create a new one
		auto res = m_gate_blocks.insert({key, gate_blockt{m_id_counter++, closest_input_depth, output_depths}});
		return &res.first->second;
	}

	function_call_blockt* add_call_block(
		int closest_input_depth, int call_id, std::string const &func_name,
		block_inputst const &block_inputs)
	{
		function_call_blockt call_block{
			m_id_counter++, closest_input_depth, func_name, call_id,
			block_inputs
		};

		auto res = m_call_blocks.insert({call_id, std::move(call_block)});
		assert(res.second); // Assert that the block was really inserted

		return &res.first->second;
	}

	GateBlockRange gate_blocks() const { return {m_gate_blocks.begin(), m_gate_blocks.end()}; }
	CallBlockRange call_blocks() const { return {m_call_blocks.begin(), m_call_blocks.end()}; }

	gate_blockt* root() { return m_root.get(); }
	gate_blockt const* root() const { return m_root.get(); }

	gate_blockt* leaf() { return m_leaf.get(); }
	gate_blockt const* leaf() const { return m_leaf.get(); }

private:
	int m_id_counter;
	GateBlockStore m_gate_blocks;
	CallBlockStore m_call_blocks;

	// Contains all gates with no fanins (INPUT, ONE and CONST gates). This ensures we have a single
	// root node.
	std::unique_ptr<gate_blockt> m_root; // unique_ptr so pointers stay valid after move assignment

    // Contains all circuit-level OUTPUTs which ensures that this is the only leaf node
	std::unique_ptr<gate_blockt> m_leaf;
};


parallel_execution_grapht build_parallel_execution_graph(simple_circuitt const &circuit);

bool equivalent(parallel_execution_grapht const &a, parallel_execution_grapht const &b);


void to_dot(std::ostream &os, parallel_execution_grapht const &graph);
void to_ps(std::ostream &os, parallel_execution_grapht const &graph);

inline void to_ps(std::ostream &&os, parallel_execution_grapht const &graph)
{
	to_ps(os, graph);
}

inline void to_dot(std::ostream &&os, parallel_execution_grapht const &graph)
{
	to_dot(os, graph);
}

void to_dot_simple(std::ostream &os, parallel_execution_grapht const &graph);

inline void to_dot_simple(std::ostream &&os, parallel_execution_grapht const &graph)
{
	to_dot_simple(os, graph);
}
