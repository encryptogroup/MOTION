#include "parallel_execution_graph.h"


namespace {

// Computing non-linear gate depth
//==================================================================================================
using gate_to_callt = std::unordered_map<
	simple_circuitt::gatet const*,
	simple_circuitt::function_callt const*
>;

// Assigns to each INPUT coming from a function call the function call it belongs to
gate_to_callt assign_input_calls(simple_circuitt const &circuit)
{
	gate_to_callt input_to_call;
	for(auto const &call: circuit.function_calls())
	{
		for(auto const &ret: call.returns)
		{
			for(auto in: ret.gates)
				input_to_call[in] = &call;
		}
	}

	return input_to_call;
}

// Assigns to each OUTPUT from a function call the function call it belongs to
gate_to_callt assign_output_calls(simple_circuitt const &circuit)
{
	gate_to_callt output_to_call;
	for(auto const &call: circuit.function_calls())
	{
		for(auto const &arg: call.args)
		{
			for(auto out: arg.gates)
				output_to_call[out] = &call;
		}
	}

	return output_to_call;
}

using gate_to_deptht = std::unordered_map<simple_circuitt::gatet const*, int>;

int compute_gate_depth_rec(
	simple_circuitt::gatet const *gate,
	gate_to_deptht &gate_depths,
	gate_to_callt const &input_to_call)
{
	auto it = gate_depths.find(gate);
	if(it != gate_depths.end())
		return it->second;

	if(gate->get_operation() == simple_circuitt::INPUT)
	{
		auto call_it = input_to_call.find(gate);
		if(call_it == input_to_call.end())
		{
			// Okay, this is a circuit-level INPUT and thus does not depend on any function calls
			return 0;
		}

		auto call = call_it->second;

		// The depth of a function call is the maximum depth of its arguments
		int depth = 0;
		for(auto const &arg: call->args)
		{
			for(auto out: arg.gates)
			{
				int fanin_depth = compute_gate_depth_rec(out, gate_depths, input_to_call);
				depth = std::max(depth, fanin_depth);
			}
		}

		for(auto const &arg: call->args)
		{
			for(auto out: arg.gates)
				gate_depths[out] = depth;
		}

		// A function call itself increases the current depth by one. Reason:
		//  - Assume a call block A has an incoming edge from gate block B whose closest input and
		//    output depth is 0, i.e. B does not contain any non-linear gates ('output/input depth'
		//    refers to the non-linear depth)
		//  - Now we want to assign a linear gate (e.g. XOR, ADD etc) that reads from call block A
		//    to a gate block. It's certainly possible that the closest output depth of the gate is
		//    0, if there are no non-linear gates before the next output. This means that the gate's
		//    closest input and output depth is 0, so it will be assigned to gate block B. Gate
		//    block B would than get a new new incoming edge from call block A. And voila, we have a
		//    cycle (not good).
		depth += 1;

		// The depth of all the return gates of a function call are the same
		for(auto const &ret: call->returns)
		{
			for(auto in: ret.gates)
				gate_depths[in] = depth;
		}

		return depth;
	}


	int depth = 0;
	for(auto fanin: gate->fanin_range())
	{
		auto fanin_depth = compute_gate_depth_rec(fanin.gate, gate_depths, input_to_call);
		depth = std::max(depth, fanin_depth);
	}

	if(is_non_linear_op(gate->get_operation()))
		depth++;

	return gate_depths[gate] = depth;
}


// Computes the non-linear depth of each gate, taking into account that INPUTs from function calls
// depend on the OUTPUTs of function arguments
gate_to_deptht compute_gate_depths(simple_circuitt const &circuit, gate_to_callt const &input_to_call)
{
	gate_to_deptht gate_depths;
	for_each_circuit_output(circuit, [&](simple_circuitt::gatet const *output)
	{
		compute_gate_depth_rec(output, gate_depths, input_to_call);
	});

	return gate_depths;
}



// Building the parallel_execution_grapht
//==================================================================================================
using gate_to_outputst = std::unordered_map<simple_circuitt::gatet const*, depth_sett>;

// Assigns to each gate the depth of the closest OUTPUT it influences
depth_sett const& assign_closest_output(
	simple_circuitt::gatet *gate,
	gate_to_callt const &output_to_call,
	gate_to_deptht const &gate_depths,
	gate_to_outputst &gate_closest_output)
{
	auto it = gate_closest_output.find(gate);
	if(it != gate_closest_output.end())
		return it->second;

	if(gate->get_operation() == simple_circuitt::OUTPUT)
	{
		depth_sett output_depths;

		auto call_it = output_to_call.find(gate);
		if(call_it == output_to_call.end())
		{
			// Circuit outputs (i.e. outputs that are not inputs to function calls) have the maximum
			// depth.
			output_depths.insert(std::numeric_limits<int>::max());
		}
		else
		{
			// If the return value of a function isn't used its arguments (i.e. OUTPUT gates) won't
			// be reached when computing gate depths (see compute_gate_depths()). This is (should)
			// be the only case where `gate_depths` is missing an entry.
			auto depth_it = gate_depths.find(gate);
			if(depth_it != gate_depths.end())
				output_depths.insert(depth_it->second);
		}

		auto res = gate_closest_output.insert({gate, std::move(output_depths)});
		return res.first->second;
	}
	else
	{
		depth_sett closest_outputs;
		for(auto fanout: gate->get_fanouts())
		{
			auto const &cur = assign_closest_output(fanout->second.gate, output_to_call, gate_depths, gate_closest_output);
			closest_outputs.insert(cur.begin(), cur.end());
		}

		auto res = gate_closest_output.insert({gate, std::move(closest_outputs)});
		return res.first->second;
	}
}


// Assigns the specified gate to a block in the parallel_execution_grapht
execution_blockt* assign_element_to_block(
	simple_circuitt::gatet const *element,
	std::unordered_map<simple_circuitt::gatet const*, execution_blockt*> &gate_blocks,
	parallel_execution_grapht &graph,
	gate_to_deptht const &gate_depths,
	gate_to_outputst const &gate_closest_output,
	gate_to_callt const &input_to_call);

execution_blockt* assign_input_to_block(
	simple_circuitt::gatet const *input,
	std::unordered_map<simple_circuitt::gatet const*, execution_blockt*> &gate_blocks,
	parallel_execution_grapht &graph,
	gate_to_deptht const &gate_depths,
	gate_to_outputst const &gate_closest_output,
	gate_to_callt const &input_to_call)
{
	assert(input->get_operation() == simple_circuitt::INPUT);

	auto call_it = input_to_call.find(input);
	if(call_it != input_to_call.end())
	{
		// Okay, this input is (part of) the output of a function call

		auto call = call_it->second;
		std::unordered_set<execution_blockt*> fanin_blocks;
		block_inputst block_inputs;
		for(auto const &arg: call->args)
		{
			for(auto out: arg.gates)
			{
				auto fanin_block = assign_element_to_block(
					out->get_fanin(0),
					gate_blocks, graph, gate_depths, gate_closest_output, input_to_call
				);

				fanin_blocks.insert(fanin_block);
				block_inputs[out->get_fanin(0)] = fanin_block;
			}
		}

		auto call_block = graph.add_call_block(
			gate_depths.at(input),
			call->call_id,
			call->name,
			block_inputs
		);

		for(auto fanin_block: fanin_blocks)
			call_block->add_fanin(fanin_block);

		// Since all the inputs from a specific function call belong to the same block we can assign
		// them in one go
		for(auto const &ret: call->returns)
		{
			for(auto in: ret.gates)
				gate_blocks[in] = call_block;
		}

		return call_block;
	}
	else
	{
		// This is a circuit input so add it to the start block

		auto gate_block = graph.root();
		gate_block->add_element(input, gate_blocks);

		return gate_blocks[input] = gate_block;
	}
}

execution_blockt* assign_output_to_block(
	simple_circuitt::gatet const *output,
	std::unordered_map<simple_circuitt::gatet const*, execution_blockt*> &gate_blocks,
	parallel_execution_grapht &graph,
	gate_to_deptht const &gate_depths,
	gate_to_outputst const &gate_closest_output,
	gate_to_callt const &input_to_call)
{
	assert(output->get_operation() == simple_circuitt::OUTPUT);

	// Since OUTPUTs belonging to function calls are handled in `assign_input_to_block()` we only
	// expect circuit-level OUTPUTs here

	auto fanin_block = assign_element_to_block(
		output->get_fanin(0),
		gate_blocks, graph, gate_depths, gate_closest_output, input_to_call
	);

	graph.leaf()->add_fanin(fanin_block);
	graph.leaf()->add_element(output, gate_blocks);

	return gate_blocks[output] = graph.leaf();
}

execution_blockt* assign_gate_to_block(
	simple_circuitt::gatet const *gate,
	std::unordered_map<simple_circuitt::gatet const*, execution_blockt*> &gate_blocks,
	parallel_execution_grapht &graph,
	gate_to_deptht const &gate_depths,
	gate_to_outputst const &gate_closest_output,
	gate_to_callt const &input_to_call)
{
	assert(gate->get_operation() != simple_circuitt::INPUT);
	assert(gate->get_operation() != simple_circuitt::OUTPUT);

	std::unordered_set<execution_blockt*> fanin_blocks;
	int closest_input_depth = 0;
	for(auto fanin: gate->fanin_range())
	{
		auto fanin_block = assign_element_to_block(
			fanin.gate,
			gate_blocks, graph, gate_depths, gate_closest_output, input_to_call
		);

		closest_input_depth = std::max(closest_input_depth, fanin_block->closest_input_depth());
		fanin_blocks.insert(fanin_block);
	}

	gate_blockt *gate_block = nullptr;
	// We put gates with no fanins (ONE and CONST gates) into the init block so we only have a
	// single root block
	if(gate->num_fanins() == 0)
		gate_block = graph.root();
	else
		gate_block = graph.get_gate_block(closest_input_depth, gate_closest_output.at(gate));

	for(auto fanin_block: fanin_blocks)
	{
		if(gate_block != fanin_block) // TODO Why is this necessary again?
			gate_block->add_fanin(fanin_block);
	}

	gate_block->add_element(gate, gate_blocks);

	return gate_blocks[gate] = gate_block;
}

execution_blockt* assign_element_to_block(
	simple_circuitt::gatet const *gate,
	std::unordered_map<simple_circuitt::gatet const*, execution_blockt*> &gate_blocks,
	parallel_execution_grapht &graph,
	gate_to_deptht const &gate_depths,
	gate_to_outputst const &gate_closest_output,
	gate_to_callt const &input_to_call)
{
	auto it = gate_blocks.find(gate);
	if(it != gate_blocks.end())
		return it->second;

	switch(gate->get_operation())
	{
		case simple_circuitt::INPUT:
			return assign_input_to_block(
				gate, gate_blocks, graph, gate_depths,
				gate_closest_output, input_to_call);

		case simple_circuitt::OUTPUT:
			return assign_output_to_block(
				gate, gate_blocks, graph, gate_depths,
				gate_closest_output, input_to_call);

		default:
			return assign_gate_to_block(
				gate, gate_blocks, graph, gate_depths,
				gate_closest_output, input_to_call);
	}
}

}


//==================================================================================================
parallel_execution_grapht build_parallel_execution_graph(simple_circuitt const &circuit)
{
	auto output_to_call = assign_output_calls(circuit);
	auto input_to_call = assign_input_calls(circuit);

	gate_to_deptht gate_depths = compute_gate_depths(circuit, input_to_call);

	gate_to_outputst gate_closest_outputs;
	for(auto gate: circuit.root_gates())
		assign_closest_output(gate, output_to_call, gate_depths, gate_closest_outputs);

	parallel_execution_grapht graph;
	std::unordered_map<simple_circuitt::gatet const*, execution_blockt*> gate_blocks;
	for_each_circuit_output(circuit, [&](simple_circuitt::gatet const *output)
	{
		assign_element_to_block(output, gate_blocks, graph, gate_depths, gate_closest_outputs, input_to_call);
	});

	return graph;
}


//==================================================================================================
namespace {

bool fanin_less_than(execution_blockt const *a, execution_blockt const *b)
{
	if(a->kind() != b->kind())
	{
		// Arbitrarily put gate_blockts before function_call_blockts
		return a->kind() == block_kindt::gate;
	}

	if(a->kind() == block_kindt::gate)
	{
		auto *a_block = static_cast<gate_blockt const*>(a);
		auto *b_block = static_cast<gate_blockt const*>(b);

		int a_closest_input_depth = a_block->closest_input_depth();
		int b_closest_input_depth = b_block->closest_input_depth();

		return std::tie(a_closest_input_depth, a_block->output_depths()) <
			std::tie(b_closest_input_depth, b_block->output_depths());
	}
	else
	{
		auto a_call_id = static_cast<function_call_blockt const*>(a)->call_id();
		auto b_call_id = static_cast<function_call_blockt const*>(b)->call_id();

		return a_call_id < b_call_id;
	}
}

bool equivalent(execution_blockt const *a, execution_blockt const *b)
{
	if(a->kind() != b->kind())
		return false;

	if(a->closest_input_depth() != b->closest_input_depth())
		return false;

	if(a->fanins().size() != b->fanins().size())
		return false;

	if(a->kind() == block_kindt::gate)
	{
		auto *a_block = static_cast<gate_blockt const*>(a);
		auto *b_block = static_cast<gate_blockt const*>(b);

		if(a_block->non_linear_height() != b_block->non_linear_height())
			return false;

		if(a_block->output_depths() != b_block->output_depths())
			return false;

		// We could also check whether the number of gates are the same but since we only really
		// care for the height we will leave it out for now. (This function is mainly used for
		// testing, so this ensures that slight changes in the graph-building algorithm that only
		// affect the number of gates in a block (but not its height) won't break any tests.)
	}
	else
	{
		auto a_call_id = static_cast<function_call_blockt const*>(a)->call_id();
		auto b_call_id = static_cast<function_call_blockt const*>(b)->call_id();

		if(a_call_id != b_call_id)
			return false;
	}

	std::vector<execution_blockt const*> fanins_a{a->fanins().begin(), a->fanins().end()};
	std::vector<execution_blockt const*> fanins_b{b->fanins().begin(), b->fanins().end()};

	std::sort(fanins_a.begin(), fanins_a.end(), fanin_less_than);
	std::sort(fanins_b.begin(), fanins_b.end(), fanin_less_than);

	return std::equal(fanins_a.begin(), fanins_a.end(), fanins_b.begin(), equivalent);
}

}

bool equivalent(parallel_execution_grapht const &a, parallel_execution_grapht const &b)
{
	return equivalent(a.leaf(), b.leaf());
}


// *.dot export
//==================================================================================================
namespace {

int compute_block_depth(
	execution_blockt const *block,
	std::unordered_map<execution_blockt const*, int> &block_depths)
{
	auto it = block_depths.find(block);
	if(it != block_depths.end())
		return it->second;

	int depth = -1;
	for(auto fanin: block->fanins())
		depth = std::max(depth, compute_block_depth(fanin, block_depths));

	return block_depths[block] = depth + 1;
}

template<typename T>
T& get_at(std::vector<T> &vec, size_t idx)
{
	if(vec.size() <= idx)
		vec.resize(idx + 1);

	return vec[idx];
}

std::vector<std::vector<execution_blockt const*>> group_blocks_by_depth(
	parallel_execution_grapht const &graph)
{
	std::vector<std::vector<execution_blockt const*>> grouped_blocks;
	std::unordered_map<execution_blockt const*, int> block_depths;

	get_at(grouped_blocks, compute_block_depth(graph.root(), block_depths)).push_back(graph.root());
	get_at(grouped_blocks, compute_block_depth(graph.leaf(), block_depths)).push_back(graph.leaf());

	for(auto &block: graph.gate_blocks())
		get_at(grouped_blocks, compute_block_depth(&block, block_depths)).push_back(&block);

	for(auto &block: graph.call_blocks())
		get_at(grouped_blocks, compute_block_depth(&block, block_depths)).push_back(&block);

	return grouped_blocks;
}

std::string print_gates(gate_blockt const *block)
{
	if(block->num_gates() == 0)
		return "";

	std::stringstream ss;
	int counter = 0;

	auto gate_it = begin(block->gates());
	ss << (*gate_it++)->to_string();
	while(gate_it != end(block->gates()) && counter++ < 10)
		ss << ", " << (*gate_it++)->to_string();

	if(block->num_gates() > 10)
		ss << "...";

	return ss.str();
}

std::string block_name(parallel_execution_grapht const &graph, execution_blockt const *block)
{
  if(block == graph.root())
    return "root";

  if(block == graph.leaf())
    return "leaf";

  return std::to_string(block->id());
}


int get_total_input_width(block_inputst const &block_inputs)
{
	int total_input_width = 0;
	for(auto const &pair: block_inputs)
		total_input_width += pair.first->get_width();

	return total_input_width;
}

using block_inputs_by_blockt = std::unordered_map<execution_blockt const*, std::vector<simple_circuitt::gatet const*>>;
int get_total_input_width(block_inputs_by_blockt const &block_inputs)
{
	int total_input_width = 0;
	for(auto const &pair: block_inputs)
	{
		for(auto const *gate: pair.second)
			total_input_width += gate->get_width();
	}

	return total_input_width;
}


int get_total_input_width(std::vector<simple_circuitt::gatet const*> const &gates)
{
	int total_input_width = 0;
	for(auto const *gate: gates)
		total_input_width += gate->get_width();

	return total_input_width;
}

int get_gate_id(
	simple_circuitt::gatet const *gate,
	std::unordered_map<simple_circuitt::gatet const*, int> &gate_ids)
{
	auto res = gate_ids.insert({gate, (int)gate_ids.size()});
	return res.first->second;
}

std::string get_gate_id_list(
	std::vector<simple_circuitt::gatet const*> const &gates,
	std::unordered_map<simple_circuitt::gatet const*, int> &gate_ids)
{
	std::stringstream ss;
	if(gates.size())
	{
		ss << get_gate_id(gates[0], gate_ids) << ":" << gates[0]->get_width();
		for(size_t i = 1; i < gates.size(); ++i)
			ss << "," << get_gate_id(gates[i], gate_ids) << ":" << gates[i]->get_width();
	}

	return ss.str();
}

}

void to_dot(std::ostream &os, parallel_execution_grapht const &graph)
{
	os << "digraph {\n";

	auto grouped_blocks = group_blocks_by_depth(graph);
	std::unordered_map<simple_circuitt::gatet const*, int> gate_ids;

	for(size_t depth = 0; depth < grouped_blocks.size(); ++depth)
	{
		auto const &blocks = grouped_blocks[depth];

		// Write nodes
		os << "\tsubgraph level_" << depth << " {\n\t\trank=same;\n";
		for(auto block: blocks)
		{
			if(block->kind() == block_kindt::gate)
			{
				auto *gate_block = static_cast<gate_blockt const*>(block);
				int total_input_width = get_total_input_width(gate_block->block_inputs());
				os << "\t\t\"" << block_name(graph, block) << "\" [" <<
					"label=\"[" <<
						"level=" << depth  <<
						",non_linear_height=" << gate_block->non_linear_height() <<
						",input_depth=" << gate_block->closest_input_depth() <<
						",output_depths=" << join(gate_block->output_depths(), ",") <<
						",num_gates=" << gate_block->num_gates() <<
						",total_input_width=" << total_input_width <<
						//"\n" << print_gates(static_cast<gate_blockt const*>(block)) <<
					"]\"" <<
					" shape=box" <<
					" input_depth=" << gate_block->closest_input_depth() <<
					" output_depths=\"" << join(gate_block->output_depths(), ",") << "\"" <<
					" non_linear_height=" << gate_block->non_linear_height() <<
					" num_non_linear_gates=" << gate_block->num_non_linear_gates() <<
					" total_input_width=" << total_input_width <<
				"];\n";
			}
			else
			{
				auto *call = static_cast<function_call_blockt const*>(block);
				int gate_depth = block->closest_input_depth();
				int total_input_width = get_total_input_width(call->block_inputs());
				os << "\t\t\"" << block_name(graph, block) << "\" [" <<
					"label=\"" << call->func_name() << " [" <<
						"level=" << depth <<
						",input_depth=" << gate_depth <<
						",total_input_width=" << total_input_width <<
					"]\"" <<
					" call_id=\"" << call->call_id() << "\""
					" func_name=\"" << call->func_name() << "\""
					" gate_depth=" << gate_depth <<
					" total_input_width=" << total_input_width <<
				"];\n";
			}
		}
		os << "\t}\n";

		// Write edges
		for(auto block: blocks)
		{
			block_inputs_by_blockt block_inputs_by_block;
			for(auto const &pair: block->block_inputs())
				block_inputs_by_block[pair.second].push_back(pair.first);

			for(auto dep: block->fanins())
			{
				std::vector<simple_circuitt::gatet const*> const &block_inputs = block_inputs_by_block.at(dep);
				std::string inputs = get_gate_id_list(block_inputs, gate_ids);
				int total_input_width = get_total_input_width(block_inputs);
				os << "\t\"" << block_name(graph, dep) << "\" -> \"" << block_name(graph, block) << "\" [" <<
					"label=\"bit_width=" << total_input_width << "\"" <<
					" bit_width=" << total_input_width << 
					" input_gates=\"" << inputs << "\"" <<
				"];\n";
			}
		}
	}

	os << "}\n";
}

void to_dot_simple(std::ostream &os, parallel_execution_grapht const &graph)
{
	os << "digraph {\n";

	for(auto const &call: graph.call_blocks())
	{
		int gate_depth = call.closest_input_depth();
		int total_input_width = get_total_input_width(call.block_inputs());
		os << "\t\t\"" << block_name(graph, &call) << "\" [" <<
			"label=\"" << call.func_name() << " [" <<
				",input_depth=" << gate_depth <<
				",total_input_width=" << total_input_width <<
			"]\"];\n";

		// Write edges
		for(auto dep: call.fanins())
			os << "\t\"" << block_name(graph, dep) << "\" -> \"" << block_name(graph, &call) << "\";\n";
	}

	for(auto const &gate_block: graph.gate_blocks())
	{
		int total_input_width = get_total_input_width(gate_block.block_inputs());
		os << "\t\t\"" << block_name(graph, &gate_block) << "\" [" <<
			"label=\"[" <<
				",non_linear_height=" << gate_block.non_linear_height() <<
				",input_depth=" << gate_block.closest_input_depth() <<
				",output_depths=" << join(gate_block.output_depths(), ",") <<
				",num_gates=" << gate_block.num_gates() <<
				",total_input_width=" << total_input_width <<
				//"\n" << print_gates(static_cast<gate_blockt const*>(block)) <<
			"]\"" <<
			" shape=box" <<
		"];\n";

		// Write edges
		for(auto dep: gate_block.fanins())
			os << "\t\"" << block_name(graph, dep) << "\" -> \"" << block_name(graph, &gate_block) << "\";\n";
	}
	os << "}\n";
}

// For Parallel execution graph
void to_ps(std::ostream &os, parallel_execution_grapht const &graph)
{
	auto grouped_blocks = group_blocks_by_depth(graph);
	
	int count_blocks = 0;
	for(size_t depth = 0; depth < grouped_blocks.size(); ++depth) {
		auto const &blocks = grouped_blocks[depth];
		for(auto block: blocks) {
			count_blocks++;
		}
	}
	os << count_blocks << std::endl;


	std::unordered_map<simple_circuitt::gatet const*, int> gate_ids;

	for(size_t depth = 0; depth < grouped_blocks.size(); ++depth)
	{
		auto const &blocks = grouped_blocks[depth];

		for(auto block: blocks)
		{
					
					
					
	/* Format:
	 * =======
	 * Number of modules
	 * id, level, name, "i"/"o"/" ", outputs:IOVariable, numChildren, [Child1, Child2, ], circuitProperties
	 * where Child1 = {id, IOVariable}
	 */					
			std::stringstream s_properties;
			if(block->kind() == block_kindt::gate)
			{
				auto *gate_block = static_cast<gate_blockt const*>(block);
				int total_input_width = get_total_input_width(gate_block->block_inputs());
				os << block->id() << "," << depth << "," << block_name(graph, block);
				s_properties << ",size=" << gate_block->num_gates() << ":depth=" << gate_block->non_linear_height();
			}
			else
			{
				auto *call = static_cast<function_call_blockt const*>(block);
				int gate_depth = block->closest_input_depth();
				int total_input_width = get_total_input_width(call->block_inputs());
				os << block->id() << "," << depth << ","  << block_name(graph, block);
				s_properties << ",funcname=" << call->func_name() << ":depth=" << gate_depth;
			}
			
			block_inputs_by_blockt block_inputs_by_block;
			for(auto const &pair: block->block_inputs())
				block_inputs_by_block[pair.second].push_back(pair.first);
			os << ",children=" << block->fanins().size();
			for(auto dep: block->fanins())
			{
				std::vector<simple_circuitt::gatet const*> const &block_inputs = block_inputs_by_block.at(dep);
				std::string inputs = get_gate_id_list(block_inputs, gate_ids);
				int total_input_width = get_total_input_width(block_inputs);
				os << "," << dep->id() << ":" << total_input_width;
			}
			os << s_properties.str() << std::endl; 
		}
	}
}
