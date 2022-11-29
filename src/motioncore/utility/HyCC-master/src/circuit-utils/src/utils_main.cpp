#include <circuit-utils/circuit.hpp>
#include <circuit-utils/circuit_io.hpp>

#include <iostream>
#include <set>
#include <map>
#include <fstream>
#include <unordered_set>


namespace circ {


//==================================================================================================
std::string unique_var()
{
	static int counter = 0;
	return "t" + std::to_string(counter++);
}


//------------------------------------------------------------------------------
void generate_random_assignment(std::ostream &os, Type const &type, std::string const &path)
{
	switch(type.kind())
	{
		case TypeKind::bits:
			throw std::runtime_error{"Random assignment of bits not yet supported"};
			break;

		case TypeKind::boolean:
		{
			os << path << " = random_bool(rd);\n";
		} break;

		case TypeKind::integer:
		{
			os << path << " = random_int<" << type << "_t>(rd);\n";
		} break;

		case TypeKind::array:
		{
			auto array_type = get_array_type(type);
			auto loop_var = unique_var();
			os << "for(size_t " << loop_var << " = 0; " << loop_var << " < " << array_type->length << "; ++" << loop_var << ") {\n";
			generate_random_assignment(os, *array_type->sub, path + "[" + loop_var + "]");
			os << "}\n";
		} break;

		case TypeKind::structure:
		{
			auto struct_type = get_struct_type(type);
			for(auto &m: struct_type->members)
				generate_random_assignment(os, *m.second, path + "." + m.first);
		} break;
	}
}

void generate_random_assignment_function(std::ostream &os, Party p, Type const &type)
{
	std::string type_name = p == Party::alice ? "InputA" : "InputB";
	os << type_name << " ";

	os << "generate_" << type_name << "(std::mt19937 &rd)\n{\n" << type_name << " in;\n";
	generate_random_assignment(os, type, "in");
	os << "return in;\n}\n";
}


//------------------------------------------------------------------------------
void generate_output_comparer(std::ostream &os, Type const &type, std::string const &path)
{
	switch(type.kind())
	{
		case TypeKind::bits:
			throw std::runtime_error{"Comparison of bits not yet supported"};
			break;

		case TypeKind::boolean:
		case TypeKind::integer:
		{
			os << "if((*a)" << path << " != (*b)" << path << ") return false;\n";
		} break;

		case TypeKind::array:
		{
			auto array_type = get_array_type(type);
			auto loop_var = unique_var();
			os << "for(size_t " << loop_var << " = 0; " << loop_var << " < " << array_type->length << "; ++" << loop_var << ") {\n";
			generate_output_comparer(os, *array_type->sub, path + "[" + loop_var + "]");
			os << "}\n";
		} break;

		case TypeKind::structure:
		{
			auto struct_type = get_struct_type(type);
			for(auto &m: struct_type->members)
				generate_output_comparer(os, *m.second, path + "." + m.first);
		} break;
	}
}

void generate_output_comparer_function(std::ostream &os, Type const &type)
{
	os << "bool outputs_equal(Output const *a, Output const *b)\n{\n";
	generate_output_comparer(os, type, "");
	os << "\treturn true;\n}\n";
}


//------------------------------------------------------------------------------
void generate_printer_for_type(std::ostream &os, Type const &type, std::string const &path)
{
	// TODO We need to separate the path we print and the path we use to access the value.
	switch(type.kind())
	{
		case TypeKind::bits:
			throw std::runtime_error{"Random assignment of bits not yet supported"};
			break;

		case TypeKind::boolean:
		case TypeKind::integer:
		{
			os << "std::cout << \"" << path << " = \" << " << path << " << '\\n';";
		} break;

		case TypeKind::array:
		{
			auto array_type = get_array_type(type);
			auto loop_var = unique_var();
			os << "for(size_t " << loop_var << " = 0; " << loop_var << " < " << array_type->length << "; ++" << loop_var << ") {\n";
			generate_printer_for_type(os, *array_type->sub, path + "[" + loop_var + "]");
			os << "}\n";
		} break;

		case TypeKind::structure:
		{
			auto struct_type = get_struct_type(type);
			for(auto &m: struct_type->members)
				generate_printer_for_type(os, *m.second, path + "." + m.first);
		} break;
	}
}

enum class VariableType
{
	input_a,
	input_b,
	output,
};

void generate_printer(std::ostream &os, VariableType vt, Type const &type)
{
	std::string type_name = vt == VariableType::input_a ? "InputA" : vt == VariableType::input_b ? "InputB" : "Output";
	std::string var_name = vt == VariableType::input_a ? "input_a" : vt == VariableType::input_b ? "input_b" : "output";

	os << "void print_" << type_name << "(" << type_name << " " << var_name << ")\n{\n";
	generate_printer_for_type(os, type, var_name);
	os << "\n}\n";
}


//==================================================================================================
std::unordered_set<int>* compute_call_dependencies_rec(
	ElementID element,
	Circuit const &circuit,
	std::unordered_map<ElementID, std::unordered_set<int>> &gate_deps)
{
	auto it = gate_deps.find(element);
	if(it != gate_deps.end())
		return &it->second;

	if(element.kind() == ElementID::Kind::input)
		return nullptr;

	std::unordered_set<int> deps;
	for(auto fanin: circuit.get_fanins(element))
	{
		auto fanin_deps = compute_call_dependencies_rec(fanin.id, circuit, gate_deps);
		if(fanin_deps)
			deps.insert(fanin_deps->begin(), fanin_deps->end());
	}

	auto insert_res = gate_deps.emplace(element, std::move(deps));
	return &insert_res.first->second;
}

struct CallDepGraph
{
	std::vector<int> roots;
	std::vector<std::unordered_set<int>> call_deps;
	std::vector<std::unordered_set<int>> call_fanouts;
};

CallDepGraph compute_call_dependencies(Circuit const &circuit)
{
	std::unordered_map<ElementID, std::unordered_set<int>> gate_deps;

	for(size_t i = 0; i < circuit.function_calls.size(); ++i)
	{
		auto const &call = circuit.function_calls[i];
		for(auto const &ret: call.returns)
		{
			for(auto in: ret.inputs)
				gate_deps[in].insert(i);
		}
	}

	CallDepGraph graph;
	graph.call_deps.resize(circuit.function_calls.size());
	graph.call_fanouts.resize(circuit.function_calls.size());
	for(size_t i = 0; i < circuit.function_calls.size(); ++i)
	{
		auto const &call = circuit.function_calls[i];
		auto &cur_call_deps = graph.call_deps[i];
		for(auto const &arg: call.args)
		{
			for(auto out: arg.outputs)
			{
				auto output_deps = compute_call_dependencies_rec(out, circuit, gate_deps);
				if(output_deps)
				{
					cur_call_deps.insert(output_deps->begin(), output_deps->end());
					for(auto dep: *output_deps)
						graph.call_fanouts[dep].insert(i);
				}
			}
		}

		if(cur_call_deps.empty())
			graph.roots.push_back(i);
	}

	return graph;
}

std::vector<int> assign_call_order(CallDepGraph const &graph)
{
	std::vector<int> call_id_to_order;
	call_id_to_order.resize(graph.call_deps.size());

	std::vector<int> bb = graph.roots;
	std::vector<int> fb;
	auto *pa = &bb;
	auto *pb = &fb;

	int order = 0;
	while(pa->size())
	{
		for(auto id: *pa)
		{
			call_id_to_order[id] = order;
			for(auto fanout: graph.call_fanouts[id])
				pb->push_back(fanout);
		}

		order++;
		pa->clear();
		std::swap(pa, pb);
	}

	return call_id_to_order;
}

void call_deps_to_dot(
	std::ostream &os,
	Circuit const &circuit,
	std::vector<std::vector<int>> const &call_deps)
{
	os << "digraph {\n";

	for(size_t i = 0; i < circuit.function_calls.size(); ++i)
	{
		auto const &call = circuit.function_calls[i];
		os << '\t' << i << " [label=\"" << call.name << " [" << i << "]\"];\n";
	}

	for(size_t i = 0; i < call_deps.size(); ++i)
	{
		for(int dep: call_deps[i])
			os << '\t' << dep << " -> " << i << ";\n";
	}

	os << "}\n";
}

void call_deps_to_dot(
	std::ostream &&os,
	Circuit const &circuit,
	std::vector<std::vector<int>> const &call_deps)
{
	call_deps_to_dot(os, circuit, call_deps);
}


//==================================================================================================
using CallID = int;

// Assigns to each gate the call-depth (= depth of sequential function calls) of the closest output
// it influences.
std::pair<CallID, int> const& assign_closest_output(
	ElementID element,
	Circuit const &circuit,
	std::vector<CallID> const &output_to_call,
	std::vector<int> const &call_orders,
	std::unordered_map<ElementID, std::pair<CallID, int>> &gate_closest_output)
{
	auto it = gate_closest_output.find(element);
	if(it != gate_closest_output.end())
		return it->second;

	if(element.kind() == ElementID::Kind::output)
	{
		CallID call_id = output_to_call[element.id()];

		// Circuit outputs (i.e. outputs that are not inputs to function calls) have the maximum
		// depth.
		int call_depth = call_id == -1 ? std::numeric_limits<int>::max() : call_orders.at(call_id);

		auto res = gate_closest_output.insert({element, {call_id, call_depth}});
		return res.first->second;
	}
	else
	{
		std::pair<CallID, int> best{-1, std::numeric_limits<int>::max()};
		for(auto fanout: circuit.get_fanouts(element))
		{
			auto cur = assign_closest_output(fanout.id, circuit, output_to_call, call_orders, gate_closest_output);
			if(cur.second < best.second)
				best = cur;
		}

		auto res = gate_closest_output.insert({element, best});
		return res.first->second;
	}
}

// Assigns to each input the function call it belongs to or -1 if it is an input to the circuit.
std::vector<CallID> assign_input_calls(Circuit const &circuit)
{
	std::vector<CallID> input_to_call(circuit.inputs.size(), -1);
	for(size_t i = 0; i < circuit.function_calls.size(); ++i)
	{
		auto const &call = circuit.function_calls[i];
		for(auto const &ret: call.returns)
		{
			for(auto in: ret.inputs)
				input_to_call[in.value] = i;
		}
	}

	return input_to_call;
}

// Assigns to each output the function call it belongs to or -1 if it is an output of the circuit.
std::vector<CallID> assign_output_calls(Circuit const &circuit)
{
	std::vector<CallID> output_to_call(circuit.outputs.size(), -1);
	for(size_t i = 0; i < circuit.function_calls.size(); ++i)
	{
		auto const &call = circuit.function_calls[i];
		for(auto const &arg: call.args)
		{
			for(auto out: arg.outputs)
				output_to_call[out.value] = i;
		}
	}

	return output_to_call;
}

enum class ClusterKind
{
	cluster,
	function_call,
};

// A cluster contains gates that can be executed in parallel to a function call
struct Cluster
{
	friend struct ClusterGraph;

	ClusterKind kind;
	int id;
	// Length of the shortest cluster-path to the root
	int depth;

	// if kind == cluster
	// The closest output influenced by the cluster's gates.
	std::pair<CallID, int> closest_output = {-1, 0};

	// if kind == function_call
	int function_call_id;

	std::unordered_set<Cluster*> const& fanins() const { return m_fanins; }

	void add_element(ElementID element, Circuit const &circuit, std::pair<CallID, int> closest_output)
	{
		assert(closest_output.second <= closest_output.second);

		int element_depth = 0;
		for(auto fanin: circuit.get_fanins(element))
		{
			auto it = m_elements.find(fanin.id);
			if(it != m_elements.end())
				element_depth = std::max(element_depth, it->second);
		}

		if(element.kind() == ElementID::Kind::gate)
		{
			Gate const &gate = circuit[element.as_gate_id()];
			if(is_non_linear_gate(gate.kind))
			{
				m_non_linear_gates++;
				element_depth++;
			}
		}

		m_elements.insert({element, element_depth});

		m_non_linear_height = std::max(m_non_linear_height, element_depth);
	}

	std::unordered_map<ElementID, int> const& elements() const { return m_elements; }
	int non_linear_height() const { return m_non_linear_height; }
	int non_linear_gates() const { return m_non_linear_gates; }

private:
	std::unordered_set<Cluster*> m_fanins;
	// cluster
	std::unordered_map<ElementID, int> m_elements; // Element -> cluster-local depth

	int m_non_linear_height = 0;
	int m_non_linear_gates = 0;
};

struct ClusterGraph
{
	ClusterGraph() :
		counter{0},
		max_depth{-1}
	{
		exit = std::unique_ptr<Cluster>{new Cluster};
		exit->id = counter++;
		exit->depth = std::numeric_limits<int>::max();
		exit->kind = ClusterKind::cluster;
	}

	// Get the cluster at the specified level/depth.
	Cluster* get_cluster(int depth, std::pair<CallID, int> closest_output)
	{
		auto it = clusters.find({depth, closest_output.second});
		if(it != clusters.end())
			return &it->second;

		auto cluster = &clusters[{depth, closest_output.second}];
		cluster->id = counter++;
		cluster->depth = depth;
		cluster->kind = ClusterKind::cluster;
		cluster->closest_output = closest_output;

		max_depth = std::max(max_depth, depth);

		return cluster;
	}

	Cluster* get_call(int call_id, int depth = 0)
	{
		if(call_id >= (int)calls.size())
			calls.resize(call_id + 1);

		if(calls[call_id])
		{
			calls[call_id]->depth = std::max(calls[call_id]->depth, depth);
			return calls[call_id].get();
		}

		calls[call_id] = std::unique_ptr<Cluster>{new Cluster{}};
		auto cluster = calls[call_id].get();

		cluster->id = counter++;
		cluster->depth = depth;
		cluster->kind = ClusterKind::function_call;
		cluster->function_call_id = call_id;

		max_depth = std::max(max_depth, depth);

		return cluster;
	}

	void add_fanin(Cluster *element, Cluster *fanin)
	{
		element->m_fanins.insert(fanin);
	}

	std::map<std::pair<int, int>, Cluster> clusters;
	std::vector<std::unique_ptr<Cluster>> calls;
	std::unique_ptr<Cluster> exit;
	int counter;
	int max_depth;
};



// If an input belongs to a function call it is assigned to its call-cluster, otherwise it is
// assigned to the start cluster.
Cluster* assign_input_to_cluster(
	InputID input,
	Circuit const &circuit,
	std::unordered_map<ElementID, Cluster*> &gate_clusters,
	ClusterGraph &graph,
	std::unordered_map<ElementID, std::pair<CallID, int>> const &gate_closest_output,
	std::vector<CallID> const &input_to_call_id,
	std::vector<CallID> const &output_to_call_id);

// If an output belongs to a function call it is assigned to its call-cluster, otherwise it is
// assigned to the exit cluster.
Cluster* assign_output_to_cluster(
	OutputID output,
	Circuit const &circuit,
	std::unordered_map<ElementID, Cluster*> &gate_clusters,
	ClusterGraph &graph,
	std::unordered_map<ElementID, std::pair<CallID, int>> const &gate_closest_output,
	std::vector<CallID> const &input_to_call_id,
	std::vector<CallID> const &output_to_call_id);

Cluster* assign_gate_to_cluster(
	GateID gate,
	Circuit const &circuit,
	std::unordered_map<ElementID, Cluster*> &gate_clusters,
	ClusterGraph &graph,
	std::unordered_map<ElementID, std::pair<CallID, int>> const &gate_closest_output,
	std::vector<CallID> const &input_to_call_id,
	std::vector<CallID> const &output_to_call_id);


// Assigns each element (input, output, gate) to a cluster.
// Works in topological order (reverse post order) on the circuit.
Cluster* assign_element_to_cluster(
	ElementID element,
	Circuit const &circuit,
	std::unordered_map<ElementID, Cluster*> &gate_clusters,
	ClusterGraph &graph,
	std::unordered_map<ElementID, std::pair<CallID, int>> const &gate_closest_output,
	std::vector<CallID> const &input_to_call_id,
	std::vector<CallID> const &output_to_call_id)
{
	auto it = gate_clusters.find(element);
	if(it != gate_clusters.end())
		return it->second;

	switch(element.kind())
	{
		case ElementID::Kind::input:
			return assign_input_to_cluster(
				element.as_input_id(), circuit, gate_clusters, graph, 
				gate_closest_output, input_to_call_id, output_to_call_id);

		case ElementID::Kind::output:
			return assign_output_to_cluster(
				element.as_output_id(), circuit, gate_clusters, graph, 
				gate_closest_output, input_to_call_id, output_to_call_id);

		case ElementID::Kind::gate:
			return assign_gate_to_cluster(
				element.as_gate_id(), circuit, gate_clusters, graph, 
				gate_closest_output, input_to_call_id, output_to_call_id);
	}
}


Cluster* assign_input_to_cluster(
	InputID input,
	Circuit const &circuit,
	std::unordered_map<ElementID, Cluster*> &gate_clusters,
	ClusterGraph &graph,
	std::unordered_map<ElementID, std::pair<CallID, int>> const &gate_closest_output,
	std::vector<CallID> const &input_to_call_id,
	std::vector<CallID> const &output_to_call_id)
{
	auto call_id = input_to_call_id[input.value];
	if(call_id != -1)
	{
		// Okay, this input is (part of) the output of a function call

		auto const &call = circuit.function_calls[call_id];

		// TODO We only need to do this once for each function call
		for(auto const &arg: call.args)
		{
			for(auto out: arg.outputs)
			{
				assign_element_to_cluster(
					out,
					circuit, gate_clusters, graph, gate_closest_output, input_to_call_id, output_to_call_id
				);
			}
		}

		Cluster *call_cluster = graph.get_call(call_id);
		gate_clusters[input] = call_cluster;
		call_cluster->add_element(input, circuit, gate_closest_output.at(input));

		return call_cluster;
	}
	else
	{
		// This is a circuit input so add it to the start cluster

		gate_clusters[input] = graph.get_cluster(0, {0, -1});
		gate_clusters[input]->add_element(input, circuit, gate_closest_output.at(input));

		return gate_clusters[input];
	}
}

Cluster* assign_output_to_cluster(
	OutputID output,
	Circuit const &circuit,
	std::unordered_map<ElementID, Cluster*> &gate_clusters,
	ClusterGraph &graph,
	std::unordered_map<ElementID, std::pair<CallID, int>> const &gate_closest_output,
	std::vector<CallID> const &input_to_call_id,
	std::vector<CallID> const &output_to_call_id)
{
	auto parent_cluster = assign_element_to_cluster(
		circuit.get_fanins(output)[0].id,
		circuit, gate_clusters, graph, gate_closest_output, input_to_call_id, output_to_call_id
	);

	Cluster *cluster = nullptr;
	CallID my_call_id = output_to_call_id[output.value];

	if(my_call_id != -1)
		cluster = graph.get_call(my_call_id, parent_cluster->depth + 1);
	else
		cluster = graph.exit.get();

	cluster->add_element(output, circuit, gate_closest_output.at(output));

	graph.add_fanin(cluster, parent_cluster);
	gate_clusters[output] = cluster;

	return cluster;
}

Cluster* assign_gate_to_cluster(
	GateID gate,
	Circuit const &circuit,
	std::unordered_map<ElementID, Cluster*> &gate_clusters,
	ClusterGraph &graph,
	std::unordered_map<ElementID, std::pair<CallID, int>> const &gate_closest_output,
	std::vector<CallID> const &input_to_call_id,
	std::vector<CallID> const &output_to_call_id)
{
	Cluster *gate_cluster = nullptr;
	int my_cluster_depth = 0;
	int fanins_max_closest_output_depth = -1;
	std::unordered_set<Cluster*> fanin_clusters;

	for(auto fanin: circuit.get_fanins(gate))
	{
		auto fanin_cluster = assign_element_to_cluster(
			fanin.id,
			circuit, gate_clusters, graph, gate_closest_output, input_to_call_id, output_to_call_id
		);

		my_cluster_depth = std::max(my_cluster_depth, fanin_cluster->depth);
		fanins_max_closest_output_depth = std::max(fanins_max_closest_output_depth, fanin_cluster->closest_output.second);

		fanin_clusters.insert(fanin_cluster);
	}

	auto my_closest_output = gate_closest_output.at(gate);

	gate_cluster = graph.get_cluster(my_cluster_depth, my_closest_output);
	for(auto fanin_cluster: fanin_clusters)
	{
		if(gate_cluster != fanin_cluster)
			graph.add_fanin(gate_cluster, fanin_cluster);
	}

	gate_cluster->add_element(gate, circuit, my_closest_output);
	gate_clusters[gate] = gate_cluster;

	return gate_cluster;
}



ClusterGraph create_call_dep_graph(Circuit const &circuit)
{
	ClusterGraph graph;
	std::unordered_map<ElementID, Cluster*> gate_clusters;

	auto output_to_call = assign_output_calls(circuit);
	auto input_to_call = assign_input_calls(circuit);
	auto call_orders = assign_call_order(compute_call_dependencies(circuit));

	std::unordered_map<ElementID, std::pair<CallID, int>> gate_closest_output;
	for(size_t i = 0; i < circuit.inputs.size(); ++i)
		assign_closest_output(InputID{i}, circuit, output_to_call, call_orders, gate_closest_output);
	for(auto e: circuit.zero_fanin_elements)
		assign_closest_output(e, circuit, output_to_call, call_orders, gate_closest_output);


	for(size_t i = 0; i < circuit.outputs.size(); ++i)
		assign_element_to_cluster(OutputID{i}, circuit, gate_clusters, graph, gate_closest_output, input_to_call, output_to_call);

	return graph;
}

std::string print_elements(std::unordered_map<ElementID, int> const &elements, Circuit const &circuit)
{
	const size_t max_display_elements = 6;

	std::stringstream ss;
	size_t count = std::min(max_display_elements, elements.size());
	auto it = elements.begin();
	while(count--)
	{
		if(it->first.kind() != ElementID::Kind::gate)
			continue;

		Gate const &gate = circuit[it->first.as_gate_id()];
		ss << to_string(gate.kind) << ' ';

		++it;
	}

	if(elements.size() > max_display_elements)
		ss << "...";

	return ss.str();
}

void call_dep_graph_to_dot(std::ostream &os, ClusterGraph const &graph, Circuit const &circuit)
{
	os << "digraph {\n";

	// Group clusters by depth
    std::unordered_map<int, std::vector<Cluster const*>> clusters_by_depth;
	for(auto const &cluster: values(graph.clusters))
		clusters_by_depth[cluster.depth].push_back(&cluster);
	for(auto const &cluster: graph.calls)
		clusters_by_depth[cluster->depth].push_back(cluster.get());


	for(auto pair: clusters_by_depth)
	{
		int depth = pair.first;

		// Write nodes
		os << "\tsubgraph level_" << depth << " {\n\t\trank=same;\n";
		for(auto cluster: pair.second)
		{
			if(cluster->kind == ClusterKind::cluster)
				os << "\t\t" << cluster->id << " [label=\"[height=" << cluster->non_linear_height() << ",elements=" << cluster->non_linear_gates() << ",level=" << cluster->depth << ",out_call_depth=" << cluster->closest_output.second << "] " << print_elements(cluster->elements(), circuit) << "\" shape=box];\n";
			else
			{
				auto func_name = circuit.function_calls[cluster->function_call_id].name;
				os << "\t\t" << cluster->id << " [label=\"" << func_name << " [level=" << cluster->depth << "]\"];\n";
			}
		}
		os << "\t}\n";

		// Write edges
		for(auto cluster: pair.second)
		{
			for(auto dep: cluster->fanins())
				os << "\t\t" << dep->id << " -> " << cluster->id << ";\n";
		}
	}

	// Write exit node
	os << "\t" << graph.exit->id << " [label=\"[height=" << graph.exit->non_linear_height() << ",elements=" << graph.exit->non_linear_gates() << ",level=" << (graph.max_depth+1) << "] " << print_elements(graph.exit->elements(), circuit) << "\" shape=box];\n";
	for(auto dep: graph.exit->fanins())
		os << "\t" << dep->id << " -> " << graph.exit->id << ";\n";

	os << "}\n";
}

void call_dep_graph_to_dot(std::ostream &&os, ClusterGraph const &graph, Circuit const &circuit)
{
	call_dep_graph_to_dot(os, graph, circuit);
}

}


//==================================================================================================
struct ConversionTarget
{
	std::string filename;
	circ::CircuitFileFormat format;
};

struct Options
{
	std::string circuit_path = ".";
	circ::CircuitFileFormat circuit_format = circ::CircuitFileFormat::cbmc_gc;

	bool show_info = false;

	optional<std::string> verifier_output_file;
	optional<std::string> tester_output_file;

	optional<std::string> reference_file;
	optional<std::string> input_constraints_file;

	optional<ConversionTarget> convert;

    optional<std::string> dot_file;
};

Options parse_options(int argc, char *argv[])
{
	Options opts;
	for(int i = 1; i < argc; ++i)
	{
		if(std::strcmp(argv[i], "--create-verifier") == 0)
		{
			if(++i == argc)
				throw std::runtime_error{"Expected output filename"};

			opts.verifier_output_file = argv[i];
		}
		else if(std::strcmp(argv[i], "--create-tester") == 0)
		{
			if(++i == argc)
				throw std::runtime_error{"Expected output filename"};

			opts.tester_output_file = argv[i];
		}
		else if(std::strcmp(argv[i], "--reference") == 0)
		{
			if(++i == argc)
				throw std::runtime_error{"Expected input filename"};

			opts.reference_file = argv[i];
		}
		else if(std::strcmp(argv[i], "--input-constraints") == 0)
		{
			if(++i == argc)
				throw std::runtime_error{"Expected input filename"};

			opts.input_constraints_file = argv[i];
		}
		else if(std::strcmp(argv[i], "--bristol") == 0)
			opts.circuit_format = circ::CircuitFileFormat::bristol;
		else if(std::strcmp(argv[i], "--as-bristol") == 0)
		{
			if(++i == argc)
				throw std::runtime_error{"Expected output filename"};

			opts.convert = {argv[i], circ::CircuitFileFormat::bristol};
		}
		else if(std::strcmp(argv[i], "--as-shdl") == 0)
		{
			if(++i == argc)
				throw std::runtime_error{"Expected output filename"};

			opts.convert = {argv[i], circ::CircuitFileFormat::shdl};
		}
		else if(std::strcmp(argv[i], "--as-scd") == 0)
		{
			if(++i == argc)
				throw std::runtime_error{"Expected output filename"};

			opts.convert = {argv[i], circ::CircuitFileFormat::scd};
		}
		else if(std::strcmp(argv[i], "--as-dot") == 0)
		{
			if(++i == argc)
				throw std::runtime_error{"Expected output filename"};

			opts.dot_file = argv[i];
		}
		else if(std::strcmp(argv[i], "--circuit-info") == 0)
			opts.show_info = true;
		else
		{
			if(argv[i][0] == '-')
				throw std::runtime_error{std::string{"Invalid option: "} + argv[i]};

			opts.circuit_path = argv[i];
		}
	}

	return opts;
}

void create_verifier(Options const &opts)
{
	auto circuit = circ::read_circuit(opts.circuit_path, opts.circuit_format);

	if(!opts.reference_file)
		throw std::runtime_error{"Reference implementation required"};

	std::ofstream file{*opts.verifier_output_file};
	file << "#include <inttypes.h>\n#include <string.h>\n\n";
	file << "#include \"" << *opts.reference_file << "\"\n";
	if(opts.input_constraints_file)
		file << "#include \"" << *opts.input_constraints_file << "\"\n";
	file << '\n';
	circ::to_c_code(file, circuit, "run_circuit");

	file << R"EOC(

int main()
{
	InputA alice;
	InputB bob;

)EOC";

	if(opts.input_constraints_file)
		file << "\t__CPROVER_assume(is_valid_input(alice, bob));\n";

	file << R"EOC(
	__CPROVER_assert(
		run_circuit(alice, bob) == mpc_main(alice, bob),
		"verifying circuit"
	);
}
)EOC";
}

void create_tester(Options const &opts)
{
	auto circuit = circ::read_circuit(opts.circuit_path, opts.circuit_format);

	if(!opts.reference_file)
		throw std::runtime_error{"Reference implementation required"};

	std::ofstream file{*opts.tester_output_file};
	file << "#include <inttypes.h>\n#include <string.h>\n#include <iostream>\n#include <random>\n#include <limits>\n";
	file << "\ntypedef bool _Bool;\n";
	file << "#include \"" << *opts.reference_file << "\"\n";
	if(opts.input_constraints_file)
		file << "#include \"" << *opts.input_constraints_file << "\"\n";
	circ::to_c_code(file, circuit, "run_circuit");

	file << R"EOC(
template<typename T>
T random_int(std::mt19937 &rd)
{
	std::uniform_int_distribution<T> dist{std::numeric_limits<T>::min(), std::numeric_limits<T>::max()};
	return dist(rd);
}

bool random_bool(std::mt19937 &rd)
{
	std::uniform_int_distribution<int> dist{0, 1};
	return dist(rd);
}
)EOC";

	circ::InputVarIterator alice_it, bob_it;
	std::tie(alice_it, bob_it) = circ::get_alice_and_bob(circuit);
	generate_random_assignment_function(file, circ::Party::alice, alice_it->second.type);
	generate_random_assignment_function(file, circ::Party::bob, bob_it->second.type);

	generate_printer(file, circ::VariableType::input_a, alice_it->second.type);
	generate_printer(file, circ::VariableType::input_b, bob_it->second.type);

	circ::OutputVariable out_var = circ::get_single_output(circuit);
	generate_printer(file, circ::VariableType::output, out_var.type);
	circ::generate_output_comparer_function(file, out_var.type);

	file << R"EOC(

std::pair<InputA, InputB> generate_inputs(std::mt19937 &rd)
{
	while(true)
	{
		InputA alice = generate_InputA(rd);
		InputB bob = generate_InputB(rd);
		
)EOC";

	if(opts.input_constraints_file)
		file << "		if(is_valid_input(alice, bob)) return {alice, bob};\n";
	else
		file << "		return {alice, bob};\n";

	file << "	}\n}\n\n";

	file << R"EOC(
int main()
{
	std::random_device rd;
	std::mt19937 mt{rd()};
	int num_iterations = 10000;
	int num_errors = 0;

	for(int i = 0; i < num_iterations; ++i)
	{
		std::pair<InputA, InputB> inputs = generate_inputs(mt);
		Output expected = mpc_main(inputs.first, inputs.second);
		Output actual = run_circuit(inputs.first, inputs.second);
		if(!outputs_equal(&actual, &expected))
		{
			num_errors++;
			print_InputA(inputs.first);
			print_InputB(inputs.second);
			std::cout << "Expected: "; print_Output(expected); std::cout << std::endl;
			std::cout << "Actual: "; print_Output(actual); std::cout << std::endl;
		}
	}

	std::cout << num_iterations << " runs, " << num_errors << " errors." << std::endl;

	return num_errors != 0;
}
)EOC";
}


//==================================================================================================
int main(int argc, char *argv[])
{
	auto opts = parse_options(argc, argv);

	if(opts.verifier_output_file)
		create_verifier(opts);
	if(opts.tester_output_file)
		create_tester(opts);
	if(opts.show_info)
	{
		auto circuit = circ::read_circuit(opts.circuit_path, opts.circuit_format);

		for(auto var: circuit.ordered_inputs)
			std::cout << "Input: " << var->name << " : " << var->type << std::endl;

		for(auto const &pair: circuit.name_to_outputs)
			std::cout << "Output: " << pair.first << " : " << pair.second.type << std::endl;

		for(auto const &call: circuit.function_calls)
		{
			std::cout << "\nCall to \"" << call.name << "\"\n";
			for(auto const &arg: call.args)
				std::cout << "Arg: " << arg.name << " : " << arg.type << std::endl;
			for(auto const &ret: call.returns)
				std::cout << "Ret: " << ret.name << " : " << ret.type << std::endl;
		}
	}
	if(opts.convert)
	{
		auto circuit = circ::read_circuit(opts.circuit_path, opts.circuit_format);
		switch(opts.convert->format)
		{
			case circ::CircuitFileFormat::bristol:
				circ::write_bristol_circuit(circuit, opts.convert->filename);
				break;
			case circ::CircuitFileFormat::shdl:
				circ::write_shdl_circuit(circuit, opts.convert->filename);
				break;
			case circ::CircuitFileFormat::scd:
				circ::write_scd_circuit(circuit, opts.convert->filename);
				break;
			default:
				throw std::runtime_error{"Invalid conversion target format"};
		}
	}
	if(opts.dot_file)
	{
		auto circuit = circ::read_circuit(opts.circuit_path, opts.circuit_format);
		circ::to_dot(std::ofstream{*opts.dot_file}, circuit);
		//auto graph = circ::create_call_dep_graph(circuit);
		//circ::call_dep_graph_to_dot(std::ofstream{"call_deps_" + *opts.dot_file}, graph, circuit);
	}
}

