#include "program_dependence_graph.h"
#include "dominators.h"
#include "pointer_analysis.h"
#include "instr.h"


namespace ir {

namespace {

// If an element X occurs more than once in the sorted container, then all occurences of X are
// removed. This differs from unique(), which would remove all but one occurence.
// Example: [1, 2, 2, 2, 3, 4, 5, 5] -> [1, 3, 4].
template<typename Container, typename Comparer>
void keep_singletons(Container &cont, Comparer &&comp)
{
	auto cur = cont.begin();
	while(cur != cont.end())
	{
		auto last_equal = cur;
		auto lookahead = std::next(last_equal);
		while(lookahead != cont.end() && comp(*lookahead, *cur))
			++last_equal, ++lookahead;

		if(cur != last_equal)
			cur = cont.erase(cur, std::next(last_equal));
		else
			++cur;
	}
}

// Adds a control dependence on `control_node` to all post-dominators of `start` until `end` is
// reached.
void add_control_edges(
	PDGNode const *control_node,
	BasicBlock const *start,
	BasicBlock const *end,
	ProgramDependenceGraph &pdg,
	DominatorTree const &post_dom_tree)
{
	while(start != end)
	{
		for(Instr const &instr: start->instructions())
			pdg.add_control_dep(pdg.get_or_create_node(&instr), control_node);

		start = post_dom_tree.get_idom(start);
	}
}

void create_immediate_control_dependencies(
	BasicBlock *branch_block,
	ProgramDependenceGraph &pdg,
	DominatorTree const &post_dom_tree)
{
	// Make sure `branch_block` actually branches.
	assert(branch_block->fanouts().size() > 1);

	PDGNode const *branch_node = pdg.get_or_create_node(branch_block->terminator());
	// `branch_post_idom` is the immediate post-dominator of `branch_block`. Thus, no block
	// following `branch_post_idom` can be control-dependent on `branch_block`.
	BasicBlock const *branch_post_idom = post_dom_tree.get_idom(branch_block);

	for(BlockEdge const &edge: branch_block->fanouts())
		add_control_edges(branch_node, edge.target(), branch_post_idom, pdg, post_dom_tree);
}

// Let INSTR be an instruction of kind `kind` and let INSTR[i] denote its ith operand. The function
// `instr_preserves_operand_dep_region` returns true iff INSTR would preserve the dependency region
// of a data dependency of INSTR[`op_idx`].
bool instr_preserves_operand_dep_region(InstrKind kind, int op_idx)
{
	switch(kind)
	{
		// TODO Casts that just reinterpret some memory would preserve dependency regions, but this
		//      may not be true for, e.g., casting int<->float.
		//case InstrKind::cast:
			//assert(op_idx == 0);
			//return true;
		
		// Note that load instructions do not preserve the dependency region of their operand
		// because the result of a load is the value stored at the address denoted by the operand.
		// Thus, the operand only indirectly influences the result of the load.

		case InstrKind::store:
			assert(op_idx >= 0 && op_idx < 2);

			// Remember: the first operand of a store instruction denotes the destination address,
			// and the second denotes the value that we want to store at that address. Since a
			// dependency on a store refers to the value that is being stored, only that dependency
			// region is preserved.
			return op_idx == 1;

		default:
			return false;
	};
}

bool is_store_to_return_var(Instr const *instr)
{
	std::string const &return_var = instr->block()->function()->name() + "#return_value";
	if(instr->kind() == InstrKind::store)
	{
		Instr const *addr = instr->op_at(0);

		// TODO This only works if the address of the return variable is
		//      directly passed to the store instruction. This should actually
		//      be the case most of the time, but to be more robust we should
		//      use the pointer analysis to make really sure that we don't miss
		//      anything.
		if(addr->kind() == InstrKind::named_addr)
		{
			if(static_cast<NamedAddrInstr const*>(addr)->decl()->name() == return_var)
				return true;
		}
	}

	return false;
}

}


//==================================================================================================
// The reason why we take `pdg` by reference and don't return a new one is that we may create an PDG
// in advance so that other PDGs can refer to its nodes.
UniqueSortedVector<PDGEdge> create_pdg(
	ProgramDependenceGraph &pdg,
	CallPath &cp,
	Function const *func,
	ReachingDefinitions const &rd,
	PDGCallAnalyzer *pdg_ca)
{
	UniqueSortedVector<PDGEdge> return_deps;

	// Add immediate (non-transitive) data dependencies between loads and stores.
	// This is exactly what ReachingDefinitions gives us.
	for(auto const &pair: rd)
	{
		LoadInstr const *load = pair.first;
		for(RDDependency const &dep: pair.second)
		{
			// If the dependency is defined in the function we are currently analyzing then we can
			// add the data dependency directly to `pdg`.
			if(dep.defined_in == cp)
			{
				pdg.add_data_dep(
					pdg.get_or_create_node(load),
					pdg.get_or_create_node(dep.defined_at),
					dep.variable,
					dep.dep_region,
					true);
			}
			// Otherwise, we need to add an input node to `pdg` that is connected to the correct
			// node in the other function's PDG.
			else
			{
				ProgramDependenceGraph *other_pdg = &pdg_ca->get_or_create_pdg(dep.defined_in);
				PDGNode const *other_node = other_pdg->get_or_create_node(dep.defined_at);
				pdg.add_data_dep(
					pdg.get_or_create_node(load),
					pdg.create_input_node(PDGInput{other_pdg, other_node}),
					dep.variable,
					dep.dep_region,
					true);
			}
		}
	}

	// Add immediate (non-transitive) data dependencies between instructions and their operands
	for(auto const &bb: func->basic_blocks())
	{
		for(auto const &instr: bb->instructions())
		{
			PDGNode const *node = pdg.get_or_create_node(&instr);
			if(node->instr->kind() == InstrKind::call)
			{
				CallInstr const *call = static_cast<CallInstr const*>(node->instr);
				cp.push_back(call);
				ProgramDependenceGraph *other_pdg = &pdg_ca->get_or_create_pdg(cp);
				cp.pop_back();

				// TODO
			}
			else
			{
				for(size_t op_idx = 0; op_idx < instr.operands().size(); ++op_idx)
				{
					Instr const *operand = instr.op_at(op_idx);
					ptrdiff_t operand_width = pdg_ca->boolbv_width()(operand->type()) / config.ansi_c.char_width;
					pdg.add_data_dep(
						node,
						pdg.get_or_create_node(operand),
						nullptr,
						Region{0, operand_width},
						instr_preserves_operand_dep_region(node->instr->kind(), op_idx));
				}
			}

			if(is_store_to_return_var(node->instr))
				return_deps.insert(node->fanins.begin(), node->fanins.end());
		}
	}

	// Compute immediate (non-transitive) control dependencies.
	// From "The Program Dependence Graph and Its Use in Optimization" by Ferrante, Ottenstein,
	// Warren, 1987:
	//
	// > Let G be a control flow graph. Let X and Y be nodes in G. Y is _control dependent_ on X iff
    // >
	// > 1. there exists a directed path P from X to Y with any Z in P (excluding X and Y)
	// >    post-dominated by Y and
    // > 2. X is not post-dominated by Y.
	//
	// The algorithm for marking immediate (i.e., non-transitive) control dependencies is as
	// follows:
	//
	//    For each basic block B such that there is an edge (A, B) in the CFG where basic block A
	//    terminates with a branch instruction
	//    1. mark all instructions in B as control dependent on the terminator of A
	//    2. set B to the immediate post-dominator of itself
	//    3. if B is equal to the immediate post-dominator of A, terminate, otherwise go to 1.
	DominatorTree post_dom_tree = compute_idoms(*func, PostDominatorFuncs{});
	for(auto const &bb: func->basic_blocks())
	{
		// Does `bb` terminate in a branch instruction, i.e., has multiple successors?
		if(bb->fanouts().size() > 1)
			create_immediate_control_dependencies(bb.get(), pdg, post_dom_tree);
	}

	// Make all nodes dependent on the entry node
	add_control_edges(pdg.get_entry_node(), func->start_block(), nullptr, pdg, post_dom_tree);

	return return_deps;
}


//==================================================================================================
namespace {

using StoreOffsetMap = std::unordered_map<std::pair<StoreInstr const*, Decl*>, ptrdiff_t, PairHash>;

StoreInstr const* get_if_store_instr(Instr const *instr)
{
	if(instr->kind() == InstrKind::store)
		return static_cast<StoreInstr const*>(instr);

	return nullptr;
}

Region compute_transitive_dep_region(
	PDGEdge const &imm_edge,
	PDGEdge const &trans_edge,
	StoreOffsetMap const &store_offsets)
{
	Region result = trans_edge.dep_region;

	if(is_data(imm_edge) && is_data(trans_edge) && trans_edge.preserves_dep_region)
	{
		PDGNode const *parent = imm_edge.target;
		if(StoreInstr const *store = get_if_store_instr(parent->instr))
		{
			auto offset_it = store_offsets.find({store, trans_edge.variable});
			Region store_region = offset_it == store_offsets.end() ? MaxRegion : trans_edge.dep_region + offset_it->second;
			result = intersection(imm_edge.dep_region, store_region);
		}
		else
			result = intersection(imm_edge.dep_region, trans_edge.dep_region);
	}

	return result;
}

optional<PDGEdge> create_transitive_edge(
	PDGEdge const &imm_edge,
	PDGEdge const &trans_edge,
	StoreOffsetMap const &store_offsets)
{
	PDGEdge new_edge = trans_edge;
	new_edge.dep_region = compute_transitive_dep_region(imm_edge, trans_edge, store_offsets);
	new_edge.preserves_dep_region = imm_edge.preserves_dep_region && trans_edge.preserves_dep_region;

	if(empty(new_edge.dep_region))
		return emptyopt;

	return new_edge;
}

bool create_transitive_dependencies_for_node(
	CallPath &cp,
	PDGNode const *node,
	ProgramDependenceGraph &pdg,
	StoreOffsetMap const &store_offsets,
	PDGCallAnalyzer *pdg_ca)
{
	// Handle call instructions
	if(node->instr->kind() == InstrKind::call)
	{
		CallInstr const *call = static_cast<CallInstr const*>(node->instr);
		cp.push_back(call);
		// TODO return pdg_ca->analyze_call(cp, pdg);
	}

	// Now, handle all other instructions.
	UniqueSortedVector<PDGEdge> new_deps;
	for(PDGEdge const &imm_edge: node->fanins)
	{
		PDGNode const *parent = imm_edge.target;
		for(PDGEdge const &trans_edge: parent->fanins)
		{
			if(optional<PDGEdge> new_edge = create_transitive_edge(imm_edge, trans_edge, store_offsets))
				new_deps.insert(*new_edge);
		}
	}

	return pdg.add_deps(node, new_deps);
}

// 
UniqueSortedVector<std::pair<Decl*, ptrdiff_t>> get_definite_addresses(
	std::vector<PointsToMap::Entry> const &dests)
{
	UniqueSortedVector<std::pair<Decl*, ptrdiff_t>> offsets;
	for(PointsToMap::Entry const &entry: dests)
	{
		if(entry.target_locs.stride() == 0)
			offsets.insert({entry.target_obj, entry.target_locs.offset()});
	}

	keep_singletons(offsets, [](std::pair<Decl*, ptrdiff_t> a, std::pair<Decl*, ptrdiff_t> b)
	{
		return a.first == b.first;
	});

	return offsets;
}

void create_transitive_dependencies(
	CallPath &cp,
	ProgramDependenceGraph &pdg,
	PointsToMap const &pt,
	PDGCallAnalyzer *pdg_ca)
{
	StoreOffsetMap store_offsets;
	for(PDGNode const &node: pdg.nodes())
	{
		if(node.instr->kind() == InstrKind::store)
		{
			StoreInstr const *store = static_cast<StoreInstr const*>(node.instr);
			std::vector<PointsToMap::Entry> dests = pt.get_addresses(store->op_at(0));
			for(std::pair<Decl*, ptrdiff_t> offset: get_definite_addresses(dests))
				store_offsets[{store, offset.first}] = offset.second;
		}
	}


	// TODO We can improve the efficiency of the algorithm if we sort the nodes based on the program
	//      order of their instruction.
	UniqueSortedVector<PDGNode const*> work_list;
	for(PDGNode const &node: pdg.nodes())
		work_list.insert(&node);

	while(work_list.size())
	{
		PDGNode const *node = work_list.back();
		work_list.pop_back();

		if(create_transitive_dependencies_for_node(cp, node, pdg, store_offsets, pdg_ca))
		{
			for(PDGEdge const &edge: node->fanouts)
				work_list.insert(edge.target);
		}
	}
}

}


//==================================================================================================
void PDGContextSensitiveCallAnalyzer::analyze_entry_point(Function const *main)
{
	CallPath cp;

	CallInfo ci{cp, main};
	create_pdg(ci.pdg, cp, main, rd()->result_for(cp), this);
	m_call_info.emplace(cp, std::move(ci));

	while(m_outstanding.size())
	{
		auto it = m_outstanding.begin();
		CallInfo *ci = it->second;
		m_outstanding.erase(it);

		create_pdg(ci->pdg, ci->cp, ci->callee, rd()->result_for(ci->cp), this);
	}
}


//==================================================================================================
void print(Function const *func, ProgramDependenceGraph const &pdg, InstrNameMap &names, std::ostream &os)
{
	for(auto const &bb: compute_post_order_of_reverse_cfg(*func))
	{
		os << std::setw(5) << std::left << (std::to_string(bb->id()) + ':') << '\n';
		for(auto &instr: bb->instructions())
		{
			PDGNode const *node = pdg.get_node(&instr);
			for(PDGEdge const &edge: node->fanins)
			{
				os << "    // " << cstr(edge.kind) << " dep: ";
				if(edge.kind == DependenceKind::data)
				{
					auto var_name = edge.variable ? edge.variable->name() : "<reg>";
					os << var_name << "[" << edge.dep_region.first << ":" << edge.dep_region.last << "]";
					os << " defined by '"; print(os, *edge.target, names);
					os << "', p: " << edge.preserves_dep_region << "\n";
				}
				else // edge.kind == DependenceKind::control
				{
					os << "'"; print(os, *edge.target, names);
					os << "', p: " << edge.preserves_dep_region << "\n";
				}
			}

			os << "    "; instr.print_inline(os, names); os << "\n\n";
		}
	}
}


//==================================================================================================
namespace {

void to_dot_nodes(std::ostream &os, ProgramDependenceGraph const &pdg, CallPath const &cp, InstrNameMap &names)
{
	std::stringstream ss;
	for(CallInstr const *c: cp)
		ss << c;

	os << "\tsubgraph \"cluster_" + ss.str() + "\" {\n";
	os << "\t\tlabel=\"" << str(cp) + "\";\n";

	for(PDGNode const &node: pdg.nodes())
	{
		if(node.is_internal() || node.is_entry())
		{
			os << "\t\t\"" << &node << "\" [label=\"";
			print(os, node, names);
			os << "\"];\n";
		}
	}

	os << "\t}\n";
}

void to_dot_edges(std::ostream &os, ProgramDependenceGraph const &pdg)
{
	for(PDGNode const &node: pdg.nodes())
	{
		for(PDGEdge const &edge: node.fanins)
		{
			PDGNode const *target = edge.target->is_input() ? edge.target->input.node : edge.target;
			os << "\t\"" << target << "\" -> \"" << &node << "\" [";
			if(is_control(edge))
				os << "style=dashed ";
			else if(edge.target->is_input())
				os << "color=gray penwidth=3";

			os << "]\n";
		}
	}
}

}

void PDGContextSensitiveCallAnalyzer::to_dot(std::ostream &os, InstrNameMap &names) const
{
	os << "digraph {\n";

	// We first write all nodes and then all edges. This is because apparetnly
	// the first occurence of a node name (either in a node specification or in
	// an edge specification) determines the cluster it belongs to. Thus, if a
	// node is used in an edge before the node was specified, then the node
	// would be rendered in the cluster that the edge was specified in.

	for(auto const &pair: m_call_info)
	{
		CallInfo const &ci = pair.second;
		to_dot_nodes(os, ci.pdg, ci.cp, names);
	}

	for(auto const &pair: m_call_info)
	{
		CallInfo const &ci = pair.second;
		to_dot_edges(os, ci.pdg);
	}

	os << "}\n";
}

void PDGContextSensitiveCallAnalyzer::print(std::ostream &os, InstrNameMap &names) const
{
	for(auto const &pair: m_call_info)
	{
		CallInfo const &ci = pair.second;
		os << "==== PDG for '" << ci.callee->name() << "'\n";
		::ir::print(ci.callee, ci.pdg, names, os);
	}
}

}
