#pragma once

#include <vector>
#include <unordered_map>
#include <fstream>

#include "reaching_definitions.h"
#include <libcircuit/sorted_vector.h>


// Basic approach follows "Field-Sensitive Program Dependence Analysis" by Litvak et. al.


namespace ir {

class PointsToMap;


//==================================================================================================
struct PDGNode;

enum class DependenceKind
{
	data,
	control,
};

inline char const* cstr(DependenceKind kind)
{
	switch(kind)
	{
		case DependenceKind::data: return "data";
		case DependenceKind::control: return "control";
	}
}


// An edge represents a data or control dependence between to nodes in the program dependence graph.
struct PDGEdge
{
	DependenceKind kind;
	
	// The target node of this edge. The source node is not explicitly stored here: whichever
	// PDGNode stores this edge is the source node.
	PDGNode const *target;

	// The following fields are only applicably if `kind == DependenceKind::data`. In this case,
	// this edge specifies a dependency on the byte-range `dep_region` of variable `variable` that
	// is defined by the StoreInstr in `target`.
	//
	// Let LHS denote the value computed by the instruction of `target`. Further, let LHS[rgn]
	// denote those bytes of LHS that are in the region rgn. If `preserves_dep_region`
	// is true, then only LHS[`dep_region`] depends on `variable`, i.e., all other parts of LHS that
	// are not covered by `dep_region` are independent of `variable`. Doing this increases the
	// precision of the dependence analysis, but has no influence on its soundness.
	// 
	// For example, consider the statement `LHS = RHS`, where, e.g., RHS[0:3] depends on A and
	// RHS[4:7] depends on B. After the assignment, we get that LHS[0:3] depends on A and LHS[4:7]
	// depends on B. Thus, assignments preserve dependency regions. On the other hand, if we have
	// `LHS = X * Y`, where, e.g., X[0:3] depends on A and X[4:7] depends on B, then *all* of LHS
	// may depend on both A and B. Thus, multiplication does not preserve dependency regions.
	//
	// At the moment, we assume that only store instructions preserve dependency regions.
	// Reinterpret-style casts would also qualify.
	Decl *variable;
	Region dep_region;
	bool preserves_dep_region;
};


inline bool is_data(PDGEdge const &edge)
{
	return edge.kind == DependenceKind::data;
}

inline bool is_control(PDGEdge const &edge)
{
	return edge.kind == DependenceKind::control;
}

inline bool operator < (PDGEdge const &a, PDGEdge const &b)
{
	return std::tie(a.kind, a.target, a.variable, a.dep_region, a.preserves_dep_region) <
		std::tie(b.kind, b.target, b.variable, b.dep_region, b.preserves_dep_region);
}

inline bool operator == (PDGEdge const &a, PDGEdge const &b)
{
	return a.kind == b.kind && a.target == b.target && a.variable == b.variable &&
		a.dep_region == b.dep_region && a.preserves_dep_region == b.preserves_dep_region;
}

inline PDGEdge data_edge(PDGNode const *target, Decl *variable, Region dep_region, bool preserves_dep_region)
{
	return PDGEdge{DependenceKind::data, target, variable, dep_region, preserves_dep_region};
}

inline PDGEdge control_edge(PDGNode const *target)
{
	return PDGEdge{DependenceKind::control, target, nullptr, {}, false};
}


//==================================================================================================
class Function;
class Instr;
class ProgramDependenceGraph;

template<typename T>
using UniqueSortedVector = sorted_vector<T, true>;

struct PDGInput
{
	ProgramDependenceGraph const *pdg;
	PDGNode const *node;
};

enum class PDGNodeKind
{
	// Every PDG has exactly one entry node. Conceptually, it represents the condition under which
	// the function is executed. Thus, all internal node in the PDG are control-dependent on the
	// entry node.
	entry,

	// An input node refers to a node in another PDG.
	input,

	// An internal node represents an instruction in the function that is modeled by the PDG.
	internal,

	return_val,
};

struct PDGNode
{
	PDGNode() :
		instr{nullptr} {}

	explicit PDGNode(Instr const *instr) :
		kind{PDGNodeKind::internal},
		instr{instr},
		input{} {}

	explicit PDGNode(PDGInput in) :
		kind{PDGNodeKind::input},
		instr{},
		input{in} {}

	PDGNodeKind kind;
	UniqueSortedVector<PDGEdge> fanins;
	UniqueSortedVector<PDGEdge> fanouts;

	bool is_entry() const { return kind == PDGNodeKind::entry; }
	bool is_input() const { return kind == PDGNodeKind::input; }
	bool is_internal() const { return kind == PDGNodeKind::internal; }

	// Either
	Instr const *instr;
	// or
	PDGInput input;
};

inline std::ostream& print(std::ostream &os, PDGNode const &node, InstrNameMap &names)
{
	switch(node.kind)
	{
		case PDGNodeKind::entry:
			os << "ENTRY";
			break;

		case PDGNodeKind::input:
			os << "Input: ";
			print(os, *node.input.node, names);
			break;

		case PDGNodeKind::internal:
			node.instr->print_inline(os, names);
			break;
	}

	return os;
}

inline PDGNode entry_node()
{
	PDGNode n;
	n.kind = PDGNodeKind::entry;
	return n;
}


//==================================================================================================
class ProgramDependenceGraph
{
public:
	ProgramDependenceGraph() :
		m_nodes{entry_node()} {}

	ProgramDependenceGraph(ProgramDependenceGraph const&) = delete;
	ProgramDependenceGraph(ProgramDependenceGraph &&) = default;

	PDGNode const* get_or_create_node(Instr const *instr)
	{
		if(auto *n = find_node(instr))
			return n;

		m_nodes.emplace_back(instr);
		m_instr_to_node.insert({instr, &m_nodes.back()});
		return &m_nodes.back();
	}

	PDGNode const* get_node(Instr const *instr) const
	{
		return m_instr_to_node.at(instr);
	}

	PDGNode const* get_entry_node() const
	{
		return &m_nodes.front();
	}

	PDGNode const* find_node(Instr const *instr) const
	{
		auto it = m_instr_to_node.find(instr);
		if(it == m_instr_to_node.end())
			return nullptr;

		return it->second;
	}

	PDGNode const* create_input_node(PDGInput const &in)
	{
		m_nodes.emplace_back(in);
		return &m_nodes.back();
	}

	bool add_data_dep(PDGNode const *node, PDGNode const *dep, Decl *variable, Region dep_region, bool preserves_dep_region)
	{
		// We assume that both `node` and `dep` were obtained via a call to `node()`, so the
		// const-casts should be safe.
		bool changed = const_cast<PDGNode*>(node)->fanins.insert(
			data_edge(dep, variable, dep_region, preserves_dep_region)
		).second;

		if(changed)
			const_cast<PDGNode*>(dep)->fanouts.insert(data_edge(node, variable, dep_region, preserves_dep_region));

		return changed;
	}

	bool add_control_dep(PDGNode const *node, PDGNode const *dep)
	{
		bool changed = const_cast<PDGNode*>(node)->fanins.insert(control_edge(dep)).second;

		if(changed)
			const_cast<PDGNode*>(dep)->fanouts.insert(control_edge(node));

		return changed;
	}

	bool add_deps(PDGNode const *node, UniqueSortedVector<PDGEdge> const &new_deps)
	{
		size_t old_fanin_count = node->fanins.size();
		const_cast<PDGNode*>(node)->fanins.insert(new_deps.begin(), new_deps.end());
		return old_fanin_count != node->fanins.size();
	}

	std::list<PDGNode> const& nodes() const { return m_nodes; }

private:
	std::list<PDGNode> m_nodes;
	std::unordered_map<Instr const*, PDGNode*> m_instr_to_node;
};


void print(Function const *func, ProgramDependenceGraph const &pdg, InstrNameMap &names, std::ostream &os);


// By abstracting how to analyze function calls we can implement various
// degrees of context-sensitivity.
class PDGCallAnalyzer
{
public:
	PDGCallAnalyzer(RDCallAnalyzer const *rd, boolbv_widtht const &bv) :
		m_rd{rd},
		m_boolbv_width{bv} {}

	virtual ProgramDependenceGraph const& result_for(CallPath const &cp) const = 0;
	virtual ProgramDependenceGraph& get_or_create_pdg(CallPath const &cp) = 0;

	virtual void analyze_entry_point(Function const *main) = 0;

	// TODO This is totally out of place here. Move somewhere else.
	boolbv_widtht const& boolbv_width() const { return m_boolbv_width; }

	RDCallAnalyzer const* rd() const { return m_rd; }

private:
	RDCallAnalyzer const *m_rd;
	boolbv_widtht const &m_boolbv_width;
};


//==================================================================================================
class PDGContextSensitiveCallAnalyzer : public PDGCallAnalyzer
{
public:
	struct CallInfo
	{
		CallInfo(CallPath const &cp, Function const *callee) :
			cp{cp},
			callee{callee},
			pdg{} {}

		CallPath cp;
		Function const *callee;
		ProgramDependenceGraph pdg;
	};

	PDGContextSensitiveCallAnalyzer(PACallAnalyzer *pa, RDCallAnalyzer const *rd, boolbv_widtht const &bv) :
		PDGCallAnalyzer{rd, bv},
		m_pa{pa} {}

	ProgramDependenceGraph const& result_for(CallPath const &cp) const override
	{
		auto it = m_call_info.find(cp);
		if(it == m_call_info.end())
			throw std::runtime_error{"No PDG available"};

		return it->second.pdg;
	}

	ProgramDependenceGraph& get_or_create_pdg(CallPath const &cp) override
	{
		auto it = m_call_info.find(cp);
		if(it == m_call_info.end())
		{
			Function *f = try_get_func_decl(cp.back())->function();
			if(not f)
				throw std::runtime_error{"Function pointers not supported yet"};

			it = m_call_info.emplace(cp, CallInfo{cp, f}).first;
			m_outstanding.insert({cp, &it->second});
		}

		return it->second.pdg;
	}

	void analyze_entry_point(Function const *main) override;

	void to_dot(std::ostream &os, InstrNameMap &names) const;
	void print(std::ostream &os, InstrNameMap &names) const;

private:
	std::unordered_map<CallPath, CallInfo, VectorHash> m_call_info;
	std::unordered_map<CallPath, CallInfo*, VectorHash> m_outstanding;
	PACallAnalyzer *m_pa;
};

}
