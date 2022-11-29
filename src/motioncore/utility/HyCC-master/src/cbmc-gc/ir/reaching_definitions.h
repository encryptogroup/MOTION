#pragma once

#include <libcircuit/utils.h>

#include "call_path.h"

#include <unordered_map>
#include <vector>
#include <ostream>
#include <limits>


// Follows "Field-Sensitive Program Dependence Analysis" by Litvak et. al.


class boolbv_widtht;

namespace ir {

class Decl;
class LoadInstr;
class StoreInstr;
class CallInstr;
class Function;
class InstrNameMap;
class PACallAnalyzer;


struct Region
{
	constexpr Region() :
		first{0},
		last{0} {}

	constexpr Region(ptrdiff_t first, ptrdiff_t last) :
		first{first},
		last{last} {}

	ptrdiff_t first;
	ptrdiff_t last;
};

constexpr Region MaxRegion{
	std::numeric_limits<ptrdiff_t>::min(),
	std::numeric_limits<ptrdiff_t>::max()
};

inline Region operator + (Region const &r, ptrdiff_t offset)
{
	return Region{r.first + offset, r.last + offset};
}

inline bool operator < (Region const &a, Region const &b)
{
	return std::tie(a.first, a.last) < std::tie(b.first, b.last);
}

inline bool operator == (Region const &a, Region const &b)
{
	return a.first == b.first && a.last == b.last;
}

inline bool overlap(Region const &a, Region const &b)
{
	return (a.first >= b.first && a.first <= b.last) || (b.first >= a.first && b.first <= a.last);
}

inline bool contains(Region const &parent, Region const &child)
{
	return parent.first <= child.first && parent.last >= child.last;
}

inline Region intersection(Region const &a, Region const &b)
{
	Region res{std::max(a.first, b.first), std::min(a.last, b.last)};
	if(res.first > res.last)
		res.first = res.last = 0;

	return res;
}

inline bool empty(Region const &r)
{
	return r.first > r.last;
}

inline std::ostream& operator << (std::ostream &os, Region const &r)
{
	return os << '[' << r.first << ':' << r.last << ']';
}


// Represents a dependency on (some part of) a variable definition (= assignment) .
struct RDDependency
{
	// The variable that we depend on.
	Decl *variable;

	// The instruction that defines the variable.
	StoreInstr const *defined_at;
	CallPath defined_in;

	// The intersection between the region defined by `defined_at` and the region of `variable` that
	// we depend on.
	Region dep_region;
};

inline bool operator < (RDDependency const &a, RDDependency const &b)
{
	return std::tie(a.variable, a.defined_at, a.dep_region) <
		std::tie(b.variable, b.defined_at, b.dep_region);
}

inline bool operator == (RDDependency const &a, RDDependency const &b)
{
	return std::tie(a.variable, a.defined_at, a.dep_region) ==
		std::tie(a.variable, b.defined_at, b.dep_region);
}

void print(RDDependency const &def, InstrNameMap &names, std::ostream &os);


// Stores for each LoadInstr the definitions it depends on
using ReachingDefinitions = std::unordered_map<LoadInstr const*, std::vector<RDDependency>>;


struct RDDefinition
{
	// The variable that is being defined.
	Decl *variable;
	// The region of the variable that is being defined.
	Region region;
	// The instruction that is defining the variable.
	StoreInstr const *defined_at;
	CallPath defined_in;
};

inline bool operator < (RDDefinition const &a, RDDefinition const &b)
{
	return std::tie(a.variable, a.defined_at, a.region) < std::tie(b.variable, b.defined_at, b.region);
}

inline bool operator == (RDDefinition const &a, RDDefinition const &b)
{
	return std::tie(a.variable, a.defined_at, a.region) == std::tie(b.variable, b.defined_at, b.region);
}

using DeclDefMap = std::unordered_map<Decl*, std::vector<RDDefinition>>;


// By abstracting how to analyze function calls we can implement various
// degrees of context-sensitivity.
class RDCallAnalyzer
{
public:
	RDCallAnalyzer(PACallAnalyzer const *pa, boolbv_widtht const &bv) :
		m_pa{pa},
		m_boolbv_width{bv} {}

	virtual ReachingDefinitions const& result_for(CallPath const &cp) const = 0;

	// Updates the PointsToMap of the caller, `pt_caller`, such that it contains
	// the points-to information added after executing the function denoted by
	// `cp`. Additionally, the last element of `cp` is removed.
	virtual bool analyze_call(CallPath &cp, DeclDefMap &defs_caller) = 0;

	virtual void analyze_entry_point(Function const *main) = 0;

	// TODO This is totally out of place here. Move somewhere else.
	boolbv_widtht const& boolbv_width() const { return m_boolbv_width; }

	PACallAnalyzer const* pa() const { return m_pa; }

private:
	PACallAnalyzer const *m_pa;
	boolbv_widtht const &m_boolbv_width;
};

ReachingDefinitions reaching_definitions(
	CallPath &cp,
	Function const *func,
	DeclDefMap const &defs_init,
	RDCallAnalyzer *rd_ca,
	DeclDefMap *defs_exit = nullptr);


//==================================================================================================
class RDContextSensitiveCallAnalyzer : public RDCallAnalyzer
{
public:
	struct CallInfo
	{
		CallInfo(Function const *callee) :
			callee{callee} {}

		Function const *callee;
		DeclDefMap defs_input;
		DeclDefMap defs_output;
		ReachingDefinitions rd_output;
	};

	RDContextSensitiveCallAnalyzer(PACallAnalyzer const *pa, boolbv_widtht const &bv) :
		RDCallAnalyzer{pa, bv} {}

	ReachingDefinitions const& result_for(CallPath const &cp) const override
	{
		auto it = m_call_info.find(cp);
		if(it == m_call_info.end())
			throw std::runtime_error{"No reaching definitions analysis result available"};

		return it->second.rd_output;
	}

	bool analyze_call(CallPath &cp, DeclDefMap &defs_caller) override;

	void analyze_entry_point(Function const *main) override
	{
		CallPath cp;

		CallInfo ci{main};
		ci.rd_output = reaching_definitions(cp, main, {}, this, &ci.defs_output);
		m_call_info.insert({{}, ci});
	}

private:
	std::unordered_map<CallPath, CallInfo, VectorHash> m_call_info;
};


}
