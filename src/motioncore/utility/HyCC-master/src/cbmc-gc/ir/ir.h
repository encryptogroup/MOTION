#pragma once

#include "instr.h"
#include "basic_block.h"
#include "function.h"
#include "dominators.h"
#include "debug.h"


namespace ir {

// Why a custom IR?
//
// - exprt is still pretty close to C code, but we only need a fraction of the provided expressions
//   (higher abstraction -> less cognitive overload)
// - A lot of information is encoded in variable names (thread ID, call ID, SSA index, ...) which
//   is tedious to work with and error prone
// - Return values are passed via specially named return variables which makes it error prone to
//   manually insert/modify function calls
//
// None of this is a huge problem, but a lot of the resulting code feels too complicated for what
// it's actually doing.


//==================================================================================================
inline Instr* create_lnot(Instr *operand, BasicBlock *bb)
{
	Instr *lnot = new Instr{InstrKind::l_not, operand->type(), bb};
	lnot->add_operand(operand);
	return lnot;
}


//==================================================================================================
inline void to_dot(
	Function const &func,
	std::ostream &os)
{
	os << "digraph {\n";

	auto post_idom_tree = compute_idoms(func, PostDominatorFuncs{});

	auto blocks = compute_post_order(func);
	InstrNameMap names;
	for(auto *b: blocks)
	{
		BasicBlock const *post_idom = post_idom_tree.get_idom(b);
		os << "\t" << b->id() << " [shape=box,label=\""
		   << "ID=" << b->id()
		   << ", PostIDom=" << (post_idom ? std::to_string(post_idom->id()) : "n/a")
		   << "\\l";

		os << "\\l";

		for(auto &instr: b->instructions())
		{
			instr.print_inline(os, names);
			os << "\\l"; // left align
		}
		os << "\"];\n";

		for(auto edge: b->fanouts())
		{
			os << "\t" << b->id() << " -> " << edge.target()->id();
			if(edge.is_back_edge())
				os << " [style=dashed]";
			os << ";\n";
		}
	}

	os << "}\n";
}

}

