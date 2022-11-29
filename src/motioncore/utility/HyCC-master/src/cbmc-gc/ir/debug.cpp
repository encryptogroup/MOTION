#include "debug.h"
#include "instr.h"
#include "dominators.h"


namespace ir {

//==================================================================================================
std::string const& InstrNameMap::get_name(Instr const *instr)
{
	auto name_it = m_instr_names.find(instr);
	if(name_it != m_instr_names.end())
		return name_it->second;

	int name_hint_count = m_name_hint_counts[instr->name_hint()]++;
	std::string name = instr->name_hint();
	if(name.empty() || name_hint_count)
		name += std::to_string(name_hint_count);

	return m_instr_names[instr] = std::move(name);
}


//==================================================================================================
bool ValidationContext::is_cur_instr_dominated_by(Instr const *dominator)
{
	// If `dominator` belongs to the current BasicBlock and has already been visited then it
	// dominates the current instruction.
	if(dominator->block() == bb)
		return instr_visited_in_bb.count(dominator);

	return dom_tree->is_dominated_by(bb, dominator->block());
}


//==================================================================================================
InstrNameMap instr_namer(Function const *func)
{
	InstrNameMap names;
	for(auto const &bb: compute_post_order_of_reverse_cfg(*func))
	{
		for(auto const &instr: bb->instructions())
			names.get_name(&instr);
	}

	return names;
}


// A basic block is valid iff
// - all its instructions are well-formed, and
// - if the basic block has a terminator instruction, then
//   - the number of outgoing edges is appropriate for the terminator instruction
// - if the basic block does not have a terminator instruction, then
//   - it does not have any outgoing edges
bool validate_block(BasicBlock const *bb, DominatorTree *dom_tree, InstrNameMap *names, std::ostream *os)
{
	bool well_formed = true;

	ValidationContext ctx{bb, dom_tree, names, os};
	for(auto &instr: bb->instructions())
	{
		well_formed &= instr.is_well_formed(ctx);
		ctx.instr_visited_in_bb.insert(&instr);
	}

	if(bb->has_terminator())
	{
		switch(bb->terminator()->kind())
		{
			case InstrKind::jump:
			{
				if(bb->fanouts().size() != 1)
				{
					well_formed = false;
					(*os) << "Error: invalid number of outgoing edges from basic block" << std::endl;
				}
			} break;

			case InstrKind::branch:
			{
				if(bb->fanouts().size() != 2)
				{
					well_formed = false;
					(*os) << "Error: invalid number of outgoing edges from basic block" << std::endl;
				}
			} break;

			default:
				well_formed = false;
				(*os) << "Error: invalid terminator instruction in basic block" << std::endl;
				break;
		}
	}
	else
	{
		if(bb->fanouts().size())
		{
			well_formed = false;
			(*os) << "Error: basic blocks without a terminator instruction must not have any outgoing edges" << std::endl;
		}
	}

	return well_formed;
}


// A function is valid iff
// - all its basic blocks are valid, and
// - only the exit block does not have a terminator instruction, and
// - the start block is not dominated by any other basic block
bool validate_function(Function const *func, InstrNameMap *names, std::ostream *os)
{
	bool well_formed = true;
	DominatorTree dom_tree = compute_idoms(*func, DominatorFuncs{});

	if(dom_tree.get_idom(func->start_block()))
	{
		well_formed = false;
		(*os) << "Error: start block is dominated by another basic block" << std::endl;
	}

	if(func->exit_block()->has_terminator())
	{
		well_formed = false;
		(*os) << "Error: the exit block must not have a terminator instruction" << std::endl;
	}

	for(auto &block: func->basic_blocks())
	{
		if(!block->has_terminator() && block.get() != func->exit_block())
		{
			well_formed = false;
			(*os) << "Error: basic block is missing a terminator instruction" << std::endl;
		}

		well_formed &= validate_block(block.get(), &dom_tree, names, os);
	}

	return well_formed;
}

}
