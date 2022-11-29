#pragma once

#include <unordered_set>
#include <unordered_map>
#include <string>


class typet;

namespace ir {

class Instr;
class BasicBlock;
class Function;
class DominatorTree;


//==================================================================================================
class InstrNameMap
{
public:
	std::string const& get_name(Instr const *instr);

private:
	std::unordered_map<Instr const*, std::string> m_instr_names;
	std::unordered_map<std::string, int> m_name_hint_counts;
};


//==================================================================================================
struct ValidationContext
{
	// Function-level data
	DominatorTree *dom_tree;
	InstrNameMap *names;
	std::ostream *os;

	// The basic block we are currently visiting
	BasicBlock const *bb;
	// Instructions that have so far been visited in the current BasicBlock
	std::unordered_set<Instr const*> instr_visited_in_bb;

	ValidationContext(BasicBlock const *bb, DominatorTree *dom_tree, InstrNameMap *names, std::ostream *os) :
		dom_tree{dom_tree},
		names{names},
		os{os},
		bb{bb} {}

	// Returns true if the current instruction is dominated by `dominator`
	bool is_cur_instr_dominated_by(Instr const *dominator);
};


//==================================================================================================
InstrNameMap instr_namer(Function const *func);

bool validate_block(BasicBlock const *bb, DominatorTree *dom_tree, InstrNameMap *names, std::ostream *os);
bool validate_function(Function const *func, InstrNameMap *names, std::ostream *os);

}
