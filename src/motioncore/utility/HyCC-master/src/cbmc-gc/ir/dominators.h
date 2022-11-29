#pragma once

#include "basic_block.h"
#include "function.h"

#include <set>


namespace ir {

//==================================================================================================
std::vector<BasicBlock const*> compute_post_order(Function const &func);
std::vector<BasicBlock*> compute_post_order(Function &func);

std::vector<BasicBlock const*> compute_post_order_of_reverse_cfg(Function const &func);
std::vector<BasicBlock*> compute_post_order_of_reverse_cfg(Function &func);


//==================================================================================================
namespace internal {

struct BBComparer
{
	BBComparer(std::vector<int> const &ordering_by_id) :
		ordering_by_id{ordering_by_id} {}

	bool operator () (BasicBlock const *a, BasicBlock const *b) const
	{
		return ordering_by_id[a->id()] < ordering_by_id[b->id()];
	}

	std::vector<int> ordering_by_id;
};

}

using BBWorkList = std::set<BasicBlock const*, internal::BBComparer>;

BBWorkList create_work_list_rpo(Function const *func);


//==================================================================================================
struct PostDominatorFuncs
{
	BasicBlock const* entry(Function const &func) const { return func.exit_block(); }

	BasicBlock::EdgeConstRange predecessors(BasicBlock const *bb) const { return bb->fanouts(); }

	std::vector<BasicBlock const*> post_order(Function const &func) const
	{
		return compute_post_order_of_reverse_cfg(func);
	}
};

struct DominatorFuncs
{
	BasicBlock const* entry(Function const &func) const { return func.start_block(); }

	BasicBlock::EdgeConstRange predecessors(BasicBlock const *bb) const { return bb->fanins(); }

	std::vector<BasicBlock const*> post_order(Function const &func) const
	{
		return compute_post_order(func);
	}
};


namespace internal {

inline int common_predecessor(int b1, int b2, std::vector<int> const &po_to_idom)
{
	while(b1 != b2)
	{
		while(b1 < b2)
			b1 = po_to_idom[b1];

		while(b2 < b1)
			b2 = po_to_idom[b2];
	}

	return b1;
}

}


using IDomMap = std::unordered_map<BasicBlock const*, BasicBlock const*>;

class DominatorTree
{
public:
	explicit DominatorTree(IDomMap &&idoms) :
		m_idoms{std::move(idoms)} {}

	// Returns nullptr if `b` is the root node
	BasicBlock const* get_idom(BasicBlock const *b) const
	{
		auto it = m_idoms.find(b);
		if(it == m_idoms.end())
			throw std::runtime_error{"BasicBlock has no idom"};

		// `m_idoms` maps the root node to itself
		if(it->second == b)
			return nullptr;

		return it->second;
	}

	bool is_dominated_by(BasicBlock const *b, BasicBlock const *dominator) const
	{
		assert(b && dominator);

		while(b != dominator)
		{
			if(not (b = get_idom(b)))
				return false;
		}

		return true;
	}

private:
	IDomMap m_idoms;
};

// See https://www.cs.rice.edu/~keith/EMBED/dom.pdf
// Requires single entry/exit (depending on whether DominatorFuncs or PostDominatorFuncs is used)
// Also see https://github.com/cretonne/cretonne/blob/master/lib/codegen/src/dominator_tree.rs
// 
// TODO The DominatorTree should not deal directly with BasicBlocks but have its own node type. Then
//      we can also drop the requirement that a function needs a single exit block, because we can
//      simply add an exit node to the DominatorTree. This is how LLVM does it.
template<typename Funcs>
DominatorTree compute_idoms(Function const &func, Funcs const &funcs)
{
	std::vector<BasicBlock const*> blocks_by_post_order = funcs.post_order(func);

	std::vector<int> label_to_order(func.basic_blocks().size());
	for(size_t i = 0; i < blocks_by_post_order.size(); ++i)
		label_to_order[blocks_by_post_order[i]->id()] = i;

	struct BlockOrder
	{
		BlockOrder(std::vector<int> const &label_to_order) :
			label_to_order{label_to_order} {}

		int operator () (BasicBlock const *b) const
		{
			return label_to_order[b->id()];
		}

		std::vector<int> const &label_to_order;
	} block_order{label_to_order};

	// Initialize all IDoms to undefined
	std::vector<int> po_to_idom(func.basic_blocks().size(), -1);

	BasicBlock const *start_block = funcs.entry(func);
	po_to_idom[block_order(start_block)] = block_order(start_block);

	bool changed = true;
	while(changed)
	{
		changed = false;

		// Traverse in reverse post order to make sure that for every block we visit, at least one
		// predecessor has already been processed.
		for(int bi = blocks_by_post_order.size() - 1; bi >= 0; --bi)
		{
			// Ignore start block
			if(block_order(start_block) == bi)
				continue;

			BasicBlock const *block = blocks_by_post_order[bi];
			BasicBlock::EdgeConstRange pred_edges = funcs.predecessors(block);

			int new_idom = -1;
			for(BlockEdge const &edge: pred_edges)
			{
				BasicBlock *pred = edge.target();

				int pred_po = block_order(pred);
				// Has this predecessor already been visited?
				if(po_to_idom[pred_po] != -1)
				{
					if(new_idom == -1)
						new_idom = pred_po;
					else
						new_idom = internal::common_predecessor(pred_po, new_idom, po_to_idom);
				}
			}

			// Since we visit blocks in reverse post-order there is always at least one predecessor
			// that has already been procesed.
			assert(new_idom != -1 && "At least one predecesor must have been visited already");

			if(po_to_idom[block_order(block)] != new_idom)
			{
				po_to_idom[block_order(block)] = new_idom;
				changed = true;
			}
		}
	}

	IDomMap idoms;
	for(size_t po = 0; po < po_to_idom.size(); ++po)
		idoms.insert({blocks_by_post_order[po], blocks_by_post_order[po_to_idom[po]]});

	return DominatorTree{std::move(idoms)};
}

}
