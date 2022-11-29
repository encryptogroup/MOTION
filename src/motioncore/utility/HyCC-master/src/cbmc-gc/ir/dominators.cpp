#include "dominators.h"


namespace ir {

//==================================================================================================
// TODO Reduce redundancy between post-order/-reverse-post-order and const/non-const versions

template<typename BB>
void post_order_visit(
	BB *b,
	std::vector<BB*> &ordering,
	std::vector<uint8_t> &marks)
{
	int label = b->id();
	if(marks[label])
		return;

	marks[label] = true;
	for(auto edge: b->fanouts())
		post_order_visit((BB*)edge.target(), ordering, marks);

	ordering.push_back(b);
}

std::vector<BasicBlock const*> compute_post_order(Function const &func)
{
	std::vector<BasicBlock const*> ordering;
	ordering.reserve(func.basic_blocks().size());
	std::vector<uint8_t> marks(func.basic_blocks().size(), 0);

	post_order_visit((BasicBlock const*)func.start_block(), ordering, marks);

	return ordering;
}

std::vector<BasicBlock*> compute_post_order(Function &func)
{
	std::vector<BasicBlock*> ordering;
	ordering.reserve(func.basic_blocks().size());
	std::vector<uint8_t> marks(func.basic_blocks().size(), 0);

	post_order_visit(func.start_block(), ordering, marks);

	return ordering;
}



template<typename BB>
void reverse_post_order_visit(
	BB *b,
	std::vector<BB*> &ordering,
	std::vector<uint8_t> &marks)
{
	int label = b->id();
	if(marks[label])
		return;

	marks[label] = true;
	for(auto edge: b->fanins())
		reverse_post_order_visit((BB*)edge.target(), ordering, marks);

	ordering.push_back(b);
}

// Why not simple reverse the result of compute_post_order() to get the reverse post order? Because
// then the start node would not always come first.
// Consider the CFG A->B, A->C, B->C, C->B, C->D, with start node A and exit node D. If we want to
// compute the reverse post order of the reverse CFG, D should be the first node in the list. But
// when computing the post order, the relative order of D and B depends on the order in which the
// algorithm traverses the graph, which means D is not guaranteed to be last, but this would be
// required if we wanted to compute the reverse post order by reversing the post order.

std::vector<BasicBlock const*> compute_post_order_of_reverse_cfg(Function const &func)
{
	std::vector<BasicBlock const*> ordering;
	ordering.reserve(func.basic_blocks().size());
	std::vector<uint8_t> marks(func.basic_blocks().size(), 0);

	reverse_post_order_visit((BasicBlock const*)func.exit_block(), ordering, marks);

	return ordering;
}

// TODO Use templates to have a single implementation of compute_reverse_post_order()
std::vector<BasicBlock*> compute_post_order_of_reverse_cfg(Function &func)
{
	std::vector<BasicBlock*> ordering;
	ordering.reserve(func.basic_blocks().size());
	std::vector<uint8_t> marks(func.basic_blocks().size(), 0);

	reverse_post_order_visit(func.exit_block(), ordering, marks);

	return ordering;
}


//==================================================================================================
BBWorkList create_work_list_rpo(Function const *func)
{
	std::vector<BasicBlock const*> rpo = compute_post_order_of_reverse_cfg(*func);
	std::vector<int> ordering_by_id(rpo.size());
	for(size_t i = 0; i < rpo.size(); ++i)
		ordering_by_id[rpo[i]->id()] = i;

	return BBWorkList{internal::BBComparer{ordering_by_id}};
}

}
