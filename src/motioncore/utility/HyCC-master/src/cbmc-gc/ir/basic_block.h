#pragma once

#include "instr.h"

#include <iomanip>


namespace ir {

//==================================================================================================
class BlockEdge
{
public:
	struct Shared
	{
		int index;
		bool is_back_edge;
		class BasicBlock *from;
		class BasicBlock *to;
	};

	BlockEdge(Shared *shared, class BasicBlock *target) :
		m_shared{shared},
		m_target{target}
	{
		assert(target == shared->from || target == shared->to);
	}

	void back_edge(bool is_back_edge) { m_shared->is_back_edge = is_back_edge; }

	Shared* shared() const { return m_shared; }
	int index() const { return m_shared->index; }
	bool is_back_edge() const { return m_shared->is_back_edge; }
	class BasicBlock* from() const { return m_shared->from; }
	class BasicBlock* to() const { return m_shared->to; }
	class BasicBlock* target() const { return m_target; }

private:
	Shared *m_shared;
	class BasicBlock *m_target;
};

class Function;

class BasicBlock
{
public:
	explicit BasicBlock(int id, Function *func) :
		m_id{id},
		m_func{func} {}

	~BasicBlock()
	{
		remove_fanouts();
		remove_fanins();

		auto it = m_instrs.begin();
		while(it != m_instrs.end())
		{
			auto next = std::next(it);
			delete &*it;
			it = next;
		}
	}

	int id() const { return m_id; }
	void set_id(int id) { m_id = id; }

	void print(std::ostream &os, InstrNameMap &names) const
	{
		os << std::setw(5) << std::left << (std::to_string(id()) + ':') << '\n';
		for(auto &instr: m_instrs)
		{
			os << "    ";
			instr.print_inline(os, names);
			os << '\n';
		}
	}

	bool has_terminator() const
	{
		return m_instrs.size() && is_jump(std::prev(m_instrs.end())->kind());
	}

	Instr const* terminator() const
	{
		assert(has_terminator());
		return &*std::prev(m_instrs.end());
	}

	IteratorRange<Instr::Iterator> instructions() { return {m_instrs.begin(), m_instrs.end()}; }
	IteratorRange<Instr::ConstIterator> instructions() const { return {m_instrs.begin(), m_instrs.end()}; }

	template<typename InstrT>
	InstrT* push_back(InstrT *instr)
	{
		assert(!has_terminator() && "Cannot insert instruction after terminator");

		m_instrs.insert(m_instrs.end(), instr);
		instr->set_block(this);
		return instr;
	}

	template<typename InstrT>
	InstrT* push_front(InstrT *instr)
	{
		m_instrs.insert(m_instrs.begin(), instr);
		instr->set_block(this);
		return instr;
	}

	template<typename InstrT>
	InstrT* insert_before(InstrT *instr, Instr* before)
	{
		m_instrs.insert(before, instr);
		instr->set_block(this);
		return instr;
	}

	JumpInstr* create_jump(BasicBlock *target)
	{
		assert(!has_terminator() && "BasicBlock already has a terminator");
		assert(m_outgoing.empty() && "BasicBlock already has outgoing edges");

		add_fanout(target);
		return push_back(new JumpInstr{});
	}

	BranchInstr* create_branch(Instr *condition, BasicBlock *true_target, BasicBlock *false_target)
	{
		assert(!has_terminator() && "BasicBlock already has a terminator");
		assert(m_outgoing.empty() && "BasicBlock already has outgoing edges");

		add_fanout(true_target);
		add_fanout(false_target);
		return push_back(new BranchInstr{condition});
	}

	void add_fanout(BasicBlock *target)
	{
		int index = m_outgoing.size();

		// Whether the edges are backedges is computed in a separate step
		BlockEdge::Shared *shared = new BlockEdge::Shared{index, false, this, target};

		m_outgoing.push_back(BlockEdge{shared, target});
		target->m_incoming.push_back(BlockEdge{shared, this});
	}

	void remove_fanouts()
	{
		for(auto edge: m_outgoing)
		{
			edge.to()->remove_fanin(this);
			delete edge.shared();
		}

		m_outgoing.clear();
	}

	void remove_fanins()
	{
		for(auto edge: m_incoming)
		{
			edge.from()->remove_fanout(this);
			delete edge.shared();
		}

		m_incoming.clear();
	}

	void remove_fanin(BasicBlock *fanin)
	{
		for(auto it = m_incoming.begin(); it != m_incoming.end(); ++it)
		{
			if(it->target() == fanin)
			{
				m_incoming.erase(it);
				break;
			}
		}
	}

	void remove_fanout(BasicBlock *fanout)
	{
		for(auto it = m_outgoing.begin(); it != m_outgoing.end(); ++it)
		{
			if(it->target() == fanout)
			{
				m_outgoing.erase(it);
				break;
			}
		}
	}

	using EdgeRange = IteratorRange<std::vector<BlockEdge>::iterator>;
	using EdgeConstRange = IteratorRange<std::vector<BlockEdge>::const_iterator>;

	EdgeRange fanins() { return {m_incoming.begin(), m_incoming.end()}; }
	EdgeConstRange fanins() const { return {m_incoming.begin(), m_incoming.end()}; }

	EdgeRange fanouts() { return {m_outgoing.begin(), m_outgoing.end()}; }
	EdgeConstRange fanouts() const { return {m_outgoing.begin(), m_outgoing.end()}; }

	Function* function() { return m_func; }
	Function const* function() const { return m_func; }

private:
	int m_id;
	IntrusiveList<Instr> m_instrs;
	Function *m_func;

	std::vector<BlockEdge> m_incoming;
	std::vector<BlockEdge> m_outgoing;
};

}
