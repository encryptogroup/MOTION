#include "function.h"
#include "instr.h"
#include "basic_block.h"
#include "dominators.h"
#include "debug.h"


namespace ir {

//==================================================================================================
size_t Function::ConstantHash::operator () (Constant const *c) const
{
	// TODO Find efficient way to compute hash of arbitrary mp_integer
	assert(c->value().is_ulong());

	size_t hash = irep_hash{}(c->type());
	hash_combine(hash, c->value().is_negative());
	hash_combine(hash, c->value().to_ulong());

	return hash;
}


bool Function::ConstantEqual::operator () (Constant const *a, Constant const *b) const
{
	return a->type() == b->type() && a->value() == b->value();
}


//==================================================================================================
Function::Function(std::string const &name, Scope *scope, namespacet const &ns) :
	m_name{name},
	m_scope{scope},
	m_start_block{create_block()},
	m_exit_block{nullptr},
	m_ns{ns}
{
	m_type.return_type() = empty_typet{};
}

Function::~Function() {}

BasicBlock* Function::create_block()
{
	m_blocks.emplace_back(new BasicBlock{(int)m_blocks.size(), this});
	return m_blocks.back().get();
}

Constant* Function::get_constant(mp_integer const  &value, typet const &type)
{
	// TODO Can we check if the constant already exists without creating a new instance?
	std::unique_ptr<Constant> tmp{new Constant{value, type}};
	auto res = m_constants.insert(tmp.get());
	if(res.second) // inserted?
	{
		// We assign constants to the start block so we don't have to create special cases for
		// instructions that do not belong to a basic block.
		m_start_block->push_front(tmp.release());
	}

	return *res.first;
}


void Function::add_input(VarDecl *input)
{
	m_inputs.push_back(input);
	m_type.parameters().push_back(code_typet::parametert{input->type()});
}

void Function::add_output(VarDecl *output)
{
	m_outputs.push_back(output);

	if(m_outputs.size() == 1)
		m_type.return_type() = m_outputs[0]->type();
	else if(m_outputs.size() == 2)
	{
		struct_typet return_type;
		return_type.components().push_back(struct_typet::componentt{"m0", m_outputs[0]->type()});
		return_type.components().push_back(struct_typet::componentt{"m1", m_outputs[1]->type()});
		m_type.return_type() = return_type;
	}
	else
	{
		struct_typet &return_type = to_struct_type(m_type.return_type());
		std::string component_name = "m" + std::to_string(m_outputs.size() - 1);
		return_type.components().push_back(struct_typet::componentt{component_name, m_outputs.back()->type()});
	}
}

void Function::print(std::ostream &os, InstrNameMap *pnames)
{
	os << m_name << ": (";
	
	if(m_inputs.size())
	{
		os << m_inputs[0]->name();
		for(size_t i = 1; i < m_inputs.size(); ++i)
			os << ", " << m_inputs[i]->name();
	}

	os << ") -> (";

	if(m_outputs.size())
	{
		os << m_outputs[0]->name();
		for(size_t i = 1; i < m_outputs.size(); ++i)
			os << ", " << m_outputs[i]->name();
	}

	os << ")\n";


	InstrNameMap new_names;
	if(!pnames)
		pnames = &new_names;

	for(auto const &bb: compute_post_order_of_reverse_cfg(*this))
		bb->print(os, *pnames);
}

namespace
{
	enum class TraversalMark
	{
		NONE,
		TEMP,
		PERM,
	};

	// Returns true if a cycle is detected (indicating a back-edge)
	bool compute_back_edges_visit(
		BasicBlock *bb,
		std::vector<TraversalMark> &visited)
	{
		TraversalMark mark = visited[bb->id()];
		if(mark == TraversalMark::PERM)
			return false;

		if(mark == TraversalMark::TEMP)
			return true;

		visited[bb->id()] = TraversalMark::TEMP;
		for(auto &edge: bb->fanouts())
			edge.back_edge(compute_back_edges_visit(edge.target(), visited));

		visited[bb->id()] = TraversalMark::PERM;
		return false;
	}

	void compute_back_edges(Function &func)
	{
		std::vector<TraversalMark> visited(func.basic_blocks().size(), TraversalMark::NONE);
		compute_back_edges_visit(func.start_block(), visited);
	}

}

void Function::update_blocks()
{
	// TODO Throw an error instead
	//      This is only here because CBMC sometimes inserts two gotos directly after each other
	//      where the second goto is not reachable which results in BasicBlocks without any fanins
	bool removed_blocks = false;
	for(auto it = m_blocks.begin(); it != m_blocks.end();)
	{
		BasicBlock *b = it->get();
		if(b->fanins().size() == 0 && b != m_start_block)
		{
			std::cout << "WARNING: removing excessive start block" << std::endl;
			it = m_blocks.erase(it);
			removed_blocks = true;
		}
		else
			++it;
	}

	if(removed_blocks)
	{
		for(size_t i = 0; i < m_blocks.size(); ++i)
			m_blocks[i]->set_id(i);
	}


	// Make sure there is only a single exit
	std::vector<BasicBlock*> exits;
	for(auto &b: m_blocks)
	{
		if(b->fanouts().empty())
			exits.push_back(b.get());
	}
	assert(exits.size());
	if(exits.size() == 1)
		m_exit_block = exits.front();
	else
	{
		m_exit_block = create_block();
		for(auto *exit: exits)
			exit->create_jump(m_exit_block);
	}


	compute_back_edges(*this);

	std::vector<BasicBlock*> rpo = compute_post_order_of_reverse_cfg(*this);
}

}
