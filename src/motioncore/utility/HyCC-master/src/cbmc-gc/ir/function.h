#pragma once

#include <util/mp_arith.h>
#include <util/std_types.h>
#include <util/namespace.h>

#include <string>
#include <vector>
#include <memory>
#include <unordered_set>


class typet;

namespace ir {

class VarDecl;
class Scope;
class Constant;
class BasicBlock;
class InstrNameMap;


//==================================================================================================
class Function
{
public:
	Function(std::string const &name, Scope *scope, namespacet const &ns);
	~Function();

	Function(Function const &rhs) = delete;
	// BasicBlocks keep a pointer to the function they belong to, so no move allowed.
	Function(Function &&rhs) = delete;

	BasicBlock* create_block();
	Constant* get_constant(mp_integer const  &value, typet const &type);

	std::string const& name() const { return m_name; }
	code_typet const& type() const { return m_type; }

	BasicBlock* start_block() { return m_start_block; }
	BasicBlock const* start_block() const { return m_start_block; }

	BasicBlock* exit_block()
	{
		assert(m_exit_block && "Call update_blocks() before exit_block()");
		return m_exit_block;
	}

	BasicBlock const* exit_block() const 
	{
		assert(m_exit_block && "Call update_blocks() before exit_block()");
		return m_exit_block;
	}

	void print(std::ostream &os, InstrNameMap *names = nullptr);

	void add_input(VarDecl *input);
	void add_output(VarDecl *output);

	std::vector<VarDecl*> const& inputs() const { return m_inputs; }
	std::vector<VarDecl*> const& outputs() const { return m_outputs; }

	std::vector<std::unique_ptr<BasicBlock>> const& basic_blocks() const { return m_blocks; }

	Scope* scope() { return m_scope; }
	Scope const* scope() const { return m_scope; }

	namespacet const& ns() const { return m_ns; }

	void update_blocks();

private:
	std::string m_name;
	code_typet m_type;
	Scope *m_scope;

	std::vector<std::unique_ptr<BasicBlock>> m_blocks;
	BasicBlock *m_start_block;
	BasicBlock *m_exit_block;

	std::vector<VarDecl*> m_inputs;
	std::vector<VarDecl*> m_outputs;

	namespacet m_ns;

	struct ConstantHash
	{
		size_t operator () (Constant const *c) const;
	};

	struct ConstantEqual
	{
		bool operator () (Constant const *a, Constant const *b) const;
	};

	std::unordered_set<Constant*, ConstantHash, ConstantEqual> m_constants;
};

}
