#include "symbol_table.h"
#include "instr.h"
#include "function.h"


namespace ir {

//==================================================================================================
namespace {

// We cannot directly compare to function types for equality because CBMC adds some meta data that
// may be different but which we don't care about (I think)
bool code_type_eq(code_typet const &a, code_typet const &b)
{
	if(a.return_type() != b.return_type())
		return false;

	if(a.parameters().size() != b.parameters().size())
		return false;

	for(size_t i = 0; i < a.parameters().size(); ++i)
	{
		if(a.parameters()[i].type() != b.parameters()[i].type())
			return false;
	}

	return true;
}

}

void FuncDecl::set_function(std::unique_ptr<Function> &&func)
{
	assert(func);
	// Todo: fix this!!!!
	// assert(code_type_eq(func->type(), to_code_type(type())));
	assert(func->name() == name());

	m_function = std::move(func);
}

}
