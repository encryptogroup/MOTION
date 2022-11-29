#pragma once

#include "instr.h"

#include <vector>


namespace ir {

// A call-path uniquely identifies a specific function call in a program. The
// elements of CallPath describe the path through the call-stack to the
// CallInstr we are interested in.
using CallPath = std::vector<CallInstr const*>;


inline FuncDecl* try_get_func_decl(CallInstr const *call)
{
	if(call->func_addr()->kind() != InstrKind::named_addr)
		return nullptr;

	Decl *decl = static_cast<NamedAddrInstr const*>(call->func_addr())->decl();
	assert(decl->kind() == DeclKind::function);
	return static_cast<FuncDecl *>(decl);
}

inline std::string str(CallPath const &cp)
{
	auto func_name_from_call = [](CallInstr const *c)
	{
		FuncDecl *f = try_get_func_decl(c);
		assert(f);
		return f->name();
	};

	return join(cp, "::", func_name_from_call);
}

}
