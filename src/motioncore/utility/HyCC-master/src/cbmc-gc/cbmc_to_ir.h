#pragma once

#include <goto-programs/goto_functions.h>



namespace ir {
	class SymbolTable;
	class Function;
}

std::unique_ptr<ir::Function> convert_to_ir(
	ir::SymbolTable &sym_table,
	namespacet const &ns,
	goto_functionst::goto_functiont const &func);

