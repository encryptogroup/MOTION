#pragma once

#include "function.h"
#include "program_dependence_graph.h"

#include "../goto_conversion_invocation.h"

namespace ir {

class InstructionOutliner {
public:
    InstructionOutliner(PDGCallAnalyzer& analyzer, InstrNameMap &names,
                        SymbolTable &symbols, goto_modulet &module)
    : ca_(analyzer), names_(names), symbols_(symbols), module_(module)
    {}

    void run(Function *main);

private:
    void outline(Function *main, CallPath& cp);
    void fixup_new_function(std::unique_ptr<ir::Function>&& fun, typet return_type, ir::Function* original, Instr* first_store);
    bool should_outline(const StoreInstr& instr);
    Instr* outline_instruction(const Instr& instr, bool store_lhs, BasicBlock* bb, std::set<std::string>& assignments, std::vector<std::string>& params);

    enum class SymbolKind {
        Parameter,
        Type,
        Variable
    };

    std::string rename(std::string name, Function* fun, SymbolKind kind);

    void define_symbol(std::string name, typet type, SymbolKind kind);

    PDGCallAnalyzer& ca_;
    InstrNameMap& names_;
    SymbolTable &symbols_;
    goto_modulet& module_;
    std::string module_name_;
    std::set<Function*> outlined_;
};

}