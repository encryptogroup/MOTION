#include "instruction_outliner.h"

#include "dominators.h"

using namespace ir;

void
InstructionOutliner::run(Function *main) {
    std::cout << "\n\nStarting instruction outliner" << std::endl;

    // We assume all functions are the in the same module
    symbolt main_symbol = *module_.original_symbols().lookup(main->name());
    module_name_ = as_string(main_symbol.module);

    CallPath cp;
    outline(main, cp);
}

std::string
InstructionOutliner::rename(std::string name, Function* fun, SymbolKind kind)
{
    // name looks like `mpc_main::1::x`
    // Strip the old function name and block
    std::string stripped = name.substr(name.find_last_of(':') + 1);

    if (stripped == "INPUT_A") {
        stripped = "input_a__";
    } else if (stripped == "INPUT_B") {
        stripped = "input_b__";
    }

    if (stripped.find("#return_value") != std::string::npos) {
        // return value can only be assigned, not read.
        assert(kind == SymbolKind::Variable);
        stripped = "return_value___";
    }

    if (!fun) {
        return stripped;
    }

    if (kind == SymbolKind::Parameter) {
        return fun->name() + "::" + stripped;
    } else {
        assert(kind == SymbolKind::Variable);
        return fun->name() + "::1::" + stripped;
    }
}

void
InstructionOutliner::outline(Function *fun, CallPath& cp)
{
    std::cout << "Outline: " << fun->name() << std::endl;
    std::cout << str(cp) << std::endl;

    // We can only really outline once.
    // This means we only use PDG data for the first call path to a function.
    // This also means we have to be careful with how we use PDG data..
    // Todo: In the future it might be a good idea to combine the data for
    // all possible call paths to a function.
    if (outlined_.find(fun) != outlined_.end()) {
        return;
    }
    outlined_.insert(fun);

    // auto& pdg = ca_.result_for(cp);
    // print(fun, pdg, names_, std::cout);

    std::vector<CallInstr const*> calls;
    int num_outlined = 0;

    for (auto &bb: compute_post_order_of_reverse_cfg(*fun))
    {
        std::cout << std::setw(5) << std::left << (std::to_string(bb->id()) + ':') << '\n';

        // Previous instruction was outlined
        bool continuing = false;
        // The first store is rewritten to the call, the rest is disabled.
        std::vector<ir::Instr*> stores;
        std::unique_ptr<ir::Function> current;
        std::vector<std::string> params;
        // All left-hand-sides of the store instructions.
        // These are going to be returned by the outlined function as well.
        std::set<std::string> assignments;

        for (auto &instr: bb->instructions())
        {
            if (instr.kind() == InstrKind::call) {
                calls.push_back(static_cast<CallInstr const*>(&instr));

                // Example:
                // a = b + c;
                // foobar();
                // b = b + c;
                // We have to create a new outlined function for the code after the call.
                continuing = false;
            } else if (instr.kind() == InstrKind::store) {
                if (should_outline(static_cast<const StoreInstr&>(instr))) {
                    if (!continuing) {
                        ir::Scope *func_scope = symbols_.root_scope()->create_child();
                        std::string name = fun->name() + "__" + (std::to_string(num_outlined++));

                        // The namespace is includes all global symbols
                        namespacet ns{module_.original_symbols()};
                        current = std::unique_ptr<ir::Function>(new ir::Function{name, func_scope, ns});
                    } else {
                        std::cout << "continuing to outline from previous instruction" << std::endl;
                        assert(current);
                    }

                    stores.push_back(&instr);
                    outline_instruction(instr, false, current->start_block(), assignments, params);
                    continuing = true;
                } else {
                    continuing = false;
                }
            } else if (instr.kind() == InstrKind::jump || instr.kind() == InstrKind::branch) {
                continuing = false;
            }

            // This was the last instruction
            if (&instr == &bb->instructions().back()) {
                std::cout << "instr next nullptr" << std::endl;
                continuing = false;
            }

            // Todo: should be able to outline branch operand!

            if (!continuing && !stores.empty()) {
                std::cout << "fixing up calls to outlined function " << current->name() << std::endl;

                struct_typet return_type{};
                for (auto const& return_val : assignments) {
                    std::cout << "return value: " << return_val << std::endl;

                    std::string name = rename(return_val, nullptr, SymbolKind::Variable);
                    struct_union_typet::componentt component{name,
                        fun->scope()->lookup(return_val)->type()};

                    return_type.components().push_back(component);
                }
                std::cout << "return type: " << from_type(return_type) << std::endl;

                // Declare new struct at the top of the outlined function for the return values
                std::string return_value_struct = current->name() + "::1::return_value_struct";
                Decl* struct_decl = current->scope()->declare_var_explicit(return_value_struct, return_type);
                define_symbol(struct_decl->name(), struct_decl->type(), SymbolKind::Variable);

                // Create local copies of the input parameters
                for (auto const& param_name : params) {
                    std::string name_param = rename(param_name, current.get(), SymbolKind::Parameter);
                    std::string name_var = rename(param_name, current.get(), SymbolKind::Variable);

                    Decl* decl_var = current->scope()->try_lookup(name_var);

                    // First declare the actual function parameters
                    VarDecl* decl_param = current->scope()->declare_var(name_param, decl_var->type());
                    current->add_input(decl_param);

                    // Add new symbol to the symbol table
                    define_symbol(decl_param->name(), decl_param->type(), SymbolKind::Parameter);

                    // Initialize the copies with the parameter values.

                    auto* block = current->start_block();

                    auto* named_var = new NamedAddrInstr{decl_var};
                    block->push_front(named_var);

                    auto* named_param = new NamedAddrInstr{decl_param};
                    block->push_front(named_param);

                    auto* load = new LoadInstr{named_param};
                    block->push_front(load);

                    auto* store = new StoreInstr{named_var, load};
                    block->push_front(store);
                }

                // Assign return values to the struct at the end of the outlined function
                BasicBlock* start_block = current->start_block();
                for (auto const& return_val : assignments) {
                    std::string name = rename(return_val, current.get(), SymbolKind::Variable);
                    Decl* decl = current->scope()->try_lookup(name);
                    assert(decl);

                    auto* named = new NamedAddrInstr{decl, start_block};
                    auto* load = new LoadInstr{named, start_block};

                    auto* struct_addr = new NamedAddrInstr{struct_decl, start_block};
                    auto* addr_comp_instr = new ComputeAddrInstr{pointer_type(decl->type()), struct_addr, start_block};
                    addr_comp_instr->add_operand(current->get_constant(0, signedbv_typet{32}));

                    std::string member_name = rename(return_val, nullptr, SymbolKind::Variable);
                    size_t member_index = return_type.component_number(member_name);
                    addr_comp_instr->add_operand(current->get_constant(member_index, signedbv_typet{32}));

                    new StoreInstr{addr_comp_instr, load, start_block};
                }

                // Assign struct to #return_value
                ir::VarDecl *return_decl = current->scope()->declare_var(current->name() + "#return_value", return_type);
                current->add_output(return_decl);
                define_symbol(return_decl->name(), return_decl->type(), SymbolKind::Variable);

                auto* struct_addr = new NamedAddrInstr{struct_decl, start_block};
                auto* struct_load = new LoadInstr{struct_addr, start_block};
                auto* return_addr = new NamedAddrInstr{return_decl, start_block};
                new StoreInstr{return_addr, struct_load, start_block};

                // Replace first store with call.
                Instr* first = stores[0];

                // Todo: this is an extremly ugly hack!
                first->set_kind(InstrKind::call);
                first->clear_operands();

                first->add_operand(new DeadInstr{"replaced by named_addr"});

                // Arguments list
                for (auto const& name : params) {
                    std::cout << "call param: " << name << std::endl;

                    // Must use the Decl from our current function/block.
                    Decl* decl = fun->scope()->lookup(name);

                    auto* named = new NamedAddrInstr{decl};
                    first->block()->insert_before(named, first);
                    auto* load = new LoadInstr{named};
                    first->block()->insert_before(load, first);

                    first->add_operand(load);
                }

                // Assign values from return_value_struct to the variables in the calling scope
                for (auto const& return_val : assignments) {
                    std::cout << "return value: " << return_val << std::endl;

                    auto* return_addr = new NamedAddrInstr{return_decl};
                    auto* addr_comp_instr = new ComputeAddrInstr{pointer_type(return_decl->type()), return_addr};
                    addr_comp_instr->add_operand(current->get_constant(0, signedbv_typet{32}));

                    std::string member_name = rename(return_val, nullptr, SymbolKind::Variable);
                    size_t member_index = return_type.component_number(member_name);
                    addr_comp_instr->add_operand(current->get_constant(member_index, signedbv_typet{32}));

                    auto* load = new LoadInstr{addr_comp_instr};

                    Decl* decl = fun->scope()->lookup(return_val);
                    auto* named = new NamedAddrInstr{decl};

                    auto* store = new StoreInstr{named, load};
                    first->block()->insert_before(store, static_cast<Instr*>(first->next()));
                }

                // Replace all the other stores with just a nop.
                for (unsigned i = 1; i < stores.size(); i++) {
                    stores[i]->set_kind(InstrKind::nop);
                }

                fixup_new_function(std::move(current), return_type, fun, first);

                stores.clear();
                current = nullptr;
                params.clear();
                assignments.clear();
            }
        }
    }

    for (CallInstr const* call: calls) {
        CallPath path = cp; // This copy is important!
        path.push_back(call);

        outline(try_get_func_decl(call)->function(), path);
    }

    std::cout << std::endl;
}

void
InstructionOutliner::fixup_new_function(std::unique_ptr<ir::Function>&& fun, typet return_type, ir::Function* original, Instr* first_store)
{
    fun->update_blocks();

    std::cout << "new function for block" << std::endl;
    fun->print(std::cout, &names_);
    std::cout << std::endl;

    // Todo: we shouldn't need to create this dummy!
    goto_functionst::goto_functiont goto_fun;
    goto_fun.type.return_type() = return_type;

    // All local variables used in the new function
    // need to be passed as a parameter.
    for (auto const* decl : fun->inputs()) {
        std::cout << "\t" << decl->name() << std::endl;

        code_typet::parametert param(decl->type());
        param.set_identifier(decl->name());

        goto_fun.type.parameters().push_back(param);
    }

    std::string name = fun->name();

    // Create a new IR function with the right function type (parameters etc.)
    FuncDecl* decl = symbols_.root_scope()->declare_func(name, goto_fun.type);
    module_.goto_functions().function_map[name] = std::move(goto_fun);
    decl->set_function(std::move(fun));

    // We just change a copied version of the original function name
    // this way we don't have to manually set correct flags.
    // Todo: Actually define all flags by hand?
    symbolt original_sym = *module_.original_symbols().lookup(original->name());

    symbolt symbol = original_sym;
    symbol.name = symbol.base_name = symbol.pretty_name = name;
    symbol.type = module_.goto_functions().function_map[name].type;
    module_.original_symbols().insert(std::move(symbol));

    symbolt symbol2 = original_sym;
    symbol2.name = symbol2.base_name = symbol2.pretty_name = name;
    symbol2.type = module_.goto_functions().function_map[name].type;
    module_.transformed_symbols().insert(std::move(symbol2));

    first_store->set_operand(new NamedAddrInstr{decl}, 0);
}

bool is_simple_increment(Instr* inst) {
    // a + 1, b - 5 etc.
    if (inst->kind() != InstrKind::add && inst->kind() != InstrKind::sub) {
        return false;
    }

    if (inst->op_at(1)->kind() != InstrKind::constant) {
        return false;
    }

    return inst->op_at(0)->kind() == InstrKind::load;
}

bool
InstructionOutliner::should_outline(const StoreInstr& store)
{
    std::cout << "  should_outline: ";

    if (store.op_at(0)->kind() != InstrKind::named_addr) {
        std::cout << "No - complex lhs of assignment" << std::endl;
        return false;
    }

    if (store.op_at(1)->kind() == InstrKind::load ||
        store.op_at(1)->kind() == InstrKind::constant) {
        // Avoid outlining some simple cases like, `x = 5` or `x = y`;
        std::cout << "No - too simple" << std::endl;
        return false;
    }

    // Avoid outlining loop increment/decrement instructions
    // i.e i++ in for (..; ..; i++) {}
    // otherwise loop unrolling will usually fail

    // The increment is the second to last instruction in the current block,
    // before the jump/branch.
    Instr* next = static_cast<Instr*>(const_cast<StoreInstr&>(store).next());
    if (next->kind() == InstrKind::jump ||
        next->kind() == InstrKind::branch) {

        if (is_simple_increment(store.op_at(1))) {
            std::cout << "No - probably a loop increment/decrement" << std::endl;
            return false;
        }
    }

    std::vector<Instr*> worklist;
    worklist.push_back(store.op_at(1));

    while (!worklist.empty()) {
        // Todo: we should do some kind of weighting, maybe?
        // x% amount of non-arithmetic instructions are ok.
        Instr* current = worklist.back();
        worklist.pop_back();

        InstrKind kind = current->kind();

        switch (kind) {
            case InstrKind::add:
            case InstrKind::sub:
            case InstrKind::mul: {
                worklist.push_back(current->op_at(1));
                worklist.push_back(current->op_at(0));
                break;
            }

            case InstrKind::load:
                worklist.push_back(current->op_at(0));
                break;

            case InstrKind::named_addr:
            case InstrKind::constant:
                // Nothing to do.
                break;

            default:
                std::cout << "No - Unexpected instruction " << cstr(kind) << std::endl;
                return false;
        }
    }

    std::cout << "YES" << std::endl;
    return true;
}

// We rewrite:
// a = b + x;
// to:
// a = fun_block1(b, x).x;
// return {a: b + x};

Instr*
InstructionOutliner::outline_instruction(const Instr& instr, bool store_lhs, BasicBlock* bb, std::set<std::string>& assignments, std::vector<std::string>& params)
{
    Function* fun = bb->function();

    switch (instr.kind()) {
        case InstrKind::call:
        case InstrKind::dead:
        case InstrKind::jump:
        case InstrKind::branch: {
            std::cout << "Unexpected instruction " << cstr(instr.kind()) << std::endl;
            assert(false);
        }

        case InstrKind::named_addr: {
            Decl *decl = (static_cast<const NamedAddrInstr&>(instr)).decl();
            std::string name = rename(decl->name(), fun, SymbolKind::Variable);
            Decl* decl_copy = fun->scope()->try_lookup(name);
            if (!decl_copy) {
                decl_copy = fun->scope()->declare_var_explicit(name, decl->type());

                // Add new symbol to the symbol table
                define_symbol(decl_copy->name(), decl_copy->type(), SymbolKind::Variable);

                if (assignments.find(decl->name()) == assignments.end() && !store_lhs) {
                    // Add original name to the list of parameters to pass to this function
                    // unless it was locally defined before or we are definig it right now.
                    params.push_back(decl->name());
                }
            }

            if (store_lhs) {
                // New assignment, add to set.
                assignments.insert(decl->name());
            }

            return new NamedAddrInstr{decl_copy, bb};
        }

        case InstrKind::constant: {
            auto& constant = static_cast<const Constant&>(instr);
            return fun->get_constant(constant.value(), constant.type());
        }

        case InstrKind::store: {
            Instr *copy = new Instr{instr.kind(), instr.type()};
            Instr *rhs = outline_instruction(*instr.op_at(1), false, bb, assignments, params);
            // LHS must be "evaluated" afer RHS, otherwise we would assume that
            // the potentially new variable created by the assignment already exists
            // when executing the RHS.
            // i.e int r = r + 1. // The |r| on the RHS is not the |r| on the LHS!.
            Instr *lhs = outline_instruction(*instr.op_at(0), true, bb, assignments, params);
            copy->add_operand(lhs);
            copy->add_operand(rhs);
            bb->push_back(copy);
            return copy;
        }

        default: {
            Instr *copy = new Instr{instr.kind(), instr.type()};
            for (auto const &op: instr.operands()) {
                copy->add_operand(outline_instruction(*op, store_lhs, bb, assignments, params));
            }
            bb->push_back(copy);
            return copy;
        }
    }
}

void
InstructionOutliner::define_symbol(std::string name, typet type, SymbolKind kind)
{
    symbolt symbol;
    symbol.name = name;
    symbol.type = type;
    symbol.is_lvalue = true;
    symbol.is_thread_local = true;
    symbol.is_file_local = true;
    symbol.is_parameter = kind == SymbolKind::Parameter;
    symbol.is_state_var = kind == SymbolKind::Parameter; // XXX might be wrong
    symbol.mode = "C";
    symbol.base_name = name.substr(name.find_last_of(':') + 1);
    symbol.module = module_name_;
    symbol.pretty_name = name;

    // Add new symbol to namespace/symbol table
    module_.transformed_symbols().insert(std::move(symbol));
}