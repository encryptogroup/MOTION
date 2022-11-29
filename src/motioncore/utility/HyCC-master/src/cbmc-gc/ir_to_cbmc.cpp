#include "ir_to_cbmc.h"

#include <memory>
#include <unordered_map>
#include <iterator>

#include "ir/ir.h"
#include "ir/instr.h"
#include "ir/dominators.h"

#include <goto-programs/goto_program.h>
#include <util/std_expr.h>
#include <util/arith_tools.h>

using namespace ir;

//#define LOG

class Conversion {
public:
    Conversion(ir::Function* fun, const namespacet& ns)
        : fun_(fun), ns_(ns), current_bb_(nullptr) {};

    bool convert(goto_programt& program);

private:
    goto_programt::instructiont&
    add_instruction(goto_program_instruction_typet type);

    bool store(const StoreInstr& instr);
    bool call(const CallInstr& instr, bool from_store);

    bool dead(const DeadInstr& instr);

    bool branch(const BranchInstr& instr, ir::BasicBlock* next_bb);
    bool jump(const JumpInstr& instr, ir::BasicBlock* next_bb);

    bool expression(const Instr& instr, exprt* expr);
    bool simple_expression(const Instr& instr, const irep_idt& _id, exprt* expr);
    bool compute_addr(const ComputeAddrInstr& instr, exprt* expr);

    std::vector<goto_programt::instructiont> instructions_;
    ir::Function* fun_;
    const namespacet& ns_;
    ir::BasicBlock* current_bb_;

    // instruction index -> BasicBlock (jump target)
    std::unordered_map<int, ir::BasicBlock*> jumps_;
    // BasicBlock -> instruction index (start of block)
    std::unordered_map<ir::BasicBlock*, int> labels_;
};

bool
Conversion::convert(goto_programt& program)
{
    for (auto const &entry : fun_->scope()->symbols()) {
        Decl* decl = entry.second.get();

        if (decl->kind() != DeclKind::variable ||
            !static_cast<VarDecl*>(decl)->is_explicit()) {
            continue;
        }

        // We need to generate explicit declarations.
        auto& t = add_instruction(DECL);
        t.code = code_declt(symbol_exprt(entry.first, decl->type()));
    }

    auto blocks = compute_post_order_of_reverse_cfg(*fun_);
    for (unsigned i = 0; i < blocks.size(); ++i) {
        auto* bb = blocks[i];
        current_bb_ = bb;

        if (bb->fanins().size() > 0) {
#ifdef LOG
            std::cout << "Found incoming edges" << std::endl;
#endif

            // TODO don't emit when single jump from previous block.

            add_instruction(SKIP);
            labels_[bb] = instructions_.size() - 1;
        }

        for (Instr const &instr: bb->instructions()) {
            if (instr.kind() == InstrKind::store) {
                if (!store(static_cast<const StoreInstr&>(instr)))
                    return false;
            } else if (instr.kind() == InstrKind::call) {
                if (!call(static_cast<const CallInstr&>(instr), false))
                    return false;
            } else if (instr.kind() == InstrKind::dead) {
                if (!dead(static_cast<const DeadInstr&>(instr)))
                    return false;
            } else if (instr.kind() == InstrKind::branch) {
                auto* next_bb = blocks[i + 1];
                if (!branch(static_cast<const BranchInstr&>(instr), next_bb))
                    return false;
            } else if (instr.kind() == InstrKind::jump) {
                auto* next_bb = blocks[i + 1];
                if (!jump(static_cast<const JumpInstr&>(instr), next_bb))
                    return false;
            }
        }
    }

    auto& end_fun = add_instruction(END_FUNCTION);
    end_fun.function = fun_->name();

    program.instructions.assign(instructions_.begin(), instructions_.end());

    // Patch goto/jump targets.
    for (auto const &entry : jumps_) {
        auto it = program.instructions.begin();
        std::advance(it, entry.first);
        assert(it->is_goto());

        auto it2 = program.instructions.begin();
        std::advance(it2, labels_[entry.second]);
        assert(it2->is_skip());

        it->set_target(it2);
    }

    program.compute_target_numbers();
    program.compute_loop_numbers();

#ifdef LOG
    std::cout << "PROGRAM OUTPUT" << std::endl;
    program.output(ns_, "", std::cout);
    std::cout << "END" << std::endl;
#endif
    return true;
}

goto_programt::instructiont&
Conversion::add_instruction(goto_program_instruction_typet type)
{
    instructions_.push_back(goto_programt::instructiont(type));
    return instructions_.back();
}

bool
Conversion::store(const StoreInstr& instr)
{
#ifdef LOG
    std::cout << "store" << std::endl;
#endif

    exprt lhs;
    if (!expression(*instr.op_at(0), &lhs))
        return false;

    if (lhs.id() == ID_address_of) {
        lhs = to_address_of_expr(lhs).object();
    } else {
        lhs = dereference_exprt(lhs);
    }


    exprt rhs;
    if (instr.op_at(1)->kind() == InstrKind::call) {
        // store return_value_function$ %call
        auto& call_instr = static_cast<const CallInstr&>(*instr.op_at(1));

        if (!call(call_instr, true))
            return false;

        // TODO type
        auto& fun_addr = static_cast<NamedAddrInstr&>(*call_instr.func_addr());
        rhs = symbol_exprt(fun_addr.decl()->name() + "#return_value");
    } else {
        if (!expression(*instr.op_at(1), &rhs))
            return false;
    }

    auto& t = add_instruction(ASSIGN);
    t.code = code_assignt(lhs, rhs);

    std::cout << std::endl;
    return true;
}

bool
Conversion::call(const CallInstr& instr, bool from_store)
{
#ifdef LOG
    std::cout << "call" << std::endl;
#endif

    if (!from_store) {
        // call can either have one use by store, or no use if the return value
        // is unused.
        assert(instr.users().size() <= 1);

        if (instr.users().size() == 1) {
            // In this case we are going to emit the call from the store instruction.
            assert((*instr.users().begin())->kind() == InstrKind::store);
            return true;
        }
    }

    // TODO
    auto& fun_addr = static_cast<NamedAddrInstr&>(*instr.func_addr());
    exprt fun = symbol_exprt(fun_addr.decl()->name());

    std::vector<exprt> arguments;
    for (Instr *instr: instr.args()) {
        exprt expr;
        if (!expression(*instr, &expr)) {
            return false;
        }
        arguments.push_back(expr);
    }


    auto& t = add_instruction(FUNCTION_CALL);
    code_function_callt function_call;
    // function_call.add_source_location()=function.source_location();
    function_call.lhs().make_nil();
    function_call.function() = fun;
    function_call.arguments() = arguments;

    // t->source_location=function.source_location();
    t.code.swap(function_call);

    return true;
}

bool
Conversion::dead(const DeadInstr& instr)
{
    auto& t = add_instruction(DEAD);
    t.code = code_deadt(symbol_exprt(instr.symbol()));
    return true;
}

bool
Conversion::branch(const BranchInstr& instr, ir::BasicBlock* next_bb)
{
    exprt condition;
    if (!expression(*instr.op_at(0), &condition))
        return false;

    auto& t = add_instruction(GOTO);
    t.guard = condition;
    jumps_[instructions_.size() - 1] = current_bb_->fanouts()[0].target();

    // The false branch might just fallthrough
    auto* false_target = current_bb_->fanouts()[1].target();
    if (next_bb != false_target) {
        auto& t2 = add_instruction(GOTO);
        t2.guard = true_exprt();
        jumps_[instructions_.size() - 1] = false_target;
    }

    return true;
}

bool
Conversion::jump(const JumpInstr& instr, ir::BasicBlock* next_bb)
{
    auto* target = current_bb_->fanouts()[0].target();
    if (target != next_bb) {
        auto& t = add_instruction(GOTO);
        t.guard = true_exprt();
        jumps_[instructions_.size() - 1] = target;
    }

    return true;
}

bool
Conversion::expression(const Instr& instr, exprt* expr)
{
#ifdef LOG
    std::cout << "expression " << cstr(instr.kind()) << std::endl;
#endif

    if (instr.kind() == InstrKind::constant) {
        auto& constant = static_cast<const ir::Constant&>(instr);
        *expr = from_integer(constant.value(), constant.type());
        return true;
    }
    if (instr.kind() == InstrKind::load) {
        exprt thing;
        if (!expression(*instr.op_at(0), &thing))
            return false;

        if (thing.id() == ID_address_of) {
            *expr = to_address_of_expr(thing).object();
        } else {
            *expr = dereference_exprt(thing);
        }
        return true;
    }
    if (instr.kind() == InstrKind::named_addr) {
        auto& named_addr = static_cast<const NamedAddrInstr&>(instr);
        auto* decl = named_addr.decl();

#ifdef LOG
        std::cout << "named_addr: " << decl->name() << " " << decl->type().id() << std::endl;
#endif

        *expr = address_of_exprt(symbol_exprt(decl->name(), decl->type()));
        return true;
    }
    if (instr.kind() == InstrKind::compute_addr) {
        return compute_addr(static_cast<const ComputeAddrInstr&>(instr), expr);
    }

    for(auto const &it: simple_operations) {
        if (it.second == instr.kind()) {
            return simple_expression(instr, it.first, expr);
        }
    }

    std::cout << "ERROR: unexpected instruction kind: " << cstr(instr.kind()) << std::endl;
    return false;
}

bool
Conversion::simple_expression(const Instr& instr, const irep_idt& _id, exprt* expr)
{
#ifdef LOG
    std::cout << "convert " << _id << std::endl;
#endif

    *expr = exprt(_id, instr.type());
    for (Instr* op: instr.operands()) {
        exprt op_expr;

        if (!expression(*op, &op_expr)) {
            return false;
        }

        expr->copy_to_operands(op_expr);
    }

    return true;
}

bool
Conversion::compute_addr(const ComputeAddrInstr& instr, exprt* expr)
{
#ifdef LOG
    std::cout << "compute_addr" << std::endl;
#endif

    exprt base;
    if (!expression(*instr.op_at(0), &base))
        return false;

    // base + offest
    // TODO always use pointer offset
    if (instr.operands().size() == 2) {
        exprt offset;
        if (!expression(*instr.op_at(1), &offset))
            return false;

        *expr = plus_exprt(base, offset, instr.type());
        return true;
    }

    if (base.id() == ID_address_of) {
        base = to_address_of_expr(base).object();
    } else {
        base = dereference_exprt(base);
    }

    if (base.type().id() == ID_symbol || base.type().id() == ID_struct) {
        auto base_type = base.type();
        if (base.type().id() == ID_symbol) {
            base_type = fun_->ns().follow(base.type());
        }

        assert(base_type.id() == ID_struct);

#ifdef LOG
        std::cout << "member expr: " << from_type(fun_->ns(), "", base_type) << std::endl;
#endif

        const struct_typet::componentst &components = to_struct_type(base_type).components();

        auto member_index = static_cast<Constant*>(instr.op_at(2));
        unsigned index = numeric_cast_v<unsigned>(member_index->value());

        *expr = address_of_exprt(member_exprt(base, components[index]));
        return true;
    }

    if (base.type().id() == ID_array) {
#ifdef LOG
        std::cout << "array index" << std::endl;
#endif

        exprt index;
        if (!expression(*instr.op_at(2), &index))
            return false;

        *expr = address_of_exprt(index_exprt(base, index));
        return true;
    }

    std::cout << "Failed: unexpected base " << base.type().id() << std::endl;
    return false;
}

bool
convert_to_cbmc(ir::Function* func, goto_programt& program, const namespacet& ns)
{
    Conversion conversion(func, ns);
    return conversion.convert(program);
}
