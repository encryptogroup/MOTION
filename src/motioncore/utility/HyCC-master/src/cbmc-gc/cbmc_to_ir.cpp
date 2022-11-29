#include "cbmc_to_ir.h"

#include <solvers/flattening/boolbv_width.h>
#include <util/expr.h>
#include <util/arith_tools.h>

#include "ir/ir.h"
#include "ir/symbol_table.h"


ir::Decl* lookup_decl(symbol_exprt const &sym_expr, ir::Function *func, ir::Scope *scope)
{
	if(sym_expr.get_identifier() == func->name() + "#return_value")
	{
		ir::Decl *decl = scope->try_lookup(as_string(sym_expr.get_identifier()));
		if(!decl)
		{
			ir::VarDecl *var_decl = scope->declare_var(as_string(sym_expr.get_identifier()), sym_expr.type());
			func->add_output(var_decl);
			decl = var_decl;
		}

		return decl;
	}

	return scope->lookup(as_string(sym_expr.get_identifier()));
}

ir::Instr* convert_to_ir_auto_deref(
	ir::BasicBlock *bb,
	ir::Scope *scope,
	namespacet const &ns,
	exprt const &expr);

ir::Instr* convert_to_ir_no_auto_deref(
	ir::BasicBlock *bb,
	ir::Scope *scope,
	namespacet const &ns,
	exprt const &expr)
{
	boolbv_widtht boolbv_width{ns};

	if(expr.id() == ID_symbol)
	{
		ir::Decl *decl = lookup_decl(to_symbol_expr(expr), bb->function(), scope);
		return new ir::NamedAddrInstr{decl, bb};
	}
	else if(expr.id() == ID_constant)
	{
		constant_exprt const &const_expr = to_constant_expr(expr);
		mp_integer int_val;

		if(const_expr.type().id() == ID_signedbv || const_expr.type().id() == ID_unsignedbv || const_expr.type().id() == ID_pointer)
		{
			if(to_integer(const_expr, int_val))
			{
				std::cerr << const_expr.pretty() << std::endl;
				throw std::runtime_error{"Converting constant to integer failed"};
			}
		}
		else if(const_expr.type().id() == ID_bool)
			int_val = const_expr.is_true();
		else
			throw std::runtime_error{"Invalid type for constant: " + as_string(const_expr.type().id())};

		return bb->function()->get_constant(int_val, const_expr.type());
	}
	else if(expr.id() == ID_struct)
	{
		assert(!"TODO");
	}
	else if(expr.id() == ID_union)
	{
		assert(!"TODO");
	}
	else if(expr.id() == ID_plus)
	{
		if(expr.type().id() == ID_pointer)
		{
			ir::Instr *pointer = nullptr;
			ir::Instr* offset = nullptr;
			for(auto const &op: expr.operands())
			{
				if(op.type().id() == ID_pointer)
				{
					assert(!pointer);
					pointer = convert_to_ir_auto_deref(bb, scope, ns, op);
				}
				else
				{
					auto *op_instr = convert_to_ir_auto_deref(bb, scope, ns, op);
					if(offset)
					{
						assert(op_instr->type() == offset->type());
						if(offset->kind() == ir::InstrKind::add)
							offset->add_operand(op_instr);
						else
						{
							auto *add = new ir::Instr{ir::InstrKind::add, op_instr->type()};
							add->add_operand(offset);
							add->add_operand(op_instr);
							offset = add;
						}
					}
					else
						offset = op_instr;
				}
			}

			if(!offset->block())
				bb->push_back(offset);

			auto *comp_addr_instr = new ir::ComputeAddrInstr{pointer->type(), pointer, bb};
			comp_addr_instr->add_operand(offset);

			return comp_addr_instr;
		}
		else
		{
			ir::Instr *add = new ir::Instr{ir::InstrKind::add, expr.type()};
			for(auto const &op: expr.operands())
				add->add_operand(convert_to_ir_auto_deref(bb, scope, ns, op));

			return bb->push_back(add);
		}
	}
	else if(expr.id() == ID_minus)
	{
		if(expr.type().id() == ID_pointer)
			throw std::runtime_error{"subtraction on pointer type not supported yet"};

		ir::Instr *sub = new ir::Instr{ir::InstrKind::sub, expr.type()};
		for(auto const &op: expr.operands())
			sub->add_operand(convert_to_ir_auto_deref(bb, scope, ns, op));

		return bb->push_back(sub);
	}
	else if(expr.id() == ID_notequal)
	{
		ir::Instr *eq = new ir::Instr{ir::InstrKind::eq, expr.type()};
		eq->add_operand(convert_to_ir_auto_deref(bb, scope, ns, expr.op0()));
		eq->add_operand(convert_to_ir_auto_deref(bb, scope, ns, expr.op1()));
		bb->push_back(eq);

		return create_lnot(eq, bb);
	}
	else if(expr.id() == ID_not)
	{
		return create_lnot(convert_to_ir_auto_deref(bb, scope, ns, expr.op0()), bb);
	}
	// Struct member access, e.g. `pos.x`
	if(expr.id() == ID_member)
	{
		member_exprt const &member_expr = to_member_expr(expr);
		exprt const &struct_op = member_expr.struct_op();
		typet const &struct_op_type = ns.follow(struct_op.type());

		const irep_idt &component_name = member_expr.get_component_name();
		const struct_typet::componentst &components = to_struct_type(struct_op_type).components();

		ir::Instr *struct_addr = convert_to_ir_no_auto_deref(bb, scope, ns, struct_op);
		auto *addr_comp_instr = new ir::ComputeAddrInstr{pointer_type(expr.type()), struct_addr, bb};
		addr_comp_instr->add_operand(bb->function()->get_constant(0, signedbv_typet{32}));

		size_t member_index = 0;
		for(; member_index < components.size(); ++member_index)
		{
			if(components[member_index].get_name()==component_name)
				break;
		}

		if(member_index == components.size())
			throw std::runtime_error{"Sruct member not found"};

		addr_comp_instr->add_operand(bb->function()->get_constant(member_index, signedbv_typet{32}));
		return addr_comp_instr;
	}
	// Array access, e.g. `arr[i]`
	else if(expr.id() == ID_index)
	{
		index_exprt array_expr = to_index_expr(expr);
		const exprt &array = array_expr.array();
		const exprt &index = array_expr.index();

		auto *array_instr = convert_to_ir_no_auto_deref(bb, scope, ns, array);
		auto *index_instr = convert_to_ir_auto_deref(bb, scope, ns, index);

		auto *addr_comp_instr = new ir::ComputeAddrInstr{pointer_type(expr.type()), array_instr, bb};
		addr_comp_instr->add_operand(bb->function()->get_constant(0, signedbv_typet{32}));
		addr_comp_instr->add_operand(index_instr);

		return addr_comp_instr;
	}
	else if(expr.id() == ID_address_of)
	{
		auto *instr = convert_to_ir_no_auto_deref(bb, scope, ns, expr.op0());
		assert(instr->type().id() == ID_pointer);

		return instr;
	}
	else if(expr.id() == ID_dereference)
	{
		dereference_exprt deref_expr = to_dereference_expr(expr);
		return convert_to_ir_auto_deref(bb, scope, ns, deref_expr.pointer());
	}
	else if(expr.id() == ID_side_effect)
	{
		side_effect_exprt const &side_effect = to_side_effect_expr(expr);
		if(side_effect.get_statement() == ID_nondet)
			return new ir::Instr{ir::InstrKind::nondet, expr.type(), bb};
		else
			throw std::runtime_error{"Unsupported side-effect: " + as_string(side_effect.get_statement())};
	}

	auto it = ir::simple_operations.find(expr.id());
	if (it != ir::simple_operations.end()) {
		ir::Instr *instr = new ir::Instr{it->second, expr.type()};
		for(auto const &op: expr.operands())
			instr->add_operand(convert_to_ir_auto_deref(bb, scope, ns, op));

		return bb->push_back(instr);
	}

	std::cerr << expr.pretty() << std::endl;
	throw std::runtime_error{"Unsupported expression: " + as_string(expr.id())};
}


ir::Instr* convert_to_ir_auto_deref(
	ir::BasicBlock *bb,
	ir::Scope *scope,
	namespacet const &ns,
	exprt const &expr)
{
	auto *instr = convert_to_ir_no_auto_deref(bb, scope, ns, expr);
	if(expr.id() == ID_symbol || expr.id() == ID_index || expr.id() == ID_member || expr.id() == ID_dereference)
		instr = new ir::LoadInstr{instr, bb};

	return instr;
}

ir::Instr* convert_to_ir_lhs(
	ir::BasicBlock *bb,
	ir::Scope *scope,
	namespacet const &ns,
	exprt const &expr)
{
	if(expr.id() == ID_symbol || expr.id() == ID_index || expr.id() == ID_member || expr.id() == ID_dereference)
		return convert_to_ir_no_auto_deref(bb, scope, ns, expr);

	std::cerr << expr.pretty() << std::endl;
	throw std::runtime_error{"Unsupported LHS expression: " + as_string(expr.id())};
}


ir::BasicBlock* get_block_for(
	goto_programt::instructiont const &inst,
	ir::Function &ir_func,
	std::unordered_map<goto_programt::instructiont const*, ir::BasicBlock*> &label_map)
{
	auto it = label_map.find(&inst);
	if(it != label_map.end())
		return it->second;
	else
		return label_map[&inst] = ir_func.create_block();
}

bool is_return_value(exprt const &expr)
{
  return expr.id() == ID_symbol && ends_with(as_string(to_symbol_expr(expr).get_identifier()), "#return_value");
}

// Returns current BasicBlock
ir::BasicBlock* convert_to_ir(
	ir::Function &ir_func,
	ir::BasicBlock *bb,
	ir::Scope *scope,
	namespacet const &ns,
	std::unordered_map<goto_programt::instructiont const*, ir::BasicBlock*> &label_map,
	goto_programt::instructionst::const_iterator const &inst_it)
{
	auto &inst = *inst_it;

	// If this instruction is a jump target we need to stop the current basic block and create a new
	// one (you cannot jump into the middle of a basic block)
	if(inst.is_target())
	{
		// If the current basic block is empty we don't need to create a new basic block after all,
		// but we still need to map the instruction to the current basic block
		if(bb->instructions().empty())
			label_map[&inst] = bb;
		else
		{
			ir::BasicBlock *next_bb = get_block_for(inst, ir_func, label_map);
			if(bb != next_bb && !bb->has_terminator())
				bb->create_jump(next_bb);

			bb = next_bb;
		}
	}


	if(inst.is_decl())
	{
		symbol_exprt const &symbol = to_symbol_expr(to_code_decl(inst.code).symbol());
		scope->declare_var_explicit(as_string(symbol.get_identifier()), symbol.type());
	}
	else if(inst.is_assign())
	{
		code_assignt const &assign = to_code_assign(inst.code);
		ir::Instr *rhs = nullptr;
		if(is_return_value(assign.rhs()))
		{
			auto *last_instr = &bb->instructions().back();
			assert(last_instr->kind() == ir::InstrKind::call);
			rhs = last_instr;
		}
		else
			rhs = convert_to_ir_auto_deref(bb, scope, ns, assign.rhs());

		auto *lhs = convert_to_ir_lhs(bb, scope, ns, assign.lhs());
		new ir::StoreInstr{lhs, rhs, bb};
	}
	else if(inst.is_goto())
	{
		if(inst.guard.id() == ID_constant)
		{
			constant_exprt const &const_expr = to_constant_expr(inst.guard);
			bool condition;
			if(const_expr.type().id() == ID_bool)
				condition = const_expr.is_true();
			else
			{
				mp_integer value;
				if(to_integer(const_expr, value))
					throw std::runtime_error{"Retrieving constant failed"};

				condition = value != 0;
			}

			ir::BasicBlock *target;
			if(condition)
				target = get_block_for(*inst.get_target(), ir_func, label_map);
			else
				target = get_block_for(*std::next(inst_it), ir_func, label_map);

			bb->create_jump(target);
			bb = get_block_for(*std::next(inst_it), ir_func, label_map);
		}
		else
		{
			auto condition = convert_to_ir_auto_deref(bb, scope, ns, inst.guard);
			ir::BasicBlock *then_target = get_block_for(*inst.get_target(), ir_func, label_map);
			ir::BasicBlock *else_target = get_block_for(*std::next(inst_it), ir_func, label_map);

			bb->create_branch(condition, then_target, else_target);
			bb = else_target;
		}
	}
	else if(inst.is_function_call())
	{
		code_function_callt const &call = to_code_function_call(inst.code);
		auto *func_addr = convert_to_ir_no_auto_deref(bb, scope, ns, call.function());
		auto *call_instr = new ir::CallInstr{func_addr};
		for(auto const &arg: call.arguments())
			call_instr->add_operand(convert_to_ir_auto_deref(bb, scope, ns, arg));

		bb->push_back(call_instr);
	}
	else if(inst.is_return())
	{
		// We assume that remove_returns() has been called already
		throw std::runtime_error{"return statements should have been removed at this point"};
	}
	else if (inst.is_dead())
	{
		code_deadt const &dead = to_code_dead(inst.code);
		new ir::DeadInstr{as_string(dead.get_identifier()), bb};
	}

	return bb;
}

std::unique_ptr<ir::Function> convert_to_ir(
	ir::SymbolTable &sym_table,
	namespacet const &ns,
	goto_functionst::goto_functiont const &func)
{
	std::string func_name = as_string(goto_programt::get_function_id(func.body));

	ir::Scope *func_scope = sym_table.root_scope()->create_child();
	std::unique_ptr<ir::Function> ir_func{new ir::Function{func_name, func_scope, ns}};

	for(auto const &param: func.type.parameters())
	{
		auto decl = ir_func->scope()->declare_var(as_string(param.get_identifier()), param.type());
		ir_func->add_input(decl);
	}

	std::unordered_map<goto_programt::instructiont const*, ir::BasicBlock*> label_map;
	ir::BasicBlock *cur = ir_func->start_block();
	for(auto inst_it = func.body.instructions.begin(); inst_it != func.body.instructions.end(); ++inst_it)
		cur = convert_to_ir(*ir_func, cur, ir_func->scope(), ns, label_map, inst_it);

	ir_func->update_blocks();

	ir::InstrNameMap names = ir::instr_namer(ir_func.get());
	if(!ir::validate_function(ir_func.get(), &names, &std::cout))
	{
		ir_func->print(std::cerr, &names);
		throw std::runtime_error{"IR validation failed for function '" + func_name + "'"};

	}

	return ir_func;
}

