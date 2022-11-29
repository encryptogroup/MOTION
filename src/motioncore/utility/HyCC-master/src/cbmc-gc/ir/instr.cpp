#include "instr.h"
#include "basic_block.h"
#include "dominators.h"
#include "debug.h"

#include "util/arith_tools.h"
#include "util/type_eq.h"


namespace ir {

//==================================================================================================
char const* cstr(InstrKind kind)
{
	switch(kind)
	{
		case InstrKind::constant: return "constant";
		case InstrKind::output: return "output";
		case InstrKind::dead: return "dead";
		case InstrKind::add: return "add";
		case InstrKind::sub: return "sub";
		case InstrKind::mul: return "mul";
		case InstrKind::div: return "div";
		case InstrKind::mod: return "mod";
		case InstrKind::unary_neg: return "unary_neg";
		case InstrKind::lt: return "lt";
		case InstrKind::le: return "le";
		case InstrKind::gt: return "gt";
		case InstrKind::ge: return "ge";
		case InstrKind::eq: return "eq";
		case InstrKind::b_and: return "b_and";
		case InstrKind::b_xor: return "b_xor";
		case InstrKind::b_or: return "b_or";
		case InstrKind::b_not: return "b_not";
		case InstrKind::l_not: return "l_not";
		case InstrKind::l_and: return "l_and";
		case InstrKind::l_or: return "l_or";
		case InstrKind::lshr: return "lshr";
		case InstrKind::ashr: return "ashr";
		case InstrKind::shl: return "shl";
		case InstrKind::call: return "call";
		case InstrKind::named_addr: return "named_addr";
		case InstrKind::compute_addr: return "compute_addr";
		case InstrKind::load: return "load";
		case InstrKind::store: return "store";
		case InstrKind::combine: return "combine";
		case InstrKind::jump: return "jump";
		case InstrKind::branch: return "branch";
		case InstrKind::phi: return "phi";
		case InstrKind::cast: return "cast";
		case InstrKind::nondet: return "nondet";
	}
}


//==================================================================================================
Instr::Instr(InstrKind kind, typet const &type, BasicBlock *block) :
	m_type{type},
	m_kind{kind},
	m_block{nullptr}
{
	if(block)
		block->push_back(this);
}

namespace
{
	void error_instr_type(Instr const *instr, typet const &expected_type, size_t operand_idx, ValidationContext &ctx)
	{
		(void)expected_type;

		(*ctx.os) << "Error: operand #" << operand_idx + 1 << " has invalid type: ";
		instr->print_inline(*ctx.os, *ctx.names);
		(*ctx.os) << std::endl;
	}

	void error_instr_not_dominated(Instr const *instr, size_t operand_idx, ValidationContext &ctx)
	{
		(*ctx.os) << "Error: operand #" << operand_idx + 1 << " does not dominate instruction: ";
		instr->print_inline(*ctx.os, *ctx.names);
		(*ctx.os) << std::endl;
	}
}

bool Instr::is_well_formed(ValidationContext &ctx) const
{
	// By default, an instruction is well formed iff
	// - all operands dominate the instruction, and
	// - the types of all operands are the same as this instruction's type.
	
	bool well_formed = type_check(this, ctx);

	// TODO Handle phi node
	for(size_t i = 0; i < m_operands.size(); ++i)
	{
		if(!ctx.is_cur_instr_dominated_by(m_operands[i]))
		{
			well_formed = false;
			error_instr_not_dominated(this, i, ctx);
		}
	}

	return well_formed;
}

void Instr::print_ref(std::ostream &os, InstrNameMap &names) const
{
	os << "%" << names.get_name(this);
}

void Instr::print_inline(std::ostream &os, InstrNameMap &names) const
{
	if(m_type.id().empty() || m_type.id() == ID_empty)
		os << cstr(m_kind);
	else
	{
		os << "%" << names.get_name(this) << " = " << cstr(m_kind);
		os << "<" << from_type(block()->function()->ns(), "", m_type) << ">";
	}

	for(auto const &op: operands())
	{
		os << ' ';
		op->print_ref(os, names);
	}
}

void Instr::dump(InstrNameMap &names) const
{
	print_inline(std::cout, names);
	std::cout << std::endl;
}


//==================================================================================================
void Constant::print_ref(std::ostream &os, InstrNameMap &names) const
{
	(void)names;
	os << "(" << from_type(block()->function()->ns(), "", type()) << ")" << m_value;
}

void Constant::print_inline(std::ostream &os, InstrNameMap &names) const
{
	os << "%" << names.get_name(this) << " = (" << from_type(block()->function()->ns(), "", type()) << ")" << m_value;
}

void NamedAddrInstr::print_inline(std::ostream &os, InstrNameMap &names) const
{
	os << "%" << names.get_name(this) << " = " << cstr(kind());
	os << "<" << from_type(block()->function()->ns(), "", type()) << ">";
	os << " " << m_decl->name();
}


//==================================================================================================
namespace
{
	void error_too_few_ops(Instr const *instr, int min_num_ops, int actual_num_ops, ValidationContext &ctx)
	{
		(*ctx.os) << "Error: expected at least " << min_num_ops << " operands, got " << actual_num_ops << ": ";
		instr->print_inline(*ctx.os, *ctx.names);
		(*ctx.os) << std::endl;
	}

	void error_num_ops(Instr const *instr, int expected_num_ops, int actual_num_ops, ValidationContext &ctx)
	{
		(*ctx.os) << "Error: expected at " << expected_num_ops << " operands, got " << actual_num_ops << ": ";
		instr->print_inline(*ctx.os, *ctx.names);
		(*ctx.os) << std::endl;
	}

	bool is_integral_type(typet const &type)
	{
		return type.id() == ID_signedbv || type.id() == ID_unsignedbv || type.id() == ID_pointer;
	}

	bool type_check_address_computation(ComputeAddrInstr const *instr, ValidationContext &ctx)
	{
		if(instr->operands().size() < 2)
		{
			error_too_few_ops(instr, 2, instr->operands().size(), ctx);
			return false;
		}

		if(instr->type().id() != ID_pointer)
		{
			(*ctx.os) << "Error: instruction must be of pointer type: ";
			instr->print_inline(*ctx.os, *ctx.names);
			(*ctx.os) << std::endl;
			return false;
		}

		if(instr->op_at(0)->type().id() != ID_pointer)
		{
			(*ctx.os) << "Error: operand #1 must be of pointer type: ";
			instr->print_inline(*ctx.os, *ctx.names);
			(*ctx.os) << std::endl;
			return false;
		}

		namespacet const &ns = instr->block()->function()->ns();

		Instr const *base_addr = instr->op_at(0);
		typet const *cur_type = &to_pointer_type(base_addr->type()).subtype();

		// The first index only denotes the offset to the base address and thus does not change the
		// type, so we start with the second index (i.e., the third operand)
		for(size_t op_idx = 2; op_idx < instr->operands().size(); ++op_idx)
		{
			Instr const *index_instr = instr->op_at(op_idx);
			if(!is_integral_type(index_instr->type()))
			{
				(*ctx.os) << "Error: operand #" << op_idx+1 << " must be of integer type: ";
				instr->print_inline(*ctx.os, *ctx.names);
				(*ctx.os) << std::endl;
				return false;
			}

			// We don't set `cur_type` to the followed() type because we compare it later to
			// `instr->type()` which is not followed() and following() does not work recursively so we
			// cannot just follow() `instr->type()` to get the completely followed() type.
			typet const &followed_type = ns.follow(*cur_type);
			if(followed_type.id() == ID_array)
				cur_type = &to_array_type(followed_type).subtype();
			else if(followed_type.id() == ID_struct)
			{
				if(index_instr->kind() != InstrKind::constant)
				{
					(*ctx.os) << "Error: operand #" << op_idx+1 << ": struct member indices must be constant: ";
					instr->print_inline(*ctx.os, *ctx.names);
					(*ctx.os) << std::endl;
					return false;
				}

				struct_typet const &struct_type = to_struct_type(followed_type);
				unsigned long member_index = static_cast<Constant const*>(index_instr)->value().to_ulong();
				if(member_index >= struct_type.components().size())
				{
					(*ctx.os) << "Error: operand #" << op_idx+1 << ": struct member index out of bounds: ";
					instr->print_inline(*ctx.os, *ctx.names);
					(*ctx.os) << std::endl;
					return false;
				}

				cur_type = &struct_type.components()[member_index].type();
			}
			else
			{
				(*ctx.os) << "Error: operand #" << op_idx+1 << " must index into an array or struct: ";
				instr->print_inline(*ctx.os, *ctx.names);
				(*ctx.os) << std::endl;
				return false;
			}
		}


		typet final_type = pointer_type(*cur_type);
		if(!type_eq(instr->type(), final_type, ns))
		{
			std::cout << from_type(ns, "", final_type) << std::endl;
			std::cout << from_type(ns, "", ns.follow(instr->type())) << std::endl;
			(*ctx.os) << "Error: instruction type differs from computed type: ";
			instr->print_inline(*ctx.os, *ctx.names);
			(*ctx.os) << std::endl;
			return false;
		}

		return true;
	}
}

bool type_check(Instr const *instr, ValidationContext &ctx)
{
	namespacet const &ns = instr->block()->function()->ns();
	switch(instr->kind())
	{
		case InstrKind::constant:
		case InstrKind::output:
		case InstrKind::dead:
			return true;

		case InstrKind::add:
		case InstrKind::sub:
		case InstrKind::mul:
		case InstrKind::div:
		case InstrKind::mod:
		case InstrKind::b_and:
		case InstrKind::b_xor:
		case InstrKind::b_or:
		{
			if(instr->operands().size() < 2)
			{
				error_too_few_ops(instr, 2, instr->operands().size(), ctx);
				return false;
			}

			if(!is_integral_type(instr->type()))
			{
				(*ctx.os) << "Error: expected integer type, got " << from_type(ns, "", instr->type()) << ": ";
				instr->print_inline(*ctx.os, *ctx.names);
				(*ctx.os) << std::endl;
				return false;
			}

			for(size_t i = 0; i < instr->operands().size(); ++i)
			{
				if(instr->op_at(i)->type() != instr->type())
				{
					error_instr_type(instr, instr->type(), i, ctx);
					return false;
				}
			}

			return true;
		}

		case InstrKind::b_not:
		case InstrKind::unary_neg:
		{
			if(instr->operands().size() != 1)
			{
				error_num_ops(instr, 1, instr->operands().size(), ctx);
				return false;
			}

			if(!is_integral_type(instr->type()))
			{
				(*ctx.os) << "Error: expected integer type, got " << from_type(ns, "", instr->type()) << ": ";
				instr->print_inline(*ctx.os, *ctx.names);
				(*ctx.os) << std::endl;
				return false;
			}

			if(instr->op_at(0)->type() != instr->type())
			{
				error_instr_type(instr, instr->type(), 0, ctx);
				return false;
			}

			return true;
		}

		case InstrKind::l_not:
		{
			if(instr->operands().size() != 1)
			{
				error_num_ops(instr, 1, instr->operands().size(), ctx);
				return false;
			}

			if(instr->type().id() != ID_bool)
			{
				(*ctx.os) << "Error: instruction must be of type bool, got " << from_type(ns, "", instr->type()) << ": ";
				instr->print_inline(*ctx.os, *ctx.names);
				(*ctx.os) << std::endl;
				return false;
			}

			if(instr->op_at(0)->type() != instr->type())
			{
				error_instr_type(instr, instr->type(), 0, ctx);
				return false;
			}

			return true;
		}

		case InstrKind::l_and:
		case InstrKind::l_or:
		{
			if(instr->operands().size() != 2)
			{
				error_too_few_ops(instr, 2, instr->operands().size(), ctx);
				return false;
			}

			if(instr->type().id() != ID_bool)
			{
				(*ctx.os) << "Error: expected bool type, got " << from_type(ns, "", instr->type()) << ": ";
				instr->print_inline(*ctx.os, *ctx.names);
				(*ctx.os) << std::endl;
				return false;
			}

			for(size_t i = 0; i < instr->operands().size(); ++i)
			{
				if(instr->op_at(i)->type() != instr->type())
				{
					error_instr_type(instr, instr->type(), i, ctx);
					return false;
				}
			}

			return true;
		}

		case InstrKind::lshr:
		case InstrKind::ashr:
		case InstrKind::shl:
		{
			if(instr->operands().size() != 2)
			{
				error_num_ops(instr, 2, instr->operands().size(), ctx);
				return false;
			}

			if(!is_integral_type(instr->type()))
			{
				(*ctx.os) << "Error: expected integer type, got " << from_type(ns, "", instr->type()) << ": ";
				instr->print_inline(*ctx.os, *ctx.names);
				(*ctx.os) << std::endl;
				return false;
			}

			for(size_t i = 0; i < instr->operands().size(); ++i)
			{
				if(instr->op_at(i)->type() != instr->type())
				{
					error_instr_type(instr, instr->type(), i, ctx);
					return false;
				}
			}

			return true;
		}

		case InstrKind::eq:
		case InstrKind::lt:
		case InstrKind::le:
		case InstrKind::gt:
		case InstrKind::ge:
		{
			if(instr->operands().size() != 2)
			{
				error_num_ops(instr, 2, instr->operands().size(), ctx);
				return false;
			}

			if(instr->type().id() != ID_bool)
			{
				(*ctx.os) << "Error: instruction must be of type bool: ";
				instr->print_inline(*ctx.os, *ctx.names);
				(*ctx.os) << std::endl;
				return false;
			}

			if(instr->op_at(0)->type() != instr->op_at(1)->type())
			{
				(*ctx.os) << "Error: both operands must be of the same type: ";
				instr->print_inline(*ctx.os, *ctx.names);
				(*ctx.os) << std::endl;
				return false;
			}

			if(instr->kind() == InstrKind::lt)
			{
				if(!is_integral_type(instr->op_at(0)->type()))
				{
					(*ctx.os) << "Error: both operands must be of integer type: ";
					instr->print_inline(*ctx.os, *ctx.names);
					(*ctx.os) << std::endl;
					return false;
				}
			}

			return true;
		}

		case InstrKind::call:
		{
			auto *call = static_cast<CallInstr const*>(instr);
			bool func_addr_type_valid = 
				(call->func_addr()->type().id() == ID_pointer) &&
				(to_pointer_type(call->func_addr()->type()).subtype().id() == ID_code);
			if(!func_addr_type_valid)
			{
				(*ctx.os) << "Error: operand #1 must be a pointer to a function: ";
				call->print_inline(*ctx.os, *ctx.names);
				(*ctx.os) << std::endl;
				return false;
			}

			code_typet const &func_type = call->func_type();
			if(instr->type() != func_type.return_type())
			{
				(*ctx.os) << "Error: instruction must be of the same type as the function return type: ";
				call->print_inline(*ctx.os, *ctx.names);
				(*ctx.os) << std::endl;
				return false;
			}

			for(size_t i = 1; i < call->operands().size(); ++i)
			{
				if(call->op_at(i)->type() != func_type.parameters()[i-1].type())
				{
					(*ctx.os) << "Error: operand #" << i+1 << " must be of the same type as the corresponding parameter type: ";
					call->print_inline(*ctx.os, *ctx.names);
					(*ctx.os) << std::endl;
					return false;
				}
			}

			return true;
		}

		case InstrKind::compute_addr:
			return type_check_address_computation(static_cast<ComputeAddrInstr const*>(instr), ctx);

		case InstrKind::named_addr:
		{
			auto *addr = static_cast<NamedAddrInstr const*>(instr);
			if(addr->type().id() != ID_pointer)
			{
				(*ctx.os) << "Error: instruction must be of pointer type: ";
				instr->print_inline(*ctx.os, *ctx.names);
				(*ctx.os) << std::endl;
				return false;
			}

			pointer_typet const &pointer_type = to_pointer_type(addr->type());
			if(pointer_type.subtype() != addr->decl()->type())
			{
				(*ctx.os) << "Error: type of named address does not match instruction type: ";
				instr->print_inline(*ctx.os, *ctx.names);
				(*ctx.os) << std::endl;
				return false;
			}

			return true;
		}

		case InstrKind::load:
		{
			if(instr->operands().size() != 1)
			{
				error_num_ops(instr, 1, instr->operands().size(), ctx);
				return false;
			}

			if(instr->op_at(0)->type().id() != ID_pointer)
			{
				(*ctx.os) << "Error: operand #1 must be of pointer type: ";
				instr->print_inline(*ctx.os, *ctx.names);
				(*ctx.os) << std::endl;
				return false;
			}

			pointer_typet const &pointer_type = to_pointer_type(instr->op_at(0)->type());
			if(pointer_type.subtype() != instr->type())
			{
				(*ctx.os) << "Error: the pointed-to type of operand #1 must match the instruction type: ";
				instr->print_inline(*ctx.os, *ctx.names);
				(*ctx.os) << std::endl;
				return false;
			}

			return true;
		}

		case InstrKind::store:
		{
			if(instr->operands().size() != 2)
			{
				error_num_ops(instr, 2, instr->operands().size(), ctx);
				return false;
			}

			if(instr->type() != typet{})
			{
				(*ctx.os) << "Error: instruction must be of empty type: ";
				instr->print_inline(*ctx.os, *ctx.names);
				(*ctx.os) << std::endl;
				return false;
			}

			if(instr->op_at(0)->type().id() != ID_pointer)
			{
				(*ctx.os) << "Error: operand #1 must be of pointer type: ";
				instr->print_inline(*ctx.os, *ctx.names);
				(*ctx.os) << std::endl;
				return false;
			}

			pointer_typet const &pointer_type = to_pointer_type(instr->op_at(0)->type());
			if(instr->op_at(1)->type() != pointer_type.subtype())
			{
				error_instr_type(instr, pointer_type.subtype(), 1, ctx);
				return false;
			}

			return true;
		}

		case InstrKind::jump:
		{
			if(instr->operands().size() != 0)
			{
				error_num_ops(instr, 0, instr->operands().size(), ctx);
				return false;
			}

			if(instr->type() != typet{})
			{
				(*ctx.os) << "Error: instruction must be of empty type: ";
				instr->print_inline(*ctx.os, *ctx.names);
				(*ctx.os) << std::endl;
				return false;
			}

			return true;
		}

		case InstrKind::branch:
		{
			if(instr->operands().size() != 1)
			{
				error_num_ops(instr, 1, instr->operands().size(), ctx);
				return false;
			}

			if(instr->type() != typet{})
			{
				(*ctx.os) << "Error: instruction must be of empty type: ";
				instr->print_inline(*ctx.os, *ctx.names);
				(*ctx.os) << std::endl;
				return false;
			}

			typet const &condition_type = instr->op_at(0)->type();
			if(condition_type.id() != ID_bool && !is_integral_type(condition_type))
			{
				(*ctx.os) << "Error: operand #1 must be of integer or boolean type, got " << from_type(ns, "", instr->type()) << ": ";
				instr->print_inline(*ctx.os, *ctx.names);
				(*ctx.os) << std::endl;
				return false;
			}

			return true;
		}

		case InstrKind::combine:
		{
			if(instr->type().id() != ID_array)
			{
				(*ctx.os) << "Error: instruction must be of array type: ";
				instr->print_inline(*ctx.os, *ctx.names);
				(*ctx.os) << std::endl;
				return false;
			}

			array_typet const &array_type = to_array_type(instr->type());
			mp_integer array_size;
			if(to_integer(array_type.size(), array_size))
			{
				(*ctx.os) << "Error: array type of instruction must be of constant length: ";
				instr->print_inline(*ctx.os, *ctx.names);
				(*ctx.os) << std::endl;
				return false;
			}

			if(array_size != instr->operands().size())
			{
				(*ctx.os) << "Error: length of array type must match number of operands: ";
				instr->print_inline(*ctx.os, *ctx.names);
				(*ctx.os) << std::endl;
				return false;
			}

			for(size_t i = 0; i < instr->operands().size(); ++i)
			{
				if(instr->op_at(i)->type() != array_type.subtype())
				{
					(*ctx.os) << "Error: operand #" << i+1 << " must be of type " << from_type(ns, "", array_type.subtype()) << ": ";
					instr->print_inline(*ctx.os, *ctx.names);
					(*ctx.os) << std::endl;
					return false;
				}
			}

			return true;
		}

		case InstrKind::cast:
			// TODO
			return true;

		case InstrKind::phi:
		{
			if(instr->operands().size() < 2)
			{
				error_too_few_ops(instr, 2, instr->operands().size(), ctx);
				return false;
			}

			for(size_t i = 0; i < instr->operands().size(); ++i)
			{
				if(instr->op_at(i)->type() != instr->type())
				{
					error_instr_type(instr, instr->type(), i, ctx);
					return false;
				}
			}

			return true;
		}

		case InstrKind::nondet:
		{
			if(instr->operands().size())
			{
				(*ctx.os) << "Error: instruction cannot have operands: ";
				instr->print_inline(*ctx.os, *ctx.names);
				(*ctx.os) << std::endl;
				return false;
			}

			return true;
		}
	}
}

}
