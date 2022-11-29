#include "pointer_analysis.h"
#include "dominators.h"



namespace ir {

static VarDecl NullObjectInst{"NULL", pointer_type(void_typet{}), 0};
Decl * const NullObject = &NullObjectInst;

static VarDecl UnknownObjectInst{"UNKNOWN", pointer_type(void_typet{}), 0};
Decl * const UnknownObject = &UnknownObjectInst;

namespace {

LinearLocationSet compute_byte_offset(ComputeAddrInstr const *instr, boolbv_widtht const &boolbv_width)
{
	namespacet const &ns = instr->block()->function()->ns();

	Instr const *base_addr = instr->op_at(0);
	typet const *cur_type = &ns.follow(to_pointer_type(base_addr->type()).subtype());
	Instr const *base_offset = instr->op_at(1);

	OffsetCalculater offset{&boolbv_width};
	offset.add_offset(*cur_type, base_offset);
	for(size_t op_idx = 2; op_idx < instr->operands().size(); ++op_idx)
	{
		Instr const *index_instr = instr->op_at(op_idx);

		assert(cur_type->id() == ID_array || cur_type->id() == ID_struct);
		if(cur_type->id() == ID_array)
		{
			cur_type = &ns.follow(to_array_type(*cur_type).subtype());
			offset.add_offset(*cur_type, index_instr);
		}
		else if(cur_type->id() == ID_struct)
		{
			assert(index_instr->kind() == InstrKind::constant);

			struct_typet const &struct_type = to_struct_type(*cur_type);
			size_t elem_offset = static_cast<Constant const*>(index_instr)->value().to_long();

			assert(elem_offset < struct_type.components().size());
			for(size_t i = 0; i < elem_offset; ++i)
				offset.add_offset(struct_type.components()[i].type(), 1);

			cur_type = &ns.follow(struct_type.components()[elem_offset].type());
		}
	}

	return offset.location_set();
}

// Creates a PointsToMap where the parameters of `callee` have been initialized with the values of
// their corresponding arguments from `ppt_caller`.
PointsToMap create_initial_pt(Function const *callee, Instr::OpRange const &args, PointsToMap const &pt_caller)
{
	// We initialize the points-to map of the callee with the one from the caller because the callee
	// may access variables from the callers via pointers passed as arguments.
	PointsToMap pt_init = pt_caller;

	assert(callee->inputs().size() == args.size());
	size_t num_args = callee->inputs().size();
	for(size_t i = 0; i < num_args; ++i)
	{
		Instr *arg = args[i];
		VarDecl *param = callee->inputs()[i];
		pt_init.merge_addresses(param, pt_caller.get_addresses(arg));
	}

	return pt_init;
}

bool updater_caller_pt(PointsToMap &pt_caller, CallInstr const *call, Function *callee, PointsToMap const &pt_callee)
{
	// TODO Support more outputs than just the return value
	assert(callee->outputs().size() <= 1);
	bool changed = false;
	if(callee->outputs().size() == 1)
	{
		VarDecl *return_val = callee->outputs()[0];
		auto addrs_it = pt_callee.objects().find(return_val);
		if(addrs_it != pt_callee.objects().end())
			changed |= pt_caller.merge_addresses(call, addrs_it->second);
	}

	// The callee may have changed variables of the caller via pointers passed as arguments.
	// Thus, we merge any information about the caller's variables from the callees
	// PointsToMap to the caller's PointsToMap.
	// TODO The same goes for global variables.
	Function const *caller = call->block()->function();
	std::string caller_var_prefix = caller->name() + "::";
	for(auto const &pair: pt_callee.objects())
	{
		Decl *decl = pair.first;
		if(starts_with(cstring_ref{decl->name()}, caller_var_prefix.c_str()))
		{
			std::vector<PointsToMap::Entry> const &entries = pair.second;
			for(auto const &entry: entries)
				changed |= pt_caller.merge_address(decl, entry.source_locs, entry.target_obj, entry.target_locs);
		}
	}

	return changed;
}

bool pointer_analysis(CallPath &cp, Instr const *instr, PointsToMap &pt, PACallAnalyzer *ca)
{
	switch(instr->kind())
	{
		case InstrKind::constant:
		{
			mp_integer const &val = static_cast<Constant const*>(instr)->value();
			if(val == 0)
				return pt.merge_address(instr, NoOffset(), NullObject);

			return pt.merge_address(instr, NoOffset(), UnknownObject);
		}

		case InstrKind::named_addr:
		{
			Decl *decl = static_cast<NamedAddrInstr const*>(instr)->decl();
			return pt.merge_address(instr, NoOffset(), decl);
		}

		case InstrKind::compute_addr:
		{
			std::vector<PointsToMap::Entry> entries = pt.get_addresses(instr->op_at(0));

			LinearLocationSet offset = compute_byte_offset(
				static_cast<ComputeAddrInstr const*>(instr),
				ca->boolbv_width()
			);

			for(auto &entry: entries)
				entry.target_locs = entry.target_locs + offset;

			return pt.merge_addresses(instr, std::move(entries));
		}

		case InstrKind::load:
		{
			std::vector<PointsToMap::Entry> const &src_entries = pt.get_addresses(instr->op_at(0));
			ptrdiff_t num_bytes = ca->boolbv_width()(instr->type()) / config.ansi_c.char_width;
			bool changed = false;
			for(auto &src_entry: src_entries)
			{
				auto target_entries = pt.get_addresses(
					src_entry.target_obj,
					src_entry.target_locs,
					num_bytes
				);

				for(auto &e: target_entries)
				{
					e.source_locs = e.source_locs - src_entry.target_locs;
					if(e.source_locs.stride() >= num_bytes)
						e.source_locs.set_stride(0);
				}

				changed |= pt.merge_addresses(instr, target_entries);
			}

			return changed;
		}

		case InstrKind::store:
		{
			std::vector<PointsToMap::Entry> const &lhs_entries = pt.get_addresses(instr->op_at(0));
			std::vector<PointsToMap::Entry> const &rhs_entries = pt.get_addresses(instr->op_at(1));
			assert(lhs_entries.size() && "Writing to the target of an unknown pointer");
			bool changed = false;
			for(auto const &lhs_entry: lhs_entries)
			{
				for(auto const &rhs_entry: rhs_entries)
				{
					changed |= pt.merge_address(
						lhs_entry.target_obj, lhs_entry.target_locs + rhs_entry.source_locs,
						rhs_entry.target_obj, rhs_entry.target_locs);
				}
			}

			return changed;
		}

		case InstrKind::cast:
		{
			return pt.merge_addresses(instr, pt.get_addresses(instr->op_at(0)));
		}

		case InstrKind::call:
		{
			CallInstr const *call = static_cast<CallInstr const*>(instr);
			cp.push_back(call);
			return ca->analyze_call(cp, pt);
		}

		case InstrKind::phi:
			throw std::runtime_error{"Pointer Analysis: phi nodes not supported yet"};

		default:
			return false;
	}
}

bool pointer_analysis(CallPath &cp, BasicBlock const *bb, PointsToMap &pt, PACallAnalyzer *ca)
{
	bool changed = false;
	for(Instr const &instr: bb->instructions())
		changed |= pointer_analysis(cp, &instr, pt, ca);

	return changed;
}

}


//==================================================================================================
PointsToMap pointer_analysis(CallPath &cp, Function const *func, PointsToMap const &pt_init, PACallAnalyzer *ca)
{
	for(VarDecl *arg: func->inputs())
	{
		if(arg->type().id() != ID_pointer)
			continue;

		auto it = pt_init.objects().find(arg);
		if(it == pt_init.objects().end())
			throw std::logic_error{"Pointer arguments must be part of the initial PointsToMap"};
	}

	std::vector<BasicBlock const*> rpo = compute_post_order(*func);
	std::reverse(rpo.begin(), rpo.end());
	std::vector<PointsToMap> pt_by_block_id(rpo.size());

	bool changed = true;
	while(changed)
	{
		changed = false;
		for(BasicBlock const *bb: rpo)
		{
			PointsToMap new_pt;
			if(bb == func->start_block())
				new_pt = pt_init;

			for(BlockEdge const &edge: bb->fanins())
				new_pt.merge(pt_by_block_id[edge.target()->id()]);

			pointer_analysis(cp, bb, new_pt, ca);
			changed = pt_by_block_id[bb->id()] != new_pt;
			pt_by_block_id[bb->id()] = std::move(new_pt);
		}
	}


	/*BBWorkList work_list = create_work_list_rpo(func);
	for(auto const &bb: func->basic_blocks())
		work_list.insert(bb.get());

	while(work_list.size())
	{
		BasicBlock const *bb = *work_list.begin(); work_list.erase(work_list.begin());
		PointsToMap &state = pt_by_block_id[bb->id()];
		bool changed = false;

		for(BlockEdge const &pred: bb->fanins())
			changed |= state.merge(pt_by_block_id[pred.target()->id()]);

		std::cout << "===== Block #" << bb->id() << std::endl;
		state.print(std::cout);

		changed |= pointer_analysis(bb, state, ca);
		if(changed)
		{
			for(BlockEdge const &succ: bb->fanouts())
				work_list.insert(succ.target());
		}
	}*/


	return pt_by_block_id[func->exit_block()->id()];
}


//==================================================================================================
struct PopBackOnExit
{
	explicit PopBackOnExit(CallPath &cp) :
		cp{&cp} {}

	~PopBackOnExit()
	{
		assert(cp->size());
		cp->pop_back();
	}

	CallPath *cp;
};

std::ostream& operator << (std::ostream &os, CallPath const &cp)
{
	for(auto *call: cp)
	{
		FuncDecl *decl = try_get_func_decl(call);
		if(!decl)
			os << "<func-ptr> ";
		else
			os << decl->name() << " ";
	}

	return os;
}

bool PAContextSensitiveCallAnalyzer::analyze_call(
	CallPath &cp,
	PointsToMap &pt_caller)
{
	assert(cp.size());

	// After we have analyzed the current function call we remove it from the
	// CallPath.
	PopBackOnExit pboe{cp};

	CallInstr const *call = static_cast<CallInstr const*>(cp.back());
	FuncDecl *func_decl = try_get_func_decl(call);

	// No support for function pointers at the moment.
	// TODO We could actually check if `call->func_addr()` is in the PointsToMap.
	if(!func_decl)
		throw std::runtime_error{"Function pointers not supported yet"};

	if(!func_decl->is_defined())
		throw std::runtime_error{"Function not defined: " + func_decl->name()};

	// `acyclic_cp` is the prefix of `cp` until (and including) the first
	// occurence of `call`. This removes recursive calls.
	CallPath acyclic_cp{
		cp.begin(),
		std::find(cp.begin(), cp.end(), call) + 1,
	};
	assert(acyclic_cp.back() == call);

	Function *callee = func_decl->function();
	PointsToMap input_pt = create_initial_pt(callee, call->args(), pt_caller);

	// We use `acyclic_cp` to retrieve the corresponding CallInfo. This means
	// that the first call of a recursion contains the summary of all following
	// recursive calls.
	auto res = m_call_info.insert({acyclic_cp, CallInfo{callee}});
	CallInfo &call_info = res.first->second;
	bool newly_inserted = res.second;

	// If we have analyzed this function at this call-path at least once, and
	// merging the new callee PointsToMap has no effect, then we don't need to
	// analyze the function again.
	// Together with using `acyclic_cp`, this also takes care of recursion,
	// because once the recursion has reached a fixed-point,
	// `call_info.input_pt.merge()` won't change anymore.
	if(!call_info.input_pt.merge(input_pt) && !newly_inserted)
		return updater_caller_pt(pt_caller, call, callee, call_info.output_pt);

	call_info.output_pt.merge(pointer_analysis(cp, callee, call_info.input_pt, this));
	call_info.num_times_analysed++;

	return updater_caller_pt(pt_caller, call, callee, call_info.output_pt);
}


//==================================================================================================
bool PAContextInsensitiveCallAnalyzer::analyze_call(
	CallPath &cp,
	PointsToMap &pt_caller)
{
	// After we have analyzed the current function call we remove it from the
	// CallPath.
	PopBackOnExit pboe{cp};

	CallInstr const *call = static_cast<CallInstr const*>(cp.back());
	FuncDecl *func_decl = try_get_func_decl(call);

	// No support for function pointers at the moment.
	// TODO We could actually check if `call->func_addr()` is in the PointsToMap.
	if(!func_decl)
		throw std::runtime_error{"Function pointers not supported yet"};

	if(!func_decl->is_defined())
		throw std::runtime_error{"Function not defined: " + func_decl->name()};

	Function *callee = func_decl->function();
	PointsToMap input_pt = create_initial_pt(callee, call->args(), pt_caller);

	auto res = m_call_info.insert({callee, CallInfo{callee}});
	CallInfo &call_info = res.first->second;
	bool newly_inserted = res.second;

	// If we have analyzed this function at this call-path at least once, and
	// merging the new callee PointsToMap has no effect, then we don't need to
	// analyze the function again.
	if(!call_info.input_pt.merge(input_pt) && !newly_inserted)
		return updater_caller_pt(pt_caller, call, callee, call_info.output_pt);

	call_info.output_pt.merge(pointer_analysis(cp, callee, call_info.input_pt, this));
	call_info.num_times_analysed++;

	return updater_caller_pt(pt_caller, call, callee, call_info.output_pt);
}

}
