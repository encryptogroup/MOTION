#include "reaching_definitions.h"

#include "function.h"
#include "pointer_analysis.h"


namespace ir {

void print(RDDependency const &dep, InstrNameMap &names, std::ostream &os)
{
	os << dep.variable->name() << "[" << dep.dep_region.first << ":" << dep.dep_region.last << "] (defined by '";
	dep.defined_at->print_inline(os, names);
	os << "')";
}

namespace
{
	// Merges the elements of of the sorted sequence `src` into into the sorted sequence `dest`.
	// Elements that already exist in `dest` are ignored. Returns true iff at least one element has
	// been added to `dest`.
	template<typename Range>
	bool merge_into(Range &dest, Range const &src)
	{
		bool changed = false;

		auto dest_it = dest.begin();
		auto src_it = src.begin();
		while(dest_it != dest.end() && src_it != src.end())
		{
			if(*src_it < *dest_it)
			{
				dest_it = dest.insert(dest_it, *src_it);
				changed = true;
				++src_it;
				++dest_it;
			}
			else if(*src_it == *dest_it)
			{
				++src_it;
				++dest_it;
			}
			else
				++dest_it;
		}

		if(src_it != src.end())
			changed = true;
		
		dest.insert(dest.end(), src_it, src.end());

		return changed;
	}


	enum class DefMode
	{
		kill,
		no_kill,
	};


	// During the analysis, an RDBlockState stores the state for a single basic block.
	class RDBlockState
	{
	public:
		// A RDBlockState only modifies the entries of those LoadInstrs that occur in its BasicBlock
		explicit RDBlockState(ReachingDefinitions *rd) :
			m_load_deps{rd} {}

		bool add_definition(RDDefinition const &def, DefMode kind)
		{
			if(kind == DefMode::kill)
				return add_killing_definition(def);

			return merge_into(m_defs[def.variable], {def});
		}

		// `deps` must be sorted
		bool add_load_deps(LoadInstr const *load, std::vector<RDDependency> const &deps)
		{
			return merge_into((*m_load_deps)[load], deps);
		}

		std::vector<RDDefinition> const& get_defs(Decl *decl) const
		{
			static std::vector<RDDefinition> empty;

			auto it = m_defs.find(decl);
			if(it != m_defs.end())
				return it->second;

			return empty;
		}

		bool merge(RDBlockState const &other)
		{
			bool changed = false;
			for(auto const &pair: other.m_defs)
				changed |= merge_into(m_defs[pair.first], pair.second);

			return changed;
		}

		void print_defs(std::ostream &os, InstrNameMap &names) const
		{
			for(auto const &pair: m_defs)
			{
				for(RDDefinition const &def: pair.second)
				{
					os << pair.first->name() << "[" << def.region.first << ":" << def.region.last << "] defined by '";
					def.defined_at->print_inline(os, names);
					os << "'\n";
				}
			}
		}

		DeclDefMap& defs() { return m_defs; }
		void set_defs(DeclDefMap const &defs) { m_defs = defs; }

	private:
		std::unordered_map<Decl*, std::vector<RDDefinition>> m_defs;
		ReachingDefinitions *m_load_deps;

		bool add_killing_definition(RDDefinition const &killing_def)
		{
			Region killing_region = killing_def.region;
			std::vector<RDDefinition> &defs = m_defs[killing_def.variable];

			std::vector<RDDefinition> new_defs = {killing_def};
			bool changed = false;
			auto it = defs.begin();
			while(it != defs.end())
			{
				RDDefinition &cur_def = *it;
				assert(cur_def.variable == killing_def.variable);

				if(contains(killing_region, cur_def.region))
				{
					it = defs.erase(it);
					changed = true;
					continue;
				}

				if(contains(cur_def.region, killing_region))
				{
					new_defs.push_back(
						RDDefinition{
							cur_def.variable,
							Region{cur_def.region.first, killing_region.first - 1},
							cur_def.defined_at,
							cur_def.defined_in
						}
					);
					cur_def.region.first = killing_region.last + 1;
					changed = true;
				}
				else if(overlap(killing_region, cur_def.region))
				{
					if(cur_def.region.first < killing_region.first)
						cur_def.region.last = killing_region.first - 1;
					else
					{
						assert(cur_def.region.last > killing_region.last);
						cur_def.region.first = killing_region.last + 1;
					}

					changed = true;
				}

				++it;
			}

			std::sort(new_defs.begin(), new_defs.end());
			changed |= merge_into(defs, new_defs);

			remove_empty_defs(defs);

			return changed;
		}

		void remove_empty_defs(std::vector<RDDefinition> &defs)
		{
			auto new_end = std::remove_if(defs.begin(), defs.end(), [](RDDefinition const &def)
			{
				return empty(def.region);
			});
			defs.erase(new_end, defs.end());
		}
	};


	Region loc_set_to_region(LinearLocationSet locs, ptrdiff_t element_width, ptrdiff_t total_width)
	{
		if(locs.stride() == 0)
			return Region{locs.offset(), locs.offset() + element_width - 1};

		// TODO We need a more precise way to handle array accesses both in the reaching definition
		//      analysis and the pointer analysis. Currently, the pointer analysis assumes that an
		//      indexed write to an array may touch anything in a surrounding struct, which is only
		//      required if we want to support C programs that rely on undefined behavior.

		// Conservatively assume the whole object is affected
		return Region{0, total_width};
	}

	std::pair<RDDefinition, DefMode> create_definition(
		PointsToMap::Entry const &dest,
		StoreInstr const *store_instr,
		CallPath const &cp,
		boolbv_widtht const &boolbv_width)
	{
		Decl *dest_object = dest.target_obj;
		LinearLocationSet dest_locs = dest.target_locs;

		ptrdiff_t store_width = boolbv_width(store_instr->op_at(1)->type()) / config.ansi_c.char_width;
		ptrdiff_t total_width = boolbv_width(dest_object->type()) / config.ansi_c.char_width;
		Region reg = loc_set_to_region(dest_locs, store_width, total_width);
		if(dest_locs.stride() == 0)
			return {RDDefinition{dest_object, reg, store_instr, cp}, DefMode::kill};
		else
		{
			// If `dest_locs` has a stride that the computed region is an
			// over-approximation (see implementation of `loc_set_to_region()`), thus we
			// must not kill previous writes to this region.
			return {RDDefinition{dest_object, reg, store_instr, cp}, DefMode::no_kill};
		}
	}

	bool reaching_definitions(
		CallPath &cp,
		RDBlockState &state,
		BasicBlock const *block,
		RDCallAnalyzer *rd_ca)
	{
		bool changed = false;
		for(Instr const &instr: block->instructions())
		{
			if(instr.kind() == InstrKind::store)
			{
				StoreInstr const *store = static_cast<StoreInstr const*>(&instr);
				std::vector<PointsToMap::Entry> dests = rd_ca->pa()->result_for(cp).get_addresses(instr.op_at(0));
				// If the store target points to a single object then we can kill previous writes to
				// the same region. Otherwise, we need to keep old writes (i.e., no killing)
				if(dests.size() == 1)
				{
					// Even if we know exactly which object we are writing to, we still should avoid
					// killing previous writes *if* the region we are defining is an
					// over-approximation.
					std::pair<RDDefinition, DefMode> def = create_definition(dests[0], store, cp, rd_ca->boolbv_width());
					changed |= state.add_definition(def.first, def.second);
				}
				else
				{
					for(auto const &dest: dests)
						changed |= state.add_definition(create_definition(dest, store, cp, rd_ca->boolbv_width()).first, DefMode::no_kill);
				}
			}
			else if(instr.kind() == InstrKind::load)
			{
				LoadInstr const *load = static_cast<LoadInstr const*>(&instr);
				std::vector<PointsToMap::Entry> srcs = rd_ca->pa()->result_for(cp).get_addresses(instr.op_at(0));
				ptrdiff_t load_width = rd_ca->boolbv_width()(instr.type()) / config.ansi_c.char_width;
				std::vector<RDDependency> deps;
				for(auto const &src: srcs)
				{
					Decl *src_object = src.target_obj;
					LinearLocationSet src_locs = src.target_locs;
					ptrdiff_t total_width = rd_ca->boolbv_width()(src_object->type()) / config.ansi_c.char_width;
					Region reg = loc_set_to_region(src_locs, load_width, total_width);

					for(RDDefinition const &def: state.get_defs(src_object))
					{
						if(overlap(reg, def.region))
						{
							deps.push_back(RDDependency{
								src_object,
								def.defined_at,
								def.defined_in,
								intersection(reg, def.region)
							});
						}
					}
				}

				std::sort(deps.begin(), deps.end());
				changed |= state.add_load_deps(load, deps);
			}
			else if(instr.kind() == InstrKind::call)
			{
				CallInstr const *call = static_cast<CallInstr const*>(&instr);
				cp.push_back(call);
				changed |= rd_ca->analyze_call(cp, state.defs());
			}
		}

		return changed;
	}
}


//==================================================================================================
bool merge(DeclDefMap &dest, DeclDefMap const &src)
{
	bool changed = false;
	for(auto &pair: src)
		changed |= merge_into(dest[pair.first], pair.second);

	return changed;
}

bool merge(ReachingDefinitions &dest, ReachingDefinitions const &src)
{
	bool changed = false;
	for(auto &pair: src)
		changed |= merge_into(dest[pair.first], pair.second);

	return changed;
}

ReachingDefinitions reaching_definitions(
	CallPath &cp,
	Function const *func,
	DeclDefMap const &defs_init,
	RDCallAnalyzer *rd_ca,
	DeclDefMap *defs_exit)
{
	ReachingDefinitions rd;
	auto num_bbs = func->basic_blocks().size();
	std::vector<RDBlockState> bb_states(num_bbs, RDBlockState{&rd});

	bb_states[func->start_block()->id()].set_defs(defs_init);

	BBWorkList work_list = create_work_list_rpo(func);
	for(auto const &bb: func->basic_blocks())
		work_list.insert(bb.get());

	while(work_list.size())
	{
		BasicBlock const *bb = *work_list.begin(); work_list.erase(work_list.begin());
		RDBlockState &state = bb_states[bb->id()];
		bool changed = false;

		for(BlockEdge const &pred: bb->fanins())
			changed |= state.merge(bb_states[pred.target()->id()]);

		changed |= reaching_definitions(cp, state, bb, rd_ca);
		if(changed)
		{
			for(BlockEdge const &succ: bb->fanouts())
				work_list.insert(succ.target());
		}
	}

	if(defs_exit)
		*defs_exit = bb_states[func->exit_block()->id()].defs();

	return rd;
}


//==================================================================================================
bool updater_caller_defs(DeclDefMap &defs_caller, CallInstr const *call, DeclDefMap const &defs_callee)
{
	bool changed = false;

	// The callee may have changed variables of the caller via pointers passed as arguments.
	// Thus, we merge any information about the caller's variables from the callees
	// PointsToMap to the caller's PointsToMap.
	// TODO The same goes for global variables.
	Function const *caller = call->block()->function();
	std::string caller_var_prefix = caller->name() + "::";
	for(auto const &pair: defs_callee)
	{
		Decl *decl = pair.first;
		if(starts_with(cstring_ref{decl->name()}, caller_var_prefix.c_str()))
		{
			changed |= (defs_caller[decl] != pair.second);
			defs_caller[decl] = pair.second;
		}
	}

	return changed;
}


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

bool RDContextSensitiveCallAnalyzer::analyze_call(CallPath &cp, DeclDefMap &defs_caller)
{
	assert(cp.size());

	// After we have analyzed the current function call we remove it from the
	// CallPath.
	PopBackOnExit pboe{cp};

	CallInstr const *call = cp.back();
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
	if(!merge(call_info.defs_input, defs_caller) && !newly_inserted)
		return updater_caller_defs(defs_caller, call, call_info.defs_output);



	call_info.rd_output = reaching_definitions(
		cp,
		callee,
		call_info.defs_input,
		this,
		&call_info.defs_output);

	return updater_caller_defs(defs_caller, call, call_info.defs_output);
}

}
