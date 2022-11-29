#pragma once

#include <libcircuit/utils.h>

#include "solvers/flattening/boolbv_width.h"
#include "util/config.h"

#include "function.h"
#include "ir.h"
#include "symbol_table.h"
#include "call_path.h"


// References
// ----------
//
// [1] Efficient Context-Sensitive Pointer Analysis for C Programs.
//

// An *object* denotes a region of memory. For example, if `x` is a variable of type `int32_t`, then
// `x` refers to an object that is stored at a specific location in memory and contains 4 bytes.

// TODO Handle recursion


class boolbv_widtht;

namespace ir {

//================================================================================================
template<typename T>
T gcd(T a, T b)
{
	while (b != 0)
	{
		T r = a % b;
		a = b;
		b = r;
	}

	return a;
}


//================================================================================================
// A LinearLocationSet contains a set of locations relative to an object given by an offset and a
// stride. Both offset and stride are specified in bytes.
// See [1]2.1.
class LinearLocationSet
{
public:
	explicit LinearLocationSet(ptrdiff_t offset = 0, ptrdiff_t stride = 0) :
		m_offset{offset},
		m_stride{stride}
	{
		normalize();
	}

	ptrdiff_t offset() const { return m_offset; }
	ptrdiff_t stride() const { return m_stride; }

	void set_offset(ptrdiff_t offset)
	{
		m_offset = offset;
		normalize();
	}

	void set_stride(ptrdiff_t stride)
	{
		m_stride = stride;
		normalize();
	}

	friend bool operator == (LinearLocationSet const &a, LinearLocationSet const &b)
	{
		return a.offset() == b.offset() && a.stride() == b.stride();
	}

	friend bool operator < (LinearLocationSet const &a, LinearLocationSet const &b)
	{
		return std::tie(a.m_offset, a.m_stride) < std::tie(b.m_offset, b.m_stride);
	}

private:
	ptrdiff_t m_offset;
	ptrdiff_t m_stride;

private:
	void normalize()
	{
		// Normalize location set to simplify tests for equality. See [1]2.1.3
		if(m_stride != 0)
			m_offset = m_offset - m_stride * (m_offset / m_stride);
	}
};

inline LinearLocationSet NoOffset()
{
	return LinearLocationSet{};
}

inline std::ostream& operator << (std::ostream &os, LinearLocationSet const &loc)
{
	return os << '<' << loc.offset() << ',' << loc.stride() << '>';
}

inline LinearLocationSet operator + (LinearLocationSet const &a, LinearLocationSet const &b)
{
	return LinearLocationSet{a.offset() + b.offset(), gcd(a.stride(), b.stride())};
}

inline LinearLocationSet operator - (LinearLocationSet const &a, LinearLocationSet const &b)
{
	return LinearLocationSet{a.offset() - b.offset(), gcd(a.stride(), b.stride())};
}

inline LinearLocationSet operator - (LinearLocationSet const &a)
{
	return LinearLocationSet{-a.offset(), a.stride()};
}

// Computes the union of two location sets. See [1]2.1.3
inline LinearLocationSet combine(LinearLocationSet const &a, LinearLocationSet const &b)
{
	return LinearLocationSet{
		a.offset(),
		gcd(gcd(a.stride(), b.stride()), std::abs(a.offset() - b.offset()))
	};
}

inline bool is_subset(LinearLocationSet const &a, LinearLocationSet const &b)
{
	if(gcd(a.stride(), b.stride()) != b.stride())
		return false;

	if(b.stride() == 0)
		return b.offset() == a.offset();

	return (b.offset() - a.offset()) % b.stride() == 0;
}

// Returns true if there exist a location `l1` in `start` and `l2` in `loc` such that `l2` is in the
// half-open interval `[l1, l1 + width)`
inline bool overlap_range(LinearLocationSet const &loc, LinearLocationSet const &start, ptrdiff_t width)
{
	// See https://math.stackexchange.com/questions/2218763/how-to-find-lcm-of-two-numbers-when-one-starts-with-an-offset
	auto d = std::abs(start.offset() - loc.offset());

	if(start.stride() == 0 && loc.stride() == 0)
		return d < width;
	if(start.stride() == 0)
		return d % loc.stride() < width;
	if(loc.stride() == 0)
		return d % start.stride() < width;

	return d % gcd(start.stride(), loc.stride()) < width;
}

// Returns true iff both LinearLocationSets have at least one location in common.
inline bool overlap(LinearLocationSet const &a, LinearLocationSet const &b)
{
	return overlap_range(a, b, 1);
}


class OffsetCalculater
{
public:
	explicit OffsetCalculater(boolbv_widtht const *boolbv_width) :
		m_boolbv_width{boolbv_width} {}

	void add_offset(typet const &type, Instr const *count_instr)
	{
		if(count_instr->kind() == InstrKind::constant)
		{
			ptrdiff_t count = static_cast<Constant const*>(count_instr)->value().to_long();
			add_offset(type, count);
		}
		else
		{
			ptrdiff_t element_size = (*m_boolbv_width)(type) / config.ansi_c.char_width;
			m_loc_set.set_stride(element_size);
		}
	}

	void add_offset(typet const &type, ptrdiff_t count)
	{
		ptrdiff_t element_size = (*m_boolbv_width)(type) / config.ansi_c.char_width;
		m_loc_set.set_offset(m_loc_set.offset() + element_size * count);
	}

	LinearLocationSet location_set() const { return m_loc_set; }

private:
	LinearLocationSet m_loc_set;
	boolbv_widtht const *m_boolbv_width;
};

}


namespace std {

template<>
struct hash<::ir::LinearLocationSet>
{
	size_t operator () (::ir::LinearLocationSet const &v) const
	{
		size_t seed = 0;
		::hash_combine(seed, v.offset());
		::hash_combine(seed, v.stride());

		return seed;
	}
};

}


namespace ir {

//==================================================================================================

// Number of LinearLocationSet per object (Decl) before we apply the widening operation
constexpr int WIDENING_THRESHOLD = 10;

extern Decl * const NullObject;
extern Decl * const UnknownObject;

class PointsToMap
{
public:
	struct Entry
	{
		LinearLocationSet source_locs;
		Decl *target_obj;
		LinearLocationSet target_locs;

		friend bool operator == (Entry const &a, Entry const &b)
		{
			return a.source_locs == b.source_locs && a.target_obj == b.target_obj && a.target_locs == b.target_locs;
		}
	};

	bool merge_address(Instr const *instr, LinearLocationSet source_locs, Decl *target)
	{
		return merge_addresses(instr, {{source_locs, target, NoOffset()}});
	}

	bool merge_addresses(Instr const *instr, std::vector<Entry> const &new_entries)
	{
		if(new_entries.empty())
			return false;

		auto it = m_instr_points_to.find(instr);
		if(it == m_instr_points_to.end())
			it = m_instr_points_to.emplace(instr, std::vector<Entry>{}).first;

		auto &entries = it->second;
		size_t original_size = entries.size();
		entries.insert(entries.end(), new_entries.begin(), new_entries.end());
		return merge_entries(entries, original_size);
	}

	// Returns all pointer values stored in the instruction
	std::vector<Entry> const& get_addresses(Instr const *instr) const
	{
		static std::vector<Entry> unknown{{NoOffset(), UnknownObject, NoOffset()}};

		auto it = m_instr_points_to.find(instr);
		if(it == m_instr_points_to.end())
			return unknown;

		assert(it->second.size());
		return it->second;
	}

	// Returns all Entries that are stored in `object` in the  location range [`start_locs`, `end_locs`].
	std::vector<Entry> get_addresses(Decl *object, LinearLocationSet start_locs, ptrdiff_t width)
	{
		auto it = m_obj_points_to.find(object);
		if(it == m_obj_points_to.end())
			return {{start_locs, UnknownObject, NoOffset()}};

		std::vector<Entry> result;
		std::vector<Entry> const &entries = it->second;
		for(auto &entry: entries)
		{
			if(overlap_range(entry.source_locs, start_locs, width))
				result.push_back(entry);
		}

		if(result.empty())
			return {{start_locs, UnknownObject, NoOffset()}};

		return result;
	}

	// Returns all Entries that are stored in `object` at location `locs`.
	std::vector<Entry> get_addresses(Decl *object, LinearLocationSet locs)
	{
		return get_addresses(object, locs, 1);
	}

	bool merge_addresses(Decl *object, std::vector<Entry> const &new_entries)
	{
		if(new_entries.empty())
			return false;

		auto entries_it = m_obj_points_to.find(object);
		if(entries_it == m_obj_points_to.end())
			entries_it = m_obj_points_to.insert({object, {}}).first;

		std::vector<Entry> &entries = entries_it->second;
		size_t original_entry_count = entries.size();
		entries.insert(entries.end(), new_entries.begin(), new_entries.end());
		assert(entries.size());

		return merge_entries(entries, original_entry_count);
	}

	bool merge_address(Decl *object, LinearLocationSet source_locs, Decl *target, LinearLocationSet target_locs)
	{
		return merge_addresses(object, {{source_locs, target, target_locs}});
	}


	std::unordered_map<Decl*, std::vector<Entry>> const& objects() const { return m_obj_points_to; }


	bool merge(PointsToMap const &other)
	{
		bool changed = false;
		for(auto const &pair: other.m_instr_points_to)
			changed |= merge_addresses(pair.first, pair.second);

		for(auto const &pair: other.m_obj_points_to)
		{
			auto entries_it = m_obj_points_to.find(pair.first);
			if(entries_it == m_obj_points_to.end())
				entries_it = m_obj_points_to.insert({pair.first, {}}).first;

			std::vector<Entry> &entries = entries_it->second;
			size_t original_entry_count = entries.size();
			entries.insert(entries.end(), pair.second.begin(), pair.second.end());

			changed |= merge_entries(entries, original_entry_count);
		}

		return changed;
	}

	void print(std::ostream &os) const
	{
		for(auto const &pair: m_obj_points_to)
		{
			Decl *object = pair.first;
			for(Entry const &entry: pair.second)
			{
				os << '(' << object->name() << ',' << entry.source_locs << ") -> "
				   << entry.target_obj->name() << ":" << entry.target_locs << std::endl;
			}
		}
	}


	friend bool operator == (PointsToMap const &a, PointsToMap const &b)
	{
		return a.m_instr_points_to == b.m_instr_points_to && a.m_obj_points_to == b.m_obj_points_to;
	}

	friend bool operator != (PointsToMap const &a, PointsToMap const &b)
	{
		return !(a == b);
	}

private:
	std::unordered_map<Instr const*, std::vector<Entry>> m_instr_points_to;
	std::unordered_map<Decl*, std::vector<Entry>> m_obj_points_to;


	bool merge_entries(std::vector<Entry> &new_entries, size_t original_size)
	{
		assert(new_entries.size());

		sort_entries(new_entries);
		remove_redundant_entries(new_entries);
		handle_unknown(new_entries);
		widening(new_entries);
		assert(new_entries.size());

		return new_entries.size() != original_size;
	}

	// Requires that `new_entries` is sorted by `Entry::target_obj`.
	void widening(std::vector<Entry> &new_entries)
	{
		auto it = new_entries.begin();
		while(it != new_entries.end())
		{
			Decl *object = it->target_obj;
			LinearLocationSet source_combined = it->source_locs;
			LinearLocationSet target_combined = it->target_locs;
			auto start = it;
			while(++it != new_entries.end() && it->target_obj == object)
			{
				source_combined = combine(source_combined, it->source_locs);
				target_combined = combine(target_combined, it->target_locs);
			}

			if(it - start >= WIDENING_THRESHOLD)
			{
				start->source_locs = source_combined;
				start->target_locs = target_combined;
				it = new_entries.erase(start + 1, it);
			}
		}
	}

	// An Entry A is redundant if there exists another Entry B that has the same target object as A
	// and whose source_locs and target_locs are a superset of A's source_locs and target_locs,
	// respectively.
	void remove_redundant_entries(std::vector<Entry> &new_entries)
	{
		// TODO This is O(n^2). Sort entries intelligently to improve this.
		for(size_t cur_idx = 0; cur_idx < new_entries.size(); ++cur_idx)
		{
			Entry &cur_entry = new_entries[cur_idx];
			for(size_t other_idx = 0; other_idx < new_entries.size(); ++other_idx)
			{
				if(cur_idx == other_idx)
					continue;

				Entry &other_entry = new_entries[other_idx];
				if(
					other_entry.target_obj == cur_entry.target_obj &&
					is_subset(other_entry.source_locs, cur_entry.source_locs) &&
					is_subset(other_entry.target_locs, cur_entry.target_locs)
				)
					other_entry.target_obj = nullptr; // mark for deletion
				else
					++other_idx;
			}
		}

		auto it = new_entries.begin();
		while(it != new_entries.end())
		{
			if(!it->target_obj)
				it = new_entries.erase(it);
			else
				++it;
		}
	}

	// If `entries` whose source locations are completely covered by UNKNOWNs are removed
	void handle_unknown(std::vector<Entry> &entries)
	{
		std::vector<LinearLocationSet> unknown_locs;
		for(auto const &e: entries)
		{
			if(e.target_obj == UnknownObject)
				unknown_locs.push_back(e.source_locs);
		}

		auto is_covered_by_unknown = [&](LinearLocationSet loc)
		{
			for(auto uloc: unknown_locs)
			{
				if(is_subset(loc, uloc))
					return true;
			}

			return false;
		};

		auto it = entries.begin();
		while(it != entries.end())
		{
			if(it->target_obj != UnknownObject && is_covered_by_unknown(it->source_locs))
				it = entries.erase(it);
			else
				++it;
		}
	}

	// Sorts `entries` into some arbitrary but stable order so we can compare to vectors of Entries
	// for equality.
	void sort_entries(std::vector<Entry> &entries)
	{
		std::sort(entries.begin(), entries.end(), [](Entry const &a, Entry const &b)
		{
			auto at = std::make_tuple(
				a.target_obj,
				a.source_locs.stride(), a.source_locs.offset(),
				a.target_locs.stride(), a.target_locs.offset()
			);
			auto bt = std::make_tuple(
				b.target_obj,
				b.source_locs.stride(), b.source_locs.offset(),
				b.target_locs.stride(), b.target_locs.offset()
			);
			return at > bt;
		});
	}
};


//==================================================================================================
// By abstracting how to analyze function calls we can implement various
// degrees of context-sensitivity.
class PACallAnalyzer
{
public:
	PACallAnalyzer(boolbv_widtht const &bv) :
		m_boolbv_width{bv} {}

	virtual PointsToMap const& result_for(CallPath const &cp) const = 0;

	// Updates the PointsToMap of the caller, `pt_caller`, such that it contains
	// the points-to information added after executing the function denoted by
	// `cp`. Additionally, the last element of `cp` is removed.
	virtual bool analyze_call(CallPath &cp, PointsToMap &pt_caller) = 0;

	virtual void analyze_entry_point(Function const *main) = 0;

	// TODO This is totally out of place here. Move somewhere else.
	boolbv_widtht const& boolbv_width() const { return m_boolbv_width; }

private:
	boolbv_widtht const &m_boolbv_width;
};


PointsToMap pointer_analysis(
	CallPath &cp,
	Function const *func,
	PointsToMap const &pt_init,
	PACallAnalyzer *ca);


//==================================================================================================
// This is the most context-sensitive analysis I can imagine (though I'm not
// very creative): For each function, we keep separate PointsToMaps for each
// possible call-path. This may result in exponential running time and memory
// usage. However, since most programs we analyze are not that large anyway, we
// may get away with it.
//
// The result of the pointer analysis for a function only depends on the
// aliasing between the arguments to the function. Thus, we may save both time
// and memory without sacrificing precision by merging the analysis results for
// functions that are called with the same aliasing between arguments. This is
// the approach taken in "Efficient context-sensitive pointer analysis for C
// programs" by Robert P. Wilson, 1997.
class PAContextSensitiveCallAnalyzer : public PACallAnalyzer
{
public:
	struct CallInfo
	{
		CallInfo(Function const *callee) :
			callee{callee},
			num_times_analysed{0} {}

		Function const *callee;
		PointsToMap input_pt;
		PointsToMap output_pt;
		int num_times_analysed;
	};

	PAContextSensitiveCallAnalyzer(boolbv_widtht const &bv) :
		PACallAnalyzer{bv} {}

	PointsToMap const& result_for(CallPath const &cp) const override
	{
		auto it = m_call_info.find(cp);
		if(it == m_call_info.end())
			throw std::runtime_error{"No pointer analysis result available for: " + str(cp)};

		return it->second.output_pt;
	}

	bool analyze_call(CallPath &cp, PointsToMap &pt_caller) override;

	void analyze_entry_point(Function const *main) override
	{
		CallPath cp;

		CallInfo ci{main};
		ci.output_pt = pointer_analysis(cp, main, {}, this);
		ci.num_times_analysed = 1;
		m_call_info.insert({{}, ci});
	}

	void print(std::ostream &os) const
	{
		for(auto const &pair: m_call_info)
		{
			CallInfo const &info = pair.second;

			os << "Points-to map for '" << info.callee->name() << "' (" << info.num_times_analysed << " times analyzed)\n";
			info.output_pt.print(os);
			os << std::endl;
		}
	}

private:
	std::unordered_map<CallPath, CallInfo, VectorHash> m_call_info;
};


//==================================================================================================
// Completely context-insensitive analysis. This means we only compute a single
// PointsToMap for each function. Much more efficient and much less precise then
// PAContextSensitiveCallAnalyzer.
class PAContextInsensitiveCallAnalyzer : public PACallAnalyzer
{
public:
	// Stores the analysis results for a single call-site (i.e., CallInstr).
	struct CallInfo
	{
		CallInfo(Function const *callee) :
			callee{callee},
			num_times_analysed{0} {}

		Function const *callee;
		PointsToMap input_pt;
		PointsToMap output_pt;
		int num_times_analysed = 0;
	};

	PAContextInsensitiveCallAnalyzer(boolbv_widtht const &bv) :
		PACallAnalyzer{bv},
		m_main_func{} {}

	PointsToMap const& result_for(CallPath const &cp) const override
	{
		assert(cp.size() || m_main_func);
		
		Function const *func = nullptr;
		if(cp.empty())
			func = m_main_func;
		else
		{
			FuncDecl *func_decl = try_get_func_decl(cp.back());
			if(!func_decl)
				throw std::runtime_error{"Unexpected function pointer"};

			func = func_decl->function();
		}

		auto it = m_call_info.find(func);
		if(it == m_call_info.end())
			throw std::runtime_error{"No analysis result available"};

		return it->second.output_pt;
	}

	bool analyze_call(CallPath &cp, PointsToMap &pt_caller) override;

	void analyze_entry_point(Function const *main) override
	{
		CallPath cp;

		CallInfo ci{main};
		ci.output_pt = pointer_analysis(cp, main, {}, this);
		ci.num_times_analysed = 1;
		m_call_info.insert({{}, ci});
		m_main_func = main;
	}

	void print(std::ostream &os) const
	{
		for(auto const &pair: m_call_info)
		{
			CallInfo const &info = pair.second;

			os << "Points-to map for '" << info.callee->name() << "' (" << info.num_times_analysed << " times analyzed)\n";
			info.output_pt.print(os);
			os << std::endl;
		}
	}

private:
	std::unordered_map<Function const*, CallInfo> m_call_info;
	Function const *m_main_func;
};

}
