#include <catch/catch.hpp>

#include <cbmc/src/util/cmdline.h>

#include <cbmc-gc/goto_conversion_invocation.h>
#include <cbmc-gc/ir/pointer_analysis.h>
#include <cbmc-gc/cbmc_to_ir.h>
#include <cbmc-gc/simple_lexer.h>


using namespace ir;

//==================================================================================================
namespace {

// TODO Remove AbstractAddress and LocationSet (they are not used by the pointer analysis anymore)
//      and directly use PointsToMap::Entry instead.

using LocationSet = std::set<LinearLocationSet>;

inline std::ostream& operator << (std::ostream &os, LocationSet const &loc_set)
{
	os << '{';
	if(loc_set.size())
	{
		auto it = loc_set.begin();
		os << *it;
		while(++it != loc_set.end())
			os << ',' << *it;
	}
	os << '}';

	return os;
}

// The widening operator computes the superset of all LinearLocationSets contained in the range
// denoted by [`begin`, `end`).
template<typename Iterator>
LinearLocationSet widening(Iterator begin, Iterator end)
{
	assert(begin != end);

	LinearLocationSet combined = *begin;
	while(++begin != end)
		combined = combine(combined, *begin);

	return combined;
}


std::ostream& operator << (std::ostream &os, class AbstractAddress const &addr);

class AbstractAddress
{
public:
	// Constructs an unknown abstract address.
	AbstractAddress() = default;

	explicit AbstractAddress(Decl *object) :
		m_objects{{object, {LinearLocationSet{}}}} {}

	AbstractAddress(Decl *object, LinearLocationSet const &locs) :
		m_objects{{object, {locs}}} {}

	AbstractAddress(Decl *object, LocationSet const &locs) :
		m_objects{{object, locs}}
	{
		assert(locs.size());
	}

	bool is_unknown() const { return m_objects.empty(); }

	std::unordered_map<Decl*, LocationSet> const& objects() const
	{
		assert(!is_unknown());
		return m_objects;
	}

	bool merge(AbstractAddress const &other)
	{
		if(other.is_unknown())
		{
			bool changed = !m_objects.empty();
			m_objects.clear();
			return changed;
		}

		if(is_unknown())
			return false;

		bool changed = false;
		for(auto const &pair: other.m_objects)
		{
			for(LinearLocationSet l: pair.second)
				changed |= merge_location_set(pair.first, l);
		}

		return changed;
	}

	void merge_location_set(LinearLocationSet locs)
	{
		for(auto const &pair: m_objects)
			merge_location_set(pair.first, locs);
	}

	void increase_offsets(LinearLocationSet const &offset)
	{
		for(auto &pair: m_objects)
		{
			LocationSet const &old_set = pair.second;
			LocationSet new_set;
			for(LinearLocationSet loc: old_set)
				new_set.insert(loc + offset);

			pair.second = std::move(new_set);
		}
	}

	void print(std::ostream &os) const
	{
		if(is_unknown())
		{
			os << "UNKNOWN";
			return;
		}

		os << '{';
		bool first = true;
		for(auto const &pair: m_objects)
		{
			if(!first)
				os << ", ";
			first = false;

			os << '(' << pair.first->name() << ": " << pair.second << ')';
		}
		os << '}';
	}


	// We use a friend so we can access m_object directly. This makes things simpler because we
	// don't need to check if either address is unknown, in which case the assert in
	// AbstractAddress::object() would fail.
	friend bool operator == (AbstractAddress const &a, AbstractAddress const &b)
	{
		return a.m_objects == b.m_objects;
	}


private:
	// The LocationSets are never empty
	std::unordered_map<Decl*, LocationSet> m_objects;

	bool merge_location_set(Decl *object, LinearLocationSet locs)
	{
		if(is_unknown())
			return false;

		auto it = m_objects.find(object);
		if(it == m_objects.end())
		{
			m_objects.insert({object, {locs}});
			return true;
		}

		LocationSet &ls = it->second;
		if(ls.size() == WIDENING_THRESHOLD)
		{
			LinearLocationSet combined = widening(ls.begin(), ls.end());
			ls.clear();
			ls.insert(combined);
			return true;
		}

		// Remove all LinearLocationSets that are subsets of `locs`
		auto loc_it = ls.begin();
		while(loc_it != ls.end())
		{
			if(is_subset(locs, *loc_it))
				return false;

			if(is_subset(*loc_it, locs))
				loc_it = ls.erase(loc_it);
			else
				++loc_it;
		}

		ls.insert(locs);
		return true;
	}
};


inline std::ostream& operator << (std::ostream &os, AbstractAddress const &addr)
{
	addr.print(os);
	return os;
}


//==================================================================================================
// TODO Use a lookup table instead of linear search
Decl* find_decl(std::string const &var_name, std::string const &func_name, Scope const *scope)
{
	if(scope->children().size())
	{
		Decl *decl = nullptr;
		for(auto &child: scope->children())
		{
			Decl *d = find_decl(var_name, func_name, child.get());
			if(!decl)
				decl = d;
			else if(d && d != decl)
				throw parsing_error{"Variable '" + var_name + "' is ambiguous"};
		}

		return decl;
	}

	Decl *decl = nullptr;
	for(auto const &pair: scope->symbols())
	{
		Decl *sym = pair.second.get();
		variable_infot var_info = extract_variable_info(sym->name());
		if(cstring_ref{func_name} == var_info.func_name && cstring_ref{var_name} == var_info.unqualified_name)
		{
			if(decl && decl != sym)
				throw parsing_error{"Variable '" + var_name + "' is ambiguous"};

			decl = sym;
		}
	}

	return decl;
}

Decl* get_decl(std::string var_name, std::string const &func_name, SymbolTable const &symbols)
{
	if(var_name == "NULL")
		return NullObject;

	Decl *decl = find_decl(var_name, func_name, symbols.root_scope());
	if(!decl)
		throw parsing_error{"Variable '" + var_name + "' not found in symbol table"};

	return decl;
}

cstring_ref tok_read_integer(lex_statet &lexer)
{
	skip_whitespaces(lexer);
	return read_integer(lexer);
}

LinearLocationSet parse_linear_location_set(lex_statet &lexer)
{
	accept_skip_ws(lexer, "<");
	cstring_ref offset = tok_read_integer(lexer);
	accept_skip_ws(lexer, ",");
	cstring_ref stride = tok_read_integer(lexer);
	accept_skip_ws(lexer, ">");

	return LinearLocationSet{atoi(offset.b), atoi(stride.b)};
}

LocationSet parse_location_set(lex_statet &lexer)
{
	accept_skip_ws(lexer, "[");
	
	LocationSet loc_set;
	bool closed = false;
	while(lexer)
	{
		if(match_skip_ws(lexer, "]"))
		{
			closed = true;
			break;
		}

		loc_set.insert(parse_linear_location_set(lexer));
		if(!match_skip_ws(lexer, ","))
		{
			accept_skip_ws(lexer, "]");
			closed = true;
			break;
		}
	}

	if(!closed)
	{
		throw parsing_error{
			"Unexpected end of file, expected ']' in line " + std::to_string(lexer.line())
		};
	}

	if(loc_set.empty())
	{
		throw parsing_error{
			"Location set must not be empty in line " + std::to_string(lexer.line())
		};
	}

	return loc_set;
}

AbstractAddress parse_abstract_address(
	lex_statet &lexer,
	std::string const &func_name,
	SymbolTable const &symbols)
{
	if(!lexer)
	{
		throw parsing_error{
			"Unexpected end of file, expected an abstract address in line " + std::to_string(lexer.line())
		};
	}

	if(match_skip_ws(lexer, "?"))
		return {};

	if(match_skip_ws(lexer, "{"))
	{
		AbstractAddress addr;
		bool first_merge = true;
		while(lexer)
		{
			if(match_skip_ws(lexer, "}"))
				return addr;

			if(first_merge)
			{
				addr = parse_abstract_address(lexer, func_name, symbols);
				first_merge = false;
			}
			else
				addr.merge(parse_abstract_address(lexer, func_name, symbols));

			if(!match_skip_ws(lexer, ","))
			{
				accept_skip_ws(lexer, "}");
				return addr;
			}
		}

		throw parsing_error{
			"Unexpected end of file, expected '}' in line " + std::to_string(lexer.line())
		};
	}

    cstring_ref identifier;
    if(lexer && lexer.get() == '"')
      identifier = read_string_skip_ws(lexer);
    else
      identifier = read_identifier_skip_ws(lexer);

	Decl *object = get_decl(str(identifier), func_name, symbols);
	LocationSet loc_set;

	skip_whitespaces(lexer);
	if(lexer && lexer.get() == '<')
		loc_set.insert(parse_linear_location_set(lexer));
	else if(lexer && lexer.get() == '[')
		loc_set = parse_location_set(lexer);
	else
		loc_set.insert(LinearLocationSet{0, 0});

	return AbstractAddress(object, loc_set);
}

PointsToMap parse_result_spec(
	lex_statet &lexer,
	std::string const &func_name,
	SymbolTable const &symbols)
{
	PointsToMap pt;
	while(true)
	{
		skip_whitespaces(lexer);
		if(!lexer)
			break;

		AbstractAddress addr = parse_abstract_address(lexer, func_name, symbols);
		accept_skip_ws(lexer, "=>");
		AbstractAddress target = parse_abstract_address(lexer, func_name, symbols);

		for(auto const &src_pair: addr.objects())
		{
			Decl *src_object = src_pair.first;
			for(LinearLocationSet src_locs: src_pair.second)
			{
				if(target.is_unknown())
					pt.merge_address(src_object, src_locs, UnknownObject, NoOffset());
				else
				{
					for(auto const &target_pair: target.objects())
					{
						Decl *target_object = target_pair.first;
						for(LinearLocationSet target_locs: target_pair.second)
							pt.merge_address(src_object, src_locs, target_object, target_locs);
					}
				}
			}
		}
	}

	return pt;
}

PointsToMap parse_result_spec(
	std::string const &filename,
	std::string const &func_name,
	SymbolTable const &symbols)
{
	std::fstream file{filename};
	if(!file.is_open())
		throw std::runtime_error{"Opening file failed: " + filename};

	std::string contents{std::istreambuf_iterator<char>{file}, std::istreambuf_iterator<char>{}};

	lex_statet lexer{contents};
	return parse_result_spec(lexer, func_name, symbols);
}

}


//==================================================================================================
namespace ir {

// This overload must be put into the ir namespace so Catch is able to find it.
std::ostream& operator << (
	std::ostream &os,
	std::unordered_map<Decl*, std::vector<PointsToMap::Entry>> const &objects)
{
	for(auto const &pair: objects)
	{
		Decl const *object = pair.first;
		std::vector<PointsToMap::Entry> const &entries = pair.second;
		for(PointsToMap::Entry const &entry: entries)
			os << object->name() << entry.source_locs << " => " << entry.target_obj->name() << ":" << entry.target_locs << std::endl;
	}

	return os;
}

}


namespace {

goto_modulet compile_file(std::string const &filename)
{
	cmdlinet args;
	args.args.push_back(filename);

	ui_message_handlert msg_handler{args, "test"};
	msg_handler.set_verbosity(messaget::M_ERROR);

	return invoke_goto_compilation(args, msg_handler);
}

class Module
{
public:
	explicit Module(std::string const &filename) :
		m_cbmc_module{compile_file(filename)},
		m_ns{m_cbmc_module.original_symbols()} {}

	void compile_all()
	{
		// We will first add all functions to the symbol table before we are compiling them to ensure
		// that function calls can find the target function.
		for(auto const &pair: m_cbmc_module.original_symbols())
		{
			symbolt const &sym = pair.second;
			if(sym.is_function())
			{
				if(starts_with(cstring_ref(sym.name.c_str()), "__CPROVER"))
					continue;

				if(!m_symbols.root_scope()->try_lookup(sym.name.c_str()))
					m_symbols.root_scope()->declare_func(sym.name.c_str(), sym.type);
			}
		}

		for(auto const &pair: m_symbols.root_scope()->symbols())
		{
			ir::Decl *decl = pair.second.get();
			if(decl->kind() == ir::DeclKind::function)
			{
				auto ir_func = convert_to_ir(
					m_symbols,
					m_ns,
					m_cbmc_module.goto_functions().function_map.at(decl->name()));

				static_cast<ir::FuncDecl*>(decl)->set_function(std::move(ir_func));
			}
		}
	}

	Function* get_func(std::string const &name)
	{
		return m_symbols.root_scope()->lookup_func(name)->function();
	}

	Function* get_main_func()
	{
		return get_func(m_cbmc_module.main_function_name());
	}

	namespacet const& ns() const { return m_ns; }

	SymbolTable const& symbols() const { return m_symbols; }

private:
	SymbolTable m_symbols;
	goto_modulet m_cbmc_module;
	namespacet m_ns;
};

std::string replace_extension(std::string filename, std::string const &new_extension)
{
	size_t last_dot = filename.rfind('.');
	if(last_dot == std::string::npos)
		throw std::runtime_error{"Filename has no extension: " + filename};

	return filename.replace(last_dot + 1, std::string::npos, new_extension);
}

void run_pointer_analysis(std::string const &filename)
{
	std::cout << "Running pointer analysis on " << filename << std::endl;

	Module module{filename};
	module.compile_all();
	Function *func = module.get_main_func();

	boolbv_widtht boolbv_width{module.ns()};
	PAContextSensitiveCallAnalyzer ca{boolbv_width};
	CallPath cp;
	PointsToMap actual_pt = pointer_analysis(cp, func, {}, &ca);

	PointsToMap reference_pt = parse_result_spec(
		replace_extension(filename, "result"),
		func->name(),
		module.symbols());

	CHECK(actual_pt.objects() == reference_pt.objects());
}

}


//==================================================================================================
TEST_CASE("PointerAnalysis: LinearLocationSet")
{
	SECTION("is_subset")
	{
		CHECK(is_subset(LinearLocationSet{0, 0}, LinearLocationSet{0, 0}));
		CHECK(is_subset(LinearLocationSet{0, 0}, LinearLocationSet{0, 4}));
		CHECK(is_subset(LinearLocationSet{3, 0}, LinearLocationSet{7, 4}));
		CHECK(is_subset(LinearLocationSet{8, 10}, LinearLocationSet{3, 5}));
		CHECK(is_subset(LinearLocationSet{8, -10}, LinearLocationSet{3, 5}));
		CHECK(is_subset(LinearLocationSet{8, 10}, LinearLocationSet{3, -5}));
		CHECK(is_subset(LinearLocationSet{8, -10}, LinearLocationSet{3, -5}));

		CHECK(!is_subset(LinearLocationSet{0, 4}, LinearLocationSet{0, 0}));
		CHECK(!is_subset(LinearLocationSet{7, 4}, LinearLocationSet{3, 0}));
	}

	SECTION("overlap")
	{
		CHECK(overlap(LinearLocationSet{0, 0}, LinearLocationSet{0, 0}));
		CHECK(overlap(LinearLocationSet{4, 0}, LinearLocationSet{0, 4}));
		CHECK(overlap(LinearLocationSet{1, 2}, LinearLocationSet{2, 3}));
		CHECK(overlap(LinearLocationSet{0, 10}, LinearLocationSet{2, 3}));

		CHECK(!overlap(LinearLocationSet{2, 0}, LinearLocationSet{0, 0}));
		CHECK(!overlap(LinearLocationSet{2, 0}, LinearLocationSet{4, 0}));
		CHECK(!overlap(LinearLocationSet{1, 0}, LinearLocationSet{4, 0}));
		CHECK(!overlap(LinearLocationSet{1, 2}, LinearLocationSet{0, 2}));
	}

	SECTION("overlap_range")
	{
		CHECK(overlap_range(LinearLocationSet{0, 0}, LinearLocationSet{0, 0}, 4));
		CHECK(overlap_range(LinearLocationSet{1, 3}, LinearLocationSet{0, 3}, 2));
		CHECK(overlap_range(LinearLocationSet{1, 5}, LinearLocationSet{0, 3}, 2));
		CHECK(overlap_range(LinearLocationSet{1, 2}, LinearLocationSet{2, 3}, 1));

		CHECK(!overlap_range(LinearLocationSet{2, 3}, LinearLocationSet{0, 3}, 2));
	}
}

TEST_CASE("PointerAnalysis: Test cases")
{
	register_languages();

	run_pointer_analysis("pointer_analysis/simple_loop.c");
	run_pointer_analysis("pointer_analysis/simple_deref_update.c");
	run_pointer_analysis("pointer_analysis/widening.c");
	run_pointer_analysis("pointer_analysis/widening_2.c");
	run_pointer_analysis("pointer_analysis/struct.c");
	run_pointer_analysis("pointer_analysis/array_struct_field_sensitive.c");
	run_pointer_analysis("pointer_analysis/function_call.c");
	run_pointer_analysis("pointer_analysis/transitive_calls.c");
	run_pointer_analysis("pointer_analysis/list.c");
	run_pointer_analysis("pointer_analysis/struct_copy.c");
}
