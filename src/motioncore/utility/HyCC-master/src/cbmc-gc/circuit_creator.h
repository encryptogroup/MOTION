#ifndef CBMC_GC_CIRCUIT_CREATOR_H
#define CBMC_GC_CIRCUIT_CREATOR_H

#include <libcircuit/utils.h>

#include <solvers/prop/prop.h>
#include <solvers/flattening/boolbv_map.h>
#include <util/arith_tools.h>

#include <ostream>
#include <unordered_set>


//==================================================================================================
class simple_circuitt;
struct mpc_variable_infot;
struct bool_function_callt;

class circuit_creatort : public propt
{
public:
  virtual void enable_scopes() = 0;
  virtual void push_scope(std::string const &name) = 0;
  virtual void pop_scope() = 0;
  virtual void scopes_to_dot(std::ostream &os) = 0;

  virtual void create_circuit(
    std::vector<mpc_variable_infot> const &vars,
    std::vector<bool_function_callt> const &func_calls,
    simple_circuitt &circuit) = 0;
};

struct scoped_scopet
{
  scoped_scopet(circuit_creatort *cc, std::string const &name) :
    cc{cc}
  {
    cc->push_scope(name);
  }

  ~scoped_scopet()
  {
    cc->pop_scope();
  }

  circuit_creatort *cc;
};


// Extracting variable information
//==================================================================================================
struct variable_infot
{
  irep_idt unique_name;
  // Contains the function the variable was declared in.
  cstring_ref func_name;
  // Contains variable name with complete scope information but without SSA index or thread id
  cstring_ref qualified_name;
  // Contains just the variable name
  cstring_ref unqualified_name;
  int ssa_index;
  bool is_argument;
  bool is_return;

  variable_infot() = default;

  variable_infot(variable_infot const &rhs) :
    unique_name{rhs.unique_name},
    ssa_index{rhs.ssa_index},
    is_argument{rhs.is_argument},
    is_return{rhs.is_return}
  {
    update_string_refs(rhs);
  }

  variable_infot& operator = (variable_infot const &rhs)
  {
    unique_name = rhs.unique_name;
    ssa_index = rhs.ssa_index;
    is_argument = rhs.is_argument;
    is_return = rhs.is_return;
    update_string_refs(rhs);

    return *this;
  }

private:
  void update_string_refs(variable_infot const &rhs)
  {
#ifdef USE_DSTRING
    // If irep_idt is a typedef to dstring, then all strings with the same contents point to the
    // exact same memory location.
    func_name = rhs.func_name;
    qualified_name = rhs.qualified_name;
    unqualified_name = rhs.unqualified_name;
#else
    char const *unique_name_begin = unique_name.c_str();
    func_name.b = unique_name_begin + (rhs.func_name.b - rhs.unique_name_begin);
    func_name.e = func_name.b + rhs.func_name.size();

    qualified_name.b = unique_name_begin + (rhs.qualified_name.b - rhs.unique_name_begin);
    qualified_name.e = qualified_name.b + rhs.qualified_name.size();

    unqualified_name.b = unique_name_begin + (rhs.unqualified_name.b - rhs.unique_name_begin);
    unqualified_name.e = unqualified_name.b + rhs.unqualified_name.size();
#endif
  }
};

inline std::ostream& operator << (std::ostream &os, variable_infot const &var)
{
  os << '{' << var.unique_name << ", " << var.func_name << ", " << var.qualified_name
     << ", " << var.unqualified_name << ", ssa_idx=" << var.ssa_index << ", is_arg="
     << var.is_argument << ", is_ret=" << var.is_return << '}';

  return os;
}

inline bool is_valid_func_name_char(char c)
{
  // We need '<', '>' and ',' so we can build a unique name for specialized functions
  return c == '_' || c == '<' || c == '>' || c == ',' || c == '[' || c == ']' || std::isalnum(c);
}

inline variable_infot extract_variable_info(irep_idt const &identifier)
{
  variable_infot info;
  info.unique_name = identifier;
  char const *cur = info.unique_name.c_str();
  char const *end = cur + info.unique_name.size();

  // Extract function name
  info.qualified_name.b = cur;
  info.func_name.b = cur;
  while(cur != end && is_valid_func_name_char(*cur))
    cur++;
  assert(cur != end);
  info.func_name.e = cur;

  // Check if the variable is a function argument
  while(cur != end && *cur == ':')
    ++cur;
  assert(cur != end);
  info.is_argument = *cur == '_' || std::isalpha(*cur);

  // Jump to the end and then search backwards to find the first ':'. This is the beginning of the
  // variable name.
  char const *cur_bkp = cur;
  cur = end - 1;
  while(cur != cur_bkp && *cur != ':')
    --cur;
  if(*cur == ':' || *cur == '#')
    ++cur;

  // Extract variable name
  info.unqualified_name.b = cur;
  while(cur != end && (*cur == '_' || *cur == ',' || *cur == '$' || std::isalnum(*cur)))
    cur++;

  info.qualified_name.e = cur;
  info.unqualified_name.e = cur;

  info.is_return = info.unqualified_name[-1] == '#' && info.unqualified_name == "return_value";

  // Extract SSA index
  auto pos = as_string(info.unique_name).rfind('#');
  info.ssa_index = 0;
  if(pos != std::string::npos)
    info.ssa_index = atoi(info.unique_name.c_str() + pos + 1);

  return info;
}


//==================================================================================================
enum class io_variable_typet
{
  input_a,
  input_b,
  output,
};

struct mpc_variable_infot
{
  variable_infot var;
  
  io_variable_typet io_type;
  boolbv_mapt::literal_mapt literals;
  typet type;
};

inline optional<io_variable_typet> extract_io_type(variable_infot const &var_info, bool treat_args_as_input)
{
  auto unqualified_name = var_info.unqualified_name;
  
  if(starts_with(unqualified_name, "INPUT_"))
  {
    if(unqualified_name.size() < 7)
      throw std::runtime_error{"Input variables must be assigned a party: " + str(unqualified_name)};

    if(unqualified_name[6] == 'A')
      return io_variable_typet::input_a;

    return io_variable_typet::input_b;
  }
  else if(var_info.is_return || starts_with(unqualified_name, "OUTPUT"))
    return io_variable_typet::output;
  else if(starts_with(unqualified_name, "INOUT"))
  {
    if(ends_with(unqualified_name, ",return"))
      return io_variable_typet::output;

    return io_variable_typet::input_a;
  }
  else if(treat_args_as_input && var_info.is_argument)
    return io_variable_typet::input_a;

  return emptyopt;
}

inline std::vector<mpc_variable_infot> get_input_output_variables(
  boolbv_mapt::mappingt const &mapping,
  std::string const &func,
  bool treat_args_as_input = false,
  std::unordered_set<std::string> const &ignore_io_vars = {})
{
  std::vector<mpc_variable_infot> vars;
  for(auto &&pair: mapping)
  {
    if(as_string(pair.first).find("__CPROVER") == 0 || as_string(pair.first).find("return'") == 0)
      continue;

    auto var_info = extract_variable_info(pair.first);
    if(ignore_io_vars.count(str(var_info.qualified_name)))
      continue;

    if(var_info.func_name == func)
    {
      optional<io_variable_typet> io_type = extract_io_type(var_info, treat_args_as_input);
      if(io_type)
        vars.push_back({var_info, *io_type, pair.second.literal_map, pair.second.type});
    }
  }
  
  std::sort(vars.begin(), vars.end(), [](mpc_variable_infot const &a, mpc_variable_infot const &b)
  {
    bool is_input_a = a.io_type != io_variable_typet::output;
    bool is_input_b = b.io_type != io_variable_typet::output;
    if(is_input_a == is_input_b)
    {
      if(is_input_a)
        // Sort inputs in ascending order based on unique variable name and SSA index.
        return std::tie(a.var.qualified_name, a.var.ssa_index) < std::tie(b.var.qualified_name, b.var.ssa_index);
      else
        // Sort outputs in descending order based on unique variable name and SSA index.
        return std::tie(a.var.qualified_name, a.var.ssa_index) > std::tie(b.var.qualified_name, b.var.ssa_index);
    }
    else
      // Sort inputs before outputs (arbitrary decision, doesn't matter).
      return is_input_a;
  });


  // Remove all but the first occurence of each variable. This leaves us the inputs with the lowest
  // SSA index and the outputs with the largest SSA index.
  auto new_end = std::unique(vars.begin(), vars.end(), [](mpc_variable_infot const &a, mpc_variable_infot const &b)
  {
    return a.var.qualified_name == b.var.qualified_name;
  });
  vars.erase(new_end, vars.end());

  return vars;
}


//==================================================================================================
struct function_vart
{
  variable_infot var;
  typet type;
  boolbv_mapt::literal_mapt literals;
};

struct bool_function_callt
{
  irep_idt name;
  int call_id;
  std::vector<function_vart> args;
  std::vector<function_vart> returns;
};


//==================================================================================================
inline std::string export_type(typet const &t);

inline void export_type(typet const &t, std::string &out)
{
  if(t.id() == ID_c_bool)
    out = std::string{"_Bool"} + out;
  else if(t.id() == ID_signedbv)
    out = std::string{"int"} + t.get("width").c_str() + out;
  else if(t.id() == ID_unsignedbv)
    out = std::string{"uint"} + t.get("width").c_str() + out;
  else if(t.id() == ID_array)
  {
    mp_integer arr_size;
    to_integer(to_array_type(t).size(), arr_size);
    out += '[' + integer2string(arr_size) + ']';
    export_type(t.subtype(), out);
  }
  else if(t.id() == ID_struct)
  {
    struct_typet const &structt = to_struct_type(t);
    std::string struct_str;
    auto const &comps = structt.components();

    for(size_t i = 0; i < comps.size(); ++i)
      struct_str += as_string(comps[i].get_pretty_name()) + ": " + export_type(comps[i].type()) + "; ";

    out = "{ " + struct_str + '}' + out;
  }
  else
    throw std::runtime_error{"export_type: unsupported type: " + t.pretty()};
}

inline std::string export_type(typet const &t)
{
  std::string out;
  export_type(t, out);
  return out;
}


//==================================================================================================
class Type from_cbmc(class typet const &cbmc_type);

#endif
