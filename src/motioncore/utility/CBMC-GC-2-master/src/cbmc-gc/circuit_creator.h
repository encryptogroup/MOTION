#ifndef CBMC_GC_CIRCUIT_CREATOR_H
#define CBMC_GC_CIRCUIT_CREATOR_H

#include <solvers/prop/prop.h>
#include <solvers/flattening/boolbv_map.h>
#include <util/arith_tools.h>


//==================================================================================================
class simple_circuitt;
struct mpc_variable_infot;

class circuit_creatort : public propt
{
public:
  virtual void create_circuit(std::vector<mpc_variable_infot> const &vars, simple_circuitt &circuit) = 0;
};


// Extracting variable information
//==================================================================================================
enum class io_variable_typet
{
  input_a,
  input_b,
  output,
};

struct mpc_variable_infot
{
  irep_idt id;
  // Contains variable name with complete scope information but without SSA index or thread id
  std::string unique_var_name;
  // Contains just the variable name
  std::string var_name;
  int ssa_index;
  io_variable_typet io_type;
  // Can only be true if io_type == output.
  bool is_return_value;
  
  boolbv_mapt::literal_mapt literals;
  typet type;
};

inline size_t go_to_end_of_name(std::string const &str, size_t start)
{
  while(start < str.length() && (str[start] == '_' || std::isalnum(str[start])))
    ++start;
  
  return start;
}

inline int get_ssa_index(std::string const &id)
{
  auto pos = id.find('#');
  if(pos == std::string::npos || pos + 1 >= id.length())
    throw std::logic_error{"id must contain SSA index: " + id};
  
  return atoi(id.c_str() + pos + 1);
}

inline bool id_is_of_func(irep_idt const &id, std::string const &func_name)
{
  auto &id_str = as_string(id);
  if(id_str.find(func_name) == 0)
  {
    if(id_str.length() <= func_name.length())
      throw std::logic_error{"id too short"};
    
    return !(std::isalnum(id_str[func_name.length()]) || id_str[func_name.length()] == '_');
  }
  
  return false;
}

inline mpc_variable_infot extract_variable_info(irep_idt const &identifier)
{
  mpc_variable_infot info;
  info.id = identifier;
  info.ssa_index = -1; // We use an ssa index of -1 if the identifier does not contain a INPUT or OUTPUT variable. It's horrible.
  auto &id_str = as_string(identifier);
  info.is_return_value = false;
  
  auto name_pos = id_str.find("INPUT_");
  if(name_pos != std::string::npos && name_pos + 6 < id_str.length())
  {
    if(id_str[name_pos + 6] == 'A')
      info.io_type = io_variable_typet::input_a;
    else
      info.io_type = io_variable_typet::input_b;

    auto name_end_pos = go_to_end_of_name(id_str, name_pos);
    info.var_name = id_str.substr(name_pos, name_end_pos - name_pos);
    info.unique_var_name = id_str.substr(0, name_end_pos);
    info.ssa_index = get_ssa_index(id_str);
  }
  else if((name_pos = id_str.find("OUTPUT")) != std::string::npos)
  {
    info.io_type = io_variable_typet::output;
    auto name_end_pos = go_to_end_of_name(id_str, name_pos);
    info.var_name = id_str.substr(name_pos, name_end_pos - name_pos);
    info.unique_var_name = id_str.substr(0, name_end_pos);
    info.ssa_index = get_ssa_index(id_str);
  }
  // Treat return value as OUTPUT
  else if((name_pos = id_str.find("#return_value")) != std::string::npos)
  {
    info.io_type = io_variable_typet::output;
    auto name_end_pos = go_to_end_of_name(id_str, name_pos + 1);
    info.var_name = id_str.substr(name_pos + 1, name_end_pos - name_pos - 1);
    info.unique_var_name = id_str.substr(0, name_end_pos);
    info.ssa_index = 1;
    info.is_return_value = true;
  }
  
  return info;
}

inline std::vector<mpc_variable_infot> get_input_output_variables(boolbv_mapt::mappingt const &mapping, std::string const &func)
{
  std::vector<mpc_variable_infot> vars;
  for(auto &&pair: mapping)
  {
    if(id_is_of_func(pair.first, func))
    {
      auto info = extract_variable_info(pair.first);
      if(info.ssa_index != -1)
      {
        // If it's a INPUT variable we only care for the one with an SSA index of 1.
        if(info.io_type == io_variable_typet::output || info.ssa_index == 1)
        {
          info.literals = pair.second.literal_map;
          info.type = pair.second.type;
          vars.push_back(info);
        }
      }
    }
  }
  
  // Sort in descending order based on unique variable name and SSA index
  std::sort(vars.begin(), vars.end(), [](mpc_variable_infot const &a, mpc_variable_infot const &b)
  {
    return std::tie(a.unique_var_name, a.ssa_index) > std::tie(b.unique_var_name, b.ssa_index);
  });
  
  // Remove all but the first occurence of each variable. Since we sorted in descending order based
  // on the SSA index this means we will only keep the variables with the largest SSA indices.
  auto new_end = std::unique(vars.begin(), vars.end(), [](mpc_variable_infot const &a, mpc_variable_infot const &b)
  {
    return a.unique_var_name == b.unique_var_name;
  });
  vars.erase(new_end, vars.end());

  // Sort again in ascending order so INPUT_A comes before INPUT_B. This is not strictly necessary,
  // but when simulating the circuit it's nice to have INPUT_A as the first and INPUT_B as the
  // second input.
  std::sort(vars.begin(), vars.end(), [](mpc_variable_infot const &a, mpc_variable_infot const &b)
  {
    return a.unique_var_name < b.unique_var_name;
  });
  
  return vars;
}


inline std::string export_type(typet const &t);

inline void export_type(typet const &t, std::string &out)
{
  if(t.id() == ID_signedbv)
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
    throw std::runtime_error{"export_type: unsupported type: " + t.id_string()};
}

std::string export_type(typet const &t)
{
  std::string out;
  export_type(t, out);
  return out;
}


#endif
