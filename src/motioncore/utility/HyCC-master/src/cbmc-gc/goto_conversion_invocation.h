#pragma once

#include "ssa_to_circuit/ssa_to_circuit.h"

#include <util/symbol_table.h>
#include <util/options.h>
#include <langapi/language_ui.h>
#include <goto-programs/goto_functions.h>

#include <fstream>
#include <vector>
#include <unordered_map>
#include <unordered_set>


class goto_modulet
{
public:
  goto_modulet(
    symbol_tablet &&original_symbols,
    symbol_tablet &&transformed_symbols,
    goto_functionst &&goto_functions,
    std::string const &main_function,
    std::unordered_set<std::string> funcs_to_skip,
    optionst &&options) :
      m_original_symbols{std::move(original_symbols)},
      m_transformed_symbols{std::move(transformed_symbols)},
      m_goto_functions{std::move(goto_functions)},
      m_main_function{main_function},
      m_funcs_to_skip{std::move(funcs_to_skip)},
      m_options{std::move(options)}
  {
    m_get_goto_function = [this](const irep_idt &key) -> const goto_functionst::goto_functiont &
    {
      auto it = m_goto_functions.function_map.find(key);
      if(it == m_goto_functions.function_map.end())
        throw std::runtime_error{"Function not found: " + as_string(key)};

      return it->second;
    };
  }

  goto_modulet(goto_modulet &&rhs) :
    m_original_symbols{std::move(rhs.m_original_symbols)},
    m_transformed_symbols{std::move(rhs.m_transformed_symbols)},
    m_goto_functions{std::move(rhs.m_goto_functions)},
    m_main_function{std::move(rhs.m_main_function)},
    m_funcs_to_skip{std::move(rhs.m_funcs_to_skip)},
    m_options{std::move(rhs.m_options)}
  {
    m_get_goto_function = [this](const irep_idt &key) -> const goto_functionst::goto_functiont &
    {
      auto it = m_goto_functions.function_map.find(key);
      if(it == m_goto_functions.function_map.end())
        throw std::runtime_error{"Function not found: " + as_string(key)};

      return it->second;
    };
  }

  symbol_tablet const& original_symbols() const { return m_original_symbols; }
  symbol_tablet& original_symbols() { return m_original_symbols; }
  symbol_tablet const& transformed_symbols() const { return m_transformed_symbols; }
  symbol_tablet& transformed_symbols() { return m_transformed_symbols; }

  goto_functionst const& goto_functions() const { return m_goto_functions; }
  goto_functionst& goto_functions() { return m_goto_functions; }
  std::string const& main_function_name() const { return m_main_function; }
  bool is_external_call(std::string const &name) const { return m_funcs_to_skip.count(name); }
  void make_external_call(std::string const &name) { m_funcs_to_skip.insert(name); }
  std::unordered_set<std::string> const& funcs_to_skip() const { return m_funcs_to_skip; }
  std::unordered_set<std::string>& funcs_to_skip() { return m_funcs_to_skip; }

  optionst const& options() const { return m_options; }
  optionst & options() { return m_options; }

  goto_programt const* find_function(std::string const &name) const
  {
    auto it = m_goto_functions.function_map.find(name);
    if(it == m_goto_functions.function_map.end())
      return nullptr;

    return &it->second.body;
  }

  goto_programt const& function(std::string const &name) const
  {
    if(auto func = find_function(name))
      return *func;

    throw std::runtime_error{"Function not found: " + name};
  }

  goto_programt const& main_function() const { return function(m_main_function); }

  code_typet const& func_type(std::string const &func_name) const
  {
    return to_code_type(m_original_symbols.lookup(func_name)->type);
  }

  symbolt const& lookup(std::string const &func_name) const
  {
    return *m_original_symbols.lookup(func_name);
  }

  void add_specialization(std::string func_name, param_specialzationst const &specializations)
  {
    auto specialized_func_name = func_name + build_func_name_suffix(func_type(func_name), specializations);
    auto res = m_specializations.insert({specialized_func_name, {func_name, specializations}});
	if(res.second)
		m_unresolved_secializations.push_back(res.first);
  }

  using specializationst = std::unordered_map<std::string, std::pair<std::string, param_specialzationst>>;

  std::list<specializationst::iterator>& specializations() { return m_unresolved_secializations; }

  goto_symext::get_goto_functiont const& function_getter() const { return m_get_goto_function; }

private:
  symbol_tablet m_original_symbols;
  symbol_tablet m_transformed_symbols;
  goto_functionst m_goto_functions;
  goto_symext::get_goto_functiont m_get_goto_function;
  std::string m_main_function;

  // The names of functions to which calls should not be inlined
  std::unordered_set<std::string> m_funcs_to_skip;

  optionst m_options;

  specializationst m_specializations;
  std::list<specializationst::iterator> m_unresolved_secializations;
};


goto_modulet invoke_goto_compilation(cmdlinet const &args, ui_message_handlert &msg);

// Run this once before any calls to `invoke_goto_compilation()`
void register_languages();

void prepare_function_calls(goto_modulet &module);

inline bool should_not_be_inlined(std::string const &func_name)
{
  static std::unordered_set<std::string> const never_inline{
    "strncpy",
    "memcpy",
    "memset",
  };

  return never_inline.count(func_name) != 0;
}
