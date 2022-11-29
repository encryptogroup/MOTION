#ifndef CBMC_GC_SYMEX_H
#define CBMC_GC_SYMEX_H

#include <cbmc/symex_bmc.h>
#include <goto-programs/remove_returns.h>

#include <unordered_set>
#include <iostream>


// Creates a new function body if you want to skip the actual function.
inline goto_programt::instructionst create_empty_body_instructions(
  symbol_tablet const &orig_symbol_table,
  symbol_tablet &new_symbol_table,
  irep_idt func_name)
{
  symbolt function_symbol = orig_symbol_table.symbols.at(func_name);
  code_typet func_type = to_code_type(function_symbol.type);
  goto_programt::instructionst instructions;

  if(func_type.return_type().id() != ID_empty)
  {
    auxiliary_symbolt new_symbol;
    new_symbol.module=function_symbol.module;
    new_symbol.base_name= id2string(function_symbol.base_name)+RETURN_VALUE_SUFFIX;
    new_symbol.name=id2string(function_symbol.name)+RETURN_VALUE_SUFFIX;
    new_symbol.mode=function_symbol.mode;
    new_symbol.type=func_type.return_type();
    new_symbol_table.add(new_symbol);

    symbol_exprt lhs_expr;
    lhs_expr.set_identifier(id2string(func_name)+RETURN_VALUE_SUFFIX);
    lhs_expr.type()=func_type.return_type();
    code_assignt assignment(lhs_expr, side_effect_expr_nondett(func_type.return_type()));

    goto_programt::instructiont inst;
    inst.type = goto_program_instruction_typet::ASSIGN;
    inst.code = assignment;
    inst.function = func_name;

    instructions.push_back(inst);
  }

  instructions.push_back(goto_programt::instructiont{goto_program_instruction_typet::END_FUNCTION});

  return instructions;
}


class cbmc_gc_symext : public symex_bmct
{
public:
  cbmc_gc_symext(
    const namespacet &_ns,
    symbol_tablet const &orig_sym_table,
    symbol_tablet &_new_symbol_table,
    symex_targett &_target,
    messaget &msg) :
      symex_bmct{msg.get_message_handler(),_ns, _new_symbol_table, _target},
      orig_sym_table{orig_sym_table},
      msg{msg} {}

  virtual void symex_function_call_code(
    const get_goto_functiont &get_goto_function,
    statet &state,
    const code_function_callt &call) override
  {
    symex_bmct::symex_function_call_code(get_goto_function, state, call);
    const irep_idt &identifier = to_symbol_expr(call.function()).get_identifier();

    goto_functionst::goto_functiont const &func = get_goto_function(identifier);

    if(ignore_function_body.find(identifier) != ignore_function_body.end() || !func.body_available())
    {
      // To ignore the function body we set the program counter to our specially crafted instructions.

      auto &alternate_instructions = get_empty_body_instructions(call);
      state.source.pc = alternate_instructions.begin();
      state.top().end_of_function = alternate_instructions.end();

      msg.debug() << "Skipping function body of \"" << identifier << "\"" << messaget::eom;
    }



  }

  goto_programt::instructionst& get_empty_body_instructions(const code_function_callt &call)
  {
    const irep_idt &identifier = to_symbol_expr(call.function()).get_identifier();

    auto res = alternate_bodies.insert({identifier, {}});
    if(res.second) // Inserted?
      res.first->second = create_empty_body_instructions(orig_sym_table, new_symbol_table, identifier);

    return res.first->second;
  }

  symex_targett& target() { return symex_bmct::target; }


  virtual void symex_transition(statet &state, goto_programt::const_targett to, bool is_backwards_goto=false) override
  {
    symex_bmct::symex_transition(state, to, is_backwards_goto);
  }

  virtual void symex_step(const get_goto_functiont &get_goto_function, statet &state) override
  {
    symex_bmct::symex_step(get_goto_function, state);
  }


  symbol_tablet const &orig_sym_table;
  std::unordered_set<irep_idt, irep_id_hash> ignore_function_body;
  std::unordered_map<irep_idt, goto_programt::instructionst, irep_id_hash> alternate_bodies;

  messaget &msg;
};


#endif
