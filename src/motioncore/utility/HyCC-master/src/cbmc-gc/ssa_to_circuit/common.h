#pragma once

#include <solvers/flattening/boolbv_width.h>
#include <goto-symex/symex_target_equation.h>
#include <goto-programs/remove_returns.h>
#include <analyses/dirty.h>

#include "../cbmc_gc_symex.h"
#include "../circuit_creator.h"
#include <libcircuit/simple_circuit.h>


using ssa_step_iterator = symex_target_equationt::SSA_stepst::const_iterator;

struct generic_function_callt
{
  using arg_vart = std::pair<variable_infot, typet>;

  struct ret_vart
  {
    variable_infot var;
    typet type;

    // If this is an additional return, contains both the variable of the argument that is being
	// overwritten and the actual expression pased as argument
    optional<std::pair<ssa_exprt, exprt>> additional_return_target;
  };

  irep_idt name;
  int call_id;
  std::vector<exprt> arg_to_param_assignments;
  std::vector<arg_vart> args;
  std::vector<ret_vart> returns;
};




// The code in this class has been copied from goto_symext::operator() (goto_symex/symex_main.cpp).
class goto_symex_steppert
{
public:
  goto_symex_steppert(
    cbmc_gc_symext &symex,
    cbmc_gc_symext::get_goto_functiont const &get_function,
    goto_programt const &func) :
      m_symex{symex},
      m_get_function{get_function}
  {
    assert(!func.instructions.empty());

    m_state.source=symex_targett::sourcet(func);
    assert(!m_state.threads.empty());
    assert(!m_state.call_stack().empty());
    m_state.top().end_of_function=--func.instructions.end();
    m_state.top().calling_location.pc=m_state.top().end_of_function;
    m_state.symex_target=&m_symex.target();
    m_state.dirty=std::unique_ptr<incremental_dirtyt>{new incremental_dirtyt()};

    m_symex.symex_transition(m_state, m_state.source.pc);


    assert(m_state.top().end_of_function->is_end_function());


    while(target_equation().SSA_steps.empty())
      step();

    m_cur_inst = target_equation().SSA_steps.begin();
    assert(m_cur_inst != target_equation().SSA_steps.cend());
  }

  symex_target_equationt::SSA_stepst::const_iterator cur_instruction()
  {
    assert(target_equation().SSA_steps.size());

    if(m_cur_inst == target_equation().SSA_steps.cend())
    {
      auto last_inst = --target_equation().SSA_steps.cend();
      auto old_size = target_equation().SSA_steps.size();
      while(old_size == target_equation().SSA_steps.size())
        step();
      m_cur_inst = ++last_inst;
    }

    assert(m_cur_inst != target_equation().SSA_steps.cend());

    return m_cur_inst;
  }

  symex_target_equationt::SSA_stepst::const_iterator next_instruction()
  {
    cur_instruction();
    return ++m_cur_inst;
  }

  bool done() const { return m_cur_inst == target_equation().SSA_steps.end() && m_state.call_stack().empty(); }
  explicit operator bool () { return done(); }

  goto_symex_statet& state() { return m_state; }

  symex_target_equationt const& target_equation() const
  {
    return dynamic_cast<symex_target_equationt const&>(m_symex.target());
  }

private:
  cbmc_gc_symext &m_symex;
  cbmc_gc_symext::get_goto_functiont const &m_get_function;
  goto_symex_statet m_state;
  symex_target_equationt::SSA_stepst::const_iterator m_cur_inst;

  void step()
  {
    assert(!m_state.call_stack().empty());

    m_symex.symex_step(m_get_function, m_state);

    // is there another thread to execute?
    if(m_state.call_stack().empty() &&
       m_state.source.thread_nr+1<m_state.threads.size())
    {
      unsigned t=m_state.source.thread_nr+1;
      // std::cout << "********* Now executing thread " << t << '\n';
      m_state.switch_to_thread(t);
      m_symex.symex_transition(m_state, m_state.source.pc);
    }
  }
};


// If the instruction pointed to by `step_it` is a function call and the called function has
// an entry in `funcs_to_skip`, the list of arguments and return values will be returned.
optional<generic_function_callt> handle_function_call(
  class bmc_gct &bmc,
  goto_symex_steppert &stepper,
  class goto_modulet &module);


bool is_template_func(code_typet const &func);


// Replaces the symbol whose (partial) value is obtained by evaluating `expr` with `new_subject`.
// For Example, if you have `foo.arr[bar.x + 2` and the new subject is `fizz` then you will get
// `fizz.arr[bar.x + 2]`.
void replace_subject_with(exprt &expr, ssa_exprt const &new_subject);

