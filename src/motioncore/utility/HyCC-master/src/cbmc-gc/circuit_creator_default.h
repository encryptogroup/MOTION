#ifndef CBMC_GC_CIRCUIT_CREATOR_DEFAULT_H
#define CBMC_GC_CIRCUIT_CREATOR_DEFAULT_H

#include <unordered_map>
#include <algorithm>
#include <fstream>
#include <memory>

#include "circuit_creator.h"
#include <libcircuit/simple_circuit.h>


//==================================================================================================
// Data-structures for the temporary graph we build using circuit_creator_defaultt.
// Unfortunately this is necessary because simple_circuitt needs to know the kind of gate we want
// to add at creation time, but we simply don't always have this information in new_variable() (to
// be specific, we don't have this information when creating literals that are part of variables).
//
// TODO Okay, the above may not be accurate anymore. In our use case new_variable() is only called
//      for INPUT variables, so we actually COULD create simple_circuitt directly?
enum class tmp_node_kindt
{
  l_and,
  l_or,
  l_xor,
  
  input,
};

struct tmp_nodet
{
  tmp_nodet() = default;
  tmp_nodet(literalt me, tmp_node_kindt kind) :
    kind{kind},
    me{me} {}

  tmp_node_kindt kind;
  literalt me;
  literalt input_left;
  literalt input_right;
};


class circuit_creator_defaultt : public circuit_creatort
{
public:
  circuit_creator_defaultt() :
    m_root_scope{"root"},
    m_cur_scope{nullptr} {}

  virtual ~circuit_creator_defaultt() {}

  // Methods of propt
  //----------------------------------------------------------------------------
  virtual literalt land(literalt a, literalt b) override
  {
    if(a.is_false() || b.is_false())
      return const_literal(false);

    if(a.is_true())
      return b;

    if(b.is_true())
      return a;

    if(a.var_no() == b.var_no())
      return a.sign() == b.sign() ? a : const_literal(false);

    auto &node = new_node(tmp_node_kindt::l_and);
    node.input_left = a;
    node.input_right = b;

    return node.me;
  }

  virtual literalt lor(literalt a, literalt b) override
  {
    if(a.is_true() || b.is_true())
      return const_literal(true);

    if(a.is_false())
      return b;

    if(b.is_false())
      return a;

    if(a.var_no() == b.var_no())
      return a.sign() == b.sign() ? a : const_literal(true);

    auto &node = new_node(tmp_node_kindt::l_or);
    node.input_left = a;
    node.input_right = b;

    return node.me;
  }
  
  virtual literalt land(const bvt &bv) override
  {
    if(bv.empty())
      return const_literal(true);

    if(bv.size() == 1)
      return bv[0];
    
    literalt cur = bv[0];
    for(size_t i = 1; i < bv.size(); ++i)
      cur = land(cur, bv[i]);

    return cur;
  }

  virtual literalt lor(const bvt &bv) override
  {
    if(bv.empty())
      return const_literal(false);

    if(bv.size() == 1)
      return bv[0];
    
    literalt cur = bv[0];
    for(size_t i = 1; i < bv.size(); ++i)
      cur = lor(cur, bv[i]);

    return cur;
  }

  virtual literalt lxor(const bvt&) override
  {
    assert(!"not yet implemented");
  }

  virtual literalt lxor(literalt a, literalt b) override
  {
    if(b.is_constant())
      return b.is_true() ? !a : a;

    if(a.is_constant())
      return a.is_true() ? !b : b;

    if(a.var_no() == b.var_no())
      return a.sign() == b.sign() ? const_literal(false) : const_literal(true);

    auto &node = new_node(tmp_node_kindt::l_xor);
    node.input_left = a;
    node.input_right = b;

    return node.me;
  }

  virtual literalt lnand(literalt, literalt) override
  {
    assert(!"not yet implemented");
  }

  virtual literalt lnor(literalt, literalt) override
  {
    assert(!"not yet implemented");
  }

  virtual literalt lequal(literalt a, literalt b) override
  {
    return !lxor(a, b);
  }

  virtual literalt limplies(literalt a, literalt b) override
  {
    return lor(!a, b);
  }

  virtual literalt lselect(literalt a, literalt b, literalt c) override // a?b:c
  {
	  return lxor(c, land(a, lxor(b, c)));
  }

  virtual literalt new_variable() override
  {
    literalt l(m_literal_to_node.size(), false);

    // New literals are only created for variables that are read from without having been written to
    // before (i.e. INPUT variables). Okay, this is not actually true (anyone can create literals
    // for anything they want, but this probably only makes sense if set_equal() is supported, which
    // we don't), but it's the only case we support.
    m_literal_to_node[l.dimacs()] = tmp_nodet{l, tmp_node_kindt::input};

    return l;
  }

  // Convert literal to three-valued logic (true, false, unknown)
  virtual tvt l_get(literalt a) const override
  {
    if(a.is_constant())
      return tvt{a.is_true()};
    
    return tvt::unknown();
  }

  virtual size_t no_variables() const override { return m_literal_to_node.size(); }
  virtual std::string const solver_text() override { return "cbmc-gc circuit_creator_defaultt"; }

  // We don't really like CNF.
  virtual bool cnf_handled_well() const override { return false; }

  // set_to() doesn't make sense in a circuit (see comment for set_equal()).
  virtual bool has_set_to() const override { return false; }


  // Methods of propt that we don't support
  //----------------------------------------------------------------------------
  // Add a CNF clause
  virtual void lcnf(bvt const&) override { throw std::runtime_error{"circuit_creator_defaultt::lcnf() not supported"}; }

  // Constraining literals to a specific value doesn't make sense in a circuit. (All gates are evaluated
  // from the inputs to the outputs. Nothing to constrain here.)
  // Although we don't support set_equal() we don't throw an exception because CBMC automatically
  // inserts some initialization code that requires set_equal() (namely __CPROVER_threads_exited,
  // which is an unbounded array) and removing that code would require source modifications outside
  // of our cbmc-gc/ directory.
  virtual void set_equal(literalt, literalt) override { /*throw std::runtime_error{"circuit_creator_defaultt::set_equal() not supported"};*/ }

  virtual resultt prop_solve() override { throw std::runtime_error{"circuit_creator_defaultt::prop_solve() not supported"}; }


  // Our stuff
  //----------------------------------------------------------------------------
  tmp_nodet& new_node(tmp_node_kindt kind)
  {
    literalt l(m_literal_to_node.size(), false);

    if(m_cur_scope)
      m_cur_scope->literals.push_back(l);

    return (m_literal_to_node[l.dimacs()] = tmp_nodet{l, kind});
  }

  std::unordered_map<int, tmp_nodet> const& graph() const { return m_literal_to_node; }

  virtual void create_circuit(
    std::vector<mpc_variable_infot> const &vars,
    std::vector<bool_function_callt> const &func_calls,
    simple_circuitt &circuit) override;

  virtual void enable_scopes() override
  {
    if(!m_cur_scope)
      m_cur_scope = &m_root_scope;
  }

  virtual void push_scope(std::string const &name) override
  {
    if(m_cur_scope)
    {
      m_cur_scope->children.push_back(std::unique_ptr<scopet>{new scopet{name, m_cur_scope}});
      m_cur_scope = m_cur_scope->children.back().get();
    }
  }

  virtual void pop_scope() override
  {
    if(m_cur_scope)
    {
      assert(m_cur_scope->parent);
      m_cur_scope = m_cur_scope->parent;
    }
  }

  virtual void scopes_to_dot(std::ostream &os) override;


  struct scopet
  {
    explicit scopet(std::string const &name, scopet *parent = nullptr) :
      parent{parent},
      name{name} {}

    scopet *parent;
    std::vector<std::unique_ptr<scopet>> children;

    std::string name;
    std::vector<literalt> literals;
  };

private:
  scopet m_root_scope;
  scopet *m_cur_scope;

  std::unordered_map<int, tmp_nodet> m_literal_to_node;
};


// Conversion to simple_circuitt
//==================================================================================================
// Converts a literal to a simple_circuitt::gatet
inline simple_circuitt::gatet* convert_node(literalt cur_lit, std::unordered_map<int, simple_circuitt::gatet*> &literal_to_gate,
                                     circuit_creator_defaultt const &src, simple_circuitt &circuit)
{
  if(cur_lit.is_true())
    return &circuit.get_one_gate();

  if(cur_lit.is_false())
    return &circuit.get_zero_gate();

  auto it = literal_to_gate.find(cur_lit.dimacs());
  if(it != literal_to_gate.end())
    return it->second;
  
  // If the negated version of the literal exists we need to create a NOT gate.
  it = literal_to_gate.find((!cur_lit).dimacs());
  if(it != literal_to_gate.end())
  {
    auto gate = circuit.get_or_create_gate(simple_circuitt::NOT);
    gate->add_fanin({it->second, 0}, 0);
    literal_to_gate[cur_lit.dimacs()] = gate;
    return gate;
  }
  

  // Okay, `cur_lit` isn't in our list of already converted literals, so let's convert it now.
  // First, check if we even know the literal. If not, it probably means that it is negated.
  bool is_negated = false;
  auto node_it = src.graph().find(cur_lit.dimacs());
  if(node_it == src.graph().end())
  {
    // Check if the negated literal exists
    node_it = src.graph().find((!cur_lit).dimacs());
    if(node_it == src.graph().end())
      throw std::runtime_error{"Literal not found: " + std::to_string(cur_lit.dimacs())};
    else
      is_negated = true;
  }
  
  auto const &cur_node = node_it->second;
  simple_circuitt::gatet *gate = nullptr;
  switch(cur_node.kind)
  {
    case tmp_node_kindt::l_and: gate = circuit.get_or_create_gate(simple_circuitt::AND); break;
    case tmp_node_kindt::l_or: gate = circuit.get_or_create_gate(simple_circuitt::OR); break;
    case tmp_node_kindt::l_xor: gate = circuit.get_or_create_gate(simple_circuitt::XOR); break;
    case tmp_node_kindt::input:
      // If we get here then a literal was created using new_variable() that is not part of an input
      // variable. This usually happens if an OUTPUT variable is not assigned a value.
      throw std::runtime_error{
        "Unknown literal: " + std::to_string(cur_lit.dimacs()) + 
        ". Did you forget to return a value or assign a value to a OUTPUT variable?"
      };
    break;
  }

  gate->add_fanin({convert_node(cur_node.input_left, literal_to_gate, src, circuit), 0}, 0);
  gate->add_fanin({convert_node(cur_node.input_right, literal_to_gate, src, circuit), 0}, 1);
  
  if(is_negated)
  {
    auto not_gate = circuit.get_or_create_gate(simple_circuitt::NOT);
    not_gate->add_fanin({gate, 0}, 0);
    literal_to_gate[cur_lit.dimacs()] = not_gate;
    literal_to_gate[(!cur_lit).dimacs()] = gate;
    gate = not_gate;
  }
  else
    literal_to_gate[cur_lit.dimacs()] = gate;
  
  return gate;
}


#endif
