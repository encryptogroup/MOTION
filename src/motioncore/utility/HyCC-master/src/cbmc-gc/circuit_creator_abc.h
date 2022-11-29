#ifndef CBMC_GC_CIRCUIT_CREATOR_ABC_H
#define CBMC_GC_CIRCUIT_CREATOR_ABC_H

#include <unordered_map>
#include <algorithm>

#include "circuit_creator.h"
#include "simple_circuit.h"

#include <base/main/main.h>
#include <base/abc/abc.h>
#include <aig/aig/aig.h>


//==================================================================================================
// Note that the Abc circuit created by this class is incomplete because the outputs are missing.
// (We only now what literals belong to outputs after we are done.)
class circuit_creator_abct : public circuit_creatort
{
public:
  circuit_creator_abct() :
    m_num_literals{0}
  {
    Abc_Start();
	m_abc = Abc_FrameGetGlobalFrame();
	m_aig = Abc_NtkAlloc( ABC_NTK_STRASH, ABC_FUNC_AIG, 1);

    m_literal_to_obj[const_literal(true).dimacs()] = Abc_AigConst1(m_aig);
  }

  virtual ~circuit_creator_abct()
  {
    Abc_Stop();
  }

  // Methods of propt
  //----------------------------------------------------------------------------
  virtual literalt land(literalt a, literalt b) override
  {
    literalt lit{m_num_literals++, false};
    m_literal_to_obj[lit.dimacs()] = Abc_AigAnd((Abc_Aig_t*)(m_aig->pManFunc), get_abc_obj(a), get_abc_obj(b));

    return lit;
  }

  virtual literalt lor(literalt a, literalt b) override
  {
    literalt lit{m_num_literals++, false};
    m_literal_to_obj[lit.dimacs()] = Abc_AigOr((Abc_Aig_t*)(m_aig->pManFunc), get_abc_obj(a), get_abc_obj(b));

    return lit;
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
    literalt lit{m_num_literals++, false};
    auto xor_o = Abc_AigXor((Abc_Aig_t*)(m_aig->pManFunc), get_abc_obj(a), get_abc_obj(b));
    m_literal_to_obj[lit.dimacs()] = xor_o;

    return lit;
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
    literalt lit{m_num_literals++, false};
    m_literal_to_obj[lit.dimacs()] = Abc_NtkCreatePi(m_aig);
    return lit;
  }

  // Convert literal to three-valued logic (true, false, unknown)
  virtual tvt l_get(literalt a) const override
  {
    if(a.is_constant())
      return tvt{a.is_true()};
    
    return tvt::unknown();
  }

  virtual size_t no_variables() const override { return m_num_literals; }
  virtual std::string const solver_text() override { return "cbmc-gc circuit_creator_defaultt"; }

  // We don't really like CNF.
  virtual bool cnf_handled_well() const override { return false; }

  // set_to() doesn't make sense in a circuit (see comment for set_equal()).
  virtual bool has_set_to() override const { return false; }


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


  //----------------------------------------------------------------------------
  virtual void create_circuit(std::vector<mpc_variable_infot> const &vars, simple_circuitt &circuit);

  virtual void enable_scopes() override {}
  virtual void push_scope(std::string const&) override {}
  virtual void pop_scope() override {}

  Abc_Obj_t* get_abc_obj(literalt l)
  {
    auto it = m_literal_to_obj.find(l.dimacs());
    if(it != m_literal_to_obj.end())
      return it->second;

    it = m_literal_to_obj.find((!l).dimacs());
    if(it != m_literal_to_obj.end())
    {
      Abc_Obj_t *neg = Abc_ObjNot(it->second);
      m_literal_to_obj[l.dimacs()] = neg;
      return neg;
    }

    throw std::runtime_error{"Literal not found: " + std::to_string(l.dimacs())};
  }

private:
  void *m_abc;
  Abc_Ntk_t *m_aig;
  std::unordered_map<int, Abc_Obj_t*> m_literal_to_obj;
  unsigned int m_num_literals;
};


//==================================================================================================
// Converts a literal to a simple_circuitt::gatet
simple_circuitt::gatet* convert_node(Abc_Obj_t *cur_obj, std::unordered_map<Abc_Obj_t*, simple_circuitt::gatet*> &obj_to_gate,
                                     simple_circuitt &circuit)
{
  // Pointers to Abc objects are not necessarily dereferencable as-is because the information whether the
  // object is negated is encoded in the pointer itself.
  Abc_Obj_t *cur_obj_reg = Abc_ObjRegular(cur_obj);

  auto it = obj_to_gate.find(cur_obj);
  if(it != obj_to_gate.end())
    return it->second;

  // If the negated version of the literal exists we need to create a NOT gate.
  it = obj_to_gate.find(Abc_ObjNot(cur_obj));
  if(it != obj_to_gate.end())
  {
    auto gate = circuit.get_or_create_gate(simple_circuitt::NOT);
    gate->add_fanin(*it->second, 0);
    obj_to_gate[cur_obj] = gate;
    return gate;
  }


  // Okay, `cur_obj` isn't in our list of already converted literals, so let's convert it now.
  simple_circuitt::gatet *gate = nullptr;
  if(Abc_AigNodeIsAnd(Abc_ObjRegular(cur_obj)))
    gate = circuit.get_or_create_gate(simple_circuitt::AND);
  else
  {
    throw std::runtime_error{
      "convert_node(): Unknown node. Did you forget to return a value or assign a value to a OUTPUT variable?"
    };
  }

  // Check if the fanins are negated
  auto fanin_0 = Abc_ObjNotCond(Abc_ObjFanin0(cur_obj_reg), Abc_ObjFaninC0(cur_obj_reg));
  auto fanin_1 = Abc_ObjNotCond(Abc_ObjFanin1(cur_obj_reg), Abc_ObjFaninC1(cur_obj_reg));

  gate->add_fanin(*convert_node(fanin_0, obj_to_gate, circuit), 0);
  gate->add_fanin(*convert_node(fanin_1, obj_to_gate, circuit), 1);
  
  if(Abc_ObjIsComplement(cur_obj))
  {
    auto not_gate = circuit.get_or_create_gate(simple_circuitt::NOT);
    not_gate->add_fanin(*gate, 0);
    obj_to_gate[cur_obj] = not_gate;
    obj_to_gate[Abc_ObjNot(cur_obj)] = gate;
    gate = not_gate;
  }
  else
    obj_to_gate[cur_obj] = gate;
  
  return gate;
}

void circuit_creator_abct::create_circuit(std::vector<mpc_variable_infot> const &vars, simple_circuitt &circuit)
{
  // Create primary outputs
  for(auto &&info: vars)
  {
    if(info.io_type == io_variable_typet::output)
    {
      std::vector<Abc_Obj_t*> pos;
      for(auto maybe_lit: info.literals)
      {
        if(!maybe_lit.is_set)
          throw std::runtime_error{"Literal of OUTPUT varialble is not set"};

        Abc_Obj_t *po = Abc_NtkCreatePo(m_aig);
        Abc_ObjAddFanin(po, get_abc_obj(maybe_lit.l));
      }
    }
  }

  // Remove dangling nodes.
  Abc_AigCleanup((Abc_Aig_t*)m_aig->pManFunc);

  if(!Abc_NtkCheck(m_aig))
    throw std::runtime_error{"Checking ABC circuit failed"};

  //Abc_NtkRewrite(m_aig, 1, 0, 0, 0, 0); Triggers an assertion
  Abc_NtkBalance(m_aig, 0, 0, 1);

  std::unordered_map<Abc_Obj_t*, simple_circuitt::gatet*> obj_to_gate;
  obj_to_gate[Abc_AigConst1(m_aig)] = &circuit.get_one_gate();

  // Convert input variables
  int counter = 1;
  for(auto &&info: vars)
  {
    if(info.io_type != io_variable_typet::output)
    {
      std::vector<simple_circuitt::gatet*> gates;
      for(auto lit: info.literals)
      {
        if(!lit.is_set)
          throw std::runtime_error{"Literal of INPUT varialble is not set"};

        auto gate = circuit.create_input_gate(std::to_string(counter++));
        obj_to_gate[get_abc_obj(lit.l)] = gate;
        gates.push_back(gate);
      }

      if(info.io_type == io_variable_typet::input_a)
        circuit.input_a_variables[info.unqualified_name] = {info.type, gates};
      else if(info.io_type == io_variable_typet::input_b)
        circuit.input_b_variables[info.unqualified_name] = {info.type, gates};
    }
  }

  // Convert everything else
  for(auto &&info: vars)
  {
    if(info.io_type == io_variable_typet::output)
    {
      std::vector<simple_circuitt::gatet*> outs;
      for(auto maybe_lit: info.literals)
      {
        if(!maybe_lit.is_set)
          throw std::runtime_error{"Literal of OUTPUT varialble is not set"};

        auto gate = circuit.create_output_gate(std::to_string(maybe_lit.l.dimacs()));
        gate->add_fanin(*convert_node(get_abc_obj(maybe_lit.l), obj_to_gate, circuit), 0);
        outs.push_back(gate);
      }

      circuit.output_variables[info.unqualified_name] = {info.type, outs};
    }
  }
}


#endif
