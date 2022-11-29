/*******************************************************************\

Module:

Author: CM Wintersteiger

\*******************************************************************/

#include <cassert>
#include <fstream>

#include <util/arith_tools.h>
#include <util/std_expr.h>

#include <langapi/language_util.h>

#include <solvers/prop/literal.h>

#include <cuddObj.hh> // CUDD Library

/*! \cond */
// FIX FOR THE CUDD LIBRARY

/*******************************************************************\

Function: DD::getNode

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

inline DdNode *DD::getNode() const
{
    return node;
} // DD::getNode
/*! \endcond */


#include "qbf_bdd_core.h"

/*******************************************************************\

Function: qbf_bdd_certificatet::qbf_bdd_certificatet

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

qbf_bdd_certificatet::qbf_bdd_certificatet(void) : qdimacs_coret()
{
  bdd_manager=new Cudd(0, 0);
}

/*******************************************************************\

Function: qbf_bdd_certificatet::~qbf_bdd_certificatet

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

qbf_bdd_certificatet::~qbf_bdd_certificatet(void)
{
  for(const BDD* model : model_bdds)
  {
    if(model)
      delete model;
  }
  model_bdds.clear();

  delete(bdd_manager);
  bdd_manager=NULL;
}

/*******************************************************************\

Function: qbf_bdd_certificatet::new_variable

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

literalt qbf_bdd_certificatet::new_variable(void)
{
  literalt l=qdimacs_coret::new_variable();

  if(!is_quantified(l))
    add_quantifier(quantifiert::EXISTENTIAL, l);

  return l;
}

/*******************************************************************\

Function: qbf_bdd_coret::qbf_bdd_coret

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

qbf_bdd_coret::qbf_bdd_coret() : qbf_bdd_certificatet()
{
  matrix=new BDD();
  *matrix=bdd_manager->bddOne();
}

/*******************************************************************\

Function: qbf_bdd_coret::~qbf_bdd_coret

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

qbf_bdd_coret::~qbf_bdd_coret()
{
  for(const BDD* variable : bdd_variable_map)
  {
    if(variable)
      delete variable;
  }
  bdd_variable_map.clear();

  if(matrix)
  {
    delete(matrix);
    matrix=NULL;
  }
}

/*******************************************************************\

Function: qbf_bdd_coret::l_get

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

tvt qbf_bdd_coret::l_get(literalt a) const
{
  assert(false);
  return tvt(false);
}

/*******************************************************************\

Function: qbf_bdd_coret::solver_text

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

const std::string qbf_bdd_coret::solver_text()
{
  return "QBF/BDD/CORE";
}

/*******************************************************************\

Function: qbf_bdd_coret::prop_solve

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

propt::resultt qbf_bdd_coret::prop_solve()
{
  {
    status() << solver_text() << ": "
             << std::to_string(no_variables()) << " variables, "
             << std::to_string(matrix->nodeCount()) << " nodes" << eom;
  }

  model_bdds.resize(no_variables()+1, NULL);

  // Eliminate variables
  for(auto it=quantifiers.rbegin();
      it!=quantifiers.rend();
      it++)
  {
    unsigned var=it->var_no;

    if(it->type==quantifiert::EXISTENTIAL)
    {
      #if 0
      std::cout << "BDD E: " << var << ", " <<
        matrix->nodeCount() << " nodes" << std::endl;
      #endif

      BDD *model=new BDD();
      const BDD &varbdd=*bdd_variable_map[var];
      *model=matrix->AndAbstract(
        varbdd.Xnor(bdd_manager->bddOne()),
        varbdd);
      model_bdds[var]=model;

      *matrix=matrix->ExistAbstract(*bdd_variable_map[var]);
    }
    else if(it->type==quantifiert::UNIVERSAL)
    {
      #if 0
      std::cout << "BDD A: " << var << ", " <<
        matrix->nodeCount() << " nodes" << std::endl;
      #endif

      *matrix=matrix->UnivAbstract(*bdd_variable_map[var]);
    }
    else
      throw "unquantified variable";
  }

  if(*matrix==bdd_manager->bddOne())
  {
    compress_certificate();
    return P_SATISFIABLE;
  }
  else if(*matrix==bdd_manager->bddZero())
  {
    model_bdds.clear();
    return P_UNSATISFIABLE;
  }
  else
    return P_ERROR;
}

/*******************************************************************\

Function: qbf_bdd_coret::is_in_core

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

bool qbf_bdd_coret::is_in_core(literalt l) const
{
  throw "nyi";
}

/*******************************************************************\

Function: qbf_bdd_coret::m_get

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

qdimacs_coret::modeltypet qbf_bdd_coret::m_get(literalt a) const
{
  throw "nyi";
}

/*******************************************************************\

Function: qbf_bdd_coret::new_variable

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

literalt qbf_bdd_coret::new_variable()
{
  literalt res=qbf_bdd_certificatet::new_variable();

  bdd_variable_map.resize(res.var_no()+1, NULL);
  BDD &var=*(new BDD());
  var=bdd_manager->bddVar();
  bdd_variable_map[res.var_no()]=&var;

  return res;
}

/*******************************************************************\

Function: qbf_bdd_coret::lcnf

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

void qbf_bdd_coret::lcnf(const bvt &bv)
{
  bvt new_bv;

  if(process_clause(bv, new_bv))
    return;

  BDD clause(bdd_manager->bddZero());

  for(const literalt &l : new_bv)
  {
    BDD v(*bdd_variable_map[l.var_no()]);

    if(l.sign())
      v=~v;

    clause|=v;
  }

  *matrix&=clause;
}

/*******************************************************************\

Function: qbf_bdd_coret::lor

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

literalt qbf_bdd_coret::lor(literalt a, literalt b)
{
  literalt nl=new_variable();

  BDD abdd(*bdd_variable_map[a.var_no()]);
  BDD bbdd(*bdd_variable_map[b.var_no()]);

  if(a.sign())
    abdd=~abdd;
  if(b.sign())
    bbdd=~bbdd;

  *bdd_variable_map[nl.var_no()]|=abdd | bbdd;

  return nl;
}

/*******************************************************************\

Function: qbf_bdd_coret::lor

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

literalt qbf_bdd_coret::lor(const bvt &bv)
{
  for(const literalt &literal : bv)
  {
    if(literal==const_literal(true))
      return literal;
  }

  literalt nl=new_variable();

  BDD &orbdd=*bdd_variable_map[nl.var_no()];

  for(const literalt &literal : bv)
  {
    if(literal==const_literal(false))
      continue;

    BDD v(*bdd_variable_map[literal.var_no()]);
    if(literal.sign())
      v=~v;

    orbdd|=v;
  }

  return nl;
}

/*******************************************************************\

Function: qbf_bdd_coret::compress_certificate

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

void qbf_bdd_coret::compress_certificate(void)
{
  status() << "Compressing Certificate" << eom;

  for(const quantifiert &quantifier : quantifiers)
  {
    if(quantifier.type==quantifiert::EXISTENTIAL)
    {
      const BDD &var=*bdd_variable_map[quantifier.var_no];
      const BDD &model=*model_bdds[quantifier.var_no];

      if(model==bdd_manager->bddOne() ||
         model==bdd_manager->bddZero())
      {
        for(const quantifiert &quantifier2 : quantifier)
        {
          BDD &model2=*model_bdds[quantifier2.var_no];

          if(model==bdd_manager->bddZero())
            model2=model2.AndAbstract(~var, var);
          else
            model2=model2.AndAbstract(var, var);
        }
      }
    }
  }
}

/*******************************************************************\

Function: qbf_bdd_certificatet::f_get

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

const exprt qbf_bdd_certificatet::f_get(literalt l)
{
  quantifiert q;
  if(!find_quantifier(l, q))
    throw "no model for unquantified variable";

  // universal?
  if(q.type==quantifiert::UNIVERSAL)
  {
    assert(l.var_no()!=0);
    variable_mapt::const_iterator it=variable_map.find(l.var_no());

    if(it==variable_map.end())
      throw "variable map error";

    const exprt &sym=it->second.first;
    unsigned index=it->second.second;

    exprt extract_expr(ID_extractbit, typet(ID_bool));
    extract_expr.copy_to_operands(sym);

    typet uint_type(ID_unsignedbv);
    uint_type.set(ID_width, 32);
    extract_expr.copy_to_operands(from_integer(index, uint_type));

    if(l.sign())
      extract_expr.negate();

    return extract_expr;
  }
  else
  {
    // skolem functions for existentials
    assert(q.type==quantifiert::EXISTENTIAL);

    function_cachet::const_iterator it=function_cache.find(l.var_no());
    if(it!=function_cache.end())
    {
      #if 0
      std::cout << "CACHE HIT for " << l.dimacs() << std::endl;
      #endif

      if(l.sign())
        return not_exprt(it->second);
      else
        return it->second;
    }

    // no cached function, so construct one

    assert(model_bdds[l.var_no()]!=NULL);
    BDD &model=*model_bdds[l.var_no()];

    #if 0
    std::cout << "Model " << l.var_no() << std::endl;
    model.PrintMinterm();
    #endif

    int *cube;
    DdGen *generator;

    exprt result=or_exprt();

    Cudd_ForeachPrime(
      bdd_manager->getManager(),
      model.getNode(),
      model.getNode(),
      generator,
      cube)
    {
      exprt prime=and_exprt();

      #if 0
      std::cout << "CUBE: ";
      for(signed i=0; i<bdd_manager->ReadSize(); i++)
        std::cout << cube[i];
      std::cout << std::endl;
      #endif

      for(signed i=0; i<bdd_manager->ReadSize(); i++)
      {
        if(quantifiers[i].var_no==l.var_no())
          break; // is this sound?

        if(cube[i]!=2)
        {
          exprt subf=f_get(literalt(quantifiers[i].var_no, (cube[i]==1)));
          prime.move_to_operands(subf);
        }
      }

      simplify_extractbits(prime);

      if(prime.operands().empty())
        result.copy_to_operands(true_exprt());
      else if(prime.operands().size()==1)
        result.move_to_operands(prime.op0());
      else
        result.move_to_operands(prime);
    }

    cube=NULL; // cube is free'd by nextCube

    exprt final;

    if(result.operands().empty())
      final=false_exprt();
    else if(result.operands().size()==1)
      final=result.op0();
    else
      final=result;

    function_cache[l.var_no()]=final;

    if(l.sign())
      return not_exprt(final);
    else
      return final;
  }
}

/*******************************************************************\

Function: qbf_bdd_certificatet::l_get

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

tvt qbf_bdd_certificatet::l_get(literalt a) const
{
  const BDD &model=*model_bdds[a.var_no()];

  if(model==bdd_manager->bddZero())
    return tvt(a.sign()?tvt::tv_enumt::TV_TRUE:tvt::tv_enumt::TV_FALSE);
  else if(model==bdd_manager->bddOne())
    return tvt(a.sign()?tvt::tv_enumt::TV_FALSE:tvt::tv_enumt::TV_TRUE);
  else
    return tvt(tvt::tv_enumt::TV_UNKNOWN);
}
