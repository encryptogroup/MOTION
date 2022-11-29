/*******************************************************************\

Module: A minimalistic BDD library, following Bryant's original paper
        and Andersen's lecture notes

Author: Daniel Kroening, kroening@kroening.com

\*******************************************************************/

#include <cassert>

#include <iostream>

#include "miniBDD.h"

#define forall_nodes(it) for(nodest::const_iterator it=nodes.begin(); \
  it!=nodes.end(); it++)

void mini_bdd_nodet::remove_reference()
{
  assert(reference_counter!=0);

  reference_counter--;

  if(reference_counter==0 && node_number>=2)
  {
    mini_bdd_mgrt::reverse_keyt reverse_key(var, low, high);
    mgr->reverse_map.erase(reverse_key);
    low.clear();
    high.clear();
    mgr->free.push(this);
  }
}

mini_bddt mini_bdd_mgrt::Var(const std::string &label)
{
  var_table.push_back(var_table_entryt(label));
  true_bdd.node->var=var_table.size()+1;
  false_bdd.node->var=var_table.size()+1;
  return mk(var_table.size(), false_bdd, true_bdd);
}

void mini_bdd_mgrt::DumpDot(std::ostream &out, bool suppress_zero) const
{
  out << "digraph BDD {\n";

  out << "center = true;\n";

  out << "{ rank = same; { node [style=invis]; \"T\" };\n";

  if(!suppress_zero)
    out << "  { node [shape=box,fontsize=24]; \"0\"; }\n";

  out << "  { node [shape=box,fontsize=24]; \"1\"; }\n"
      << "}\n\n";

  for(unsigned v=0; v<var_table.size(); v++)
  {
    out << "{ rank=same; "
           "{ node [shape=plaintext,fontname=\"Times Italic\",fontsize=24] \" "
        << var_table[v].label
        << " \" }; ";

    forall_nodes(u)
      if(u->var==(v+1) && u->reference_counter!=0)
        out << '"' << u->node_number << "\"; ";

    out << "}\n";
  }

  out << '\n';

  out << "{ edge [style = invis];";

  for(unsigned v=0; v<var_table.size(); v++)
    out << " \" " << var_table[v].label
        << " \" ->";

  out << " \"T\"; }\n";

  out << '\n';

  forall_nodes(u)
  {
    if(u->reference_counter==0)
      continue;
    if(u->node_number<=1)
      continue;

    if(!suppress_zero || u->high.node_number()!=0)
      out << '"' << u->node_number << '"' << " -> "
          << '"' << u->high.node_number() << '"'
          << " [style=solid,arrowsize=\".75\"];\n";

    if(!suppress_zero || u->low.node_number()!=0)
      out << '"' << u->node_number << '"' << " -> "
          << '"' << u->low.node_number() << '"'
          << " [style=dashed,arrowsize=\".75\"];\n";

    out << '\n';
  }

  out << "}\n";
}

void mini_bdd_mgrt::DumpTikZ(
  std::ostream &out,
  bool suppress_zero,
  bool node_numbers) const
{
  out << "\\begin{tikzpicture}[node distance=1cm]\n";

  out << "  \\tikzstyle{BDDnode}=[circle,draw=black,"
         "inner sep=0pt,minimum size=5mm]\n";

  for(unsigned v=0; v<var_table.size(); v++)
  {
    out << "  \\node[";

    if(v!=0)
      out << "below of=v" << var_table[v-1].label;

    out << "] (v" << var_table[v].label << ") {$\\mathit{"
        << var_table[v].label << "}$};\n";

    unsigned previous=0;

    forall_nodes(u)
    {
      if(u->var==(v+1) && u->reference_counter!=0)
      {
        out << "  \\node[xshift=0cm, BDDnode, ";

        if(previous==0)
          out << "right of=v" << var_table[v].label;
        else
          out << "right of=n" << previous;

        out << "] (n" << u->node_number << ") {";
        if(node_numbers)
          out << "\\small $" << u->node_number << "$";
        out << "};\n";
        previous=u->node_number;
      }
    }

    out << '\n';
  }

  out << '\n';

  out << "  % terminals\n";
  out << "  \\node[draw=black, style=rectangle, below of=v"
      << var_table.back().label
      << ", xshift=1cm] (n1) {$1$};\n";

  if(!suppress_zero)
    out << "  \\node[draw=black, style=rectangle, left of=n1] (n0) {$0$};\n";

  out << '\n';

  out << "  % edges\n";
  out << '\n';

  forall_nodes(u)
  {
    if(u->reference_counter!=0 && u->node_number>=2)
    {
      if(!suppress_zero || u->low.node_number()!=0)
        out << "  \\draw[->,dashed] (n" << u->node_number << ") -> (n"
            << u->low.node_number() << ");\n";

      if(!suppress_zero || u->high.node_number()!=0)
        out << "  \\draw[->] (n" << u->node_number << ") -> (n"
            << u->high.node_number() << ");\n";
    }
  }

  out << '\n';

  out << "\\end{tikzpicture}\n";
}

class mini_bdd_applyt
{
public:
  inline explicit mini_bdd_applyt(bool (*_fkt)(bool, bool)):fkt(_fkt)
  {
  }

  mini_bddt operator()(const mini_bddt &x, const mini_bddt &y)
  {
    return APP(x, y);
  }

protected:
  bool (*fkt)(bool, bool);
  mini_bddt APP(const mini_bddt &x, const mini_bddt &y);

  typedef std::map<std::pair<unsigned, unsigned>, mini_bddt> Gt;
  Gt G;
};

mini_bddt mini_bdd_applyt::APP(const mini_bddt &x, const mini_bddt &y)
{
  assert(x.is_initialized() && y.is_initialized());
  assert(x.node->mgr==y.node->mgr);

  // dynamic programming
  std::pair<unsigned, unsigned> key(x.node_number(), y.node_number());
  Gt::const_iterator G_it=G.find(key);
  if(G_it!=G.end())
    return G_it->second;

  mini_bdd_mgrt *mgr=x.node->mgr;

  mini_bddt u;

  if(x.is_constant() && y.is_constant())
    u=mini_bddt(fkt(x.is_true(), y.is_true())?mgr->True():mgr->False());
  else if(x.var()==y.var())
    u=mgr->mk(x.var(),
              APP(x.low(), y.low()),
              APP(x.high(), y.high()));
  else if(x.var()<y.var())
    u=mgr->mk(x.var(),
              APP(x.low(), y),
              APP(x.high(), y));
  else /* x.var() > y.var() */
    u=mgr->mk(y.var(),
              APP(x, y.low()),
              APP(x, y.high()));

  G[key]=u;

  return u;
}

bool equal_fkt(bool x, bool y)
{
  return x==y;
}

mini_bddt mini_bddt::operator==(const mini_bddt &other) const
{
  return mini_bdd_applyt(equal_fkt)(*this, other);
}

bool xor_fkt(bool x, bool y)
{
  return x^y;
}

mini_bddt mini_bddt::operator^(const mini_bddt &other) const
{
  return mini_bdd_applyt(xor_fkt)(*this, other);
}

mini_bddt mini_bddt::operator!() const
{
  return node->mgr->True()^*this;
}

bool and_fkt(bool x, bool y)
{
  return x && y;
}

mini_bddt mini_bddt::operator&(const mini_bddt &other) const
{
  return mini_bdd_applyt(and_fkt)(*this, other);
}

bool or_fkt(bool x, bool y)
{
  return x || y;
}

mini_bddt mini_bddt::operator|(const mini_bddt &other) const
{
  return mini_bdd_applyt(or_fkt)(*this, other);
}

mini_bdd_mgrt::mini_bdd_mgrt()
{
  // add true/false nodes
  nodes.push_back(mini_bdd_nodet(this, 0, 0, mini_bddt(), mini_bddt()));
  false_bdd=mini_bddt(&nodes.back());
  nodes.push_back(mini_bdd_nodet(this, 1, 1, mini_bddt(), mini_bddt()));
  true_bdd=mini_bddt(&nodes.back());
}

mini_bdd_mgrt::~mini_bdd_mgrt()
{
}

mini_bddt mini_bdd_mgrt::mk(
  unsigned var,
  const mini_bddt &low,
  const mini_bddt &high)
{
  assert(var<=var_table.size());

  if(low.node_number()==high.node_number())
    return low;
  else
  {
    reverse_keyt reverse_key(var, low, high);
    reverse_mapt::const_iterator it=reverse_map.find(reverse_key);

    if(it!=reverse_map.end())
      return mini_bddt(it->second);
    else
    {
      mini_bdd_nodet *n;

      if(free.empty())
      {
        unsigned new_number=nodes.back().node_number+1;
        nodes.push_back(mini_bdd_nodet(this, var, new_number, low, high));
        n=&nodes.back();
      }
      else // reuse a node
      {
        n=free.top();
        free.pop();
        n->var=var;
        n->low=low;
        n->high=high;
      }

      reverse_map[reverse_key]=n;
      return mini_bddt(n);
    }
  }
}

bool mini_bdd_mgrt::reverse_keyt::operator<(
  const mini_bdd_mgrt::reverse_keyt &other) const
{
  if(var<other.var || low<other.low)
    return true;
  if(var>other.var || low>other.low)
    return false;

  return high<other.high;
}

void mini_bdd_mgrt::DumpTable(std::ostream &out) const
{
  out << "\\# & \\mathit{var} & \\mathit{low} &"
         " \\mathit{high} \\\\\\hline\n";

  forall_nodes(it)
  {
    out << it->node_number << " & ";

    if(it->node_number==0 || it->node_number==1)
      out << it->var << " & & \\\\";
    else if(it->reference_counter==0)
      out << "- & - & - \\\\";
    else
      out << it->var << "\\," << var_table[it->var-1].label << " & "
          << it->low.node_number() << " & " << it->high.node_number()
          << " \\\\";

    if(it->node_number==1)
      out << "\\hline";

    out << " % " << it->reference_counter << '\n';
  }
}

class restrictt
{
public:
  inline restrictt(const unsigned _var, const bool _value):
    var(_var), value(_value)
  {
  }

  mini_bddt operator()(const mini_bddt &u) { return RES(u); }

protected:
  const unsigned var;
  const bool value;

  mini_bddt RES(const mini_bddt &u);
};

mini_bddt restrictt::RES(const mini_bddt &u)
{
  // replace 'var' in 'u' by constant 'value'

  assert(u.is_initialized());
  mini_bdd_mgrt *mgr=u.node->mgr;

  mini_bddt t;

  if(u.var()>var)
    t=u;
  else if(u.var()<var)
    t=mgr->mk(u.var(), RES(u.low()), RES(u.high()));
  else // u.var()==var
    t=RES(value?u.high():u.low());

  return t;
}

mini_bddt restrict(const mini_bddt &u, unsigned var, const bool value)
{
  return restrictt(var, value)(u);
}

mini_bddt exists(const mini_bddt &u, const unsigned var)
{
  // u[var/0] OR u[var/1]
  return restrict(u, var, false) |
         restrict(u, var, true);
}

mini_bddt substitute(const mini_bddt &t, unsigned var, const mini_bddt &tp)
{
  // t[var/tp] =
  //  ( tp &t[var/1]) |
  //  (!tp &t[var/0])

  return ( tp &restrict(t, var, true)) |
         ((!tp) &restrict(t, var, false));
}

void cubes(const mini_bddt &u, const std::string &path, std::string &result)
{
  if(u.is_false())
    return;
  else if(u.is_true())
  {
    result+=path;
    result+='\n';
    return;
  }

  mini_bdd_mgrt *mgr=u.node->mgr;
  std::string path_low=path;
  std::string path_high=path;
  if(!path.empty())
  {
    path_low+=" & ";
    path_high+=" & ";
  }
  path_low+='!'+mgr->var_table[u.var()-1].label;
  path_high+=mgr->var_table[u.var()-1].label;
  cubes(u.low(), path_low, result);
  cubes(u.high(), path_high, result);
}

std::string cubes(const mini_bddt &u)
{
  if(u.is_false())
    return "false\n";
  else if(u.is_true())
    return "true\n";
  else
  {
    std::string result;
    cubes(u, "", result);
    return result;
  }
}

bool OneSat(const mini_bddt &v, std::map<unsigned, bool> &assignment)
{
  // http://www.ecs.umass.edu/ece/labs/vlsicad/ece667/reading/somenzi99bdd.pdf
  if(v.is_true())
    return true;
  else if(v.is_false())
    return false;
  else
  {
    assignment[v.var()]=true;
    if(OneSat(v.high(), assignment))
      return true;
    assignment[v.var()]=false;
    return OneSat(v.low(), assignment);
  }
}
