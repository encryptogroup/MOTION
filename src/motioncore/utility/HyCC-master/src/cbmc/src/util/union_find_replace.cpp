/*******************************************************************\

Module: util

Author: Romain Brenguier, romain.brenguier@diffblue.com

\*******************************************************************/

#include "union_find_replace.h"

/// Keeps a map of symbols to expressions, such as none of the mapped values
/// exist as a key
/// \param a: an expression of type char array
/// \param b: an expression to map it to, which should be either a symbol
///             a string_exprt, an array_exprt, an array_of_exprt or an
///             if_exprt with branches of the previous kind
/// \return the new mapped value
exprt union_find_replacet::make_union(const exprt &a, const exprt &b)
{
  const exprt &lhs_root = find(a);
  const exprt &rhs_root = find(b);
  if(lhs_root != rhs_root)
    map[lhs_root] = rhs_root;
  return rhs_root;
}

/// Replace subexpressions of `expr` by a canonical element of the set they
/// belong to.
/// \param expr: an expression, modified in place
/// \return true if expr is left unchanged
bool union_find_replacet::replace_expr(exprt &expr) const
{
  bool unchanged = ::replace_expr(map, expr);
  while(!unchanged && !::replace_expr(map, expr))
    continue;
  return unchanged;
}

/// \param expr: an expression
/// \return canonical representation for expressions which belong to the same
///         set
exprt union_find_replacet::find(exprt expr) const
{
  replace_expr(expr);
  return expr;
}

/// \return pairs of expression composed of expressions and a canonical
///         expression for the set they below to.
std::vector<std::pair<exprt, exprt>> union_find_replacet::to_vector() const
{
  std::vector<std::pair<exprt, exprt>> equations;
  for(const auto &pair : map)
    equations.emplace_back(pair.first, find(pair.second));
  return equations;
}
