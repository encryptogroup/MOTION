/*******************************************************************\

Module:

Author: Daniel Kroening, kroening@kroening.com

\*******************************************************************/

#include <ostream>

#include "ansi_c_scope.h"

/*******************************************************************\

Function: ansi_c_scopet::print

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

void ansi_c_scopet::print(std::ostream &out) const
{
  out << "Prefix: " << prefix << "\n";

  for(const auto &name : name_map)
  {
    out << "  ID: " << name.first
        << " CLASS: " << name.second.id_class
        << "\n";
  }
}
