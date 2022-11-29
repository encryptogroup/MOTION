/*******************************************************************\

Module:

Author: Daniel Kroening, kroening@kroening.com

\*******************************************************************/

#ifndef CPROVER_ANSI_C_ANSI_C_INTERNAL_ADDITIONS_H
#define CPROVER_ANSI_C_ANSI_C_INTERNAL_ADDITIONS_H

#include <string>

void ansi_c_internal_additions(std::string &code);
void ansi_c_architecture_strings(std::string &code);

extern const char gcc_builtin_headers_generic[];
extern const char gcc_builtin_headers_ia32[];
extern const char arm_builtin_headers[];

#endif // CPROVER_ANSI_C_ANSI_C_INTERNAL_ADDITIONS_H
