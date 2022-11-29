/*******************************************************************\

Module: Loop Acceleration

Author: Matt Lewis

\*******************************************************************/

#include <iostream>

#include <goto-programs/goto_program.h>

#include "path.h"

void output_path(
  const patht &path,
  const goto_programt &program,
  const namespacet &ns,
  std::ostream &str)
{
  for(const auto &step : path)
    program.output_instruction(ns, "path", str, step.loc);
}
