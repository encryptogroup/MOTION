#pragma once

#include "common.h"

class bmc_gct;


simple_circuitt compile_bool(
  goto_programt const &func,
  class goto_modulet &module,
  bmc_gct &bmc,
  messaget& msg);

