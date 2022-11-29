/*******************************************************************\

Module: CBMC-GC Main Module

Copied and slightly modified from cbmc/cbmc_main.cpp

\*******************************************************************/

/*

  CBMC
  Bounded Model Checking for ANSI-C
  Copyright (C) 2001-2014 Daniel Kroening <kroening@kroening.com>

*/

#include <util/unicode.h>

#include <iostream>

#include "cbmc_gc_parse_options.h"

#include "building_blocks/building_blocks.h"
#include "circuit_creator_default.h"

/*******************************************************************\

Function: main / wmain

  Inputs:

 Outputs:

 Purpose:

\*******************************************************************/

#ifdef IREP_HASH_STATS
extern unsigned long long irep_hash_cnt;
extern unsigned long long irep_cmp_cnt;
extern unsigned long long irep_cmp_ne_cnt;
#endif

#ifdef _MSC_VER
int wmain(int argc, const wchar_t **argv_wide)
{
  const char **argv=narrow_argv(argc, argv_wide);
#else
int main(int argc, const char **argv)
{
#endif
  cbmc_gc_parse_optionst parse_options(argc, argv);

  // My personal playground
  /*circuit_creator_defaultt cc;
  literalt one = const_literal(true);
  literalt zero = const_literal(false);
  auto res = adder(cc, {one, zero, zero, zero, zero, one, zero, zero}, {one, one, one, one, one, zero, one, one});
  auto neg = res.first[res.first.size() - 1];
  assert(neg.is_constant());
  //std::cout << "neg = " << neg.is_true() << std::endl;
  
  std::cout << "one.sign() = " << one.sign() << std::endl;
  std::cout << "zero.sign() = " << zero.sign() << std::endl;*/
    
  int res=parse_options.main();

  #ifdef IREP_HASH_STATS
  std::cout << "IREP_HASH_CNT=" << irep_hash_cnt << std::endl;
  std::cout << "IREP_CMP_CNT=" << irep_cmp_cnt << std::endl;
  std::cout << "IREP_CMP_NE_CNT=" << irep_cmp_ne_cnt << std::endl;
  #endif

  return res;
}
