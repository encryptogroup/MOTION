#ifndef CPROVER_BMC_GC_PARSE_OPTIONS_H
#define CPROVER_BMC_GC_PARSE_OPTIONS_H

#include <cbmc/bmc.h>

class bmc_gct : public bmct
{
public:
  bmc_gct(
    const optionst &_options,
    const symbol_tablet &_symbol_table,
    message_handlert &_message_handler,
    prop_convt& _prop_conv) :
    bmct(_options, _symbol_table, _message_handler, _prop_conv) {}
  
  virtual void setup_unwind() override { bmct::setup_unwind(); }
  symex_target_equationt& symex_equation() { return equation; }
  symex_bmct& symex() { return bmct::symex; }
};

#endif
