#ifndef CBMC_GC_BV_CBMC_GC_DEFAULT_H
#define CBMC_GC_BV_CBMC_GC_DEFAULT_H

#include <cbmc/bv_cbmc.h>
#include "building_blocks/building_blocks.h"


enum class expr_optimizationt
{
  size,
  depth,
};

// Responsible for converting expressions (exprt) to vectors of literals (bvt). The actual
// conversion to boolean formulas is done using the operation_convertert interface.
// 
// In the methods that are overwitten, often the only change is that operation_convertert is used
// instead of bvutils.
class boolean_expr_loweringt : public bv_cbmct
{
public:
  boolean_expr_loweringt(const namespacet &_ns, propt &_prop, building_blockst _conv, expr_optimizationt opt) :
    bv_cbmct(_ns, _prop),
    conv{_conv},
    optimization{opt} {}
  
  virtual ~boolean_expr_loweringt() {}

  virtual bvt convert_add_sub(const exprt &expr) override;
  virtual bvt convert_unary_minus(const unary_exprt &expr) override;
  virtual bvt convert_mult(const exprt &expr) override;
  virtual bvt convert_div(const div_exprt &expr) override;
  virtual bvt convert_mod(const mod_exprt &expr) override;
  virtual bvt convert_index(const index_exprt &expr) override;
  virtual bvt convert_shift(const binary_exprt &expr) override;
  virtual bvt convert_if(const if_exprt &expr) override;
  virtual literalt convert_equality(const equal_exprt &expr) override;
  virtual literalt convert_bv_rel(const exprt &expr) override;

  bvt convert_add_sub_lowdepth(const exprt &expr);

  boolbv_mapt &get_map() { return map; }
  propt& get_prop() { return prop; }

private:
  building_blockst conv;
  expr_optimizationt optimization;
};

#endif
