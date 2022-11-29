#ifndef CBMC_GC_BUILDING_BLOCKS_H
#define CBMC_GC_BUILDING_BLOCKS_H

#include <solvers/prop/prop.h>
#include <solvers/flattening/bv_utils.h>


using UnaryConverterFunc = bvt (*)(propt&, bvt const&);
using BinaryConverterFunc = bvt (*)(propt&, bvt const&, bvt const&);
using AddSubConverterFunc = std::pair<bvt, literalt> (*)(propt&, bvt const&, bvt const&);
using ComparisonConverterFunc = literalt (*)(propt&, bvt const&, bvt const&);
using DivisionConverterFunc = std::pair<bvt, bvt> (*)(propt&, bvt const&, bvt const&);

struct building_blockst
{
  UnaryConverterFunc negator;
  AddSubConverterFunc adder;
  AddSubConverterFunc subtractor;
  // Since the width of the output is same as the width of the inputs signed/unsigned multiplication
  // is equivalent.
  BinaryConverterFunc multiplier;
  DivisionConverterFunc signed_divider;
  DivisionConverterFunc unsigned_divider;
  bvt (*shifter)(propt&, bvt const&, bv_utilst::shiftt, bvt const&);

  ComparisonConverterFunc equal;
  literalt (*less_than)(propt&, bvt const&, bvt const&, bool);

  bvt (*multiplexer)(propt&, bvt const&, std::vector<bvt> const&);
};


// Helpers
//------------------------------------------------------------------------------
inline bvt adder_subtractor(building_blockst const &conv, propt &prop, bvt const &a, bvt const &b, bool subtract)
{
  if(subtract)
    return conv.subtractor(prop, a, b).first;
  
  return conv.adder(prop, a, b).first;
}

inline bool is_constant(const bvt &bv)
{
  forall_literals(it, bv)
    if(!it->is_constant())
      return false;

  return true;
}

inline bvt inverter(bvt const &bv)
{
  bvt inv; inv.reserve(bv.size());
  for(auto &l: bv)
    inv.push_back(!l);
  
  return inv;
}

// selects a vector out of two by the use of a condition literal
inline bvt bv_if(propt &prop, const literalt cond, const bvt &op1, const bvt &op2)
{
  assert(op1.size() == op2.size());

  bvt bv;
  bv.resize(op1.size());

  for (unsigned i = 0; i < bv.size(); i++)
    bv[i] = prop.lselect(cond, op1[i], op2[i]);

  return bv;
}


std::pair<literalt, literalt> full_adder(literalt a, literalt b, literalt c);

inline literalt comparer(building_blockst const &bb, propt &prop, const bvt &bv0, irep_idt id, const bvt &bv1, bv_utilst::representationt rep)
{
  if(id==ID_equal)
    return bb.equal(prop, bv0, bv1);
  else if(id==ID_notequal)
    return !bb.equal(prop, bv0, bv1);
  else if(id==ID_le)
    return !bb.less_than(prop, bv1, bv0, rep == bv_utilst::SIGNED);
  else if(id==ID_lt)
    return bb.less_than(prop, bv0, bv1, rep == bv_utilst::SIGNED);
  else if(id==ID_ge)
    return !bb.less_than(prop, bv0, bv1, rep == bv_utilst::SIGNED);
  else if(id==ID_gt)
    return bb.less_than(prop, bv1, bv0, rep == bv_utilst::SIGNED);
  else
    assert(false);
}


// Default building blocks
//------------------------------------------------------------------------------
std::pair<bvt, literalt> basic_adder(propt &prop, bvt const &a, bvt const &b, literalt carry_in);
std::pair<bvt, literalt> adder(propt &prop, bvt const &a, bvt const &b);
std::pair<bvt, literalt> subtractor(propt &prop, bvt const &a, bvt const &b);
bvt multiplier(propt &prop, bvt const &a, bvt const &b);
bvt negator(propt &prop, bvt const &a);
std::pair<bvt, bvt> signed_divider(propt &prop, bvt const &a, bvt const &b);
std::pair<bvt, bvt> unsigned_divider(propt &prop, bvt const &a, bvt const &b);
bvt shifter(propt &prop, bvt const &in, bv_utilst::shiftt shift, const bvt &dist);
bvt multiplexer(propt &prop, bvt const &selector_terms, std::vector<bvt> const &columns);
literalt less_than(propt &prop, const bvt &bv0, const bvt &bv1, bool is_signed);


// Low-depth building bocks
//------------------------------------------------------------------------------
std::pair<bvt, literalt> adder_lowdepth(propt &prop, bvt const &a, bvt const &b);
std::pair<bvt, literalt> subtractor_lowdepth(propt &prop, bvt const &a, bvt const &b);
bvt multiplier_lowdepth(propt &prop, bvt const &a, bvt const &b);
bvt negator_lowdepth(propt &prop, bvt const &a);
bvt multiplier_adder_lowdepth(propt &prop, std::vector<std::pair<bool, bvt>> &&summands, std::vector<std::vector<bvt>> const &mults);
std::pair<bvt, bvt> signed_divider_lowdepth(propt &prop, bvt const &a, bvt const &b);
bvt multiplexer_lowdepth(propt &prop, const bvt &selector, std::vector<bvt> const &columns);
bvt shifter_lowdepth(propt &prop, bvt const &in, const bv_utilst::shiftt shift, const bvt &dist);
literalt equal_lowdepth(propt &prop, bvt const& bv0, const bvt& bv1);
literalt less_than_lowdepth(propt &prop, const bvt &bv0, const bvt &bv1, bool is_signed);


//------------------------------------------------------------------------------
inline building_blockst get_default_building_blocks()
{
  building_blockst bb;
  bb.adder = adder;
  bb.negator = negator;
  bb.subtractor = subtractor;
  bb.multiplier = multiplier;
  bb.signed_divider = signed_divider;
  bb.unsigned_divider = unsigned_divider;
  bb.shifter = shifter;
  bb.multiplexer = multiplexer;
  bb.equal = equal_lowdepth;
  bb.less_than = less_than;

  return bb;
}

inline building_blockst get_lowdepth_building_blocks()
{
  building_blockst bb;
  bb.adder = adder_lowdepth;
  bb.negator = negator_lowdepth;
  bb.subtractor = subtractor_lowdepth;
  bb.multiplier = multiplier_lowdepth;
  bb.signed_divider = signed_divider_lowdepth;
  bb.unsigned_divider = unsigned_divider;
  bb.shifter = shifter_lowdepth;
  bb.multiplexer = multiplexer_lowdepth;
  bb.equal = equal_lowdepth;
  bb.less_than = less_than_lowdepth;

  return bb;
}


#endif
