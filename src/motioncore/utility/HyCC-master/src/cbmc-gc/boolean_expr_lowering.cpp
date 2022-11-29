#include "boolean_expr_lowering.h"

#include <util/arith_tools.h>
#include <solvers/floatbv/float_utils.h>
#include <util/base_type.h>
#include <solvers/flattening/flatten_byte_operators.h>

#include <libcircuit/utils.h>

#include <iostream>
#include <limits>


// [CBMC-GC] The functions in here are mostly copied verbatim from boolbvt. Changes are marked with
//           [CBMC-GC].


static std::vector<bvt> get_mul_operands(boolean_expr_loweringt &bel, exprt const &mul, unsigned width)
{
  std::vector<bvt> mult;
  for(exprt::operandst::const_iterator it2=mul.operands().begin(); it2!=mul.operands().end(); it2++)
  {
    if(it2->type()!=mul.type())
      throw "multiplication with mixed types";

    mult.push_back(bel.convert_bv(*it2));
    if(mult.back().size()!=width)
      throw "convert_add_sub: unexpected operand width";
  }

  assert(mult.size());

  return mult;
}

bvt boolean_expr_loweringt::convert_add_sub_lowdepth(const exprt &expr)
{
  assert(expr.id()==ID_plus || expr.id()=="no-overflow-plus");

  const typet &type=ns.follow(expr.type());
  assert(type.id() == ID_unsignedbv || type.id() == ID_signedbv);

  std::size_t width=boolbv_width(type);

  if(width==0)
    return conversion_failed(expr);

  const exprt::operandst &operands=expr.operands();

  if(operands.empty())
    throw "operator "+expr.id_string()+" takes at least one operand";

  bool subtract=(expr.id()==ID_minus ||
                 expr.id()=="no-overflow-minus");

  const exprt &op0=expr.op0();

  if(op0.type()!=type)
  {
    std::cerr << expr.pretty() << std::endl;
    throw "add/sub with mixed types";
  }

  std::vector<std::pair<bool, bvt>> summands;
  std::vector<std::pair<bool, std::vector<bvt>>> mults;
  for(exprt::operandst::const_iterator it=operands.begin(); it!=operands.end(); it++)
  {
    if(it->type()!=type)
    {
      std::cerr << expr.pretty() << std::endl;
      throw "add/sub with mixed types";
    }

    // [CBMC-GC] CBMC encodes subtraction as an addition followed by a unary minus, but for us it's
    //           better to handle subtractions directly.
    if(it->id()=="unary-" || it->id()=="no-overflow-unary-minus")
    {
      const exprt::operandst &operands_sub= it->operands();
      if(operands_sub.size()!=1) {
        throw "unary minus takes one operand";
      }
      const exprt &op_sub0=it->op0();
      if(op_sub0.type()!=expr.type())
      {
        std::cerr << expr.pretty() << std::endl;
        throw "add/sub with mixed types";
      }

      if(op_sub0.id() == ID_mult)
        mults.push_back({true, get_mul_operands(*this, op_sub0, width)});
      else
      {
        bvt op = convert_bv(op_sub0);
        if(op.size()!=width)
          throw "convert_add_sub: unexpected operand width";

        summands.push_back({true, op});
      }
    }
    else if(it->id() == ID_mult)
      mults.push_back({false, get_mul_operands(*this, *it, width)});
    else
    {
      bvt op = convert_bv(*it);
      if(op.size()!=width)
        throw "convert_add_sub: unexpected operand width";

      summands.push_back({subtract, op});
    }
  }

  return multiplier_adder_lowdepth(prop, std::move(summands), std::move(mults));
}


bvt boolean_expr_loweringt::convert_add_sub(const exprt &expr)
{
  const typet &type=ns.follow(expr.type());

  if(type.id()!=ID_unsignedbv &&
     type.id()!=ID_signedbv &&
     type.id()!=ID_fixedbv &&
     //type.id()!=ID_floatbv && TODO Add support for FP!
     type.id()!=ID_range &&
     type.id()!=ID_complex &&
     type.id()!=ID_vector)
    return conversion_failed(expr);

  std::size_t width=boolbv_width(type);

  if(width==0)
    return conversion_failed(expr);

  const exprt::operandst &operands=expr.operands();

  if(operands.empty())
    throw "operator "+expr.id_string()+" takes at least one operand";

  bool subtract=(expr.id()==ID_minus ||
                 expr.id()=="no-overflow-minus");

  // [CBMC-GC] If we have multiple additions in a row we can use the depth-efficient carry-save adder.
  if(optimization == expr_optimizationt::depth && (type.id() == ID_unsignedbv || type.id() == ID_signedbv))
      return convert_add_sub_lowdepth(expr);

  const exprt &op0=expr.op0();

  if(op0.type()!=type)
  {
    std::cerr << expr.pretty() << std::endl;
    throw "add/sub with mixed types";
  }

  bvt bv=convert_bv(op0);
  if(bv.size()!=width)
    throw "convert_add_sub: unexpected operand width";

  typet arithmetic_type=
    (type.id()==ID_vector || type.id()==ID_complex)?
      ns.follow(type.subtype()):type;

  for(exprt::operandst::const_iterator
      it=operands.begin()+1;
      it!=operands.end(); it++)
  {
    if(it->type()!=type)
    {
      std::cerr << expr.pretty() << std::endl;
      throw "add/sub with mixed types";
    }

    // [CBMC-GC] CBMC encodes subtraction as an addition followed by a unary minus, but for us it's
    //           better to handle subtractions directly.
    bvt op;
    bool subtract_this = false;
    if(it->id()=="unary-" || it->id()=="no-overflow-unary-minus")
    {
      const exprt::operandst &operands_sub= it->operands();
      if(operands_sub.size()!=1) {
        throw "unary minus takes one operand";
      }
      const exprt &op_sub0=it->op0();
      if(op_sub0.type()!=expr.type())
      {
        std::cerr << expr.pretty() << std::endl;
        throw "add/sub with mixed types";
      }
      op = convert_bv(op_sub0);
      subtract_this = true;
    }
    else
      op=convert_bv(*it);

    if(op.size()!=width)
      throw "convert_add_sub: unexpected operand width";

    if(type.id()==ID_vector || type.id()==ID_complex)
    {
      const typet &subtype=ns.follow(type.subtype());

      std::size_t sub_width=boolbv_width(subtype);

      if(sub_width==0 || width%sub_width!=0)
        throw "convert_add_sub: unexpected vector operand width";

      std::size_t size=width/sub_width;
      bv.resize(width);

	  // [CBMC-GC] TODO Use multiply_add() and multiple_add() for vectors, too?
      for(std::size_t i=0; i<size; i++)
      {
        bvt tmp_op;
        tmp_op.resize(sub_width);

        for(std::size_t j=0; j<tmp_op.size(); j++)
        {
          assert(i*sub_width+j<op.size());
          tmp_op[j]=op[i*sub_width+j];
        }

        bvt tmp_result;
        tmp_result.resize(sub_width);

        for(std::size_t j=0; j<tmp_result.size(); j++)
        {
          assert(i*sub_width+j<bv.size());
          tmp_result[j]=bv[i*sub_width+j];
        }

        if(type.subtype().id()==ID_floatbv)
        {
          // needs to change due to rounding mode
          float_utilst float_utils(prop, to_floatbv_type(subtype));
          tmp_result=float_utils.add_sub(tmp_result, tmp_op, subtract);
        }
        else
          // [CBMC-GC]
          tmp_result=adder_subtractor(conv, prop, tmp_result, tmp_op, subtract || subtract_this);

        assert(tmp_result.size()==sub_width);

        for(std::size_t j=0; j<tmp_result.size(); j++)
        {
          assert(i*sub_width+j<bv.size());
          bv[i*sub_width+j]=tmp_result[j];
        }
      }
    }
    else if(type.id()==ID_floatbv)
    {
      // needs to change due to rounding mode
      float_utilst float_utils(prop, to_floatbv_type(arithmetic_type));
      bv=float_utils.add_sub(bv, op, subtract);
    }
    
    // [CBMC-GC]
    // Applying additions sequentially yields the same depth as building a tree.
    bv=adder_subtractor(conv, prop, bv, op, subtract || subtract_this);
  }

  return bv;
}


bvt boolean_expr_loweringt::convert_unary_minus(const unary_exprt &expr)
{
  const typet &type=ns.follow(expr.type());

  std::size_t width=boolbv_width(type);

  if(width==0)
    return conversion_failed(expr);

  const exprt::operandst &operands=expr.operands();

  if(operands.size()!=1)
    throw "unary minus takes one operand";

  const exprt &op0=expr.op0();

  const bvt &op_bv=convert_bv(op0);

  bvtypet bvtype=get_bvtype(type);
  bvtypet op_bvtype=get_bvtype(op0.type());
  std::size_t op_width=op_bv.size();

  bool no_overflow=(expr.id()=="no-overflow-unary-minus");

  if(op_width==0 || op_width!=width)
    return conversion_failed(expr);

  if(bvtype==bvtypet::IS_UNKNOWN &&
     (type.id()==ID_vector || type.id()==ID_complex))
  {
    const typet &subtype=ns.follow(type.subtype());

    std::size_t sub_width=boolbv_width(subtype);

    if(sub_width==0 || width%sub_width!=0)
      throw "unary-: unexpected vector operand width";

    std::size_t size=width/sub_width;
    bvt bv;
    bv.resize(width);

    for(std::size_t i=0; i<size; i++)
    {
      bvt tmp_op;
      tmp_op.resize(sub_width);

      for(std::size_t j=0; j<tmp_op.size(); j++)
      {
        assert(i*sub_width+j<op_bv.size());
        tmp_op[j]=op_bv[i*sub_width+j];
      }

      bvt tmp_result;

      if(type.subtype().id()==ID_floatbv)
      {
        float_utilst float_utils(prop, to_floatbv_type(subtype));
        tmp_result=float_utils.negate(tmp_op);
      }
      else
        // [CBMC-GC]
        tmp_result=conv.negator(prop, tmp_op);

      assert(tmp_result.size()==sub_width);

      for(std::size_t j=0; j<tmp_result.size(); j++)
      {
        assert(i*sub_width+j<bv.size());
        bv[i*sub_width+j]=tmp_result[j];
      }
    }

    return bv;
  }
  else if(bvtype==bvtypet::IS_FIXED && op_bvtype==bvtypet::IS_FIXED)
  {
    // [CBMC-GC]
    return conv.negator(prop, op_bv);
  }
  else if(bvtype==bvtypet::IS_FLOAT && op_bvtype==bvtypet::IS_FLOAT)
  {
    assert(!no_overflow);
    float_utilst float_utils(prop, to_floatbv_type(expr.type()));
    return float_utils.negate(op_bv);
  }
  else if((op_bvtype==bvtypet::IS_SIGNED || op_bvtype==bvtypet::IS_UNSIGNED) &&
          (bvtype==bvtypet::IS_SIGNED || bvtype==bvtypet::IS_UNSIGNED))
  {
    // [CBMC-GC]
    return conv.negator(prop, op_bv);
  }

  return conversion_failed(expr);
}


bvt boolean_expr_loweringt::convert_mult(const exprt &expr)
{
  std::size_t width=boolbv_width(expr.type());

  if(width==0)
    return conversion_failed(expr);

  const exprt::operandst &operands=expr.operands();
  if(operands.empty())
    throw "mult without operands";

  const exprt &op0=expr.op0();

  if(expr.type().id()==ID_fixedbv)
  {
    if(op0.type()!=expr.type())
      throw "multiplication with mixed types";

    bvt bv=convert_bv(op0);
    if(bv.size()!=width)
      throw "convert_mult: unexpected operand width";

    std::size_t fraction_bits=
      to_fixedbv_type(expr.type()).get_fraction_bits();

    // do a sign extension by fraction_bits bits
    bv=bv_utils.sign_extension(bv, bv.size()+fraction_bits);

    for(exprt::operandst::const_iterator it=operands.begin()+1;
        it!=operands.end(); it++)
    {
      if(it->type()!=expr.type())
        throw "multiplication with mixed types";

      bvt op=convert_bv(*it);

      if(op.size()!=width)
        throw "convert_mult: unexpected operand width";

      op=bv_utils.sign_extension(op, bv.size());

      // [CBMC-GC]
      bv=conv.multiplier(prop, bv, op);
    }

    // cut it down again
    bv.erase(bv.begin(), bv.begin()+fraction_bits);

    return bv;
  }
  else if(expr.type().id()==ID_unsignedbv ||
          expr.type().id()==ID_signedbv)
  {
    std::vector<bvt> bv_operands;
    for(exprt::operandst::const_iterator it=operands.begin();
        it!=operands.end(); it++)
    {
      if(it->type()!=expr.type())
        throw "multiplication with mixed types";

      const bvt &op=convert_bv(*it);

      if(op.size()!=width)
        throw "convert_mult: unexpected operand width";

      // [CBMC-GC]
      bv_operands.push_back(op);
    }


    // [CBMC-GC] Build multiplier tree
    return build_tree(bv_operands, [&](bvt const &a, bvt const &b, int)
    {
      return conv.multiplier(prop, a, b);
    });
  }

  return conversion_failed(expr);
}


bvt boolean_expr_loweringt::convert_div(const div_exprt &expr)
{
  if(expr.type().id()!=ID_unsignedbv &&
     expr.type().id()!=ID_signedbv &&
     expr.type().id()!=ID_fixedbv)
    return conversion_failed(expr);

  std::size_t width=boolbv_width(expr.type());

  if(width==0)
    return conversion_failed(expr);

  if(expr.op0().type().id()!=expr.type().id() ||
     expr.op1().type().id()!=expr.type().id())
    return conversion_failed(expr);

  bvt op0=convert_bv(expr.op0());
  bvt op1=convert_bv(expr.op1());

  if(op0.size()!=width ||
     op1.size()!=width)
    throw "convert_div: unexpected operand width";

  bvt res;

  if(expr.type().id()==ID_fixedbv)
  {
    std::size_t fraction_bits=
      to_fixedbv_type(expr.type()).get_fraction_bits();

    bvt zeros;
    zeros.resize(fraction_bits, const_literal(false));

    // add fraction_bits least-significant bits
    op0.insert(op0.begin(), zeros.begin(), zeros.end());
    op1=bv_utils.sign_extension(op1, op1.size()+fraction_bits);

    // [CBMC-GC]
    res = conv.signed_divider(prop, op0, op1).first;

    // cut it down again
    res.resize(width);
  }
  else
  {
    bv_utilst::representationt rep=
      expr.type().id()==ID_signedbv?bv_utilst::representationt::SIGNED:
                                   bv_utilst::representationt::UNSIGNED;

    // [CBMC-GC]
    if(rep == bv_utilst::representationt::SIGNED)
      res = conv.signed_divider(prop, op0, op1).first;
    else
      res = conv.unsigned_divider(prop, op0, op1).first;
  }

  return res;
}


bvt boolean_expr_loweringt::convert_mod(const mod_exprt &expr)
{
  if(expr.type().id()==ID_floatbv)
  {
  }

  if(expr.type().id()!=ID_unsignedbv &&
     expr.type().id()!=ID_signedbv)
    return conversion_failed(expr);

  std::size_t width=boolbv_width(expr.type());

  if(width==0)
    return conversion_failed(expr);

  if(expr.op0().type().id()!=expr.type().id() ||
     expr.op1().type().id()!=expr.type().id())
    throw "mod got mixed-type operands";

  bv_utilst::representationt rep=
    expr.type().id()==ID_signedbv?bv_utilst::representationt::SIGNED:
                                  bv_utilst::representationt::UNSIGNED;

  const bvt &op0=convert_bv(expr.op0());
  const bvt &op1=convert_bv(expr.op1());

  if(op0.size()!=width ||
     op1.size()!=width)
    throw "convert_mod: unexpected operand width";

  bvt rem;

  // [CBMC-GC]
  if(rep == bv_utilst::representationt::SIGNED)
    rem = conv.signed_divider(prop, op0, op1).second;
  else
    rem = conv.unsigned_divider(prop, op0, op1).second;

  return rem;
}


bvt boolean_expr_loweringt::convert_index(const index_exprt &expr)
{
  // [CBMC-GC] Removed all code-paths that require prop.has_set_to().

  if(expr.id()!=ID_index)
    throw "expected index expression";

  if(expr.operands().size()!=2)
    throw "index takes two operands";

  const exprt &array=expr.array();
  const exprt &index=expr.index();

  const typet &array_op_type=ns.follow(array.type());

  bvt bv;

  if(array_op_type.id()==ID_array)
  {
    const array_typet &array_type=
      to_array_type(array_op_type);

    std::size_t width=boolbv_width(expr.type());

    if(width==0)
      return conversion_failed(expr);

    // see if the array size is constant

    if(is_unbounded_array(array_type))
	{
		// [CBMC-GC] We don't support unbounded array (yet).
		throw "Unbounded arrays not supported";
	}

    // Must have a finite size
    mp_integer array_size;
    if(to_integer(array_type.size(), array_size))
      throw "failed to convert array size";

    // see if the index address is constant
    // many of these are compacted by simplify_expr
    // but variable location writes will block this
    mp_integer index_value;
    if(!to_integer(index, index_value))
      return bv_cbmct::convert_index(array, index_value);


    // TODO : As with constant index, there is a trade-off
    // of when it is best to flatten the whole array and
    // when it is best to use the array theory and then use
    // one or more of the above encoding strategies.

    // get literals for the whole array

    const bvt &array_bv=convert_bv(array);

    if(array_size*width!=array_bv.size())
      throw "unexpected array size";

    // TODO: maybe a shifter-like construction would be better
    // Would be a lot more compact but propagate worse

    assert(array_size>0);

    // [CBMC-GC] The this the added code.
    bvt index_bv = convert_bv(index);

    std::vector<bvt> input_columns;
    input_columns.reserve(width);

    // do this for every bit of our array-elements
    size_t array_size_int = integer2size_t(array_size);
    for (unsigned j = 0; j < width; j++)
    {
        bvt inputs; inputs.reserve(array_size_int);
        for (size_t i = 0; i < array_size_int; i++)
            inputs.push_back(array_bv[i * width + j]);

        input_columns.push_back(inputs);
    }

    bv = conv.multiplexer(prop, index_bv, input_columns);
  }
  else
    return conversion_failed(expr);

  return bv;
}


bvt boolean_expr_loweringt::convert_shift(const binary_exprt &expr)
{
  const irep_idt &type_id=expr.type().id();

  if(type_id!=ID_unsignedbv &&
     type_id!=ID_signedbv &&
     type_id!=ID_floatbv &&
     type_id!=ID_pointer &&
     type_id!=ID_bv &&
     type_id!=ID_verilog_signedbv &&
     type_id!=ID_verilog_unsignedbv)
    return conversion_failed(expr);

  std::size_t width=boolbv_width(expr.type());

  if(width==0)
    return conversion_failed(expr);

  if(expr.operands().size()!=2)
    throw "shifting takes two operands";

  const bvt &op=convert_bv(expr.op0());

  if(op.size()!=width)
    throw "convert_shift: unexpected operand 0 width";

  bv_utilst::shiftt shift;

  if(expr.id()==ID_shl)
    shift=bv_utilst::shiftt::LEFT;

  else if(expr.id()==ID_ashr)
    shift=bv_utilst::shiftt::ARIGHT;
  else if(expr.id()==ID_lshr)
    shift=bv_utilst::shiftt::LRIGHT;
  else
    throw "unexpected shift operator";

  // we allow a constant as shift distance

  if(expr.op1().is_constant())
  {
    mp_integer i;
    if(to_integer(expr.op1(), i))
      throw "convert_shift: failed to convert constant";

    std::size_t distance;

    if(i<0 || i>std::numeric_limits<signed>::max())
      distance=0;
    else
      distance=integer2size_t(i);

    if(type_id==ID_verilog_signedbv ||
       type_id==ID_verilog_unsignedbv)
      distance*=2;

    return bv_utils.shift(op, shift, distance);
  }
  else
  {
    const bvt &distance=convert_bv(expr.op1());
    return conv.shifter(prop, op, shift, distance);
  }
}

bvt boolean_expr_loweringt::convert_if(const if_exprt &expr)
{
  std::size_t width=boolbv_width(expr.type());

  if(width==0)
    return bvt(); // An empty bit-vector if.

  literalt cond=convert(expr.cond());

  const bvt &op1_bv=convert_bv(expr.true_case());
  const bvt &op2_bv=convert_bv(expr.false_case());

  if(op1_bv.size()!=width || op2_bv.size()!=width)
    throw "operand size mismatch for if "+expr.pretty();

  return select_bv(prop, cond, op1_bv, op2_bv);
}


literalt boolean_expr_loweringt::convert_equality(const equal_exprt &expr)
{
  if(!base_type_eq(expr.lhs().type(), expr.rhs().type(), ns))
  {
    std::cout << "######### lhs: " << expr.lhs().pretty() << std::endl;
    std::cout << "######### rhs: " << expr.rhs().pretty() << std::endl;
    throw "equality without matching types";
  }

  // see if it is an unbounded array
  if(is_unbounded_array(expr.lhs().type()))
  {
    // flatten byte_update/byte_extract operators if needed

    if(has_byte_operator(expr))
    {
      exprt tmp=flatten_byte_operators(expr, ns);
      //std::cout << "X: " << from_expr(ns, "", tmp) << std::endl;
      return record_array_equality(to_equal_expr(tmp));
    }

    return record_array_equality(expr);
  }

  const bvt &bv0=convert_bv(expr.lhs());
  const bvt &bv1=convert_bv(expr.rhs());

  if(bv0.size()!=bv1.size())
  {
    std::cerr << "lhs: " << expr.lhs().pretty() << std::endl;
    std::cerr << "lhs size: " << bv0.size() << std::endl;
    std::cerr << "rhs: " << expr.rhs().pretty() << std::endl;
    std::cerr << "rhs size: " << bv1.size() << std::endl;
    throw "unexpected size mismatch on equality";
  }

  if(bv0.empty())
  {
    // An empty bit-vector comparison. It's not clear
    // what this is meant to say.

    // [CBMC-GC] Well, we will throw an exception then
    throw "empty bit-vector comparison";
  }

  return conv.equal(prop, bv0, bv1);
}

literalt boolean_expr_loweringt::convert_bv_rel(const exprt &expr)
{
  const exprt::operandst &operands=expr.operands();

  if(operands.size()==2)
  {
    const exprt &op0=expr.op0();
    const exprt &op1=expr.op1();

    const bvt &bv0=convert_bv(op0);
    const bvt &bv1=convert_bv(op1);

    bvtypet bvtype0=get_bvtype(op0.type());
    bvtypet bvtype1=get_bvtype(op1.type());

    irep_idt const &rel = expr.id();

    if(bv0.size()==bv1.size() && !bv0.empty() &&
       bvtype0==bvtype1)
    {
      if(bvtype0==bvtypet::IS_FLOAT)
      {
        float_utilst float_utils(prop, to_floatbv_type(op0.type()));

        if(rel==ID_le)
          return float_utils.relation(bv0, float_utilst::relt::LE, bv1);
        else if(rel==ID_lt)
          return float_utils.relation(bv0, float_utilst::relt::LT, bv1);
        else if(rel==ID_ge)
          return float_utils.relation(bv0, float_utilst::relt::GE, bv1);
        else if(rel==ID_gt)
          return float_utils.relation(bv0, float_utilst::relt::GT, bv1);
        else
          return SUB::convert_rest(expr);
      }
      else if((op0.type().id()==ID_range &&
               op1.type()==op0.type()) ||
               bvtype0==bvtypet::IS_SIGNED ||
               bvtype0==bvtypet::IS_UNSIGNED ||
               bvtype0==bvtypet::IS_FIXED)
      {
        literalt literal;

        bv_utilst::representationt rep=
          ((bvtype0==bvtypet::IS_SIGNED) || (bvtype0==bvtypet::IS_FIXED))?bv_utilst::representationt::SIGNED:
                                                        bv_utilst::representationt::UNSIGNED;

        // [CBMC-GC]
        return comparer(conv, prop, bv0, rel, bv1, rep);
      }
      else if((bvtype0==bvtypet::IS_VERILOG_SIGNED ||
               bvtype0==bvtypet::IS_VERILOG_UNSIGNED) &&
              op0.type()==op1.type())
      {
        // extract number bits
        bvt extract0, extract1;

        extract0.resize(bv0.size()/2);
        extract1.resize(bv1.size()/2);

        for(std::size_t i=0; i<extract0.size(); i++)
          extract0[i]=bv0[i*2];

        for(std::size_t i=0; i<extract1.size(); i++)
          extract1[i]=bv1[i*2];

        bv_utilst::representationt rep=bv_utilst::representationt::UNSIGNED;

        // now compare
        // [CBMC-GC]
        return comparer(conv, prop, extract0, rel, extract1, rep);
      }
    }
  }

  return SUB::convert_rest(expr);
}

