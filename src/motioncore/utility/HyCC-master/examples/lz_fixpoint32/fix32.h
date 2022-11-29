#include <inttypes.h>
#include <math.h>

#define FIXEDPOINT_BITS 32
#define FIXEDPOINT_INTEGER_BITS 24
#define FIXEDPOINT_FRACTION_BITS (FIXEDPOINT_BITS - FIXEDPOINT_INTEGER_BITS)

typedef int32_t fixedpt;
typedef int64_t fixedptd;

typedef uint32_t ufixedp_t;
typedef uint64_t ufixedpd_t;

// double fixed_to_double(fixedpt input)
// {
//   return ((double)input / (double)(1 << FIXEDPOINT_FRACTION_BITS));
// }

// fixedpt double_to_fixed(double input)
// {
//   return (fixedpt)(round(input * (1 << FIXEDPOINT_FRACTION_BITS)));
// }

fixedpt fixedpt_mul(fixedpt a, fixedpt b)
{
  return (a * b) >> FIXEDPOINT_FRACTION_BITS;
}

// fixedpt fixedpt_mul_overflow_free(fixedpt a, fixedpt b)
// {
//   fixedpt_64 a2 = a;
//   fixedpt_64 b2 = b;
//   fixedpt_64 res = (a2 * b2) >> FIXEDPOINT_FRACTION_BITS;
//   return res;
// }

fixedpt fixedpt_add(fixedpt a, fixedpt b)
{
  return (a + b);
}

fixedpt fixedpt_sub(fixedpt a, fixedpt b)
{
  return (a - b);
}

fixedpt fixedpt_div(fixedpt a, fixedpt b)
{
  return (a << FIXEDPOINT_FRACTION_BITS) / b;
}

fixedpt fixedpt_gt(fixedpt a, fixedpt b)
{
  return (a > b);
}



// output 64-bit fixed-point number
// fixedptd fixedpt_mul_overflow_free(fixedpt a, fixedpt b)
// {
//   fixedptd a2 = a;
//   fixedptd b2 = b;
//   fixedptd res = (a2 * b2);
//   return res;
// }

fixedpt fixedpt_mul_overflow_free(fixedpt a, fixedpt b)
{
  fixedptd a2 = a;
  fixedptd b2 = b;
  fixedpt res = (a2 * b2) >> (fixedptd)FIXEDPOINT_FRACTION_BITS;
  ;
  return res;
}

// can't generate circuits, program get killed
// fixedpt fixedpt_div_overflow_free(fixedpt a, fixedpt b)
// {
// 	return ((fixedptd)a << FIXEDPOINT_FRACTION_BITS) / b;
// }
