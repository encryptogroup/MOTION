#include <inttypes.h>
#include <math.h>

#define FIXEDPOINT_BITS 64
#define FIXEDPOINT_INTEGER_BITS 48
#define FIXEDPOINT_FRACTION_BITS (FIXEDPOINT_BITS - FIXEDPOINT_INTEGER_BITS)

// error: not working for int64_t
// typedef int32_t fixedpt;
// typedef int64_t fixedptd;

// only for test
typedef int32_t fixedptd;
// typedef unsigned long int fixedptd;
// typedef unsigned long long int fixedptd;

fixedptd fixedptd_mul(fixedptd a, fixedptd b)
{
  fixedptd c = a * b;
  fixedptd d = c >> 2;
  // fixedptd d = c/242;
  return d;
}

// inline double
// fixed_to_double(fixedpt input)
// {
//   return ((double)input / (double)(1 << FIXEDPOINT_FRACTION_BITS));
// }

// inline fixedpt double_to_fixed(double input)
// {
//     return (fixedpt)(round(input * (1 << FIXEDPOINT_FRACTION_BITS)));
// }

// fixedpt fixedpt_add(fixedpt a, fixedpt b)
// {
//   return (a + b);
// }

// fixedpt fixedpt_sub(fixedpt a, fixedpt b)
// {
//   return (a - b);
// }

// fixedpt fixedpt_div(fixedpt a, fixedpt b)
// {
//   return (a << FIXEDPOINT_FRACTION_BITS) / b;
// }

// fixedpt fixedpt_gt(fixedpt a, fixedpt b)
// {
//   return (a > b);
// }

// ufixedp_t fixedpt_add_overflow_free(ufixedp_t a, ufixedp_t b)
// {
//   ufixedpd_t res = a + b;
//   return res;
// }

// ufixedp_t fixedpt_sub_overflow_free(ufixedp_t a, ufixedp_t b)
// {
//   ufixedpd_t res = a - b;
//   return res;
// }

// ufixedp_t fixedpt_mul_overflow_free(ufixedp_t a, ufixedp_t b)
// {
//   ufixedpd_t a2 = a;
//   ufixedpd_t b2 = b;
//   ufixedpd_t res = (a2 * b2) >> FIXEDPOINT_FRACTION_BITS;
//   return res;
// }

// ufixedp_t fixedpt_div_overflow_free(ufixedp_t a, ufixedp_t b)
// {
//   ufixedpd_t a2 = a;
//   ufixedpd_t b2 = b;
//   ufixedpd_t res = (a2 << FIXEDPOINT_FRACTION_BITS) / b2;
//   return res;
// }

// fixedptd fixedpt_cmp_overflow_free(ufixedp_t a, ufixedp_t b)
// {
//   // fixedpt c = fixedpt_sub_overflow_free(a, b);
//   // return c & 0x80000000;

//   return a > b;
// }
