#include <inttypes.h>

#define FIXEDPOINT_BITS 32
#define FIXEDPOINT_INTEGER_BITS 24
#define FIXEDPOINT_FRACTION_BITS (FIXEDPOINT_BITS - FIXEDPOINT_INTEGER_BITS)

typedef int32_t fixedpt;
typedef uint32_t fixedptd;

typedef uint32_t ufixedp_t;
typedef uint64_t ufixedpd_t;

fixedpt fixedpt_mul(fixedpt a, fixedpt b)
{
	return ((fixedptd)a * (fixedptd)b) >> FIXEDPOINT_FRACTION_BITS;
}

fixedpt fixedpt_div(fixedpt a, fixedpt b)
{
	return ((fixedptd)a << FIXEDPOINT_FRACTION_BITS) / b;
}


ufixedp_t fixedpt_add_overflow_free(ufixedp_t a, ufixedp_t b)
{
  ufixedpd_t res = a+b;
  return res;
}

ufixedp_t fixedpt_mul_overflow_free(ufixedp_t a, ufixedp_t b)
{
  ufixedpd_t a2 = a;
  ufixedpd_t b2 = b;
  ufixedpd_t res = (a2*b2) >> FIXEDPOINT_FRACTION_BITS;
  return res;
}

ufixedp_t fixedpt_div_overflow_free(ufixedp_t a, ufixedp_t b)
{
  ufixedpd_t a2 = a;
  ufixedpd_t b2 = b;
  ufixedpd_t res = (a2 << FIXEDPOINT_FRACTION_BITS) / b;
	return res;
}

