#include <inttypes.h>

// #define FIXEDPOINT_BITS 32
// #define FIXEDPOINT_INTEGER_BITS 24
// #define FIXEDPOINT_FRACTION_BITS (FIXEDPOINT_BITS - FIXEDPOINT_INTEGER_BITS)

// typedef int32_t fixedpt;
// typedef int32_t fixedptd;

// typedef int32_t ufixedp_t;
// typedef int64_t ufixedpd_t;

int32_t int32_mul(int32_t a, int32_t b)
{
  return a * b;
}
int32_t int32_div(int32_t a, int32_t b)
{
  return a / b;
}
int32_t int32_add(int32_t a, int32_t b)
{
  return a + b;
}
int32_t int32_sub(int32_t a, int32_t b)
{
  return a - b;
}
int32_t int32_gt(int32_t a, int32_t b)
{
  return a > b;
}

int32_t int32_eqz(int32_t a, int32_t not_used)
{
  return a == (int32_t)(0);
}

int32_t int32_geq(int32_t a, int32_t b)
{
  return a >= b;
}

int32_t int32_in_range(int32_t a, int32_t b)
{
  return (a >= -b) & (a <= b);
}