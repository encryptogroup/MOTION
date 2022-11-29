#include <inttypes.h>

// #define FIXEDPOINT_BITS 64
// #define FIXEDPOINT_INTEGER_BITS 24
// #define FIXEDPOINT_FRACTION_BITS (FIXEDPOINT_BITS - FIXEDPOINT_INTEGER_BITS)

// typedef int64_t fixedpt;
// typedef int64_t fixedptd;

// typedef int64_t ufixedp_t;
// typedef int64_t ufixedpd_t;

int64_t int64_mul(int64_t a, int64_t b)
{
  return a * b;
}
int64_t int64_div(int64_t a, int64_t b)
{
  return a / b;
}
int64_t int64_add(int64_t a, int64_t b)
{
  return a + b;
}
int64_t int64_sub(int64_t a, int64_t b)
{
  return a - b;
}
int64_t int64_gt(int64_t a, int64_t b)
{
  return a > b;
}

int64_t int64_eqz(int64_t a, int64_t not_used)
{
  return a == (int64_t)(0);
}

int64_t int64_geq(int64_t a, int64_t b)
{
  return a >= b;
}
int64_t int64_in_range(int64_t a, int64_t b)
{
  return (a >= -b) & (a <= b);
}
