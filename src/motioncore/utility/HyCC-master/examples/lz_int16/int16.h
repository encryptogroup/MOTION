#include <inttypes.h>

// #define FIXEDPOINT_BITS 32
// #define FIXEDPOINT_INTEGER_BITS 24
// #define FIXEDPOINT_FRACTION_BITS (FIXEDPOINT_BITS - FIXEDPOINT_INTEGER_BITS)

// typedef int32_t fixedpt;
// typedef int32_t fixedptd;

// typedef int32_t ufixedp_t;
// typedef int64_t ufixedpd_t;

int16_t int16_mul(int16_t a, int16_t b)
{
  return a * b;
}
int16_t int16_div(int16_t a, int16_t b)
{
  return a / b;
}
int16_t int16_add(int16_t a, int16_t b)
{
  return a + b;
}
int16_t int16_sub(int16_t a, int16_t b)
{
  return a - b;
}
int16_t int16_gt(int16_t a, int16_t b)
{
  return a > b;
}

int16_t int16_eqz(int16_t a, int16_t not_used)
{
  return a == (int16_t)(0);
}
int16_t int16_geq(int16_t a, int16_t b)
{
  return a >= b;
}

int16_t int16_in_range(int16_t a, int16_t b)
{
  return (a >= -b) & (a <= b);
}
