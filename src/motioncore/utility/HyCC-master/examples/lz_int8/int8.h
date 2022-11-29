#include <inttypes.h>

// #define FIXEDPOINT_BITS 32
// #define FIXEDPOINT_INTEGER_BITS 24
// #define FIXEDPOINT_FRACTION_BITS (FIXEDPOINT_BITS - FIXEDPOINT_INTEGER_BITS)

// typedef int32_t fixedpt;
// typedef int32_t fixedptd;

// typedef int32_t ufixedp_t;
// typedef int64_t ufixedpd_t;

int8_t int8_mul(int8_t a, int8_t b)
{
  return a * b;
}
int8_t int8_div(int8_t a, int8_t b)
{
  return a / b;
}
int8_t int8_add(int8_t a, int8_t b)
{
  return a + b;
}
int8_t int8_sub(int8_t a, int8_t b)
{
  return a - b;
}
int8_t int8_gt(int8_t a, int8_t b)
{
  return a > b;
}

int8_t int8_eqz(int8_t a, int8_t not_used)
{
  return a == (int8_t)(0);
}
int8_t int8_geq(int8_t a, int8_t b)
{
  return a >= b;
}

int8_t int8_in_range(int8_t a, int8_t b)
{
  return (a >= -b) & (a <= b);
}