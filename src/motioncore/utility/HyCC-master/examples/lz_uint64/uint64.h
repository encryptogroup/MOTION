#include <inttypes.h>

// #define FIXEDPOINT_BITS 64
// #define FIXEDPOINT_INTEGER_BITS 24
// #define FIXEDPOINT_FRACTION_BITS (FIXEDPOINT_BITS - FIXEDPOINT_INTEGER_BITS)

// typedef int64_t fixedpt;
// typedef uint64_t fixedptd;

// typedef uint64_t ufixedp_t;
// typedef uint64_t ufixedpd_t;

uint64_t uint64_mul(uint64_t a, uint64_t b)
{
  return a * b;
}
uint64_t uint64_div(uint64_t a, uint64_t b)
{
  return a / b;
}
uint64_t uint64_add(uint64_t a, uint64_t b)
{
  return a + b;
}
uint64_t uint64_sub(uint64_t a, uint64_t b)
{
  return a - b;
}
uint64_t uint64_gt(uint64_t a, uint64_t b)
{
  return a > b;
}
uint64_t uint64_geq(uint64_t a, uint64_t b)
{
  return a >= b;
}

uint64_t uint64_eqz(uint64_t a, uint64_t not_used)
{
  return a == (uint64_t)(0);
}
uint64_t uint64_mod(uint64_t a, uint64_t b)
{
  return a % b;
}

 
