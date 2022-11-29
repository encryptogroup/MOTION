#include <inttypes.h>

// #define FIXEDPOINT_BITS 32
// #define FIXEDPOINT_INTEGER_BITS 24
// #define FIXEDPOINT_FRACTION_BITS (FIXEDPOINT_BITS - FIXEDPOINT_INTEGER_BITS)

// typedef int32_t fixedpt;
// typedef uint32_t fixedptd;

// typedef uint32_t ufixedp_t;
// typedef uint64_t ufixedpd_t;

uint32_t uint32_mul(uint32_t a, uint32_t b)
{
  return a * b;
}
uint32_t uint32_div(uint32_t a, uint32_t b)
{
  return a / b;
}
uint32_t uint32_add(uint32_t a, uint32_t b)
{
  return a + b;
}
uint32_t uint32_sub(uint32_t a, uint32_t b)
{
  return a - b;
}
uint32_t uint32_gt(uint32_t a, uint32_t b)
{
  return a > b;
}
uint32_t uint32_geq(uint32_t a, uint32_t b)
{
  return a >= b;
}

uint32_t uint32_eqz(uint32_t a, uint32_t not_used)
{
  return a == (uint32_t)(0);
}

 uint32_t uint32_mod(uint32_t a, uint32_t b)
{
  return a % b;
}
