#include <inttypes.h>

// #define FIXEDPOINT_BITS 32
// #define FIXEDPOINT_INTEGER_BITS 24
// #define FIXEDPOINT_FRACTION_BITS (FIXEDPOINT_BITS - FIXEDPOINT_INTEGER_BITS)

// typedef int32_t fixedpt;
// typedef uint32_t fixedptd;

// typedef uint32_t ufixedp_t;
// typedef uint64_t ufixedpd_t;

uint16_t uint16_mul(uint16_t a, uint16_t b)
{
  return a * b;
}
uint16_t uint16_div(uint16_t a, uint16_t b)
{
  return a / b;
}
uint16_t uint16_add(uint16_t a, uint16_t b)
{
  return a + b;
}
uint16_t uint16_sub(uint16_t a, uint16_t b)
{
  return a - b;
}
uint16_t uint16_gt(uint16_t a, uint16_t b)
{
  return a > b;
}
uint16_t uint16_geq(uint16_t a, uint16_t b)
{
  return a >= b;
}

uint16_t uint16_eqz(uint16_t a, uint16_t not_used)
{
  return a == (uint16_t)(0);
}
uint16_t uint16_mod(uint16_t a, uint16_t b)
{
  return a %b;
}

 
