#include <inttypes.h>

// #define FIXEDPOINT_BITS 32
// #define FIXEDPOINT_INTEGER_BITS 24
// #define FIXEDPOINT_FRACTION_BITS (FIXEDPOINT_BITS - FIXEDPOINT_INTEGER_BITS)

// typedef int32_t fixedpt;
// typedef uint32_t fixedptd;

// typedef uint32_t ufixedp_t;
// typedef uint64_t ufixedpd_t;

uint8_t uint8_mul(uint8_t a, uint8_t b)
{
  return a * b;
}
uint8_t uint8_div(uint8_t a, uint8_t b)
{
  return a / b;
}
uint8_t uint8_add(uint8_t a, uint8_t b)
{
  return a + b;
}
uint8_t uint8_sub(uint8_t a, uint8_t b)
{
  return a - b;
}
uint8_t uint8_gt(uint8_t a, uint8_t b)
{
  return a > b;
}
uint8_t uint8_geq(uint8_t a, uint8_t b)
{
  return a >= b;
}

uint8_t uint8_eqz(uint8_t a, uint8_t not_used)
{
  return a == (uint8_t)(0);
}
uint8_t uint8_mod(uint8_t a, uint8_t b)
{
  return a % b;
}


// uint8_t uint8_neg(uint8_t a, uint8_t b)
// {
//   uint8_t neg_a = a;
//   if (b == 1)
//   {
//     neg_a = -a;
//   }
//   return neg_a;
// }
