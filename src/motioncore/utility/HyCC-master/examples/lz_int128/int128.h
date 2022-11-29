#include <inttypes.h>

// #define FIXEDPOINT_BITS 32
// #define FIXEDPOINT_INTEGER_BITS 24
// #define FIXEDPOINT_FRACTION_BITS (FIXEDPOINT_BITS - FIXEDPOINT_INTEGER_BITS)

// typedef int32_t fixedpt;
// typedef int32_t fixedptd;

// typedef int32_t ufixedp_t;
// typedef __int128_t ufixedpd_t;

// #define FIXEDPOINT_BITS 32
// #define FIXEDPOINT_INTEGER_BITS 24
// #define FIXEDPOINT_FRACTION_BITS (FIXEDPOINT_BITS - FIXEDPOINT_INTEGER_BITS)

__int128_t int128_mul(__int128_t a, __int128_t b)
{
  return a * b;
}
__int128_t int128_div(__int128_t a, __int128_t b)
{
  return a / b;
}
__int128_t int128_add(__int128_t a, __int128_t b)
{
  return a + b;
}
__int128_t int128_sub(__int128_t a, __int128_t b)
{
  return a - b;
}
__int128_t int128_gt(__int128_t a, __int128_t b)
{
  return a > b;
}

__int128_t int128_eqz(__int128_t a, __int128_t b)
{
  return a == 0;
}
__int128_t int128_geq(__int128_t a, __int128_t b)
{
  return a >= b;
}
__int128_t int128_in_range(__int128_t a, __int128_t b)
{
  return (a >= -b) & (a <= b);
}