#include <inttypes.h>

// #define FIXEDPOINT_BITS 32
// #define FIXEDPOINT_INTEGER_BITS 24
// #define FIXEDPOINT_FRACTION_BITS (FIXEDPOINT_BITS - FIXEDPOINT_INTEGER_BITS)

// typedef int32_t fixedpt;
// typedef uint32_t fixedptd;

// typedef uint32_t ufixedp_t;
// typedef __uint128_t ufixedpd_t;

// #define FIXEDPOINT_BITS 32
// #define FIXEDPOINT_INTEGER_BITS 24
// #define FIXEDPOINT_FRACTION_BITS (FIXEDPOINT_BITS - FIXEDPOINT_INTEGER_BITS)

__uint128_t uint128_mul(__uint128_t a, __uint128_t b) { return a * b; }

__uint128_t uint128_add(__uint128_t a, __uint128_t b) { return a + b; }
__uint128_t uint128_sub(__uint128_t a, __uint128_t b) { return a - b; }
__uint128_t uint128_gt(__uint128_t a, __uint128_t b) { return a > b; }
__uint128_t uint128_geq(__uint128_t a, __uint128_t b) { return a >= b; }

__uint128_t uint128_eqz(__uint128_t a, __uint128_t b) { return a == 0; }

// depth-optimized circuit generated successfully
// ! size-optimized circuit generated successfully?
__uint128_t uint128_div(__uint128_t a, __uint128_t b) { return a / b; }

// ! depth-optimized circuit generated successfully?
// ! size-optimized circuit generated successfully?
__uint128_t uint128_mod(__uint128_t a, __uint128_t b) { return a % b; }
