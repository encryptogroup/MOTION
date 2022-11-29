#include <inttypes.h>
// #include <stdbool.h >
#include <stdio.h>
// #define FIXEDPOINT_BITS 32
// #define FIXEDPOINT_INTEGER_BITS 24
// #define FIXEDPOINT_FRACTION_BITS (FIXEDPOINT_BITS - FIXEDPOINT_INTEGER_BITS)

// typedef int32_t fixedpt;
// typedef uint32_t fixedptd;

// typedef uint32_t ufixedp_t;
// typedef uint64_t ufixedpd_t;
// typedef enum {false, true} bool;


typedef struct 
{
    bool v[8];
}uint8_vec;

uint8_vec uint8ToInt8(uint8_t a)
{
    // uint8_t result;
    uint8_t tmp0;
    uint8_t tmp1;
    uint8_t tmp2;
    uint8_t tmp3;
    uint8_t tmp4;
    uint8_t tmp5;
    uint8_t tmp6;
    uint8_t tmp7;

    tmp0 = a ^ 0x1;
    tmp1 = a ^ 0x10;
    tmp2 = a ^ 0x100;
    tmp3 = a ^ 0x1000;
    tmp4 = a ^ 0x10000;
    tmp5 = a ^ 0x100000;
    tmp6 = a ^ 0x1000000;
    tmp7 = a ^ 0x10000000;

    uint8_vec result;
    result.v[0]=tmp0;

    return result;
}
