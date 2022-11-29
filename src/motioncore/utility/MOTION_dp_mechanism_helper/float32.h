#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "SPARC-GCC.h"
#include "print_uint128_t.h"

typedef unsigned int float32;

#define FLOATINGPOINT32_MANTISSA_BITS 23
#define FLOATINGPOINT32_EXPONENT_BITS 8
#define FLOATINGPOINT32_EXPONENT_BIAS 127

#define float32_exponent_mask ((((int16)1) << 5) - 1)

enum {
    float_round_nearest_even = 0, float_round_down = 1, float_round_up = 2, float_round_to_zero = 3
};

enum {
    float_tininess_after_rounding = 0, float_tininess_before_rounding = 1
};

typedef float32 fixedptd;

fixedptd KMulL_float32(fixedptd *x_array, unsigned head, unsigned tail);

// 2^x
// x: integer
// m = ceil(log2(x_max)), m is the maximum number of bits to represent 2^x
fixedptd pow2_float32(fixedptd x, unsigned m);

INLINE bits32 extractFloat32Frac(float32 a);

INLINE int16 extractFloat32Exp(float32 a);

INLINE flag extractFloat32Sign(float32 a);

INLINE float32 packFloat32(flag zSign, int16 zExp, bits32 zSig);

static int8 countLeadingZeros32(bits32 a);

static int8 countLeadingZeros64(bits64 a);

INLINE void shift32RightJamming(bits32 a, int16 count, bits32 *zPtr);

INLINE void shift64ExtraRightJamming(bits64 a0, bits64 a1, int16 count, bits64 *z0Ptr, bits64 *z1Ptr);

INLINE void shift64RightJamming(bits64 a, int16 count, bits64 *zPtr);

static float32 roundAndPackFloat32(flag zSign, int16 zExp, bits32 zSig);

static int64 roundAndPackInt64(flag zSign, bits64 absZ0, bits64 absZ1);

static float32 normalizeRoundAndPackFloat32(flag zSign, int16 zExp, bits32 zSig);

// static float32 propagateFloat32NaN( float32 a, float32 b )
// {
//     flag aIsNaN, aIsSignalingNaN, bIsNaN, bIsSignalingNaN;

//     aIsNaN = float32_is_nan( a );
//     aIsSignalingNaN = float32_is_signaling_nan( a );
//     bIsNaN = float32_is_nan( b );
//     bIsSignalingNaN = float32_is_signaling_nan( b );
//     a |= 0x00400000;
//     b |= 0x00400000;
//     // if ( aIsSignalingNaN | bIsSignalingNaN ) float_raise( float_flag_invalid );
//     if ( aIsSignalingNaN ) {
//         if ( bIsSignalingNaN ) goto returnLargerSignificand;
//         return bIsNaN ? b : a;
//     }
//     else if ( aIsNaN ) {
//         if ( bIsSignalingNaN | ! bIsNaN ) return a;
//  returnLargerSignificand:
//         if ( (bits32) ( a<<1 ) < (bits32) ( b<<1 ) ) return b;
//         if ( (bits32) ( b<<1 ) < (bits32) ( a<<1 ) ) return a;
//         return ( a < b ) ? a : b;
//     }
//     else {
//         return b;
//     }

// }
// =================================================================

int32 float32_to_int32(float32 a, float32 not_used);

// ! we mask the correct result z with zero_bits_mask, otherwise, it cannot be converted to bristol
// format in MOTION, input wire zero_bits_mask must be zero bits
float32 int32_to_float32(int32 a, int32 zero_bits_mask);

// backup
// ! we mask the correct result z with zero_bits_mask, otherwise, it cannot be converted to bristol
// format in MOTION, input wire zero_bits_mask must be zero bits
float32 float32_floor(float32 a, float32 zero_bits_mask);

// ! we mask the correct result z with zero_bits_mask, otherwise, it cannot be converted to bristol
// format in MOTION, input wire zero_bits_mask must be zero bits
float32 float32_ceil(float32 a, float32 zero_bits_mask);

unsigned char msb_index_reverse_float32(__uint128_t x, unsigned num_of_bits);

float32 int128_to_float32(__uint128_t a, __uint128_t not_used);

float32 int128_to_float32_towards_zero(__uint128_t a, __uint128_t not_used);

void test_float32_to_int32();

void test_int32_to_float32();

void test_float32_floor();

void test_float32_ceil();

void test_float32_to_int64();

void test_int64_to_float32();

void test_int128_to_float32();

void test_int128_to_float32_towards_zero();