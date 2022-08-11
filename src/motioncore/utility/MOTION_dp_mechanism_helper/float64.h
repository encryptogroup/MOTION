#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "SPARC-GCC.h"

typedef unsigned long long float64;

extern signed char float_rounding_mode;
enum {
    float_round_nearest_even = 0, float_round_down = 1, float_round_up = 2, float_round_to_zero = 3
};

//typedef float64 fixedptd;
typedef uint64_t fixedptd;

fixedptd KMulL_float64(fixedptd *x_array, unsigned head, unsigned tail);

// 2^x
// x: integer
// m = ceil(log2(x_max)), m is the maximum number of bits to represent 2^x
fixedptd pow2_float64(fixedptd x, unsigned m);

INLINE bits64 extractFloat64Frac(float64 a);

INLINE int16 extractFloat64Exp(float64 a);

INLINE flag extractFloat64Sign(float64 a);

INLINE void shift64ExtraRightJamming(bits64 a0, bits64 a1, int16 count, bits64 *z0Ptr, bits64 *z1Ptr);

INLINE float64 packFloat64(flag zSign, int16 zExp, bits64 zSig);
// =================================================================

static int8 countLeadingZeros32(bits32 a);

static int8 countLeadingZeros64(bits64 a);

static int64 roundAndPackInt64(flag zSign, bits64 absZ0, bits64 absZ1);

static int32 roundAndPackInt32(flag zSign, bits64 absZ);

INLINE void shift64RightJamming(bits64 a, int16 count, bits64 *zPtr);

static float64 roundAndPackFloat64(flag zSign, int16 zExp, bits64 zSig);

static float64 normalizeRoundAndPackFloat64(flag zSign, int16 zExp, bits64 zSig);

int64 float64_to_int64(float64 a, float64 not_used);

// ! we mask the correct result z with zero_bits_mask, otherwise, it cannot be converted to bristol
// format in MOTION, input wire zero_bits_mask must be zero bits
float64 int64_to_float64(int64 a, int64 zero_bits_mask);

int64 float64_to_int64_round_to_zero(float64 a, float64 not_used);

float64 float64_floor(float64 a, float64 not_used);

float64 float64_ceil(float64 a, float64 not_used);

int32 float64_to_int32(float64 a, float64 b);

float64 int32_to_float64(int32 a, int32 b);

uint16_t msb_index_reverse_float64(__uint128_t x, unsigned num_of_bits);

float64 int128_to_float64(__uint128_t a, __uint128_t not_used);
float64 int128_to_float64_towards_zero(__uint128_t a, __uint128_t not_used);
void test_float64_to_int64();

void test_int64_to_float64();

void test_float64_floor();

void test_float64_ceil();

void test_float64_to_int32();

void test_int32_to_float64();

void test_int128_to_float64();
void test_int128_to_float64_towards_zero();