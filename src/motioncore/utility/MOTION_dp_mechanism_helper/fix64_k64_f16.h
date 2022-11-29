//
// Created by liangzhao on 18.05.22.
//

#pragma once

#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "print_uint128_t.h"
//#include "fixed_point_operation.h"
#include "snapping_mechanism.h"
#include <bitset>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <iostream>

#define FIXEDPOINT_BITS 64
#define FIXEDPOINT_INTEGER_BITS 48
#define FIXEDPOINT_FRACTION_BITS (FIXEDPOINT_BITS - FIXEDPOINT_INTEGER_BITS)

typedef uint32_t ufixedpt;
typedef int32_t fixedpt;

typedef uint64_t ufixedptd;
typedef int64_t fixedptd;

typedef uint32_t float32;

typedef uint64_t float64;

typedef __uint128_t ufixedptd_t;
typedef __int128_t fixedptd_t;

typedef int32_t int32;
typedef int64_t int64;

#define constant_fixed_point_one (fixedptd)((fixedptd)1 << FIXEDPOINT_FRACTION_BITS)

#define fraction_part_mask (((fixedptd)1 << FIXEDPOINT_FRACTION_BITS) - 1)
#define integer_part_mask 18446744073709486080L

#define floating_point64_mantissa_bits_l 52
#define floating_point64_exponente_bits_k 11
#define floating_point64_mantissa_mask (((fixedptd)1 << floating_point64_mantissa_bits_l) - 1)
#define floating_point64_exponent_mask \
  ((((fixedptd)1 << floating_point64_exponente_bits_k) - 1) << floating_point64_mantissa_bits_l)
#define floating_point64_exponent_bias 1023

#define floating_point32_mantissa_bits_l 23
#define floating_point32_exponente_bits_k 8
#define floating_point32_mantissa_mask (((fixedptd)1 << floating_point32_mantissa_bits_l) - 1)
#define floating_point32_exponent_mask \
  ((((fixedptd)1 << floating_point32_exponente_bits_k) - 1) << floating_point32_mantissa_bits_l)
#define floating_point32_exponent_bias 127

static const double p_1045_SCALEMAMBA[] = {+0.99999999999998151058451, +0.69314718056364205693851, +0.24022650683729748257646,
                                           +0.0555041102193305250618, +0.0096181190501642860210497, +0.0013333931011014250476911,
                                           +0.00015395144945146697380844, +0.000015368748541192116946474, +0.0000012256971722926501833228,
                                           +0.00000014433329807023165258784};
static const double p_2524[] = {-2.05466671951, -8.8626599391, +6.10585199015, +4.81147460989};
static const double q_2524[] = {+0.353553425277, +4.54517087629, +6.42784209029, +1};
static const double p_0132[] = {+0.22906994529, +1.3006690496, -0.90932104982, +0.50104207633, -0.12146838249};
static const double p_0371[] = {+0.073633718232, +0.946607534649, +0.444001732732, -0.041034283936};
static const double q_0371[] = {+0.4232099882, +1.0};
static const double p_2508[] = {-4.58532387645, 18.3513525596, -51.5256443742, +111.767841656, -174.170840774, +191.731001033, -145.611919796,
                                +72.6500829774, -21.4473491967, +2.84079979731};
static const double p_LinAppSQ[] = {+1.787727479, -0.8099868542};
static const double p_AppRcr[] = {2.9142, -2};

static const double p_3307[] = {1.570796326794896619231314989, -0.6459640975062462536551665255, 0.07969262624616704510515876375,
                                -0.00468175413531868791644803589, 0.00016044118478735859304303855, -0.00000359884323520707781565727,
                                0.0000000569217292065732739624, -0.00000000066880348849204233722, 0.00000000000606691056085201792,
                                -0.00000000000004375295071181748, 0.00000000000000025002854189303};

static const double p_3508[] = {0.9999999999999999999999914771, -0.4999999999999999999991637437, 0.04166666666666666665310411988,
                                -0.00138888888888888880310186415, 0.00002480158730158702330045157, -0.000000275573192239332256421489,
                                0.000000002087675698165412591559, -0.0000000000114707451267755432394, 0.0000000000000477945439406649917,
                                -0.00000000000000015612263428827781, 0.00000000000000000039912654507924};

//static const double p_3508[]= {1.00000000000000000000, -0.50000000000000000000,
//0.04166666666666667129, -0.00138888888888888873,
//0.00002480158730158702, -0.00000027557319223933,
//0.00000000208767569817, -0.00000000001147074513,
//0.00000000000004779454, -0.00000000000000015612,
//0.00000000000000000040};



// Mathematical Expression	C++ Symbol	Decimal Representation
// pi	M_PI	3.14159265358979323846
// pi/2	M_PI_2	1.57079632679489661923
// pi/4	M_PI_4	0.785398163397448309616
// 1/pi	M_1_PI	0.318309886183790671538
// 2/pi	M_2_PI	0.636619772367581343076
// 2/sqrt(pi)	M_2_SQRTPI	1.12837916709551257390
// sqrt(2)	M_SQRT2	1.41421356237309504880
// 1/sqrt(2)	M_SQRT1_2	0.707106781186547524401
// e	M_E	2.71828182845904523536
// log_2(e)	M_LOG2E	1.44269504088896340736
// log_10(e)	M_LOG10E	0.434294481903251827651
// log_e(2)	M_LN2	0.693147180559945309417
// log_e(10)	M_LN10	2.30258509299404568402

// ============================================================
// coefficient in fixed-point format
// recalculate if FIXEDPOINT_BITS or FIXEDPOINT_FRACTION_BITS changes
static const fixedptd p_1045_fixedptd_SCLAEMAMBA[] = {65535, 45426, 15743, 3637, 630, 87, 10, 1, 0, 0};
static const fixedptd p_2524_fixedptd[] = {static_cast<fixedptd>((18446744073709416962)), static_cast<fixedptd>((18446744073708970793)), 400153,
                                           315324};
static const fixedptd q_2524_fixedptd[] = {23170, 297872, 421255, 65536};
static const fixedptd p_2508_fixedptd[] = {-300503, 1202674, -3376784, 7324817, -11414460, 12565282, -9542822, 4761195, -1405573, 186174};
static const fixedptd p_0132_fixedptd[] = {15012, 85240, -59593, 32836, -7960};
static const fixedptd p_0371_fixedptd[] = {4825, 62036, 29098, -2689};
static const fixedptd q_0371_fixedptd[] = {27735, 65536};
static const fixedptd p_LinAppSq_fixedptd[] = {117160, -53083};
static const fixedptd p_AppRcr_fixedptd[] = {190985, -131072};

static const fixedptd p_3307_fixedptd[] = {102943, -42333, 5222, -306, 10, 0, 0, 0, 0, 0, 0};
static const fixedptd p_3508_fixedptd[] = {65536, -32768, 2730, -91, 1, 0, 0, 0, 0, 0, 0};

static const fixedptd constant_fixed_point_1 = ((fixedptd) 1) << (FIXEDPOINT_FRACTION_BITS);
static const fixedptd constant_fixed_point_2 = ((fixedptd) 2) << (FIXEDPOINT_FRACTION_BITS);
static const fixedptd constant_fixed_point_3 = ((fixedptd) 3) << (FIXEDPOINT_FRACTION_BITS);

static const fixedptd constant_fixed_point_pow2_f = ((fixedptd) 1) << (2 * FIXEDPOINT_FRACTION_BITS);

// static const fixedptd constant_3_div_2 = (fixedptd)((3.0 / 2) * pow(2,
// FIXEDPOINT_FRACTION_BITS));
static const fixedptd constant_3_div_2 = 98304;

// static const fixedptd constant_M_SQRT1_2 = (fixedptd) (M_SQRT1_2 * pow(2,
// FIXEDPOINT_FRACTION_BITS));
static const fixedptd constant_M_SQRT1_2 = 46340;

// static const fixedptd constant_SQRT1_2_minus_1 = (fixedptd)((M_SQRT1_2 - 1) * pow(2,
// FIXEDPOINT_FRACTION_BITS));
static const fixedptd constant_SQRT1_2_minus_1 = -19195;

// static const fixedptd constant_SQRT2_minus_1 = (fixedptd) ((M_SQRT2 - 1) * pow(2,
// FIXEDPOINT_FRACTION_BITS));
static const fixedptd constant_SQRT2_minus_1 = 27145;

// static const fixedptd constant_M_LN2 = (fixedptd) (M_LN2 * pow(2, FIXEDPOINT_FRACTION_BITS));
static const fixedptd constant_M_LN2 = 45426;

// static const fixedptd constant_M_LOG2E = (fixedptd) (M_LOG2E * pow(2, FIXEDPOINT_FRACTION_BITS));
static const fixedptd constant_M_LOG2E = 94548;

// static const fixedptd constant_2_neg_1 = (fixedptd) (0.5 * pow(2,
// FIXEDPOINT_FRACTION_BITS));
static const fixedptd constant_2_neg_1 = 32768;

// static const unsigned sqrt_theta = ceil(log2(FIXEDPOINT_BITS / 5.4));
static const unsigned sqrt_theta = 4;

// static const unsigned pow2_m = ceil(log2(FIXEDPOINT_BITS));
static const unsigned pow2_m = 6;

// static const unsigned div_Goldschmidt_theta = ceil(log2(FIXEDPOINT_BITS/3.5));
static const unsigned div_Goldschmidt_theta = 5;

// only the last FIXEDPOINT_FRACTION_BITS are "1", the rest are "0"
// ufixedptd fraction_all_one = (ufixedptd(1)<<FIXEDPOINT_FRACTION_BITS)-1;
// ufixedptd fraction_all_one_invert = fraction_all_one;
// for(std::size_t i =0;i<sizeof(ufixedptd)*8;i++){
//     fraction_all_one_invert = fraction_all_one_invert ^ ((ufixedptd)(1)<<i);
// }
// #define fixedptd integer_part_mask = 18446744073709486080L;

// static const fixedptd fraction_part_mask = ((fixedptd)1 << FIXEDPOINT_FRACTION_BITS) - 1;

// ============================================================

fixedptd absolute_value(fixedptd a);

double fixedptd_to_double(fixedptd fixed_point);

// convert double coefficient to fixed-point numbers (as integer)
void double_to_fixedptd(const double coeff[], unsigned coeff_size);

fixedptd double_to_fixedptd(const double double_value);

fixedptd fixedptd_add(fixedptd a, fixedptd b);

fixedptd fixedptd_sub(fixedptd a, fixedptd b);

// overflowfree version
fixedptd fixedptd_mul(fixedptd a, fixedptd b);

// overflowfree version
// very slow
fixedptd fixedptd_div(fixedptd a, fixedptd b);

fixedptd fixedptd_gt(fixedptd a, fixedptd b);

fixedptd fixedptd_ltz(fixedptd a, fixedptd not_used);

fixedptd fixedptd_eqz(fixedptd a, fixedptd not_used);

fixedptd fixedptd_ceil(fixedptd a, fixedptd not_used);

// directly manipulate on boolean bits without circuits
fixedptd fixedptd_floor(fixedptd a, fixedptd not_used);

// round fixed-point to nearest integer
fixedptd fixedptd_to_int64(fixedptd a, fixedptd not_used);

fixedptd fixedptd_poly_eval(fixedptd x, const fixedptd coeff[], unsigned coeff_size);

fixedptd KMulL(fixedptd *x_array, unsigned head, unsigned tail);

fixedptd KAddL(fixedptd *x_array, unsigned head, unsigned tail);

fixedptd
fixedptd_poly_eval_low_depth(fixedptd x, const fixedptd coeff[], unsigned coeff_size, unsigned log_coeff_size, unsigned max_pow2_log_coeff_size);

// 2^x
// x: integer
fixedptd pow2(fixedptd x);

// 2^(-x)
// x: positive integer
fixedptd pow2_neg(fixedptd x);

fixedptd msb_index(fixedptd x);

fixedptd msb_index_reverse(fixedptd x);

// TODO: regenerate circuits, as abs is not correct for fixedptd
// ! note efficient because of division
fixedptd fixedptd_exp2_P1045_slow(fixedptd a, fixedptd not_used);

// more efficient without division operation
fixedptd fixedptd_exp2_P1045(fixedptd a, fixedptd not_used);

//   return result;
// }
// 2^{a}, a is in (-1,0]
fixedptd fixedptd_exp2_P1045_neg_0_1(fixedptd a, fixedptd not_used);

// 2^{a}, a is in (-1,0]
fixedptd fixedptd_exp2_P1045_neg_0_1_low_depth(fixedptd a, fixedptd not_used);

// backup
fixedptd fixedptd_log2_P2508(fixedptd a, fixedptd not_used);;

fixedptd fixedptd_sqrt_P0132(fixedptd a, fixedptd not_used);

fixedptd fixedptd_LinAppSQ(fixedptd a);

fixedptd fixedptd_sqrt(fixedptd x, fixedptd not_used);

fixedptd fixedptd_exp(fixedptd x, fixedptd not_used);

fixedptd fixedptd_exp_neg_0_1(fixedptd x, fixedptd not_used);

fixedptd fixedptd_ln(fixedptd x, fixedptd not_used);

// a >= 0;
fixedptd fixedptd_AppRcr(fixedptd a);

// TODO: regenerate circuits, as abs is not correct for fixedptd
fixedptd fixedptd_div_Goldschmidt(fixedptd a, fixedptd b);

fixedptd fixedptd_exp2_P1045_with_div_Goldschmidt(fixedptd a, fixedptd not_used);

// a is a non-zero integer, the output is a floating-point number without sign
// we set the sign and deal with the case that a=0 in MOTION
// as we can't convert to Bristol format with direct connection between input and output
float32 fixedptd_to_float32(fixedptd a, fixedptd not_used);

float64 fixedptd_to_float64(fixedptd a, fixedptd not_used);

fixedptd fixedptd_int32_to_fix64(int32 a, fixedptd not_used);

fixedptd fixedptd_int64_to_fix64(int64 a, fixedptd not_used);

fixedptd fixedptd_sqr(fixedptd a, fixedptd not_used);

// x in range (0,1)
fixedptd fixedptd_sin_P3307(fixedptd x, fixedptd not_used);

// x in range (0,pi/2)
fixedptd fixedptd_cos_P3508(fixedptd x, fixedptd not_used);



void test_fix64_k64_f16();