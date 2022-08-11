//
// Created by liangzhao on 18.05.22.
//
// !has error when generating circuits with CBMC-GC
#pragma once

#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "print_uint128_t.h"
#include "fixed_point_operation.h"
#include "snapping_mechanism.h"

#define FIXEDPOINT_BITS 64
#define FIXEDPOINT_INTEGER_BITS 16
#define FIXEDPOINT_FRACTION_BITS (FIXEDPOINT_BITS - FIXEDPOINT_INTEGER_BITS)

// typedef int32_t fixedpt;
typedef uint64_t ufixedptd;
typedef int64_t fixedptd;

typedef __uint128_t ufixedptd_t;
typedef __int128_t fixedptd_t;

#define constant_fixed_point_one (fixedptd)((fixedptd)1 << FIXEDPOINT_FRACTION_BITS)

#define fraction_part_mask (((fixedptd)1 << FIXEDPOINT_FRACTION_BITS) - 1)
#define integer_part_mask 18446744073709486080L

#define floating_point_mantissa_bits_l 52
#define floating_point_exponente_bits_k 11
#define floating_point_mantissa_mask (((fixedptd)1 << floating_point_mantissa_bits_l) - 1)
#define floating_point_exponent_mask ((((fixedptd)1 << floating_point_exponente_bits_k) - 1) << floating_point_mantissa_bits_l)
#define floating_point_exponent_bias 1023

// only for test
// typedef int32_t fixedptd;
// typedef unsigned long int fixedptd;

//static const double p_1045[] = {+0.99999999999998151058451, +0.69314718056364205693851, +0.24022650683729748257646, +0.0555041102193305250618, +0.0096181190501642860210497, +0.0013333931011014250476911, +0.00015395144945146697380844, +0.000015368748541192116946474, +0.0000012256971722926501833228, +0.00000014433329807023165258784};
//static const double p_2524[] = {-2.05466671951, -8.8626599391, +6.10585199015, +4.81147460989};
//static const double q_2524[] = {+0.353553425277, +4.54517087629, +6.42784209029, +1};
//static const double p_0132[] = {+0.22906994529, +1.3006690496, -0.90932104982, +0.50104207633, -0.12146838249};
//static const double p_0371[] = {+0.073633718232, +0.946607534649, +0.444001732732, -0.041034283936};
//static const double q_0371[] = {+0.4232099882, +1.0};
//static const double p_2508[] = {-4.58532387645, 18.3513525596, -51.5256443742, +111.767841656, -174.170840774, +191.731001033, -145.611919796, +72.6500829774, -21.4473491967, +2.84079979731};
//static const double p_LinAppSQ[] = {+1.787727479, -0.8099868542};
static const double p_AppRcr[] = {2.9142, -2};

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
static const fixedptd p_1045_fixedptd[] = {281474976710650 , 195103586506208 , 67617750417310 , 15623018131331 , 2707259835645 , 375316792078 , 43333480648 , 4325918137 , 345003083 , 40626211};
static const fixedptd p_2524_fixedptd[] = {-578337267022237 , -2494616999952636 , 1718644546726183 , 1354309703762700};
static const fixedptd q_2524_fixedptd[] = {99516442145816 , 1279351866549679 , 1809276702664152 , 281474976710656};
static const fixedptd p_2508_fixedptd[] = {-1290653931334578 , 5165446534322447 , -14503179550229488 , 31459850627122888 , -49024733350537024 , 53967479050474440 , -40986111733373008 , 20449180414090892 , -6036892115646439 , 799614056787468};
static const fixedptd p_0132_fixedptd[] = {64477457515613 , 366105790444431 , -255951121320593 , 141030806766045 , -34190310132453};
static const fixedptd p_0371_fixedptd[] = {20726049124471 , 266446333769458 , 124975377380230 , -11550124115224};
static const fixedptd q_0371_fixedptd[] = {119123021572312 , 281474976710656};
static const fixedptd p_LinAppSq_fixedptd[] = {503200550516524 , -227991030921882};
static const fixedptd p_AppRcr_fixedptd[] = {820274377130193 , -562949953421312};

static const fixedptd constant_fixed_point_1 = (fixedptd) 1 << (FIXEDPOINT_FRACTION_BITS);
static const fixedptd constant_fixed_point_2 = (fixedptd) 2 << (FIXEDPOINT_FRACTION_BITS);
static const fixedptd constant_fixed_point_3 = (fixedptd) 3 << (FIXEDPOINT_FRACTION_BITS);

// static const fixedptd constant_3_div_2 = (fixedptd)((3.0 / 2) * pow(2, FIXEDPOINT_FRACTION_BITS));
static const fixedptd constant_3_div_2 = 422212465065984;

// static const fixedptd constant_M_SQRT1_2 = (fixedptd) (M_SQRT1_2 * pow(2, FIXEDPOINT_FRACTION_BITS));
static const fixedptd constant_M_SQRT1_2 = 199032864766430;

// static const fixedptd constant_SQRT1_2_minus_1 = (fixedptd)((M_SQRT1_2 - 1) * pow(2, FIXEDPOINT_FRACTION_BITS));
static const fixedptd constant_SQRT1_2_minus_1 = -82442111944225;

// static const fixedptd constant_SQRT2_minus_1 = (fixedptd) ((M_SQRT2 - 1) * pow(2, FIXEDPOINT_FRACTION_BITS));
static const fixedptd constant_SQRT2_minus_1 = 116590752822204;

// static const fixedptd constant_M_LN2 = (fixedptd) (M_LN2 * pow(2, FIXEDPOINT_FRACTION_BITS));
static const fixedptd constant_M_LN2 = 195103586505167;

// static const fixedptd constant_M_LOG2E = (fixedptd) (M_LOG2E * pow(2, FIXEDPOINT_FRACTION_BITS));
static const fixedptd constant_M_LOG2E = 406082553034799;

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

fixedptd absolute_value(fixedptd a) {
    bool a_LTZ = a < 0;

    fixedptd a_abs = 0;
    if (a_LTZ) {
        a_abs = -a;
    } else
        a_abs = a;

    return a_abs;
}

double fixeddptd_to_double(fixedptd fixed_point) {
    double result;
    result = (double) ((fixedptd) (fixed_point)) / (double) (pow(2, FIXEDPOINT_FRACTION_BITS));

    //    print_u128_u("T_int(fixed_point_struct.v): ", T_int(fixed_point));
    return result;
}

// convert double coefficient to fixed-point numbers (as integer)
fixedptd double_to_fixedptd(const double double_value) {
    fixedptd result = 0;
    if (double_value < 0) {

        result = -(fixedptd) (-double_value * (pow(2, FIXEDPOINT_FRACTION_BITS)));
    } else {
        result = (fixedptd) (double_value * (pow(2, FIXEDPOINT_FRACTION_BITS)));
    }
    return result;
}

// convert double coefficient to fixed-point numbers (as integer)
void double_to_fixedptd(const double coeff[], unsigned coeff_size) {
    fixedptd fixed_point_array[coeff_size];
    unsigned i;
    for (i = 0; i < coeff_size; i++) {
        if (coeff[i] < 0) {

            fixed_point_array[i] = -(fixedptd) (-coeff[i] * (pow(2, FIXEDPOINT_FRACTION_BITS)));
        } else {
            fixed_point_array[i] = (fixedptd) (coeff[i] * (pow(2, FIXEDPOINT_FRACTION_BITS)));
        }
    }
    for (i = 0; i < coeff_size; i++) {
        printf("%ld ", fixed_point_array[i]);
        printf(", ");
    }
    printf("\n");
}

void generate_constants() {
    std::cout<<"p_1045: ";
    double_to_fixedptd(p_1045, (sizeof(p_1045)/sizeof(*p_1045)));

    std::cout<<"p_2524_fixedptd: ";
    double_to_fixedptd(p_2524, (sizeof(p_2524)/sizeof(*p_2524)));

    std::cout<<"q_2524_fixedptd: ";
    double_to_fixedptd(q_2524, (sizeof(q_2524)/sizeof(*q_2524)));

    std::cout<<"p_2508_fixedptd: ";
    double_to_fixedptd(p_2508, (sizeof(p_2508)/sizeof(*p_2508)));

    std::cout<<"p_0132_fixedptd: ";
    double_to_fixedptd(p_0132, (sizeof(p_0132)/sizeof(*p_0132)));

    std::cout<<"p_0371_fixedptd: ";
    double_to_fixedptd(p_0371, (sizeof(p_0371)/sizeof(*p_0371)));

    std::cout<<"q_0371_fixedptd: ";
    double_to_fixedptd(q_0371, (sizeof(q_0371)/sizeof(*q_0371)));

    std::cout<<"p_LinAppSq_fixedptd: ";
    double_to_fixedptd(p_LinAppSQ, (sizeof(p_LinAppSQ)/sizeof(*p_LinAppSQ)));

    std::cout<<"p_AppRcr_fixedptd: ";
    double_to_fixedptd(p_AppRcr, (sizeof(p_AppRcr)/sizeof(*p_AppRcr)));

    std::cout<<  "constant_3_div_2: " << (fixedptd)((3.0 / 2) * pow(2, FIXEDPOINT_FRACTION_BITS))<<std::endl;
    std::cout<<  "constant_M_SQRT1_2: " << (fixedptd) (M_SQRT1_2 * pow(2, FIXEDPOINT_FRACTION_BITS))<<std::endl;
    std::cout<<  "constant_SQRT1_2_minus_1: " << (fixedptd)((M_SQRT1_2 - 1) * pow(2, FIXEDPOINT_FRACTION_BITS))<<std::endl;
    std::cout<<  "constant_SQRT2_minus_1: " << (fixedptd) ((M_SQRT2 - 1) * pow(2, FIXEDPOINT_FRACTION_BITS))<<std::endl;
    std::cout<<  "constant_M_LN2: " <<  (fixedptd) (M_LN2 * pow(2, FIXEDPOINT_FRACTION_BITS))<<std::endl;
    std::cout<<  "constant_M_LOG2E: " << (fixedptd) (M_LOG2E * pow(2, FIXEDPOINT_FRACTION_BITS))<<std::endl;
    std::cout<<  "sqrt_theta: " << ceil(log2(FIXEDPOINT_BITS / 5.4))<<std::endl;
    std::cout<<  "pow2_m: " <<  ceil(log2(FIXEDPOINT_BITS))<<std::endl;
    std::cout<<  "div_Goldschmidt_theta: " << ceil(log2(FIXEDPOINT_BITS/3.5))<<std::endl;
}

fixedptd fixedptd_add(fixedptd a, fixedptd b) {
    return (a + b);
}

fixedptd fixedptd_sub(fixedptd a, fixedptd b) {
    return (a - b);
}

//fixedptd fixedptd_mul(fixedptd a, fixedptd b) {
//    fixedptd c = (a * b) >> FIXEDPOINT_FRACTION_BITS;
//    return c;
//}

// overflowfree version
fixedptd fixedptd_mul(fixedptd a, fixedptd b) {
    fixedptd c = ((fixedptd_t) a * (fixedptd_t) b) >> FIXEDPOINT_FRACTION_BITS;
    return c;
}

//// TODO: overflow?
//// TODO: depth not optimized, find other algorithms
//fixedptd fixedptd_div(fixedptd a, fixedptd b) {
//    return (fixedptd) (a << FIXEDPOINT_FRACTION_BITS) / b;
//}

// overflowfree version
fixedptd fixedptd_div(fixedptd a, fixedptd b) {
    return  ((fixedptd_t)(a) << FIXEDPOINT_FRACTION_BITS) / b;}

// fixedptd fixedptd_div(fixedptd a, fixedptd b)
// {
//   return (ufixedptd(a) << FIXEDPOINT_FRACTION_BITS) / b;
// }

fixedptd fixedptd_gt(fixedptd a, fixedptd b) {
    return (a > b);
}

fixedptd fixedptd_ltz(fixedptd a, fixedptd not_used) {
    return (a < 0);
}

fixedptd fixedptd_eqz(fixedptd a, fixedptd not_used) {
    return (a == 0);
}

fixedptd fixedptd_ceil(fixedptd a, fixedptd not_used) {
    // fixedptd a_abs = absolute_value(a);
    // bool fractional_part_msb = a_abs & ((fixedptd)1 << (FIXEDPOINT_FRACTION_BITS - 1));
    // bool a_LTZ = a < 0;

    // fixedptd a_ceil = 0;
    // if (fractional_part_msb)
    // {
    //   fixedptd a_prime = a + ((ufixedptd)1 << (FIXEDPOINT_FRACTION_BITS));
    //   // a_ceil = a_prime & integer_part_mask;
    //   a_ceil = ((a_prime >> FIXEDPOINT_FRACTION_BITS) << FIXEDPOINT_FRACTION_BITS);
    // }
    // else
    // {
    //   // fixedptd a_prime = a_abs;
    //   // a_ceil = (a_prime & integer_part_mask);
    //   a_ceil = ((a >> FIXEDPOINT_FRACTION_BITS) << FIXEDPOINT_FRACTION_BITS) + a_LTZ * ((fixedptd)1 << FIXEDPOINT_FRACTION_BITS);

    //   // return a_prime >> ;
    // }
    // // return a_ceil;

    // return a_abs & fraction_part_mask;

    fixedptd a_prime = a + fraction_part_mask;
    fixedptd a_ceil = ((a_prime >> FIXEDPOINT_FRACTION_BITS) << FIXEDPOINT_FRACTION_BITS);
    return a_ceil;
}

fixedptd fixedptd_floor(fixedptd a, fixedptd not_used) {
    fixedptd a_floor = (a >> (FIXEDPOINT_FRACTION_BITS)) << (FIXEDPOINT_FRACTION_BITS);
    return a_floor;
}

fixedptd fixedptd_fx2int(fixedptd a, fixedptd not_used) {
    bool fractional_part_msb = absolute_value(a) & ((fixedptd) 1 << (FIXEDPOINT_FRACTION_BITS - 1));
    fixedptd a_fx2int = 0;
    bool a_GTZ = a > 0;

    if (fractional_part_msb) {
        if (a_GTZ) {
            a_fx2int = fixedptd_ceil(a, a);
            a_fx2int = a_fx2int >> FIXEDPOINT_FRACTION_BITS;
        } else {
            a_fx2int = fixedptd_floor(a, a);
            a_fx2int = a_fx2int >> FIXEDPOINT_FRACTION_BITS;
        }
    } else {
        if (a_GTZ) {
            a_fx2int = fixedptd_floor(a, a);
            a_fx2int = a_fx2int >> FIXEDPOINT_FRACTION_BITS;
        } else {
            a_fx2int = fixedptd_ceil(a, a);
            a_fx2int = a_fx2int >> FIXEDPOINT_FRACTION_BITS;
            // a_fx2int = a_fx2int;
        }
    }

    return a_fx2int;
}

fixedptd fixedptd_poly_eval(fixedptd x, const fixedptd coeff[], unsigned coeff_size) {
    fixedptd x_premult = x;
    fixedptd local_aggregation = coeff[0];

    unsigned i;
    for (i = 1; i < coeff_size - 1; i++) {
        fixedptd coefficient_mul_x = fixedptd_mul(coeff[i], x_premult);
        local_aggregation = local_aggregation + coefficient_mul_x;
        x_premult = fixedptd_mul(x, x_premult);
    }

    fixedptd coefficient_mul_x = fixedptd_mul(coeff[i], x_premult);
    local_aggregation = local_aggregation + coefficient_mul_x;

    return local_aggregation;
}

fixedptd KMulL(fixedptd *x_array, unsigned head, unsigned tail) {
    if (tail - head == 0) {
        return x_array[head];
    } else {
        fixedptd premult_left = KMulL(x_array, head, head + (tail - head) / 2);
        fixedptd premult_right = KMulL(x_array, head + (tail - head) / 2 + 1, tail);
        return premult_left * premult_right;
    }
}

// 2^x
// x: integer
fixedptd pow2(fixedptd x) {
    unsigned i;

    fixedptd x_temp = x;
    bool x_array[FIXEDPOINT_BITS];

    for (i = 0; i < FIXEDPOINT_INTEGER_BITS - 1; i++) {
        x_array[i] = x_temp & 1;
        x_temp = x_temp >> 1;
    }
    x_array[FIXEDPOINT_INTEGER_BITS - 1] = x_temp & 1;

    unsigned m = pow2_m;

    fixedptd v[m];
    for (i = 0; i < m; i++) {
        v[i] = ((fixedptd) (1) << ((fixedptd) (1) << i)) * x_array[i] + 1 - x_array[i];
    }

    //    fixedptd pow2_x = v[0];
    //    for (std::size_t i = 1; i < m; i++) {
    //        pow2_x = pow2_x * v[i];
    //    }

    // more efficient methodf
    fixedptd pow2_x = KMulL(v, 0, m - 1);

    return pow2_x;
}

// 2^(-x)
// x: positive integer
fixedptd pow2_neg(fixedptd x) {

    // 2^x
    fixedptd pow2_x = pow2(x);

    // compute 2^(-x) by exchange the integer bits and fraction bits:
    // 2^6=64: 01000000.00000000
    // ->
    // 2^(-6): 00000000.00000100

    bool pow2_x_bool_array[FIXEDPOINT_BITS];
    fixedptd pow2_x_temp = pow2_x << FIXEDPOINT_FRACTION_BITS;
//    unsigned i;
//    for (i = 0; i < FIXEDPOINT_INTEGER_BITS - 1; i++) {
//        pow2_x_bool_array[i] = pow2_x_temp & 1;
//        pow2_x_temp = pow2_x_temp >> 1;
//    }
//    pow2_x_bool_array[FIXEDPOINT_INTEGER_BITS - 1] = pow2_x_temp & 1;
    int_to_bool_array(pow2_x_temp, pow2_x_bool_array);

//    for (std::size_t i = 0; i < FIXEDPOINT_BITS; i++) {
//        std::cout << pow2_x_bool_array[i];
//    }
//    std::cout << std::endl;

    unsigned i;
    // exchange the integer bits and fraction bits:
    bool pow2_neg_x_bool_array[FIXEDPOINT_BITS];
    for (i = 0; i < FIXEDPOINT_BITS; i++) {
        pow2_neg_x_bool_array[i] = false;
    }

    for (i = 0; i < FIXEDPOINT_FRACTION_BITS; i++) {
        pow2_neg_x_bool_array[FIXEDPOINT_BITS - i - 1] = pow2_x_bool_array[FIXEDPOINT_INTEGER_BITS - FIXEDPOINT_FRACTION_BITS - 1 + i];
    }
    for (i = 0; i < FIXEDPOINT_INTEGER_BITS - FIXEDPOINT_FRACTION_BITS; i++) {
        pow2_neg_x_bool_array[i] = false;
    }

//    for (std::size_t i = 0; i < FIXEDPOINT_BITS; i++) {
//       std::cout<< pow2_neg_x_bool_array[i] ;
//    }
//    std::cout << std::endl;

//
//     convert pow2_neg_x_array to pow2_neg_x_array
    fixedptd pow2_neg_x = bool_array_to_int(pow2_neg_x_bool_array, FIXEDPOINT_BITS);

    return pow2_neg_x;
}

fixedptd msb_index(fixedptd x) {
    unsigned i;
    fixedptd x_temp = x;
    bool a[FIXEDPOINT_BITS];
    for (i = 0; i < FIXEDPOINT_BITS; i++) {
        a[i] = x_temp & 1;
        x_temp = x_temp >> 1;
    }

    bool b[FIXEDPOINT_BITS];
    b[0] = a[FIXEDPOINT_BITS - 1];
    for (i = 1; i < FIXEDPOINT_BITS; i++) {
        b[i] = b[i - 1] | a[FIXEDPOINT_BITS - 1 - i];
    }

    fixedptd sum_1_minus_bi = (fixedptd) (1 - b[0]);
    for (i = 1; i < FIXEDPOINT_BITS; i++) {
        sum_1_minus_bi = sum_1_minus_bi + (fixedptd) (1 - b[i]);
    }

    return sum_1_minus_bi;
}

fixedptd msb_index_reverse(fixedptd x) {
    unsigned i;
    fixedptd x_temp = x;
    bool a[FIXEDPOINT_BITS];
    for (i = 0; i < FIXEDPOINT_BITS; i++) {
        a[i] = x_temp & 1;
        x_temp = x_temp >> 1;
    }

    bool b[FIXEDPOINT_BITS];
    b[0] = a[FIXEDPOINT_BITS - 1];
    for (i = 1; i < FIXEDPOINT_BITS; i++) {
        b[i] = b[i - 1] | a[FIXEDPOINT_BITS - 1 - i];
    }

    fixedptd sum_bi = (fixedptd) (b[0]);
    for (i = 1; i < FIXEDPOINT_BITS; i++) {
        sum_bi = sum_bi + (fixedptd) (b[i]);
    }

    return sum_bi;
}

// TODO: regenerate circuits, as abs is not correct for fixedptd
// ! note efficient because of division
fixedptd fixedptd_exp2_P1045_slow(fixedptd a, fixedptd not_used) {
    bool s = a < 0;
    fixedptd a_prime = absolute_value(a);
    fixedptd b = a_prime >> FIXEDPOINT_FRACTION_BITS;
    fixedptd c = a_prime & fraction_part_mask;

    fixedptd d = pow2(b);

    fixedptd e = fixedptd_poly_eval(c, p_1045_fixedptd, sizeof(p_1045_fixedptd) / sizeof(p_1045_fixedptd[0]));

    fixedptd g = d * e;

    // TODO: more efficient for division
    fixedptd g_inverse = ((fixedptd) 1 << (2 * FIXEDPOINT_FRACTION_BITS)) / g;
    fixedptd pow2_a = (1 - s) * g + s * g_inverse;

    return pow2_a;
}

// more efficient without division operation
fixedptd fixedptd_exp2_P1045(fixedptd a, fixedptd not_used) {
    bool a_LTZ = a < 0;
    bool a_EQZ = a == 0;

    fixedptd a_abs = absolute_value(a);
    fixedptd a_integer_abs = a_abs >> FIXEDPOINT_FRACTION_BITS;
    fixedptd a_fraction = a_abs & fraction_part_mask;
    bool fraction_all_zeros = a_fraction == 0;

    fixedptd result = 0;

    if (a_EQZ) {
        result = (fixedptd) 1 << FIXEDPOINT_FRACTION_BITS;
    }
        // when a > 0
    else if (!a_LTZ) {
        fixedptd pow2_a_integer_abs = pow2(a_integer_abs);
        fixedptd pow2_a_fraction = fixedptd_poly_eval(a_fraction, p_1045_fixedptd, sizeof(p_1045_fixedptd) / sizeof(p_1045_fixedptd[0]));
        result = pow2_a_integer_abs * pow2_a_fraction;

//        // only for debugging
//        result = pow2_a_integer_abs;
    }

        // a = -1
    else if (fraction_all_zeros) {
        fixedptd pow2_neg_a_integer_abs = pow2_neg(a_integer_abs);
        result = pow2_neg_a_integer_abs;
    }

        // if a = -1.4, a_integer = -2, a_fraction = 0.6
    else {
        fixedptd a_integer_abs_plus_1 = a_integer_abs + (fixedptd) (1);
        fixedptd pow2_neg_a_integer_abs_plus_1 = pow2_neg(a_integer_abs_plus_1);
        fixedptd one_minus_a_fraction = ((fixedptd) 1 << FIXEDPOINT_FRACTION_BITS) - a_fraction;
        fixedptd pow2_one_minus_a_fraction = fixedptd_poly_eval(one_minus_a_fraction, p_1045_fixedptd,
                                                                sizeof(p_1045_fixedptd) / sizeof(p_1045_fixedptd[0]));
        result = fixedptd_mul(pow2_neg_a_integer_abs_plus_1, pow2_one_minus_a_fraction);

//        // only for debugging
//        result =pow2_one_minus_a_fraction;

    }
    return result;
}



// not efficient as fixedptd_exp2_P1045
// fixedptd fixedptd_exp2_PQ1064(fixedptd a, fixedptd not_used)
// {
// }

// fixedptd fixedptd_log2_P2508(fixedptd a, fixedptd not_used)
// {
//   fixedptd a_temp = a;
//   unsigned char k = msb_index_reverse(a);
//   unsigned char k_minus_f = k - FIXEDPOINT_FRACTION_BITS;
//   unsigned char f_minus_k = FIXEDPOINT_FRACTION_BITS - k;

//   bool right_shift = k > (unsigned char)FIXEDPOINT_FRACTION_BITS;
//   bool left_shift = !right_shift;

//   fixedptd a_norm = right_shift * (a_temp >> k_minus_f) + left_shift * (a_temp << f_minus_k);

//   fixedptd P = fixedptd_poly_eval(a_norm, p_2508_fixedptd, sizeof(p_2508_fixedptd) / sizeof(p_2508_fixedptd[0]));

//   fixedptd log2_a = P + right_shift * k_minus_f * constant_fixed_point_1 - left_shift * f_minus_k * constant_fixed_point_1;
//   return log2_a;
// }

// TODO:: test and compare
fixedptd fixedptd_log2_P2508(fixedptd a, fixedptd not_used) {
    fixedptd a_temp = a;
    unsigned char k = msb_index_reverse(a);
    char k_minus_f = k - FIXEDPOINT_FRACTION_BITS;
    char f_minus_k = FIXEDPOINT_FRACTION_BITS - k;

    bool right_shift = k > (unsigned char) FIXEDPOINT_FRACTION_BITS;
    bool left_shift = !right_shift;

    fixedptd a_norm;
    if (right_shift) {
        a_norm = a_temp >> k_minus_f;
    } else {
        a_norm = a_temp << f_minus_k;
    }

    fixedptd P = fixedptd_poly_eval(a_norm, p_2508_fixedptd, sizeof(p_2508_fixedptd) / sizeof(p_2508_fixedptd[0]));

    fixedptd log2_a;
    log2_a = P + k_minus_f * constant_fixed_point_1;

    return log2_a;
}

// fixedptd fixedptd_log2_PQ2524(fixedptd a, fixedptd not_used)
// {
//   fixedptd a_temp = a;
//   unsigned char k = msb_index_reverse(a);
//   unsigned char k_minus_f = k - FIXEDPOINT_FRACTION_BITS;
//   unsigned char f_minus_k = FIXEDPOINT_FRACTION_BITS - k;

//   bool right_shift = k > (unsigned char)FIXEDPOINT_FRACTION_BITS;
//   bool left_shift = !right_shift;

//   fixedptd a_norm = right_shift * (a_temp >> k_minus_f) + left_shift * (a_temp << f_minus_k);

//   fixedptd P = fixedptd_poly_eval(a_norm, p_2524_fixedptd, sizeof(p_2524_fixedptd) / sizeof(p_2524_fixedptd[0]));
//   fixedptd Q = fixedptd_poly_eval(a_norm, q_2524_fixedptd, sizeof(q_2524_fixedptd) / sizeof(q_2524_fixedptd[0]));

//   fixedptd P_div_Q = fixedptd_div(P, Q);

//   fixedptd log2_a = P_div_Q + right_shift * k_minus_f * constant_fixed_point_1 - left_shift * f_minus_k * constant_fixed_point_1;
//   return log2_a;
// }

// // TODO: correction
// fixedptd fixedptd_sqrt_P0132(fixedptd a, fixedptd not_used)
// {
//   fixedptd a_temp = a;
//   unsigned char k = msb_index_reverse(a);
//   unsigned char k_minus_f = k - FIXEDPOINT_FRACTION_BITS;
//   unsigned char f_minus_k = FIXEDPOINT_FRACTION_BITS - k;

//   bool right_shift = k > (unsigned char)FIXEDPOINT_FRACTION_BITS;
//   bool left_shift = !right_shift;

//   fixedptd a_norm = right_shift * (a_temp >> k_minus_f) + left_shift * (a_temp << f_minus_k);

//   fixedptd P = fixedptd_poly_eval(a_norm, p_0132_fixedptd, sizeof(p_0132_fixedptd) / sizeof(p_0132_fixedptd[0]));

//   fixedptd k_minus_f_div_2 = k_minus_f >> 1;
//   fixedptd f_minus_k_div_2 = f_minus_k >> 1;

//   fixedptd P_1_div_sqrt_x_right_shift = P << k_minus_f_div_2;
//   fixedptd P_1_div_sqrt_x_left_shift = P >> f_minus_k_div_2;
//   fixedptd P_1_div_sqrt_x_shift = right_shift * P_1_div_sqrt_x_right_shift + left_shift * P_1_div_sqrt_x_left_shift;

//   bool k_minus_f_is_odd = k_minus_f & 1;

//   fixedptd correction = right_shift * (constant_fixed_point_1 + k_minus_f_is_odd * (constant_SQRT2_minus_1)) +
//                         left_shift * (constant_fixed_point_1 + k_minus_f_is_odd * (constant_SQRT1_2_minus_1));

//   fixedptd result = fixedptd_mul(P_1_div_sqrt_x_shift, correction);

//   return result;
// }

fixedptd fixedptd_sqrt_P0132(fixedptd a, fixedptd not_used) {
    fixedptd a_temp = a;
    unsigned char k = msb_index_reverse(a);
    unsigned char k_minus_f = k - FIXEDPOINT_FRACTION_BITS;
    unsigned char f_minus_k = FIXEDPOINT_FRACTION_BITS - k;

    bool right_shift = k > (unsigned char) FIXEDPOINT_FRACTION_BITS;
    bool left_shift = !right_shift;

    fixedptd a_norm = right_shift * (a_temp >> k_minus_f) + left_shift * (a_temp << f_minus_k);

    fixedptd P = fixedptd_poly_eval(a_norm, p_0132_fixedptd, sizeof(p_0132_fixedptd) / sizeof(p_0132_fixedptd[0]));

    fixedptd k_minus_f_div_2 = k_minus_f >> 1;
    fixedptd f_minus_k_div_2 = f_minus_k >> 1;

    fixedptd P_1_div_sqrt_x_right_shift = P << k_minus_f_div_2;
    fixedptd P_1_div_sqrt_x_left_shift = P >> f_minus_k_div_2;
    fixedptd P_1_div_sqrt_x_shift = right_shift * P_1_div_sqrt_x_right_shift + left_shift * P_1_div_sqrt_x_left_shift;

    bool k_minus_f_is_odd = k_minus_f & 1;

    fixedptd correction = right_shift * (constant_fixed_point_1 + k_minus_f_is_odd * (constant_SQRT2_minus_1)) +
                          left_shift * (constant_fixed_point_1 + k_minus_f_is_odd * (constant_SQRT1_2_minus_1));

    fixedptd result = fixedptd_mul(P_1_div_sqrt_x_shift, correction);

    return result;
}

// // TODO: correction
// fixedptd fixedptd_sqrt_PQ0371(fixedptd a, fixedptd not_used)
// {

//   fixedptd a_temp = a;
//   unsigned char k = msb_index_reverse(a);
//   unsigned char k_minus_f = k - FIXEDPOINT_FRACTION_BITS;
//   unsigned char f_minus_k = FIXEDPOINT_FRACTION_BITS - k;

//   bool right_shift = k > (unsigned char)FIXEDPOINT_FRACTION_BITS;
//   bool left_shift = !right_shift;

//   fixedptd a_norm = right_shift * (a_temp >> k_minus_f) + left_shift * (a_temp << f_minus_k);

//   fixedptd P = fixedptd_poly_eval(a_norm, p_0371_fixedptd, sizeof(p_0371_fixedptd) / sizeof(p_0371_fixedptd[0]));
//   fixedptd Q = fixedptd_poly_eval(a_norm, q_0371_fixedptd, sizeof(q_0371_fixedptd) / sizeof(q_0371_fixedptd[0]));

//   fixedptd P_div_Q = fixedptd_div(P, Q);

//   fixedptd k_minus_f_div_2 = k_minus_f >> 1;
//   fixedptd f_minus_k_div_2 = f_minus_k >> 1;

//   fixedptd P_1_div_sqrt_x_right_shift = P_div_Q << k_minus_f_div_2;
//   fixedptd P_1_div_sqrt_x_left_shift = P_div_Q >> f_minus_k_div_2;
//   fixedptd P_1_div_sqrt_x_shift = right_shift * P_1_div_sqrt_x_right_shift + left_shift * P_1_div_sqrt_x_left_shift;

//   bool k_minus_f_is_odd = k_minus_f & 1;

//   fixedptd correction = right_shift * (constant_fixed_point_1 + k_minus_f_is_odd * (constant_SQRT2_minus_1)) +
//                         left_shift * (constant_fixed_point_1 + k_minus_f_is_odd * (constant_SQRT1_2_minus_1));

//   fixedptd result = fixedptd_mul(P_1_div_sqrt_x_shift, correction);

//   return result;
// }

fixedptd fixedptd_LinAppSQ(fixedptd a) {
    fixedptd a_temp = a;
    unsigned char k = msb_index_reverse(a);
    unsigned char k_minus_f = k - FIXEDPOINT_FRACTION_BITS;
    unsigned char f_minus_k = FIXEDPOINT_FRACTION_BITS - k;

    bool right_shift = k > (unsigned char) FIXEDPOINT_FRACTION_BITS;
    bool left_shift = !right_shift;

    fixedptd a_norm = right_shift * (a_temp >> k_minus_f) + left_shift * (a_temp << f_minus_k);

    fixedptd P_1_div_sqrt_x = fixedptd_poly_eval(a_norm, p_LinAppSq_fixedptd, sizeof(p_LinAppSq_fixedptd) / sizeof(p_LinAppSq_fixedptd[0]));

    fixedptd k_minus_f_div_2 = k_minus_f >> 1;
    fixedptd f_minus_k_div_2 = f_minus_k >> 1;

    fixedptd P_1_div_sqrt_x_right_shift = P_1_div_sqrt_x >> k_minus_f_div_2;
    fixedptd P_1_div_sqrt_x_left_shift = P_1_div_sqrt_x << f_minus_k_div_2;
    fixedptd P_1_div_sqrt_x_shift = right_shift * P_1_div_sqrt_x_right_shift + left_shift * P_1_div_sqrt_x_left_shift;

    bool k_minus_f_is_odd = k_minus_f & 1;

    fixedptd correction = right_shift * (constant_fixed_point_1 + k_minus_f_is_odd * (constant_SQRT1_2_minus_1)) +
                          left_shift * (constant_fixed_point_1 + k_minus_f_is_odd * (constant_SQRT2_minus_1));

    fixedptd result = fixedptd_mul(P_1_div_sqrt_x_shift, correction);

    return result;
}

fixedptd fixedptd_sqrt(fixedptd x, fixedptd not_used) {

    fixedptd y0 = fixedptd_LinAppSQ(x);
    fixedptd x0 = x;

    fixedptd g0 = fixedptd_mul(x0, y0);
    fixedptd h0 = y0 >> 1;
    fixedptd g0h0 = fixedptd_mul(g0, h0);

    fixedptd g = g0;
    fixedptd h = h0;
    fixedptd gh = g0h0;

    unsigned i;
    for (i = 1; i < (sqrt_theta - 2); i++) {
        fixedptd r = fixedptd_sub(constant_3_div_2, gh);
        g = fixedptd_mul(g, r);
        h = fixedptd_mul(h, r);
        gh = fixedptd_mul(g, h);
    }

    fixedptd r = fixedptd_sub(constant_3_div_2, gh);
    h = fixedptd_mul(h, r);
    fixedptd H_mul_2 = fixedptd_mul(constant_fixed_point_2, h);
    fixedptd H_square = fixedptd_mul(H_mul_2, H_mul_2);
    fixedptd H_mul_x = fixedptd_mul(H_square, x);
    fixedptd H_mul_3 = fixedptd_sub(constant_fixed_point_3, H_mul_x);
    fixedptd H_mul_h = fixedptd_mul(H_mul_3, h);
    g = fixedptd_mul(H_mul_h, x);

    return g;
}

fixedptd fixedptd_exp(fixedptd x, fixedptd not_used) {
    fixedptd result = fixedptd_exp2_P1045(fixedptd_mul(x, constant_M_LOG2E), not_used);
    return result;
}

fixedptd fixedptd_ln(fixedptd x, fixedptd not_used) {
    fixedptd result = fixedptd_mul(fixedptd_log2_P2508(x, not_used), constant_M_LN2);
    return result;
}

// a >= 0;
fixedptd fixedptd_AppRcr(fixedptd a) {
    fixedptd a_temp = a;
    unsigned char k = msb_index_reverse(a);
    unsigned char k_minus_f = k - FIXEDPOINT_FRACTION_BITS;
    unsigned char f_minus_k = FIXEDPOINT_FRACTION_BITS - k;

    bool right_shift = k > (unsigned char) FIXEDPOINT_FRACTION_BITS;
    bool left_shift = !right_shift;

    fixedptd a_norm = right_shift * (a_temp >> k_minus_f) + left_shift * (a_temp << f_minus_k);

    fixedptd P_1_div_x = fixedptd_poly_eval(a_norm, p_AppRcr_fixedptd, sizeof(p_AppRcr_fixedptd) / sizeof(p_AppRcr_fixedptd[0]));

    fixedptd P_1_div_x_right_shift = P_1_div_x >> k_minus_f;
    fixedptd P_1_div_x_left_shift = P_1_div_x << f_minus_k;
    fixedptd P_1_div_x_shift = right_shift * P_1_div_x_right_shift + left_shift * P_1_div_x_left_shift;

    return P_1_div_x_shift;
}

// TODO: regenerate circuits, as abs is not correct for fixedptd
fixedptd fixedptd_div_Goldschmidt(fixedptd a, fixedptd b) {
    unsigned theta = div_Goldschmidt_theta;

    fixedptd b_positive = absolute_value(b);
    bool b_LTZ = b < 0;

    fixedptd w = fixedptd_AppRcr(b_positive);

    fixedptd x = fixedptd_sub(constant_fixed_point_1, fixedptd_mul(b_positive, w));
    fixedptd y = fixedptd_mul(a, w);

    unsigned i;
    for (i = 1; i < theta; i++) {
        y = fixedptd_mul(y, fixedptd_add(constant_fixed_point_1, x));
        x = fixedptd_mul(x, x);
    }
    y = fixedptd_mul(y, fixedptd_add(constant_fixed_point_1, x));

    fixedptd y_correction = y * (1 - 2 * b_LTZ);

    return y_correction;
}

fixedptd fixedptd_exp2_P1045_with_div_Goldschmidt(fixedptd a, fixedptd not_used) {
    bool s = a < 0;
    fixedptd a_prime = absolute_value(a);
    fixedptd b = a_prime >> FIXEDPOINT_FRACTION_BITS;
    fixedptd c = a_prime & fraction_part_mask;

    fixedptd d = pow2(b);

    fixedptd e = fixedptd_poly_eval(c, p_1045_fixedptd, sizeof(p_1045_fixedptd) / sizeof(p_1045_fixedptd[0]));

    fixedptd g = d * e;

    // TODO: more efficient for division
    // fixedptd g_inverse = ((fixedptd)1 << (2 * FIXEDPOINT_FRACTION_BITS)) / g;
    fixedptd g_inverse = fixedptd_div_Goldschmidt(constant_fixed_point_1, g);

    fixedptd pow2_a = (1 - s) * g + s * g_inverse;

    return pow2_a;
}

// // a is a positive integer, as we can't convert to Bristol format with direct connection between input and output
// fixedptd fixedptd_fx2fl(fixedptd a, fixedptd not_used)
// {
//   // bool a_NEQZ = a != 0;
//   // bool a_EQZ = a == 0;
//   // bool a_LTZ = a < 0;
//   fixedptd floating_point_a = 0;

//   // fixedptd a_abs = absolute_value(a);
//   unsigned char k = msb_index_reverse(a);

//   unsigned char right_shift_num_of_bits = k - (floating_point_mantissa_bits_l + 1);
//   unsigned char left_shift_num_of_bits = (floating_point_mantissa_bits_l + 1) - k;

//   bool right_shift = k > (unsigned char)floating_point_mantissa_bits_l;
//   bool left_shift = !right_shift;

//   fixedptd floating_point_mantissa = right_shift * (a >> right_shift_num_of_bits) + left_shift * (a << left_shift_num_of_bits);

//   fixedptd floating_point_exponent = (fixedptd)(right_shift * right_shift_num_of_bits - left_shift * left_shift_num_of_bits) - FIXEDPOINT_FRACTION_BITS + floating_point_exponent_bias + floating_point_mantissa_bits_l;

//   fixedptd floating_point_a_with_mantissa = floating_point_mantissa & floating_point_mantissa_mask;

//   fixedptd floating_point_a_with_exponent = floating_point_a_with_mantissa ^ (floating_point_exponent << floating_point_mantissa_bits_l);

//   // fixedptd floating_point_a_with_sign = floating_point_a_with_exponent ^ ((fixedptd)a_LTZ << (floating_point_mantissa_bits_l + floating_point_exponente_bits_k));

//   // floating_point_a = (fixedptd)(floating_point_a_with_sign);

//   return floating_point_a_with_exponent;
// }

// a is a non-zero integer, the output is a floating-point number without sign
// we set the sign and deal with the case that a=0 in MOTION
// as we can't convert to Bristol format with direct connection between input and output
fixedptd fixedptd_fx2fl(fixedptd a, fixedptd not_used) {
    // bool a_LTZ = a < 0;
    fixedptd floating_point_a = 0;
    fixedptd a_abs = absolute_value(a);

    unsigned char k = msb_index_reverse(a_abs);

    unsigned char right_shift_num_of_bits = k - (floating_point_mantissa_bits_l + 1);
    unsigned char left_shift_num_of_bits = (floating_point_mantissa_bits_l + 1) - k;

    bool right_shift = k > (unsigned char) floating_point_mantissa_bits_l;
    bool left_shift = !right_shift;

    fixedptd floating_point_mantissa;
    fixedptd floating_point_exponent;

    if (right_shift) {
        floating_point_mantissa = (a_abs >> right_shift_num_of_bits);
        floating_point_exponent = right_shift_num_of_bits;
    } else {
        floating_point_mantissa = (a_abs << left_shift_num_of_bits);
        floating_point_exponent = -left_shift_num_of_bits;
    }

    floating_point_exponent = floating_point_exponent - FIXEDPOINT_FRACTION_BITS + floating_point_exponent_bias + floating_point_mantissa_bits_l;

    fixedptd floating_point_a_with_mantissa = floating_point_mantissa & floating_point_mantissa_mask;

    fixedptd floating_point_a_with_exponent = floating_point_a_with_mantissa ^ (floating_point_exponent << floating_point_mantissa_bits_l);

    // fixedptd floating_point_a_with_sign = (((fixedptd)1 << (floating_point_mantissa_bits_l + floating_point_exponente_bits_k)) & a) ^ floating_point_a_with_exponent;

    floating_point_a = floating_point_a_with_exponent;

    return floating_point_a;
}

fixedptd fixedptd_int2fx(fixedptd a, fixedptd not_used) {
    fixedptd c = (a) << FIXEDPOINT_FRACTION_BITS;
    return c;
}

fixedptd fixedptd_sqr(fixedptd a, fixedptd not_used) {
    fixedptd c = (a * a) << FIXEDPOINT_FRACTION_BITS;
    return c;
}

void test_fix64_k64_f48() {

    double a_double = 1.1;
    double b_double = 2;
    fixedptd c;
    fixedptd a = double_to_fixedptd(a_double);
    fixedptd b = double_to_fixedptd(b_double);
    std::cout << "a_fixedptd: " << a << std::endl;
    std::cout << "b_fixedptd: " << b << std::endl;
    std::cout << "a_double: " << fixeddptd_to_double(a) << std::endl;
    std::cout << "b_double: " << fixeddptd_to_double(b) << std::endl;
    std::cout << std::endl;

    c = fixedptd_add(a, b);
    std::cout << "fixedptd_add" << std::endl;
    std::cout << "c_double: " << fixeddptd_to_double(c) << std::endl;
    std::cout << "expect_c_double: " << fixeddptd_to_double(a) + fixeddptd_to_double(b) << std::endl;
    std::cout << std::endl;

    c = fixedptd_sub(a, b);
    std::cout << "fixedptd_sub" << std::endl;
    std::cout << "c_double: " << fixeddptd_to_double(c) << std::endl;
    std::cout << "expect_c_double: " << fixeddptd_to_double(a) - fixeddptd_to_double(b) << std::endl;
    std::cout << std::endl;

    c = fixedptd_mul(a, b);
    std::cout << "fixedptd_mul" << std::endl;
    std::cout << "c_double: " << fixeddptd_to_double(c) << std::endl;
    std::cout << "expect_c_double: " << fixeddptd_to_double(a) * fixeddptd_to_double(b) << std::endl;
    std::cout << std::endl;

    c = fixedptd_div(a, b);
    std::cout << "fixedptd_div" << std::endl;
    std::cout << "c_double: " << fixeddptd_to_double(c) << std::endl;
    std::cout << "expect_c_double: " << fixeddptd_to_double(a) / fixeddptd_to_double(b) << std::endl;
    std::cout << std::endl;

    c = fixedptd_LinAppSQ(a);
    std::cout << "fixedptd_LinAppSQ" << std::endl;
    std::cout << "c_double: " << fixeddptd_to_double(c) << std::endl;
    std::cout << "expect_c_double: " << 1.0 / sqrt(fixeddptd_to_double(a)) << std::endl;
    std::cout << std::endl;

    c = fixedptd_sqrt(a, b);
    std::cout << "fixedptd_sqrt" << std::endl;
    std::cout << "c_double: " << fixeddptd_to_double(c) << std::endl;
    std::cout << "expect_c_double: " << sqrt(fixeddptd_to_double(a)) << std::endl;
    std::cout << std::endl;

    c = fixedptd_sqrt_P0132(a, b);
    std::cout << "fixedptd_sqrt_P0132" << std::endl;
    std::cout << "c_double: " << fixeddptd_to_double(c) << std::endl;
    std::cout << "expect_c_double: " << sqrt(fixeddptd_to_double(a)) << std::endl;
    std::cout << std::endl;

//    c = fixedptd_sqrt_PQ0371(a, b);
//    print_u128_u("c: ", c);
//    std::cout << "c_double: " << fixeddptd_to_double(c) << std::endl;
//    std::cout << "expect_c_double: " << sqrt(fixeddptd_to_double(a)) << std::endl;



//    c = fixedptd_log2_PQ2524(a, b);
//    print_u128_u("c: ", c);
//    std::cout << "c_double: " << fixeddptd_to_double(c) << std::endl;
//    std::cout << "expect_c_double: " << log2(fixeddptd_to_double(a)) << std::endl;

    c = fixedptd_exp2_P1045(a, b);
    std::cout << "fixedptd_exp2_P1045" << std::endl;
    std::cout << "c_double: " << fixeddptd_to_double(c) << std::endl;
    std::cout << "expect_c_double: " << pow(2, (fixeddptd_to_double(a))) << std::endl;
    std::cout << std::endl;

    c = fixedptd_exp2_P1045_with_div_Goldschmidt(a, b);
    std::cout << "fixedptd_exp2_P1045_with_div_Goldschmidt" << std::endl;
    std::cout << "c_double: " << fixeddptd_to_double(c) << std::endl;
    std::cout << "expect_c_double: " << pow(2, (fixeddptd_to_double(a))) << std::endl;
    std::cout << std::endl;

    c = fixedptd_exp(a, b);
    std::cout << "fixedptd_exp" << std::endl;
    std::cout << "c_double: " << fixeddptd_to_double(c) << std::endl;
    std::cout << "expect_c_double: " << exp(fixeddptd_to_double(a)) << std::endl;
    std::cout << std::endl;

    c = fixedptd_log2_P2508(a, b);
    std::cout << "fixedptd_log2_P2508" << std::endl;
    std::cout << "c_double: " << fixeddptd_to_double(c) << std::endl;
    std::cout << "expect_c_double: " << log2(fixeddptd_to_double(a)) << std::endl;
    std::cout << std::endl;

    c = fixedptd_ln(a, b);
    std::cout << "fixedptd_ln" << std::endl;
    std::cout << "c_double: " << fixeddptd_to_double(c) << std::endl;
    std::cout << "expect_c_double: " << log(fixeddptd_to_double(a)) << std::endl;
    std::cout << std::endl;

    c = fixedptd_AppRcr(a);
    std::cout << "fixedptd_AppRcr" << std::endl;
    std::cout << "c_double: " << fixeddptd_to_double(c) << std::endl;
    std::cout << "expect_c_double: " << 1.0 / (fixeddptd_to_double(a)) << std::endl;
    std::cout << std::endl;

    c = fixedptd_div_Goldschmidt(a, b);
    std::cout << "fixedptd_div_Goldschmidt" << std::endl;
    std::cout << "c_double: " << fixeddptd_to_double(c) << std::endl;
    std::cout << "expect_c_double: " << (fixeddptd_to_double(a)) / (fixeddptd_to_double(b)) << std::endl;
    std::cout << std::endl;

}