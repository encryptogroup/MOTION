//
// Created by liangzhao on 18.05.22.
//


#include <iomanip>
#include  "fix64_k64_f16.h"

fixedptd absolute_value(fixedptd a) {
    bool a_LTZ = a < 0;

    fixedptd a_abs = 0;
    if (a_LTZ) {
        a_abs = -a;
    } else
        a_abs = a;

    return a_abs;
}

double fixedptd_to_double(fixedptd fixed_point) {
    double result;
//    result = (double) ((fixedptd) (fixed_point)) / (double) (1 << FIXEDPOINT_FRACTION_BITS);
    result = (double) ((fixedptd) (fixed_point)) / std::exp2(FIXEDPOINT_FRACTION_BITS);

    //    print_u128_u("T_int(fixed_point_struct.v): ", T_int(fixed_point));
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

fixedptd double_to_fixedptd(const double double_value) {
    fixedptd fixed_point;
    unsigned i;
    if (double_value < 0) {
        fixed_point = -(fixedptd) (-double_value * (pow(2, FIXEDPOINT_FRACTION_BITS)));
    } else {
        fixed_point = (fixedptd) (double_value * (pow(2, FIXEDPOINT_FRACTION_BITS)));
    }

}

fixedptd fixedptd_add(fixedptd a, fixedptd b) { return (a + b); }

fixedptd fixedptd_sub(fixedptd a, fixedptd b) { return (a - b); }

// fixedptd fixedptd_mul(fixedptd a, fixedptd b) {
//     fixedptd c = (a * b) >> FIXEDPOINT_FRACTION_BITS;
//     return c;
// }

// overflowfree version
fixedptd fixedptd_mul(fixedptd a, fixedptd b) {
    fixedptd c = ((fixedptd_t) a * (fixedptd_t) b) >> FIXEDPOINT_FRACTION_BITS;
    return c;
}

fixedptd fixedptd_mul_with_overflow(fixedptd a, fixedptd b) {
    fixedptd c = (a * b) >> FIXEDPOINT_FRACTION_BITS;
    return c;
}

// //// TODO: overflow?
// //// TODO: depth not optimized, find other algorithms
// fixedptd fixedptd_div(fixedptd a, fixedptd b) {
//   return (fixedptd)(a << FIXEDPOINT_FRACTION_BITS) / b;
// }

// overflowfree version
// very slow
fixedptd fixedptd_div(fixedptd a, fixedptd b) {
    return ((fixedptd_t) (a) << FIXEDPOINT_FRACTION_BITS) / b;
}

// fixedptd fixedptd_div(fixedptd a, fixedptd b)
// {
//   return (ufixedptd(a) << FIXEDPOINT_FRACTION_BITS) / b;
// }
// fixedptd fixedptd_div(fixedptd a, fixedptd b)
// {
//   return (ufixedptd(a) << FIXEDPOINT_FRACTION_BITS) / b;
// }

fixedptd fixedptd_gt(fixedptd a, fixedptd b) { return (a > b); }

fixedptd fixedptd_ltz(fixedptd a, fixedptd not_used) { return (a < 0); }

fixedptd fixedptd_eqz(fixedptd a, fixedptd not_used) { return (a == 0); }

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
    //   a_ceil = ((a >> FIXEDPOINT_FRACTION_BITS) << FIXEDPOINT_FRACTION_BITS) + a_LTZ * ((fixedptd)1
    //   << FIXEDPOINT_FRACTION_BITS);

    //   // return a_prime >> ;
    // }
    // // return a_ceil;

    // return a_abs & fraction_part_mask;

    fixedptd a_prime = a + fraction_part_mask;
    fixedptd a_ceil = ((a_prime >> FIXEDPOINT_FRACTION_BITS) << FIXEDPOINT_FRACTION_BITS);
    return a_ceil;
}

// directly manipulate on boolean bits without circuits
fixedptd fixedptd_floor(fixedptd a, fixedptd not_used) {
    fixedptd a_floor = (a >> (FIXEDPOINT_FRACTION_BITS)) << (FIXEDPOINT_FRACTION_BITS);
    return a_floor;
}

// round fixed-point to nearest integer
int64 fixedptd_to_int64(fixedptd a, fixedptd not_used) {
    bool fractional_part_msb = absolute_value(a) & ((fixedptd) 1 << (FIXEDPOINT_FRACTION_BITS - 1));
    fixedptd a_fx2int = 0;
    bool a_GTZ = a > 0;

    if (fractional_part_msb) {
        if (a_GTZ) {
            a_fx2int = fixedptd_ceil(a, not_used);
            a_fx2int = a_fx2int >> FIXEDPOINT_FRACTION_BITS;
        } else {
            a_fx2int = fixedptd_floor(a, not_used);
            a_fx2int = a_fx2int >> FIXEDPOINT_FRACTION_BITS;
        }
    } else {
        if (a_GTZ) {
            a_fx2int = fixedptd_floor(a, not_used);
            a_fx2int = a_fx2int >> FIXEDPOINT_FRACTION_BITS;
        } else {
            a_fx2int = fixedptd_ceil(a, not_used);
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

fixedptd fixedptd_poly_eval_with_overflow(fixedptd x, const fixedptd coeff[], unsigned coeff_size) {
    fixedptd x_premult = x;
    fixedptd local_aggregation = coeff[0];

    unsigned i;
    for (i = 1; i < coeff_size - 1; i++) {
        fixedptd coefficient_mul_x = fixedptd_mul_with_overflow(coeff[i], x_premult);
        local_aggregation = local_aggregation + coefficient_mul_x;
        x_premult = fixedptd_mul_with_overflow(x, x_premult);
    }

    fixedptd coefficient_mul_x = fixedptd_mul_with_overflow(coeff[i], x_premult);
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

fixedptd KAddL(fixedptd *x_array, unsigned head, unsigned tail) {
    if (tail - head == 0) {
        return x_array[head];
    } else {
        fixedptd preadd_left = KAddL(x_array, head, head + (tail - head) / 2);
        fixedptd preadd_right = KAddL(x_array, head + (tail - head) / 2 + 1, tail);
        return preadd_left + preadd_right;
    }
}

fixedptd
fixedptd_poly_eval_low_depth(fixedptd x, const fixedptd coeff[], unsigned coeff_size, unsigned log_coeff_size, unsigned max_pow2_log_coeff_size) {
    fixedptd pre_mul_list[coeff_size];

    //    std::memcpy(pre_or_list, x_array, coeff_size);

    unsigned i;
    unsigned j;
    unsigned z;
    unsigned k = coeff_size;
    for (i = 0; i < coeff_size; i++) {
        pre_mul_list[i] = x;
    }

    //    pre_or_list[0]=bool_array_list[0];
    for (i = 0; i < log_coeff_size; i++) {
        for (j = 0; j < max_pow2_log_coeff_size / ((unsigned) (1 << (i + 1))); j++) {
            unsigned y = ((unsigned) (1) << i) + j * ((unsigned) (1) << (i + 1)) - 1;
            for (z = 1; z < ((unsigned) (1) << i) + 1; z++) {
                if (y + z < k) {
                    pre_mul_list[y + z] = fixedptd_mul(pre_mul_list[y], pre_mul_list[y + z]);
                }
            }
        }
    }

    for (i = 0; i < coeff_size; i++) {
        pre_mul_list[i] = fixedptd_mul(pre_mul_list[i], coeff[i + 1]);
    }

    fixedptd result = KAddL(pre_mul_list, 0, coeff_size - 1);
    result = result + coeff[0];

    // only for debug
    //    result =pre_mul_list[4];

    return result;
}

// 2^x
// x: integer
fixedptd pow2(fixedptd x) {
    unsigned i;

    fixedptd x_temp = x & (0x3F);
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

    return pow2_x & (0xFFFFFFFFFFFFFFFF);
}

// 2^(-x)
// x: positive integer
fixedptd pow2_neg(fixedptd x) {
    // 2^x
    fixedptd pow2_x = pow2(x);
    std::cout << "pow2_x: " << pow2_x << std::endl;

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

    fixedptd e = fixedptd_poly_eval(c, p_1045_fixedptd_SCLAEMAMBA, sizeof(p_1045_fixedptd_SCLAEMAMBA) / sizeof(p_1045_fixedptd_SCLAEMAMBA[0]));

    fixedptd g = d * e;

    // TODO: more efficient for division
    fixedptd g_inverse = ((fixedptd) 1 << (2 * FIXEDPOINT_FRACTION_BITS)) / g;
    fixedptd pow2_a = (1 - s) * g + s * g_inverse;

    return pow2_a;
}

// backup file
//// more efficient without division operation
fixedptd fixedptd_exp2_P1045(fixedptd a, fixedptd not_used) {
    bool a_LTZ = a < 0;
    bool a_EQZ = a == 0;

    fixedptd a_abs = absolute_value(a);
    fixedptd a_integer_abs = (a_abs >> FIXEDPOINT_FRACTION_BITS) & (((fixedptd) (1) << FIXEDPOINT_INTEGER_BITS) - 1);;
    fixedptd a_fraction = a_abs & fraction_part_mask;
    bool fraction_all_zeros = a_fraction == 0;

    fixedptd result = 0;

    if (a_EQZ) {
        result = (fixedptd) 1 << FIXEDPOINT_FRACTION_BITS;
    }
        // when a > 0
    else if (!a_LTZ) {
        fixedptd pow2_a_integer_abs = pow2(a_integer_abs);
        fixedptd pow2_a_fraction = fixedptd_poly_eval_with_overflow(a_fraction, p_1045_fixedptd_SCLAEMAMBA,
                                                                    sizeof(p_1045_fixedptd_SCLAEMAMBA) / sizeof(p_1045_fixedptd_SCLAEMAMBA[0]));
        result = pow2_a_integer_abs * pow2_a_fraction;
    }

        // a = -1
    else if (fraction_all_zeros) {
        fixedptd pow2_neg_a_integer_abs = pow2_neg(a_integer_abs) & fraction_part_mask;
        result = pow2_neg_a_integer_abs;
    }

        // if a = -1.4, a_integer = -2, a_fraction = 0.6
    else {
        fixedptd a_integer_abs_plus_1 = a_integer_abs + (fixedptd) (1);
//        std::cout << "a_integer_abs_plus_1: " << a_integer_abs_plus_1 << std::endl;

        fixedptd pow2_neg_a_integer_abs_plus_1 = pow2_neg(a_integer_abs_plus_1) & fraction_part_mask;

//        std::cout << "pow2_neg_a_integer_abs_plus_1 " << pow2_neg_a_integer_abs_plus_1 / std::exp2(FIXEDPOINT_FRACTION_BITS) << std::endl;
        fixedptd one_minus_a_fraction = (((fixedptd) 1 << FIXEDPOINT_FRACTION_BITS) - a_fraction);
        fixedptd pow2_one_minus_a_fraction = fixedptd_poly_eval_with_overflow(one_minus_a_fraction, p_1045_fixedptd_SCLAEMAMBA,
                                                                              sizeof(p_1045_fixedptd_SCLAEMAMBA) /
                                                                              sizeof(p_1045_fixedptd_SCLAEMAMBA[0]));
        result = fixedptd_mul_with_overflow(pow2_neg_a_integer_abs_plus_1, pow2_one_minus_a_fraction);
    }
    return result;
}


// takes quite long time, seems not working
// // 2^{a}, a is in (-1,0]
// fixedptd fixedptd_exp2_P1045_neg_0_1(fixedptd a, fixedptd not_used) {
//   bool a_EQZ = a == 0;

//   fixedptd a_abs = -a;
//   fixedptd a_integer_abs = 0;
//   fixedptd a_fraction = a;
//   // bool fraction_all_zeros = a_fraction == 0;

//   // a = 0
//   fixedptd result = (fixedptd)1 << FIXEDPOINT_FRACTION_BITS;

//   // when a < 0
//   // if a = -0.4, a_integer = -2, a_fraction = 0.6
//   // if(!a_EQZ) {
//   // fixedptd a_integer_abs_plus_1 = a_integer_abs + (fixedptd)(1);
//   fixedptd pow2_neg_a_integer_abs_plus_1 = constant_2_neg_1;
//   fixedptd one_minus_a_fraction = ((fixedptd)1 << FIXEDPOINT_FRACTION_BITS) + a_fraction;
//   fixedptd pow2_one_minus_a_fraction = fixedptd_poly_eval(
//       one_minus_a_fraction, p_1045_fixedptd_SCLAEMAMBA, sizeof(p_1045_fixedptd_SCLAEMAMBA) /
//       sizeof(p_1045_fixedptd_SCLAEMAMBA[0]));
//   result = fixedptd_mul(pow2_neg_a_integer_abs_plus_1, pow2_one_minus_a_fraction) * (!a_EQZ) +
//            result * a_EQZ;

//   // only for debug
//   //        result = pow2_one_minus_a_fraction;
//   // }

//   return result;
// }
// 2^{a}, a is in (-1,0]
fixedptd fixedptd_exp2_P1045_neg_0_1(fixedptd a, fixedptd not_used) {
    bool a_LTZ = a < 0;
    bool a_EQZ = a == 0;

    fixedptd a_abs = -(a);
    fixedptd a_integer_abs = 0;
    fixedptd a_fraction = a_abs & fraction_part_mask;
    // bool fraction_all_zeros = a_fraction == 0;

    fixedptd result = 0;

    if (a_EQZ) {
        result = (fixedptd) 1 << FIXEDPOINT_FRACTION_BITS;
    }
        // // when a > 0
        // else if (!a_LTZ) {
        //   fixedptd pow2_a_integer_abs = pow2(a_integer_abs);
        //   fixedptd pow2_a_fraction = fixedptd_poly_eval(
        //       a_fraction, p_1045_fixedptd_SCLAEMAMBA, sizeof(p_1045_fixedptd_SCLAEMAMBA) / sizeof(p_1045_fixedptd_SCLAEMAMBA[0]));
        //   result = pow2_a_integer_abs * pow2_a_fraction;
        // }

        // // a = -1
        // else if (fraction_all_zeros) {
        //   fixedptd pow2_neg_a_integer_abs = pow2_neg(a_integer_abs);
        //   result = pow2_neg_a_integer_abs;
        // }

        // if a = -0.4, a_integer = -1, a_fraction = 0.6
    else {
        fixedptd a_integer_abs_plus_1 = a_integer_abs + (fixedptd) (1);
        fixedptd pow2_neg_a_integer_abs_plus_1 = constant_2_neg_1;
        fixedptd one_minus_a_fraction = ((fixedptd) 1 << FIXEDPOINT_FRACTION_BITS) - a_fraction;
        fixedptd pow2_one_minus_a_fraction = fixedptd_poly_eval_with_overflow(one_minus_a_fraction, p_1045_fixedptd_SCLAEMAMBA,
                                                                              sizeof(p_1045_fixedptd_SCLAEMAMBA) /
                                                                              sizeof(p_1045_fixedptd_SCLAEMAMBA[0]));
        result = fixedptd_mul_with_overflow(pow2_neg_a_integer_abs_plus_1, pow2_one_minus_a_fraction);
    }
    return result;
}

// 2^{a}, a is in (-1,0]
fixedptd fixedptd_exp2_P1045_neg_0_1_low_depth(fixedptd a, fixedptd not_used) {
    bool a_LTZ = a < 0;
    bool a_EQZ = a == 0;

    fixedptd a_abs = -(a);
    fixedptd a_integer_abs = 0;
    fixedptd a_fraction = a_abs & fraction_part_mask;
    // bool fraction_all_zeros = a_fraction == 0;

    fixedptd result = 0;

    if (a_EQZ) {
        result = (fixedptd) 1 << FIXEDPOINT_FRACTION_BITS;
    }
        // // when a > 0
        // else if (!a_LTZ) {
        //   fixedptd pow2_a_integer_abs = pow2(a_integer_abs);
        //   fixedptd pow2_a_fraction = fixedptd_poly_eval(
        //       a_fraction, p_1045_fixedptd_SCLAEMAMBA, sizeof(p_1045_fixedptd_SCLAEMAMBA) / sizeof(p_1045_fixedptd_SCLAEMAMBA[0]));
        //   result = pow2_a_integer_abs * pow2_a_fraction;
        // }

        // // a = -1
        // else if (fraction_all_zeros) {
        //   fixedptd pow2_neg_a_integer_abs = pow2_neg(a_integer_abs);
        //   result = pow2_neg_a_integer_abs;
        // }

        // if a = -0.4, a_integer = -1, a_fraction = 0.6
    else {
        fixedptd a_integer_abs_plus_1 = a_integer_abs + (fixedptd) (1);
        fixedptd pow2_neg_a_integer_abs_plus_1 = constant_2_neg_1;
        fixedptd one_minus_a_fraction = ((fixedptd) 1 << FIXEDPOINT_FRACTION_BITS) - a_fraction;
        fixedptd pow2_one_minus_a_fraction = fixedptd_poly_eval_low_depth(one_minus_a_fraction, p_1045_fixedptd_SCLAEMAMBA, 9, 4, 16);
        result = fixedptd_mul(pow2_neg_a_integer_abs_plus_1, pow2_one_minus_a_fraction);
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

//   fixedptd P = fixedptd_poly_eval(a_norm, p_2508_fixedptd, sizeof(p_2508_fixedptd) /
//   sizeof(p_2508_fixedptd[0]));

//   fixedptd log2_a = P + right_shift * k_minus_f * constant_fixed_point_1 - left_shift * f_minus_k
//   * constant_fixed_point_1; return log2_a;
// }

// backup
fixedptd fixedptd_log2_P2508(fixedptd a, fixedptd not_used) {
    fixedptd a_temp = a;
    unsigned char k = msb_index_reverse(a) & (((fixedptd) 1 << FIXEDPOINT_BITS) - 1);
    char k_minus_f = k - FIXEDPOINT_FRACTION_BITS;
    char f_minus_k = FIXEDPOINT_FRACTION_BITS - k;

    bool right_shift = k > (unsigned char) FIXEDPOINT_FRACTION_BITS;
    bool left_shift = !right_shift;

    fixedptd a_norm;
    if (right_shift) {
        a_norm = (a_temp >> k_minus_f) & fraction_part_mask;
    } else {
        a_norm = (a_temp << f_minus_k) & fraction_part_mask;
    }

    fixedptd P = fixedptd_poly_eval_with_overflow(a_norm, p_2508_fixedptd, sizeof(p_2508_fixedptd) / sizeof(p_2508_fixedptd[0]));

    fixedptd log2_a;
    log2_a = P + k_minus_f * constant_fixed_point_1;

    return log2_a;
}

// // assume a is normalzied to [0.5,1]
// fixedptd fixedptd_log2_P2508(fixedptd a, fixedptd not_used) {
//   // fixedptd a_temp = a;
//   // unsigned char k = msb_index_reverse(a) & (((fixedptd)1 << FIXEDPOINT_BITS)-1);
//   // char k_minus_f = k - FIXEDPOINT_FRACTION_BITS;
//   // char f_minus_k = FIXEDPOINT_FRACTION_BITS - k;

//   // bool right_shift = k > (unsigned char)FIXEDPOINT_FRACTION_BITS;
//   // bool left_shift = !right_shift;

//   // fixedptd a_norm = a ;
//   // if (right_shift) {
//   //   a_norm = (a_temp >> k_minus_f) & fraction_part_mask;
//   // } else {
//   //   a_norm = (a_temp << f_minus_k) & fraction_part_mask;
//   // }

//   fixedptd a_norm = a & fraction_part_mask;

//   fixedptd P = fixedptd_poly_eval(a_norm, p_2508_fixedptd,
//                                   sizeof(p_2508_fixedptd) / sizeof(p_2508_fixedptd[0]));

//   fixedptd log2_a;
//   log2_a = P;

//   return log2_a;
// }

// fixedptd fixedptd_log2_PQ2524(fixedptd a, fixedptd not_used)
// {
//   fixedptd a_temp = a;
//   unsigned char k = msb_index_reverse(a);
//   unsigned char k_minus_f = k - FIXEDPOINT_FRACTION_BITS;
//   unsigned char f_minus_k = FIXEDPOINT_FRACTION_BITS - k;

//   bool right_shift = k > (unsigned char)FIXEDPOINT_FRACTION_BITS;
//   bool left_shift = !right_shift;

//   fixedptd a_norm = right_shift * (a_temp >> k_minus_f) + left_shift * (a_temp << f_minus_k);

//   fixedptd P = fixedptd_poly_eval(a_norm, p_2524_fixedptd, sizeof(p_2524_fixedptd) /
//   sizeof(p_2524_fixedptd[0])); fixedptd Q = fixedptd_poly_eval(a_norm, q_2524_fixedptd,
//   sizeof(q_2524_fixedptd) / sizeof(q_2524_fixedptd[0]));

//   fixedptd P_div_Q = fixedptd_div(P, Q);

//   fixedptd log2_a = P_div_Q + right_shift * k_minus_f * constant_fixed_point_1 - left_shift *
//   f_minus_k * constant_fixed_point_1; return log2_a;
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

//   fixedptd P = fixedptd_poly_eval(a_norm, p_0132_fixedptd, sizeof(p_0132_fixedptd) /
//   sizeof(p_0132_fixedptd[0]));

//   fixedptd k_minus_f_div_2 = k_minus_f >> 1;
//   fixedptd f_minus_k_div_2 = f_minus_k >> 1;

//   fixedptd P_1_div_sqrt_x_right_shift = P << k_minus_f_div_2;
//   fixedptd P_1_div_sqrt_x_left_shift = P >> f_minus_k_div_2;
//   fixedptd P_1_div_sqrt_x_shift = right_shift * P_1_div_sqrt_x_right_shift + left_shift *
//   P_1_div_sqrt_x_left_shift;

//   bool k_minus_f_is_odd = k_minus_f & 1;

//   fixedptd correction = right_shift * (constant_fixed_point_1 + k_minus_f_is_odd *
//   (constant_SQRT2_minus_1)) +
//                         left_shift * (constant_fixed_point_1 + k_minus_f_is_odd *
//                         (constant_SQRT1_2_minus_1));

//   fixedptd result = fixedptd_mul(P_1_div_sqrt_x_shift, correction);

//   return result;
// }

fixedptd fixedptd_sqrt_P0132(fixedptd a, fixedptd not_used) {
    fixedptd a_temp = a;
//    unsigned char k = msb_index_reverse(a) & (((fixedptd) 1 << FIXEDPOINT_BITS) - 1);
    unsigned char k = msb_index_reverse(a) & (0x3F);
    unsigned char k_minus_f = (k - (unsigned char) (FIXEDPOINT_FRACTION_BITS)) & (0x3F);
    unsigned char f_minus_k = ((unsigned char) (FIXEDPOINT_FRACTION_BITS) - k) & (0x3F);
    fixedptd k_minus_f_div_2 = k_minus_f >> 1;
    fixedptd f_minus_k_div_2 = f_minus_k >> 1;
    bool right_shift = k > (unsigned char) FIXEDPOINT_FRACTION_BITS;
    bool left_shift = !right_shift;
    bool k_minus_f_is_odd = k_minus_f & 1;

    if (right_shift) {
        fixedptd a_norm = (right_shift * (a_temp >> k_minus_f)) & fraction_part_mask;
        fixedptd P = fixedptd_poly_eval_with_overflow(a_norm, p_0132_fixedptd, sizeof(p_0132_fixedptd) / sizeof(p_0132_fixedptd[0]));
        fixedptd P_1_div_sqrt_x_right_shift = P << k_minus_f_div_2;
        fixedptd P_1_div_sqrt_x_shift = right_shift * P_1_div_sqrt_x_right_shift;
        fixedptd correction = right_shift * (constant_fixed_point_1 + k_minus_f_is_odd * (constant_SQRT2_minus_1));
        fixedptd result = fixedptd_mul_with_overflow(P_1_div_sqrt_x_shift, correction);
        return result;
    } else {
        fixedptd a_norm = (left_shift * (a_temp << f_minus_k)) & fraction_part_mask;
        fixedptd P = fixedptd_poly_eval_with_overflow(a_norm, p_0132_fixedptd, sizeof(p_0132_fixedptd) / sizeof(p_0132_fixedptd[0]));
        fixedptd P_1_div_sqrt_x_left_shift = P >> f_minus_k_div_2;
        fixedptd P_1_div_sqrt_x_shift = left_shift * P_1_div_sqrt_x_left_shift;
        fixedptd correction = left_shift * (constant_fixed_point_1 + k_minus_f_is_odd * (constant_SQRT1_2_minus_1));
        fixedptd result = fixedptd_mul_with_overflow(P_1_div_sqrt_x_shift, correction);
        return result;
    }
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

//   fixedptd P = fixedptd_poly_eval(a_norm, p_0371_fixedptd, sizeof(p_0371_fixedptd) /
//   sizeof(p_0371_fixedptd[0])); fixedptd Q = fixedptd_poly_eval(a_norm, q_0371_fixedptd,
//   sizeof(q_0371_fixedptd) / sizeof(q_0371_fixedptd[0]));

//   fixedptd P_div_Q = fixedptd_div(P, Q);

//   fixedptd k_minus_f_div_2 = k_minus_f >> 1;
//   fixedptd f_minus_k_div_2 = f_minus_k >> 1;

//   fixedptd P_1_div_sqrt_x_right_shift = P_div_Q << k_minus_f_div_2;
//   fixedptd P_1_div_sqrt_x_left_shift = P_div_Q >> f_minus_k_div_2;
//   fixedptd P_1_div_sqrt_x_shift = right_shift * P_1_div_sqrt_x_right_shift + left_shift *
//   P_1_div_sqrt_x_left_shift;

//   bool k_minus_f_is_odd = k_minus_f & 1;

//   fixedptd correction = right_shift * (constant_fixed_point_1 + k_minus_f_is_odd *
//   (constant_SQRT2_minus_1)) +
//                         left_shift * (constant_fixed_point_1 + k_minus_f_is_odd *
//                         (constant_SQRT1_2_minus_1));

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

// ! inaccurate method
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

fixedptd fixedptd_exp_neg_0_1(fixedptd x, fixedptd not_used) {
    fixedptd result = fixedptd_exp2_P1045_neg_0_1(fixedptd_mul(x, constant_M_LOG2E), not_used);
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
    std::cout << "k_minus_f: " << int(k_minus_f) << std::endl;
    std::cout << "f_minus_k: " << int(f_minus_k) << std::endl;

    bool right_shift = k > (unsigned char) FIXEDPOINT_FRACTION_BITS;
    bool left_shift = !right_shift;
    std::cout << "right_shift: " << right_shift << std::endl;
    std::cout << "left_shift: " << left_shift << std::endl;

    fixedptd a_norm = right_shift * (a_temp >> k_minus_f) + left_shift * (a_temp << f_minus_k);

    std::cout << "a_norm: " << a_norm << std::endl;
    std::cout << "fixedptd_to_double(a_norm): " << fixedptd_to_double(a_norm) << std::endl;

    fixedptd P_1_div_x = fixedptd_poly_eval(a_norm, p_AppRcr_fixedptd, sizeof(p_AppRcr_fixedptd) / sizeof(p_AppRcr_fixedptd[0]));

    std::cout << "P_1_div_x: " << P_1_div_x << std::endl;
    std::cout << "fixedptd_to_double(P_1_div_x): " << fixedptd_to_double(P_1_div_x) << std::endl;

    fixedptd P_1_div_x_right_shift = P_1_div_x >> k_minus_f;
    fixedptd P_1_div_x_left_shift = P_1_div_x << f_minus_k;

    fixedptd P_1_div_x_shift = 0;

    if (right_shift)
        P_1_div_x_shift = right_shift * P_1_div_x_right_shift;
    else {
        P_1_div_x_shift = left_shift * P_1_div_x_left_shift;
    }

    std::cout << "fixedptd_to_double(P_1_div_x_shift): " << fixedptd_to_double(P_1_div_x_shift) << std::endl;

    return P_1_div_x_shift;
}

// ! this method is not accurate when b is greater than 2^16=65536 (because fixedptd_AppRcr cannot compute 1/b accurately)
fixedptd fixedptd_div_Goldschmidt(fixedptd a, fixedptd b) {
    unsigned theta = div_Goldschmidt_theta;

    fixedptd b_positive = absolute_value(b);
    bool b_LTZ = b < 0;

    std::cout << "b_positive_double: " << fixedptd_to_double(b_positive) << std::endl;

    fixedptd w = fixedptd_AppRcr(b_positive);
    std::cout << "w_double: " << fixedptd_to_double(w) << std::endl;

//    fixedptd x = fixedptd_sub(constant_fixed_point_1, fixedptd_mul(b_positive, w));
    fixedptd x = fixedptd_sub(constant_fixed_point_1, fixedptd_mul(b_positive, w));
    std::cout << "fixedptd_mul(b, w)_double: " << fixedptd_to_double(fixedptd_mul(b, w)) << std::endl;
    std::cout << "x_double: " << fixedptd_to_double(x) << std::endl;

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

    fixedptd e = fixedptd_poly_eval(c, p_1045_fixedptd_SCLAEMAMBA, sizeof(p_1045_fixedptd_SCLAEMAMBA) / sizeof(p_1045_fixedptd_SCLAEMAMBA[0]));

    fixedptd g = d * e;

    // TODO: more efficient for division
    // fixedptd g_inverse = ((fixedptd)1 << (2 * FIXEDPOINT_FRACTION_BITS)) / g;
    fixedptd g_inverse = fixedptd_div_Goldschmidt(constant_fixed_point_1, g);

    fixedptd pow2_a = (1 - s) * g + s * g_inverse;

    return pow2_a;
}

// // a is a positive integer, as we can't convert to Bristol format with direct connection between
// input and output fixedptd fixedptd_fx2fl(fixedptd a, fixedptd not_used)
// {
//   // bool a_NEQZ = a != 0;
//   // bool a_EQZ = a == 0;
//   // bool a_LTZ = a < 0;
//   fixedptd floating_point_a = 0;

//   // fixedptd a_abs = absolute_value(a);
//   unsigned char k = msb_index_reverse(a);

//   unsigned char right_shift_num_of_bits = k - (floating_point64_mantissa_bits_l + 1);
//   unsigned char left_shift_num_of_bits = (floating_point64_mantissa_bits_l + 1) - k;

//   bool right_shift = k > (unsigned char)floating_point64_mantissa_bits_l;
//   bool left_shift = !right_shift;

//   fixedptd floating_point_mantissa = right_shift * (a >> right_shift_num_of_bits) + left_shift *
//   (a << left_shift_num_of_bits);

//   fixedptd floating_point_exponent = (fixedptd)(right_shift * right_shift_num_of_bits -
//   left_shift * left_shift_num_of_bits) - FIXEDPOINT_FRACTION_BITS +
//   floating_point64_exponent_bias
//   + floating_point64_mantissa_bits_l;

//   fixedptd floating_point_a_with_mantissa = floating_point_mantissa &
//   floating_point64_mantissa_mask;

//   fixedptd floating_point_a_with_exponent = floating_point_a_with_mantissa ^
//   (floating_point_exponent << floating_point64_mantissa_bits_l);

//   // fixedptd floating_point_a_with_sign = floating_point_a_with_exponent ^ ((fixedptd)a_LTZ <<
//   (floating_point64_mantissa_bits_l + floating_point64_exponente_bits_k));

//   // floating_point_a = (fixedptd)(floating_point_a_with_sign);

//   return floating_point_a_with_exponent;
// }

// a is a non-zero integer, the output is a floating-point number without sign
// we set the sign and deal with the case that a=0 in MOTION
// as we can't convert to Bristol format with direct connection between input and output
float32 fixedptd_to_float32(fixedptd a, fixedptd not_used) {
//     bool a_LTZ = a < 0;
    float32 floating_point_a = 0;
    fixedptd a_abs = absolute_value(a);

//    unsigned char k = msb_index_reverse(a_abs) & 0xFFFF;
    unsigned char k = msb_index_reverse(a_abs);
    std::cout << "k:" << int(k) << std::endl;

    unsigned char right_shift_num_of_bits = (k - (floating_point32_mantissa_bits_l + 1)) & 0xFFFF;
    std::cout << "right_shift_num_of_bits:" << int(right_shift_num_of_bits) << std::endl;
    unsigned char left_shift_num_of_bits = ((floating_point32_mantissa_bits_l + 1) - k) & 0xFFFF;
//    unsigned char right_shift_num_of_bits = (k - (floating_point64_mantissa_bits_l + 1)) & 0xFFFF;
//    unsigned char left_shift_num_of_bits = ((floating_point64_mantissa_bits_l + 1) - k) & 0xFFFF;

    bool right_shift = (k > (unsigned char) floating_point32_mantissa_bits_l);
    bool left_shift = !right_shift;
    std::cout << "right_shift:" << right_shift << std::endl;

    float32 floating_point_mantissa;
    float32 floating_point_exponent;

    if (right_shift) {
//        floating_point_mantissa = (a_abs >> right_shift_num_of_bits) & 0x7FFFFF;
        floating_point_mantissa = (a_abs >> right_shift_num_of_bits);
        std::cout << "floating_point_mantissa:" << floating_point_mantissa << std::endl;
        floating_point_exponent =
                right_shift_num_of_bits - FIXEDPOINT_FRACTION_BITS + floating_point32_mantissa_bits_l + floating_point32_exponent_bias;
        std::cout << "floating_point_exponent:" << floating_point_exponent << std::endl;
    } else {
        floating_point_mantissa = (a_abs << left_shift_num_of_bits);
        floating_point_exponent =
                -left_shift_num_of_bits - FIXEDPOINT_FRACTION_BITS + floating_point32_mantissa_bits_l + floating_point32_exponent_bias;
    }



//    floating_point_exponent = floating_point_exponent  + floating_point32_exponent_bias ;

    // float32 floating_point_a_with_mantissa = floating_point_mantissa &
    // floating_point32_mantissa_mask;
    float32 floating_point_a_with_mantissa = floating_point_mantissa & floating_point32_mantissa_mask;
    std::cout << "floating_point_a_with_mantissa:" << floating_point_a_with_mantissa << std::endl;

    float32 floating_point_a_with_exponent = floating_point_a_with_mantissa ^ (floating_point_exponent << floating_point32_mantissa_bits_l);

    // fixedptd floating_point_a_with_sign = (((fixedptd)1 << (floating_point64_mantissa_bits_l +
    // floating_point64_exponente_bits_k)) & a) ^ floating_point_a_with_exponent;

    floating_point_a = floating_point_a_with_exponent;

    return floating_point_a;
}

float64 fixedptd_to_float64(fixedptd a, fixedptd not_used) {
    // bool a_LTZ = a < 0;
    float64 floating_point_a = 0;
    fixedptd a_abs = absolute_value(a);

    unsigned char k = msb_index_reverse(a_abs) & 0xFFFF;

    unsigned char right_shift_num_of_bits = (k - (floating_point64_mantissa_bits_l + 1)) & 0xFFFF;
    unsigned char left_shift_num_of_bits = ((floating_point64_mantissa_bits_l + 1) - k) & 0xFFFF;

    bool right_shift = k > (unsigned char) floating_point64_mantissa_bits_l;
    bool left_shift = !right_shift;

    float64 floating_point_mantissa;
    float64 floating_point_exponent;

    if (right_shift) {
        floating_point_mantissa = (a_abs >> right_shift_num_of_bits);
        floating_point_exponent =
                right_shift_num_of_bits - FIXEDPOINT_FRACTION_BITS + floating_point64_mantissa_bits_l + floating_point64_exponent_bias;
    } else {
        floating_point_mantissa = (a_abs << left_shift_num_of_bits);
        floating_point_exponent =
                -left_shift_num_of_bits - FIXEDPOINT_FRACTION_BITS + floating_point64_mantissa_bits_l + floating_point64_exponent_bias;
    }

//    floating_point_exponent = floating_point_exponent - FIXEDPOINT_FRACTION_BITS + floating_point64_exponent_bias + floating_point64_mantissa_bits_l;

    float64 floating_point_a_with_mantissa = floating_point_mantissa & floating_point64_mantissa_mask;

    float64 floating_point_a_with_exponent = floating_point_a_with_mantissa ^ (floating_point_exponent << floating_point64_mantissa_bits_l);

    // fixedptd floating_point_a_with_sign = (((fixedptd)1 << (floating_point64_mantissa_bits_l +
    // floating_point64_exponente_bits_k)) & a) ^ floating_point_a_with_exponent;

    floating_point_a = floating_point_a_with_exponent;

    return floating_point_a;
}

// directly manipulate bits without circuits
fixedptd fixedptd_int32_to_fix64(int64 a, fixedptd not_used) {
    fixedptd c = ((fixedptd) (a)) << FIXEDPOINT_FRACTION_BITS;
    return c;
}

// directly manipulate bits without circuits
fixedptd fixedptd_int64_to_fix64(int32 a, fixedptd not_used) {
    fixedptd c = (a) << FIXEDPOINT_FRACTION_BITS;
    return c;
}

fixedptd fixedptd_sqr(fixedptd a, fixedptd not_used) {
    fixedptd c = (a * a) << FIXEDPOINT_FRACTION_BITS;
    return c;
}

// sin(0.5*pi*x)
// x in range (0,1)
fixedptd fixedptd_sin_P3307(fixedptd x, fixedptd not_used) {
    fixedptd x_fraction = x & fraction_part_mask;
    fixedptd x_fraction_sqr = fixedptd_mul_with_overflow(x_fraction, x_fraction);

    fixedptd x_fraction_polynomials = fixedptd_poly_eval_with_overflow(x_fraction_sqr, p_3307_fixedptd,
                                                                       sizeof(p_3307_fixedptd) / sizeof(p_3307_fixedptd[0]));

    fixedptd result = fixedptd_mul_with_overflow(x_fraction, x_fraction_polynomials);

    return result;
}

// cos(x)
// x in range (0,pi/2)
fixedptd fixedptd_cos_P3508(fixedptd x, fixedptd not_used) {
    fixedptd x_fraction = x & fraction_part_mask;
    fixedptd x_fraction_sqr = fixedptd_mul_with_overflow(x_fraction, x_fraction);

    fixedptd result = fixedptd_poly_eval_with_overflow(x_fraction_sqr, p_3508_fixedptd, sizeof(p_3508_fixedptd) / sizeof(p_3508_fixedptd[0]));
    return result;
}

void test_fix64_k64_f16() {

//    fixedptd a =-3;
//    fixedptd b = 54000;
//    fixedptd c;
//    std::cout << "a_double: " << fixedptd_to_double(a) << std::endl;
//    std::cout << "b_double: " << fixedptd_to_double(b) << std::endl;

//    double a_double = 666666667;
//    double b_double = 100000000;
    std::srand(time(nullptr));

//    double min = -std::exp2(FIXEDPOINT_FRACTION_BITS);
    double min = 0.5;
//    double max = std::exp2(FIXEDPOINT_INTEGER_BITS);
    double max = 1;
    std::size_t num_of_values = 500;

    std::vector<double> a_double_vector = rand_range_double_vector(min, max, num_of_values);
    std::vector<double> b_double_vector = rand_range_double_vector(min, max, num_of_values);

    for (std::size_t i = 0; i < num_of_values; i++) {

        fixedptd c;
        double expect_c;
        fixedptd a = double_to_fixedptd(a_double_vector[i]);
        fixedptd b = double_to_fixedptd(b_double_vector[i]);
        double a_double_tmp;
        double b_double_tmp;
        fixedptd a_fix64_tmp;
        fixedptd b_fix64_tmp;
        float32 c_float32_tmp;
        float64 c_float64_tmp;
        std::cout << "a_fixedptd: " << a << std::endl;
        std::cout << "b_fixedptd: " << b << std::endl;
        std::cout << "a_double: " << fixedptd_to_double(a) << std::endl;
        std::cout << "b_double: " << fixedptd_to_double(b) << std::endl;
        std::cout << std::endl;

//        // =========================
//
//        std::cout << "fixedptd_add" << std::endl;
//        c = fixedptd_add(a, b);
//        expect_c = fixedptd_to_double(a) + fixedptd_to_double(b);
//        std::cout << "c_double: " << fixedptd_to_double(c) << std::endl;
//        std::cout << "expect_c_double: " << expect_c << std::endl;
//        if (abs(fixedptd_to_double(c) - expect_c) > (double(1) / std::exp2(FIXEDPOINT_FRACTION_BITS))) {
//            std::cout << "fixedptd_add fail" << std::endl;
//            break;
//        }
//        std::cout << std::endl;
//
//        // =========================
//
//        std::cout << "fixedptd_sub" << std::endl;
//        c = fixedptd_sub(a, b);
//        expect_c = fixedptd_to_double(a) - fixedptd_to_double(b);
//        std::cout << "c_double: " << fixedptd_to_double(c) << std::endl;
//        std::cout << "expect_c_double: " << expect_c << std::endl;
//        if (abs(fixedptd_to_double(c) - expect_c) > (double(1) / std::exp2(FIXEDPOINT_FRACTION_BITS))) {
//            std::cout << "fixedptd_sub fail" << std::endl;
//            break;
//        }
//        std::cout << std::endl;
//
//        // =========================
//
//        std::cout << "fixedptd_mul" << std::endl;
//        c = fixedptd_mul(a, b);
//        expect_c = fixedptd_to_double(a) * fixedptd_to_double(b);
//        std::cout << "c_double: " << fixedptd_to_double(c) << std::endl;
//        std::cout << "expect_c_double: " << expect_c << std::endl;
//        if (abs(fixedptd_to_double(c) - expect_c) > (double(1) / std::exp2(FIXEDPOINT_FRACTION_BITS))) {
//            std::cout << "fixedptd_mul fail" << std::endl;
//            break;
//        }
//        std::cout << std::endl;
//
//        // =========================
//
//        std::cout << "fixedptd_div" << std::endl;
//        c = fixedptd_div(a, b);
//        expect_c = fixedptd_to_double(a) / fixedptd_to_double(b);
//        std::cout << "c_double: " << fixedptd_to_double(c) << std::endl;
//        std::cout << "expect_c_double: " << expect_c << std::endl;
//        if (abs(fixedptd_to_double(c) - expect_c) > (double(1) / std::exp2(FIXEDPOINT_FRACTION_BITS))) {
//            std::cout << "fixedptd_div fail" << std::endl;
//            break;
//        }
//        std::cout << std::endl;
//
//        // =========================
//
//        std::cout << "fixedptd_ceil" << std::endl;
//        c = fixedptd_ceil(a, b);
//        expect_c = ceil(fixedptd_to_double(a));
//        std::cout << "c_double: " << fixedptd_to_double(c) << std::endl;
//        std::cout << "expect_c_double: " << expect_c << std::endl;
//        if (abs(fixedptd_to_double(c) - expect_c) > (double(1) / std::exp2(FIXEDPOINT_FRACTION_BITS))) {
//            std::cout << "fixedptd_ceil fail" << std::endl;
//            break;
//        }
//        std::cout << std::endl;
//
//        // =========================
//
//        std::cout << "fixedptd_to_int64" << std::endl;
//        c = fixedptd_to_int64(a, b);
//        expect_c = round(fixedptd_to_double(a));
//        std::cout << "c_double: " << double(c) << std::endl;
//        std::cout << "expect_c_double: " << expect_c << std::endl;
//        if (abs(double(c) - expect_c) > (double(1) / std::exp2(FIXEDPOINT_FRACTION_BITS))) {
//            std::cout << "fixedptd_to_int64 fail" << std::endl;
//            break;
//        }
//        std::cout << std::endl;
//
//        // =========================
//        std::cout << "fixedptd_to_float32" << std::endl;
//        // only for debugging
////        double a_double = 234.425;
//        a_double_tmp = std::abs(a_double_vector[i]);
//        a_fix64_tmp = double_to_fixedptd(a_double_tmp);
//        c_float32_tmp = fixedptd_to_float32(a_fix64_tmp, b);
//        auto *random_float32_pointer = reinterpret_cast<float *>(&c_float32_tmp);
//        float random_float32 = *random_float32_pointer;
//        expect_c = a_double_tmp;
//        std::cout << "c_float32: " << std::setprecision(15) << c_float32_tmp << std::endl;
//        std::cout << "random_float32: " << std::setprecision(15) << random_float32 << std::endl;
//        std::cout << "expect_c_double: " << expect_c << std::endl;
//        if (abs((random_float32 - expect_c) / expect_c) > (0.000001)) {
//            std::cout << "fixedptd_to_float32 fail" << std::endl;
//            break;
//        }
//        std::cout << std::endl;
//
//        // =========================
//
//        std::cout << "fixedptd_to_float64" << std::endl;
//        // only for debugging
////        double a_double = 234.425;
//        a_double_tmp = std::abs(a_double_vector[i]);
//        a_fix64_tmp = double_to_fixedptd(a_double_tmp);
//        c_float64_tmp = fixedptd_to_float64(a_fix64_tmp, b);
//        auto *random_float64_pointer = reinterpret_cast<double *>(&c_float64_tmp);
//        double random_float64 = *random_float64_pointer;
//        expect_c = a_double_tmp;
//        std::cout << "c_float64: " << std::setprecision(15) << c_float64_tmp << std::endl;
//        std::cout << "random_float64: " << std::setprecision(15) << random_float64 << std::endl;
//        std::cout << "expect_c_double: " << expect_c << std::endl;
//        if (abs((random_float64 - expect_c) / expect_c) > (0.000000001)) {
//            std::cout << "fixedptd_to_float64 fail" << std::endl;
//            break;
//        }
//        std::cout << std::endl;
//
//        // =========================
//
//        std::cout << "fixedptd_AppRcr" << std::endl;
//        c = fixedptd_AppRcr(a);
//        expect_c = 1.0 / (fixedptd_to_double(a));
//        std::cout << "c_double: " << fixedptd_to_double(c) << std::endl;
//        std::cout << "expect_c_double: " << expect_c << std::endl;
//        if ((c != 0)) {
//            if (abs((fixedptd_to_double(c) - expect_c) / expect_c) > (1)) {
//                std::cout << "fixedptd_AppRcr fail" << std::endl;
//                break;
//            }
//        }
//        std::cout << std::endl;
//
//        // =========================
//
//        a_double_tmp = a_double_vector[i];
//        b_double_tmp = b_double_vector[i];
//
//////        // only for debug
//        a_double_tmp = 17820.7923972145;
////        b_double_tmp = 62813.6096789081; // error
//        b_double_tmp = 213.6096789081;
//
//        std::cout << "fixedptd_div_Goldschmidt" << std::endl;
//        std::cout << "a_double: " << a_double_tmp << std::endl;
//        std::cout << "b_double: " << b_double_tmp << std::endl;
//        a_fix64_tmp = double_to_fixedptd(a_double_tmp);
//        b_fix64_tmp = double_to_fixedptd(b_double_tmp);
//        std::cout << "a_fix64_tmp: " << a_fix64_tmp << std::endl;
//        std::cout << "b_fix64_tmp: " << b_fix64_tmp << std::endl;
//        c = fixedptd_div_Goldschmidt(a_fix64_tmp, b_fix64_tmp);
//        expect_c = a_double_tmp / b_double_tmp;
//        std::cout << "c_double: " << fixedptd_to_double(c) << std::endl;
//        std::cout << "expect_c_double: " << expect_c << std::endl;
//        if (abs((fixedptd_to_double(c) - expect_c) / expect_c) > (double(1) / std::exp2(8))) {
//            std::cout << "fixedptd_div_Goldschmidt fail" << std::endl;
//            break;
//        }
//        std::cout << std::endl;
//
//        // =========================
//
//        a_double_tmp = a_double_vector[i];
//        // only for debug
////        a_double_tmp = 0.7732;
//
//        std::cout << "fixedptd_LinAppSQ" << std::endl;
//        a_fix64_tmp = double_to_fixedptd(a_double_tmp);
//        c = fixedptd_LinAppSQ(a_fix64_tmp);
//        expect_c = 1 / sqrt((a_double_tmp));
//        std::cout << "c_double: " << fixedptd_to_double(c) << std::endl;
//        std::cout << "expect_c_double: " << expect_c << std::endl;
//        if (abs(fixedptd_to_double(c) - expect_c) > (double(1) / std::exp2(7))) {
//            std::cout << "fixedptd_LinAppSQ fail" << std::endl;
//            break;
//        }
//        std::cout << std::endl;
//
//
//
//        // =========================

        a_double_tmp = a_double_vector[i];
        if (a_double_tmp < 0) {
            a_double_tmp = -a_double_tmp;
        }

////         only for debug
//        a_double_tmp = 0.32;

        std::cout << "fixedptd_sqrt_P0132" << std::endl;
        a_fix64_tmp = double_to_fixedptd(a_double_tmp);
        c = fixedptd_sqrt_P0132(a_fix64_tmp, b);
        expect_c = sqrt((a_double_tmp));
        std::cout << "c_double: " << fixedptd_to_double(c) << std::endl;
        std::cout << "expect_c_double: " << expect_c << std::endl;
        if (abs(fixedptd_to_double(c) - expect_c) > (double(1) / std::exp2(13))) {
            std::cout << "fixedptd_sqrt_P0132 fail" << std::endl;
            break;
        }
        std::cout << std::endl;


//        // =========================
//        a_fix64_tmp = 35;
//
//        std::cout << "pow2" << std::endl;
//        c = pow2(a_fix64_tmp);
//        expect_c = std::exp2((a_fix64_tmp));
//        std::cout << "c_double: " << c << std::endl;
//        std::cout << "expect_c_double: " << expect_c << std::endl;
//        if (abs((c) - expect_c) > (double(1) / std::exp2(13))) {
//            std::cout << "pow2 fail" << std::endl;
//            break;
//        }
//        std::cout << std::endl;
//
//        // =========================
//        a_fix64_tmp = 45635;
//
//        std::cout << "pow2_neg" << std::endl;
//        c = pow2_neg(a_fix64_tmp);
//        expect_c = std::exp2((-a_fix64_tmp));
//        std::cout << "c_double: " << double(c)/std::exp2(FIXEDPOINT_FRACTION_BITS) << std::endl;
//        std::cout << "expect_c_double: " << expect_c << std::endl;
////        if (abs((c) - expect_c) > (double(1) / std::exp2(13))) {
////            std::cout << "pow2_neg fail" << std::endl;
////            break;
////        }
//        std::cout << std::endl;

        // =========================

//        a_double_tmp = a_double_vector[i];

        // only for debug
//        a_double_tmp =  13.7732;
//        a_double_tmp = -434.4533998624;
//        a_double_tmp = -0.4533998624;
//        a_double_tmp = -14.9245;

//        std::cout << "fixedptd_exp2_P1045" << std::endl;
//        std::cout << "a_double_tmp: " << a_double_tmp << std::endl;
//        a_fix64_tmp = double_to_fixedptd(a_double_tmp);
//        c = fixedptd_exp2_P1045(a_fix64_tmp, b);
//        expect_c = std::exp2((a_double_tmp));
//        std::cout << "c_double: " << fixedptd_to_double(c) << std::endl;
//        std::cout << "expect_c_double: " << expect_c << std::endl;
//        if (abs(fixedptd_to_double(c) - expect_c) > (double(1) / std::exp2(13))) {
//            std::cout << "fixedptd_exp2_P1045 fail" << std::endl;
//            break;
//        }
//        std::cout << std::endl;

        // =========================

//        a_double_tmp = a_double_vector[i];
//
////        // only for debug
////        a_double_tmp = -0.321;
//
//        std::cout << "fixedptd_exp2_P1045_neg_0_1" << std::endl;
//        a_fix64_tmp = double_to_fixedptd(a_double_tmp);
//        c = fixedptd_exp2_P1045_neg_0_1(a_fix64_tmp, b);
//        expect_c = std::exp2((a_double_tmp));
//        std::cout << "c_double: " << fixedptd_to_double(c) << std::endl;
//        std::cout << "expect_c_double: " << expect_c << std::endl;
//        if (abs(fixedptd_to_double(c) - expect_c) > (double(1) / std::exp2(13))) {
//            std::cout << "fixedptd_exp2_P1045_neg_0_1 fail" << std::endl;
//            break;
//        }
//        std::cout << std::endl;

        // =========================

//        a_double_tmp = a_double_vector[i];
//
//        // only for debug
//        if (a_double_tmp < 0) { a_double_tmp = -a_double_tmp; }
//
//        std::cout << "fixedptd_log2_P2508" << std::endl;
//        a_fix64_tmp = double_to_fixedptd(a_double_tmp);
//        c = fixedptd_log2_P2508(a_fix64_tmp, b);
//        expect_c = std::log2((a_double_tmp));
//        std::cout << "c_double: " << fixedptd_to_double(c) << std::endl;
//        std::cout << "expect_c_double: " << expect_c << std::endl;
//        if (abs(fixedptd_to_double(c) - expect_c) > (double(1) / std::exp2(13))) {
//            std::cout << "fixedptd_log2_P2508 fail" << std::endl;
//            break;
//        }
//        std::cout << std::endl;

        // =========================

//        a_double_tmp = a_double_vector[i];
//        std::cout << "fixedptd_sin_P3307" << std::endl;
//        a_fix64_tmp = double_to_fixedptd(a_double_tmp);
//        c = fixedptd_sin_P3307(a_fix64_tmp, b);
//        expect_c = std::sin(a_double_tmp*0.5*M_PI);
//        std::cout << "c_double: " << fixedptd_to_double(c) << std::endl;
//        std::cout << "expect_c_double: " << expect_c << std::endl;
//        if (abs(fixedptd_to_double(c) - expect_c) > (double(1) / std::exp2(13))) {
//            std::cout << "fixedptd_sin_P3307 fail" << std::endl;
//            break;
//        }
//        std::cout << std::endl;

        // =========================

//        a_double_tmp = a_double_vector[i];
//        std::cout << "fixedptd_cos_P3508" << std::endl;
//        a_fix64_tmp = double_to_fixedptd(a_double_tmp);
//        c = fixedptd_cos_P3508(a_fix64_tmp, b);
//        expect_c = std::cos(a_double_tmp);
//        std::cout << "c_double: " << fixedptd_to_double(c) << std::endl;
//        std::cout << "expect_c_double: " << expect_c << std::endl;
//        if (abs(fixedptd_to_double(c) - expect_c) > (double(1) / std::exp2(13))) {
//            std::cout << "fixedptd_cos_P3508 fail" << std::endl;
//            break;
//        }
//        std::cout << std::endl;

        // =========================
//        a_fix64_tmp = 4335416758804742313;
//
//        std::cout << "fixedptd_ceil" << std::endl;
//        std::cout << "std::int64_t(a_fix64_tmp): "<< std::int64_t(a_fix64_tmp)<< std::endl;
//        std::cout<<"a_double: "<<std::setprecision(20) <<fixedptd_to_double(a_fix64_tmp) << std::endl;
//        c = fixedptd_ceil(a_fix64_tmp, b);
//        expect_c = ceil(fixedptd_to_double(a_fix64_tmp));
//        std::cout << "c_double: " << std::setprecision(20) << fixedptd_to_double(c) << std::endl;
//        std::cout << "expect_c_double: " << std::setprecision(20) << ceil(expect_c) << std::endl;
//        if ((fixedptd_to_double(c) != expect_c)) {
//            std::cout << "fixedptd_ceil fail" << std::endl;
//            break;
//        }
//        std::cout << std::endl;
        // =========================
//        std::cout << "fixedptd_floor" << std::endl;
//        c = fixedptd_floor(a_fix64_tmp, b);
//        expect_c = floor(fixedptd_to_double(a_fix64_tmp));
//        std::cout << "c_double: " << fixedptd_to_double(c) << std::endl;
//        std::cout << "expect_c_double: " << floor(expect_c) << std::endl;
//        if ((fixedptd_to_double(c) != expect_c)) {
//            std::cout << "fixedptd_floor fail" << std::endl;
//            break;
//        }
//        std::cout << std::endl;
        // =========================


    }
}