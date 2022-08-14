// MIT License
//
// Copyright (c) 2022 Liang Zhao
// Cryptography and Privacy Engineering Group (ENCRYPTO)
// TU Darmstadt, Germany
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.


#include "snapping_mechanism.h"

#include <bitset>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <iostream>

template<typename T>
T double_to_int(double double_input) {
    T *int_output = reinterpret_cast<T *>(&double_input);

    return *int_output;
}

template std::uint64_t double_to_int(double double_input);

FLType double_to_bool_array(double double_input) {
    FLType *int_output = reinterpret_cast<FLType *>(&double_input);

    std::bitset<sizeof(FLType) * 8> bitset_output{*int_output};
    std::cout << "bitset_output: " << bitset_output << std::endl;

    return *int_output;
}

FLType bool_array_to_int(bool bool_array[], unsigned count) {
    //    FLType ret = 0;
    FLType tmp;

    FLType tmp_int_array[count];
    for (unsigned i = 0; i < count; i++) {
        tmp_int_array[i] = ((FLType) bool_array[i] << (count - i - 1));
    }
    unsigned head = 0;
    unsigned tail = count - 1;

    FLType int_output = KOrL(tmp_int_array, head, tail);

    //    for (unsigned i = 0; i < count; i++) {
    //        tmp = bool_array[i];
    //        ret |= tmp << (count - i - 1);
    //    }

    return int_output;
}

double bool_array_to_double(bool bool_array[], unsigned count) {
    FLType int_output = bool_array_to_int(bool_array, count);
    double *double_output = reinterpret_cast<double *>(&int_output);
    return *double_output;
}

double int_to_double(FLType int_input, unsigned count) {
    double *double_output = reinterpret_cast<double *>(&int_input);
    return *double_output;
}

void int_to_bool_array(FLType int_input, bool bool_array[]) {
    unsigned count = sizeof(FLType) * 8;
    unsigned i;
    for (i = 0; i < count; i++) {
        bool_array[count - i - 1] = ((int_input >> i) & 1);
    }
}

void PreOrL(bool bool_array_list[], bool pre_or_list[], unsigned count, unsigned log_k, unsigned kmax) {
    //    unsigned log_k = ceil_log2_52;
    //    unsigned kmax = max_pow2_log52;

    std::memcpy(pre_or_list, bool_array_list, count);

    unsigned i;
    unsigned j;
    unsigned z;
    unsigned k = count;

    //    pre_or_list[0]=bool_array_list[0];
    for (i = 0; i < log_k; i++) {
        for (j = 0; j < kmax / ((unsigned) (1 << (i + 1))); j++) {
            unsigned y = ((unsigned) (1) << i) + j * ((unsigned) (1) << (i + 1)) - 1;
            for (z = 1; z < ((unsigned) (1) << i) + 1; z++) {
                if (y + z < k) {
                    pre_or_list[y + z] = pre_or_list[y] | pre_or_list[y + z];
                }
            }
        }
    }
    //    return preOr_list;
}

bool KAndL(bool bool_array_list[], const unsigned head, const unsigned tail) {
    if (tail - head == 0) {
        return bool_array_list[head];
    } else {
        bool t1 = KAndL(bool_array_list, head, head + (tail - head) / 2);
        bool t2 = KAndL(bool_array_list, head + (tail - head) / 2 + 1, tail);
        return t1 & t2;
    }
}

bool KOrL(bool bool_array_list[], const unsigned head, const unsigned tail) {
    if (tail - head == 0) {
        return bool_array_list[head];
    } else {
        bool t1 = KOrL(bool_array_list, head, head + (tail - head) / 2);
        bool t2 = KOrL(bool_array_list, head + (tail - head) / 2 + 1, tail);
        return t1 | t2;
    }
}

FLType KOrL(FLType int_array_list[], const unsigned head, const unsigned tail) {
    if (tail - head == 0) {
        return int_array_list[head];
    } else {
        FLType t1 = KOrL(int_array_list, head, head + (tail - head) / 2);
        FLType t2 = KOrL(int_array_list, head + (tail - head) / 2 + 1, tail);
        return t1 | t2;
    }
}

// lambda is publicly known
FLType get_smallest_greater_or_eq_power_of_two(const FLType lambda) {
    assert(FLType_int(lambda) > 0);
    FLType lambda_mantissa = lambda & FLOATINGPOINT_MANTISSA_MASK;
    FLType sigma = 0;
    FLType lambda_sign = lambda & FLOATINGPOINT_SIGN_MASK;

    FLType lambda_exponent = (((lambda & FLOATINGPOINT_EXPONENT_MASK) >> FLOATINGPOINT_MANTISSA_BITS) + 1) << FLOATINGPOINT_MANTISSA_BITS;
    if (lambda_mantissa == 0) {
        sigma = lambda;
    } else {
        sigma = sigma ^ lambda_sign ^ lambda_exponent;
    }

    double *sigma_double = reinterpret_cast<double *>(&sigma);
    //   std::cout << "sigma_double: " << *sigma_double << std::endl;

    FLType m = (FLType) (lambda_exponent >> FLOATINGPOINT_MANTISSA_BITS) - FLOATINGPOINT_EXPONENT_BIAS;

    return m;
}

void divide_by_power_of_two(const FLType x, const FLType m, FLType x_div_pow2_m[]) {
    FLType x_mantissa = x & FLOATINGPOINT_MANTISSA_MASK;
    FLType x_sign = x & FLOATINGPOINT_SIGN_MASK;

    FLType x_exponent = x & FLOATINGPOINT_EXPONENT_MASK;
    x_exponent = ((FLType) (x_exponent >> FLOATINGPOINT_MANTISSA_BITS) - m) << FLOATINGPOINT_MANTISSA_BITS;

    //    FLType x_div_pow2_m = x_mantissa ^ x_exponent ^ x_sign;
    //
    x_div_pow2_m[0] = x_sign;
    x_div_pow2_m[1] = x_exponent;
    x_div_pow2_m[2] = x_mantissa;
}

void round_to_nearest_int(const FLType x, FLType x_round_to_nearest_int[]) {
    //    FLType x_div_pow2_m[3];
    //    divide_by_power_of_two(x, m, x_div_pow2_m);
    //    FLType sign_x_div_pow2_m = x_div_pow2_m[0];
    //    FLType exponent_x_div_pow2_m = x_div_pow2_m[1];
    //    FLType mantissa_x_div_pow2_m = x_div_pow2_m[2];

    //    std::cout << "x_div_pow2_m_double: " << int_to_double(x_div_pow2_m[0] ^ x_div_pow2_m[1] ^
    //    x_div_pow2_m[2]) << std::endl;

    // TODO: compare bit mask and shift circuit cost
    //    FLType x_sign = x & FLOATINGPOINT_SIGN_MASK;
    //    FLType x_exponent = x & FLOATINGPOINT_EXPONENT_MASK;
    //    FLType x_mantissa = x & FLOATINGPOINT_MANTISSA_MASK;

    FLType x_sign = (x >> (FLOATINGPOINT_EXPONENT_BITS + FLOATINGPOINT_MANTISSA_BITS)) << (FLOATINGPOINT_EXPONENT_BITS + FLOATINGPOINT_MANTISSA_BITS);
    FLType x_exponent = ((x << FLOATINGPOINT_SIGN_BITS) >> (FLOATINGPOINT_SIGN_BITS + FLOATINGPOINT_MANTISSA_BITS)) << FLOATINGPOINT_MANTISSA_BITS;
    FLType x_mantissa = (x << (FLOATINGPOINT_SIGN_BITS + FLOATINGPOINT_EXPONENT_BITS)) >> (FLOATINGPOINT_SIGN_BITS + FLOATINGPOINT_EXPONENT_BITS);

    FLType mantissa_x_round_to_nearest_int = x_mantissa;
    FLType exponent_x_round_to_nearest_int = x_exponent;
    FLType sign_x_round_to_nearest_int = x_sign;

    // TODO: change to unsigned integer operation to save computation
    std::int16_t unbiased_exponent_num_y = (std::int16_t) (x_exponent >> FLOATINGPOINT_MANTISSA_BITS) - (std::int16_t) (FLOATINGPOINT_EXPONENT_BIAS);

    std::cout << "exponent_x_num: " << (x_exponent >> FLOATINGPOINT_MANTISSA_BITS) << std::endl;
    std::cout << "unbiased_exponent_num_y: " << unbiased_exponent_num_y << std::endl;

    // case 1
    // y >= 52
    if (unbiased_exponent_num_y > (std::int16_t) (FLOATINGPOINT_MANTISSA_BITS - 1)) {
        std::cout << "case 1" << std::endl;
        std::cout << "y >= 52" << std::endl;
    }

        // case 3
        // y in [0, 51]
    else if (unbiased_exponent_num_y >= 0) {
        std::cout << "case 2, 3" << std::endl;
        std::cout << "y in [0, 51]" << std::endl;
        FLType mantissa_x_tmp = x_mantissa;
        std::cout << "mantissa_x_tmp: " << mantissa_x_tmp << std::endl;

        unsigned i;
        bool mantissa_array[FLOATINGPOINT_MANTISSA_BITS];
        mantissa_array[FLOATINGPOINT_MANTISSA_BITS - 1] = (mantissa_x_tmp) & 1;
        for (i = 1; i < FLOATINGPOINT_MANTISSA_BITS; i++) {
            mantissa_array[FLOATINGPOINT_MANTISSA_BITS - 1 - i] = ((mantissa_x_tmp >> i) & 1);
        }

        std::cout << "mantissa_array: ";
        for (i = 0; i < FLOATINGPOINT_MANTISSA_BITS; i++) {
            std::cout << mantissa_array[i];
        }
        std::cout << std::endl;

        bool mantissa_fraction_msb_mask[FLOATINGPOINT_MANTISSA_BITS];
        mantissa_fraction_msb_mask[FLOATINGPOINT_MANTISSA_BITS - 1] = (unbiased_exponent_num_y == (std::int16_t) (FLOATINGPOINT_MANTISSA_BITS));

        bool mantissa_fraction_msb = mantissa_fraction_msb_mask[FLOATINGPOINT_MANTISSA_BITS - 1] & mantissa_array[FLOATINGPOINT_MANTISSA_BITS - 1];
        for (i = 1; i < FLOATINGPOINT_MANTISSA_BITS; i++) {
            mantissa_fraction_msb_mask[FLOATINGPOINT_MANTISSA_BITS - 1 - i] = (unbiased_exponent_num_y ==
                                                                               (std::int16_t) (FLOATINGPOINT_MANTISSA_BITS - i - 1));
            mantissa_fraction_msb = mantissa_fraction_msb ^ (mantissa_fraction_msb_mask[FLOATINGPOINT_MANTISSA_BITS - 1 - i] &
                                                             mantissa_array[FLOATINGPOINT_MANTISSA_BITS - 1 - i]);
        }

        std::cout << "mantissa_fraction_msb_mask: ";
        for (i = 0; i < FLOATINGPOINT_MANTISSA_BITS; i++) {
            std::cout << mantissa_fraction_msb_mask[i];
        }
        std::cout << std::endl;

        std::cout << "mantissa_fraction_msb: " << mantissa_fraction_msb << std::endl;

        bool mantissa_fraction_mask[FLOATINGPOINT_MANTISSA_BITS];
        PreOrL(mantissa_fraction_msb_mask, mantissa_fraction_mask);

        std::cout << "mantissa_fraction_mask: ";
        for (i = 0; i < FLOATINGPOINT_MANTISSA_BITS; i++) {
            std::cout << mantissa_fraction_mask[i];
        }
        std::cout << std::endl;

        bool mantissa_integer_mask[FLOATINGPOINT_MANTISSA_BITS];
        for (i = 0; i < FLOATINGPOINT_MANTISSA_BITS; i++) {
            mantissa_integer_mask[i] = !mantissa_fraction_mask[i];
        }

        std::cout << "mantissa_integer_mask: ";
        for (i = 0; i < FLOATINGPOINT_MANTISSA_BITS; i++) {
            std::cout << mantissa_integer_mask[i];
        }
        std::cout << std::endl;

        bool mantissa_integer_array[FLOATINGPOINT_MANTISSA_BITS];
        for (i = 0; i < FLOATINGPOINT_MANTISSA_BITS; i++) {
            mantissa_integer_array[i] = mantissa_integer_mask[i] & mantissa_array[i];
        }

        std::cout << "mantissa_integer_array: ";
        for (i = 0; i < FLOATINGPOINT_MANTISSA_BITS; i++) {
            std::cout << mantissa_integer_array[i];
        }
        std::cout << std::endl;

        const unsigned head = 0;
        const unsigned tail = FLOATINGPOINT_MANTISSA_BITS - 1;

        bool mantissa_integer_with_fraction_all_ones[FLOATINGPOINT_MANTISSA_BITS];
        for (i = 0; i < FLOATINGPOINT_MANTISSA_BITS; i++) {
            mantissa_integer_with_fraction_all_ones[i] = mantissa_integer_array[i] ^ mantissa_fraction_mask[i];
        }

        std::cout << "mantissa_integer_with_fraction_all_ones: ";
        for (i = 0; i < FLOATINGPOINT_MANTISSA_BITS; i++) {
            std::cout << mantissa_integer_with_fraction_all_ones[i];
        }
        std::cout << std::endl;

        bool mantissa_integer_all_ones = KAndL(mantissa_integer_with_fraction_all_ones, head, tail);
        bool mantissa_integer_contain_zero = !mantissa_integer_all_ones;

        std::cout << "mantissa_integer_all_ones: " << mantissa_integer_all_ones << std::endl;
        std::cout << "mantissa_integer_contain_zero: " << mantissa_integer_contain_zero << std::endl;

        FLType mantissa_integer_bit[FLOATINGPOINT_MANTISSA_BITS];
        // convert integer integer bool array to integer
        //        for (i = 0; i < FLOATINGPOINT_MANTISSA_BITS; i++) {
        //            mantissa_integer_bit[i] = ((FLType) (mantissa_integer_array[i]) <<
        //            (FLOATINGPOINT_MANTISSA_BITS - 1 - i));
        //        }
        //        FLType mantissa_integer = KOrL(mantissa_integer_bit, head, tail);
        FLType mantissa_integer = bool_array_to_int(mantissa_integer_array, FLOATINGPOINT_MANTISSA_BITS);

        std::cout << "mantissa_integer: " << mantissa_integer << std::endl;

        bool mantissa_integer_one_array[FLOATINGPOINT_MANTISSA_BITS];
        mantissa_integer_one_array[FLOATINGPOINT_MANTISSA_BITS - 1] = 0;
        for (i = 0; i < FLOATINGPOINT_MANTISSA_BITS - 1; i++) {
            mantissa_integer_one_array[i] = mantissa_fraction_msb_mask[i + 1];
        }

        FLType mantissa_integer_one = bool_array_to_int(mantissa_integer_one_array, FLOATINGPOINT_MANTISSA_BITS);
        std::cout << "mantissa_integer_one: " << mantissa_integer_one << std::endl;

        // case 3a
        if (mantissa_fraction_msb & mantissa_integer_contain_zero) {
            std::cout << "case 3a" << std::endl;
            mantissa_x_round_to_nearest_int = mantissa_integer + mantissa_integer_one;
            std::cout << "mantissa_x_round_to_nearest_int: " << mantissa_x_round_to_nearest_int << std::endl;
        }

            // case 3c
        else if (!mantissa_fraction_msb) {
            std::cout << "case 3c" << std::endl;
            mantissa_x_round_to_nearest_int = mantissa_integer;
        }

            // case 3b
        else {
            std::cout << "case 3b" << std::endl;
            mantissa_x_round_to_nearest_int = 0;
            exponent_x_round_to_nearest_int = (((exponent_x_round_to_nearest_int >> FLOATINGPOINT_MANTISSA_BITS) + 1) << FLOATINGPOINT_MANTISSA_BITS);
        }

    }

        // case 4
        // y = -1
    else if (unbiased_exponent_num_y == -1) {
        std::cout << "case 4" << std::endl;
        mantissa_x_round_to_nearest_int = 0;
        exponent_x_round_to_nearest_int = ((FLType) (FLOATINGPOINT_EXPONENT_BIAS) << FLOATINGPOINT_MANTISSA_BITS);
    }

        // case 5
    else {
        std::cout << "case 5" << std::endl;
        mantissa_x_round_to_nearest_int = 0;
        exponent_x_round_to_nearest_int = 0;
    }

    x_round_to_nearest_int[0] = sign_x_round_to_nearest_int;
    x_round_to_nearest_int[1] = exponent_x_round_to_nearest_int;
    x_round_to_nearest_int[2] = mantissa_x_round_to_nearest_int;
}

void multiply_by_power_of_two(const FLType x, FLType m, FLType x_mul_pow2_m[]) {
    FLType x_sign = (x >> (FLOATINGPOINT_EXPONENT_BITS + FLOATINGPOINT_MANTISSA_BITS)) << (FLOATINGPOINT_EXPONENT_BITS + FLOATINGPOINT_MANTISSA_BITS);
    FLType x_exponent = (x << FLOATINGPOINT_SIGN_BITS) >> (FLOATINGPOINT_SIGN_BITS + FLOATINGPOINT_MANTISSA_BITS);
    FLType x_mantissa = (x << (FLOATINGPOINT_SIGN_BITS + FLOATINGPOINT_EXPONENT_BITS)) >> (FLOATINGPOINT_SIGN_BITS + FLOATINGPOINT_EXPONENT_BITS);

    FLType sign_x_mul_pow2_m = x_sign;
    FLType exponent_x_mul_pow2_m = x_exponent;
    FLType mantissa_x_mul_pow2_m = x_mantissa;
    if (x == 0) {
        sign_x_mul_pow2_m = 0;
        exponent_x_mul_pow2_m = 0;
        mantissa_x_mul_pow2_m = 0;
    } else {
        exponent_x_mul_pow2_m = exponent_x_mul_pow2_m + m;
    }

    x_mul_pow2_m[0] = sign_x_mul_pow2_m;
    x_mul_pow2_m[1] = exponent_x_mul_pow2_m << FLOATINGPOINT_MANTISSA_BITS;
    x_mul_pow2_m[2] = mantissa_x_mul_pow2_m;
}

FLType get_closest_multiple_of_sigma(const FLType lambda, FLType x) {
    FLType m = get_smallest_greater_or_eq_power_of_two(lambda);

    std::cout << "m: " << m << std::endl;
    std::cout << "int(m): " << int(m) << std::endl;

    FLType x_div_pow2_m_array[3];
    divide_by_power_of_two(x, m, x_div_pow2_m_array);
    FLType x_div_pow2_m = x_div_pow2_m_array[0] ^ x_div_pow2_m_array[1] ^ x_div_pow2_m_array[2];

    FLType x_round_to_nearest_int_array[3];
    round_to_nearest_int(x_div_pow2_m, x_round_to_nearest_int_array);
    FLType x_round_to_nearest_int = x_round_to_nearest_int_array[0] ^ x_round_to_nearest_int_array[1] ^ x_round_to_nearest_int_array[2];

    std::cout << "x_round_to_nearest_int: " << int_to_double(x_round_to_nearest_int) << std::endl;

    FLType x_round_to_sigma_array[3];
    multiply_by_power_of_two(x_round_to_nearest_int, m, x_round_to_sigma_array);

    std::cout << "x_round_to_sigma: " << int_to_double(x_round_to_sigma_array[0] ^ x_round_to_sigma_array[1] ^ x_round_to_sigma_array[2])
              << std::endl;

    return x_round_to_sigma_array[0] ^ x_round_to_sigma_array[1] ^ x_round_to_sigma_array[2];
}

// unsigned geometric_sample(const FLType random_bits) {
//
//     unsigned count = sizeof(FLType) * 8;
//     bool bool_array[count];
//     bool bool_array_pre_or[count];
//     int_to_bool_array(random_bits, bool_array);
//
//     PreOrL(bool_array, bool_array_pre_or, count, ceil_log2_64, max_pow2_log64);
//     bool bool_array_pre_or_invert[count];
//
//     unsigned i;
//     for (i = 0; i < count; i++) {
//         bool_array_pre_or_invert[i] = !bool_array_pre_or[i];
//         std::cout << bool_array_pre_or_invert[i];
//     }
//     std::cout << std::endl;
//
//     unsigned hamming_weight = 0;
//     for (i = 0; i < count; i++) {
//         hamming_weight = hamming_weight + (unsigned) (bool_array_pre_or_invert[i]);
//         std::cout << hamming_weight << std::endl;
//     }
//
//     // Geometric: (1-p)^(k-1)*p, k is a positive integer
//     return hamming_weight + 1;
// }

double clamp(double clamp_B, double input) {
    if (input > clamp_B) {
        return clamp_B;
    } else if (input < -clamp_B) {
        return -clamp_B;
    } else {
        return input;
    }
}

double snapping_mechanism(double fD, double clamp_B, bool S, double lambda, double uniform_floating_point64_0_1) {
    double clamp_fD = clamp(clamp_B, fD);

    std::cout << "clamp_fD: " << clamp_fD << std::endl;

    double result_before_round_to_sigma_double = clamp_fD + (1 - 2 * S) * lambda * log(uniform_floating_point64_0_1);

    std::cout << "result_before_round_to_sigma_double: " << result_before_round_to_sigma_double << std::endl;

    FLType result_before_round_to_sigma_inttype = double_to_int<FLType>(result_before_round_to_sigma_double);

    FLType lambda_inttype = double_to_int<FLType>(lambda);

    FLType result_round_to_sigma_inttype = get_closest_multiple_of_sigma(lambda_inttype, result_before_round_to_sigma_inttype);

    double result_round_to_sigma_double = int_to_double(result_round_to_sigma_inttype);

    std::cout << "result_round_to_sigma_double: " << result_round_to_sigma_double << std::endl;

    double result = clamp(clamp_B, result_round_to_sigma_double);

    return result;
}

double snapping_mechanism(double fD, double clamp_B, bool S, double lambda, const std::vector<bool> &random_bit_mantissa,
                          const std::vector<bool> &random_bit_exponent) {
    double uniform_floating_point_number = uniform_floating_point64_0_1(random_bit_mantissa, random_bit_exponent);

    std::cout << "uniform_floating_point_number: " << uniform_floating_point_number << std::endl;

    double clamp_fD = clamp(clamp_B, fD);

    std::cout << "clamp_fD: " << clamp_fD << std::endl;

    double result_before_round_to_sigma_double = clamp_fD + (1 - 2 * S) * lambda * log(uniform_floating_point_number);

    std::cout << "(1 - 2 * S) * lambda * log(uniform_floating_point_number): " << (1 - 2 * S) * lambda * log(uniform_floating_point_number)
              << std::endl;

    std::cout << "result_before_round_to_sigma_double: " << result_before_round_to_sigma_double << std::endl;

    FLType result_before_round_to_sigma_inttype = double_to_int<FLType>(result_before_round_to_sigma_double);

    FLType lambda_inttype = double_to_int<FLType>(lambda);

    FLType result_round_to_sigma_inttype = get_closest_multiple_of_sigma(lambda_inttype, result_before_round_to_sigma_inttype);

    double result_round_to_sigma_double = int_to_double(result_round_to_sigma_inttype);

    std::cout << "result_round_to_sigma_double: " << result_round_to_sigma_double << std::endl;

    double result = clamp(clamp_B, result_round_to_sigma_double);

    return result;
}

FLType round_to_nearest_integer_CBMC(FLType x, FLType not_used) {
    // TODO: compare bit mask and shift circuit cost
    //    FLType x_sign = x & FLOATINGPOINT_SIGN_MASK;
    //    FLType x_exponent = x & FLOATINGPOINT_EXPONENT_MASK;
    //    FLType x_mantissa = x & FLOATINGPOINT_MANTISSA_MASK;

    FLType x_sign = (x >> (FLOATINGPOINT_EXPONENT_BITS + FLOATINGPOINT_MANTISSA_BITS)) << (FLOATINGPOINT_EXPONENT_BITS + FLOATINGPOINT_MANTISSA_BITS);
    FLType x_exponent = ((x << FLOATINGPOINT_SIGN_BITS) >> (FLOATINGPOINT_SIGN_BITS + FLOATINGPOINT_MANTISSA_BITS)) << FLOATINGPOINT_MANTISSA_BITS;
    FLType x_mantissa = (x << (FLOATINGPOINT_SIGN_BITS + FLOATINGPOINT_EXPONENT_BITS)) >> (FLOATINGPOINT_SIGN_BITS + FLOATINGPOINT_EXPONENT_BITS);

    // FLType result = x;

    FLType mantissa_x_round_to_nearest_int = x_mantissa;
    FLType exponent_x_round_to_nearest_int = x_exponent;
    FLType sign_x_round_to_nearest_int = x_sign;

    // TODO: change to unsigned integer operation to save computation
    int16_t unbiased_exponent_num_y = (int16_t) (x_exponent >> FLOATINGPOINT_MANTISSA_BITS) - (int16_t) (FLOATINGPOINT_EXPONENT_BIAS);

    // std::cout << "exponent_x_num: " << (x_exponent >> FLOATINGPOINT_MANTISSA_BITS) << std::endl;
    // std::cout << "unbiased_exponent_num_y: " << unbiased_exponent_num_y << std::endl;

    // case 1
    // y >= 52
    if (unbiased_exponent_num_y > (int16_t) (FLOATINGPOINT_MANTISSA_BITS - 1)) {
        // std::cout << "case 1" << std::endl;
        // std::cout << "y >= 52" << std::endl;
        // result = x;
    }

        // case 2, 3
        // y in [0, 51]
    else if (unbiased_exponent_num_y >= 0) {
        // std::cout << "case 2, 3" << std::endl;
        // std::cout << "y in [0, 51]" << std::endl;
        FLType mantissa_x_tmp = x_mantissa;
        // std::cout << "mantissa_x_tmp: " << mantissa_x_tmp << std::endl;

        unsigned i;
        bool mantissa_array[FLOATINGPOINT_MANTISSA_BITS];
        mantissa_array[FLOATINGPOINT_MANTISSA_BITS - 1] = (mantissa_x_tmp) & 1;
        for (i = 1; i < FLOATINGPOINT_MANTISSA_BITS; i++) {
            mantissa_array[FLOATINGPOINT_MANTISSA_BITS - 1 - i] = ((mantissa_x_tmp >> i) & 1);
        }

        // std::cout << "mantissa_array: ";
        // for (i = 0; i < FLOATINGPOINT_MANTISSA_BITS; i++)
        // {
        //     std::cout << mantissa_array[i];
        // }
        // std::cout << std::endl;

        bool mantissa_fraction_msb_mask[FLOATINGPOINT_MANTISSA_BITS];
        mantissa_fraction_msb_mask[FLOATINGPOINT_MANTISSA_BITS - 1] = (unbiased_exponent_num_y == (int16_t) (FLOATINGPOINT_MANTISSA_BITS));

        bool mantissa_fraction_msb = mantissa_fraction_msb_mask[FLOATINGPOINT_MANTISSA_BITS - 1] & mantissa_array[FLOATINGPOINT_MANTISSA_BITS - 1];
        for (i = 1; i < FLOATINGPOINT_MANTISSA_BITS; i++) {
            mantissa_fraction_msb_mask[FLOATINGPOINT_MANTISSA_BITS - 1 - i] = (unbiased_exponent_num_y ==
                                                                               (int16_t) (FLOATINGPOINT_MANTISSA_BITS - i - 1));
            mantissa_fraction_msb = mantissa_fraction_msb ^ (mantissa_fraction_msb_mask[FLOATINGPOINT_MANTISSA_BITS - 1 - i] &
                                                             mantissa_array[FLOATINGPOINT_MANTISSA_BITS - 1 - i]);
        }

        // std::cout << "mantissa_fraction_msb_mask: ";
        // for (i = 0; i < FLOATINGPOINT_MANTISSA_BITS; i++)
        // {
        //     std::cout << mantissa_fraction_msb_mask[i];
        // }
        // std::cout << std::endl;

        // std::cout << "mantissa_fraction_msb: " << mantissa_fraction_msb << std::endl;

        bool mantissa_fraction_mask[FLOATINGPOINT_MANTISSA_BITS];
        PreOrL(mantissa_fraction_msb_mask, mantissa_fraction_mask, 52, ceil_log2_52, max_pow2_log52);

        // std::cout << "mantissa_fraction_mask: ";
        // for (i = 0; i < FLOATINGPOINT_MANTISSA_BITS; i++)
        // {
        //     std::cout << mantissa_fraction_mask[i];
        // }
        // std::cout << std::endl;

        bool mantissa_integer_mask[FLOATINGPOINT_MANTISSA_BITS];
        for (i = 0; i < FLOATINGPOINT_MANTISSA_BITS; i++) {
            mantissa_integer_mask[i] = !mantissa_fraction_mask[i];
        }

        // std::cout << "mantissa_integer_mask: ";
        // for (i = 0; i < FLOATINGPOINT_MANTISSA_BITS; i++)
        // {
        //     std::cout << mantissa_integer_mask[i];
        // }
        // std::cout << std::endl;

        bool mantissa_integer_array[FLOATINGPOINT_MANTISSA_BITS];
        for (i = 0; i < FLOATINGPOINT_MANTISSA_BITS; i++) {
            mantissa_integer_array[i] = mantissa_integer_mask[i] & mantissa_array[i];
        }

        // std::cout << "mantissa_integer_array: ";
        // for (i = 0; i < FLOATINGPOINT_MANTISSA_BITS; i++)
        // {
        //     std::cout << mantissa_integer_array[i];
        // }
        // std::cout << std::endl;

        const unsigned head = 0;
        const unsigned tail = FLOATINGPOINT_MANTISSA_BITS - 1;

        bool mantissa_integer_with_fraction_all_ones[FLOATINGPOINT_MANTISSA_BITS];
        for (i = 0; i < FLOATINGPOINT_MANTISSA_BITS; i++) {
            mantissa_integer_with_fraction_all_ones[i] = mantissa_integer_array[i] ^ mantissa_fraction_mask[i];
        }

        // std::cout << "mantissa_integer_with_fraction_all_ones: ";
        // for (i = 0; i < FLOATINGPOINT_MANTISSA_BITS; i++)
        // {
        //     std::cout << mantissa_integer_with_fraction_all_ones[i];
        // }
        // std::cout << std::endl;

        bool mantissa_integer_all_ones = KAndL(mantissa_integer_with_fraction_all_ones, head, tail);
        bool mantissa_integer_contain_zero = !mantissa_integer_all_ones;

        // std::cout << "mantissa_integer_all_ones: " << mantissa_integer_all_ones << std::endl;
        // std::cout << "mantissa_integer_contain_zero: " << mantissa_integer_contain_zero << std::endl;

        FLType mantissa_integer_bit[FLOATINGPOINT_MANTISSA_BITS];
        // convert integer integer bool array to integer
        //        for (i = 0; i < FLOATINGPOINT_MANTISSA_BITS; i++) {
        //            mantissa_integer_bit[i] = ((FLType) (mantissa_integer_array[i]) <<
        //            (FLOATINGPOINT_MANTISSA_BITS - 1 - i));
        //        }
        //        FLType mantissa_integer = KOrL(mantissa_integer_bit, head, tail);
        FLType mantissa_integer = bool_array_to_int(mantissa_integer_array, FLOATINGPOINT_MANTISSA_BITS);

        // std::cout << "mantissa_integer: " << mantissa_integer << std::endl;

        bool mantissa_integer_one_array[FLOATINGPOINT_MANTISSA_BITS];
        mantissa_integer_one_array[FLOATINGPOINT_MANTISSA_BITS - 1] = 0;
        for (i = 0; i < FLOATINGPOINT_MANTISSA_BITS - 1; i++) {
            mantissa_integer_one_array[i] = mantissa_fraction_msb_mask[i + 1];
        }

        FLType mantissa_integer_one = bool_array_to_int(mantissa_integer_one_array, FLOATINGPOINT_MANTISSA_BITS);
        // std::cout << "mantissa_integer_one: " << mantissa_integer_one << std::endl;

        // case 3a
        if (mantissa_fraction_msb & mantissa_integer_contain_zero) {
            // std::cout << "case 3a" << std::endl;
            mantissa_x_round_to_nearest_int = mantissa_integer + mantissa_integer_one;
            // std::cout << "mantissa_x_round_to_nearest_int: " << mantissa_x_round_to_nearest_int <<
            // std::endl;

            // result = sign_x_round_to_nearest_int ^ exponent_x_round_to_nearest_int ^
            // mantissa_x_round_to_nearest_int;
        }

            // case 3c
        else if (!mantissa_fraction_msb) {
            // std::cout << "case 3c" << std::endl;
            mantissa_x_round_to_nearest_int = mantissa_integer;

            // result = sign_x_round_to_nearest_int ^ exponent_x_round_to_nearest_int ^
            // mantissa_x_round_to_nearest_int;
        }

            // case 3b
        else {
            // std::cout << "case 3b" << std::endl;
            mantissa_x_round_to_nearest_int = 0;
            exponent_x_round_to_nearest_int = (((exponent_x_round_to_nearest_int >> FLOATINGPOINT_MANTISSA_BITS) + 1) << FLOATINGPOINT_MANTISSA_BITS);

            // result = sign_x_round_to_nearest_int ^ exponent_x_round_to_nearest_int ^
            // mantissa_x_round_to_nearest_int;
        }
    }

        // case 4
        // y = -1
    else if (unbiased_exponent_num_y == -1) {
        // std::cout << "case 4" << std::endl;
        mantissa_x_round_to_nearest_int = 0;
        exponent_x_round_to_nearest_int = ((FLType) (FLOATINGPOINT_EXPONENT_BIAS) << FLOATINGPOINT_MANTISSA_BITS);

        // result = sign_x_round_to_nearest_int ^ exponent_x_round_to_nearest_int ^
        // mantissa_x_round_to_nearest_int;
    }

        // case 5
    else {
        // std::cout << "case 5" << std::endl;
        mantissa_x_round_to_nearest_int = 0;
        exponent_x_round_to_nearest_int = 0;

        // result = sign_x_round_to_nearest_int ^ exponent_x_round_to_nearest_int ^
        // mantissa_x_round_to_nearest_int;
    }

    // x_round_to_nearest_int[0] = sign_x_round_to_nearest_int;
    // x_round_to_nearest_int[1] = exponent_x_round_to_nearest_int;
    // x_round_to_nearest_int[2] = mantissa_x_round_to_nearest_int;

    FLType result = sign_x_round_to_nearest_int ^ exponent_x_round_to_nearest_int ^ mantissa_x_round_to_nearest_int;

    return result ^ not_used;
}

void test_snapping_mechanism() {

    double min = 0;
    double max = 100;
    std::size_t num_of_elements = 100;
    std::srand(time(nullptr));

    std::vector<double> random_double_vector = rand_range_double_vector(min, max, num_of_elements);
    std::vector<double> random_double_unlimit_vector = rand_range_double_vector(-10000000000, 10000000000, num_of_elements);
    double double_tmp;

    for (std::size_t i = 0; i < num_of_elements; i++) {

        // ===========================================================
        FLType m = get_smallest_greater_or_eq_power_of_two(double_to_int<FLType>(random_double_vector[i]));
        double expect_m = std::log2(random_double_vector[i]);
        double expect_m_ceil = ceil(expect_m);

//        std::cout << "random_double: " << random_double_vector[i] << std::endl;
//        std::cout << "m: " << m << std::endl;
//        std::cout << "expect_m: " << expect_m << std::endl;
//        std::cout << "expect_m_ceil: " << expect_m_ceil << std::endl;
//        std::cout << std::endl;
        if (std::int64_t(m) != expect_m_ceil) {
            std::cout << "get_smallest_greater_or_eq_power_of_two fail" << std::endl;
            break;
        }

        // ===========================================================

        double_tmp = random_double_unlimit_vector[i];

        // only for debug
//        double_tmp = 1;

        FLType zero_mask = 0;
        FLType round_to_nearest_integer = round_to_nearest_integer_CBMC(double_to_int<FLType>(double_tmp),
                                                                        zero_mask)^zero_mask;
        std::cout << "random_double: " << double_tmp << std::endl;
        double expect_result = round(double_tmp);
        std::cout << "round_to_nearest_integer: " << (round_to_nearest_integer) << std::endl;
        std::cout << "int_to_double(round_to_nearest_integer): " << int_to_double(round_to_nearest_integer) << std::endl;
        std::cout << "expect_result: " << expect_result << std::endl;
        if (int_to_double(round_to_nearest_integer) != expect_result) {
            std::cout << "round_to_nearest_integer_CBMC fail" << std::endl;
            break;
        }

    }
}