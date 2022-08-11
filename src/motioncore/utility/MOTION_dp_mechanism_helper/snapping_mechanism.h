#pragma once

#include <cstdint>
#include <vector>
#include "dp_mechanism_helper.h"

#define FLOATINGPOINT_BITS 64
#define FLOATINGPOINT_MANTISSA_BITS 52
#define FLOATINGPOINT_EXPONENT_BITS 11
#define FLOATINGPOINT_SIGN_BITS 1
#define FLOATINGPOINT_EXPONENT_BIAS 1023

#define FLOATINGPOINT_MANTISSA_MASK ((FLType(1) << FLOATINGPOINT_MANTISSA_BITS) - 1)
#define FLOATINGPOINT_EXPONENT_MASK \
  (((FLType(1) << FLOATINGPOINT_EXPONENT_BITS) - 1) << FLOATINGPOINT_MANTISSA_BITS)
#define FLOATINGPOINT_SIGN_MASK ((FLType(1) << (FLOATINGPOINT_BITS - FLOATINGPOINT_SIGN_BITS)))

// single precision floating point
#define FLOATINGPOINT32_BITS 32
#define FLOATINGPOINT32_MANTISSA_BITS 23
#define FLOATINGPOINT32_EXPONENT_BITS 8
#define FLOATINGPOINT32_SIGN_BITS 1
#define FLOATINGPOINT32_EXPONENT_BIAS 127

#define ceil_log2_52 6
#define ceil_log2_64 6
#define max_pow2_log52 64
#define max_pow2_log64 64

using FLType = std::uint64_t;
using FLType_int = std::int64_t;

template <typename T>
T double_to_int(double double_input);

FLType double_to_bool_array(double double_input);

FLType bool_array_to_int(bool bool_array[], unsigned count = FLOATINGPOINT_BITS);

double bool_array_to_double(bool bool_array[], unsigned count = FLOATINGPOINT_BITS);

double int_to_double(FLType int_input, unsigned count = FLOATINGPOINT_BITS);

void int_to_bool_array(FLType int_input, bool bool_array[]);

void PreOrL(bool bool_array_list[], bool pre_or_list[], unsigned count = 52,
            unsigned log_k = ceil_log2_52, unsigned kmax = max_pow2_log52);

bool KAndL(bool bool_array_list[], const unsigned head, const unsigned tail);

bool KOrL(bool bool_array_list[], const unsigned head, const unsigned tail);

FLType KOrL(FLType array_list[], const unsigned head, const unsigned tail);

FLType get_smallest_greater_or_eq_power_of_two(const FLType lambda);

void divide_by_power_of_two(const FLType x, const FLType m, FLType output_x_div_pow2_m[]);

void round_to_nearest_int(const FLType x, FLType output_x_round_to_nearest_int[]);

void multiply_by_power_of_two(const FLType x, FLType m, FLType output_x_mul_pow2_sigma[]);

FLType get_closest_multiple_of_sigma(const FLType lambda, const FLType x);

//// sample from geometric distribution in 64 iterations, fail probaility is 2^(-64)
// unsigned geometric_sample(const FLType random_bits);

double clamp(double clamp_B);

double snapping_mechanism(double f_D, double clamp_B, bool S, double lambda,
                          double uniform_floating_point64_0_1);

double snapping_mechanism(double fD, double clamp_B, bool S, double lambda,
                          const std::vector<bool>& random_bit_mantissa,
                          const std::vector<bool>& random_bit_exponent);

FLType round_to_nearest_integer_CBMC(FLType x, FLType not_used);

void test_snapping_mechanism();