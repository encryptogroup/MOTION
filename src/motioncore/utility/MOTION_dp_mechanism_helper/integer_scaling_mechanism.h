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


#pragma once

#include <cmath>
#include <iostream>
#include <vector>
#include "discrete_gaussian_mechanism.h"
#include "dp_mechanism_helper.h"
#include "print_uint128_t.h"

static double binomial_bound = std::exp2(57.0);

using FLType = std::uint64_t;
using FLType_int = std::int64_t;

FLType
geometric_sampling_binary_search(FLType L0, FLType R0, double lambda, std::size_t iterations, std::vector<double> uniform_floating_point_0_1_vector);

double integer_scaling_laplace_noise_generation(double sensitivity_l1, double epsilon, std::size_t num_of_simd_lap,
                                                long double fail_probability = standard_fail_probability);

double integer_scaling_gaussian_noise_generation(double sensitivity_l1, double sigma, std::size_t num_of_simd_gau,
                                                 long double fail_probability = standard_fail_probability);

template<typename IntType, typename IntType_int, typename A = std::allocator<IntType>>
std::vector<IntType> symmetrical_binomial_distribution(double constant_sqrt_n, std::vector<std::uint64_t> signed_integer_geometric_sample_vector,
                                                       std::vector<bool> random_bits_vector,
                                                       std::vector<std::uint64_t> random_unsigned_integer_vector,
                                                       std::vector<double> random_floating_point_0_1_vector, std::size_t iteration);

std::vector<long double> symmetrical_binomial_distribution_fail_probability_estimation(double sqrt_n, double iteration);

std::vector<long double>
optimize_symmetrical_binomial_distribution_iteration(double sqrt_n, double total_fail_probability = standard_fail_probability);

double UnitNormalCDF(double value);

// https://github.com/google/differential-privacy
double SigmaForGaussian(std::int64_t l0Sensitivity, double lInfSensitivity, double epsilon, double delta);

double deltaForGaussian(double sigma, double l0Sensitivity, double lInfSensitivity, double epsilon);

// km + l > INT64_MAX
void symmetrical_binomial_distribution_represent_as_int64_fail_probability_estimation();

void test_symmetrical_binomial_distribution();

void test_SigmaForGaussian();

void test_symmetrical_binomial_distribution();