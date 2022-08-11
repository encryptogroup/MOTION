#pragma once

#include <vector>
#include <climits>
#include "snapping_mechanism.h"
#include <cassert>
#include <cmath>

#define standard_fail_probability std::exp2l(-40)

#define iteration_1_weight (14.125+155.486+130.030+2.799)
#define iteration_2_weight (2.799)
#define iteration_3_weight (1)
#define iteration_4_weight (14.125+155.486+38)

template<typename T>
T bool_vector_hamming_weight(std::vector<bool> bool_vector);

template<typename T>
T bool_vector_to_int(std::vector<bool> bool_vector);

float bool_vector_to_float(std::vector<bool> bool_vector);

double bool_vector_to_double(std::vector<bool> bool_vector);

template<typename T>
T bool_vector_geometric_sampling(std::vector<bool> bool_vector);

double uniform_floating_point64_0_1(const std::vector<bool> &random_bit_exponent, const std::vector<bool> &random_bit_mantissa);

float uniform_floating_point32_0_1(const std::vector<bool> &random_bit_exponent, const std::vector<bool> &random_bit_mantissa);

void print_double_as_bit(double input);

double rand_range_double(double min, double max);

std::vector<float> rand_range_float_vector(double min, double max, std::size_t num_of_elements);

std::vector<double> rand_range_double_vector(double min, double max, std::size_t num_of_elements);

template<typename T>
std::vector<T> rand_range_integer_vector(double min, double max, std::size_t num_of_elements);

std::vector<bool> rand_bool_vector(std::size_t num_of_elements);

// compute the overlapping area (number of integers) of area A and area B, i.e., overlapping area / area A
long double overlapping_area_percent(long double A_lower_bound, long double A_upper_bound, long double B_lower_bound, long double B_upper_bound);

// count the number of integers in range
long double number_of_integer_in_range(long double lower_bound, long double upper_bound);

// PDF: (1-p)^x * p
long double geometric_distribution_PDF(long double p, long double x);

long long gcd(long long a, long long b);

std::vector<double> decimalToFraction(double number, long precision=std::exp2(62));

double ceil_power_of_two(double);

std::vector<double> scale_double_vector(std::vector<double> input_vector, double scale_factor);

double laplace_distribution(double lambda, double random_floating_point_0_1_rx, double random_floating_point_0_1_ry);

std::vector<double> gaussian_distribution_box_muller(double mu, double sigma, double random_floating_point_0_1_u1, double random_floating_point_0_1_u2);

double discrete_laplace_distribution(double lambda, double random_floating_point_0_1_rx, double random_floating_point_0_1_ry);


void test_dp_mechanism_helper();