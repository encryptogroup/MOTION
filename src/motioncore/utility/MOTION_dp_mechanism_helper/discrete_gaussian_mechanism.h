#pragma once

#include <cmath>
#include <vector>
#include "dp_mechanism_helper.h"

// based on paper (The Discrete Gaussian for Differential Privacy)
template <typename T>
struct GeometricDistributionEXPOptimizationStruct {
  long double iteration_1;
  long double iteration_2;
  long double minimum_total_iteration;
  long double minimum_total_MPC_time;
  long double geometric_failure_probability_estimation;
  T numerator;
  T denominator;
  std::size_t log2_denominator;

  // not used currently
  long double upscale_factor;
};

template <typename T>
struct DiscreteLaplaceDistributionOptimizationStruct {
  long double iteration_geo_1;
  long double iteration_geo_2;
  long double iteration_dlap_3;
  long double minimum_total_iteration;
  long double minimum_total_MPC_time;
  long double geometric_failure_probability_estimation;
  long double discrete_laplace_failure_probability_estimation;
  T numerator;
  T denominator;
  std::size_t log2_denominator;

  // not used currently
  long double upscale_factor;
};

template <typename T>
struct DiscreteGaussianDistributionOptimizationStruct {
  long double iteration_geo_1;
  long double iteration_geo_2;
  long double iteration_dlap_3;
  long double iteration_dgauss_4;
  long double minimum_total_iteration;
  long double minimum_total_MPC_time;
  long double geometric_failure_probability_estimation;
  long double discrete_laplace_failure_probability_estimation;
  long double discrete_gaussian_failure_probability_estimation;
  T numerator;
  T denominator;
  std::size_t log2_denominator;
  long double t;
  long double sigma;

  // not used currently
  long double upscale_factor;
};

// sample from a Bernoulli(exp(-x)) distribution
// assumes x is a rational number in [0,1]
std::vector<bool> Bernoulli_distribution_EXP_0_1(double gamma,
                                                 std::vector<double> random_floating_point_0_1);

// sample from a Bernoulli(exp(-x)) distribution
// assumes x is a rational number in [1, +inf]
std::vector<bool> Bernoulli_distribution_EXP_1(double gamma, double upper_bound_gamma,
                                               std::vector<double> random_floating_point_0_1);

// sample from a Bernoulli(exp(-x)) distribution
std::vector<bool> Bernoulli_distribution_EXP(double gamma,
                                             std::vector<double> random_floating_point_0_1);

// sample from a geometric(1-exp(-x)) distribution, x = numerator / denominator
// assumes x >= 0 and is rational
// return: geometric sample, if sampling is success
template <typename T, typename A = std::allocator<T>>
std::vector<T> geometric_distribution_EXP(T numerator, T denominator,
                                          std::vector<double> random_floating_point_0_1_vector,
                                          std::vector<T, A> random_integer_vector,
                                          std::size_t iteration_1, std::size_t iteration_2);
// sample from a geometric(1-exp(-x)) distribution, x = numerator
// assumes x >= 0 and is rational
// return: geometric sample, if sampling is success
// special case when denominator = 1, where bernoulli (p = exp^(-0/t)) always output 1, skip the
// first for loop
// we can avoid the generation of random_integer_vector in this method
template <typename T, typename A = std::allocator<T>>
std::vector<T> geometric_distribution_EXP(T numerator,
                                          std::vector<double> random_floating_point_0_1_vector,
                                          std::size_t iteration_2);

// sample from a discrete Laplace(scale) distribution
// Returns integer x with Pr[x] = exp(-abs(x)/scale)*(exp(1/scale)-1)/(exp(1/scale)+1)
// casts scale to Fraction
// assumes scale>=0
template <typename T, typename A = std::allocator<T>>
std::vector<T> discrete_laplace_distribution_EXP(
    T numerator, T denominator, std::vector<double> random_floating_point_0_1_vector,
    std::vector<T, A> random_integer_vector, std::vector<bool> bernoulli_sample_vector,
    std::size_t iteration_1, std::size_t iteration_2, std::size_t iteration_3);

template <typename T, typename A = std::allocator<T>>
std::vector<T> discrete_laplace_distribution_EXP(
    T numerator, std::vector<double> random_floating_point_0_1_vector,
    std::vector<bool> bernoulli_sample_vector, std::size_t iteration_2, std::size_t iteration_3);

// sample from a discrete Gaussian distribution N_Z(0,sigma2)
// Returns integer x with Pr[x] = exp(-x^2/(2*sigma2))/normalizing_constant(sigma2)
// mean 0 variance ~= sigma2 for large sigma2
// casts sigma2 to Fraction
// assumes sigma2>=0
template <typename T, typename T_int, typename A = std::allocator<T>>
std::vector<T> discrete_gaussian_distribution_EXP(
    double sigma, T numerator, T denominator,
    std::vector<double> random_floating_point_0_1_dlap_vector,
    std::vector<T, A> random_integer_dlap_vector, std::vector<bool> bernoulli_sample_dlap_vector,
    std::vector<double> random_floating_point_0_1_dgau_vector, std::size_t iteration_1,
    std::size_t iteration_2, std::size_t iteration_3, std::size_t iteration_4);

template <typename T, typename T_int, typename A = std::allocator<T>>
std::vector<T> discrete_gaussian_distribution_EXP(
    double sigma, T numerator, T denominator,
    std::vector<double> random_floating_point_0_1_dlap_vector,
    std::vector<bool> bernoulli_sample_dlap_vector,
    std::vector<double> random_floating_point_0_1_dgau_vector, std::size_t iteration_2,
    std::size_t iteration_3, std::size_t iteration_4);

template <typename T, typename T_int, typename A = std::allocator<T>>
std::vector<T> discrete_gaussian_distribution_EXP_with_discrete_Laplace_EKMPP(
    double sigma, const std::vector<T>& discrete_laplace_sample_vector,
    const std::vector<double>& random_floating_point_0_1_dgau_vector, std::size_t iteration);

long double discrete_laplace_distribution_PDF(long double t, std::int64_t x);

// following functions are used to estimate the number of iterations of the sampling functions

// template<typename T>
// std::vector<long double>
// geometric_distribution_EXP_iteration_estimation(T numerator, T denominator, long double
// total_failure_probability = standard_failure_probability);

// estimate the failure probability given iteration and other parameters
template <typename T>
long double geometric_distribution_EXP_failure_probability_estimation(T numerator, T denominator,
                                                                      long double iteration_1,
                                                                      long double iteration_2);

// find the minimum total number of iterations
template <typename T>
GeometricDistributionEXPOptimizationStruct<T> optimize_geometric_distribution_EXP_iteration(
    T numerator, T denominator, long double total_failure_probability);

// find the minimum total number of iterations
template <typename T>
GeometricDistributionEXPOptimizationStruct<T> optimize_geometric_distribution_EXP_iteration(
    long double x_geo, long double total_failure_probability);
//
// template<typename T>
// std::vector<long double>
// discrete_laplace_distribution_EXP_iteration_estimation(T numerator, T denominator, long double
// total_failure_probability = standard_failure_probability);

template <typename T>
long double discrete_laplace_distribution_EXP_failure_probability_estimation(
    T numerator, T denominator, long double iteration_1, long double iteration_2,
    long double iteration_3);

template <typename T>
DiscreteLaplaceDistributionOptimizationStruct<T> optimize_discrete_laplace_distribution_EXP_iteration(
    long double x_lap, long double total_failure_probability = standard_failure_probability);

// ! remove later
// template <typename T>
// std::vector<long double> optimize_discrete_laplace_distribution_EXP_iteration_with_tolerance(
//     double scale, long double total_failure_probability = standard_failure_probability,
//     double error_threshold = 0, double error_granularity = 0.0001);

template <typename T, typename T_int>
std::vector<long double> discrete_gaussian_distribution_EXP_failure_probability_estimation(
    long double sigma, T numerator, T denominator, long double iteration_1, long double iteration_2,
    long double iteration_3, long double iteration_4);

template <typename T, typename T_int>
std::vector<long double>
discrete_gaussian_distribution_EXP_with_discrete_laplace_EKMPP_failure_probability_estimation(
    double sigma, long double iteration);

template <typename T, typename T_int>
DiscreteGaussianDistributionOptimizationStruct<T>
optimize_discrete_gaussian_distribution_EXP_iteration(
    long double sigma, long double total_failure_probability = standard_failure_probability);

template <typename T, typename T_int>
std::vector<long double>
optimize_discrete_gaussian_distribution_EXP_with_discrete_laplace_EKMPP_iteration(
    double sigma, long double total_failure_probability = standard_failure_probability);

template <typename T, typename T_int>
std::vector<T> geometric_noise_generation(
    T numerator, T denominator, long double failure_probability = standard_failure_probability,
    std::size_t num_of_elements = 1);

template <typename T>
std::vector<T> discrete_laplace_noise_generation(
    double scale, long double failure_probability = standard_failure_probability,
    std::size_t num_of_elements = 1);

template <typename T, typename T_int>
std::vector<T> discrete_gaussian_noise_generation(
    double sigma, long double failure_probability = standard_failure_probability,
    std::size_t num_of_elements = 1);

void test_optimize_geometric_distribution_EXP_iteration();

void test_optimize_discrete_laplace_distribution_EXP_iteration();

void test_optimize_discrete_gaussian_distribution_EXP_iteration();

void test_optimize_discrete_gaussian_distribution_EXP_iteration();

void test_optimize_integer_scaling_laplace_distribution_EXP_iteration();

// void test_optimize_discrete_laplace_distribution_EXP_iteration_with_threshold();