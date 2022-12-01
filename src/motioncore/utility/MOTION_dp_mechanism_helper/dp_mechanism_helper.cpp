//
// Created by liangzhao on 30.05.22.
//

#include "dp_mechanism_helper.h"
#include <bits/stdc++.h>
#include <iostream>

#include <openssl/rand.h>
#include <algorithm>

template <typename T>
T bool_vector_hamming_weight(std::vector<bool> bool_vector) {
  T r = 0;
  for (std::size_t j = 0; j < bool_vector.size(); j++) {
    if (bool_vector[j]) {
      r++;
    }
  }
  return r;
}

template <typename T>
T bool_vector_to_int(std::vector<bool> bool_vector) {
  T tmp;

  std::size_t count = bool_vector.size();
  T tmp_int_array[count];
  for (unsigned i = 0; i < count; i++) {
    tmp_int_array[i] = ((T)bool_vector[i] << (i));
  }

  T integer_T = tmp_int_array[0];
  for (std::size_t i = 1; i < count; i++) {
    integer_T |= tmp_int_array[i];
  }

  return integer_T;
}

float bool_vector_to_float(std::vector<bool> bool_vector) {
  std::size_t count = bool_vector.size();
  std::uint32_t int_output = bool_vector_to_int<std::uint32_t>(bool_vector);

  // std::cout << "int_output: " << int_output << std::endl;

  float* float_output = reinterpret_cast<float*>(&int_output);
  return *float_output;
}

double bool_vector_to_double(std::vector<bool> bool_vector) {
  std::size_t count = bool_vector.size();
  std::uint64_t int_output = bool_vector_to_int<std::uint64_t>(bool_vector);

  // std::cout << "int_output: " << int_output << std::endl;

  double* double_output = reinterpret_cast<double*>(&int_output);
  return *double_output;
}

template <typename T>
T bool_vector_geometric_sampling(std::vector<bool> bool_vector) {
  T r = 0;
  for (std::size_t j = 0; j < bool_vector.size(); j++) {
    if (bool_vector[j] == 0) {
      r++;
    } else if (bool_vector[j] == 1) {
      r++;
      break;
    }
  }
  return r;
}

template std::uint64_t bool_vector_geometric_sampling(std::vector<bool> bool_vector);

double uniform_floating_point64_0_1(const std::vector<bool>& random_bit_mantissa,
                                    const std::vector<bool>& random_bit_exponent) {
  //   bool floating_point_bool_array[FLOATINGPOINT_BITS];

  using T = std::uint16_t;
  using T_int = std::int16_t;
  T_int geo = bool_vector_geometric_sampling<T>(random_bit_exponent);
  //  std::cout << "geo: " << geo << std::endl;
  T_int biased_exponent = FLOATINGPOINT_EXPONENT_BIAS - geo;

  //  std::cout << "biased_exponent: " << biased_exponent << std::endl;

  std::vector<bool> exponent_bool_vector(FLOATINGPOINT_EXPONENT_BITS);
  for (std::size_t i = 0; i < FLOATINGPOINT_EXPONENT_BITS; i++) {
    exponent_bool_vector[i] = ((biased_exponent >> i) & 1);
  }

  //  std::cout << "random_bit_mantissa: ";
  std::vector<bool> uniform_floating_point_bool_vector(FLOATINGPOINT_BITS);
  for (std::size_t i = 0; i < FLOATINGPOINT_MANTISSA_BITS; i++) {
    uniform_floating_point_bool_vector[i] = random_bit_mantissa[i];
    //    std::cout << random_bit_mantissa[FLOATINGPOINT_MANTISSA_BITS - 1 - i];
  }
  //  std::cout << std::endl;

  for (std::size_t i = 0; i < FLOATINGPOINT_EXPONENT_BITS; i++) {
    uniform_floating_point_bool_vector[i + FLOATINGPOINT_MANTISSA_BITS] = exponent_bool_vector[i];
  }
  uniform_floating_point_bool_vector.emplace_back(false);

  //  std::cout << "uniform_floating_point_bool_vector: ";
  //  for (std::size_t i = 0; i < FLOATINGPOINT_BITS; i++) {
  //    std::cout << uniform_floating_point_bool_vector[i];
  //  }
  //  std::cout << std::endl;

  //  std::cout << "uniform_floating_point_bool_vector reverse: ";
  //  for (std::size_t i = 0; i < FLOATINGPOINT_BITS; i++) {
  //    std::cout << uniform_floating_point_bool_vector[FLOATINGPOINT_BITS - 1 - i];
  //  }
  //  std::cout << std::endl;

  double uniform_floating_point_double = bool_vector_to_double(uniform_floating_point_bool_vector);

  return uniform_floating_point_double;
}

float uniform_floating_point32_0_1(const std::vector<bool>& random_bit_mantissa,
                                   const std::vector<bool>& random_bit_exponent) {
  //   bool floating_point_bool_array[FLOATINGPOINT32_BITS];

  // std::size_t FLOATINGPOINT32_BITS = 32;
  // std::size_t FLOATINGPOINT32_MANTISSA_BITS = 23;
  // std::size_t FLOATINGPOINT32_EXPONENT_BITS = 8;
  // std::size_t FLOATINGPOINT32_EXPONENT_BIAS = 127;

  using T = std::uint16_t;
  using T_int = std::int16_t;
  T_int geo = bool_vector_geometric_sampling<T>(random_bit_exponent);
  T_int biased_exponent = FLOATINGPOINT32_EXPONENT_BIAS - geo;

  std::vector<bool> exponent_bool_vector(FLOATINGPOINT32_EXPONENT_BITS);
  for (std::size_t i = 0; i < FLOATINGPOINT32_EXPONENT_BITS; i++) {
    exponent_bool_vector[i] = ((biased_exponent >> i) & 1);
  }

  // set the mantissa bits
  std::vector<bool> uniform_floating_point_bool_vector(FLOATINGPOINT32_BITS);
  for (std::size_t i = 0; i < FLOATINGPOINT32_MANTISSA_BITS; i++) {
    uniform_floating_point_bool_vector[i] = random_bit_mantissa[i];
  }

  // set the exponent bits
  for (std::size_t i = 0; i < FLOATINGPOINT32_EXPONENT_BITS; i++) {
    uniform_floating_point_bool_vector[i + FLOATINGPOINT32_MANTISSA_BITS] = exponent_bool_vector[i];
  }

  // set the sign bit
  uniform_floating_point_bool_vector.emplace_back(false);

  float uniform_floating_point_float = bool_vector_to_float(uniform_floating_point_bool_vector);

  return uniform_floating_point_float;
}

// double rand_range_double(double min, double max) {
//   double range = (max - min);
//   double div = RAND_MAX / range;
//   return min + (std::rand() / div);
// }

double rand_range_double(double min, double max) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_real_distribution<> dist(min, max);
  return dist(gen);
}

// std::vector<float> rand_range_float_vector(double min, double max, std::size_t num_of_elements) {
//   std::vector<float> result_vector(num_of_elements);
//   for (std::size_t i = 0; i < num_of_elements; i++) {
//     float range = (max - min);
//     float div = RAND_MAX / range;
//     result_vector[i] = min + (std::rand() / div);
//   }
//   return result_vector;
// }

std::vector<float> rand_range_float_vector(double min, double max, std::size_t num_of_elements) {
  std::vector<float> result_vector;
  result_vector.reserve(num_of_elements);

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_real_distribution<> dist(min, max);

  for (std::size_t i = 0; i < num_of_elements; i++) {
    result_vector.emplace_back(dist(gen));
  }
  return result_vector;
}

// std::vector<double> rand_range_double_vector(double min, double max, std::size_t num_of_elements)
// {
//   std::vector<double> result_vector(num_of_elements);
//   for (std::size_t i = 0; i < num_of_elements; i++) {
//     double range = (max - min);
//     double div = RAND_MAX / range;
//     result_vector[i] = min + (std::rand() / div);
//   }
//   return result_vector;
// }

std::vector<double> rand_range_double_vector(double min, double max, std::size_t num_of_elements) {
  std::vector<double> result_vector;
  result_vector.reserve(num_of_elements);

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_real_distribution<> dist(min, max);

  for (std::size_t i = 0; i < num_of_elements; i++) {
    result_vector.emplace_back(dist(gen));
  }
  return result_vector;
}

// template <typename T>
// std::vector<T> rand_range_integer_vector(double min, double max, std::size_t num_of_elements) {
//   std::vector<T> result_vector(num_of_elements);
//   for (std::size_t i = 0; i < num_of_elements; i++) {
//     double range = (max - min);
//     double div = RAND_MAX / range;
//     result_vector[i] = min + (std::rand() / div);
//   }
//   return result_vector;
// }

template <typename T>
std::vector<T> rand_range_integer_vector(double min, double max, std::size_t num_of_elements) {
  std::vector<T> random_numbers;
  random_numbers.reserve(num_of_elements);

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_real_distribution<> dist(min, max);

  for (std::size_t i = 0; i < num_of_elements; i++) {
    random_numbers.emplace_back(dist(gen));
  }
  return random_numbers;
}

template std::vector<std::int32_t> rand_range_integer_vector<std::int32_t>(
    double min, double max, std::size_t num_of_elements);

template std::vector<std::int64_t> rand_range_integer_vector<std::int64_t>(
    double min, double max, std::size_t num_of_elements);

template std::vector<std::uint64_t> rand_range_integer_vector<std::uint64_t>(
    double min, double max, std::size_t num_of_elements);

template std::vector<__int128_t> rand_range_integer_vector<__int128_t>(double min, double max,
                                                                       std::size_t num_of_elements);

template std::vector<unsigned int> rand_range_integer_vector<unsigned int>(
    double min, double max, std::size_t num_of_elements);

std::vector<bool> rand_bool_vector(std::size_t num_of_elements) {
  double min = 0;
  double max = 1;
  std::vector<bool> result_vector(num_of_elements);
  for (std::size_t i = 0; i < num_of_elements; i++) {
    double range = (max - min);
    double div = RAND_MAX / range;
    result_vector[i] = (min + (std::rand() / div)) < 0.5;
  }
  return result_vector;
}

long double geometric_distribution_PDF(long double p, long double x) {
  return powl((1 - p), x) * p;
}

long double number_of_integer_in_range(long double lower_bound, long double upper_bound) {
  long double number_of_integer_in_range = floorl(upper_bound) - ceill(lower_bound);
  if (number_of_integer_in_range < 0) {
    return 0;
  } else {
    return number_of_integer_in_range;
  }
}

long double overlapping_area_percent(long double A_lower_bound, long double A_upper_bound,
                                     long double B_lower_bound, long double B_upper_bound) {
  assert(A_lower_bound <= A_upper_bound);
  assert(B_lower_bound <= B_upper_bound);

  long double num_of_integers_in_A = floorl(A_upper_bound) - ceill(A_lower_bound);

  // no overlapping area
  if ((A_upper_bound < B_lower_bound) || (B_upper_bound < A_lower_bound)) {
    return 0;
  }

  // A is in B
  else if ((B_lower_bound <= A_lower_bound) && (A_upper_bound <= B_upper_bound)) {
    return 1;

  }

  // B is in A
  else if ((A_lower_bound < B_lower_bound) || (B_upper_bound < A_upper_bound)) {
    return number_of_integer_in_range(B_lower_bound, B_upper_bound) / num_of_integers_in_A;
  }

  // A, B
  else if ((A_lower_bound <= B_lower_bound <= A_upper_bound) && (A_upper_bound <= B_upper_bound)) {
    return number_of_integer_in_range(B_lower_bound, A_upper_bound) / num_of_integers_in_A;

  }

  // B, A
  else if ((B_lower_bound <= A_lower_bound <= B_upper_bound) && (B_upper_bound <= A_upper_bound)) {
    return number_of_integer_in_range(A_lower_bound, B_upper_bound) / num_of_integers_in_A;

  } else {
    return 0;
  }
}

// Recursive function to
// return GCD of a and b
long long gcd(long long a, long long b) {
  if (a == 0)
    return b;
  else if (b == 0)
    return a;
  if (a < b)
    return gcd(a, b % a);
  else
    return gcd(b, a % b);
}

// Function to convert decimal to fraction
std::vector<double> decimalToFraction(double number, long precision) {
  // Fetch integral value of the decimal
  double intVal = floor(number);

  // Fetch fractional part of the decimal
  double fVal = number - intVal;

  // TODO: precision need to be consistent with integer mod security

  // Consider precision value to
  // convert fractional part to
  // integral equivalent
  //    const long pVal = 100000000000;

  // ! we need to guarantee that num and deo are not greater than 2^(64),
  // because the random unsigned integer we generate in MPC is smaller than 2^(64)
  const long pVal = precision;

  //// only for debug
  //  const long pVal = std::exp2l(30);

  // Calculate GCD of integral
  // equivalent of fractional
  // part and precision value
  long long gcdVal = gcd(round(fVal * pVal), pVal);

  // Calculate num and deno
  long long num = round(fVal * pVal) / gcdVal;
  long long deno = pVal / gcdVal;

  // Print the fraction
  //    std::cout << (intVal * deno) + num << "/" << deno << std::endl;

  std::vector<double> result_vector(2);
  result_vector[0] = (intVal * deno) + num;
  result_vector[1] = deno;

  return result_vector;
}

std::vector<long double> decimalToFractionWithDenominatorFixed(long double x,
                                                               long double denominator) {
  std::vector<long double> result_vector(3);
  long double numerator_new = roundl(x * denominator);
  // std::cout<<"numerator_new: "<<numerator_new<<std::endl;
  long double denominator_new = denominator;

  result_vector[0] = numerator_new;
  result_vector[1] = denominator_new;
  if (numerator_new == 0) {
    result_vector[2] = 1;
  } else {
    result_vector[2] = std::abs((long double)(numerator_new) / (long double)(denominator_new)-x);
  }
  return result_vector;
}

std::vector<double> scale_double_vector(std::vector<double> input_vector, double scale_factor) {
  std::vector<double> result_vector(input_vector.size());
  for (std::size_t i = 0; i < input_vector.size(); i++) {
    result_vector[i] = input_vector[i] * scale_factor;
  }
  return result_vector;
}

double ceil_power_of_two(double a_double) {
  std::uint64_t* a_uint = reinterpret_cast<std::uint64_t*>(&a_double);
  assert(std::int64_t(*a_uint) > 0);
  std::uint64_t lambda_mantissa = *a_uint & FLOATINGPOINT_MANTISSA_MASK;
  std::uint64_t a_uint_ceil_power_of_two = 0;
  std::uint64_t lambda_sign = *a_uint & FLOATINGPOINT_SIGN_MASK;

  std::uint64_t lambda_exponent =
      (((*a_uint & FLOATINGPOINT_EXPONENT_MASK) >> FLOATINGPOINT_MANTISSA_BITS) + 1)
      << FLOATINGPOINT_MANTISSA_BITS;
  if (lambda_mantissa == 0) {
    a_uint_ceil_power_of_two = *a_uint;
  } else {
    a_uint_ceil_power_of_two = a_uint_ceil_power_of_two ^ lambda_sign ^ lambda_exponent;
  }

  double* a_double_ceil_power_of_two = reinterpret_cast<double*>(&a_uint_ceil_power_of_two);

  //    std::cout << "*a_double_ceil_power_of_two: " << *a_double_ceil_power_of_two << std::endl;

  return *a_double_ceil_power_of_two;
}

double laplace_distribution(double lambda, double random_floating_point_0_1_rx,
                            double random_floating_point_0_1_ry) {
  return lambda * (log(random_floating_point_0_1_rx) - log(random_floating_point_0_1_ry));
}

std::vector<double> gaussian_distribution_box_muller(double mu, double sigma,
                                                     double random_floating_point_0_1_u1,
                                                     double random_floating_point_0_1_u2) {
  double gaussian_random_variable_x1 = sqrt(-2.0 * std::log(random_floating_point_0_1_u1)) *
                                       cos(2.0 * M_PI * random_floating_point_0_1_u2);
  double gaussian_random_variable_x2 = sqrt(-2.0 * std::log(random_floating_point_0_1_u1)) *
                                       sin(2.0 * M_PI * random_floating_point_0_1_u2);

  std::vector<double> gaussian_random_variable_vector(2);
  gaussian_random_variable_vector[0] = gaussian_random_variable_x1 * sigma + mu;
  gaussian_random_variable_vector[1] = gaussian_random_variable_x2 * sigma + mu;

  return gaussian_random_variable_vector;
}

double discrete_laplace_distribution(double lambda, double random_floating_point_0_1_rx,
                                     double random_floating_point_0_1_ry) {
  double alpha = 1 / log(lambda);
  return floor(alpha * (log(random_floating_point_0_1_rx)) -
               floor(alpha * log(random_floating_point_0_1_ry)));
}

void test_dp_mechanism_helper() {
  std::srand(time(nullptr));

  //    double min = -std::exp2(FIXEDPOINT_FRACTION_BITS);
  double min = 0;
  //    double max = std::exp2(FIXEDPOINT_INTEGER_BITS);
  double max = 100000000;
  std::size_t num_of_values = 500;

  std::vector<double> a_double_vector = rand_range_double_vector(min, max, num_of_values);
  std::vector<double> b_double_vector = rand_range_double_vector(min, max, num_of_values);

  for (std::size_t i = 0; i < num_of_values; i++) {
    double expect_c;
    double a_double_tmp;
    double b_double_tmp;
    std::cout << std::endl;

    // =========================

    a_double_tmp = a_double_vector[i];
    double numerator = decimalToFraction(a_double_tmp)[0];
    double denominator = decimalToFraction(a_double_tmp)[1];
    std::cout << "numerator: " << numerator << std::endl;
    std::cout << "denominator: " << denominator << std::endl;
    std::cout << "a_double_tmp: " << a_double_tmp << std::endl;
    std::cout << "numerator/denominator: " << numerator / denominator << std::endl;
    if (numerator >= std::exp2(64) || denominator >= std::exp2(64)) {
      std::cout << "decimalToFraction failed: " << std::endl;
      break;
    }
  }
}