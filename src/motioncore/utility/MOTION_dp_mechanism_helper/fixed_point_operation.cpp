//
// Created by liangzhao on 13.05.22.
//

#include "fixed_point_operation.h"
#include <bitset>
#include "snapping_mechanism.h"

// T: std::uint8_t, std::uint16_t, std::uint32_t, std::uint64_t, __uint128_t,
template <typename T>
FixedPointStruct<T> CreateFixedPointStruct(double fixed_point, std::size_t k, std::size_t f) {
  FixedPointStruct<T> fixed_point_struct;

  if (fixed_point < 0) {
    fixed_point_struct.v = -T(-fixed_point * (pow(2, f)));
  } else {
    fixed_point_struct.v = T(fixed_point * (pow(2, f)));
  }
  //    std::cout<<"fixed_point * (1 << f): "<<fixed_point * (1 << f)<<std::endl;
  //    print_u128_u("fixed_point_struct.v: ", __int128_t(fixed_point_struct.v));
  //    double mantissa;
  //    int exponent;
  //    mantissa = std::frexp(std::abs(fixed_point), &exponent);
  //    T v = mantissa *

  fixed_point_struct.k = k;
  fixed_point_struct.f = f;

  return fixed_point_struct;
}

template FixedPointStruct<std::uint64_t> CreateFixedPointStruct<std::uint64_t>(double fixed_point,
                                                                               std::size_t k,
                                                                               std::size_t f);

template FixedPointStruct<__uint128_t> CreateFixedPointStruct<__uint128_t>(double fixed_point,
                                                                           std::size_t k,
                                                                           std::size_t f);

template <typename T>
FixedPointVectorStruct<T> CreateFixedPointVectorStruct(double fixed_point, std::size_t k,
                                                       std::size_t f, std::size_t vector_size) {
  FixedPointVectorStruct<T> fixed_point_vector_struct;
  fixed_point_vector_struct.v_vector.reserve(vector_size);
  T fixed_point_T;
  if (fixed_point < 0) {
    fixed_point_T = -T(-fixed_point * (pow(2, f)));
  } else {
    fixed_point_T = T(fixed_point * (pow(2, f)));
  }

  //   print_u128_u("fixed_point_T: ", fixed_point_T);
  //   std::cout << "std::int64_t(fixed_point_T) = " << std::int64_t(fixed_point_T) << std::endl;

  for (std::size_t i = 0; i < vector_size; ++i) {
    fixed_point_vector_struct.v_vector.emplace_back(fixed_point_T);
    // print_u128_u("fixed_point_vector_struct.v_vector ", fixed_point_vector_struct.v_vector[i]);
  }

  fixed_point_vector_struct.k = k;
  fixed_point_vector_struct.f = f;

  return fixed_point_vector_struct;
}

template FixedPointVectorStruct<std::uint64_t> CreateFixedPointVectorStruct<std::uint64_t>(
    double fixed_point, std::size_t k, std::size_t f, std::size_t vector_size);

template FixedPointVectorStruct<__uint128_t> CreateFixedPointVectorStruct<__uint128_t>(
    double fixed_point, std::size_t k, std::size_t f, std::size_t vector_size);

template <typename T>
FixedPointVectorStruct<T> CreateFixedPointVectorStruct(
    const std::vector<double>& fixed_point_vector, std::size_t k, std::size_t f) {
  std::size_t vector_size = fixed_point_vector.size();
  FixedPointVectorStruct<T> fixed_point_vector_struct;
  fixed_point_vector_struct.v_vector.reserve(vector_size);

  for (std::size_t i = 0; i < vector_size; i++) {
    if (fixed_point_vector[i] < 0) {
      fixed_point_vector_struct.v_vector.emplace_back(-T(-fixed_point_vector[i] * (pow(2, f))));
    } else {
      fixed_point_vector_struct.v_vector.emplace_back(T(fixed_point_vector[i] * (pow(2, f))));
    }
  }
  fixed_point_vector_struct.k = k;
  fixed_point_vector_struct.f = f;

  return fixed_point_vector_struct;
}

template FixedPointVectorStruct<std::uint64_t> CreateFixedPointVectorStruct<std::uint64_t>(
    const std::vector<double>& fixed_point_vector, std::size_t k, std::size_t f);

template FixedPointVectorStruct<__uint128_t> CreateFixedPointVectorStruct<__uint128_t>(
    const std::vector<double>& fixed_point_vector, std::size_t k, std::size_t f);

template <typename T>
void double_to_integer(const double coeff[], std::size_t coeff_size, std::size_t k, std::size_t f) {
  T fixed_point_array[coeff_size];
  for (std::size_t i = 0; i < coeff_size; i++) {
    if (coeff[i] < 0) {
      fixed_point_array[i] = -(T)(-coeff[i] * (pow(2, f)));
    } else {
      fixed_point_array[i] = (T)(coeff[i] * (pow(2, f)));
    }
  }
  for (std::size_t i = 0; i < coeff_size; i++) {
    std::cout << "i: ";
    print_u128_u(fixed_point_array[i]);
  }
}

template void double_to_integer<std::uint64_t>(const double coeff[], std::size_t coeff_size,
                                               std::size_t k, std::size_t f);

template void double_to_integer<__uint128_t>(const double coeff[], std::size_t coeff_size,
                                             std::size_t k, std::size_t f);

template <typename T>
FixedPointStruct<T> CreateFixedPointStruct(T fixed_point_mantissa, std::size_t k, std::size_t f) {
  FixedPointStruct<T> fixed_point;
  fixed_point.v = fixed_point_mantissa;
  fixed_point.k = k;
  fixed_point.f = f;
  return fixed_point;
}

template FixedPointStruct<std::uint64_t> CreateFixedPointStruct<std::uint64_t>(
    std::uint64_t fixed_point_mantissa, std::size_t k, std::size_t f);

template FixedPointStruct<__uint128_t> CreateFixedPointStruct<__uint128_t>(
    __uint128_t fixed_point_mantissa, std::size_t k, std::size_t f);

template <typename T>
FixedPointVectorStruct<T> CreateFixedPointVectorStruct(T fixed_point_mantissa, std::size_t k,
                                                       std::size_t f, std::size_t vector_size) {
  FixedPointVectorStruct<T> fixed_point;

  std::vector<T> fixed_point_mantissa_vector(vector_size, fixed_point_mantissa);

  fixed_point.v_vector = fixed_point_mantissa_vector;
  fixed_point.k = k;
  fixed_point.f = f;
  return fixed_point;
}

template FixedPointVectorStruct<std::uint64_t> CreateFixedPointVectorStruct<std::uint64_t>(
    std::uint64_t fixed_point_mantissa, std::size_t k, std::size_t f, std::size_t vector_size);

template FixedPointVectorStruct<__uint128_t> CreateFixedPointVectorStruct<__uint128_t>(
    __uint128_t fixed_point_mantissa, std::size_t k, std::size_t f, std::size_t vector_size);

template <typename T>
FixedPointVectorStruct<T> CreateFixedPointVectorStruct(
    const std::vector<T>& fixed_point_mantissa_vector, std::size_t k, std::size_t f) {
  FixedPointVectorStruct<T> fixed_point;

  fixed_point.v_vector = fixed_point_mantissa_vector;
  fixed_point.k = k;
  fixed_point.f = f;
  return fixed_point;
}

template FixedPointVectorStruct<std::uint64_t> CreateFixedPointVectorStruct<std::uint64_t>(
    const std::vector<std::uint64_t>& fixed_point_mantissa_vector, std::size_t k, std::size_t f);

template FixedPointVectorStruct<__uint128_t> CreateFixedPointVectorStruct<__uint128_t>(
    const std::vector<__uint128_t>& fixed_point_mantissa_vector, std::size_t k, std::size_t f);

template <typename T, typename T_int>
double FixedPointToDouble(FixedPointStruct<T> fixed_point_struct) {
  double result;
  result = double(T_int(fixed_point_struct.v)) / double(1 << fixed_point_struct.f);

  //    print_u128_u("T_int(fixed_point_struct.v): ", T_int(fixed_point_struct.v));
  return result;
}

template double FixedPointToDouble<std::uint64_t, std::int64_t>(
    FixedPointStruct<std::uint64_t> fixed_point_struct);

template double FixedPointToDouble<__uint128_t, __int128_t>(
    FixedPointStruct<__uint128_t> fixed_point_struct);

// ! double division may get rounded result when the operator are too larger (around 2^(64))
template <typename T, typename T_int>
double FixedPointToDouble(T fixed_point, std::size_t k, std::size_t f) {
  double result;
  result = double(T_int(fixed_point)) / double(1 << f);

  //    print_u128_u("T_int(fixed_point_struct.v): ", T_int(fixed_point));
  //    std::cout << "result: " << result << std::endl;
  return result;
}

template double FixedPointToDouble<std::uint64_t, std::int64_t>(std::uint64_t fixed_point,
                                                                std::size_t k, std::size_t f);

template double FixedPointToDouble<__uint128_t, __int128_t>(__uint128_t fixed_point, std::size_t k,
                                                            std::size_t f);

// template <typename T, typename T_int, typename A>
// std::vector<double> FixedPointToDouble(std::vector<FixedPointStruct<T>, A> fixed_point_struct) {
//   std::size_t result_vector_size = fixed_point_struct.size();
//   std::vector<double> result_vector;
//   result_vector.reserve(result_vector_size);
//   for (std::size_t i = 0; i < result_vector_size; i++) {
//     result_vector.template emplace_back(FixedPointToDouble<T, T_int>(fixed_point_struct[i]));
//   }
//   return result_vector;
// }
//
// template std::vector<double>
// FixedPointToDouble<__uint64_t, __int64_t, std::allocator<FixedPointStruct<__uint64_t>>>(
//     std::vector<FixedPointStruct<__uint64_t>, std::allocator<FixedPointStruct<__uint64_t>>>
//         fixed_point_struct);
//
// template std::vector<double>
// FixedPointToDouble<__uint128_t, __int128_t, std::allocator<FixedPointStruct<__uint128_t>>>(
//     std::vector<FixedPointStruct<__uint128_t>, std::allocator<FixedPointStruct<__uint128_t>>>
//         fixed_point_struct);

template <typename T, typename T_int, typename A>
std::vector<double> FixedPointToDouble(std::vector<T, A> fixed_point_mantissa_vector, std::size_t k,
                                       std::size_t f) {
  std::size_t result_vector_size = fixed_point_mantissa_vector.size();
  std::vector<double> result_vector;
  result_vector.reserve(result_vector_size);
  for (std::size_t i = 0; i < result_vector_size; i++) {
    result_vector.template emplace_back(
        FixedPointToDouble<T, T_int>(fixed_point_mantissa_vector[i], k, f));
  }
  return result_vector;
}

template std::vector<double> FixedPointToDouble<__uint64_t, __int64_t, std::allocator<__uint64_t>>(
    std::vector<__uint64_t, std::allocator<__uint64_t>> fixed_point_mantissa_vector, std::size_t k,
    std::size_t f);

template std::vector<double>
FixedPointToDouble<__uint128_t, __int128_t, std::allocator<__uint128_t>>(
    std::vector<__uint128_t, std::allocator<__uint128_t>> fixed_point_mantissa_vector,
    std::size_t k, std::size_t f);

template <typename T>
FixedPointStruct<T> FixedPointAddition(FixedPointStruct<T>& fixed_point_a,
                                       FixedPointStruct<T>& fixed_point_b) {
  FixedPointStruct<T> fixed_point_struct;
  fixed_point_struct.v = fixed_point_a.v + fixed_point_b.v;
  fixed_point_struct.k = fixed_point_a.k;
  fixed_point_struct.f = fixed_point_a.f;

  return fixed_point_struct;
}

template FixedPointStruct<std::uint64_t> FixedPointAddition(
    FixedPointStruct<std::uint64_t>& fixed_point_a, FixedPointStruct<std::uint64_t>& fixed_point_b);

template FixedPointStruct<__uint128_t> FixedPointAddition(
    FixedPointStruct<__uint128_t>& fixed_point_a, FixedPointStruct<__uint128_t>& fixed_point_b);

template <typename T>
FixedPointStruct<T> FixedPointSubtraction(FixedPointStruct<T>& fixed_point_a,
                                          FixedPointStruct<T>& fixed_point_b) {
  FixedPointStruct<T> fixed_point_struct;
  fixed_point_struct.v = fixed_point_a.v - fixed_point_b.v;
  fixed_point_struct.k = fixed_point_a.k;
  fixed_point_struct.f = fixed_point_a.f;

  return fixed_point_struct;
}

template FixedPointStruct<std::uint64_t> FixedPointSubtraction(
    FixedPointStruct<std::uint64_t>& fixed_point_a, FixedPointStruct<std::uint64_t>& fixed_point_b);

template FixedPointStruct<__uint128_t> FixedPointSubtraction(
    FixedPointStruct<__uint128_t>& fixed_point_a, FixedPointStruct<__uint128_t>& fixed_point_b);

template <typename T, typename T_int>
FixedPointStruct<T> FixedPointMultiplication(FixedPointStruct<T>& fixed_point_a,
                                             FixedPointStruct<T>& fixed_point_b) {
  FixedPointStruct<T> fixed_point_struct;
  fixed_point_struct.v = T_int(fixed_point_a.v * fixed_point_b.v) >> (fixed_point_a.f);
  fixed_point_struct.k = fixed_point_a.k;
  fixed_point_struct.f = fixed_point_a.f;

  return fixed_point_struct;
}

template FixedPointStruct<std::uint64_t> FixedPointMultiplication<std::uint64_t, std::int64_t>(
    FixedPointStruct<std::uint64_t>& fixed_point_a, FixedPointStruct<std::uint64_t>& fixed_point_b);

template FixedPointStruct<__uint128_t> FixedPointMultiplication<__uint128_t, __int128_t>(
    FixedPointStruct<__uint128_t>& fixed_point_a, FixedPointStruct<__uint128_t>& fixed_point_b);

template <typename T, typename T_int>
FixedPointStruct<T> FixedPointDivisionSimple(FixedPointStruct<T>& fixed_point_a,
                                             FixedPointStruct<T>& fixed_point_b) {
  //    double inverse_b = double(T_int(fixed_point_a.v)) / double(1 << fixed_point_a.f);
  double inverse_b = 1 / FixedPointToDouble<T, T_int>(fixed_point_b);
  FixedPointStruct<T> fixed_point_inverse_b =
      CreateFixedPointStruct<T>(inverse_b, fixed_point_a.k, fixed_point_a.f);
  FixedPointStruct<T> fixed_point_struct =
      FixedPointMultiplication<T, T_int>(fixed_point_a, fixed_point_inverse_b);

  return fixed_point_struct;
}

template FixedPointStruct<std::uint64_t> FixedPointDivisionSimple<std::uint64_t, std::int64_t>(
    FixedPointStruct<std::uint64_t>& fixed_point_a, FixedPointStruct<std::uint64_t>& fixed_point_b);

template FixedPointStruct<__uint128_t> FixedPointDivisionSimple<__uint128_t, __int128_t>(
    FixedPointStruct<__uint128_t>& fixed_point_a, FixedPointStruct<__uint128_t>& fixed_point_b);

template <typename T, typename T_int, typename A>
FixedPointStruct<T> FixedPointDivision(FixedPointStruct<T>& fixed_point_a,
                                       FixedPointStruct<T>& fixed_point_b) {
  std::size_t k = fixed_point_a.k;
  std::size_t f = fixed_point_a.f;
  std::size_t theta = ceil(log2(double(k) / 3.5));
  std::cout << "ceil(log2(double(k) / 3.5)): " << ceil(log2(double(k) / 3.5)) << std::endl;

  T alpha = T(pow(2, 2 * f));
  print_u128_u("alpha: ", alpha);
  T b = fixed_point_b.v;
  T w = FixedPointAppRcr<T, T_int, A>(b, k, f);

  print_u128_u("b: ", b);
  std::cout << "b_double: " << FixedPointToDouble<T, T_int>(b) << std::endl;
  print_u128_u("w: ", w);
  std::cout << "w_double: " << FixedPointToDouble<T, T_int>(w) << std::endl;
  //

  T x = alpha - b * w;

  T a = fixed_point_a.v;
  T y = a * w;

  T y_prime = T_int(y) >> f;
  std::cout << "y_prime: " << FixedPointToDouble<T, T_int>(y_prime, k, f) << std::endl;

  T x_prime = x;

  for (std::size_t i = 1; i < theta; i++) {
    y_prime = y_prime * (alpha + x_prime);
    x_prime = x_prime * x_prime;
    y_prime = T_int(y_prime) >> (2 * f);
    std::cout << "y_prime: " << FixedPointToDouble<T, T_int>(y_prime, k, f) << std::endl;
    x_prime = T_int(x_prime) >> (2 * f);
  }
  T y_prime_prime = y_prime * (alpha + x_prime);
  T y_prime_prime_prime = T_int(y_prime_prime) >> (2 * f);
  print_u128_u("y_prime_prime_prime: ", y_prime_prime_prime);

  FixedPointStruct<T> result;
  result.v = y_prime_prime_prime;
  result.k = fixed_point_a.k;
  result.f = fixed_point_a.f;
  return result;
}

template FixedPointStruct<__uint128_t>
FixedPointDivision<__uint128_t, __int128_t, std::allocator<__uint128_t>>(
    FixedPointStruct<__uint128_t>& fixed_point_a, FixedPointStruct<__uint128_t>& fixed_point_b);

template <typename T>
T FixedPointLessThan(FixedPointStruct<T>& fixed_point_a, FixedPointStruct<T>& fixed_point_b) {}

template <typename T>
T FixedPointEqual(FixedPointStruct<T>& fixed_point_a, FixedPointStruct<T>& fixed_point_b) {}

template <typename T>
T FixedPointEQZ(FixedPointStruct<T>& fixed_point_a) {}

template <typename T>
T FixedPointLTZ(FixedPointStruct<T>& fixed_point_a) {}

template <typename T>
T FixedPointAbs(FixedPointStruct<T>& fixed_point_a) {}

template <typename T>
T FixedPointFloor(FixedPointStruct<T>& fixed_point_a) {}

template <typename T>
FixedPointStruct<T> FixedPointNegation(FixedPointStruct<T>& fixed_point_a) {}

template <typename T>
T Pow2(T a, std::size_t k) {
  std::size_t m = ceil(log2(k));
  std::bitset<sizeof(T) * 8> bit_set_a(a);

  T v[m];
  for (std::size_t i = 0; i < m; i++) {
    v[i] = (T(1) << (T(1) << i)) * bit_set_a[i] + 1 - bit_set_a[i];
  }

  T pow2_a = v[0];
  for (std::size_t i = 1; i < m; i++) {
    pow2_a = pow2_a * v[i];
  }
  return pow2_a;
}

template __uint128_t Pow2<__uint128_t>(__uint128_t a, std::size_t k);

template <typename T, typename T_int, typename A>
T FixedPointAppRcr(T b, std::size_t k, std::size_t f) {
  double alpha = 2.9142;
  //    FixedPointStruct<T> fixed_point_alpha = CreateFixedPointStruct<T>(alpha, k, f);

  // std::cout<<"(k): "<<(k)<<std::endl;
  // std::cout<<"(1 << 41): "<<(pow(2,k))<<std::endl;
  T alpha_T = T(alpha * (pow(2, k)));
  //    std::cout << "alpha * (pow(2, k)): " << alpha * (pow(2, k)) << std::endl;
  //    print_u128_u("alpha_T: ", alpha_T);

  std::vector<T, A> c_v_vector = FixedPointNorm<T, T_int, A>(b, k, f);
  T c = c_v_vector[0];
  T v = c_v_vector[1];
  T d = alpha_T - T(2) * c;
  std::cout << "alpha_T - T(2) * c: " << FixedPointToDouble<T, T_int>(T_int(d) >> (k - f), k, f)
            << std::endl;

  print_u128_u("c: ", c);
  print_u128_u("v: ", v);
  print_u128_u("d: ", d);

  T w = d * v;
  print_u128_u("w: ", w);
  std::cout << "w_double: " << FixedPointToDouble<T, T_int>(T_int(w) >> (k - f), k, f) << std::endl;

  // truncation may lead to wrong result, e.g., for b= 262144
  // TODO: improve alpha accuracy
  T w_prime = (T_int(w)) >> (2 * (k - f));
  // T w_prime = ((w)) >> (2 * (k - f));
  print_u128_u("w_prime: ", w_prime);

  return w_prime;
}

template __uint128_t FixedPointAppRcr<__uint128_t, __int128_t, std::allocator<__uint128_t>>(
    __uint128_t b, std::size_t k, std::size_t f);

template <typename T, typename T_int, typename A>
T FixedPointAppRcr_opt(T x, std::size_t k, std::size_t f) {
  double b_coe = 1.466;
  double d_coe = 1.0012;

  T b_coe_T = T(b_coe * (pow(2, k)));
  T d_coe_T = T(d_coe * (pow(2, k)));

  std::vector<T, A> c_v_vector = FixedPointNorm<T, T_int, A>(x, k, f);
  T a = c_v_vector[0];
  T v = c_v_vector[1];
  T b = b_coe_T - a;
  T c = T_int((b_coe_T - a) * a) >> k;
  T d = d_coe_T - c;
  T e = T_int(d * b) >> k;
  T ee = e * 4;

  print_u128_u("c: ", c);
  print_u128_u("v: ", v);
  print_u128_u("d: ", d);

  T w = ee * v;
  print_u128_u("w: ", w);
  std::cout << "w_double: " << FixedPointToDouble<T, T_int>(T_int(w) >> (k - f), k, f) << std::endl;

  // truncation may lead to wrong result, e.g., for b= 262144
  // TODO: improve alpha accuracy
  T w_prime = T_int(w) >> (2 * (k - f));
  print_u128_u("w_prime: ", w_prime);

  return w_prime;
}

template __uint128_t FixedPointAppRcr_opt<__uint128_t, __int128_t, std::allocator<__uint128_t>>(
    __uint128_t b, std::size_t k, std::size_t f);

template <typename T, typename T_int, typename A>
std::vector<T, A> FixedPointNorm(T b, std::size_t k, std::size_t f) {
  T s = 1 - 2 * (T_int(b) < 0);
  print_u128_u("s: ", s);

  // T s = (b & (T(1) << (k - 1))) >>(k-1);
  // print_u128_u("s: ", s);

  T x = s * b;

  std::bitset<sizeof(T) * 8> bit_set_x(x);
  std::vector<bool> y(k);

  y[k - 1] = bit_set_x[k - 1];
  for (std::size_t i = 1; i < k; i++) {
    y[k - 1 - i] = y[k - i] | bit_set_x[k - 1 - i];
  }

  std::cout << std::endl;

  std::vector<bool> z(k);
  for (std::size_t i = 0; i <= k - 2; i++) {
    z[i] = y[i] ^ y[i + 1];
  }
  z[k - 1] = y[k - 1];

  std::cout << std::endl;
  std::cout << "z[i]: ";
  for (std::size_t i = 0; i < k; i++) {
    std::cout << z[i];
  }
  std::cout << std::endl;

  T v = 0;
  for (std::size_t i = 0; i < k; i++) {
    v = v + (T(1) << T(k - i - 1)) * T(z[i]);
  }

  print_u128_u("v: ", v);

  //    print_u128_u("v: ", v);

  T c = x * v;
  T v_prime = s * v;
  //    print_u128_u("v_prime: ", v_prime);
  std::vector<T, A> result;
  result.template emplace_back(c);
  result.template emplace_back(v_prime);

  print_u128_u("c: ", c);
  print_u128_u("v_prime: ", v_prime);

  return result;
}

template std::vector<__uint128_t, std::allocator<__uint128_t>>
FixedPointNorm<__uint128_t, __int128_t, std::allocator<__uint128_t>>(__uint128_t b, std::size_t k,
                                                                     std::size_t f);

// assume b >= 0
template <typename T, typename A>
std::vector<T, A> FixedPointNormSQ(T b, std::size_t k, std::size_t f) {
  std::bitset<sizeof(T) * 8> bit_set_x(b);
  std::vector<bool> y(k);

  y[k - 1] = bit_set_x[k - 1];
  for (std::size_t i = 1; i < k; i++) {
    y[k - 1 - i] = y[k - i] | bit_set_x[k - 1 - i];
  }

  std::cout << std::endl;

  std::size_t w_array_size = ceil(double(k) / 2) + 1;
  std::vector<bool> z(2 * (w_array_size - 1) + 1);
  for (std::size_t i = 0; i < (2 * (w_array_size - 1) + 1); i++) {
    z[i] = 0;
  }

  //   std::vector<bool> z(k);
  for (std::size_t i = 0; i <= k - 2; i++) {
    z[i] = y[i] ^ y[i + 1];
  }
  z[k - 1] = y[k - 1];

  std::cout << "z[i]: ";
  for (std::size_t i = 0; i <= k - 2; i++) {
    std::cout << z[i];
  }
  std::cout << std::endl;

  T v = 0;
  for (std::size_t i = 0; i < k; i++) {
    v = v + (T(1) << T(k - i - 1)) * T(z[i]);
  }

  // ==========

  T c = b * v;

  T m = 0;
  for (std::size_t i = 0; i < k; i++) {
    m = m + T(i + 1) * T(z[i]);
  }

  //   std::size_t w_array_size = ceil(double(k) / 2) + 1;
  std::vector<bool> w_array(w_array_size);
  w_array[0] = false;
  for (std::size_t i = 1; i < w_array_size; i++) {
    w_array[i] = z[2 * i - 1] ^ z[2 * i];

    // std::cout << "i: " << i;
    // std::cout << "z[2 * i]: " << z[2 * i];
    // std::cout << std::endl;
  }

  std::cout << "z[2 * 21]: " << z[2 * 21] << std::endl;
  std::cout << "z.size(): " << z.size() << std::endl;

  T w = 0;
  for (std::size_t i = 1; i < w_array_size; i++) {
    w = w + (T(1) << i) * T(w_array[i]);
  }

  std::vector<T, A> result;
  result.template emplace_back(c);
  result.template emplace_back(v);
  result.template emplace_back(m);
  result.template emplace_back(w);
  return result;
}

template std::vector<__uint128_t, std::allocator<__uint128_t>>
FixedPointNormSQ<__uint128_t, std::allocator<__uint128_t>>(__uint128_t b, std::size_t k,
                                                           std::size_t f);

template <typename T, typename A>
std::vector<T, A> FixedPointSimplifiedNormSQ(T b, std::size_t k, std::size_t f) {
  std::bitset<sizeof(T) * 8> bit_set_x(b);
  std::vector<bool> y(k);

  y[k - 1] = bit_set_x[k - 1];
  for (std::size_t i = 1; i < k; i++) {
    y[k - 1 - i] = y[k - i] | bit_set_x[k - 1 - i];
  }

  std::cout << std::endl;

  std::vector<bool> z(k);
  for (std::size_t i = 0; i <= k - 2; i++) {
    z[i] = y[i] ^ y[i + 1];
  }
  z[k - 1] = y[k - 1];

  //    std::cout << "z[i]: ";
  //    for (std::size_t i = 0; i <= k - 2; i++) {
  //        std::cout << z[i];
  //    }
  //    std::cout << std::endl;

  //    T v = 0;
  //    for (std::size_t i = 0; i < k; i++) {
  //        v = v + (T(1) << T(k - i - 1)) * T(z[i]);
  //    }

  // ==========

  //    T c = b * v;

  T m = 0;
  for (std::size_t i = 0; i < k; i++) {
    m = m + T(i + 1) * T(z[i]);
  }

  bool m_odd;
  for (std::size_t i = 0; i < k; i++) {
    if (i % 2 == 0) {
      m_odd = m_odd ^ z[i];
    }
  }

  std::size_t w_array_size = ceil(double(k) / 2) + 1;
  std::vector<bool> w_array(w_array_size);
  w_array[0] = false;
  for (std::size_t i = 1; i < w_array_size; i++) {
    w_array[i] = z[2 * i - 1] ^ z[2 * i];
  }

  T w = 0;
  for (std::size_t i = 1; i < w_array_size; i++) {
    w = w + (T(1) << i) * T(w_array[i]);
  }

  std::vector<T, A> result;
  result.template emplace_back(m_odd);
  result.template emplace_back(w);
  return result;
}

template std::vector<__uint128_t, std::allocator<__uint128_t>>
FixedPointSimplifiedNormSQ<__uint128_t, std::allocator<__uint128_t>>(__uint128_t b, std::size_t k,
                                                                     std::size_t f);

template <typename T>
// assumes abs(a) <= 2^(k-f)
FixedPointStruct<T> FixedPointInt2Fx(T a, std::size_t k, std::size_t f) {
  FixedPointStruct<T> fixed_point = CreateFixedPointStruct<T>(a * (T(1) << f), k, f);
  return fixed_point;
}

template <typename T, typename T_int>
T FixedPointFx2Int(FixedPointStruct<T>& fixed_point_a) {
  T integer_result = T_int(fixed_point_a.v) >> (fixed_point_a.f);
  return integer_result;
}

template __uint128_t FixedPointFx2Int<__uint128_t, __int128_t>(
    FixedPointStruct<__uint128_t>& fixed_point_a);

template <typename T>
FloatingPointStruct<T> FixedPointToFloatingPoint(FixedPointStruct<T>& fixed_point_a) {}

template <typename T, typename T_int, typename A>
FixedPointStruct<T> FixedPointParamFxSqrt(T x, std::size_t k, std::size_t f) {
  std::size_t theta = ceil(log2(k / 5.4));

  std::cout << "theta: " << theta << std::endl;

  T y0 = FixedPointLinAppSQ<T, T_int, A>(x, k, f);
  double scale_factor = 1.0 / (pow(2.0, f));

  FixedPointStruct<T> constant_fixed_point_two = CreateFixedPointStruct<T>(2.0, k, f);

  FixedPointStruct<T> fixed_point_x0 = CreateFixedPointStruct<T>(x, k, f);
  FixedPointStruct<T> fixed_point_y0 = CreateFixedPointStruct<T>(y0, k, f);

  FixedPointStruct<T> fixed_point_g0 =
      FixedPointMultiplication<T, T_int>(fixed_point_x0, fixed_point_y0);
  FixedPointStruct<T> fixed_point_h0 =
      FixedPointDivisionSimple<T, T_int>(fixed_point_y0, constant_fixed_point_two);

  FixedPointStruct<T> fixed_point_g0h0 =
      FixedPointMultiplication<T, T_int>(fixed_point_g0, fixed_point_h0);

  std::cout << "fixed_point_x0: " << FixedPointToDouble<T, T_int>(fixed_point_x0) << std::endl;
  std::cout << "fixed_point_y0: " << FixedPointToDouble<T, T_int>(fixed_point_y0) << std::endl;
  std::cout << "fixed_point_g0: " << FixedPointToDouble<T, T_int>(fixed_point_g0) << std::endl;
  std::cout << "fixed_point_h0: " << FixedPointToDouble<T, T_int>(fixed_point_h0) << std::endl;
  std::cout << "fixed_point_g0h0: " << FixedPointToDouble<T, T_int>(fixed_point_g0h0) << std::endl;

  FixedPointStruct<T> fixed_point_g = fixed_point_g0;
  FixedPointStruct<T> fixed_point_h = fixed_point_h0;
  FixedPointStruct<T> fixed_point_gh = fixed_point_g0h0;

  FixedPointStruct<T> constant_fixed_point_3_div_2 = CreateFixedPointStruct<T>(1.5, k, f);
  FixedPointStruct<T> constant_fixed_point_3 = CreateFixedPointStruct<T>(3, k, f);

  // note: the following fixed-point multiplication can be optimized by delay the truncation
  for (std::size_t i = 1; i < theta - 2; i++) {
    std::cout << "for loop" << std::endl;

    FixedPointStruct<T> fixed_point_r =
        FixedPointSubtraction<T>(constant_fixed_point_3_div_2, fixed_point_gh);
    fixed_point_g = FixedPointMultiplication<T, T_int>(fixed_point_g, fixed_point_r);
    fixed_point_h = FixedPointMultiplication<T, T_int>(fixed_point_h, fixed_point_r);
    fixed_point_gh = FixedPointMultiplication<T, T_int>(fixed_point_g, fixed_point_h);
  }

  FixedPointStruct<T> fixed_point_r =
      FixedPointSubtraction<T>(constant_fixed_point_3_div_2, fixed_point_gh);
  std::cout << "fixed_point_r: " << FixedPointToDouble<T, T_int>(fixed_point_r) << std::endl;

  FixedPointStruct<T> fixed_point_h_mul_r =
      FixedPointMultiplication<T, T_int>(fixed_point_h, fixed_point_r);
  std::cout << "fixed_point_h_mul_r: " << FixedPointToDouble<T, T_int>(fixed_point_h_mul_r)
            << std::endl;

  FixedPointStruct<T> fixed_point_h_square =
      FixedPointMultiplication<T, T_int>(fixed_point_h_mul_r, fixed_point_h_mul_r);
  std::cout << "fixed_point_h_square: " << FixedPointToDouble<T, T_int>(fixed_point_h_square)
            << std::endl;

  FixedPointStruct<T> fixed_point_H = fixed_point_h_square;
  fixed_point_H.v = fixed_point_H.v * 4;
  std::cout << "fixed_point_H: " << FixedPointToDouble<T, T_int>(fixed_point_H) << std::endl;

  FixedPointStruct<T> fixed_point_H_prime =
      FixedPointMultiplication<T, T_int>(fixed_point_H, fixed_point_x0);
  std::cout << "fixed_point_H_prime: " << FixedPointToDouble<T, T_int>(fixed_point_H_prime)
            << std::endl;

  FixedPointStruct<T> fixed_point_H_prime_prime =
      FixedPointSubtraction<T>(constant_fixed_point_3, fixed_point_H_prime);
  std::cout << "fixed_point_H_prime_prime: "
            << FixedPointToDouble<T, T_int>(fixed_point_H_prime_prime) << std::endl;

  FixedPointStruct<T> fixed_point_H_prime_prime_prime =
      FixedPointMultiplication<T, T_int>(fixed_point_h_mul_r, fixed_point_H_prime_prime);
  std::cout << "fixed_point_H_prime_prime_prime: "
            << FixedPointToDouble<T, T_int>(fixed_point_H_prime_prime_prime) << std::endl;

  fixed_point_g =
      FixedPointMultiplication<T, T_int>(fixed_point_H_prime_prime_prime, fixed_point_x0);

  return fixed_point_g;
}

template FixedPointStruct<__uint128_t>
FixedPointParamFxSqrt<__uint128_t, __int128_t, std::allocator<__uint128_t>>(__uint128_t x,
                                                                            std::size_t k,
                                                                            std::size_t f);

// TODO: this function only works for x <= 2^(31)
template <typename T, typename T_int, typename A>
FixedPointStruct<T> FixedPointSimplifiedFxSqrt(T x, std::size_t k, std::size_t f) {
  std::size_t theta = std::max(int(ceil(log2(k))), 6);
  std::cout << "theta: " << theta << std::endl;

  FixedPointStruct<T> constant_fixed_point_two = CreateFixedPointStruct<T>(2.0, k, f);
  FixedPointStruct<T> constant_fixed_point_one = CreateFixedPointStruct<T>(1.0, k, f);
  FixedPointStruct<T> fixed_point_x0 = CreateFixedPointStruct<T>(x, k, f);

  FixedPointStruct<T> fixed_point_x = CreateFixedPointStruct<T>(x, k, f);
  std::vector<T, A> simplified_norm_SQ = FixedPointSimplifiedNormSQ<T, A>(x, k, f);
  bool m_odd = simplified_norm_SQ[0];
  T w = simplified_norm_SQ[1];
  print_u128_u("m_odd: ", m_odd);
  print_u128_u("w: ", w);

  m_odd = (1 - 2 * m_odd) * (f % 2);
  print_u128_u("m_odd: ", m_odd);

  T w_prime = (2 * w - w) * (1 - m_odd) * (f % 2) + w;
  print_u128_u("w_prime: ", w_prime);
  T w_prime_prime = w_prime * (T(1) << ((f - f % 2) / 2));
  print_u128_u("w_prime_prime: ", w_prime_prime);

  FixedPointStruct<T> fixed_point_w = CreateFixedPointStruct<T>(w_prime_prime, k, f);
  std::cout << "fixed_point_w: " << FixedPointToDouble<T, T_int>(fixed_point_w) << std::endl;

  FixedPointStruct<T> constant_fixed_point_sqrt_2 = CreateFixedPointStruct<T>(pow(2, 0.5), k, f);
  FixedPointStruct<T> w_prime_prime_prime_part_1 =
      FixedPointMultiplication<T, T_int>(constant_fixed_point_sqrt_2, fixed_point_w);
  FixedPointStruct<T> w_prime_prime_prime_part_2 =
      FixedPointSubtraction<T>(w_prime_prime_prime_part_1, fixed_point_w);
  FixedPointStruct<T> fixed_point_w_prime_prime_prime = w_prime_prime_prime_part_2;

  fixed_point_w_prime_prime_prime.v = fixed_point_w_prime_prime_prime.v * m_odd + fixed_point_w.v;

  FixedPointStruct<T> fixed_point_y0 =
      FixedPointDivision<T, T_int>(constant_fixed_point_one, fixed_point_w_prime_prime_prime);

  FixedPointStruct<T> fixed_point_g0 =
      FixedPointMultiplication<T, T_int>(fixed_point_y0, fixed_point_x);

  FixedPointStruct<T> fixed_point_h0 =
      FixedPointDivisionSimple<T, T_int>(fixed_point_y0, constant_fixed_point_two);

  FixedPointStruct<T> fixed_point_g0h0 =
      FixedPointMultiplication<T, T_int>(fixed_point_g0, fixed_point_h0);

  std::cout << "fixed_point_x0: " << FixedPointToDouble<T, T_int>(fixed_point_x0) << std::endl;
  std::cout << "fixed_point_y0: " << FixedPointToDouble<T, T_int>(fixed_point_y0) << std::endl;
  std::cout << "fixed_point_g0: " << FixedPointToDouble<T, T_int>(fixed_point_g0) << std::endl;
  std::cout << "fixed_point_h0: " << FixedPointToDouble<T, T_int>(fixed_point_h0) << std::endl;
  std::cout << "fixed_point_g0h0: " << FixedPointToDouble<T, T_int>(fixed_point_g0h0) << std::endl;

  FixedPointStruct<T> fixed_point_g = fixed_point_g0;
  FixedPointStruct<T> fixed_point_h = fixed_point_h0;
  FixedPointStruct<T> fixed_point_gh = fixed_point_g0h0;

  FixedPointStruct<T> constant_fixed_point_3_div_2 = CreateFixedPointStruct<T>(1.5, k, f);
  FixedPointStruct<T> constant_fixed_point_3 = CreateFixedPointStruct<T>(3, k, f);

  // note: the following fixed-point multiplication can be optimized by delay the truncation
  for (std::size_t i = 1; i < theta - 2; i++) {
    std::cout << "for loop" << std::endl;

    FixedPointStruct<T> fixed_point_r =
        FixedPointSubtraction<T>(constant_fixed_point_3_div_2, fixed_point_gh);
    fixed_point_g = FixedPointMultiplication<T, T_int>(fixed_point_g, fixed_point_r);
    fixed_point_h = FixedPointMultiplication<T, T_int>(fixed_point_h, fixed_point_r);
    fixed_point_gh = FixedPointMultiplication<T, T_int>(fixed_point_g, fixed_point_h);
  }

  FixedPointStruct<T> fixed_point_r =
      FixedPointSubtraction<T>(constant_fixed_point_3_div_2, fixed_point_gh);
  std::cout << "fixed_point_r: " << FixedPointToDouble<T, T_int>(fixed_point_r) << std::endl;

  FixedPointStruct<T> fixed_point_h_mul_r =
      FixedPointMultiplication<T, T_int>(fixed_point_h, fixed_point_r);
  std::cout << "fixed_point_h_mul_r: " << FixedPointToDouble<T, T_int>(fixed_point_h_mul_r)
            << std::endl;

  FixedPointStruct<T> fixed_point_h_square =
      FixedPointMultiplication<T, T_int>(fixed_point_h_mul_r, fixed_point_h_mul_r);
  std::cout << "fixed_point_h_square: " << FixedPointToDouble<T, T_int>(fixed_point_h_square)
            << std::endl;

  FixedPointStruct<T> fixed_point_H = fixed_point_h_square;
  fixed_point_H.v = fixed_point_H.v * 4;
  std::cout << "fixed_point_H: " << FixedPointToDouble<T, T_int>(fixed_point_H) << std::endl;

  FixedPointStruct<T> fixed_point_H_prime =
      FixedPointMultiplication<T, T_int>(fixed_point_H, fixed_point_x0);
  std::cout << "fixed_point_H_prime: " << FixedPointToDouble<T, T_int>(fixed_point_H_prime)
            << std::endl;

  FixedPointStruct<T> fixed_point_H_prime_prime =
      FixedPointSubtraction<T>(constant_fixed_point_3, fixed_point_H_prime);
  std::cout << "fixed_point_H_prime_prime: "
            << FixedPointToDouble<T, T_int>(fixed_point_H_prime_prime) << std::endl;

  FixedPointStruct<T> fixed_point_H_prime_prime_prime =
      FixedPointMultiplication<T, T_int>(fixed_point_h_mul_r, fixed_point_H_prime_prime);
  std::cout << "fixed_point_H_prime_prime_prime: "
            << FixedPointToDouble<T, T_int>(fixed_point_H_prime_prime_prime) << std::endl;

  fixed_point_g =
      FixedPointMultiplication<T, T_int>(fixed_point_H_prime_prime_prime, fixed_point_x0);

  return fixed_point_g;
}

template FixedPointStruct<__uint128_t>
FixedPointSimplifiedFxSqrt<__uint128_t, __int128_t, std::allocator<__uint128_t>>(__uint128_t x,
                                                                                 std::size_t k,
                                                                                 std::size_t f);

template <typename T>
FixedPointStruct<T> FixedPointSqrt(FixedPointStruct<T>& fixed_point_a, std::size_t k,
                                   std::size_t f) {
  //    TODO: further test
  //    if (3 * k - 2 * f > fixed_point_a.f) {
  //        return
  //    } else {
  //
  //    }
}

template <typename T, typename T_int, typename A>
T FixedPointLinAppSQ(T b, std::size_t k, std::size_t f) {
  double constant_1 = -0.8099868542;
  double constant_2 = 1.787727479;

  print_u128_u("b: ", b);

  T alpha = -T(-constant_1 * (pow(2, k)));
  //    T beta = T(constant_2 * (1 << (2*f)));
  T beta = T(constant_2 * (pow(2, 2 * k)));

  //    print_u128_u("alpha: ", alpha);
  //    print_u128_u("beta: ", beta);
  //    print_u128_u("alpha + beta: ", alpha + beta);

  std::vector<T, A> norm_SQ_result = FixedPointNormSQ<T, A>(b, k, f);
  T c = norm_SQ_result[0];
  T v = norm_SQ_result[1];
  T m = norm_SQ_result[2];
  T W = norm_SQ_result[3];

  print_u128_u("c: ", c);
  print_u128_u("v: ", v);
  print_u128_u("m: ", m);
  print_u128_u("W: ", W);

  T w = alpha * c + beta;
  print_u128_u("alpha * c + beta: ", w);

  T m_prime = m % 2;
  print_u128_u("m_prime: ", m_prime);

  T w_mul_v = w * v;
  print_u128_u("w_mul_v: ", w_mul_v);

  //    double factor = 1.0 / (pow(2, (3.0 * k - 2 * f)));
  //    FixedPointStruct<T> fixed_point_factor = CreateFixedPointStruct<T>(factor, k, f);

  // TODO: use FixDiv?, efficiency difference?
  // assumption: T >= 3k
  T w_prime_trunc = T_int(w_mul_v) >> (3 * k - 2 * f);

  // TODO: this requires 3*k - 2*f < f, compare arithmeic shift vs FxDivSimple
  //    FixedPointStruct<T> constant_fixed_point_1_div_3_mul_k_minus_2_mul_f =
  //    CreateFixedPointStruct<T>(1.0 / (pow(2.0, (3.0 * k - 2 * f))), k, f); FixedPointStruct<T>
  //    fixed_point_w_mul_v = CreateFixedPointStruct<T>(w_mul_v, k, f); FixedPointStruct<T>
  //    fixed_point_w_prime_trunc = FixedPointDivisionSimple<T, T_int>(fixed_point_w_mul_v,
  //                                                                                       constant_fixed_point_1_div_3_mul_k_minus_2_mul_f);
  //    T w_prime_trunc=  fixed_point_w_prime_trunc.v;

  print_u128_u("w_prime_trunc: ", w_prime_trunc);

  T w_prime_trunc_mul_W = w_prime_trunc * W;

  print_u128_u("w_prime_trunc_mul_W: ", w_prime_trunc_mul_W);

  FixedPointStruct<T> fixed_point_w_prime_trunc_mul_W =
      CreateFixedPointStruct<T>(w_prime_trunc_mul_W, k, f);

  FixedPointStruct<T> constant_fixed_point_1_div_2_high_f_div_2 =
      CreateFixedPointStruct<T>((pow(2, (f / 2.0))), k, f);

  FixedPointStruct<T> fixed_point_w = FixedPointDivisionSimple<T, T_int>(
      fixed_point_w_prime_trunc_mul_W, constant_fixed_point_1_div_2_high_f_div_2);

  print_u128_u("fixed_point_w.v: ", fixed_point_w.v);

  FixedPointStruct<T> fixed_point_sqrt_2 = CreateFixedPointStruct<T>(pow(2, 0.5), k, f);
  print_u128_u("fixed_point_sqrt_2.v: ", fixed_point_sqrt_2.v);

  T sqrt_2_mul_w = FixedPointMultiplication<T, T_int>(fixed_point_sqrt_2, fixed_point_w).v;
  print_u128_u("sqrt_2_mul_w: ", sqrt_2_mul_w);

  T result = (1 - m_prime) * fixed_point_w.v + m_prime * sqrt_2_mul_w;

  return result;
}

template std::uint64_t
FixedPointLinAppSQ<std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(std::uint64_t b,
                                                                               std::size_t k,
                                                                               std::size_t f);

template __uint128_t FixedPointLinAppSQ<__uint128_t, __int128_t, std::allocator<__uint128_t>>(
    __uint128_t b, std::size_t k, std::size_t f);

// template<typename T, typename T_int, typename A>
// T FixedPointLinAppSQ_optimization_1(T b, std::size_t k, std::size_t f) {
//
//     double constant_alpha = -0.8099868542;
//     double constant_beta = 1.787727479;
//
//     T alpha = -T(-constant_alpha * (pow(2, k)));
//     //    T beta = T(constant_2 * (1 << (2*f)));
//     T beta = T(constant_beta * (pow(2, 2 * k)));
//
//     //    print_u128_u("alpha: ", alpha);
//     //    print_u128_u("beta: ", beta);
//     //    print_u128_u("alpha + beta: ", alpha + beta);
//
//     // std::vector<T, A> norm_SQ_result = FixedPointNormSQ<T, A>(b, k, f);
//     // T c = norm_SQ_result[0];
//     // T v = norm_SQ_result[1];
//     // T m = norm_SQ_result[2];
//     // T W = norm_SQ_result[3];
//
//     FixedPointStruct<T> fixed_point_b = CreateFixedPointStruct<T>(b, k, f);
//
//     std::vector<T, A> floating_point_b = FixedPointFx2FL<T, T, T_int, A>(fixed_point_b, k, f, k -
//     1, k); std::cout << "floating_point_b: " << FloatingPointToDouble<T>(floating_point_b) <<
//     std::endl;
//
//     FixedPointStruct<T> fixed_point_b_norm = CreateFixedPointStruct<T>(floating_point_b[0] >> (k
//     - 1 - f), k, f);
//
//     std::cout << "fixed_point_b_norm: " << FixedPointToDouble<T, T_int>(fixed_point_b_norm) <<
//     std::endl;
//
//     print_u128_u("fixed_point_b_norm.v: ", fixed_point_b_norm.v);
//
//     double b_LinAppSQ = (FixedPointToDouble<T, T_int>(fixed_point_b_norm.v) * constant_alpha +
//     constant_beta);
//
//     std::cout << "b_LinAppSQ: " << b_LinAppSQ << std::endl;
//     FixedPointStruct<T> fixed_point_b_LinAppSQ = CreateFixedPointStruct<T>(b_LinAppSQ, k, f);
//
//     std::cout << "fixed_point_b_LinAppSQ: " << FixedPointToDouble<T,
//     T_int>(fixed_point_b_LinAppSQ) << std::endl;
//
//     T constant_p_plus_k_minus_1 = floating_point_b[1] + (k - 1);
//     T constant_p_plus_k_minus_1_div2 = T_int(constant_p_plus_k_minus_1) >> 1;

// T w = alpha * c + beta;
//    print_u128_u("alpha * c + beta: ", w);

// T m_prime = m % 2;
//    print_u128_u("m_prime: ", m_prime);

// T w_mul_v = w * v;
//    print_u128_u("w_mul_v: ", w_mul_v);

//    double factor = 1.0 / (pow(2, (3.0 * k - 2 * f)));
//    FixedPointStruct<T> fixed_point_factor = CreateFixedPointStruct<T>(factor, k, f);

//    TODO: use FixDiv?, efficiency difference?
// assumption: T >= 3k
// T w_prime_trunc = T_int(w_mul_v) >> (3 * k - 2 * f);

// TODO: this requires 3*k - 2*f < f, compare arithmeic shift vs FxDivSimple
//    FixedPointStruct<T> constant_fixed_point_1_div_3_mul_k_minus_2_mul_f =
//    CreateFixedPointStruct<T>(1.0 / (pow(2.0, (3.0 * k - 2 * f))), k, f); FixedPointStruct<T>
//    fixed_point_w_mul_v = CreateFixedPointStruct<T>(w_mul_v, k, f); FixedPointStruct<T>
//    fixed_point_w_prime_trunc = FixedPointDivisionSimple<T, T_int>(fixed_point_w_mul_v,
//                                                                                       constant_fixed_point_1_div_3_mul_k_minus_2_mul_f);
//    T w_prime_trunc=  fixed_point_w_prime_trunc.v;

//    print_u128_u("w_prime_trunc: ", w_prime_trunc);

// T w_prime_trunc_mul_W = w_prime_trunc * W;
// //    print_u128_u("w_prime_trunc_mul_W: ", w_prime_trunc_mul_W);

// FixedPointStruct<T> fixed_point_w_prime_trunc_mul_W =
// CreateFixedPointStruct<T>(w_prime_trunc_mul_W, k, f);

// FixedPointStruct<T> constant_fixed_point_1_div_2_high_f_div_2 = CreateFixedPointStruct<T>((pow(2,
// (f / 2.0))), k, f);

// FixedPointStruct<T> fixed_point_w = FixedPointDivisionSimple<T,
// T_int>(fixed_point_w_prime_trunc_mul_W,
//                                                                        constant_fixed_point_1_div_2_high_f_div_2);

// //    print_u128_u("fixed_point_w.v: ", fixed_point_w.v);

// FixedPointStruct<T> fixed_point_sqrt_2 = CreateFixedPointStruct<T>(pow(2, 0.5), k, f);
// //    print_u128_u("fixed_point_sqrt_2.v: ", fixed_point_sqrt_2.v);

// T sqrt_2_mul_w = FixedPointMultiplication<T, T_int>(fixed_point_sqrt_2, fixed_point_w).v;
// //    print_u128_u("sqrt_2_mul_w: ", sqrt_2_mul_w);

// T result = (1 - m_prime) * fixed_point_w.v + m_prime * sqrt_2_mul_w;

//    return b;
//}

// template __uint128_t
// FixedPointLinAppSQ_optimization_1<__uint128_t, __int128_t,
// std::allocator<__uint128_t>>(__uint128_t b, std::size_t k, std::size_t f);

template <typename T, typename T_int, typename A>
FixedPointStruct<T> FixedPointExp2P1045(FixedPointStruct<T>& fixed_point_a) {
  std::size_t k = fixed_point_a.k;
  std::size_t f = fixed_point_a.f;

  T a = fixed_point_a.v;
  print_u128_u("a: ", a);
  bool s = T_int(a) < 0;

  std::cout << "s: " << s << std::endl;

  // abs(a)
  T a_prime = (1 - 2 * s) * a;
  print_u128_u("a_prime: ", a_prime);

  // integer part of abs(a)
  T b = T_int(a_prime) >> (fixed_point_a.f);
  print_u128_u("b: ", b);

  FixedPointStruct<T> fixed_point_a_prime = fixed_point_a;
  fixed_point_a_prime.v = a_prime;

  T c = a_prime - b * (T(1) << f);
  FixedPointStruct<T> fixed_point_c = CreateFixedPointStruct<T>(c, k, f);
  std::cout << "fixed_point_c: " << FixedPointToDouble<T, T_int>(fixed_point_c) << std::endl;

  T pow2_b = (T(1) << b);
  std::cout << "pow2_b_double: " << FixedPointToDouble<T, T_int>(pow2_b, k, f) << std::endl;
  FixedPointStruct<T> fixed_point_d = FixedPointInt2Fx<T>(pow2_b, k, f);
  // TODO: FxPol

  FixedPointStruct<T> fixed_point_e = FixedPointPolynomialEvaluation<T, T_int>(
      fixed_point_c, p_1045, sizeof(p_1045) / sizeof(p_1045[0]));
  FixedPointStruct<T> fixed_point_g =
      FixedPointMultiplication<T, T_int>(fixed_point_d, fixed_point_e);
  std::cout << "fixed_point_g: " << FixedPointToDouble<T, T_int>(fixed_point_g) << std::endl;

  FixedPointStruct<T> constant_fixed_point_one = CreateFixedPointStruct<T>(double(1.0), k, f);
  std::cout << "constant_fixed_point_one: "
            << FixedPointToDouble<T, T_int>(constant_fixed_point_one) << std::endl;

  FixedPointStruct<T> fixed_point_g_inverse =
      FixedPointDivision<T, T_int, A>(constant_fixed_point_one, fixed_point_g);
  std::cout << "fixed_point_g_inverse: " << FixedPointToDouble<T, T_int>(fixed_point_g_inverse)
            << std::endl;

  FixedPointStruct<T> fixed_point_exp2_a =
      CreateFixedPointStruct<T>((1 - s) * fixed_point_g.v + s * fixed_point_g_inverse.v, k, f);

  return fixed_point_exp2_a;
}

template FixedPointStruct<__uint128_t>
FixedPointExp2P1045<__uint128_t, __int128_t, std::allocator<__uint128_t>>(
    FixedPointStruct<__uint128_t>& fixed_point_a);

template <typename T, typename T_int>
FixedPointStruct<T> FixedPointPolynomialEvaluation(FixedPointStruct<T>& fixed_point_x,
                                                   const double coefficient[],
                                                   std::size_t array_size) {
  std::size_t k = fixed_point_x.k;
  std::size_t f = fixed_point_x.f;

  FixedPointStruct<T> fixed_point_x_premult = fixed_point_x;
  //    std::cout << "fixed_point_x_premult: " << FixedPointToDouble<T,
  //    T_int>(fixed_point_x_premult) << std::endl;

  FixedPointStruct<T> fixed_point_coefficient = CreateFixedPointStruct<T>(coefficient[0], k, f);
  //    std::cout << "fixed_point_coefficient: " << FixedPointToDouble<T,
  //    T_int>(fixed_point_coefficient) << std::endl;

  FixedPointStruct<T> local_aggregation = fixed_point_coefficient;

  for (std::size_t i = 1; i < array_size; i++) {
    fixed_point_coefficient = CreateFixedPointStruct<T>(coefficient[i], k, f);

    FixedPointStruct<T> fixed_point_coefficient_mul_x =
        FixedPointMultiplication<T, T_int>(fixed_point_coefficient, fixed_point_x_premult);
    //        std::cout << "fixed_point_coefficient_mul_x: " << FixedPointToDouble<T,
    //        T_int>(fixed_point_coefficient_mul_x) << std::endl;

    local_aggregation = FixedPointAddition<T>(local_aggregation, fixed_point_coefficient_mul_x);
    //        std::cout << "local_aggregation: " << FixedPointToDouble<T, T_int>(local_aggregation)
    //        << std::endl;

    // save one multiplication
    if (i != array_size - 1) {
      fixed_point_x_premult =
          FixedPointMultiplication<T, T_int>(fixed_point_x_premult, fixed_point_x);
    }
  }

  return local_aggregation;
}

template FixedPointStruct<__uint128_t> FixedPointPolynomialEvaluation<__uint128_t, __int128_t>(
    FixedPointStruct<__uint128_t>& fixed_point_x, const double coefficient[],
    std::size_t array_size);

template <typename FLType, typename IntType, typename IntType_int, typename A>
std::vector<FLType, A> FixedPointFx2FL(FixedPointStruct<FLType>& fixed_point_g, std::size_t gamma,
                                       std::size_t f, std::size_t l, std::size_t k) {
  std::vector<FLType, A> floating_point_a =
      IntegerToFloatingPoint_ABZS<FLType, IntType, IntType_int, A>(fixed_point_g.v, gamma, l, k);
  FLType v = floating_point_a[0];
  FLType p = floating_point_a[1];
  FLType z = floating_point_a[2];
  FLType s = floating_point_a[3];

  FLType p_prime = (p - f) * (1 - z);

  std::vector<FLType, A> floating_point_result;
  floating_point_result.template emplace_back(v);
  floating_point_result.template emplace_back(p_prime);
  floating_point_result.template emplace_back(z);
  floating_point_result.template emplace_back(s);

  return floating_point_result;
}

template std::vector<__uint128_t, std::allocator<__uint128_t>>
FixedPointFx2FL<__uint128_t, __uint128_t, __int128_t, std::allocator<__uint128_t>>(
    FixedPointStruct<__uint128_t>& fixed_point_g, std::size_t gamma, std::size_t f, std::size_t l,
    std::size_t k);

template <typename FLType, typename FLType_int, typename FxType, typename FxType_int,
          typename IntType, typename IntType_int, typename A>
FixedPointStruct<FxType> FixedPointLog2P2508(FixedPointStruct<FLType>& fixed_point_a) {
  std::size_t k = fixed_point_a.k;
  std::size_t f = fixed_point_a.f;

  std::size_t gamma = FLOATINGPOINT_BITS;
  std::size_t l_floating_point = FLOATINGPOINT_MANTISSA_BITS + 1;
  std::size_t k_floating_point = FLOATINGPOINT_EXPONENT_BITS;

  std::vector<FLType, A> floating_point_a = FixedPointFx2FL<FLType, IntType, IntType_int, A>(
      fixed_point_a, gamma, f, l_floating_point, k_floating_point);
  print_u128_u("floating_point_a.v: ", floating_point_a[0]);
  print_u128_u("floating_point_a.p: ", floating_point_a[1]);
  std::cout << "int(floating_point_a[1]): " << int(floating_point_a[1]) << std::endl;

  //    FixedPointStruct<IntType> fixed_point_v =
  //    CreateFixedPointStruct<IntType>(floating_point_a[0], k, f); std::cout << "fixed_point_v: "
  //    << FixedPointToDouble<IntType, IntType_int>(fixed_point_v) << std::endl;

  //    double costant_pow2_k = pow(2, k - 10);
  //    std::cout << "costant_pow2_k: " << costant_pow2_k << std::endl;
  //    FixedPointStruct<IntType> constant_fixed_point_pow2_k =
  //    CreateFixedPointStruct<IntType>(costant_pow2_k, k, f); std::cout << "constant_fixed_point_k:
  //    " << FixedPointToDouble<IntType, IntType_int>(constant_fixed_point_pow2_k) << std::endl;

  //    FixedPointStruct<IntType> fixed_point_norm_v = FixedPointDivisionSimple<IntType,
  //    IntType_int>(fixed_point_v, constant_fixed_point_pow2_k);
  std::size_t shift_bits = l_floating_point - f;

  FixedPointStruct<FxType> fixed_point_norm_v =
      CreateFixedPointStruct<FxType>(floating_point_a[0] >> (shift_bits), k, f);
  std::cout << "fixed_point_norm_v: " << FixedPointToDouble<FxType, FxType_int>(fixed_point_norm_v)
            << std::endl;

  FixedPointStruct<FxType> fixed_point_poly_P = FixedPointPolynomialEvaluation<FxType, FxType_int>(
      fixed_point_norm_v, p_2508, sizeof(p_2508) / sizeof(p_2508[0]));
  std::cout << "fixed_point_poly_P: " << FixedPointToDouble<FxType, FxType_int>(fixed_point_poly_P)
            << std::endl;

  double p_plus_l = double(FLType_int(floating_point_a[1])) + double(l_floating_point);
  std::cout << "p_plus_l: " << p_plus_l << std::endl;
  FixedPointStruct<FxType> fixed_point_p_plus_l = CreateFixedPointStruct<FxType>(p_plus_l, k, f);
  std::cout << "fixed_point_p_plus_l: "
            << FixedPointToDouble<FxType, FxType_int>(fixed_point_p_plus_l) << std::endl;

  FixedPointStruct<FxType> fixed_point_log2_result =
      FixedPointAddition<FxType>(fixed_point_poly_P, fixed_point_p_plus_l);

  return fixed_point_log2_result;
}

template FixedPointStruct<__uint128_t>
FixedPointLog2P2508<__uint128_t, __int128_t, __uint128_t, __int128_t, std::uint64_t, std::int64_t,
                    std::allocator<__uint128_t>>(FixedPointStruct<__uint128_t>& fixed_point_a);

template <typename FLType, typename IntType, typename IntType_int, typename A>
FixedPointStruct<FLType> FixedPointLog2PQ2524(FixedPointStruct<FLType>& fixed_point_a) {
  std::size_t k = fixed_point_a.k;
  std::size_t f = fixed_point_a.f;

  std::vector<FLType, A> floating_point_a =
      FixedPointFx2FL<FLType, IntType, IntType_int, A>(fixed_point_a, k, f, k - 1, k);
  print_u128_u("floating_point_a.v: ", floating_point_a[0]);
  print_u128_u("floating_point_a.p: ", floating_point_a[1]);
  std::cout << "int(floating_point_a[1]): " << int(floating_point_a[1]) << std::endl;

  //    FixedPointStruct<IntType> fixed_point_v =
  //    CreateFixedPointStruct<IntType>(floating_point_a[0], k, f); std::cout << "fixed_point_v: "
  //    << FixedPointToDouble<IntType, IntType_int>(fixed_point_v) << std::endl;

  //    double costant_pow2_k = pow(2, k - 10);
  //    std::cout << "costant_pow2_k: " << costant_pow2_k << std::endl;
  //    FixedPointStruct<IntType> constant_fixed_point_pow2_k =
  //    CreateFixedPointStruct<IntType>(costant_pow2_k, k, f); std::cout << "constant_fixed_point_k:
  //    " << FixedPointToDouble<IntType, IntType_int>(constant_fixed_point_pow2_k) << std::endl;

  //    FixedPointStruct<IntType> fixed_point_norm_v = FixedPointDivisionSimple<IntType,
  //    IntType_int>(fixed_point_v, constant_fixed_point_pow2_k);
  FixedPointStruct<IntType> fixed_point_norm_v =
      CreateFixedPointStruct<IntType>(floating_point_a[0] >> (k - 1 - f), k, f);
  std::cout << "fixed_point_norm_v: "
            << FixedPointToDouble<IntType, IntType_int>(fixed_point_norm_v) << std::endl;

  FixedPointStruct<IntType> fixed_point_poly_P =
      FixedPointPolynomialEvaluation<IntType, IntType_int>(fixed_point_norm_v, p_2524,
                                                           sizeof(p_2524) / sizeof(p_2524[0]));
  FixedPointStruct<IntType> fixed_point_poly_Q =
      FixedPointPolynomialEvaluation<IntType, IntType_int>(fixed_point_norm_v, q_2524,
                                                           sizeof(q_2524) / sizeof(q_2524[0]));

  FixedPointStruct<IntType> fixed_point_P_div_Q =
      FixedPointDivision<IntType, IntType_int>(fixed_point_poly_P, fixed_point_poly_Q);
  std::cout << "fixed_point_P_div_Q: "
            << FixedPointToDouble<IntType, IntType_int>(fixed_point_P_div_Q) << std::endl;

  double constant_p_plus_k_minus_1 = double(IntType_int(floating_point_a[1])) + double(k - 1);
  FixedPointStruct<IntType> constant_fixed_point_p_plus_k_minus_1 =
      CreateFixedPointStruct<IntType>(constant_p_plus_k_minus_1, k, f);
  std::cout << "constant_p_plus_k_minus_1: "
            << FixedPointToDouble<IntType, IntType_int>(constant_p_plus_k_minus_1) << std::endl;

  FixedPointStruct<IntType> fixed_point_log2_result =
      FixedPointAddition<IntType>(fixed_point_P_div_Q, constant_fixed_point_p_plus_k_minus_1);

  return fixed_point_log2_result;
}

template FixedPointStruct<__uint128_t>
FixedPointLog2PQ2524<__uint128_t, __uint128_t, __int128_t, std::allocator<__uint128_t>>(
    FixedPointStruct<__uint128_t>& fixed_point_a);

template <typename FLType, typename FxType, typename FxType_int, typename IntType,
          typename IntType_int, typename A>
FixedPointStruct<FxType> FixedPointSqrtP0132(FixedPointStruct<FxType>& fixed_point_a) {
  std::size_t k = fixed_point_a.k;
  std::size_t f = fixed_point_a.f;

  std::size_t gamma = FLOATINGPOINT_BITS;
  std::size_t l_floating_point = FLOATINGPOINT_MANTISSA_BITS + 1;
  std::size_t k_floating_point = FLOATINGPOINT_EXPONENT_BITS;

  std::vector<FLType, A> floating_point_a = FixedPointFx2FL<FLType, IntType, IntType_int, A>(
      fixed_point_a, gamma, f, l_floating_point, k_floating_point);
  print_u128_u("floating_point_a.v: ", floating_point_a[0]);
  print_u128_u("floating_point_a.p: ", floating_point_a[1]);
  std::cout << "int(floating_point_a[1]): " << int(floating_point_a[1]) << std::endl;

  //    FixedPointStruct<IntType> fixed_point_norm_v = FixedPointDivisionSimple<IntType,
  //    IntType_int>(fixed_point_v, constant_fixed_point_pow2_k);
  std::size_t shift_bits = l_floating_point - f;

  std::cout << "shift_bits: " << shift_bits << std::endl;
  FixedPointStruct<FxType> fixed_point_norm_v =
      CreateFixedPointStruct<FxType>((floating_point_a[0] >> (shift_bits)), k, f);
  print_u128_u("floating_point_a[0] >> (shift_bits): ", floating_point_a[0] >> (shift_bits));
  print_u128_u("fixed_point_norm_v.v: ", fixed_point_norm_v.v);
  std::cout << "fixed_point_norm_v_double: "
            << FixedPointToDouble<FxType, FxType_int>(fixed_point_norm_v) << std::endl;

  FixedPointStruct<FxType> fixed_point_poly_P = FixedPointPolynomialEvaluation<FxType, FxType_int>(
      fixed_point_norm_v, p_0132, sizeof(p_0132) / sizeof(p_0132[0]));
  std::cout << "fixed_point_poly_P: " << FixedPointToDouble<FxType, FxType_int>(fixed_point_poly_P)
            << std::endl;

  double p_double = double(FxType_int(floating_point_a[1]));
  std::cout << "p_double: " << p_double << std::endl;

  // (2^k)^0.5 = 2^(floor(k/2)) + 2^0.5 if k is odd
  // (2^k)^0.5 = 2^(floor(k/2)) if k is even
  FxType_int shift_bits_plus_f_plus_p =
      FxType_int(shift_bits) + FxType_int(floating_point_a[1]) + f;
  print_u128_u("shift_bits_plus_f_plus_p: ", shift_bits_plus_f_plus_p);

  FxType_int shift_bits_plus_f_plus_p_div_2 = FxType_int(shift_bits_plus_f_plus_p) >> 1;
  // bool k_minus_1_plus_p_div2_is_odd = k_minus_1_plus_p_div_2 & 1;
  bool shift_bits_plus_f_plus_p_is_odd = shift_bits_plus_f_plus_p & 1;
  std::cout << "shift_bits_plus_f_plus_p_is_odd: " << shift_bits_plus_f_plus_p_is_odd << std::endl;
  print_u128_u("shift_bits_plus_f_plus_p_div_2: ", shift_bits_plus_f_plus_p_div_2);

  FxType pow2_shift_bits_plus_f_plus_p_div_2 = Pow2(shift_bits_plus_f_plus_p_div_2, k);
  print_u128_u("pow2_shift_bits_plus_f_plus_p_div_2: ", pow2_shift_bits_plus_f_plus_p_div_2);

  FixedPointStruct<FxType> fixed_point_pow2_shift_bits_plus_f_plus_p_div_2 =
      CreateFixedPointStruct<FxType>(pow2_shift_bits_plus_f_plus_p_div_2 << f, k, f);
  std::cout << "fixed_point_pow2_shift_bits_plus_f_plus_p_div_2_double: "
            << FixedPointToDouble<FxType, FxType_int>(
                   fixed_point_pow2_shift_bits_plus_f_plus_p_div_2)
            << std::endl;
  FixedPointStruct<FxType> fixed_point_pow2_shift_bits_plus_f_plus_p_div_2_final =
      fixed_point_pow2_shift_bits_plus_f_plus_p_div_2;
  fixed_point_pow2_shift_bits_plus_f_plus_p_div_2_final.v =
      FxType_int(fixed_point_pow2_shift_bits_plus_f_plus_p_div_2_final.v *
                 ((FxType(1) << f) +
                  shift_bits_plus_f_plus_p_is_odd * FxType((M_SQRT2 - double(1)) * pow(2, f)))) >>
      f;
  print_u128_u("fixed_point_pow2_shift_bits_plus_f_plus_p_div_2_final.v: ",
               fixed_point_pow2_shift_bits_plus_f_plus_p_div_2_final.v);
  std::cout << "fixed_point_pow2_shift_bits_plus_f_plus_p_div_2_final_double: "
            << FixedPointToDouble<FxType, FxType_int>(
                   fixed_point_pow2_shift_bits_plus_f_plus_p_div_2_final)
            << std::endl;

  FixedPointStruct<FxType> fixed_point_sqrt_result = FixedPointMultiplication<FxType, FxType_int>(
      fixed_point_poly_P, fixed_point_pow2_shift_bits_plus_f_plus_p_div_2_final);

  return fixed_point_sqrt_result;
}

template FixedPointStruct<__uint128_t>
FixedPointSqrtP0132<__uint128_t, __uint128_t, __int128_t, std::uint64_t, std::int64_t,
                    std::allocator<__uint128_t>>(FixedPointStruct<__uint128_t>& fixed_point_a);

// template FixedPointStruct<__uint128_t>
// FixedPointSqrtP0132<__uint128_t, __uint128_t, __int128_t,
// std::allocator<__uint128_t>>(FixedPointStruct<__uint128_t> &fixed_point_a);

template <typename FLType, typename IntType, typename IntType_int, typename A>
FixedPointStruct<FLType> FixedPointSqrtPQ0371(FixedPointStruct<FLType>& fixed_point_a) {
  std::size_t k = fixed_point_a.k;
  std::size_t f = fixed_point_a.f;

  std::vector<FLType, A> floating_point_a =
      FixedPointFx2FL<FLType, IntType, IntType_int, A>(fixed_point_a, k, f, k - 1, k);
  print_u128_u("floating_point_a.v: ", floating_point_a[0]);
  print_u128_u("floating_point_a.p: ", floating_point_a[1]);
  std::cout << "int(floating_point_a[1]): " << int(floating_point_a[1]) << std::endl;

  //    FixedPointStruct<IntType> fixed_point_norm_v = FixedPointDivisionSimple<IntType,
  //    IntType_int>(fixed_point_v, constant_fixed_point_pow2_k);
  FixedPointStruct<IntType> fixed_point_norm_v =
      CreateFixedPointStruct<IntType>(floating_point_a[0] >> (k - 1 - f), k, f);
  std::cout << "fixed_point_norm_v: "
            << FixedPointToDouble<IntType, IntType_int>(fixed_point_norm_v) << std::endl;

  FixedPointStruct<IntType> fixed_point_poly_P =
      FixedPointPolynomialEvaluation<IntType, IntType_int>(fixed_point_norm_v, p_0371,
                                                           sizeof(p_0371) / sizeof(p_0371[0]));
  std::cout << "fixed_point_poly_P: "
            << FixedPointToDouble<IntType, IntType_int>(fixed_point_poly_P) << std::endl;

  FixedPointStruct<IntType> fixed_point_poly_Q =
      FixedPointPolynomialEvaluation<IntType, IntType_int>(fixed_point_norm_v, q_0371,
                                                           sizeof(q_0371) / sizeof(q_0371[0]));
  std::cout << "fixed_point_poly_Q: "
            << FixedPointToDouble<IntType, IntType_int>(fixed_point_poly_Q) << std::endl;

  FixedPointStruct<IntType> fixed_point_P_div_Q =
      FixedPointDivision<IntType, IntType_int>(fixed_point_poly_P, fixed_point_poly_Q);
  std::cout << "fixed_point_P_div_Q: "
            << FixedPointToDouble<IntType, IntType_int>(fixed_point_P_div_Q) << std::endl;

  double p_double = double(IntType_int(floating_point_a[1]));
  std::cout << "p_double: " << p_double << std::endl;

  // (2^k)^0.5 = 2^(floor(k/2)) + 2^0.5 if k is odd
  // (2^k)^0.5 = 2^(floor(k/2)) if k is even
  IntType k_minus_1_plus_p = IntType(k - 1) + IntType(floating_point_a[1]);
  IntType k_minus_1_plus_p_div_2 = IntType_int(k_minus_1_plus_p) >> 1;
  // bool k_minus_1_plus_p_div2_is_odd = k_minus_1_plus_p_div_2 & 1;
  bool k_minus_1_plus_p_is_odd = k_minus_1_plus_p_div_2 & 1;
  print_u128_u("k_minus_1_plus_p_div_2: ", k_minus_1_plus_p_div_2);

  IntType pow2_k_minus_1_plus_p_div_2 = Pow2(k_minus_1_plus_p_div_2, k);
  print_u128_u("pow2_k_minus_1_plus_p_div_2: ", pow2_k_minus_1_plus_p_div_2);

  FixedPointStruct<IntType> fixed_point_pow2_k_minus_1_plus_p_div_2 =
      CreateFixedPointStruct<IntType>(pow2_k_minus_1_plus_p_div_2 << f, k, f);
  FixedPointStruct<IntType> fixed_point_pow2_k_minus_1_plus_p_div_2_final =
      fixed_point_pow2_k_minus_1_plus_p_div_2;
  fixed_point_pow2_k_minus_1_plus_p_div_2_final.v =
      IntType_int(fixed_point_pow2_k_minus_1_plus_p_div_2_final.v *
                  ((IntType(1) << f) +
                   k_minus_1_plus_p_is_odd * IntType((M_SQRT2 - double(1)) * pow(2, f)))) >>
      f;
  print_u128_u("fixed_point_pow2_k_minus_1_plus_p_div_2_final.v: ",
               fixed_point_pow2_k_minus_1_plus_p_div_2_final.v);
  std::cout << "fixed_point_pow2_k_minus_1_plus_p_div_2_final: "
            << FixedPointToDouble<IntType, IntType_int>(
                   fixed_point_pow2_k_minus_1_plus_p_div_2_final)
            << std::endl;

  FixedPointStruct<IntType> fixed_point_sqrt_result =
      FixedPointMultiplication<IntType, IntType_int>(fixed_point_P_div_Q,
                                                     fixed_point_pow2_k_minus_1_plus_p_div_2_final);

  return fixed_point_sqrt_result;
}

template FixedPointStruct<__uint128_t>
FixedPointSqrtPQ0371<__uint128_t, __uint128_t, __int128_t, std::allocator<__uint128_t>>(
    FixedPointStruct<__uint128_t>& fixed_point_a);

void test_fixed_point_operation() {
  using T = std::uint64_t;
  using T_int = std::int64_t;
  using FLType = __uint128_t;
  using FLType_int = __int128_t;
  using FxType = __uint128_t;
  using FxType_int = __int128_t;
  using IntType = std::uint64_t;
  using IntType_int = std::int64_t;
  std::size_t k = 41;
  std::size_t f = 20;

  //  T fixed_point_a = 1 << 31;
  //  double fixed_point_a_double = FixedPointToDouble<T, T_int>(fixed_point_a);
  //  FixedPointStruct<T> result_struct = FixedPointSimplifiedFxSqrt<T, T_int>(fixed_point_a, k, f);
  //  std::cout << "fixed_point_a_double: " << fixed_point_a_double << std::endl;
  //  std::cout << "sqrt_fixed_point_a_double: " << sqrt(fixed_point_a_double) << std::endl;
  //  print_u128_u("result_struct.v: ", result_struct.v);
  //  std::cout << "result_struct.v_double: " << FixedPointToDouble<T, T_int>(result_struct.v)
  //            << std::endl;

  // =======================================================

  //    IntType integer_a = 43234252;
  //    std::size_t gamma = FLOATINGPOINT_BITS;
  //    std::size_t l_floating_point = FLOATINGPOINT_MANTISSA_BITS+1;
  //    std::size_t k_floating_point = FLOATINGPOINT_EXPONENT_BITS;
  //    std::vector<FLType> integer_to_floating_point = IntegerToFloatingPoint_ABZS<FLType, IntType,
  //    IntType_int>(integer_a, gamma, l_floating_point,
  //                                                                                                              k_floating_point);

  // =======================================================
  //    FxType fixed_point_a = 144566918243;
  //    double fixed_point_a_double = FixedPointToDouble<FxType, FxType_int>(fixed_point_a, k, f);
  //    std::cout << "fixed_point_a_double: " << fixed_point_a_double << std::endl;
  //    FixedPointStruct<FxType> fixed_point_a_struct =
  //    CreateFixedPointStruct<FxType>(fixed_point_a); FixedPointStruct<FxType>
  //    fixed_point_sqrt_result_struct = FixedPointSqrtP0132<FLType, FxType, FxType_int, IntType,
  //    IntType_int, std::allocator<FLType> >(
  //            fixed_point_a_struct);
  //    double fixed_point_a_sqrt_double = FixedPointToDouble<FxType,
  //    FxType_int>(fixed_point_sqrt_result_struct); std::cout << "fixed_point_a_sqrt_double: " <<
  //    fixed_point_a_sqrt_double << std::endl;
  // =======================================================

  FxType fixed_point_a = 166918243;
  double fixed_point_a_double = FixedPointToDouble<FxType, FxType_int>(fixed_point_a, k, f);
  std::cout << "fixed_point_a_double: " << fixed_point_a_double << std::endl;
  FixedPointStruct<FxType> fixed_point_a_struct = CreateFixedPointStruct<FxType>(fixed_point_a);
  FixedPointStruct<FxType> fixed_point_log2_result_struct =
      FixedPointLog2P2508<FLType, FLType_int, FxType, FxType_int, IntType, IntType_int,
                          std::allocator<FLType>>(fixed_point_a_struct);
  double fixed_point_a_log2_double =
      FixedPointToDouble<FxType, FxType_int>(fixed_point_log2_result_struct);
  std::cout << "fixed_point_a_log2_double: " << fixed_point_a_log2_double << std::endl;
  // =======================================================
}