#pragma once

#include <cmath>
#include <iostream>
#include <vector>
#include "print_uint128_t.h"

template <typename T>
struct FloatingPointStruct {
  T mantissa;
  T exponent;
  T zero;
  T sign;
  T error;
  std::size_t l = 53;
  std::size_t k = 11;
};

template <typename T>
struct FloatingPointVectorStruct {
  std::vector<T> mantissa;
  std::vector<T> exponent;
  std::vector<T> zero;
  std::vector<T> sign;
  std::vector<T> error;
  std::size_t l = 53;
  std::size_t k = 11;
  std::size_t num_of_simd;
};

template <typename T, typename A = std::allocator<T>>
std::vector<T, A> FloatingPointDecomposeToVector(double floating_point_number, std::size_t l = 53,
                                                 std::size_t k = 11);

template <typename T>
FloatingPointStruct<T> FloatingPointDecomposeToStruct(double floating_point_number,
                                                      std::size_t l = 53, std::size_t k = 11);
template <typename T>
FloatingPointVectorStruct<T> FloatingPointDecomposeToStruct(
    const std::vector<double>& floating_point_number, std::size_t l = 53, std::size_t k = 11);

template <typename T, typename A = std::allocator<T>>
std::vector<T, A> CreateFloatingPointVector(T v, T p, T z, T s, std::size_t l = 53,
                                            std::size_t k = 11);

template <typename T>
FloatingPointStruct<T> CreateFloatingPointStruct(T v, T p, T z, T s, std::size_t l = 53,
                                                 std::size_t k = 11);

template <typename T, typename A = std::allocator<T>>
double FloatingPointToDouble(T v, T p, T z, T s, std::size_t l = 53, std::size_t k = 11);

template <typename T, typename A = std::allocator<T>>
std::vector<double> FloatingPointToDouble(std::vector<T, A> v_vector, std::vector<T, A> p_vector,
                             std::vector<T, A> z_vector, std::vector<T, A> s_vector,
                             std::size_t l = 53, std::size_t k = 11);

template <typename T, typename A = std::allocator<T>>
double FloatingPointToDouble(std::vector<T, A> floating_point_vector, std::size_t l = 53,
                             std::size_t k = 11);

template <typename T, typename A = std::allocator<T>>
double FloatingPointToDouble(FloatingPointStruct<T> floating_point_struct, std::size_t l = 53,
                             std::size_t k = 11);

// template<typename T>
// std::vector<bool> BitDecompose(T x, std::size_t l);

// ============================================================

template <typename T, typename T_int, typename A = std::allocator<T>>
std::vector<T, A> FloatingPointAddition_ABZS(T v1, T p1, T z1, T s1, T v2, T p2, T z2, T s2,
                                             std::size_t l = 53, std::size_t k = 11);

template <typename T,typename T_int, typename A = std::allocator<T>>
std::vector<T, A> FloatingPointSubtraction_ABZS(T v1, T p1, T z1, T s1, T v2, T p2, T z2, T s2,
                                                std::size_t l = 53, std::size_t k = 11);

template <typename T>
T FloatingPointSimpleDivision_ABZS(T a, T b, std::size_t l = 53, std::size_t k = 11);

template <typename T, typename A = std::allocator<T>>
std::vector<T, A> FloatingPointDivision_ABZS(T v1, T p1, T z1, T s1, T v2, T p2, T z2, T s2,
                                             std::size_t l = 53, std::size_t k = 11);

template <typename T, typename A = std::allocator<T>>
std::vector<T, A> FloatingPointMultiplication_ABZS(T v1, T p1, T z1, T s1, T v2, T p2, T z2, T s2,
                                                   std::size_t l = 53, std::size_t k = 11);

template <typename T, typename T_int>
T FloatingPointLessThan_ABZS(T v1, T p1, T z1, T s1, T v2, T p2, T z2, T s2, std::size_t l = 53,
                             std::size_t k = 11);

template <typename T>
T FloatingPointEqual_ABZS(T v1, T p1, T z1, T s1, T v2, T p2, T z2, T s2, std::size_t l = 53,
                          std::size_t k = 11);

template <typename T,typename T_int, typename A = std::allocator<T>>
std::vector<T, A> FloatingPointRound_ABZS(T v1, T p1, T z1, T s1, std::size_t mode = 0,
                                          std::size_t l = 53, std::size_t k = 11);

template <typename FLType, typename IntType, typename IntType_int,
          typename A = std::allocator<FLType>>
std::vector<FLType, A> IntegerToFloatingPoint_ABZS(IntType a,
                                                   std::size_t gamma = sizeof(IntType) * 8,
                                                   std::size_t l = 53, std::size_t k = 11);

template <typename T, typename T_int, typename A = std::allocator<T>>
std::vector<T, A> FloatingPointSqrt_ABZS(T v1, T p1, T z1, T s1, std::size_t l = 53,
                                         std::size_t k = 11);

template <typename T,typename T_int,  typename A = std::allocator<T>>
std::vector<T, A> FloatingPointExp2_ABZS(T v1, T p1, T z1, T s1, std::size_t l = 53,
                                         std::size_t k = 11);

template <typename T, typename T_int, typename A = std::allocator<T>>
std::vector<T, A> FloatingPointLog2_ABZS(T v1, T p1, T z1, T s1, std::size_t l = 53,
                                         std::size_t k = 11);

// ============================================================

template <typename T, typename T_int, typename A = std::allocator<T>>
std::vector<T, A> FloatingPointAddition_ABZS(std::vector<T, A> floating_point_1,
                                             std::vector<T, A> floating_point_2, std::size_t l = 53,
                                             std::size_t k = 11);

template <typename T, typename T_int, typename A = std::allocator<T>>
std::vector<T, A> FloatingPointSubtraction_ABZS(std::vector<T, A> floating_point_1,
                                                std::vector<T, A> floating_point_2,
                                                std::size_t l = 53, std::size_t k = 11);

template <typename T, typename A = std::allocator<T>>
std::vector<T, A> FloatingPointDivision_ABZS(std::vector<T, A> floating_point_1,
                                             std::vector<T, A> floating_point_2, std::size_t l = 53,
                                             std::size_t k = 11);

template <typename T, typename A = std::allocator<T>>
std::vector<T, A> FloatingPointMultiplication_ABZS(std::vector<T, A> floating_point_1,
                                                   std::vector<T, A> floating_point_2,
                                                   std::size_t l = 53, std::size_t k = 11);

template <typename T,typename T_int, typename A = std::allocator<T>>
T FloatingPointLessThan_ABZS(std::vector<T, A> floating_point_1, std::vector<T, A> floating_point_2,
                             std::size_t l = 53, std::size_t k = 11);

template <typename T, typename A = std::allocator<T>>
T FloatingPointEqual_ABZS(std::vector<T, A> floating_point_1, std::vector<T, A> floating_point_2,
                          std::size_t l = 53, std::size_t k = 11);

template <typename T,typename T_int, typename A = std::allocator<T>>
std::vector<T, A> FloatingPointRound_ABZS(std::vector<T, A> floating_point_1, std::size_t mode,
                                          std::size_t l = 53, std::size_t k = 11);

template <typename T,typename T_int,  typename A = std::allocator<T>>
std::vector<T, A> FloatingPointSqrt_ABZS(std::vector<T, A> floating_point_1, std::size_t l,
                                         std::size_t k);

// ============================================================

template <typename T,typename T_int,  typename A = std::allocator<T>>
FloatingPointStruct<T> FloatingPointAddition_ABZS(FloatingPointStruct<T>& floating_point_1,
                                                  FloatingPointStruct<T>& floating_point_2,
                                                  std::size_t l = 53, std::size_t k = 11);

template <typename T,typename T_int, typename A = std::allocator<T>>
FloatingPointStruct<T> FloatingPointSubtraction_ABZS(FloatingPointStruct<T>& floating_point_1,
                                                     FloatingPointStruct<T>& floating_point_2,
                                                     std::size_t l = 53, std::size_t k = 11);

template <typename T, typename A = std::allocator<T>>
FloatingPointStruct<T> FloatingPointDivision_ABZS(FloatingPointStruct<T>& floating_point_1,
                                                  FloatingPointStruct<T>& floating_point_2,
                                                  std::size_t l = 53, std::size_t k = 11);

template <typename T, typename A = std::allocator<T>>
FloatingPointStruct<T> FloatingPointMultiplication_ABZS(FloatingPointStruct<T>& floating_point_1,
                                                        FloatingPointStruct<T>& floating_point_2,
                                                        std::size_t l = 53, std::size_t k = 11);

template <typename T, typename T_int,typename A = std::allocator<T>>
T FloatingPointLessThan_ABZS(FloatingPointStruct<T>& floating_point_1,
                             FloatingPointStruct<T>& floating_point_2, std::size_t l = 53,
                             std::size_t k = 11);

template <typename T, typename A = std::allocator<T>>
T FloatingPointEqual_ABZS(FloatingPointStruct<T>& floating_point_1,
                          FloatingPointStruct<T>& floating_point_2, std::size_t l = 53,
                          std::size_t k = 11);

template <typename T,typename T_int,  typename A = std::allocator<T>>
FloatingPointStruct<T> FloatingPointRound_ABZS(FloatingPointStruct<T>& floating_point_1,
                                               std::size_t mode, std::size_t l = 53,
                                               std::size_t k = 11);

// template<typename FLType, typename IntType, typename IntType_int,
//         typename A = std::allocator<FLType>>
// FloatingPointStruct<FLType> IntegerToFloatingPoint_ABZS(IntType a,std::size_t gamma =
// sizeof(IntType) * 8,
//                                                         std::size_t l = 53, std::size_t k = 11);

template <typename T,typename T_int, typename A = std::allocator<T>>
FloatingPointStruct<T> FloatingPointSqrt_ABZS(FloatingPointStruct<T>& floating_point_1,
                                              std::size_t l, std::size_t k);

template <typename T, typename A = std::allocator<T>>
FloatingPointStruct<T> FloatingPointProduct_ABZS(
    std::vector<FloatingPointStruct<T>>& floating_point_vector, std::size_t head, std::size_t tail,
    std::size_t l = 53, std::size_t k = 11);

template <typename T,typename T_int, typename A = std::allocator<T>>
FloatingPointStruct<T> FloatingPointExp2_ABZS(FloatingPointStruct<T>& floating_point_1,
                                              std::size_t l, std::size_t k);

template <typename T,typename T_int, typename A = std::allocator<T>>
FloatingPointStruct<T> FloatingPointLog2_ABZS(FloatingPointStruct<T>& floating_point_1,
                                              std::size_t l, std::size_t k);

// template<typename T>
// struct FloatingPointNumber {
//     T mantissa;
//     T exponent;
//     T z;
//     T s;
//     T error;
//     std::size_t l = 53;
//     std::size_t k = 11;
// };

// template<typename T, typename A = std::allocator<T>>
// std::vector<T, A> FloatingPointDecomposeToVector(double floating_point_number, std::size_t l =
// 53,
//                                          std::size_t k = 11) {
//     std::size_t size_of_T = sizeof(T) * 8;

//     double mantissa;
//     int exponent;
//     mantissa = std::frexp(std::abs(floating_point_number), &exponent);

//     // convert mantissa to field [1,2)
//     mantissa = mantissa * 2;
//     exponent = exponent - 1;

//     T v = mantissa * (T(1) << (T(l) - 1));
//     T p = T(exponent - T(l) + T(1));
//     T s = floating_point_number < 0;
//     T z = floating_point_number == 0;

//     if (z) {
//         v = 0;
//         p = 0;
//         s = 0;
//     }

//     std::cout << floating_point_number << " = " << mantissa << " * 2^" << exponent << '\n';

//     print_u128_u("mantissa: ", v);
//     print_u128_u("exponent: ", p);
//     std::cout << "std::int64_t(exponent): " << std::int64_t(p) << std::endl;
//     print_u128_u("sign: ", s);
//     print_u128_u("zero: ", z);

//     std::vector<T, A> floating_point_decomposition_result;
//     floating_point_decomposition_result.reserve(4);
//     floating_point_decomposition_result.emplace_back(v);
//     floating_point_decomposition_result.emplace_back(p);
//     floating_point_decomposition_result.emplace_back(z);
//     floating_point_decomposition_result.emplace_back(s);

//     return floating_point_decomposition_result;
// }

// template std::vector<std::uint64_t, std::allocator<std::uint64_t>>
// FloatingPointDecomposeToVector<std::uint64_t, std::allocator<std::uint64_t>>(double
// floating_point_number,
//                                                                      std::size_t l, std::size_t
//                                                                      k);

// template std::vector<__uint128_t, std::allocator<__uint128_t>>
// FloatingPointDecomposeToVector<__uint128_t, std::allocator<__uint128_t>>(double
// floating_point_number,
//                                                                  std::size_t l, std::size_t k);

// // added by Liang Zhao
// template<typename T, typename A = std::allocator<T>>
// std::vector<T, A> CreateFloatingPointShareVector(T v, T p, T z, T s, std::size_t l = 53,
// std::size_t k = 11) {
//     std::vector<T> floating_point_vector;
//     floating_point_vector.emplace_back(v);
//     floating_point_vector.emplace_back(p);
//     floating_point_vector.emplace_back(z);
//     floating_point_vector.emplace_back(s);

//     return floating_point_vector;

// }

// template<typename T, typename A>
// double FloatingPointToDouble(T v, T p, T z, T s, std::size_t l = 53, std::size_t k = 11) {
// //    double result = double(v) * (pow(2, std::int64_t(p))) * (1 - double(z)) * (1 - 2 *
// double(s));
//     double mantissa = double(v) / (T(1) << (l));
//     double result = std::ldexp(mantissa, std::int64_t(p) + l);

//     result = result * (1 - std::int64_t(z)) * (1 - 2 * std::int64_t(s));
//     return result;
// }

// template<typename T, typename A= std::allocator<T>>
// double FloatingPointToDouble(std::vector<T, A> floating_point_vector, std::size_t l = 53,
// std::size_t k = 11) {
//     double result = FloatingPointToDouble<T, A>(floating_point_vector[0],
//     floating_point_vector[1],
//                                                 floating_point_vector[2],
//                                                 floating_point_vector[3], l, k);
//     return result;
// }

// //template<>
// //double FloatingPointToDouble<__uint128_t, std::allocator<__uint128_t>>(std::vector<__uint128_t,
// std::allocator<__uint128_t>> floating_point_vector,
// //                                                                       std::size_t l,
// //                                                                       std::size_t k) {
// //    double result = FloatingPointToDouble<__uint128_t,
// std::allocator<__uint128_t>>(floating_point_vector[0], floating_point_vector[1],
// // floating_point_vector[2], floating_point_vector[3], l, k);
// //    return result;
// //}

// // ============================================================

// template<typename T, typename A = std::allocator<T>>
// std::vector<T, A> FloatingPointAddition_ABZS(T v1, T p1, T z1, T s1, T v2, T p2, T z2, T s2,
//                                              std::size_t l = 53, std::size_t k = 11);

// template<typename T, typename A = std::allocator<T>>
// std::vector<T, A> FloatingPointSubtraction_ABZS(T v1, T p1, T z1, T s1, T v2, T p2, T z2, T s2,
//                                                 std::size_t l = 53, std::size_t k = 11);

// template<typename T>
// T FloatingPointSimpleDivision_ABZS(T a, T b, std::size_t l = 53, std::size_t k = 11);

// template<typename T, typename A = std::allocator<T>>
// std::vector<T, A> FloatingPointDivision_ABZS(T v1, T p1, T z1, T s1, T v2, T p2, T z2, T s2,
//                                              std::size_t l = 53, std::size_t k = 11);

// template<typename T, typename A = std::allocator<T>>
// std::vector<T, A> FloatingPointMultiplication_ABZS(T v1, T p1, T z1, T s1, T v2, T p2, T z2, T
// s2,
//                                                    std::size_t l = 53, std::size_t k = 11);

// template<typename T>
// T FloatingPointLessThan_ABZS(T v1, T p1, T z1, T s1, T v2, T p2, T z2, T s2, std::size_t l = 53,
//                              std::size_t k = 11);

// template<typename T>
// T FloatingPointEqual_ABZS(T v1, T p1, T z1, T s1, T v2, T p2, T z2, T s2, std::size_t l = 53,
//                           std::size_t k = 11);

// template<typename T, typename A = std::allocator<T>>
// std::vector<T, A> FloatingPointRound_ABZS(T v1, T p1, T z1, T s1, std::size_t mode = 0,
//                                           std::size_t l = 53, std::size_t k = 11);

// template<typename FLType, typename IntType, typename IntType_int,
//         typename A = std::allocator<FLType>>
// std::vector<FLType, A> IntegerToFloatingPoint_ABZS(IntType a,
//                                                    std::size_t gamma = sizeof(IntType) * 8,
//                                                    std::size_t l = 53, std::size_t k = 11);

// template<typename T, typename A = std::allocator<T>>
// std::vector<T, A> FloatingPointSqrt_ABZS(T v1, T p1, T z1, T s1, std::size_t l = 53,
//                                          std::size_t k = 11);

// // ============================================================

// template<typename T, typename A = std::allocator<T>>
// std::vector<T, A> FloatingPointAddition_ABZS(std::vector<T, A> floating_point_1,
//                                              std::vector<T, A> floating_point_2, std::size_t l =
//                                              53, std::size_t k = 11) {
//     std::vector<T, A> result = FloatingPointAddition_ABZS<T, A>(
//             floating_point_1[0], floating_point_1[1], floating_point_1[2], floating_point_1[3],
//             floating_point_2[0], floating_point_2[1], floating_point_2[2], floating_point_2[3],
//             l, k);
//     return result;
// }

// template<typename T, typename A = std::allocator<T>>
// std::vector<T, A> FloatingPointSubtraction_ABZS(std::vector<T, A> floating_point_1,
//                                                 std::vector<T, A> floating_point_2, std::size_t l
//                                                 = 53, std::size_t k = 11) {
//     std::vector<T, A> result = FloatingPointSubtraction_ABZS<T, A>(
//             floating_point_1[0], floating_point_1[1], floating_point_1[2], floating_point_1[3],
//             floating_point_2[0], floating_point_2[1], floating_point_2[2], floating_point_2[3],
//             l, k);
//     return result;
// }

// template<typename T, typename A = std::allocator<T>>
// std::vector<T, A> FloatingPointDivision_ABZS(std::vector<T, A> floating_point_1,
//                                              std::vector<T, A> floating_point_2, std::size_t l =
//                                              53, std::size_t k = 11) {
//     std::vector<T, A> result = FloatingPointDivision_ABZS<T, A>(
//             floating_point_1[0], floating_point_1[1], floating_point_1[2], floating_point_1[3],
//             floating_point_2[0], floating_point_2[1], floating_point_2[2], floating_point_2[3],
//             l, k);
//     return result;
// }

// template<typename T, typename A= std::allocator<T>>
// std::vector<T, A> FloatingPointMultiplication_ABZS(std::vector<T, A> floating_point_1,
//                                                    std::vector<T, A> floating_point_2,
//                                                    std::size_t l = 53, std::size_t k = 11) {
//     std::vector<T, A> result = FloatingPointMultiplication_ABZS<T, A>(
//             floating_point_1[0], floating_point_1[1], floating_point_1[2], floating_point_1[3],
//             floating_point_2[0], floating_point_2[1], floating_point_2[2], floating_point_2[3],
//             l, k);
//     return result;
// }

// template<typename T, typename A= std::allocator<T>>
// T FloatingPointLessThan_ABZS(std::vector<T, A> floating_point_1, std::vector<T, A>
// floating_point_2,
//                              std::size_t l = 53, std::size_t k = 11) {
//     std::vector<T, A> result = FloatingPointLessThan_ABZS<T, A>(
//             floating_point_1[0], floating_point_1[1], floating_point_1[2], floating_point_1[3],
//             floating_point_2[0], floating_point_2[1], floating_point_2[2], floating_point_2[3],
//             l, k);
//     return result;
// }

// template<typename T, typename A= std::allocator<T>>
// T FloatingPointEqual_ABZS(std::vector<T, A> floating_point_1, std::vector<T, A> floating_point_2,
//                           std::size_t l = 53, std::size_t k = 11) {
//     std::vector<T, A> result = FloatingPointEqual_ABZS<T, A>(
//             floating_point_1[0], floating_point_1[1], floating_point_1[2], floating_point_1[3],
//             floating_point_2[0], floating_point_2[1], floating_point_2[2], floating_point_2[3],
//             l, k);
//     return result;
// }

// template<typename T, typename A= std::allocator<T>>
// std::vector<T, A> FloatingPointRound_ABZS(std::vector<T, A> floating_point_1, std::size_t mode,
//                                           std::size_t l = 53, std::size_t k = 11) {
//     std::vector<T, A> result =
//             FloatingPointRound_ABZS<T, A>(floating_point_1[0], floating_point_1[1],
//             floating_point_1[2],
//                                           floating_point_1[3], mode, l, k);
//     return result;
// }

// template<typename T, typename A>
// std::vector<T, A> FloatingPointSqrt_ABZS(std::vector<T, A> floating_point_1,
//                                          std::size_t l, std::size_t k) {
//     std::vector<T, A> result =
//             FloatingPointSqrt_ABZS<T, A>(floating_point_1[0], floating_point_1[1],
//             floating_point_1[2],
//                                          floating_point_1[3], l, k);
//     return result;
// }
