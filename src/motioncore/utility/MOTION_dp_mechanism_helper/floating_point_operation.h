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

template <typename T, typename T_int, typename A = std::allocator<T>>
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

template <typename T, typename T_int, typename A = std::allocator<T>>
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

template <typename T, typename T_int, typename A = std::allocator<T>>
std::vector<T, A> FloatingPointExp2_ABZS(T v1, T p1, T z1, T s1, std::size_t l = 53,
                                         std::size_t k = 11);

template <typename T, typename T_int, typename A = std::allocator<T>>
std::vector<T, A> FloatingPointLog2_ABZS(T v1, T p1, T z1, T s1, std::size_t l = 53,
                                         std::size_t k = 11);


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

template <typename T, typename T_int, typename A = std::allocator<T>>
T FloatingPointLessThan_ABZS(std::vector<T, A> floating_point_1, std::vector<T, A> floating_point_2,
                             std::size_t l = 53, std::size_t k = 11);

template <typename T, typename A = std::allocator<T>>
T FloatingPointEqual_ABZS(std::vector<T, A> floating_point_1, std::vector<T, A> floating_point_2,
                          std::size_t l = 53, std::size_t k = 11);

template <typename T, typename T_int, typename A = std::allocator<T>>
std::vector<T, A> FloatingPointRound_ABZS(std::vector<T, A> floating_point_1, std::size_t mode,
                                          std::size_t l = 53, std::size_t k = 11);

template <typename T, typename T_int, typename A = std::allocator<T>>
std::vector<T, A> FloatingPointSqrt_ABZS(std::vector<T, A> floating_point_1, std::size_t l,
                                         std::size_t k);

// ============================================================

template <typename T, typename T_int, typename A = std::allocator<T>>
FloatingPointStruct<T> FloatingPointAddition_ABZS(FloatingPointStruct<T>& floating_point_1,
                                                  FloatingPointStruct<T>& floating_point_2,
                                                  std::size_t l = 53, std::size_t k = 11);

template <typename T, typename T_int, typename A = std::allocator<T>>
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

template <typename T, typename T_int, typename A = std::allocator<T>>
T FloatingPointLessThan_ABZS(FloatingPointStruct<T>& floating_point_1,
                             FloatingPointStruct<T>& floating_point_2, std::size_t l = 53,
                             std::size_t k = 11);

template <typename T, typename A = std::allocator<T>>
T FloatingPointEqual_ABZS(FloatingPointStruct<T>& floating_point_1,
                          FloatingPointStruct<T>& floating_point_2, std::size_t l = 53,
                          std::size_t k = 11);

template <typename T, typename T_int, typename A = std::allocator<T>>
FloatingPointStruct<T> FloatingPointRound_ABZS(FloatingPointStruct<T>& floating_point_1,
                                               std::size_t mode, std::size_t l = 53,
                                               std::size_t k = 11);

template <typename T, typename T_int, typename A = std::allocator<T>>
FloatingPointStruct<T> FloatingPointSqrt_ABZS(FloatingPointStruct<T>& floating_point_1,
                                              std::size_t l, std::size_t k);

template <typename T, typename A = std::allocator<T>>
FloatingPointStruct<T> FloatingPointProduct_ABZS(
    std::vector<FloatingPointStruct<T>>& floating_point_vector, std::size_t head, std::size_t tail,
    std::size_t l = 53, std::size_t k = 11);

template <typename T, typename T_int, typename A = std::allocator<T>>
FloatingPointStruct<T> FloatingPointExp2_ABZS(FloatingPointStruct<T>& floating_point_1,
                                              std::size_t l, std::size_t k);

template <typename T, typename T_int, typename A = std::allocator<T>>
FloatingPointStruct<T> FloatingPointLog2_ABZS(FloatingPointStruct<T>& floating_point_1,
                                              std::size_t l, std::size_t k);
