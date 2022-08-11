#pragma once

#include <cmath>
#include <iostream>
#include <vector>
#include "floating_point_operation.h"
#include "print_uint128_t.h"

// k: total bit length of fixed-point number
// f: fraction bit length of fixed-point number
template <typename T>
struct FixedPointStruct {
  T v;
  std::size_t k = 41;
  std::size_t f = 20;
};

// k: total bit length of fixed-point number
// f: fraction bit length of fixed-point number
template <typename T>
struct FixedPointVectorStruct {
  std::vector<T, std::allocator<T>> v_vector;
  std::size_t k = 41;
  std::size_t f = 20;
};

//# polynomials as enumerated on Hart's book

static const double p_1045[] = {+0.99999999999998151058451,      +0.69314718056364205693851,
                                +0.24022650683729748257646,      +0.0555041102193305250618,
                                +0.0096181190501642860210497,    +0.0013333931011014250476911,
                                +0.00015395144945146697380844,   +0.000015368748541192116946474,
                                +0.0000012256971722926501833228, +0.00000014433329807023165258784};

static const double p_2524[] = {-2.05466671951, -8.8626599391, +6.10585199015, +4.81147460989};
static const double q_2524[] = {+0.353553425277, +4.54517087629, +6.42784209029, +1};

static const double p_0132[] = {+0.22906994529, +1.3006690496, -0.90932104982, +0.50104207633,
                                -0.12146838249};

static const double p_0371[] = {+0.073633718232, +0.946607534649, +0.444001732732, -0.041034283936};

static const double q_0371[] = {+0.4232099882, +1.0};

static const double p_2508[] = {-4.58532387645, 18.3513525596,  -51.5256443742, +111.767841656,
                                -174.170840774, +191.731001033, -145.611919796, +72.6500829774,
                                -21.4473491967, +2.84079979731};

static const double p_LinAppSQ[] = {+1.787727479, -0.8099868542};

// Mathematical Expression	C++ Symbol	Decimal Representation
// pi	M_PI	3.14159265358979323846
// pi/2	M_PI_2	1.57079632679489661923
// pi/4	M_PI_4	0.785398163397448309616
// 1/pi	M_1_PI	0.318309886183790671538
// 2/pi	M_2_PI	0.636619772367581343076
// 2/sqrt(pi)	M_2_SQRTPI	1.12837916709551257390
// sqrt(2)	M_SQRT2	1.41421356237309504880
// 1/sqrt(2)	M_SQRT1_2	0.707106781186547524401
// e	M_E	2.71828182845904523536
// log_2(e)	M_LOG2E	1.44269504088896340736
// log_10(e)	M_LOG10E	0.434294481903251827651
// log_e(2)	M_LN2	0.693147180559945309417
// log_e(10)	M_LN10	2.30258509299404568402

// 2^0.5
// M_SQRT2

template <typename T>
FixedPointStruct<T> CreateFixedPointStruct(double fixed_point, std::size_t k = 41,
                                           std::size_t f = 20);

template <typename T>
FixedPointStruct<T> CreateFixedPointStruct(T fixed_point, std::size_t k = 41, std::size_t f = 20);

template <typename T>
FixedPointVectorStruct<T> CreateFixedPointVectorStruct(double fixed_point, std::size_t k,
                                                       std::size_t f, std::size_t vector_size);

template <typename T>
FixedPointVectorStruct<T> CreateFixedPointVectorStruct(const std::vector<double>& fixed_point,
                                                       std::size_t k, std::size_t f);

template <typename T>
FixedPointVectorStruct<T> CreateFixedPointVectorStruct(T fixed_point_mantissa_vector,
                                                       std::size_t k = 41, std::size_t f = 20,
                                                       std::size_t vector_size = 1);

template <typename T>
FixedPointVectorStruct<T> CreateFixedPointVectorStruct(const std::vector<T>& fixed_point_mantissa_vector,
                                                       std::size_t k = 41, std::size_t f = 20);

template <typename T>
void double_to_integer(const double coeff[], std::size_t coeff_size, std::size_t k = 41,
                       std::size_t f = 20);

template <typename T, typename T_int>
double FixedPointToDouble(FixedPointStruct<T> fixed_point_struct);

template <typename T, typename T_int>
double FixedPointToDouble(T fixed_point_struct, std::size_t k = 41, std::size_t f = 20);

// template <typename T, typename T_int, typename A = std::allocator<FixedPointStruct<T>>>
// std::vector<double> FixedPointToDouble(std::vector<FixedPointStruct<T>, A> fixed_point_struct);

template <typename T, typename T_int, typename A = std::allocator<T>>
std::vector<double> FixedPointToDouble(std::vector<T, A> fixed_point_mantissa_vector,
                                       std::size_t k = 41, std::size_t f = 20);

template <typename T>
FixedPointStruct<T> FixedPointAddition(FixedPointStruct<T>& fixed_point_a,
                                       FixedPointStruct<T>& fixed_point_b);

template <typename T>
FixedPointStruct<T> FixedPointSubtraction(FixedPointStruct<T>& fixed_point_a,
                                          FixedPointStruct<T>& fixed_point_b);

template <typename T, typename T_int>
FixedPointStruct<T> FixedPointMultiplication(FixedPointStruct<T>& fixed_point_a,
                                             FixedPointStruct<T>& fixed_point_b);

template <typename T, typename T_int>
FixedPointStruct<T> FixedPointDivisionSimple(FixedPointStruct<T>& fixed_point_a,
                                             FixedPointStruct<T>& fixed_point_b);

template <typename T, typename T_int, typename A = std::allocator<T>>
FixedPointStruct<T> FixedPointDivision(FixedPointStruct<T>& fixed_point_a,
                                       FixedPointStruct<T>& fixed_point_b);

template <typename T>
T FixedPointLessThan(FixedPointStruct<T>& fixed_point_a, FixedPointStruct<T>& fixed_point_b);

template <typename T>
T FixedPointEqual(FixedPointStruct<T>& fixed_point_a, FixedPointStruct<T>& fixed_point_b);

template <typename T>
T FixedPointEQZ(FixedPointStruct<T>& fixed_point_a);

template <typename T>
T FixedPointLTZ(FixedPointStruct<T>& fixed_point_a);

template <typename T>
T FixedPointAbs(FixedPointStruct<T>& fixed_point_a);

template <typename T>
T FixedPointFloor(FixedPointStruct<T>& fixed_point_a);

template <typename T>
FixedPointStruct<T> FixedPointNegation(FixedPointStruct<T>& fixed_point_a);

template <typename T>
T Pow2(T a, std::size_t k);

template <typename T, typename T_int, typename A = std::allocator<T>>
T FixedPointAppRcr(T b, std::size_t k = 41, std::size_t f = 20);

template <typename T, typename T_int, typename A = std::allocator<T>>
T FixedPointAppRcr_opt(T b, std::size_t k = 41, std::size_t f = 20);

template <typename T, typename T_int, typename A = std::allocator<T>>
std::vector<T, A> FixedPointNorm(T b, std::size_t k = 41, std::size_t f = 20);

template <typename T, typename A = std::allocator<T>>
std::vector<T, A> FixedPointNormSQ(T b, std::size_t k = 41, std::size_t f = 20);

template <typename T, typename A = std::allocator<T>>
std::vector<T, A> FixedPointSimplifiedNormSQ(T b, std::size_t k = 41, std::size_t f = 20);

template <typename T>
FixedPointStruct<T> FixedPointInt2Fx(T a, std::size_t k = 41, std::size_t f = 20);

template <typename T, typename T_int>
T FixedPointFx2Int(FixedPointStruct<T>& fixed_point_a);

template <typename FLType, typename IntType, typename IntType_int, typename A>
std::vector<FLType, A> FixedPointFx2FL(FixedPointStruct<FLType>& fixed_point_g, std::size_t gamma,
                                       std::size_t f, std::size_t l, std::size_t k);

template <typename T, typename T_int, typename A = std::allocator<T>>
FixedPointStruct<T> FixedPointParamFxSqrt(T x, std::size_t k = 41, std::size_t f = 20);

template <typename T, typename T_int, typename A = std::allocator<T>>
FixedPointStruct<T> FixedPointSimplifiedFxSqrt(T x, std::size_t k = 41, std::size_t f = 20);

template <typename T>
FixedPointStruct<T> FixedPointSqrt(FixedPointStruct<T>& fixed_point_a, std::size_t k = 41,
                                   std::size_t f = 20);

template <typename FLType, typename FxType, typename FxType_int, typename IntType,
          typename IntType_int, typename A>
FixedPointStruct<FxType> FixedPointSqrtP0132(FixedPointStruct<FxType>& fixed_point_a);

template <typename FLType, typename IntType, typename IntType_int, typename A>
FixedPointStruct<FLType> FixedPointSqrtPQ0371(FixedPointStruct<FLType>& fixed_point_a);

// approximation of 1/sqrt(b)
template <typename T, typename T_int, typename A = std::allocator<T>>
T FixedPointLinAppSQ(T b, std::size_t k = 41, std::size_t f = 20);

// template <typename T, typename T_int, typename A = std::allocator<T>>
// T FixedPointLinAppSQ_optimization_1(T b, std::size_t k = 41, std::size_t f = 20);

template <typename T, typename T_int, typename A = std::allocator<T>>
FixedPointStruct<T> FixedPointExp2P1045(FixedPointStruct<T>& fixed_point_a);

// too much arithmetic shift -> not efficient
// template<typename T, typename T_int, typename A = std::allocator<T>>
// FixedPointStruct<T> FixedPointExp2PQ1065(FixedPointStruct<T> &fixed_point_a);

template <typename T, typename T_int>
FixedPointStruct<T> FixedPointPolynomialEvaluation(FixedPointStruct<T>& fixed_point_x,
                                                   const double coefficient[],
                                                   std::size_t array_size);

template <typename FLType, typename FLType_int, typename FxType, typename FxType_int,
          typename IntType, typename IntType_int, typename A = std::allocator<FLType>>
FixedPointStruct<FxType> FixedPointLog2P2508(FixedPointStruct<FLType>& fixed_point_a);

template <typename FLType, typename IntType, typename IntType_int,
          typename A = std::allocator<FLType>>
FixedPointStruct<FLType> FixedPointLog2PQ2524(FixedPointStruct<FLType>& fixed_point_a);

void test_fixed_point_operation();