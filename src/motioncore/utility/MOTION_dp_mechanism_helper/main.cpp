#include <iostream>

#include <cmath>
#include <limits>
#include <bitset>
#include <climits>
#include <ctime>
#include "export_to_csv.h"
#include "print_uint128_t.h"

//#include "floating_point_operation.h"
//#include "fixed_point_operation.h"
#include "fix64_k64_f16.h"
//#include "fix64_k64_f33.h"
//#include "fix64_k64_f48.h"
#include "dp_mechanism_helper.h"
//#include "snapping_mechanism.h"
#include "integer_scaling_mechanism.h"
#include "discrete_gaussian_mechanism.h"
//#include "float32.h"
//#include "float64.h"
//#include "fix128.h"


using namespace std;

int main() {

//    test_optimize_geometric_distribution_EXP_iteration();
//    test_optimize_discrete_laplace_distribution_EXP_iteration();
    test_optimize_discrete_gaussian_distribution_EXP_iteration();
//test_discrete_gaussian_distribution_EXP_failure_estimation();
//     test_optimize_discrete_laplace_distribution_EXP_iteration_with_threshold();

//test_optimize_integer_scaling_laplace_distribution_EXP_iteration();



//    test_SigmaForGaussian();
//    test_symmetrical_binomial_distribution();
//    symmetrical_binomial_distribution_represent_as_int64_failure_probability_estimation();

//     test_dp_mechanism_helper();
//    test_snapping_mechanism();

//    test_fixed_point_operation();`

//    test_float32_to_int32();
//    test_int32_to_float32();
//    test_float32_ceil();
//    test_float32_floor();
//    test_float32_to_int64();
//    test_int64_to_float32();
//    test_int128_to_float32();//
//    test_int128_to_float32_towards_zero();//

//    test_float64_to_int64();
//    test_int64_to_float64();
//    test_float64_ceil();
//    test_float64_floor();
//    test_float64_to_int32();
//    test_int32_to_float64();
//    test_int128_to_float64();//
//    test_int128_to_float64_towards_zero();//
//
//    generate_constants_k64_f16();
//    generate_constants_k64_f33();
//    generate_constants_k64_f48();

//    test_fix64_k64_f16();
//    test_fix64_k64_f33();
//    test_fix64_k64_f48();



//    using T = std::uint64_t;
//    using T_int = std::int64_t;
//    using T = __uint128_t;
//    using T_int = __int128_t;
//
//    using A = std::allocator<T>;
//    constexpr std::size_t l = 53;
//    constexpr std::size_t k = 11;

//    constexpr std::size_t k = 41;
//    constexpr std::size_t f = 20;


    // ============================================================

//    // floating-point addition
//    T v1 = 10603234854910220;
//    T p1 = 1600;
//    T z1 = 0;
//    T s1 = 1;
//
//    T v2 = 7019701771887925;
//    T p2 = 1021;
//    T z2 = 0;
//    T s2 = 0;
//
//
//    std::vector<T> floating_point_addition_result = FloatingPointAddition_ABZS<T, std::allocator<T>>(v1, p1, z1, s1, v2, p2, z2, s2, l);
//
//    std::cout << "v_prime_prime_prime: ";
//    print_u128_u(floating_point_addition_result[0]);
//    std::cout << "p_prime: ";
//    print_u128_u(floating_point_addition_result[1]);
//    std::cout << "z: ";
//    print_u128_u(floating_point_addition_result[2]);
//    std::cout << "s_prime: ";
//    print_u128_u(floating_point_addition_result[3]);
//
//    std::cout<<std::endl;
//    T v_value = 42412939419640878;
//    unsigned msb_v_prime = 0;
//    while (v_value >>= 1) {
//        msb_v_prime++;
//    }
//
//    std::cout<<"msb_v_prime: "<<msb_v_prime<<std::endl;


// ============================================================

//// floating-point simple division
//    T a = 6359903626343629;
//    T b = 6156827691253182;
//
//    double a_double = double(a) / double(T(1) << (l - 1));
//    double b_double = double(b) / double(T(1) << (l - 1));
//
//    std::cout << "a_double: " << a_double << std::endl;
//    std::cout << "b_double: " << b_double << std::endl;
//    std::cout << "a/b_double: " << a_double / b_double << std::endl;
//
//
//    T floating_point_simple_division = FloatingPointSimpleDivision_ABZS<T>(a, b, l);
//    std::cout << "floating_point_simple_division: ";
//    print_u128_u(floating_point_simple_division);
//
//    double floating_point_simple_division_double = double(floating_point_simple_division) / double(T(1) << (l - 1));
//    std::cout << "floating_point_simple_division_double: " << floating_point_simple_division_double << std::endl;


// ============================================================

//// floating-point division
//    T v1 = 6359903626343629;
//    T p1 = 1765;
//    T z1 = 0;
//    T s1 = 0;
//
//    T v2 = 6156827691253182;
//    T p2 = 1818;
//    T z2 = 0;
//    T s2 = 0;
//
//    std::vector<T> floating_point_division_result = FloatingPointDivision_ABZS<T>(v1, p1, z1, s1, v2, p2, z2, s2, l);

//std::uint64_t  a= -10;
//
//std::uint64_t  b= 3;
//std::uint64_t  c =a*b;
//    std::uint64_t  d= 1;
//    std::uint64_t  e= (1-2*d)*a;


//std::cout<<e;

//    double a = sqrt(2);
//    FloatingPointDecomposeToVector<std::uint64_t,std::allocator<std::uint64_t>>(a);

//    double b = sqrt(2);
//    FloatingPointDecomposeToVector<__uint128_t,std::allocator<__uint128_t>>(b);

// ============================================================
//// floating-point sqrt

////    print_u128_u(constant_floating_point_number[0]);
//
//    double constant_double_alpha = -0.8099868542;
////    double constant_double_alpha = 10;
//    double constant_double_beta = 1.787727479;
//    double constant_double_sqrt2 = sqrt(2);
//    std::vector<T> alpha = FloatingPointDecomposeToVector<T, A>(constant_double_alpha, l, k);
//    std::vector<T> beta = FloatingPointDecomposeToVector<T, A>(constant_double_beta, l, k);
////    std::vector<T> sqrt2 = FloatingPointDecomposeToVector<T, A>(constant_double_sqrt2, l, k);
//
//    std::cout << std::endl;
//
////    std::vector<T> fl_3_div_2 =
////            CreateFloatingPointVector<T, A>(3 * (T(1) << (T(l) - 2)), -(T(l) - 1), 0, 0, l, k);
//    std::vector<T, A> fl_3_div_2 =
//            FloatingPointDecomposeToVector<T, A>(1.5, l, k);
//    std::cout << "fl_3_div_2: " << FloatingPointToDouble<T, A>(fl_3_div_2) << std::endl;//
//
//    std::cout << std::endl;
//
//    std::vector<T, A> gihi =
//            FloatingPointDecomposeToVector<T, A>(0.513189, l, k);
//    std::cout << "gihi: " << FloatingPointToDouble<T, A>(gihi) << std::endl;//
//
//
//
//    std::cout << std::endl;
//
//    std::vector<T, A> addition_result = FloatingPointAddition_ABZS<T, A>(fl_3_div_2, fl_3_div_2, l, k);
//    std::cout << "addition_result: " << FloatingPointToDouble<T, A>(addition_result) << std::endl;
//
//    std::cout << std::endl;
//
//    double constant_number = 13412134;
//    double constant_number = 5421937.6544;
//    for (std::size_t i = 0; i < 100; i++) {
//
//    std::srand(time(0));
//    double constant_number = std::rand();
//    std::vector<T, A> constant_floating_point_number = FloatingPointDecomposeToVector<T, A>(constant_number);
//    std::vector<T, A> sqrt_x = FloatingPointSqrt_ABZS<T, A>(constant_floating_point_number, l, k);
//    double recover_sqrt_x = FloatingPointToDouble<T, A>(sqrt_x);
//    std::cout << "recover_sqrt_x: " << recover_sqrt_x << std::endl;
//    std::cout << "expect_sqrt_x: " << sqrt(constant_number) << std::endl;

//    }
//
//    print_u128_u("sqrt_x[0]:", sqrt_x[0]);
//
//
//    T p1 = -50;
//
//    T p1_div_2 = p1 / 2;
//
//    print_u128_u("p1_div_2: ", p1_div_2);
//
//    std::cout << "std::int64_t(p1_div_2): " << std::int64_t(p1_div_2) << std::endl;

// ============================================================
// floating-point multiplication
//    FloatingPointStruct<T> fl_1 = FloatingPointDecomposeToStruct<T>(3.5, l, k);
//    FloatingPointStruct<T> fl_2 = FloatingPointDecomposeToStruct<T>(27, l, k);
//    FloatingPointStruct<T> fl_3 = FloatingPointDecomposeToStruct<T>(78, l, k);
//    FloatingPointStruct<T> mult_result = FloatingPointMultiplication_ABZS<T, A>(&fl_1, &fl_2, l, k);
//
//    std::cout << "mult_result: " << FloatingPointToDouble<T>(mult_result, l, k) << std::endl;
//
//    FloatingPointStruct<T> mult_result_2 = FloatingPointMultiplication_ABZS<T, A>(&mult_result, &fl_3, l, k);
//
//    std::cout << "mult_result_2: " << FloatingPointToDouble<T>(mult_result_2, l, k) << std::endl;
//    return 0;



// ============================================================
// floating-point product

//    std::vector<FloatingPointStruct<T>> floating_point_struct_vector;
//    FloatingPointStruct<T> fl_1 = FloatingPointDecomposeToStruct<T>(3.5, l, k);
//    FloatingPointStruct<T> fl_2 = FloatingPointDecomposeToStruct<T>(-27, l, k);
//    FloatingPointStruct<T> fl_3 = FloatingPointDecomposeToStruct<T>(1, l, k);
////    FloatingPointStruct<T> fl_4 = FloatingPointDecomposeToStruct<T>(222, l, k);
//    FloatingPointStruct<T> fl_5 = FloatingPointDecomposeToStruct<T>(4, l, k);
//    floating_point_struct_vector.emplace_back(fl_1);
//    floating_point_struct_vector.emplace_back(fl_2);
//    floating_point_struct_vector.emplace_back(fl_3);
////    floating_point_struct_vector.emplace_back(fl_4);
//    floating_point_struct_vector.emplace_back(fl_5);
//
//    std::size_t head = 0;
//    std::size_t tail = floating_point_struct_vector.size() - 1;
//    std::cout << "head: " << head << std::endl;
//    std::cout << "tail: " << tail << std::endl;
//
//    FloatingPointStruct<T> product_result = FloatingPointProduct_ABZS<T, A>(floating_point_struct_vector, head, tail,
//                                                                            l, k);
//
//    std::cout << "product_result: " << FloatingPointToDouble<T>(product_result, l, k) << std::endl;

// ============================================================
// floating-point exp2

////    double a =2.5;
//    std::srand(time(0));
//    double a = (std::rand() % (20000)) / 100;
//    a = -30000000;
////
//    FloatingPointStruct<T> number_to_exp2 = FloatingPointDecomposeToStruct<T>(a, l, k);
//
//    FloatingPointStruct<T> exp2_result = FloatingPointExp2_ABZS<T, A>(number_to_exp2, l, k);
//    std::cout << "exp2_result: " << FloatingPointToDouble<T, A>(exp2_result, l, k) << std::endl;
//    std::cout << "expect_exp2_result: " << pow(2, a);


//    FloatingPointStruct<T> number_to_exp2 = FloatingPointDecomposeToStruct<T>(a, l, k);
//    FloatingPointStruct<T> exp2_result = FloatingPointExp2_ABZS<T, A>(number_to_exp2, l, k);
//    std::cout << "exp2_result: " << FloatingPointToDouble<T, A>(exp2_result, l, k) << std::endl;
//    std::cout << "expect_exp2_result: " << pow(2, a);
//

//    std::cout << std::endl;
//    std::cout << std::endl;
//
//    std::size_t i = 20;
//    double floating_point_c = pow(2, pow(2, -std::int64_t(i)));
//    FloatingPointStruct<T> floating_point_struct_c = FloatingPointDecomposeToStruct<T>(floating_point_c, l, k);


//    std::cout << pow(2, -1) << std::endl;



// ============================================================
// floating-point log2
//
//    double a = 23431.123;
//
//    FloatingPointStruct<T> number_to_log2 = FloatingPointDecomposeToStruct<T>(a, l, k);
//
//    FloatingPointStruct<T> log2_result = FloatingPointLog2_ABZS<T, A>(number_to_log2, l, k);
//
//    std::cout << "log2_result: " << FloatingPointToDouble<T, A>(log2_result, l, k) << std::endl;
//    std::cout << "expect_log2_result: " << log2(a)<<std::endl;
//

//    double log_1_div_2 = 2 * log2(std::numbers::e) * (double(1) / double(3));
//    std::cout << "log_1_div_2: " << log_1_div_2 << std::endl;
//
//    for (std::size_t i = 1; i < 17; i++) {
//        log_1_div_2 += 2 * log2(std::numbers::e) * (double(1) / pow(3, 2 * i + 1)) / (2 * i + 1);
//        std::cout << "log_1_div_2 - after addition: " << log_1_div_2 << std::endl;
//    }


//// ============================================================
//    double t = 2.5;
//    uint64_t tmp;
//    std::copy(reinterpret_cast<std::uint64_t *>(&t), reinterpret_cast<std::uint64_t *>(&t) + 1, &tmp);
//
//    std::cout << "tmp: " << tmp << std::endl;
//
//    std::bitset<sizeof(t) * 8> bitset_t{tmp};
//
//    std::cout << bitset_t << std::endl;
//    for (std::size_t i = 0; i < sizeof(t) * 8; i++) {
//        std::cout << bitset_t[i];
//    }
//    std::cout<<std::endl;
//
//    std::uint64_t as_unsigned_output = tmp;
//    double *as_float_output;
//
//    as_float_output = reinterpret_cast<double * > (&as_unsigned_output);
//
//    std::cout<<"*as_float_output: "<<*as_float_output<<std::endl;
//
////    std::copy(reinterpret_cast<double * > (&as_unsigned_output), reinterpret_cast<double * > (&as_unsigned_output) + 1. & as_float_output);

// ============================================================

// floating-point round
//    double a = 0.1;
////
//    FloatingPointStruct<T> number_to_floor = FloatingPointDecomposeToStruct<T>(a, l, k);
//    FloatingPointStruct<T> floor_result = FloatingPointRound_ABZS<T, A>(number_to_floor, false, l, k);
//    std::cout << "floor_result: " << FloatingPointToDouble<T, A>(floor_result, l, k) << std::endl;
//    std::cout << "expect_result: " << floor(a) << std::endl;
//
//    FloatingPointStruct<T> number_to_ceil = FloatingPointDecomposeToStruct<T>(a, l, k);
//    FloatingPointStruct<T> ceil_result = FloatingPointRound_ABZS<T, A>(number_to_ceil, true, l, k);
//    std::cout << "ceil_result: " << FloatingPointToDouble<T, A>(ceil_result, l, k) << std::endl;
//    std::cout << "expect_result: " << ceil(a) << std::endl;
//

// ============================================================
//pow2

//    T a1 = 11;
//    T pow2_a1 = Pow2(a1, 30);
//    print_u128_u("pow2_a1: ", pow2_a1);

//    fixedptd a1 = 11;
//    fixedptd pow2_a1 = pow2(a1);
//    print_u128_u("pow2_a1: ", pow2_a1);


// ============================================================

//    double a = 308.604;
//    FixedPointStruct<T> fixed_point_a = CreateFixedPointStruct<T>(a, k, f);
//    print_u128_u("fixed_point_a.v: ", fixed_point_a.v);
//    double a_double = FixedPointToDouble<T, T_int>(fixed_point_a);
//    std::cout << "a_double: " << a_double << std::endl;
////////
//    double b = 350728;
//    FixedPointStruct<T> fixed_point_b = CreateFixedPointStruct<T>(b, k, f);
//    print_u128_u("fixed_point_b.v: ", fixed_point_b.v);
//    double b_double = FixedPointToDouble<T, T_int>(fixed_point_b);
//    std::cout << "b_double: " << b_double << std::endl;
////
//    FixedPointStruct<T> fixed_point_struct_a_add_b = FixedPointAddition<T>(fixed_point_a, fixed_point_b);
//    print_u128_u("fixed_point_struct_a_add_b.v: ", fixed_point_struct_a_add_b.v);
//    double a_add_b_double = FixedPointToDouble<T, T_int>(fixed_point_struct_a_add_b);
//    std::cout << "a_add_b_double: " << a_add_b_double << std::endl;
//
//    FixedPointStruct<T> fixed_point_struct_a_sub_b = FixedPointSubtraction<T>(fixed_point_a, fixed_point_b);
//    print_u128_u("fixed_point_struct_a_sub_b.v: ", fixed_point_struct_a_sub_b.v);
//    double a_sub_b_double = FixedPointToDouble<T, T_int>(fixed_point_struct_a_sub_b);
//    std::cout << "a_sub_b_double: " << a_sub_b_double << std::endl;
////
//    FixedPointStruct<T> fixed_point_struct_a_mul_b = FixedPointMultiplication<T, T_int>(fixed_point_a, fixed_point_b);
//    print_u128_u("fixed_point_struct_a_mul_b.v: ", fixed_point_struct_a_mul_b.v);
//    double fixed_point_struct_a_mul_b_double = FixedPointToDouble<T, T_int>(fixed_point_struct_a_mul_b);
//    std::cout << "a_mul_b_double: " << fixed_point_struct_a_mul_b_double << std::endl;
//
// ============================================================

//    double inverse_a = 1 / a;
//    FixedPointStruct<T> fixed_point_struct_inverse_a = CreateFixedPointStruct<T, double>(inverse_a, k, f);
//    print_u128_u("fixed_point_struct_inverse_a.v: ", fixed_point_struct_inverse_a.v);
//    double inverse_a_double = FixedPointToDouble<T, T_int>(fixed_point_struct_inverse_a);
//    std::cout << "inverse_a_double: " << inverse_a_double << std::endl;
//
//    FixedPointStruct<T> fixed_point_struct_a_div_simple_b = FixedPointDivisionSimple<T, T_int>(fixed_point_a, fixed_point_b);
//    print_u128_u("fixed_point_struct_a_div_simple_b.v: ", fixed_point_struct_a_div_simple_b.v);
//    double fixed_point_struct_a_div_simple_b_double = FixedPointToDouble<T, T_int>(fixed_point_struct_a_div_simple_b);
//    std::cout << "fixed_point_struct_a_div_simple_b_double: " << fixed_point_struct_a_div_simple_b_double << std::endl;

// ============================================================
//
//    T b_uint = 2531;
//    std::vector<T, A> b_norm = FixedPointNorm<T, T_int, A>(fixed_point_b.v, k, f);
//    print_u128_u("fixed_point_b.v: ", fixed_point_b.v);
//    print_u128_u("b_norm[0]: ", b_norm[0]);
//    print_u128_u("b_norm[1]: ", b_norm[1]);
//    std::cout << "b_norm[0]_double: " << FixedPointToDouble<T, T_int>(b_norm[0], k, f) << std::endl;
////
//    T w_prime = FixedPointAppRcr<T, T_int, A>(fixed_point_b.v, k, f);
//    print_u128_u("w_prime: ", w_prime);
//    std::cout << "w_prime_double: " << FixedPointToDouble<T, T_int>(w_prime, k, f)<<std::endl;

//    T w_prime = FixedPointAppRcr_opt<T, T_int, A>(fixed_point_b.v, k, f);
//    print_u128_u("w_prime: ", w_prime);
//    std::cout << "w_prime_double: " << FixedPointToDouble<T, T_int>(w_prime, k, f)<<std::endl;
////
////
//    FixedPointStruct<T> fixed_point_struct_a_div_b = FixedPointDivision<T, T_int, A>(fixed_point_a, fixed_point_b);
//    print_u128_u("fixed_point_struct_a_div_b.v: ", fixed_point_struct_a_div_b.v);
//    double fixed_point_struct_a_div_b_double = FixedPointToDouble<T, T_int>(fixed_point_struct_a_div_b);
//    std::cout << "fixed_point_struct_a_div_b_double: " << fixed_point_struct_a_div_b_double << std::endl;
//    std::cout << "expect result: " << a_double/b_double << std::endl;
////    std::cout << "1/b: " << 1.0 / b << std::endl;
//
// ============================================================

//    T b_uint = 6627;
//    std::vector<T, A> b_norm_SQ = FixedPointNormSQ<T, A>(b_uint, k, f);
//    print_u128_u("b_norm_SQ[0] c: ", b_norm_SQ[0]);
//    print_u128_u("b_norm_SQ[1] v: ", b_norm_SQ[1]);
//    print_u128_u("b_norm_SQ[2] m: ", b_norm_SQ[2]);
//    print_u128_u("b_norm_SQ[3] w: ", b_norm_SQ[3]);
//    std::cout << "b_norm_SQ[0]_double: " << FixedPointToDouble<T, T_int>(b_norm_SQ[0], k, f) << std::endl;
//
//    std::vector<T, A> b_norm_SQ = FixedPointSimplifiedNormSQ<T, A>(b_uint, k, f);
//    print_u128_u("b_norm_SQ[0] m_odd: ", b_norm_SQ[0]);
//    print_u128_u("b_norm_SQ[1] w: ", b_norm_SQ[1]);
//

// ============================================================
//    double x_double = 126;
//    FixedPointStruct<T> fixed_point_struct_x = CreateFixedPointStruct<T>(x_double, k, f);
//    print_u128_u("fixed_point_struct_x.v: ", fixed_point_struct_x.v);
//    T fixed_point_1_div_sqrt_x = FixedPointLinAppSQ<T, T_int, A>(fixed_point_struct_x.v, k, f);
//    print_u128_u("fixed_point_1_div_sqrt_x: ", fixed_point_1_div_sqrt_x);
//    std::cout << "fixed_point_1_div_sqrt_b_double: " << FixedPointToDouble<T, T_int>(fixed_point_1_div_sqrt_x, k, f) << std::endl;

// ============================================================
//    double x_double = 7924;
//
//    FixedPointStruct<T> fixed_point_struct_x = CreateFixedPointStruct<T>(a, k, f);
//    FixedPointStruct<T> fixed_point_sqrt_x = FixedPointParamFxSqrt<T, T_int, A>(fixed_point_struct_x.v, k, f);
//    std::cout << "fixed_point_sqrt_x: " << FixedPointToDouble<T, T_int>(fixed_point_sqrt_x) << std::endl;
//    std::cout << "expect_result: " << sqrt(FixedPointToDouble<T, T_int>(fixed_point_struct_x)) << std::endl;
//
//
//// ============================================================
//      fixed_point_struct_x = CreateFixedPointStruct<T>(a, k, f);
//    print_u128_u("fixed_point_struct_x.v: ", fixed_point_struct_x.v);
//    fixed_point_sqrt_x = FixedPointSimplifiedFxSqrt<T, T_int, A>(fixed_point_struct_x.v, k, f);
//    std::cout << "fixed_point_sqrt_x: " << FixedPointToDouble<T, T_int>(fixed_point_sqrt_x) << std::endl;

// ============================================================


//    FixedPointStruct<T> fixed_point_poly = FixedPointPolynomialEvaluation<T, T_int>(fixed_point_a, p_1045, sizeof(p_1045)/sizeof(p_1045[0]));
//    std::cout << "fixed_point_poly: " << FixedPointToDouble<T, T_int>(fixed_point_poly) << std::endl;
//
//    FixedPointStruct<T>   fixed_point_struct_to_exp2 = CreateFixedPointStruct<T>(15, k, f);
//    FixedPointStruct<T> fixed_point_exp2_a = FixedPointExp2P1045<T, T_int,A>(fixed_point_struct_to_exp2);
//    std::cout << "fixed_point_exp2_a: " << FixedPointToDouble<T, T_int>(fixed_point_exp2_a) << std::endl;
//    std::cout << "expect_result: " << pow(2,FixedPointToDouble<T, T_int>(fixed_point_struct_to_exp2)) << std::endl;

//    FixedPointStruct<T> fixed_point_log2_a_P2508 = FixedPointLog2P2508<T, T, T_int, A>(fixed_point_a);
//    std::cout << "fixed_point_log2_a_P2508: " << FixedPointToDouble<T, T_int>(fixed_point_log2_a_P2508) << std::endl;
//    std::cout << "expect_result: " << log2(FixedPointToDouble<T, T_int>(fixed_point_a)) << std::endl;


//
//    FixedPointStruct<T> fixed_point_log2_a_PQ2524 = FixedPointLog2PQ2524<T, T, T_int, A>(fixed_point_a);
//    std::cout << "fixed_point_log2_a_PQ2524: " << FixedPointToDouble<T, T_int>(fixed_point_log2_a_PQ2524) << std::endl;

//    FixedPointStruct<T> fixed_point_sqrt_P0132 = FixedPointSqrtP0132<T, T, T_int, A>(fixed_point_a);
//    std::cout << "fixed_point_sqrt_P0132: " << FixedPointToDouble<T, T_int>(fixed_point_sqrt_P0132) << std::endl;
//    std::cout << "expect_result: " << sqrt(FixedPointToDouble<T, T_int>(fixed_point_a)) << std::endl;

//    FixedPointStruct<T> fixed_point_sqrt_PQ0371 = FixedPointSqrtPQ0371<T, T, T_int, A>(fixed_point_a);
//    std::cout << "fixed_point_sqrt_PQ0371: " << FixedPointToDouble<T, T_int>(fixed_point_sqrt_PQ0371) << std::endl;
//    std::cout << "expect_result: " << sqrt(FixedPointToDouble<T, T_int>(fixed_point_a)) << std::endl;

//    T a_v = -24557649;
//    std::vector<T, A> floating_point_a = IntegerToFloatingPoint_ABZS<T, T, T_int>(a_v, 41, 41-1, 41);

// ============================================================
// convert coefficient to integer
//    double_to_integer<std::uint64_t>(p_1045, sizeof(p_1045) / sizeof(p_1045[0]), k, 16);


//


//fixedptd aa = 32;
//    c = pow2(aa);
//    print_u128_u("c: ", c);


//    double_to_fixedptd(p_AppRcr, sizeof(p_AppRcr) / sizeof(p_AppRcr[0]));

//    fixedptd norm_SQ_result[4];
//    fixedptd_NormSQ(b, norm_SQ_result);
//    print_u128_u("c:", norm_SQ_result[0]);
//    print_u128_u("v:",norm_SQ_result[1]);
//    print_u128_u("m:",norm_SQ_result[2]);
//    print_u128_u("w:",norm_SQ_result[3]);

// ============================================================
//LinAppSQ optimization
//
//    T a = 150000;
//    T b = 300000;
//    std::cout << "a_double: " << FixedPointToDouble<T, T_int>(a) << std::endl;
//    std::cout << "b_double: " << FixedPointToDouble<T, T_int>(b) << std::endl;
//
//    FixedPointLinAppSQ_optimization_1<T, T_int, A>(b, k, f);




// ============================================================
//     export to csv
//     Make three vectors, each of length 100 filled with 1s, 2s, and 3s
//    std::vector<double> vec1(100, 1.2);
//    std::vector<double> vec2(100, 2.6);
//    std::vector<double> vec3(100, 3);
//
//    // Wrap into a vector
//    std::vector<std::pair<std::string, std::vector<double>>> vals = {{"One", vec1}, {"Two", vec2}, {"Three", vec3}};
//
//    // Write the vector to CSV
//    write_csv("three_cols.csv", vals);


// ============================================================
// snapping mechanism

//    double double_input = 2.3;
//    FLType int_output = double_to_int(double_input);
//
//    std::cout << "int_output: " << int_output << std::endl;
//
//    FLType int_output_ = double_to_bool_array(double_input);
//
//
//// ============================================================
//    bool bool_array_list_52[FLOATINGPOINT64_MANTISSA_BITS] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
//                                                            1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
//
//    bool bool_array_pre_or[FLOATINGPOINT64_MANTISSA_BITS];
//    PreOrL(bool_array_list_52, bool_array_pre_or);
//
//    std::cout << "PreOr: " << std::endl;
//    for (std::size_t i = 0; i < FLOATINGPOINT64_MANTISSA_BITS; i++) {
//        std::cout << bool_array_pre_or[i];
//    }
//    std::cout << std::endl;
//
//// ============================================================
//
//    unsigned head = 0;
//    unsigned tail = FLOATINGPOINT64_MANTISSA_BITS - 1;
//
//    bool K_and_L = KAndL(bool_array_list_52, head, tail);
//    std::cout << "K_and_L: " << K_and_L << std::endl;
//
//// ============================================================
//    bool bool_array_list_64[FLOATINGPOINT64_BITS] = {0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0,
//                                                   0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0,};

//    bool bool_array_list_64[FLOATINGPOINT64_BITS] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//                                                   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
//    bool bool_array_list_64[FLOATINGPOINT64_BITS] = {0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//                                                   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,};
//
//
//    FLType int_output__ = bool_array_to_int(bool_array_list_64, FLOATINGPOINT64_BITS);
//    std::cout << "int_output__: " << int_output__ << std::endl;
//
//    std::cout << "bitset: " << std::bitset<64>(int_output__) << std::endl;
//
//    double double_output = bool_array_to_double(bool_array_list_64, FLOATINGPOINT64_BITS);
//    std::cout << "double_output: " << double_output << std::endl;
//

//    FLType int_input = 23464532346;
//    bool bool_array[FLOATINGPOINT64_BITS];
//    int_to_bool_array(int_input, bool_array);
//    unsigned i;
//    for (i = 0; i < FLOATINGPOINT64_BITS; i++) {
//        std::cout << bool_array[i];
//    }
//    std::cout << std::endl;



//// ============================================================
//    double lambda = 4.5;
//    FLType m = get_smallest_greater_or_eq_power_of_two(double_to_int(lambda));
//
//    std::cout << "m: " << m << std::endl;

// ============================================================

//    double x = 3;
//    FLType m = 5;
//    FLType x_div_pow2_m[3];
//    divide_by_power_of_two(double_to_int(x), m, x_div_pow2_m);
//    double x_div_pow2_m_double = int_to_double(x_div_pow2_m[0] ^ x_div_pow2_m[1] ^ x_div_pow2_m[2]);
//    std::cout << "x_div_pow2_m_double: " << x_div_pow2_m_double << std::endl;
//    std::cout << "expect result: " << x / pow(2, m) << std::endl;

// ============================================================

//    FLType m = 5;
//    double x = 30002300.2345;
////    double x_div_pow2_m = x / pow(2, m);
//    double x_div_pow2_m = 2097151.99999999976716935634613;
//    std::cout.precision(20);
//    std::cout << "x_div_pow2_m: " << x_div_pow2_m << std::endl;
//    FLType x_round_to_nearest_int[3];
//    round_to_nearest_int(double_to_int(x_div_pow2_m), x_round_to_nearest_int);
//
//    std::cout << "x_round_to_nearest_int: " << int_to_double(x_round_to_nearest_int[0] ^ x_round_to_nearest_int[1] ^ x_round_to_nearest_int[2])
//              << std::endl;
//    std::cout << "expect result x_round_to_nearest_int: " << round(x_div_pow2_m)
//              << std::endl;


// ============================================================

//    FLType m = 5;
//    double x = 30002300.2345;
////    double x_div_pow2_m = x / pow(2, m);
//    double x_div_pow2_m = -20971.549999999976716935634613;
//    std::cout.precision(20);
//    std::cout << "x_div_pow2_m: " << x_div_pow2_m << std::endl;
//    FLType x_mask =1;
//   FLType result = round_to_nearest_integer_CBMC(double_to_int(x_div_pow2_m), x_mask);
//
//    std::cout << "round_to_nearest_integer_CBMC: " << int_to_double(result^x_mask)
//              << std::endl;
//    std::cout << "expect result x_round_to_nearest_int: " << round(x_div_pow2_m)
//              << std::endl;





//// ============================================================
//for(std::size_t i =0;i<100;i++) {
//    std::srand(std::time(nullptr)+i);
//    std::size_t FLOATINGPOINT32_MANTISSA_BITS = 23;
//    std::size_t FLOATINGPOINT32_EXPONENT_BIAS = 127;
//
//    std::vector<bool> random_bit_mantissa_23(FLOATINGPOINT32_MANTISSA_BITS);
//    std::vector<bool> random_bit_exponent_126(FLOATINGPOINT32_EXPONENT_BIAS - 1);
//
//    random_bit_mantissa_23 = rand_bool_vector(FLOATINGPOINT32_MANTISSA_BITS);
//    random_bit_exponent_126 = rand_bool_vector(FLOATINGPOINT32_EXPONENT_BIAS - 1);
//
//    float uniform_floating_point32 = uniform_floating_point32_0_1(random_bit_mantissa_23, random_bit_exponent_126);
//
//    std::cout << "uniform_floating_point32: " << uniform_floating_point32 << std::endl;


// ============================================================

//    FLType random_bits = 9223372036854775809;
//    unsigned hamming_weight = geometric_sample(random_bits);
//    std::cout<<"hamming_weight: "<<hamming_weight<<std::endl;


//    std::vector<bool> random_bit_mantissa(FLOATINGPOINT64_MANTISSA_BITS);
//    std::vector<bool> random_bit_exponent(FLOATINGPOINT64_EXPONENT_BIAS - 1);
////
//    random_bit_mantissa = rand_bool_vector(FLOATINGPOINT64_MANTISSA_BITS);
//    random_bit_exponent = rand_bool_vector(FLOATINGPOINT64_EXPONENT_BIAS - 1);
////
//    double uniform_floating_point = uniform_floating_point64_0_1(random_bit_mantissa, random_bit_exponent);
//
//    std::cout << "uniform_floating_point: " << uniform_floating_point << std::endl;
//}


//    double fD = 2;
//    double clamp_B = 1.8;
//    bool S = 0;
//    double lambda = 0.1;
//    double uniform_floating_point64_0_1 = 0.1;
//
////    FLType round_to_multiple_of_sigma = get_closest_multiple_of_sigma(double_to_int(lambda), double_to_int(fD));
////    std::cout << "round_to_multiple_of_sigma: " << int_to_double(round_to_multiple_of_sigma) << std::endl;
//
//
//    double snapping_mechanism_result = snapping_mechanism(fD, clamp_B,S,lambda,uniform_floating_point64_0_1);
//
//    std::cout<<"snapping_mechanism_result: "<<snapping_mechanism_result<<std::endl;

// ============================================================
////
//    FLType L0 = 0;
//    FLType R0 = INT64_MAX;
//    double lambda = 0.01;
//    std::size_t iterations = log2(R0 - L0);
//    std::vector<double> uniform_floating_point_0_1_vector(iterations);
//    for (std::size_t i = 0; i < iterations; i++) {
//        uniform_floating_point_0_1_vector[i] = rand_range_double(0, 1);
//    }
//
//    std::vector<double> random_bool_vector(iterations);
//    for (std::size_t i = 0; i < iterations; i++) {
//        random_bool_vector[i] = rand_range_double(0, 1) > 0.5;
//    }
//
//    FLType geometric_sampling_binary_search_result = geometric_sampling_binary_search(L0, R0, lambda, iterations, uniform_floating_point_0_1_vector);
//
//    std::cout << "geometric_sampling_binary_search_result: " << geometric_sampling_binary_search_result << std::endl;


    // ==========
//    std::size_t iterations = 50;
//    std::srand(std::time(nullptr));
//    std::vector<double> uniform_floating_point_0_1_vector(iterations);
//    for (std::size_t i = 0; i < iterations; i++) {
//        uniform_floating_point_0_1_vector[i] = rand_range_double(0, 1);
//    }
//
//    std::vector<double> random_bool_vector(iterations);
//    for (std::size_t i = 0; i < iterations; i++) {
//        random_bool_vector[i] = rand_range_double(0, 1) > 0.5;
//    }
//
//    double gamma = rand_range_double(0, 1);
//    std::vector<bool> Bernoulli_distribution_EXP1_result = Bernoulli_distribution_EXP_0_1(gamma, uniform_floating_point_0_1_vector);
//    std::cout << "Bernoulli_distribution_EXP_0_1_result[0]: " << Bernoulli_distribution_EXP1_result[0] << std::endl;
//    std::cout << "Bernoulli_distribution_EXP_0_1_result[1]: " << Bernoulli_distribution_EXP1_result[1] << std::endl;
//
//
//    double gamma = rand_range_double(0, 10);
//    double upper_bound_gamma = gamma+1;
//    std::cout << "gamma: " << gamma << std::endl;
//    std::vector<bool> Bernoulli_distribution_EXP_1_result = Bernoulli_distribution_EXP_1(gamma,upper_bound_gamma, uniform_floating_point_0_1_vector);
//    std::cout << "Bernoulli_distribution_EXP_1[0]: " << Bernoulli_distribution_EXP_1_result[0] << std::endl;
//    std::cout << "Bernoulli_distribution_EXP_1[1]: " << Bernoulli_distribution_EXP_1_result[1] << std::endl;

//     ==========
//    std::srand(std::time(nullptr));
//    double scale = 0.8;
//    std::uint64_t numerator = decimalToFraction(1 / scale)[0];
//    std::uint64_t denominator = decimalToFraction(1 / scale)[1];
//
//    std::cout << "numerator: " << numerator << std::endl;
//    std::cout << "denominator: " << denominator << std::endl;
//
//    std::vector<long double> optimize_geometric_distribution_EXP_iteration_result_vector = optimize_geometric_distribution_EXP_iteration<std::uint64_t>(
//            numerator, denominator, standard_failure_probability);
//
//    std::size_t iteration_1 = optimize_geometric_distribution_EXP_iteration_result_vector[0];
//    std::size_t iteration_2 = optimize_geometric_distribution_EXP_iteration_result_vector[1];
//    std::size_t total_iteration = optimize_geometric_distribution_EXP_iteration_result_vector[2];
//    long double total_failure_probability = optimize_geometric_distribution_EXP_iteration_result_vector[3];
//
//    if (denominator == 1) {
//        iteration_1 = 0;
//    }
//
////
//    for (std::size_t j = 0; j < 50; j++) {
//        std::vector<double> uniform_floating_point_0_1_vector = rand_range_double_vector(0, 1, iteration_1 + iteration_2);
//
//        std::vector<std::uint64_t> random_integer_vector = rand_range_integer_vector<std::uint64_t>(0, denominator, iteration_1);
//
//        if (denominator != 1) {
//            std::vector<std::uint64_t> geometric_distribution_EXP_result = geometric_distribution_EXP<std::uint64_t, std::allocator<std::uint64_t>>(
//                    numerator, denominator, uniform_floating_point_0_1_vector, random_integer_vector, iteration_1, iteration_2);
//            std::cout << "geometric_distribution_EXP_result[0]: " << geometric_distribution_EXP_result[0] << std::endl;
//            std::cout << "geometric_distribution_EXP_result[1]: " << geometric_distribution_EXP_result[1] << std::endl;
//        } else {
//            std::vector<std::uint64_t> geometric_distribution_EXP_result = geometric_distribution_EXP<std::uint64_t, std::allocator<std::uint64_t>>(
//                    numerator, uniform_floating_point_0_1_vector, iteration_2);
//            std::cout << "geometric_distribution_EXP_result[0]: " << geometric_distribution_EXP_result[0] << std::endl;
//            std::cout << "geometric_distribution_EXP_result[1]: " << geometric_distribution_EXP_result[1] << std::endl;
//        }
//    }

    // ==========
//    std::srand(std::time(nullptr));
//    double scale = 4;
////    std::uint64_t numerator = decimalToFraction(1 / scale)[0];
////    std::uint64_t denominator = decimalToFraction(1 / scale)[1];
//    std::uint64_t numerator = 1;
//    std::uint64_t denominator = 6;
//
//    std::cout << "numerator: " << numerator << std::endl;
//    std::cout << "denominator: " << denominator << std::endl;
//
//    std::vector<long double> optimize_discrete_laplace_distribution_EXP_iteration_result_vector = optimize_discrete_laplace_distribution_EXP_iteration<std::uint64_t>(
//            numerator, denominator, standard_failure_probability);
//    std::size_t iteration_1 = optimize_discrete_laplace_distribution_EXP_iteration_result_vector[0];
//    std::size_t iteration_2 = optimize_discrete_laplace_distribution_EXP_iteration_result_vector[1];
//    std::size_t iteration_3 = optimize_discrete_laplace_distribution_EXP_iteration_result_vector[2];
//    std::size_t total_iteration = optimize_discrete_laplace_distribution_EXP_iteration_result_vector[3];
//    long double total_failure_probability = optimize_discrete_laplace_distribution_EXP_iteration_result_vector[4];
//
//    if (denominator == 1) {
//        iteration_1 = 0;
//    }
////
//    for (std::size_t j = 0; j < 50; j++) {
//        std::vector<double> uniform_floating_point_0_1_vector((iteration_1 + iteration_2) * iteration_3);
//        for (std::size_t i = 0; i < (iteration_1 + iteration_2) * iteration_3; i++) {
//            uniform_floating_point_0_1_vector[i] = rand_range_double(0, 1);
//        }
//
//        std::vector<std::uint64_t> random_integer_vector(iteration_1 * iteration_3);
//        for (std::size_t i = 0; i < iteration_1 * iteration_3; i++) {
//            random_integer_vector[i] = rand_range_double(0, denominator);
////        std::cout<<"random_integer_vector[i]: "<<random_integer_vector[i]<<std::endl;
//        }
//
//        std::vector<bool> bernoulli_sample_vector(iteration_3);
//        for (std::size_t i = 0; i < iteration_3; i++) {
//            bernoulli_sample_vector[i] = rand_range_double(0, 1) < 0.5;
////        std::cout<<"bernoulli_sample_vector[i]: "<<bernoulli_sample_vector[i]<<std::endl;
//        }
//
//        if (denominator != 1) {
//            std::vector<std::uint64_t> discrete_laplace_distribution_EXP_result = discrete_laplace_distribution_EXP<std::uint64_t, std::allocator<std::uint64_t>>(
//                    numerator, denominator, uniform_floating_point_0_1_vector, random_integer_vector, bernoulli_sample_vector, iteration_1,
//                    iteration_2, iteration_3);
//            std::cout << "discrete_laplace_distribution_EXP_result[0]: " << std::int64_t(discrete_laplace_distribution_EXP_result[0]) << std::endl;
////            std::cout << "discrete_laplace_distribution_EXP_result[1]: " << discrete_laplace_distribution_EXP_result[1] << std::endl;
//        } else {
//            std::vector<std::uint64_t> discrete_laplace_distribution_EXP_result = discrete_laplace_distribution_EXP<std::uint64_t, std::allocator<std::uint64_t>>(
//                    numerator, uniform_floating_point_0_1_vector, bernoulli_sample_vector, iteration_2, iteration_3);
//            std::cout << "discrete_laplace_distribution_EXP_result[0]: " << std::int64_t(discrete_laplace_distribution_EXP_result[0]) << std::endl;
////            std::cout << "discrete_laplace_distribution_EXP_result[1]: " << discrete_laplace_distribution_EXP_result[1] << std::endl;
//        }
//    }
//    // ==========
//
//    std::srand(std::time(nullptr));
//    double sigma = 1.5;
//    std::uint64_t t = floor(sigma) + 1;
//    std::cout << "t: " << t << std::endl;
//
//    std::vector<long double> optimize_discrete_gaussian_distribution_EXP_iteration_result_vector = optimize_discrete_gaussian_distribution_EXP_iteration<std::uint64_t, std::int64_t>(
//            sigma, standard_failure_probability);
//    std::size_t iteration_1 = optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[0];
//    std::size_t iteration_2 = optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[1];
//    std::size_t iteration_3 = optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[2];
//    std::size_t iteration_4 = optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[3];
//    std::size_t total_iteration = optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[4];
//    long double total_failure_probability = optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[5];
//
//    if (t == 1) {
//        iteration_1 = 0;
//    }
//
//    for (std::size_t j = 0; j < 50; j++) {
//        std::vector<double> random_floating_point_0_1_dlap_vector = rand_range_double_vector(0, 1,
//                                                                                             (iteration_1 + iteration_2) * iteration_3 * iteration_4);
//
//        std::vector<std::uint64_t> random_integer_dlap_vector = rand_range_integer_vector<std::uint64_t>(0, t,
//                                                                                                         iteration_1 * iteration_3 * iteration_4);
//
//        std::vector<bool> bernoulli_sample_dlap_vector = rand_bool_vector(iteration_3 * iteration_4);
//
//        std::vector<double> random_floating_point_0_1_dgau_vector = rand_range_double_vector(0, 1, iteration_4);
//
//        if (t != 1) {
//            std::vector<std::uint64_t> discrete_gaussian_distribution_EXP_result = discrete_gaussian_distribution_EXP<std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
//                    sigma, random_floating_point_0_1_dlap_vector, random_integer_dlap_vector, bernoulli_sample_dlap_vector,
//                    random_floating_point_0_1_dgau_vector, iteration_1, iteration_2, iteration_3, iteration_4);
//            std::cout << "discrete_gaussian_distribution_EXP_result[0]: " << std::int64_t(discrete_gaussian_distribution_EXP_result[0]) << std::endl;
////            std::cout << "discrete_gaussian_distribution_EXP_result[1]: " << discrete_gaussian_distribution_EXP_result[1] << std::endl;
//        } else {
//            std::vector<std::uint64_t> discrete_gaussian_distribution_EXP_result = discrete_gaussian_distribution_EXP<std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
//                    sigma, random_floating_point_0_1_dlap_vector, bernoulli_sample_dlap_vector, random_floating_point_0_1_dgau_vector, iteration_2,
//                    iteration_3, iteration_4);
//            std::cout << "discrete_gaussian_distribution_EXP_result[0]: " << std::int64_t(discrete_gaussian_distribution_EXP_result[0]) << std::endl;
////            std::cout << "discrete_gaussian_distribution_EXP_result[1]: " << discrete_gaussian_distribution_EXP_result[1] << std::endl;
//        }
//    }
    // ==========
//    // ==========
//
//    std::srand(std::time(nullptr));
//    double sigma = 1.5;
//    std::uint64_t t = floor(sigma) + 1;
//    std::cout << "t: " << t << std::endl;
//
//    std::vector<long double> optimize_discrete_gaussian_distribution_EXP_with_discrete_laplace_EKMPP_iteration_result_vector = optimize_discrete_gaussian_distribution_EXP_with_discrete_laplace_EKMPP_iteration<std::uint64_t, std::int64_t>(
//            sigma, standard_failure_probability);
//    std::size_t iteration = optimize_discrete_gaussian_distribution_EXP_with_discrete_laplace_EKMPP_iteration_result_vector[0];
//    std::size_t total_iteration = optimize_discrete_gaussian_distribution_EXP_with_discrete_laplace_EKMPP_iteration_result_vector[1];
//    long double total_failure_probability = optimize_discrete_gaussian_distribution_EXP_with_discrete_laplace_EKMPP_iteration_result_vector[3];
//
//    for (std::size_t j = 0; j < 50; j++) {
//
//        std::vector<std::uint64_t> discrete_laplace_sample_vector = rand_range_integer_vector<std::uint64_t>(-5, 5, iteration);
//        for(std::size_t i = 0; i < iteration; i++){
////            std::cout<<std::int64_t((discrete_laplace_sample_vector)[i])<<std::endl;
//        }
//
//        std::vector<double> random_floating_point_0_1_dgau_vector = rand_range_double_vector(0, 1, iteration);
//
//        std::vector<std::uint64_t> discrete_gaussian_distribution_EXP_with_discrete_laplace_EKMPP_result = discrete_gaussian_distribution_EXP_with_discrete_Laplace_EKMPP<std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
//                sigma, discrete_laplace_sample_vector, random_floating_point_0_1_dgau_vector, iteration);
//        std::cout << "discrete_gaussian_distribution_EXP_with_discrete_laplace_EKMPP_result[0]: "
//                  << std::int64_t(discrete_gaussian_distribution_EXP_with_discrete_laplace_EKMPP_result[0]) << std::endl;
////        std::cout << "discrete_gaussian_distribution_EXP_with_discrete_laplace_EKMPP_result[1]: " << discrete_gaussian_distribution_EXP_with_discrete_laplace_EKMPP_result[1] << std::endl;
//}
// ==========

//    std::size_t iterations = 50;
//    std::srand(std::time(nullptr));
//    double sqrt_n = double(std::uint64_t(1) << 48);
//    double m = floor(M_SQRT2 * sqrt_n + 1);
//
//    std::cout<<"sqrt_n: "<<sqrt_n<<std::endl;
//    std::cout<<"m: "<<m<<std::endl;
//
//    std::vector<std::uint64_t> signed_integer_geometric_sample_vector(iterations);
//    for (std::size_t i = 0; i < iterations; i++) {
//        signed_integer_geometric_sample_vector[i] = rand_range_double(0, 0);
//    }
//
//    std::vector<bool> random_bits_vector(iterations);
//    for (std::size_t i = 0; i < iterations; i++) {
//        random_bits_vector[i] = rand_range_double(0, 1) < 0.5;
////        std::cout<<"bernoulli_sample_vector[i]: "<<bernoulli_sample_vector[i]<<std::endl;
//    }
//
//    std::vector<std::uint64_t> random_unsigned_integer_vector(iterations);
//    for (std::size_t i = 0; i < iterations; i++) {
//        random_unsigned_integer_vector[i] = rand_range_double(0, m);
//
////        // only for debug
////        random_unsigned_integer_vector[i] =0;
//    }
//
//    std::vector<double> random_floating_point_0_1_vector(iterations);
//    for (std::size_t i = 0; i < iterations; i++) {
//        random_floating_point_0_1_vector[i] = rand_range_double(0, 1);
//    }
//
//    std::vector<std::uint64_t> symmetrical_binomial_distribution_result = symmetrical_binomial_distribution<std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(
//            sqrt_n, signed_integer_geometric_sample_vector, random_bits_vector, random_unsigned_integer_vector,
//            random_floating_point_0_1_vector, iterations);
//    std::cout << "symmetrical_binomial_distribution[0]: " << std::int64_t(symmetrical_binomial_distribution_result[0]) << std::endl;
//    std::cout << "symmetrical_binomial_distribution[1]: " << symmetrical_binomial_distribution_result[1] << std::endl;

//    // ==========

//    double double_number = 0.643;
// std::vector<double> fraction_result_vector=    decimalToFraction(double_number);
//std::cout << "numerator: " << fraction_result_vector[0]<<std::endl;
//std::cout << "denominator: " << fraction_result_vector[1]<<std::endl;
//
//
//
//
////    // ==========

//    std::uint64_t numerator = 1;
//    std::uint64_t denominator = 3;
//
//    std::vector<long double> optimize_geometric_distribution_EXP_iteration_result_vector = optimize_geometric_distribution_EXP_iteration<std::uint64_t>(
//            numerator, denominator, standard_failure_probability);
//
//    std::cout << "optimize_geometric_distribution_EXP_iteration_result_vector[0]: " << optimize_geometric_distribution_EXP_iteration_result_vector[0]
//              << std::endl;
//    std::cout << "optimize_geometric_distribution_EXP_iteration_result_vector[1]: " << optimize_geometric_distribution_EXP_iteration_result_vector[1]
//              << std::endl;
//    std::cout << "optimize_geometric_distribution_EXP_iteration_result_vector[2]: " << optimize_geometric_distribution_EXP_iteration_result_vector[2]
//              << std::endl;
//    std::cout << "optimize_geometric_distribution_EXP_iteration_result_vector[3]: " << optimize_geometric_distribution_EXP_iteration_result_vector[3]
//              << std::endl;
////
////// ==========
////
////

//double scale = 0.01;
//std::uint64_t numerator = decimalToFraction(scale)[0];
//std::uint64_t denominator = decimalToFraction(scale)[1];
////    std::uint64_t numerator =100;
////    std::uint64_t denominator=400;
//
//long double discrete_laplace_distribution_EXP_failure_probability_estimation_result = discrete_laplace_distribution_EXP_failure_probability_estimation(
//        numerator, denominator, 0, 2, 49);
//
//std::cout << "discrete_laplace_distribution_EXP_failure_probability_estimation_result: "
//<< discrete_laplace_distribution_EXP_failure_probability_estimation_result <<
//std::endl;
//
//std::uint64_t numerator_dlap = 2;
//std::uint64_t denominator_dlap = 3;
//std::vector<long double> optimize_discrete_laplace_distribution_EXP_iteration_result_vector = optimize_discrete_laplace_distribution_EXP_iteration<std::uint64_t>(
//        numerator, denominator, standard_failure_probability);
//
//std::cout << "optimize_discrete_laplace_distribution_EXP_iteration_result_vector[0]: "
//<< optimize_discrete_laplace_distribution_EXP_iteration_result_vector[0] <<
//std::endl;
//std::cout << "optimize_discrete_laplace_distribution_EXP_iteration_result_vector[1]: "
//<< optimize_discrete_laplace_distribution_EXP_iteration_result_vector[1] <<
//std::endl;
//std::cout << "optimize_discrete_laplace_distribution_EXP_iteration_result_vector[2]: "
//<< optimize_discrete_laplace_distribution_EXP_iteration_result_vector[2] <<
//std::endl;
//std::cout << "optimize_discrete_laplace_distribution_EXP_iteration_result_vector[3]: "
//<< optimize_discrete_laplace_distribution_EXP_iteration_result_vector[3] <<
//std::endl;
//std::cout << "optimize_discrete_laplace_distribution_EXP_iteration_result_vector[4]: "
//<< optimize_discrete_laplace_distribution_EXP_iteration_result_vector[4] <<
//std::endl;
//


// ================================================================
//    double sigma = 1.25;
//    std::vector<long double> discrete_gaussian_distribution_EXP_failure_probability_estimation_result_vector = discrete_gaussian_distribution_EXP_failure_probability_estimation<std::uint64_t, std::int64_t>(
//            sigma, 1, 1, 3, 1);
//    std::cout << "discrete_gaussian_distribution_EXP_failure_probability_estimation_result_vector[0]: "
//              << discrete_gaussian_distribution_EXP_failure_probability_estimation_result_vector[0] << std::endl;
//
//    std::vector<long double> optimize_discrete_gaussian_distribution_EXP_iteration_result_vector = optimize_discrete_gaussian_distribution_EXP_iteration<std::uint64_t, std::int64_t>(
//            sigma, standard_failure_probability);
//    std::cout << "optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[0]: "
//              << optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[0] << std::endl;
//    std::cout << "optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[1]: "
//              << optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[1] << std::endl;
//    std::cout << "optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[2]: "
//              << optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[2] << std::endl;
//    std::cout << "optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[3]: "
//              << optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[3] << std::endl;
//    std::cout << "optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[4]: "
//              << optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[4] << std::endl;
//    std::cout << "optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[5]: "
//              << optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[5] << std::endl;
////
//
//
//
//
//
//
//
//
////
////// ============================================================
////
//    long double iteration = 1;
//    long double sqrt_n = powl(2.0, 48);
//    std::vector<long double> symmetrical_binomial_distribution_failure_probability_estimation_result_vector = symmetrical_binomial_distribution_failure_probability_estimation(
//            sqrt_n, iteration);
//    std::cout << "symmetrical_binomial_distribution_failure_probability_estimation_result_vector[0]: "
//              << symmetrical_binomial_distribution_failure_probability_estimation_result_vector[0] << std::endl;
//
//    std::vector<long double> optimize_symmetrical_binomial_distribution_iteration_result_vector = optimize_symmetrical_binomial_distribution_iteration(
//            sqrt_n, standard_failure_probability);
//    std::cout << "optimize_symmetrical_binomial_distribution_iteration_result_vector[0]: "
//              << optimize_symmetrical_binomial_distribution_iteration_result_vector[0] << std::endl;
//    std::cout << "optimize_symmetrical_binomial_distribution_iteration_result_vector[1]: "
//              << optimize_symmetrical_binomial_distribution_iteration_result_vector[1] << std::endl;


//    double a_double =0.006543;
//
//    double a_double_ceil_power_of_two = ceil_power_of_two(a_double);
//    std::cout << "a_double_ceil_power_of_two: " << a_double_ceil_power_of_two << std::endl;


// ============================================================
//    std::uint64_t numerator = 2;
//    std::uint64_t denominator = 1;
//
//    std::vector<std::uint64_t> geometric_noise_vector = geometric_noise_generation<std::uint64_t, std::int64_t>(numerator, denominator,
//                                                                                                                standard_failure_probability, 50);
//
//    for (std::size_t i = 0; i < 50; i++) {
//        std::cout << "geometric_noise_vector: " << std::uint64_t(geometric_noise_vector[i]) << std::endl;
//    }


// ============================================================

//    std::srand(std::time(nullptr));
//    double scale = 2;
//    std::size_t num_of_elements = 100;
//    std::vector<std::uint64_t> discrete_laplace_noise_vector = discrete_laplace_noise_generation<std::uint64_t, std::int64_t>(scale,
//                                                                                                                              standard_failure_probability,
//                                                                                                                              num_of_elements);
//
//    for (std::size_t i = 0; i < num_of_elements; i++) {
//        std::cout << "discrete_laplace_noise_vector: " << std::int64_t(discrete_laplace_noise_vector[i]) << std::endl;
//    }

//





// ============================================================

//    double sigma = 1;
//
//    std::vector<std::uint64_t> discrete_gaussian_noise_vector = discrete_gaussian_noise_generation<std::uint64_t, std::int64_t>(sigma,
//                                                                                                                                standard_failure_probability,
//                                                                                                                                50);
//
//    for (std::size_t i = 0; i < 50; i++) {
//        std::cout << "discrete_gaussian_noise: " << std::int64_t(discrete_gaussian_noise_vector[i]) << std::endl;
//    }






// ============================================================


//    std::srand(std::time(nullptr));
//
//    double sensitivity_l1 = 1;
//    double epsilon = 1;
//    std::size_t num_of_simd_lap = 1;
//    for (std::size_t i = 0; i < 50; i++) {
//        double integer_scaling_laplace_noise = integer_scaling_laplace_noise_generation(sensitivity_l1, epsilon, num_of_simd_lap,
//                                                                                        standard_failure_probability);
//        std::cout << "integer_scaling_laplace_noise: " << integer_scaling_laplace_noise << std::endl;
//    }


    return 0;
}
