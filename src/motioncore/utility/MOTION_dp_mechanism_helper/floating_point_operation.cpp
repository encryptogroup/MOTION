#include "floating_point_operation.h"
#include <bitset>
#include <cmath>

template<typename T, typename A>
std::vector<T, A> FloatingPointDecomposeToVector(double floating_point_number, std::size_t l, std::size_t k) {
    std::size_t size_of_T = sizeof(T) * 8;

    double mantissa;
    int exponent;
    mantissa = std::frexp(std::abs(floating_point_number), &exponent);

    // convert mantissa to field [1,2)
    mantissa = mantissa * 2;
    exponent = exponent - 1;

    T v = mantissa * (T(1) << (T(l) - 1));

    // T p = T(exponent - T(l) + T(1));

    // only for debug
    T p = T(exponent - int(l) + int(1));

    T s = floating_point_number < 0;
    T z = floating_point_number == 0;

    if (z) {
        v = 0;
        p = 0;
        s = 0;
    }

    // std::cout << floating_point_number << " = " << mantissa << " * 2^" << exponent << '\n';

    // print_u128_u("mantissa: ", v);
    // print_u128_u("exponent: ", p);
    // std::cout << "std::int64_t(exponent): " << std::int64_t(p) << std::endl;
    // print_u128_u("sign: ", s);
    // print_u128_u("zero: ", z);

    std::vector<T, A> floating_point_decomposition_result;
    floating_point_decomposition_result.reserve(4);
    floating_point_decomposition_result.emplace_back(v);
    floating_point_decomposition_result.emplace_back(p);
    floating_point_decomposition_result.emplace_back(z);
    floating_point_decomposition_result.emplace_back(s);

    return floating_point_decomposition_result;
}

template std::vector<std::uint64_t, std::allocator<std::uint64_t>>
FloatingPointDecomposeToVector<std::uint64_t, std::allocator<std::uint64_t>>(double floating_point_number, std::size_t l, std::size_t k);

template std::vector<__uint128_t, std::allocator<__uint128_t>>
FloatingPointDecomposeToVector<__uint128_t, std::allocator<__uint128_t>>(double floating_point_number, std::size_t l, std::size_t k);

template<typename T>
FloatingPointStruct<T> FloatingPointDecomposeToStruct(double floating_point_number, std::size_t l, std::size_t k) {
    std::size_t size_of_T = sizeof(T) * 8;

    double mantissa;
    int exponent;
    mantissa = std::frexp(std::abs(floating_point_number), &exponent);

    // convert mantissa to field [1,2)
    mantissa = mantissa * 2;
    exponent = exponent - 1;

    T v = mantissa * (T(1) << (T(l) - 1));
    T p = T(exponent - T(l) + T(1));
    T s = floating_point_number < 0;
    T z = floating_point_number == 0;

    if (z) {
        v = 0;
        p = 0;
        s = 0;
    }

    // std::cout << floating_point_number << " = " << mantissa << " * 2^" << exponent << '\n';

    // print_u128_u("mantissa: ", v);
    // print_u128_u("exponent: ", p);
    // std::cout << "std::int64_t(exponent): " << std::int64_t(p) << std::endl;
    // print_u128_u("sign: ", s);
    // print_u128_u("zero: ", z);

    FloatingPointStruct<T> result_struct;
    result_struct.mantissa = v;
    result_struct.exponent = p;
    result_struct.zero = z;
    result_struct.sign = s;

    return result_struct;
}

template FloatingPointStruct<std::uint64_t> FloatingPointDecomposeToStruct<std::uint64_t>(double floating_point_number, std::size_t l, std::size_t k);

template FloatingPointStruct<__uint128_t> FloatingPointDecomposeToStruct<__uint128_t>(double floating_point_number, std::size_t l, std::size_t k);

template<typename T>
FloatingPointVectorStruct<T> FloatingPointDecomposeToStruct(const std::vector<double> &floating_point_number_vector, std::size_t l, std::size_t k) {
    std::size_t size_of_T = sizeof(T) * 8;
    std::size_t num_of_simd = floating_point_number_vector.size();
    FloatingPointVectorStruct<T> result_vector_struct;
    result_vector_struct.num_of_simd = num_of_simd;

    for (std::size_t i = 0; i < num_of_simd; i++) {
        double mantissa;
        int exponent;
        mantissa = std::frexp(std::abs(floating_point_number_vector[i]), &exponent);

        // convert mantissa to field [1,2)
        mantissa = mantissa * 2;
        exponent = exponent - 1;

        T v = mantissa * (T(1) << (T(l) - 1));
        T p = T(exponent - T(l) + T(1));
        T s = floating_point_number_vector[i] < 0;
        T z = floating_point_number_vector[i] == 0;

        if (z) {
            v = 0;
            p = 0;
            s = 0;
        }

        // std::cout << floating_point_number << " = " << mantissa << " * 2^" << exponent << '\n';

        // print_u128_u("mantissa: ", v);
        // print_u128_u("exponent: ", p);
        // std::cout << "std::int64_t(exponent): " << std::int64_t(p) << std::endl;
        // print_u128_u("sign: ", s);
        // print_u128_u("zero: ", z);

        // FloatingPointVectorStruct<T> result_vector_struct;
        result_vector_struct.mantissa.emplace_back(v);
        result_vector_struct.exponent.emplace_back(p);
        result_vector_struct.zero.emplace_back(z);
        result_vector_struct.sign.emplace_back(s);
    }

    return result_vector_struct;
}

template FloatingPointVectorStruct<std::uint64_t>
FloatingPointDecomposeToStruct<std::uint64_t>(const std::vector<double> &floating_point_number_vector, std::size_t l, std::size_t k);

template FloatingPointVectorStruct<__uint128_t>
FloatingPointDecomposeToStruct<__uint128_t>(const std::vector<double> &floating_point_number_vector, std::size_t l, std::size_t k);

template<typename T, typename A>
std::vector<T, A> CreateFloatingPointVector(T v, T p, T z, T s, std::size_t l, std::size_t k) {
    std::vector<T> floating_point_vector;
    floating_point_vector.emplace_back(v);
    floating_point_vector.emplace_back(p);
    floating_point_vector.emplace_back(z);
    floating_point_vector.emplace_back(s);
    return floating_point_vector;
}

template<typename T>
FloatingPointStruct<T> CreateFloatingPointStruct(T v, T p, T z, T s, std::size_t l, std::size_t k) {
    FloatingPointStruct<T> floating_point_struct;
    floating_point_struct.mantissa = v;
    floating_point_struct.exponent = p;
    floating_point_struct.zero = z;
    floating_point_struct.sign = s;
    floating_point_struct.l = l;
    floating_point_struct.k = k;
    return floating_point_struct;
}

template<typename T, typename A>
double FloatingPointToDouble(T v, T p, T z, T s, std::size_t l, std::size_t k) {
    // std::cout<<"FloatingPointToDouble"<<std::endl;
    //    double result = double(v) * (pow(2, std::int64_t(p))) * (1 - double(z)) * (1 - 2 *
    //    double(s));
    // double mantissa = double(v) / double(T(1) << (l));
    // double result = std::ldexp(mantissa, std::int64_t(__int128_t(p)) + std::int64_t(l));

    double mantissa = double(std::int64_t(v));
    double result = std::ldexp(mantissa, std::int64_t(p));

    // only for debugging
    // std::cout<<"l: "<<l << std::endl;
    // std::cout << "std::int64_t(p): " << (std::int64_t((__int128_t(p)))) << std::endl;
    // std::cout << "std::int64_t(p) + std::int64_t(l): " << (std::int64_t((p)) + std::int64_t(l)) <<
    // std::endl; std::cout << "mantissa: " << mantissa << std::endl; std::cout << "result: " <<
    // result << std::endl; std::cout<<"result: "<<(std::ldexp(mantissa, 54))<<std::endl;

    result = result * (1 - std::int64_t(z)) * (1 - 2 * std::int64_t(s));
    // std::cout << "result: " << result << std::endl;
    return result;
}

template double
FloatingPointToDouble<__uint128_t, std::allocator<__uint128_t>>(__uint128_t v, __uint128_t p, __uint128_t z, __uint128_t s, std::size_t l,
                                                                std::size_t k);

template<typename T, typename A>
std::vector<double>
FloatingPointToDouble(std::vector<T, A> v_vector, std::vector<T, A> p_vector, std::vector<T, A> z_vector, std::vector<T, A> s_vector, std::size_t l,
                      std::size_t k) {
    //    double result = double(v) * (pow(2, std::int64_t(p))) * (1 - double(z)) * (1 - 2 *
    //    double(s));
    std::size_t num_of_simd = v_vector.size();
    std::vector<double> result_vector;
    result_vector.reserve(num_of_simd);
    for (std::size_t i = 0; i < num_of_simd; ++i) {
        // double mantissa = double(v_vector[i]) / (T(1) << (l));
        // double result = std::ldexp(mantissa, std::int64_t(p_vector[i]) + std::int64_t(l));

        // TODO: retest other functions that rely on this function
        double mantissa = double(v_vector[i]);
        double result = std::ldexp(mantissa, std::int64_t(p_vector[i]));

        result_vector.emplace_back(result * (1 - std::int64_t(z_vector[i])) * (1 - 2 * std::int64_t(s_vector[i])));
    }
    return result_vector;
}

template std::vector<double>
FloatingPointToDouble<__uint128_t, std::allocator<__uint128_t>>(std::vector<__uint128_t> v_vector, std::vector<__uint128_t> p_vector,
                                                                std::vector<__uint128_t> z_vector, std::vector<__uint128_t> s_vector, std::size_t l,
                                                                std::size_t k);

template<typename T, typename A>
double FloatingPointToDouble(std::vector<T, A> floating_point_vector, std::size_t l, std::size_t k) {
    double result = FloatingPointToDouble<T, A>(floating_point_vector[0], floating_point_vector[1], floating_point_vector[2],
                                                floating_point_vector[3], l, k);
    return result;
}

template double
FloatingPointToDouble<__uint128_t, std::allocator<__uint128_t>>(std::vector<__uint128_t, std::allocator<__uint128_t>> floating_point_vector,
                                                                std::size_t l, std::size_t k);

template<typename T, typename A>
double FloatingPointToDouble(FloatingPointStruct<T> floating_point_struct, std::size_t l, std::size_t k) {
    double result = FloatingPointToDouble<T, A>(floating_point_struct.mantissa, floating_point_struct.exponent, floating_point_struct.zero,
                                                floating_point_struct.sign, l, k);
    return result;
}

template double FloatingPointToDouble<__uint128_t>(FloatingPointStruct<__uint128_t> floating_point_struct, std::size_t l, std::size_t k);

// template<typename T>
// std::vector<bool> BitDecompose(T x, std::size_t l) {
//     std::vector<bool> bit_decomposition_result;
//
//     for (std::size_t i = 0; i < l; i++) {
//         bit_decomposition_result. emplace_back()
//
//
//     }
// }

template<typename T, typename T_int, typename A>
std::vector<T, A> FloatingPointAddition_ABZS(T v1, T p1, T z1, T s1, T v2, T p2, T z2, T s2, std::size_t l, std::size_t k) {
    // p1, p2 are signed integer
    // bool a = p1 < p2;
    bool a = std::int64_t(p1) < std::int64_t(p2);
    bool b = p1 == p2;
    bool c = v1 < v2;

    T pmax = a * p2 + (1 - a) * p1;
    T pmin = (1 - a) * p2 + a * p1;

    T vmax = (1 - b) * (a * v2 + (1 - a) * v1) + b * (c * v2 + (1 - c) * v1);
    T vmin = (1 - b) * (a * v1 + (1 - a) * v2) + b * (c * v1 + (1 - c) * v2);

    bool s3 = s1 ^ s2;
    bool d = std::int64_t(T(l)) < (std::int64_t(pmax) - std::int64_t(pmin));

    T delta = (1 - d) * (pmax - pmin);
    T pow2_delta = pow(2, (1 - d) * (pmax - pmin));
    T v3 = 2 * (vmax - s3) + 1;

    T v4 = vmax * pow2_delta + (1 - 2 * s3) * vmin;
    T l_minus_delta = T(l) - delta;
    //    T v = (d * v3 + (1 - d) * v4) * T(pow(2, l)) / pow2_delta;
    T v = (d * v3 + (1 - d) * v4) * T(pow(2, T(l) - delta));
    //    T v = (d * v3 + (1 - d) * v4) * T(pow(2, l)) >> delta;

    T v_prime = v >> (T(l) - 1);

    T v_value = v_prime;
    unsigned msb_v_prime = 0;
    while (v_value >>= 1) {
        msb_v_prime++;
    }
    msb_v_prime++;
    msb_v_prime = T(l) + 2 - msb_v_prime;
    T p0 = msb_v_prime;

    T pow2_p0 = pow(2, p0);

    T v_prime_prime = (pow2_p0 * v_prime) >> 2;

    T p = pmax - p0 + 1 - d;

    T v_prime_prime_prime = (1 - z1) * (1 - z2) * v_prime_prime + z1 * v2 + z2 * v1;

    bool z = v_prime_prime_prime == 0;

    T p_prime = ((1 - z1) * (1 - z2) * p + z1 * p2 + z2 * p1) * (1 - z);

    T s = (1 - b) * (a * s2 + (1 - a) * s1) + b * (c * s2 + (1 - c) * s1);

    T s_prime = (1 - z1) * (1 - z2) * s + (1 - z1) * z2 * s1 + z1 * (1 - z2) * s2;

    std::vector<T, A> floating_point_addition_result;
    floating_point_addition_result.template emplace_back(v_prime_prime_prime);
    floating_point_addition_result.template emplace_back(p_prime);
    floating_point_addition_result.template emplace_back(z);
    floating_point_addition_result.template emplace_back(s_prime);

    // std::cout << "a: ";
    // print_u128_u(a);
    // std::cout << "b: ";
    // print_u128_u(b);
    // std::cout << "c: ";
    // print_u128_u(c);
    // std::cout << "pmax: ";
    // print_u128_u(pmax);
    // std::cout << "pmin: ";
    // print_u128_u(pmin);
    // std::cout << "vmax: ";
    // print_u128_u(vmax);
    // std::cout << "vmin: ";
    // print_u128_u(vmin);
    // std::cout << "s3: ";
    // print_u128_u(s3);
    // std::cout << "d: ";
    // print_u128_u(d);
    // std::cout << "delta: ";
    // print_u128_u(delta);
    // std::cout << "l - delta: ";
    // print_u128_u(l_minus_delta);
    // std::cout << "pow2_delta: ";
    // print_u128_u(pow2_delta);
    // std::cout << "v3: ";
    // print_u128_u(v3);
    // std::cout << "v4: ";
    // print_u128_u(v4);

    // print_u128_u("v1: ", v1);

    // std::cout << "v: ";
    // print_u128_u(v);
    // std::cout << "v_prime: ";
    // print_u128_u(v_prime);
    // std::cout << "p0: ";
    // print_u128_u(p0);
    // std::cout << "pow2_p0: ";
    // print_u128_u(pow2_p0);
    // std::cout << "v_prime_prime: ";
    // print_u128_u(v_prime_prime);
    // std::cout << "p: ";
    // print_u128_u(p);
    // std::cout << "s: ";
    // print_u128_u(s);
    // std::cout;

    return floating_point_addition_result;
}

template std::vector<std::uint64_t, std::allocator<std::uint64_t>>
FloatingPointAddition_ABZS<std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(std::uint64_t v1, std::uint64_t p1, std::uint64_t z1,
                                                                                       std::uint64_t s1, std::uint64_t v2, std::uint64_t p2,
                                                                                       std::uint64_t z2, std::uint64_t s2, std::size_t l,
                                                                                       std::size_t k);

template std::vector<__uint128_t, std::allocator<__uint128_t>>
FloatingPointAddition_ABZS<__uint128_t, __int128_t, std::allocator<__uint128_t>>(__uint128_t v1, __uint128_t p1, __uint128_t z1, __uint128_t s1,
                                                                                 __uint128_t v2, __uint128_t p2, __uint128_t z2, __uint128_t s2,
                                                                                 std::size_t l, std::size_t k);

template<typename T, typename T_int, typename A>
std::vector<T, A> FloatingPointSubtraction_ABZS(T v1, T p1, T z1, T s1, T v2, T p2, T z2, T s2, std::size_t l, std::size_t k) {
    std::vector<T, A> result = FloatingPointAddition_ABZS<T, T_int, A>(v1, p1, z1, s1, v2, p2, z2, 1 - s2, l, k);
    return result;
}

template std::vector<std::uint64_t, std::allocator<std::uint64_t>>
FloatingPointSubtraction_ABZS<std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(std::uint64_t v1, std::uint64_t p1, std::uint64_t z1,
                                                                                          std::uint64_t s1, std::uint64_t v2, std::uint64_t p2,
                                                                                          std::uint64_t z2, std::uint64_t s2, std::size_t l,
                                                                                          std::size_t k);

template std::vector<__uint128_t, std::allocator<__uint128_t>>
FloatingPointSubtraction_ABZS<__uint128_t, __int128_t, std::allocator<__uint128_t>>(__uint128_t v1, __uint128_t p1, __uint128_t z1, __uint128_t s1,
                                                                                    __uint128_t v2, __uint128_t p2, __uint128_t z2, __uint128_t s2,
                                                                                    std::size_t l, std::size_t k);

template<typename T>
T FloatingPointSimpleDivision_ABZS(T a, T b, std::size_t l, std::size_t k) {
    std::size_t theta = ceil(std::log2(T(l)));

    T x = b;
    T y = a;
    T constant_pow_l_plus_1 = (T(1) << (T(l) + 1));

    for (std::size_t i = 1; i < theta; i++) {
        y = y * (constant_pow_l_plus_1 - x);
        y = y >> T(l);
        x = x * (constant_pow_l_plus_1 - x);
        x = x >> T(l);
    }
    y = y * (constant_pow_l_plus_1 - x);
    y = y >> T(l);
    return y;
}

template std::uint64_t FloatingPointSimpleDivision_ABZS<std::uint64_t>(std::uint64_t a, std::uint64_t b, std::size_t l, std::size_t k);

template __uint128_t FloatingPointSimpleDivision_ABZS<__uint128_t>(__uint128_t a, __uint128_t b, std::size_t l, std::size_t k);

template<typename T, typename A>
std::vector<T, A> FloatingPointDivision_ABZS(T v1, T p1, T z1, T s1, T v2, T p2, T z2, T s2, std::size_t l, std::size_t k) {
    T v = FloatingPointSimpleDivision_ABZS(v1, v2 + z2, l);
    T b = v < (T(1) << T(l));
    T v_prime = (b * v + v) >> 1;
    T p = (1 - z1) * (p1 - p2 - T(l) + 1 - b);

    T z = z1;
    T s = s1 + s2 - 2 * s1 * s2;
    T error = z2;

    std::vector<T, A> floating_point_division_result;
    floating_point_division_result.emplace_back(v_prime);
    floating_point_division_result.emplace_back(p);
    floating_point_division_result.emplace_back(z);
    floating_point_division_result.emplace_back(s);
    floating_point_division_result.emplace_back(error);

    // std::cout << "v: ";
    // print_u128_u(v);

    // std::cout << "b: ";
    // print_u128_u(b);

    // std::cout << "v_prime: ";
    // print_u128_u(v_prime);

    // std::cout << "z: ";
    // print_u128_u(z);

    // std::cout << "s: ";
    // print_u128_u(s);

    // std::cout << "error: ";
    // print_u128_u(error);

    return floating_point_division_result;
}

template std::vector<std::uint64_t>
FloatingPointDivision_ABZS<std::uint64_t>(std::uint64_t v1, std::uint64_t p1, std::uint64_t z1, std::uint64_t s1, std::uint64_t v2, std::uint64_t p2,
                                          std::uint64_t z2, std::uint64_t s2, std::size_t l, std::size_t k);

template std::vector<__uint128_t>
FloatingPointDivision_ABZS<__uint128_t>(__uint128_t v1, __uint128_t p1, __uint128_t z1, __uint128_t s1, __uint128_t v2, __uint128_t p2,
                                        __uint128_t z2, __uint128_t s2, std::size_t l, std::size_t k);

template<typename T, typename A>
std::vector<T, A> FloatingPointMultiplication_ABZS(T v1, T p1, T z1, T s1, T v2, T p2, T z2, T s2, std::size_t l, std::size_t k) {
    T v = v1 * v2;
    T v_prime = v >> (T(l) - 1);

    T b = v_prime < (T(1) << T(l));

    T v_prime_prime = (b * v_prime + v_prime) >> 1;
    T z = z1 | z2;
    T s = s1 ^ s2;
    T p = (p1 + p2 + T(l) - b) * (1 - z);

    // std::cout << "v: ";
    // print_u128_u(v);

    // std::cout << "v_prime: ";
    // print_u128_u(v_prime);

    // std::cout << "v_prime_prime: ";
    // print_u128_u(v_prime_prime);

    // std::cout << "b: ";
    // print_u128_u(b);

    // std::cout << "z: ";
    // print_u128_u(z);

    // std::cout << "s: ";
    // print_u128_u(s);

    // std::cout << "p: ";
    // print_u128_u(p);

    std::vector<T, A> floating_point_multiplication_result;
    floating_point_multiplication_result.emplace_back(v_prime_prime);
    floating_point_multiplication_result.emplace_back(p);
    floating_point_multiplication_result.emplace_back(z);
    floating_point_multiplication_result.emplace_back(s);

    return floating_point_multiplication_result;
}

template std::vector<std::uint64_t>
FloatingPointMultiplication_ABZS<std::uint64_t>(std::uint64_t v1, std::uint64_t p1, std::uint64_t z1, std::uint64_t s1, std::uint64_t v2,
                                                std::uint64_t p2, std::uint64_t z2, std::uint64_t s2, std::size_t l, std::size_t k);

template std::vector<__uint128_t>
FloatingPointMultiplication_ABZS<__uint128_t>(__uint128_t v1, __uint128_t p1, __uint128_t z1, __uint128_t s1, __uint128_t v2, __uint128_t p2,
                                              __uint128_t z2, __uint128_t s2, std::size_t l, std::size_t k);

template<typename T, typename T_int>
T FloatingPointLessThan_ABZS(T v1, T p1, T z1, T s1, T v2, T p2, T z2, T s2, std::size_t l, std::size_t k) {
    T a = T_int(p1) < T_int(p2);
    T c = p1 == p2;
    T d = T_int((1 - 2 * s1) * v1) < T_int((1 - 2 * s2) * v2);

    T b_plus = c * d + (1 - c) * a;
    T b_minus = c * d + (1 - c) * (1 - a);

    T b = z1 * (1 - z2) * (1 - s2) + (1 - z1) * z2 * s1 + (1 - z1) * (1 - z2) * (s1 * (1 - s2) + (1 - s1) * (1 - s2) * b_plus + s1 * s2 * b_minus);

    return b;
}

template std::uint64_t
FloatingPointLessThan_ABZS<std::uint64_t, std::int64_t>(std::uint64_t v1, std::uint64_t p1, std::uint64_t z1, std::uint64_t s1, std::uint64_t v2,
                                                        std::uint64_t p2, std::uint64_t z2, std::uint64_t s2, std::size_t l, std::size_t k);

template __uint128_t
FloatingPointLessThan_ABZS<__uint128_t, __int128_t>(__uint128_t v1, __uint128_t p1, __uint128_t z1, __uint128_t s1, __uint128_t v2, __uint128_t p2,
                                                    __uint128_t z2, __uint128_t s2, std::size_t l, std::size_t k);

template<typename T>
T FloatingPointEqual_ABZS(T v1, T p1, T z1, T s1, T v2, T p2, T z2, T s2, std::size_t l, std::size_t k) {
    T b1 = v1 == v2;
    T b2 = p1 == p2;
    T b3 = z1 * z2;
    T b4 = s1 * s2;

    return b1 * b2 * b4 * (1 - b3) + b3;
}

template std::uint64_t
FloatingPointEqual_ABZS<std::uint64_t>(std::uint64_t v1, std::uint64_t p1, std::uint64_t z1, std::uint64_t s1, std::uint64_t v2, std::uint64_t p2,
                                       std::uint64_t z2, std::uint64_t s2, std::size_t l, std::size_t k);

template __uint128_t
FloatingPointEqual_ABZS<__uint128_t>(__uint128_t v1, __uint128_t p1, __uint128_t z1, __uint128_t s1, __uint128_t v2, __uint128_t p2, __uint128_t z2,
                                     __uint128_t s2, std::size_t l, std::size_t k);

template<typename T, typename T_int, typename A>
std::vector<T, A> FloatingPointRound_ABZS(T v1, T p1, T z1, T s1, std::size_t mode, std::size_t l, std::size_t k) {
    T a = T_int(p1) < 0;
    T b = T_int(p1) < T_int(-T(l) + 1);

    T v2 = v1 % (T(1) << T(-a * (1 - b) * p1));

    T c = v2 == 0;

    T away_from_zero = mode ^ s1;
    T v = v1 - v2 + (T(1) - c) * (T(1) << (-T_int(p1))) * (away_from_zero);

    T d = v == (T(1) << T(l));
    T v_prime = d * (T(1) << (T(l) - T(1))) + (T(1) - d) * v;
    T v_prime_prime = a * ((T(1) - b) * v_prime + b * away_from_zero * (T(1) << (T(l) - T(1)))) + (T(1) - a) * v1;

    T s = (T(1) - b * mode) * s1;
    T v_prime_prime_eq_zero = v_prime_prime == 0;
    T z = v_prime_prime_eq_zero | z1;
    T v_prime_prime_prime = v_prime_prime * (T(1) - z);

    //    T p = (p1 + d * a * (1 - b)) * (1 - z);

    // only for debug
    //    T away_from_zero = mode ^ s1;
    T p = ((p1 + d * a) * (T(1) - b) + b * away_from_zero * (T(1) - T(l))) * (T(1) - z);

    std::vector<T, A> floating_point_round_result;
    floating_point_round_result.emplace_back(v_prime_prime_prime);
    floating_point_round_result.emplace_back(p);
    floating_point_round_result.emplace_back(z);
    floating_point_round_result.emplace_back(s);

    // print_u128_u("a: ", a);
    // print_u128_u("b: ", b);
    // print_u128_u("v2: ", v2);
    // print_u128_u("c: ", c);
    // print_u128_u("v: ", v);
    // print_u128_u("d: ", d);
    // print_u128_u("v_prime: ", v_prime);
    // print_u128_u("v_prime_prime: ", v_prime_prime);
    // print_u128_u("s: ", s);
    // print_u128_u("v_prime_prime_eq_zero: ", v_prime_prime_eq_zero);
    // print_u128_u("z: ", z);
    // print_u128_u("v_prime_prime_prime: ", v_prime_prime_prime);
    // print_u128_u("p: ", p);
    // print_u128_u("T(-a * (1 - b) * p1): ", T(-a * (1 - b) * p1));
    // print_u128_u("T(1)<< (-p1): ", T(1) << (-p1));

    return floating_point_round_result;
}

template std::vector<std::uint64_t>
FloatingPointRound_ABZS<std::uint64_t, std::int64_t>(std::uint64_t v1, std::uint64_t p1, std::uint64_t z1, std::uint64_t s1, std::size_t mode,
                                                     std::size_t l, std::size_t k);

template std::vector<__uint128_t>
FloatingPointRound_ABZS<__uint128_t, __int128_t>(__uint128_t v1, __uint128_t p1, __uint128_t z1, __uint128_t s1, std::size_t mode, std::size_t l,
                                                 std::size_t k);

template<typename FLType, typename IntType, typename IntType_int, typename A>
std::vector<FLType, A> IntegerToFloatingPoint_ABZS(IntType a, std::size_t gamma, std::size_t l, std::size_t k) {
    FLType lambda = gamma - 1;
    FLType s = IntType_int(a) < 0;
    FLType z = a == 0;
    FLType a_prime = (1 - 2 * s) * FLType(a);
    FLType v;

    FLType a_value = a_prime;

    print_u128_u("a_prime: ", a_prime);
    //    unsigned msb_a_prime = 0;
    //    while (a_value >>= 1) {
    //        msb_a_prime++;
    //    }
    //    msb_a_prime++;
    std::bitset<sizeof(FLType) * 8> bit_set_a(a_prime);

    std::cout << "bit_set_a[i]: ";
    for (std::size_t i = 0; i < lambda; i++) {
        std::cout << bit_set_a[i];
    }
    std::cout << std::endl;

    std::cout << "bit_set_a[i]_reverse: ";
    for (std::size_t i = 0; i < lambda; i++) {
        std::cout << bit_set_a[lambda-1-i];
    }
    std::cout << std::endl;

    std::vector<bool> b(lambda);

    b[0] = bit_set_a[lambda - 1];
    for (std::size_t i = 1; i < lambda; i++) {
        b[i] = b[i - 1] | bit_set_a[lambda - 1 - i];
    }

    std::cout << std::endl;

    std::cout << "b[i]: ";
    for (std::size_t i = 0; i < lambda; i++) {
        std::cout << b[i];
    }

    std::cout << std::endl;

    FLType sum_bi = 0;
    for (std::size_t i = 0; i < lambda; i++) {
        sum_bi = sum_bi + b[i];
    }

    FLType sum_1_minus_bi = 0;
    for (std::size_t i = 0; i < lambda; i++) {
        sum_1_minus_bi = sum_1_minus_bi + (1 - b[i]);
    }

    //
    FLType pow2_i_mul_1_minus_b_plus_1 = 1;
    for (std::size_t i = 0; i < lambda; i++) {
        pow2_i_mul_1_minus_b_plus_1 = pow2_i_mul_1_minus_b_plus_1 + (FLType(1) << i) * (1 - b[i]);
    }

    v = a_prime * (pow2_i_mul_1_minus_b_plus_1);
    //
    FLType p = -(lambda - sum_bi);
    //
    FLType v_prime = 0;
    if (gamma - 1 > l) {
        std::cout << "if" << std::endl;
        v_prime = v >> (gamma - l - 1);
    } else {
        std::cout << "else" << std::endl;
        v_prime = (FLType(1) << (l - gamma + 1)) * v;
    }
    //
    FLType p_prime = (p + FLType(gamma) - 1 - FLType(l)) * (1 - z);
    //
    std::vector<FLType, A> integer_to_floating_point_result;
    integer_to_floating_point_result.emplace_back(v_prime);
    integer_to_floating_point_result.emplace_back(p_prime);
    integer_to_floating_point_result.emplace_back(z);
    integer_to_floating_point_result.emplace_back(s);
    //
    //    print_u128_u("a: ", a);
    //    // std::cout << "int(a): " << int(a) << std::endl;
    //    std::cout << "msb_a_prime: " << msb_a_prime << std::endl;;
    //    print_u128_u("a_prime: ", a_prime);
    print_u128_u("v_prime: ", v_prime);
    print_u128_u("p_prime: ", p_prime);
    std::cout << "int(p_prime): " << int(p_prime) << std::endl;;
    print_u128_u("z: ", z);
    print_u128_u("s: ", s);
    //
    print_u128_u("sum_bi: ", sum_bi);
    print_u128_u("sum_1_minus_bi: ", sum_1_minus_bi);
    print_u128_u("pow2_i_mul_1_minus_b_plus_1: ", pow2_i_mul_1_minus_b_plus_1);
    print_u128_u("v: ", v);
    print_u128_u("p: ", p);
    std::cout << "int(p): " << int(p) << std::endl;;

    return integer_to_floating_point_result;
}

template std::vector<__uint128_t, std::allocator<__uint128_t>>
IntegerToFloatingPoint_ABZS<__uint128_t, std::uint64_t, std::int64_t, std::allocator<__uint128_t>>(std::uint64_t a, std::size_t gamma, std::size_t l,
                                                                                                   std::size_t k);

template std::vector<__uint128_t, std::allocator<__uint128_t>>
IntegerToFloatingPoint_ABZS<__uint128_t, __uint128_t, __int128_t, std::allocator<__uint128_t>>(__uint128_t a, std::size_t gamma, std::size_t l,
                                                                                               std::size_t k);

template<typename T, typename T_int, typename A>
std::vector<T, A> FloatingPointSqrt_ABZS(T v1, T p1, T z1, T s1, std::size_t l, std::size_t k) {
    double constant_double_alpha = -0.8099868542;
    double constant_double_beta = 1.787727479;
    double constant_double_sqrt2 = sqrt(2);

    // T b = p1 & 1;
    // T l0 = l & 1;
    // T c = b ^ l0;

    //    T p = T((std::int64_t(p1) - b) / 2) + T(floor(T(l) / 2)) ;

    // only for debug
    // T p = T((p1 - b) / 2) + T(floor(T(l) / 2));
    T p = T_int(T_int(p1) + l) >> 1;
    T c = (T_int(p1) + l) & 1;

    //
    std::vector<T> x = CreateFloatingPointVector<T, A>(v1, -T(l), 0, 0);
    // std::cout << "x:  " << FloatingPointToDouble<T, A>(x) << std::endl;
    print_u128_u("x.v: ", x[0]);
    print_u128_u("x.p: ", x[1]);
    print_u128_u("x.z: ", x[2]);
    print_u128_u("x.s: ", x[3]);

    std::vector<T> alpha = FloatingPointDecomposeToVector<T, A>(constant_double_alpha, l, k);
    std::vector<T> beta = FloatingPointDecomposeToVector<T, A>(constant_double_beta, l, k);
    std::vector<T> sqrt2 = FloatingPointDecomposeToVector<T, A>(constant_double_sqrt2, l, k);

    // std::cout << "sqrt2: " << FloatingPointToDouble<T, A>(sqrt2) << std::endl;

    std::vector<T> alpha_mul_x = FloatingPointMultiplication_ABZS<T, A>(x, alpha, l, k);
    std::vector<T> y0 = FloatingPointAddition_ABZS<T, T_int, A>(alpha_mul_x, beta, l, k);
    std::vector<T> g0 = FloatingPointMultiplication_ABZS<T, A>(x, y0, l, k);
    std::vector<T> h0 = CreateFloatingPointVector<T, A>(y0[0], y0[1] - 1, y0[2], y0[3], l, k);

    print_u128_u("y0.v: ", y0[0]);
    print_u128_u("y0.p: ", y0[1]);
    print_u128_u("y0.z: ", y0[2]);
    print_u128_u("y0.s: ", y0[3]);
    print_u128_u("g0.v: ", g0[0]);
    print_u128_u("g0.p: ", g0[1]);
    print_u128_u("g0.z: ", g0[2]);
    print_u128_u("g0.s: ", g0[3]);
    print_u128_u("h0.v: ", h0[0]);
    print_u128_u("h0.p: ", h0[1]);
    print_u128_u("h0.z: ", h0[2]);
    print_u128_u("h0.s: ", h0[3]);
    // std::cout << "alpha_mul_x: " << FloatingPointToDouble<T, A>(alpha_mul_x) << std::endl;
    // std::cout << "y0: " << FloatingPointToDouble<T, A>(y0) << std::endl;
    // std::cout << "g0: " << FloatingPointToDouble<T, A>(g0) << std::endl;
    // std::cout << "h0: " << FloatingPointToDouble<T, A>(h0) << std::endl;

    //    std::vector<T> fl_3_div_2 =
    //            CreateFloatingPointVector<T, A>(3 * (T(1) << (T(l) - 2)), -(T(l) - 1), 0, 0, l,
    //            k);
    std::vector<T> fl_3_div_2 = FloatingPointDecomposeToVector<T, A>(1.5, l, k);
    std::vector<T> gi = g0;
    std::vector<T> hi = h0;

    // std::cout << "floor(log2(double(l) / 5.4)): " << floor(log2(double(l) / 5.4)) << std::endl;

    for (std::size_t i = 1; i < ceil(log2(double(l) / 5.4)); i++) {
        //    for (std::size_t i = 1; i < 2; i++) {
        std::vector<T> gihi = FloatingPointMultiplication_ABZS<T, A>(gi, hi, l, k);

        //    print_u128_u("gihi_v: ", gihi[0]);
        //    print_u128_u("gihi_p: ", gihi[1]);
        //    std::cout << "std::int64_t(gihi_p): " << std::int64_t(gihi[1]) << std::endl;
        //    print_u128_u("gihi_z: ", gihi[2]);
        //    print_u128_u("gihi_s: ", gihi[3]);

        // std::cout << "gihi: " << FloatingPointToDouble<T, A>(gihi) << std::endl;

        std::vector<T> fl_3_div_2_minus_gi_mul_hi = FloatingPointSubtraction_ABZS<T, T_int, A>(fl_3_div_2, gihi, l, k);

        // std::cout << "fl_3_div_2: " << FloatingPointToDouble<T, A>(fl_3_div_2) << std::endl;
        // std::cout << "fl_3_div_2_minus_gi_mul_hi: " << FloatingPointToDouble<T,
        // A>(fl_3_div_2_minus_gi_mul_hi) << std::endl;

        gi = FloatingPointMultiplication_ABZS<T, A>(gi, fl_3_div_2_minus_gi_mul_hi, l, k);
        hi = FloatingPointMultiplication_ABZS<T, A>(hi, fl_3_div_2_minus_gi_mul_hi, l, k);

        // std::cout << "gi: " << FloatingPointToDouble<T, A>(gi) << std::endl;
        // std::cout << "hi: " << FloatingPointToDouble<T, A>(hi) << std::endl;
    }
    std::vector<T> hi_square = FloatingPointMultiplication_ABZS<T, A>(hi, hi, l, k);
    // std::cout << "hi_square: " << FloatingPointToDouble<T, A>(hi_square) << std::endl;
    print_u128_u("hi_square.v: ", hi_square[0]);
    print_u128_u("hi_square.p: ", hi_square[1]);
    print_u128_u("hi_square.z: ", hi_square[2]);
    print_u128_u("hi_square.s: ", hi_square[3]);

    std::vector<T> x_mul_hi_square = FloatingPointMultiplication_ABZS<T, A>(x, hi_square, l, k);

    std::vector<T> ki = FloatingPointSubtraction_ABZS<T, T_int, A>(fl_3_div_2[0], fl_3_div_2[1], fl_3_div_2[2], fl_3_div_2[3], x_mul_hi_square[0],
                                                                   x_mul_hi_square[1] + 1, x_mul_hi_square[2], x_mul_hi_square[3], l, k);

    hi = FloatingPointMultiplication_ABZS<T, A>(hi, ki, l, k);

    std::vector<T> sqrt_x = FloatingPointMultiplication_ABZS<T, A>(x[0], x[1], x[2], x[3], hi[0], hi[1] + 1, hi[2], hi[3], l, k);

    // std::cout << "sqrt_x: " << FloatingPointToDouble<T, A>(sqrt_x) << std::endl;

    double sqrt_a = FloatingPointToDouble<T, A>((1 - c) * (T(1) << (T(l) - 1)) + c * sqrt2[0], -(1 - c) * (T(l) - 1) + c * sqrt2[1], 0, 0, l, k);
    // std::cout << "sqrt_a: " << sqrt_a << std::endl;

    std::vector<T> sqrt_a_mul_x = FloatingPointMultiplication_ABZS<T, A>(sqrt_x[0], sqrt_x[1], sqrt_x[2], sqrt_x[3],
                                                                         (1 - c) * (T(1) << (T(l) - 1)) + c * sqrt2[0],
                                                                         -(1 - c) * (T(l) - 1) + c * sqrt2[1], 0, 0, l, k);

    // std::cout << "sqrt_a_mul_x: " << FloatingPointToDouble<T, A>(sqrt_a_mul_x) << std::endl;

    //    std::vector<T> sqrt_a_mul_x = FloatingPointMultiplication_ABZS<T, A>(sqrt_a, sqrt_x, l,
    //    k);
    //
    //    std::cout << "sqrt_a_mul_x: " << FloatingPointToDouble<T, A>(sqrt_a_mul_x) << std::endl;

    T p_prime = (sqrt_a_mul_x[1] + p) * (1 - z1);
    T v = sqrt_a_mul_x[0] * (1 - z1);
    T error = s1;

    std::vector<T> floating_point_sqrt_result;
    floating_point_sqrt_result.emplace_back(v);
    floating_point_sqrt_result.emplace_back(p_prime);
    floating_point_sqrt_result.emplace_back(z1);
    floating_point_sqrt_result.emplace_back(s1);
    floating_point_sqrt_result.emplace_back(error);

    // print_u128_u("b: ", b);
    // print_u128_u("l0: ", l0);
    // print_u128_u("c: ", c);
    // print_u128_u("p: ", p);
    // print_u128_u("v1: ", v1);
    // print_u128_u("v: ", v);
    // print_u128_u("p2: ", sqrt_a_mul_x[1]);
    // print_u128_u("p_prime: ", p_prime);
    // std::cout << "floating_point_sqrt_result: " << FloatingPointToDouble<T,
    // A>(floating_point_sqrt_result) << std::endl; std::cout << "std::int64_t(p): " <<
    // std::int64_t(p) << std::endl; std::cout << "std::int64_t(p1): " << std::int64_t(p1) <<
    // std::endl; std::cout << "std::int64_t(p2): " << std::int64_t(sqrt_a_mul_x[1]) << std::endl;
    // std::cout << "std::int64_t(p1 - b): " << std::int64_t(p1 - b) << std::endl;
    // std::cout << "std::int64_t((p1 - b)/2)): " << std::int64_t(T(p1 - b) / 2) << std::endl;
    // std::cout << "T((std::int64_t (p1) - b) / 2): " << std::int64_t(T((std::int64_t(p1) - b) /
    // 2))
    // << std::endl; std::cout << "std::int64_t(p_prime): " << std::int64_t(p_prime) << std::endl;

    return floating_point_sqrt_result;
}

template std::vector<__uint128_t, std::allocator<__uint128_t>>
FloatingPointSqrt_ABZS<__uint128_t, __int128_t, std::allocator<__uint128_t>>(__uint128_t v1, __uint128_t p1, __uint128_t z1, __uint128_t s1,
                                                                             std::size_t l, std::size_t k);

template<typename T, typename T_int, typename A>
std::vector<T, A> FloatingPointExp2_ABZS(T v1, T p1, T z1, T s1, std::size_t l, std::size_t k) {
    T max = int(ceil(log2(std::int64_t(T(1) << (k - 1)) - 1 + l) - std::int64_t(l) + 1));

    bool a = T_int(p1) < T_int(max);
    bool b = T_int(p1) < T_int(1 - T_int(l));
    bool c = T_int(p1) < T_int(1 - 2 * T_int(l));

    T p2 = -(a) * (1 - c) * (b * (p1 + l) + (1 - b) * p1);

    bool e = T_int(p2) < 0;

    T x = v1 >> ((1 - e) * p2);
    T pow2_p2 = T(1) << (p2);

    T y = v1 - x * pow2_p2;

    bool d = y == 0;

    // original paper may have error
    //    T x_prime = (1 - b * s1) * (x - (1 - d) * s1) + b * s1 * ((T(1) << l) - 1 + d - x);

    T x_prime = (1 - b * s1) * (x + (1 - d) * s1) + b * s1 * ((T(1) << l) - 1 + d - x);

    T y_prime = (1 - d) * s1 * ((T(1) << p2) - y) + (1 - s1) * y;

    T w = a * (1 - c) * ((1 - b) * x_prime + b * s1) * (1 - 2 * s1) - c * s1;

    T u = a * (1 - c) * (b * x_prime + (1 - b) * (T(1) << (T(l) - T_int(p2))) * y_prime) + ((T(1) << l) - 1) * c * s1;

    constexpr std::size_t l_constexpr = 53;
    std::bitset<l_constexpr> bit_set_u(u);

    T ai;
    T bi;

    T cvi;
    T cpi;

    std::vector<FloatingPointStruct<T>> floating_point_ab_vector;
    for (std::size_t i = 1; i <= l; ++i) {
        //    for (std::size_t i = 0; i < 3; ++i) {
        double floating_point_c = pow(2, pow(2, -T_int(i)));

        FloatingPointStruct<T> floating_point_struct_c = FloatingPointDecomposeToStruct<T>(floating_point_c, l, k);
        cvi = floating_point_struct_c.mantissa;
        cpi = floating_point_struct_c.exponent;

        // std::cout << "floating_point_struct_c: " << FloatingPointToDouble<T,
        // A>(floating_point_struct_c, l, k) << std::endl;

        ai = (T(1) << (T(l) - 1)) * (1 - bit_set_u[l - i]) + cvi * bit_set_u[l - i];
        bi = -(T_int(l) - 1) * (1 - bit_set_u[l - i]) + T_int(cpi) * bit_set_u[l - i];

        // print_u128_u("ai: ", ai);
        // print_u128_u("bi: ", bi);

        // std::cout << "std::int64_t(bi): " << std::int64_t(bi) << std::endl;

        FloatingPointStruct<T> floating_point_struct_ab = CreateFloatingPointStruct<T>(ai, bi, 0, 0, l, k);

        // std::cout << "floating_point_struct_ab: " << FloatingPointToDouble<T,
        // A>(floating_point_struct_ab, l, k) << std::endl;

        floating_point_ab_vector.emplace_back(floating_point_struct_ab);
    }
    std::size_t head = 0;
    std::size_t tail = floating_point_ab_vector.size() - 1;
    FloatingPointStruct<T> floating_point_struct_u = FloatingPointProduct_ABZS<T, A>(floating_point_ab_vector, head, tail, l, k);

    // only for debug
    FloatingPointStruct<T> inter_product = floating_point_ab_vector[0];
    for (std::size_t i = 0; i < bit_set_u.size(); ++i) {
        inter_product = FloatingPointMultiplication_ABZS<T, A>(inter_product, floating_point_ab_vector[i], l, k);
        // std::cout << "inter_product: " << FloatingPointToDouble<T, A>(inter_product, l, k) <<
        // std::endl;
        //            FloatingPointStruct<T> inter_product_1 = FloatingPointMultiplication_ABZS<T, A>(
        //                    inter_product_0,
        //                    floating_point_ab_vector[2], l, k);
        //            std::cout << "inter_product_1: " << FloatingPointToDouble<T, A>(inter_product_1,
        //            l, k) << std::endl;

        //
    }

    // std::cout << "floating_point_struct_u: " << FloatingPointToDouble<T,
    // A>(floating_point_struct_u, l, k) << std::endl;

    T vu = floating_point_struct_u.mantissa;
    T pu = floating_point_struct_u.exponent;

    T p = a * (w + pu) + (T(1) << (T(k) - 1)) * (1 - a) * (1 - 2 * s1);

    T v = (T(1) << (T(l) - 1)) * z1 + (1 - z1) * vu;

    T p_prime = -z1 * (T(l) - 1) + (1 - z1) * p;

    std::vector<T> floating_point_exp2_result;
    floating_point_exp2_result.emplace_back(v);
    floating_point_exp2_result.emplace_back(p_prime);
    floating_point_exp2_result.emplace_back(0);
    floating_point_exp2_result.emplace_back(0);

    // // only for debug
    // floating_point_exp2_result.emplace_back(v);
    //   floating_point_exp2_result.emplace_back(p_prime);
    //   floating_point_exp2_result.emplace_back(0);
    //   floating_point_exp2_result.emplace_back(0);

    // only for debug
    print_u128_u("max: ", max);
    std::cout << "std::int64_t(max): " << std::int64_t(max) << std::endl;
    print_u128_u("a: ", a);
    print_u128_u("b: ", b);
    print_u128_u("c: ", c);
    print_u128_u("p2: ", p2);
    print_u128_u("x: ", x);
    print_u128_u("y: ", y);
    print_u128_u("pow2_p2: ", pow2_p2);
    print_u128_u("d: ", d);
    print_u128_u("x_prime: ", x_prime);
    print_u128_u("y_prime: ", y_prime);
    print_u128_u("w: ", w);
    std::cout << "std::int64_t(w): " << std::int64_t(w) << std::endl;
    print_u128_u("u: ", u);
    print_u128_u("vu: ", vu);
    print_u128_u("pu: ", pu);
    std::cout << "std::int64_t(pu): " << std::int64_t(pu) << std::endl;
    print_u128_u("p: ", p);
    std::cout << "std::int64_t(p): " << std::int64_t(p) << std::endl;
    print_u128_u("v: ", v);
    print_u128_u("p_prime: ", p_prime);
    std::cout << "std::int64_t(p_prime): " << std::int64_t(p_prime) << std::endl;

    std::cout << "bit_set_u: ";
    for (std::size_t i = 1; i < bit_set_u.size(); ++i) {
        std::cout << bit_set_u[l - i];
    }

    std::cout << std::endl;

    return floating_point_exp2_result;
}

template std::vector<__uint128_t, std::allocator<__uint128_t>>
FloatingPointExp2_ABZS<__uint128_t, __int128_t, std::allocator<__uint128_t>>(__uint128_t v1, __uint128_t p1, __uint128_t z1, __uint128_t s1,
                                                                             std::size_t l, std::size_t k);

template<typename T, typename T_int, typename A>
std::vector<T, A> FloatingPointLog2_ABZS(T v1, T p1, T z1, T s1, std::size_t l, std::size_t k) {
    std::size_t M = ceil(double(l) / (2 * log2(3)) - 0.5);

    FloatingPointStruct<T> floating_point_one = CreateFloatingPointStruct<T>(T(1) << (T(l) - 1), T(1) - T(l), 0, 0, l, k);
    FloatingPointStruct<T> floating_point_v_mul_2_minus_l = CreateFloatingPointStruct<T>(v1, -T(l), 0, 0, l, k);

    FloatingPointStruct<T> floating_point_1_minus_v_mul_2_minus_l = FloatingPointSubtraction_ABZS<T, T_int, A>(floating_point_one,
                                                                                                               floating_point_v_mul_2_minus_l, l, k);

    print_u128_u("floating_point_1_minus_v_mul_2_minus_l.v: ", floating_point_1_minus_v_mul_2_minus_l.mantissa);
    print_u128_u("floating_point_1_minus_v_mul_2_minus_l.p: ", floating_point_1_minus_v_mul_2_minus_l.exponent);
    print_u128_u("floating_point_1_minus_v_mul_2_minus_l.z: ", floating_point_1_minus_v_mul_2_minus_l.zero);
    print_u128_u("floating_point_1_minus_v_mul_2_minus_l.s: ", floating_point_1_minus_v_mul_2_minus_l.sign);

    FloatingPointStruct<T> floating_point_1_plus_v_mul_2_minus_l = FloatingPointAddition_ABZS<T, T_int, A>(floating_point_one,
                                                                                                           floating_point_v_mul_2_minus_l, l, k);
    FloatingPointStruct<T> floating_point_y = FloatingPointDivision_ABZS(floating_point_1_minus_v_mul_2_minus_l,
                                                                         floating_point_1_plus_v_mul_2_minus_l, l, k);

    FloatingPointStruct<T> floating_point_y_square = FloatingPointMultiplication_ABZS(floating_point_y, floating_point_y, l, k);

    double c0 = 2 * log2(std::numbers::e);
    FloatingPointStruct<T> floating_point_c0 = FloatingPointDecomposeToStruct<T>(c0, l, k);
    FloatingPointStruct<T> floating_point_y_mul_c0 = FloatingPointMultiplication_ABZS(floating_point_y, floating_point_c0, l, k);

    FloatingPointStruct<T> floating_point_sum_y_2i_plus_1_mul_ci = floating_point_y_mul_c0;
    FloatingPointStruct<T> floating_point_y_2i_plus_1 = floating_point_y;

    print_u128_u("floating_point_c0.v: ", floating_point_c0.mantissa);
    print_u128_u("floating_point_c0.p: ", floating_point_c0.exponent);
    print_u128_u("floating_point_c0.z: ", floating_point_c0.zero);
    print_u128_u("floating_point_c0.s: ", floating_point_c0.sign);

    for (std::size_t i = 1; i <= M; i++) {
        // std::cout << "i: " << i << std::endl;
        floating_point_y_2i_plus_1 = FloatingPointMultiplication_ABZS(floating_point_y_2i_plus_1, floating_point_y_square, l, k);

        // std::cout << "floating_point_y_2i_plus_1: " << FloatingPointToDouble<T,
        // A>(floating_point_y_2i_plus_1, l, k) << std::endl;

        double ci = 2 * log2(std::numbers::e) / (2 * i + 1);
        FloatingPointStruct<T> floating_point_c = FloatingPointDecomposeToStruct<T>(ci, l, k);

        // std::cout << "ci: " << ci << std::endl;

        FloatingPointStruct<T> floating_point_y_2i_plus_1_mul_c = FloatingPointMultiplication_ABZS(floating_point_y_2i_plus_1, floating_point_c, l,
                                                                                                   k);

        // std::cout << "floating_point_y_2i_plus_1_mul_c: " << FloatingPointToDouble<T,
        // A>(floating_point_y_2i_plus_1_mul_c, l, k) << std::endl;

        // std::cout << "floating_point_sum_y_2i_plus_1_mul_ci - before addition: " <<
        // FloatingPointToDouble<T, A>(floating_point_sum_y_2i_plus_1_mul_ci, l, k) << std::endl;

        floating_point_sum_y_2i_plus_1_mul_ci = FloatingPointAddition_ABZS<T, T_int, A>(floating_point_sum_y_2i_plus_1_mul_ci,
                                                                                        floating_point_y_2i_plus_1_mul_c, l, k);

        // std::cout << "floating_point_sum_y_2i_plus_1_mul_ci - after addition: " <<
        // FloatingPointToDouble<T, A>(floating_point_sum_y_2i_plus_1_mul_ci, l, k) << std::endl;
    }

    print_u128_u("floating_point_sum_y_2i_plus_1_mul_ci.v: ", floating_point_sum_y_2i_plus_1_mul_ci.mantissa);
    print_u128_u("floating_point_sum_y_2i_plus_1_mul_ci.p: ", floating_point_sum_y_2i_plus_1_mul_ci.exponent);
    print_u128_u("floating_point_sum_y_2i_plus_1_mul_ci.z: ", floating_point_sum_y_2i_plus_1_mul_ci.zero);
    print_u128_u("floating_point_sum_y_2i_plus_1_mul_ci.s: ", floating_point_sum_y_2i_plus_1_mul_ci.sign);

    T l_plus_p = T(l) + T_int(p1);

    // std::cout<<"std::int64_t (p1): "<<std::int64_t (p1)<<std::endl;
    std::cout << "std::int64_t(l_plus_p): " << std::int64_t(l_plus_p) << std::endl;
    // print_u128_u("T_int(l_plus_p): ", l_plus_p);

    //    std::uint64_t l_plus_p = T(l) + T(floating_point_sum_y_2i_plus_1_mul_ci.exponent);
    std::vector<T, A> floating_point_l_plus_p_vector = IntegerToFloatingPoint_ABZS<T, __uint128_t, __int128_t, std::allocator<T>>(l_plus_p);

    print_u128_u("floating_point_l_plus_p_vector.v: ", floating_point_l_plus_p_vector[0]);
    print_u128_u("floating_point_l_plus_p_vector.p: ", floating_point_l_plus_p_vector[1]);
    print_u128_u("floating_point_l_plus_p_vector.z: ", floating_point_l_plus_p_vector[2]);
    print_u128_u("floating_point_l_plus_p_vector.s: ", floating_point_l_plus_p_vector[3]);

    FloatingPointStruct<T> floating_point_l_plus_p_struct = CreateFloatingPointStruct(floating_point_l_plus_p_vector[0],
                                                                                      floating_point_l_plus_p_vector[1],
                                                                                      floating_point_l_plus_p_vector[2],
                                                                                      floating_point_l_plus_p_vector[3], l, k);

    FloatingPointStruct<T> floating_point_log_x = FloatingPointSubtraction_ABZS<T, T_int, A>(floating_point_l_plus_p_struct,
                                                                                             floating_point_sum_y_2i_plus_1_mul_ci, l, k);

    print_u128_u("floating_point_log_x.v: ", floating_point_log_x.mantissa);
    print_u128_u("floating_point_log_x.p: ", floating_point_log_x.exponent);
    print_u128_u("floating_point_log_x.z: ", floating_point_log_x.zero);
    print_u128_u("floating_point_log_x.s: ", floating_point_log_x.sign);

    std::vector<T> floating_point_log2_result;
    bool a = std::int64_t(p1) == (1 - std::int64_t(l));
    bool b = v1 == (T(1) << (T(l) - 1));
    T z = a * b;
    T v_prime_prime = floating_point_log_x.mantissa * (1 - z);
    T p_prime_prime = floating_point_log_x.exponent * (1 - z);
    print_u128_u("v_prime_prime: ", v_prime_prime);
    print_u128_u("p_prime_prime: ", p_prime_prime);

    floating_point_log2_result.template emplace_back(v_prime_prime);
    floating_point_log2_result.template emplace_back(p_prime_prime);
    floating_point_log2_result.template emplace_back(z);
    floating_point_log2_result.template emplace_back(s1);
    floating_point_log2_result.template emplace_back(s1);

    std::cout << "a: " << a << std::endl;
    std::cout << "b: " << b << std::endl;
    std::cout << "M: " << M << std::endl;
    std::cout << "floating_point_one: " << FloatingPointToDouble<T, A>(floating_point_one, l, k) << std::endl;
    std::cout << "floating_point_v_mul_2_minus_l: " << FloatingPointToDouble<T, A>(floating_point_v_mul_2_minus_l, l, k) << std::endl;
    std::cout << "floating_point_1_minus_v_mul_2_minus_l: " << FloatingPointToDouble<T, A>(floating_point_1_minus_v_mul_2_minus_l, l, k) << std::endl;
    std::cout << "floating_point_1_plus_v_mul_2_minus_l: " << FloatingPointToDouble<T, A>(floating_point_1_plus_v_mul_2_minus_l, l, k) << std::endl;
    std::cout << "floating_point_y: " << FloatingPointToDouble<T, A>(floating_point_y, l, k) << std::endl;
    std::cout << "floating_point_y_square: " << FloatingPointToDouble<T, A>(floating_point_y_square, l, k) << std::endl;
    std::cout << "c0: " << c0 << std::endl;
    std::cout << "floating_point_l_plus_p_vector: " << FloatingPointToDouble<T, A>(floating_point_l_plus_p_vector, l, k) << std::endl;
    std::cout << "floating_point_log_x: " << FloatingPointToDouble<T, A>(floating_point_log_x, l, k) << std::endl;

    return floating_point_log2_result;
}

template std::vector<__uint128_t, std::allocator<__uint128_t>>
FloatingPointLog2_ABZS<__uint128_t, __int128_t, std::allocator<__uint128_t>>(__uint128_t v1, __uint128_t p1, __uint128_t z1, __uint128_t s1,
                                                                             std::size_t l, std::size_t k);

template<typename T, typename A>
FloatingPointStruct<T>
FloatingPointProduct_ABZS(std::vector<FloatingPointStruct<T>> &floating_point_vector, std::size_t head, std::size_t tail, std::size_t l,
                          std::size_t k) {
    //    std::cout << "head: " << head << std::endl;
    //    std::cout << "tail: " << tail << std::endl;

    if (tail - head == 0) {
        //        std::cout << "floating_point_vector[0]: " <<
        //        FloatingPointToDouble<T>(floating_point_vector[head], l, k) << std::endl;
        return floating_point_vector[head];
    } else {
        std::size_t mid = int(head + (tail - head) / 2);

        //        std::cout << "mid: " << mid << std::endl;

        FloatingPointStruct<T> result_left = FloatingPointProduct_ABZS<T, A>(floating_point_vector, head, mid, l, k);

        FloatingPointStruct<T> result_right = FloatingPointProduct_ABZS<T, A>(floating_point_vector, mid + 1, tail, l, k);

        FloatingPointStruct<T> product_result = FloatingPointMultiplication_ABZS<T, A>(result_left, result_right, l, k);
        return product_result;
    }
}

template FloatingPointStruct<__uint128_t>
FloatingPointProduct_ABZS<__uint128_t>(std::vector<FloatingPointStruct<__uint128_t>> &floating_point_vector, std::size_t head, std::size_t tail,
                                       std::size_t l, std::size_t k);

template<typename T, typename T_int, typename A>
std::vector<T, A> FloatingPointAddition_ABZS(std::vector<T, A> floating_point_1, std::vector<T, A> floating_point_2, std::size_t l, std::size_t k) {
    std::vector<T, A> result = FloatingPointAddition_ABZS<T, T_int, A>(floating_point_1[0], floating_point_1[1], floating_point_1[2],
                                                                       floating_point_1[3], floating_point_2[0], floating_point_2[1],
                                                                       floating_point_2[2], floating_point_2[3], l, k);
    return result;
}

template std::vector<__uint128_t, std::allocator<__uint128_t>> FloatingPointAddition_ABZS<__uint128_t, __int128_t, std::allocator<__uint128_t>>(
        std::vector<__uint128_t, std::allocator<__uint128_t>> floating_point_1,
        std::vector<__uint128_t, std::allocator<__uint128_t>> floating_point_2, std::size_t l, std::size_t k);

template<typename T, typename T_int, typename A>
std::vector<T, A>
FloatingPointSubtraction_ABZS(std::vector<T, A> floating_point_1, std::vector<T, A> floating_point_2, std::size_t l, std::size_t k) {
    std::vector<T, A> result = FloatingPointSubtraction_ABZS<T, T_int, A>(floating_point_1[0], floating_point_1[1], floating_point_1[2],
                                                                          floating_point_1[3], floating_point_2[0], floating_point_2[1],
                                                                          floating_point_2[2], floating_point_2[3], l, k);
    return result;
}

template std::vector<__uint128_t, std::allocator<__uint128_t>> FloatingPointSubtraction_ABZS<__uint128_t, __int128_t, std::allocator<__uint128_t>>(
        std::vector<__uint128_t, std::allocator<__uint128_t>> floating_point_1,
        std::vector<__uint128_t, std::allocator<__uint128_t>> floating_point_2, std::size_t l, std::size_t k);

template<typename T, typename A>
std::vector<T, A> FloatingPointDivision_ABZS(std::vector<T, A> floating_point_1, std::vector<T, A> floating_point_2, std::size_t l, std::size_t k) {
    std::vector<T, A> result = FloatingPointDivision_ABZS<T, A>(floating_point_1[0], floating_point_1[1], floating_point_1[2], floating_point_1[3],
                                                                floating_point_2[0], floating_point_2[1], floating_point_2[2], floating_point_2[3], l,
                                                                k);
    return result;
}

template std::vector<__uint128_t, std::allocator<__uint128_t>>
FloatingPointDivision_ABZS<__uint128_t, std::allocator<__uint128_t>>(std::vector<__uint128_t, std::allocator<__uint128_t>> floating_point_1,
                                                                     std::vector<__uint128_t, std::allocator<__uint128_t>> floating_point_2,
                                                                     std::size_t l, std::size_t k);

template<typename T, typename A>
std::vector<T, A>
FloatingPointMultiplication_ABZS(std::vector<T, A> floating_point_1, std::vector<T, A> floating_point_2, std::size_t l, std::size_t k) {
    std::vector<T, A> result = FloatingPointMultiplication_ABZS<T, A>(floating_point_1[0], floating_point_1[1], floating_point_1[2],
                                                                      floating_point_1[3], floating_point_2[0], floating_point_2[1],
                                                                      floating_point_2[2], floating_point_2[3], l, k);
    return result;
}

template std::vector<__uint128_t, std::allocator<__uint128_t>>
FloatingPointMultiplication_ABZS(std::vector<__uint128_t, std::allocator<__uint128_t>> floating_point_1,
                                 std::vector<__uint128_t, std::allocator<__uint128_t>> floating_point_2, std::size_t l, std::size_t k);

template<typename T, typename T_int, typename A>
T FloatingPointLessThan_ABZS(std::vector<T, A> floating_point_1, std::vector<T, A> floating_point_2, std::size_t l, std::size_t k) {
    T result = FloatingPointLessThan_ABZS<T, T_int>(floating_point_1[0], floating_point_1[1], floating_point_1[2], floating_point_1[3],
                                                    floating_point_2[0], floating_point_2[1], floating_point_2[2], floating_point_2[3], l, k);
    return result;
}

template __uint128_t FloatingPointLessThan_ABZS<__uint128_t, __int128_t, std::allocator<__uint128_t>>(
        std::vector<__uint128_t, std::allocator<__uint128_t>> floating_point_1,
        std::vector<__uint128_t, std::allocator<__uint128_t>> floating_point_2, std::size_t l, std::size_t k);

template<typename T, typename A>
T FloatingPointEqual_ABZS(std::vector<T, A> floating_point_1, std::vector<T, A> floating_point_2, std::size_t l, std::size_t k) {
    T result = FloatingPointEqual_ABZS<T>(floating_point_1[0], floating_point_1[1], floating_point_1[2], floating_point_1[3], floating_point_2[0],
                                          floating_point_2[1], floating_point_2[2], floating_point_2[3], l, k);
    return result;
}

template __uint128_t
FloatingPointEqual_ABZS<__uint128_t, std::allocator<__uint128_t>>(std::vector<__uint128_t, std::allocator<__uint128_t>> floating_point_1,
                                                                  std::vector<__uint128_t, std::allocator<__uint128_t>> floating_point_2,
                                                                  std::size_t l, std::size_t k);

template<typename T, typename T_int, typename A>
std::vector<T, A> FloatingPointRound_ABZS(std::vector<T, A> floating_point_1, std::size_t mode, std::size_t l, std::size_t k) {
    std::vector<T, A> result = FloatingPointRound_ABZS<T, T_int, A>(floating_point_1[0], floating_point_1[1], floating_point_1[2],
                                                                    floating_point_1[3], mode, l, k);
    return result;
}

template std::vector<__uint128_t, std::allocator<__uint128_t>>
FloatingPointRound_ABZS<__uint128_t, __int128_t, std::allocator<__uint128_t>>(std::vector<__uint128_t, std::allocator<__uint128_t>> floating_point_1,
                                                                              std::size_t mode, std::size_t l, std::size_t k);

template<typename T, typename T_int, typename A>
std::vector<T, A> FloatingPointSqrt_ABZS(std::vector<T, A> floating_point_1, std::size_t l, std::size_t k) {
    std::vector<T, A> result = FloatingPointSqrt_ABZS<T, T_int, A>(floating_point_1[0], floating_point_1[1], floating_point_1[2], floating_point_1[3],
                                                                   l, k);
    return result;
}

template std::vector<__uint128_t, std::allocator<__uint128_t>>
FloatingPointSqrt_ABZS<__uint128_t, __int128_t, std::allocator<__uint128_t>>(std::vector<__uint128_t, std::allocator<__uint128_t>> floating_point_1,
                                                                             std::size_t l, std::size_t k);

template<typename T, typename T_int, typename A>
FloatingPointStruct<T>
FloatingPointAddition_ABZS(FloatingPointStruct<T> &floating_point_1, FloatingPointStruct<T> &floating_point_2, std::size_t l, std::size_t k) {
    std::vector<T, A> result = FloatingPointAddition_ABZS<T, T_int, A>(floating_point_1.mantissa, floating_point_1.exponent, floating_point_1.zero,
                                                                       floating_point_1.sign, floating_point_2.mantissa, floating_point_2.exponent,
                                                                       floating_point_2.zero, floating_point_2.sign, l, k);

    FloatingPointStruct<T> result_struct;
    result_struct.mantissa = result[0];
    result_struct.exponent = result[1];
    result_struct.zero = result[2];
    result_struct.sign = result[3];

    return result_struct;
}

template<typename T, typename T_int, typename A>
FloatingPointStruct<T>
FloatingPointSubtraction_ABZS(FloatingPointStruct<T> &floating_point_1, FloatingPointStruct<T> &floating_point_2, std::size_t l, std::size_t k) {
    std::vector<T, A> result = FloatingPointSubtraction_ABZS<T, T_int, A>(floating_point_1.mantissa, floating_point_1.exponent, floating_point_1.zero,
                                                                          floating_point_1.sign, floating_point_2.mantissa, floating_point_2.exponent,
                                                                          floating_point_2.zero, floating_point_2.sign, l, k);

    FloatingPointStruct<T> result_struct;
    result_struct.mantissa = result[0];
    result_struct.exponent = result[1];
    result_struct.zero = result[2];
    result_struct.sign = result[3];

    return result_struct;
}

template<typename T, typename A>
FloatingPointStruct<T>
FloatingPointDivision_ABZS(FloatingPointStruct<T> &floating_point_1, FloatingPointStruct<T> &floating_point_2, std::size_t l, std::size_t k) {
    std::vector<T, A> result = FloatingPointDivision_ABZS<T, A>(floating_point_1.mantissa, floating_point_1.exponent, floating_point_1.zero,
                                                                floating_point_1.sign, floating_point_2.mantissa, floating_point_2.exponent,
                                                                floating_point_2.zero, floating_point_2.sign, l, k);

    FloatingPointStruct<T> result_struct;
    result_struct.mantissa = result[0];
    result_struct.exponent = result[1];
    result_struct.zero = result[2];
    result_struct.sign = result[3];

    return result_struct;
}

template<typename T, typename A>
FloatingPointStruct<T>
FloatingPointMultiplication_ABZS(FloatingPointStruct<T> &floating_point_1, FloatingPointStruct<T> &floating_point_2, std::size_t l, std::size_t k) {
    std::vector<T, A> result = FloatingPointMultiplication_ABZS<T, A>(floating_point_1.mantissa, floating_point_1.exponent, floating_point_1.zero,
                                                                      floating_point_1.sign, floating_point_2.mantissa, floating_point_2.exponent,
                                                                      floating_point_2.zero, floating_point_2.sign, l, k);

    FloatingPointStruct<T> result_struct;
    result_struct.mantissa = result[0];
    result_struct.exponent = result[1];
    result_struct.zero = result[2];
    result_struct.sign = result[3];

    return result_struct;
}

template<typename T, typename T_int, typename A>
T FloatingPointLessThan_ABZS(FloatingPointStruct<T> &floating_point_1, FloatingPointStruct<T> &floating_point_2, std::size_t l, std::size_t k) {
    T result = FloatingPointLessThan_ABZS<T, T_int, A>(floating_point_1.mantissa, floating_point_1.exponent, floating_point_1.zero,
                                                       floating_point_1.sign, floating_point_2.mantissa, floating_point_2.exponent,
                                                       floating_point_2.zero, floating_point_2.sign, l, k);
    return result;
}

template<typename T, typename A>
T FloatingPointEqual_ABZS(FloatingPointStruct<T> &floating_point_1, FloatingPointStruct<T> &floating_point_2, std::size_t l, std::size_t k) {
    T result = FloatingPointEqual_ABZS<T, A>(floating_point_1.mantissa, floating_point_1.exponent, floating_point_1.zero, floating_point_1.sign,
                                             floating_point_2.mantissa, floating_point_2.exponent, floating_point_2.zero, floating_point_2.sign, l,
                                             k);
    return result;
}

template<typename T, typename T_int, typename A>
FloatingPointStruct<T> FloatingPointRound_ABZS(FloatingPointStruct<T> &floating_point_1, std::size_t mode, std::size_t l, std::size_t k) {
    std::vector<T, A> result = FloatingPointRound_ABZS<T, T_int, A>(floating_point_1.mantissa, floating_point_1.exponent, floating_point_1.zero,
                                                                    floating_point_1.sign, mode, l, k);
    FloatingPointStruct<T> result_struct;
    result_struct.mantissa = result[0];
    result_struct.exponent = result[1];
    result_struct.zero = result[2];
    result_struct.sign = result[3];

    return result_struct;
}

// template<typename FLType, typename IntType, typename IntType_int,
//         typename A>
// FloatingPointStruct<FLType> IntegerToFloatingPoint_ABZS(IntType a, std::size_t gamma,
//                                                         std::size_t l, std::size_t k) {
//     std::vector<FLType> result =
//             IntegerToFloatingPoint_ABZS<FLType, IntType, IntType_int, A>(a, gamma,
//                                                                          l, k);
//
//     FloatingPointStruct<FLType> result_struct;
//     result_struct.mantissa = result[0];
//     result_struct.exponent = result[1];
//     result_struct.zero = result[2];
//     result_struct.sign = result[3];
//
//     return result_struct;
// }

template<typename T, typename T_int, typename A>
FloatingPointStruct<T> FloatingPointSqrt_ABZS(FloatingPointStruct<T> &floating_point_1, std::size_t l, std::size_t k) {
    std::vector<T, A> result = FloatingPointSqrt_ABZS<T, T_int, A>(floating_point_1.mantissa, floating_point_1.exponent, floating_point_1.zero,
                                                                   floating_point_1.sign, l, k);

    FloatingPointStruct<T> result_struct;
    result_struct.mantissa = result[0];
    result_struct.exponent = result[1];
    result_struct.zero = result[2];
    result_struct.sign = result[3];

    return result_struct;
}

template<typename T, typename T_int, typename A>
FloatingPointStruct<T> FloatingPointExp2_ABZS(FloatingPointStruct<T> &floating_point_1, std::size_t l, std::size_t k) {
    std::vector<T, A> result = FloatingPointExp2_ABZS<T, T_int, A>(floating_point_1.mantissa, floating_point_1.exponent, floating_point_1.zero,
                                                                   floating_point_1.sign, l, k);

    FloatingPointStruct<T> result_struct;
    result_struct.mantissa = result[0];
    result_struct.exponent = result[1];
    result_struct.zero = result[2];
    result_struct.sign = result[3];

    return result_struct;
}

template FloatingPointStruct<__uint128_t>
FloatingPointExp2_ABZS<__uint128_t, __int128_t, std::allocator<__uint128_t>>(FloatingPointStruct<__uint128_t> &floating_point_1, std::size_t l,
                                                                             std::size_t k);

template<typename T, typename T_int, typename A>
FloatingPointStruct<T> FloatingPointLog2_ABZS(FloatingPointStruct<T> &floating_point_1, std::size_t l, std::size_t k) {
    std::vector<T, A> result = FloatingPointLog2_ABZS<T, T_int, A>(floating_point_1.mantissa, floating_point_1.exponent, floating_point_1.zero,
                                                                   floating_point_1.sign, l, k);

    FloatingPointStruct<T> result_struct;
    result_struct.mantissa = result[0];
    result_struct.exponent = result[1];
    result_struct.zero = result[2];
    result_struct.sign = result[3];

    return result_struct;
}

template FloatingPointStruct<__uint128_t>
FloatingPointLog2_ABZS<__uint128_t, __int128_t, std::allocator<__uint128_t>>(FloatingPointStruct<__uint128_t> &floating_point_1, std::size_t l,
                                                                             std::size_t k);