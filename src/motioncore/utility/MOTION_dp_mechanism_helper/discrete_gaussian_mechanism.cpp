#include "discrete_gaussian_mechanism.h"
#include <cstdint>
#include <iostream>

// template<typename T>
// std::vector<long double> geometric_distribution_EXP_iteration_estimation(T numerator, T
// denominator, long double total_fail_probability) {
//
//     long double fail_probability_geometric_fast_uniform_bound = total_fail_probability / 2;
//     long double fail_probability_geometric_slow_bound = total_fail_probability -
//     fail_probability_geometric_fast_uniform_bound;
//
//     long double fail_probability_geometric_fast_uniform = 0;
//     if (denominator != 1) {
//         for (std::size_t i = 0; i < denominator; i++) {
//             fail_probability_geometric_fast_uniform = fail_probability_geometric_fast_uniform +
//             exp(-(long double) (i) / (long double) (denominator));
//         }
//     }
//
//     fail_probability_geometric_fast_uniform = fail_probability_geometric_fast_uniform /
//     denominator; long double iterations_1_estimation =
//     ceill(logl(fail_probability_geometric_fast_uniform_bound) /
//     logl(fail_probability_geometric_fast_uniform));
//
//     long double fail_probability_geometric_slow = exp(-1);
//     long double iterations_2_estimation = ceill(logl(fail_probability_geometric_slow_bound) /
//     logl(fail_probability_geometric_slow));
//
//     std::vector<long double> result_vector(2);
//     result_vector[0] = iterations_1_estimation;
//     result_vector[1] = iterations_2_estimation;
//
//     return result_vector;
// }
//
// template std::vector<long double>
// geometric_distribution_EXP_iteration_estimation<std::uint64_t>(std::uint64_t numerator,
// std::uint64_t denominator,
//                                                                                                  long double total_fail_probability);

std::vector<bool> Bernoulli_distribution_EXP_0_1(double gamma, std::vector<double> random_floating_point_0_1) {
    std::size_t iterations = random_floating_point_0_1.size();

    assert((gamma >= 0) && (gamma <= 1));

    for (std::size_t j = 1; j < iterations + 1; j++) {
        std::cout << "gamma : " << gamma << std::endl;
        std::cout << "random_floating_point_0_1[j - 1]: " << random_floating_point_0_1[j - 1] << std::endl;

        if (!((gamma / j) > random_floating_point_0_1[j - 1])) {
            std::cout << "j: " << j << std::endl;
            std::vector<bool> result(2);
            result[0] = j % 2;

            bool success = true;
            result[1] = success;

            return result;
        }
    }

    bool success = true;
    std::vector<bool> result(2);
    result[0] = 0;
    result[1] = !success;
    return result;
}

std::vector<bool> Bernoulli_distribution_EXP_1(double gamma, double upper_bound_gamma, std::vector<double> random_floating_point_0_1) {
    assert(gamma > 1);

    for (std::size_t i = 0; i < upper_bound_gamma; i++) {
        std::vector<bool> b_vector = Bernoulli_distribution_EXP_0_1(1, random_floating_point_0_1);
        if (b_vector[0] == 0) {
            b_vector[1] = b_vector[1] & (upper_bound_gamma >= gamma);

            return b_vector;
        }
    }
    std::vector<bool> c_vector = Bernoulli_distribution_EXP_0_1(-(floor(gamma) - gamma), random_floating_point_0_1);
    c_vector[1] = c_vector[1] & (upper_bound_gamma >= gamma);

    return c_vector;
}

std::vector<bool> Bernoulli_distribution_EXP(double gamma, std::vector<double> random_floating_point_0_1) {
    if ((gamma <= 1) && (gamma >= 0)) {
        return Bernoulli_distribution_EXP_0_1(gamma, random_floating_point_0_1);
    } else {
        for (std::size_t i = 0; i < floor(gamma); i++) {
            std::vector<bool> b_vector = Bernoulli_distribution_EXP_0_1(1, random_floating_point_0_1);
            if (b_vector[0] == 0) {
                return b_vector;
            }
        }
        std::vector<bool> c_vector = Bernoulli_distribution_EXP_0_1(-(floor(gamma) - gamma), random_floating_point_0_1);
        return c_vector;
    }
}

template<typename T, typename A>
std::vector<T>
geometric_distribution_EXP(T numerator, T denominator, std::vector<double> random_floating_point_0_1_vector, std::vector<T, A> random_integer_vector,
                           std::size_t iteration_1, std::size_t iteration_2) {
    assert(random_floating_point_0_1_vector.size() == (iteration_1 + iteration_2));
    assert(random_integer_vector.size() == iteration_1);
    double x = double(numerator) / double(denominator);
    assert(x >= 0);

    if (numerator == 0) {
        // std::cout << "numerator == 0" << std::endl;
        std::vector<T> result_vector(2);
        result_vector[0] = 0;
        result_vector[1] = 1;
        return result_vector;
    } else {
        T u = 0;
        bool u_success = false;

        // special case when denominator = 1, where bernoulli (p = exp^(-0/t)) always output 1
        if (denominator == 1) {
            u = 0;
            u_success = true;
        } else {
            for (std::size_t i = 0; i < iteration_1; i++) {
                // bernoulli (p = exp^(-U/t))
                bool b1 = random_floating_point_0_1_vector[i] < std::exp(-double(random_integer_vector[i]) / double(denominator));

                //
                if (b1 == 1) {
                    u = random_integer_vector[i];
                    u_success = true;
                    // std::cout << "i: " << i << std::endl;
                    // std::cout << "u_success" << std::endl;
                    break;
                }
            }
        }

        T v = 0;
        T v_success = false;

        for (std::size_t j = 0; j < iteration_2; j++) {
            bool b2 = random_floating_point_0_1_vector[iteration_1 + j] < std::exp(-1);

            if (b2 == 0) {
                v = j;
                v_success = true;
                // std::cout << "j: " << j << std::endl;
                // std::cout << "v_success" << std::endl;
                break;
            } else {
                v = j + 1;
            }
        }
        T t = denominator;
        T w = v * t + u;
//        std::cout << "v: " << v << std::endl;
//        std::cout << "u: " << u << std::endl;
//        std::cout << "w: " << w << std::endl;

        std::vector<T> result_vector(2);
        result_vector[0] = w / numerator;
        result_vector[1] = T(u_success & v_success);

//        std::cout << "geometric sample: " << result_vector[0] << std::endl;
//        if (result_vector[1]) {
//            std::cout << "geometric sample success" << std::endl;
//        } else {
//            std::cout << "geometric sample fail" << std::endl;
//        }

        return result_vector;
    }
}

template std::vector<std::uint64_t>
geometric_distribution_EXP<std::uint64_t, std::allocator<std::uint64_t>>(std::uint64_t numerator, std::uint64_t denominator,
                                                                         std::vector<double> random_floating_point_0_1_vector,
                                                                         std::vector<std::uint64_t, std::allocator<std::uint64_t>> random_integer_vector,
                                                                         std::size_t iteration_1, std::size_t iteration_2);

template<typename T, typename A>
std::vector<T> geometric_distribution_EXP(T numerator, std::vector<double> random_floating_point_0_1_vector, std::size_t iteration_2) {
    T denominator = 1;
    std::size_t iteration_1 = 0;
    assert(random_floating_point_0_1_vector.size() == (iteration_2));
    double x = double(numerator) / double(denominator);
    assert(x >= 0);

    if (numerator == 0) {
        // std::cout << "numerator == 0" << std::endl;
        std::vector<T> result_vector(2);
        result_vector[0] = 0;
        result_vector[1] = 1;
        return result_vector;
    } else {
        T u = 0;
        bool u_success = false;

        // special case when denominator = 1, where bernoulli (p = exp^(-0/t)) always output 1
        // if (denominator == 1) {
        u = 0;
        u_success = true;
        // } else {
        //     for (std::size_t i = 0; i < iteration_1; i++) {

        //         // bernoulli (p = exp^(-U/t))
        //         bool b1 = random_floating_point_0_1_vector[i] <
        //         std::exp(-double(random_integer_vector[i]) / double(denominator));

        //         //
        //         if (b1 == 1) {
        //             u = random_integer_vector[i];
        //             u_success = true;
        //             // std::cout << "i: " << i << std::endl;
        //             // std::cout << "u_success" << std::endl;
        //             break;
        //         }
        //     }
        // }

        T v = 0;
        T v_success = false;
        for (std::size_t j = 0; j < iteration_2; j++) {
            bool b2 = random_floating_point_0_1_vector[j] < std::exp(-1);

            if (b2 == 0) {
                v = j;
                v_success = true;
                // std::cout << "j: " << j << std::endl;
                // std::cout << "v_success" << std::endl;
                break;
            } else {
                v = j + 1;
            }
        }

        T w = v * denominator + u;
//        std::cout << "v: " << v << std::endl;
//        std::cout << "u: " << u << std::endl;
//        std::cout << "w: " << w << std::endl;

        std::vector<T> result_vector(2);
        result_vector[0] = w / numerator;
        result_vector[1] = T(u_success & v_success);

        // std::cout << "geometric sample: " << result_vector[0] << std::endl;
        // if (result_vector[1]) {
        //   std::cout << "geometric sample success" << std::endl;
        // } else {
        //   std::cout << "geometric sample fail" << std::endl;
        // }

        return result_vector;
    }
}

template std::vector<std::uint64_t> geometric_distribution_EXP<std::uint64_t, std::allocator<std::uint64_t>>(std::uint64_t numerator,
                                                                                                             std::vector<double> random_floating_point_0_1_vector,

                                                                                                             std::size_t iteration_2);

template<typename T, typename A>
std::vector<T> discrete_laplace_distribution_EXP(T numerator, T denominator, std::vector<double> random_floating_point_0_1_vector,
                                                 std::vector<T, A> random_integer_vector, std::vector<bool> bernoulli_sample_vector,
                                                 std::size_t iteration_1, std::size_t iteration_2, std::size_t iteration_3) {
    assert(random_floating_point_0_1_vector.size() == (iteration_1 + iteration_2) * iteration_3);
    assert(random_integer_vector.size() == iteration_1 * iteration_3);
    double x = double(numerator) / double(denominator);
    assert(x >= 0);
    assert(bernoulli_sample_vector.size() == iteration_3);
    std::vector<T> result_vector(2);
    std::size_t num_of_simd_geo = iteration_3;

    bool iteration_3_finish = false;

    for (std::size_t i = 0; i < iteration_3; i++) {
        std::vector<double> random_floating_point_0_1_subvector(

                random_floating_point_0_1_vector.begin() + i * (iteration_1), random_floating_point_0_1_vector.begin() + (i + 1) * (iteration_1));
        random_floating_point_0_1_subvector.insert(random_floating_point_0_1_subvector.end(),
                                                   random_floating_point_0_1_vector.begin() + iteration_3 * iteration_1 + i * iteration_2,
                                                   random_floating_point_0_1_vector.begin() + iteration_3 * iteration_1 + (i + 1) * iteration_2);

        std::vector<T> random_integer_subvector(random_integer_vector.begin() + i * (iteration_1),
                                                random_integer_vector.begin() + (i + 1) * (iteration_1));

        std::vector<T> geometric_distribution_EXP_result = geometric_distribution_EXP<T, A>(numerator, denominator,
                                                                                            random_floating_point_0_1_subvector,
                                                                                            random_integer_subvector, iteration_1, iteration_2);

        bool sign = bernoulli_sample_vector[i];
        T magnitude = geometric_distribution_EXP_result[0];
        bool geo_success = geometric_distribution_EXP_result[1];
        bool dlap_success = false;

        if ((!(sign == 1 && magnitude == 0)) && (geo_success)) {
            dlap_success = true;
            if ((!iteration_3_finish)) {
                result_vector[0] = magnitude * (1 - 2 * sign);
                result_vector[1] = T(geo_success & dlap_success);
                iteration_3_finish = true;
            }
        }
    }

    return result_vector;
}

template std::vector<std::uint64_t>
discrete_laplace_distribution_EXP<std::uint64_t, std::allocator<std::uint64_t>>(std::uint64_t numerator, std::uint64_t denominator,
                                                                                std::vector<double> random_floating_point_0_1_vector,
                                                                                std::vector<std::uint64_t, std::allocator<std::uint64_t>> random_integer_vector,
                                                                                std::vector<bool> bernoulli_sample_vector, std::size_t iteration_1,
                                                                                std::size_t iteration_2, std::size_t iteration_3);

template<typename T, typename A>
std::vector<T>
discrete_laplace_distribution_EXP(T numerator, std::vector<double> random_floating_point_0_1_vector, std::vector<bool> bernoulli_sample_vector,
                                  std::size_t iteration_2, std::size_t iteration_3) {
    assert(random_floating_point_0_1_vector.size() == (iteration_2) * iteration_3);

    T denominator = 1;
    double x = double(numerator) / double(denominator);
    assert(x >= 0);
    assert(bernoulli_sample_vector.size() == iteration_3);
    std::vector<T> result_vector(2);
    std::size_t num_of_simd_geo = iteration_3;

    bool iteration_3_finish = false;

    for (std::size_t i = 0; i < iteration_3; i++) {
        std::vector<double> random_floating_point_0_1_subvector(

                random_floating_point_0_1_vector.begin() + i * iteration_2, random_floating_point_0_1_vector.begin() + (i + 1) * iteration_2);

        std::vector<T> geometric_distribution_EXP_result = geometric_distribution_EXP<T, A>(numerator, random_floating_point_0_1_subvector,
                                                                                            iteration_2);

        bool sign = bernoulli_sample_vector[i];
        T magnitude = geometric_distribution_EXP_result[0];
        bool geo_success = geometric_distribution_EXP_result[1];
        bool dlap_success = false;

        if ((!(sign == 1 && magnitude == 0)) && (geo_success)) {
            dlap_success = true;
            if ((!iteration_3_finish)) {
                result_vector[0] = magnitude * (1 - 2 * sign);
                result_vector[1] = T(geo_success & dlap_success);
                iteration_3_finish = true;
            }
        }
    }

    return result_vector;
}

template std::vector<std::uint64_t> discrete_laplace_distribution_EXP<std::uint64_t, std::allocator<std::uint64_t>>(std::uint64_t numerator,
                                                                                                                    std::vector<double> random_floating_point_0_1_vector,
                                                                                                                    std::vector<bool> bernoulli_sample_vector,
                                                                                                                    std::size_t iteration_2,
                                                                                                                    std::size_t iteration_3);

template<typename T, typename T_int, typename A>
std::vector<T> discrete_gaussian_distribution_EXP(double sigma, std::vector<double> random_floating_point_0_1_dlap_vector,
                                                  std::vector<T, A> random_integer_dlap_vector, std::vector<bool> bernoulli_sample_dlap_vector,
                                                  std::vector<double> random_floating_point_0_1_dgau_vector, std::size_t iteration_1,
                                                  std::size_t iteration_2, std::size_t iteration_3, std::size_t iteration_4) {
    assert(sigma > 0);
    assert(random_floating_point_0_1_dlap_vector.size() == (iteration_1 + iteration_2) * iteration_3 * iteration_4);
    assert(random_integer_dlap_vector.size() == iteration_1 * iteration_3 * iteration_4);
    assert(bernoulli_sample_dlap_vector.size() == iteration_3 * iteration_4);
    assert(random_floating_point_0_1_dgau_vector.size() == iteration_4);

    std::vector<T> result_vector(2);
    std::size_t num_of_simd_dgau = iteration_4;

    bool iteration_4_finish = false;

    for (std::size_t i = 0; i < iteration_4; i++) {
        std::vector<double> random_floating_point_0_1_dlap_subvector(
                // random_floating_point_0_1_vector.begin() + i * (iteration_1 + iteration_2),
                // random_floating_point_0_1_vector.begin() + (i + 1) * (iteration_1 + iteration_2));

                random_floating_point_0_1_dlap_vector.begin() + i * (iteration_1) * iteration_3,
                random_floating_point_0_1_dlap_vector.begin() + (i + 1) * (iteration_1) * iteration_3);

        random_floating_point_0_1_dlap_subvector.insert(random_floating_point_0_1_dlap_subvector.end(),
                                                        random_floating_point_0_1_dlap_vector.begin() + iteration_4 * iteration_3 * iteration_1 +
                                                        i * iteration_2 * iteration_3,
                                                        random_floating_point_0_1_dlap_vector.begin() + iteration_4 * iteration_3 * iteration_1 +
                                                        (i + 1) * iteration_2 * iteration_3);

        // std::cout << "random_floating_point_0_1_dlap_subvector.size(): "
        //           << random_floating_point_0_1_dlap_subvector.size() << std::endl;

        std::vector<T> random_integer_subvector(random_integer_dlap_vector.begin() + i * (iteration_1) * iteration_3,
                                                random_integer_dlap_vector.begin() + (i + 1) * (iteration_1) * iteration_3);

        std::vector<bool> bernoulli_sample_dlap_subvector(bernoulli_sample_dlap_vector.begin() + i * iteration_3,
                                                          bernoulli_sample_dlap_vector.begin() + (i + 1) * iteration_3);

        T t = floor(sigma) + 1;
        T numerator = 1;
        T denominator = t;

        std::vector<T> discrete_laplace_distribution_EXP_result = discrete_laplace_distribution_EXP<T, A>(numerator, denominator,
                                                                                                          random_floating_point_0_1_dlap_subvector,
                                                                                                          random_integer_subvector,
                                                                                                          bernoulli_sample_dlap_subvector,
                                                                                                          iteration_1, iteration_2, iteration_3);

        T_int Y = discrete_laplace_distribution_EXP_result[0];
        bool dlap_success = discrete_laplace_distribution_EXP_result[1];
        bool C = random_floating_point_0_1_dgau_vector[i] < exp(-(abs(Y) - sigma * sigma / t) * (abs(Y) - sigma * sigma / t) / (2 * sigma * sigma));

//        std::cout << "exp(-(abs(Y) - sigma * sigma / t) * (abs(Y) - sigma * sigma / t) / (2 * sigma * "
//                     "sigma)): " << exp(-(abs(Y) - sigma * sigma / t) * (abs(Y) - sigma * sigma / t) / (2 * sigma * sigma)) << std::endl;

        bool dgau_success = false;

        if ((C == 1) && (dlap_success)) {
//            std::cout << "i: " << i << std::endl;
            dgau_success = true;
            // std::vector<T> result_vector(2);
            if ((!iteration_4_finish)) {
                result_vector[0] = Y;
                result_vector[1] = T(dgau_success & dlap_success);
                iteration_4_finish = true;
            }
            // return result_vector;
        }
//        std::cout << "Y: " << Y << std::endl;
//        std::cout << "dlap_success: " << dlap_success << std::endl;
//        std::cout << "dgau_success & dlap_success: " << (dgau_success & dlap_success) << std::endl;
    }
//    std::cout << std::endl;
//    std::cout << "discrete gaussian: " << std::int64_t(result_vector[0]) << std::endl;

//    if (result_vector[1]) {
//        std::cout << "discrete gaussian: success: " << std::endl;
//    } else {
//        std::cout << "discrete gaussian: fail: " << std::endl;
//    }
    return result_vector;
}

template std::vector<std::uint64_t> discrete_gaussian_distribution_EXP<std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(double sigma,
                                                                                                                                   std::vector<double> random_floating_point_0_1_dlap_vector,
                                                                                                                                   std::vector<std::uint64_t, std::allocator<std::uint64_t>> random_integer_dlap_vector,
                                                                                                                                   std::vector<bool> bernoulli_sample_dlap_vector,
                                                                                                                                   std::vector<double> random_floating_point_0_1_dgau_vector,
                                                                                                                                   std::size_t iteration_1,
                                                                                                                                   std::size_t iteration_2,
                                                                                                                                   std::size_t iteration_3,
                                                                                                                                   std::size_t iteration_4);

template<typename T, typename T_int, typename A>
std::vector<T> discrete_gaussian_distribution_EXP(double sigma, std::vector<double> random_floating_point_0_1_dlap_vector,
                                                  std::vector<bool> bernoulli_sample_dlap_vector,
                                                  std::vector<double> random_floating_point_0_1_dgau_vector, std::size_t iteration_2,
                                                  std::size_t iteration_3, std::size_t iteration_4) {
    assert(sigma > 0);
    assert(random_floating_point_0_1_dlap_vector.size() == (iteration_2) * iteration_3 * iteration_4);
    assert(bernoulli_sample_dlap_vector.size() == iteration_3 * iteration_4);
    assert(random_floating_point_0_1_dgau_vector.size() == iteration_4);

    std::vector<T> result_vector(2);
    std::size_t num_of_simd_dlap = iteration_4;

    bool iteration_4_finish = false;

    for (std::size_t i = 0; i < iteration_4; i++) {
        std::vector<double> random_floating_point_0_1_dlap_subvector(
                // random_floating_point_0_1_vector.begin() + i * (iteration_1 + iteration_2),
                // random_floating_point_0_1_vector.begin() + (i + 1) * (iteration_1 + iteration_2));

                random_floating_point_0_1_dlap_vector.begin() + i * iteration_2 * iteration_3,
                random_floating_point_0_1_dlap_vector.begin() + (i + 1) * iteration_2 * iteration_3);

        // std::cout << "random_floating_point_0_1_dlap_subvector.size(): "
        //           << random_floating_point_0_1_dlap_subvector.size() << std::endl;

        std::vector<bool> bernoulli_sample_dlap_subvector(bernoulli_sample_dlap_vector.begin() + i * iteration_3,
                                                          bernoulli_sample_dlap_vector.begin() + (i + 1) * iteration_3);

        T t = floor(sigma) + 1;
        T numerator = 1;
        T denominator = t;

        assert(denominator == 1);

        std::vector<T> discrete_laplace_distribution_EXP_result = discrete_laplace_distribution_EXP<T, A>(numerator,
                                                                                                          random_floating_point_0_1_dlap_subvector,
                                                                                                          bernoulli_sample_dlap_subvector,
                                                                                                          iteration_2, iteration_3);

        T_int Y = discrete_laplace_distribution_EXP_result[0];
        bool dlap_success = discrete_laplace_distribution_EXP_result[1];
        bool C = random_floating_point_0_1_dgau_vector[i] < exp(-(abs(Y) - sigma * sigma / t) * (abs(Y) - sigma * sigma / t) / (2 * sigma * sigma));

//        std::cout << "exp(-(abs(Y) - sigma * sigma / t) * (abs(Y) - sigma * sigma / t) / (2 * sigma * "
//                     "sigma)): " << exp(-(abs(Y) - sigma * sigma / t) * (abs(Y) - sigma * sigma / t) / (2 * sigma * sigma)) << std::endl;

        bool dgau_success = false;

        if ((C == 1) && (dlap_success)) {
//            std::cout << "i: " << i << std::endl;
            dgau_success = true;
            // std::vector<T> result_vector(2);
            if ((!iteration_4_finish)) {
                result_vector[0] = Y;
                result_vector[1] = T(dgau_success & dlap_success);
                iteration_4_finish = true;
            }
            // return result_vector;
        }
//        std::cout << "Y: " << Y << std::endl;
//        std::cout << "dlap_success: " << dlap_success << std::endl;
//        std::cout << "dgau_success & dlap_success: " << (dgau_success & dlap_success) << std::endl;
    }
//    std::cout << std::endl;
//    std::cout << "discrete gaussian: " << std::int64_t(result_vector[0]) << std::endl;

//    if (result_vector[1]) {
//        std::cout << "discrete gaussian: success: " << std::endl;
//    } else {
//        std::cout << "discrete gaussian: fail: " << std::endl;
//    }
    return result_vector;
}

template std::vector<std::uint64_t> discrete_gaussian_distribution_EXP<std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(double sigma,
                                                                                                                                   std::vector<double> random_floating_point_0_1_dlap_vector,
                                                                                                                                   std::vector<bool> bernoulli_sample_dlap_vector,
                                                                                                                                   std::vector<double> random_floating_point_0_1_dgau_vector,
                                                                                                                                   std::size_t iteration_2,
                                                                                                                                   std::size_t iteration_3,
                                                                                                                                   std::size_t iteration_4);

// =================================================================
template<typename T, typename T_int, typename A>
std::vector<T> discrete_gaussian_distribution_EXP_with_discrete_Laplace_EKMPP(double sigma, const std::vector<T> &discrete_laplace_sample_vector,
                                                                              const std::vector<double> &random_floating_point_0_1_dgau_vector,
                                                                              std::size_t iteration) {

    assert(sigma > 0);
    assert(discrete_laplace_sample_vector.size() == iteration);
    assert(random_floating_point_0_1_dgau_vector.size() == iteration);

    std::vector<T> result_vector(2);
    std::size_t num_of_simd_dlap = iteration;

    bool iteration_finish = false;

    for (std::size_t i = 0; i < iteration; i++) {

        T t = floor(sigma) + 1;

        T_int Y = discrete_laplace_sample_vector[i];
        bool C = random_floating_point_0_1_dgau_vector[i] < exp(-(abs(Y) - sigma * sigma / t) * (abs(Y) - sigma * sigma / t) / (2 * sigma * sigma));

//        std::cout << "exp(-(abs(Y) - sigma * sigma / t) * (abs(Y) - sigma * sigma / t) / (2 * sigma * "
//                     "sigma)): " << exp(-(abs(Y) - sigma * sigma / t) * (abs(Y) - sigma * sigma / t) / (2 * sigma * sigma)) << std::endl;

        bool dgau_success = false;

        if (C == 1) {
            dgau_success = true;
            if ((!iteration_finish)) {
                result_vector[0] = Y;
                result_vector[1] = T(dgau_success);
                iteration_finish = true;
            }
        }
    }
    return result_vector;
}

template std::vector<std::uint64_t>
discrete_gaussian_distribution_EXP_with_discrete_Laplace_EKMPP<std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(double sigma,
                                                                                                                           const std::vector<std::uint64_t> &discrete_laplace_sample_vector,
                                                                                                                           const std::vector<double> &random_floating_point_0_1_dgau_vector,
                                                                                                                           std::size_t iteration);


// =================================================================

template<typename T>
long double geometric_distribution_EXP_fail_probability_estimation(T numerator, T denominator, long double iteration_1, long double iteration_2) {
    long double fail_probability_geometric_slow = exp(-1);
    long double fail_probability_geometric_fast_uniform = 0;

    if (denominator != 1) {
//        for (std::size_t i = 0; i < denominator; i++) {
//            fail_probability_geometric_fast_uniform =
//                    fail_probability_geometric_fast_uniform + expl(-(long double) (i) / (long double) (denominator));
//        }
//        fail_probability_geometric_fast_uniform = fail_probability_geometric_fast_uniform / denominator;

// use analytic solution to compute fail_probability_geometric_fast_uniform
        fail_probability_geometric_fast_uniform = 1 - ((1 - expl(-1.0)) / (1 - expl(-1.0 / (denominator)))) / denominator;
//        std::cout << "fail_probability_geometric_fast_uniform: " << fail_probability_geometric_fast_uniform << std::endl;


        long double result;

        // probability geometric_fast_uniform or geometric_slow fail
        result = powl(fail_probability_geometric_fast_uniform, iteration_1) + powl(fail_probability_geometric_slow, iteration_2) -
                 powl(fail_probability_geometric_fast_uniform, iteration_1) * powl(fail_probability_geometric_slow, iteration_2);
        return result;

    } else {
        fail_probability_geometric_fast_uniform = 0;
        long double result;
        result = powl(fail_probability_geometric_slow, iteration_2);
        return result;
    }
}

template long double
geometric_distribution_EXP_fail_probability_estimation<std::uint64_t>(std::uint64_t numerator, std::uint64_t denominator, long double iteration_1,
                                                                      long double iteration_2);

template<typename T>
std::vector<long double> optimize_geometric_distribution_EXP_iteration(T numerator, T denominator, long double total_fail_probability) {
    //    std::vector<long double> initial_estimation_result_vector =
    //    geometric_distribution_EXP_iteration_estimation<std::uint64_t>(numerator, denominator,
    //                                                                                                                               total_fail_probability);
    //    long double max_iterations = initial_estimation_result_vector[0] +
    //    initial_estimation_result_vector[1]; long double min_iterations =
    //    std::min(initial_estimation_result_vector[0], initial_estimation_result_vector[1]); long
    //    double min_iterations = 1;

    std::size_t iteration_1_lower_bound = 1;
    std::size_t iteration_1_upper_bound = 150;
    std::size_t iteration_2_upper_bound = 150;
    long double minimum_total_iteration = iteration_1_upper_bound + iteration_2_upper_bound;

    long double minimum_total_MPC_time = (iteration_1_upper_bound * iteration_1_weight + iteration_2_upper_bound * iteration_2_weight);

    // rescale numerator and denominator s.t., to reduce MPC iterations without decrease fail probability
    T upscale_factor_lower_bound = 1;
    T upscale_factor_upper_bound = 50;

    if (denominator == 1) {
        iteration_1_upper_bound = 1;
        iteration_1_lower_bound = 0;
        upscale_factor_upper_bound = 2;
    }

    if (denominator > 20) {
        upscale_factor_upper_bound = 2;
    }

    std::vector<long double> result_vector(5);
    //    result_vector[0] = initial_estimation_result_vector[0];
    //    result_vector[1] = initial_estimation_result_vector[1];



    for (std::size_t upscale_factor = upscale_factor_lower_bound; upscale_factor < upscale_factor_upper_bound; upscale_factor++) {
        for (std::size_t iteration_1 = iteration_1_lower_bound; iteration_1 < iteration_1_upper_bound; iteration_1++) {
            for (std::size_t iteration_2 = 1; iteration_2 < iteration_2_upper_bound; iteration_2++) {
                long double fail_probability_estimation = geometric_distribution_EXP_fail_probability_estimation<std::uint64_t>(
                        numerator * upscale_factor, denominator * upscale_factor, iteration_1, iteration_2);

                if (((iteration_1 + iteration_2) <= minimum_total_iteration) && (fail_probability_estimation <= total_fail_probability)) {

//            if (((iteration_1 * iteration_1_weight + iteration_2 * iteration_2_weight) <= minimum_total_MPC_time) &&
//                (fail_probability_estimation <= total_fail_probability)) {

                    minimum_total_iteration = iteration_1 + iteration_2;
                    minimum_total_MPC_time = iteration_1 * iteration_1_weight + iteration_2 * iteration_2_weight;
                    result_vector[0] = iteration_1;
                    result_vector[1] = iteration_2;
                    result_vector[2] = minimum_total_iteration;
                    result_vector[3] = fail_probability_estimation;
                    result_vector[4] = upscale_factor;

//                    std::cout << "geometric_minimum_total_iteration: " << minimum_total_iteration << std::endl;
//                    std::cout << "minimum_total_MPC_time: " << minimum_total_MPC_time << std::endl;

//                    std::cout << "geometric_best_iterations_1_result: " << result_vector[0] << std::endl;
//                    std::cout << "geometric_best_iterations_2_result: " << result_vector[1] << std::endl;
//                    std::cout << "geometric_best_fail_probability_result: " << result_vector[3] << std::endl;
//                    std::cout << "geometric_upscale_factor: " << result_vector[4] << std::endl;
                }
            }
        }
    }

    return result_vector;
}

template std::vector<long double>
optimize_geometric_distribution_EXP_iteration<std::uint64_t>(std::uint64_t numerator, std::uint64_t denominator, long double total_fail_probability);

// template<typename T>
// std::vector<long double> discrete_laplace_distribution_EXP_iteration_estimation(T numerator, T
// denominator, long double total_fail_probability) {
//
//     long double iteration_3_bound = 1000;
//     std::vector<long double> result_vector(4);
//
//     for (std::size_t iteration_3 = 1; iteration_3 < iteration_3_bound; iteration_3++) {
////        std::cout << "iteration_3: " << iteration_3 << std::endl;
//        long double fail_probability_geometric_fast_bound = powl((total_fail_probability / 2), 1.0
//        / (long double) (iteration_3));
////        std::cout << "fail_probability_geometric_fast_bound: " <<
/// fail_probability_geometric_fast_bound << std::endl;
//
//        long double fail_probability_sign_magnitude_bound = total_fail_probability / 2;
//
//        std::vector<long double> geometric_distribution_estimation_result_vector =
//        optimize_geometric_distribution_EXP_iteration<T>(numerator,
//                                                                                                                                denominator,
//                                                                                                                                fail_probability_geometric_fast_bound);
//
//        long double geometric_fast_distribution_iteration_1_estimation =
//        geometric_distribution_estimation_result_vector[0]; long double
//        geometric_fast_distribution_iteration_2_estimation =
//        geometric_distribution_estimation_result_vector[1]; long double
//        geometric_fast_distribution_fail_probability =
//        geometric_distribution_estimation_result_vector[2]; long double
//        geometric_fast_distribution_success_probability = 1 -
//        geometric_fast_distribution_fail_probability;
//
//        long double geometric_slow_distribution_fail_probability = powl(exp(-1),
//        geometric_fast_distribution_iteration_2_estimation); long double
//        geometric_slow_distribution_output_0_and_fail =
//        geometric_slow_distribution_fail_probability; long double
//        geometric_slow_distribution_output_0_and_success = (1 - exp(-1)) *
//        geometric_fast_distribution_success_probability; long double
//        geometric_slow_distribution_output_0 =
//                geometric_slow_distribution_output_0_and_success +
//                geometric_slow_distribution_output_0_and_fail;
//
//        long double geometric_fast_distribution_output_0_and_success =
//                1 / geometric_fast_distribution_iteration_1_estimation *
//                geometric_slow_distribution_output_0;
//        long double geometric_fast_distribution_output_0_and_fail =
//        geometric_fast_distribution_fail_probability; long double
//        geometric_fast_distribution_output_0 =
//                geometric_fast_distribution_output_0_and_success +
//                geometric_fast_distribution_output_0_and_fail;
//
//        long double probability_sign_equal_1 = 0.5;
//        long double probability_magnitude_equal_0 = geometric_fast_distribution_output_0;
//        long double sign_magnitude_fail_probability = probability_sign_equal_1 *
//        probability_magnitude_equal_0; long double sign_magnitude_iteration_estimation =
//        ceill(logl(fail_probability_sign_magnitude_bound) /
//        logl(sign_magnitude_fail_probability));
//
//        if (sign_magnitude_iteration_estimation == iteration_3) {
//            result_vector[0] = geometric_fast_distribution_iteration_1_estimation;
//            result_vector[1] = geometric_fast_distribution_iteration_2_estimation;
//            result_vector[2] = sign_magnitude_iteration_estimation;
//            result_vector[3] = (geometric_fast_distribution_iteration_1_estimation +
//            geometric_fast_distribution_iteration_2_estimation) *
//                               sign_magnitude_iteration_estimation +
//                               sign_magnitude_iteration_estimation;
//
//            std::cout << "geometric_fast_distribution_iteration_1_estimation[0]: " <<
//            result_vector[0] << std::endl; std::cout <<
//            "geometric_fast_distribution_iteration_2_estimation[1]: " << result_vector[1] <<
//            std::endl; std::cout << "sign_magnitude_fail_probability: " <<
//            sign_magnitude_fail_probability << std::endl; std::cout <<
//            "sign_magnitude_iteration_estimation: " << result_vector[2] << std::endl; std::cout <<
//            "total_iteration_estimation: " << result_vector[3] << std::endl; return result_vector;
//        } else {
//            result_vector[0] = 1;
//            result_vector[1] = 1;
//            result_vector[2] = 1;
//            result_vector[3] = 1;
//
//        }
//    }
//    return result_vector;
//
//}
//
// template std::vector<long double>
// discrete_laplace_distribution_EXP_iteration_estimation<std::uint64_t>(std::uint64_t numerator,
// std::uint64_t denominator,
//                                                                      long double
//                                                                      total_fail_probability);

template<typename T>
long double
discrete_laplace_distribution_EXP_fail_probability_estimation(T numerator, T denominator, long double iteration_1, long double iteration_2,
                                                              long double iteration_3) {
//    if (denominator != 1) {

    long double geometric_distribution_EXP_fail_probability_estimation_result = geometric_distribution_EXP_fail_probability_estimation<std::uint64_t>(
            numerator, denominator, iteration_1, iteration_2);

//    long double geometric_fast_distribution_iteration_1_estimation = iteration_1;
    long double geometric_fast_distribution_Y_equal_0_and_success;

//    long double geometric_fast_distribution_iteration_2_estimation = iteration_2;
    long double geometric_fast_distribution_fail_probability = geometric_distribution_EXP_fail_probability_estimation_result;
    long double geometric_fast_distribution_success_probability = 1 - geometric_fast_distribution_fail_probability;

//    long double geometric_slow_distribution_fail_probability = powl(exp(-1), geometric_fast_distribution_iteration_2_estimation);
//    long double geometric_slow_distribution_output_0_and_fail = geometric_slow_distribution_fail_probability;
//    long double geometric_slow_distribution_V_equal_0_and_success = (1 - exp(-1));
//    long double geometric_slow_distribution_V_equal_0 =
//            geometric_slow_distribution_V_equal_0_and_success + geometric_slow_distribution_fail_probability;

//        if (denominator == 1) {
//            geometric_fast_distribution_output_0_and_success = 1;
//        } else {
//
//        }
//        geometric_fast_distribution_output_0_and_success = 1.0 / denominator * geometric_slow_distribution_output_0_and_success;
    geometric_fast_distribution_Y_equal_0_and_success =
            (1.0 - exp(-(long double) (numerator) / (long double) (denominator))) * geometric_fast_distribution_success_probability;

//    std::cout<<"(1.0 - exp(-(long double) (numerator) / (long double) (denominator))): "<<(1.0 - exp(-(long double) (numerator) / (long double) (denominator)))<<std::endl;

//    std::cout<<"geometric_fast_distribution_Y_equal_0_and_success: "<<geometric_fast_distribution_Y_equal_0_and_success<<std::endl;

//        long double geometric_fast_distribution_output_0_and_fail = geometric_fast_distribution_fail_probability;
//        long double geometric_fast_distribution_output_0 =
//                geometric_fast_distribution_output_0_and_success + geometric_fast_distribution_output_0_and_fail;

    long double probability_sign_equal_1 = 0.5;
//        long double probability_magnitude_equal_0 = geometric_fast_distribution_output_0;
//        long double sign_magnitude_fail_probability = probability_sign_equal_1 * probability_magnitude_equal_0;
    long double probability_B_equal_1_and_Y_equal_0_and_geometric_fast_success =
            probability_sign_equal_1 * geometric_fast_distribution_Y_equal_0_and_success;
    long double discrete_laplace_fail_probability =
            probability_B_equal_1_and_Y_equal_0_and_geometric_fast_success + geometric_fast_distribution_fail_probability;

    return powl(discrete_laplace_fail_probability, iteration_3);
    //
//    }
}

template long double discrete_laplace_distribution_EXP_fail_probability_estimation<std::uint64_t>(std::uint64_t numerator, std::uint64_t denominator,
                                                                                                  long double iteration_1, long double iteration_2,
                                                                                                  long double iteration_3);

template<typename T>
std::vector<long double> optimize_discrete_laplace_distribution_EXP_iteration(T numerator, T denominator, long double total_fail_probability) {
    std::cout << "optimize_discrete_laplace_distribution_EXP_iteration" << std::endl;
    std::cout << "numerator: " << numerator << std::endl;
    std::cout << "denominator: " << denominator << std::endl;

//    std::vector<long double> optimize_geometric_distribution_EXP_iteration_result_vector = optimize_geometric_distribution_EXP_iteration<T>(numerator,
//    denominator, total_fail_probability);
//    std::size_t iteration_1 = optimize_geometric_distribution_EXP_iteration_result_vector[0];
//    std::size_t iteration_2 = optimize_geometric_distribution_EXP_iteration_result_vector[1];
//    std::size_t upscale_factor = optimize_geometric_distribution_EXP_iteration_result_vector[4];

    std::size_t iteration_1_lower_bound = 1;
    std::size_t iteration_1_upper_bound = 150;
    std::size_t iteration_2_upper_bound = 150;

    std::size_t iteration_3_upper_bound = 200;
    long double minimum_total_iteration = (iteration_1_upper_bound + iteration_2_upper_bound) * iteration_3_upper_bound + iteration_3_upper_bound;

    long double minimum_total_MPC_time = ((iteration_1_upper_bound * iteration_1_weight + iteration_2_upper_bound * iteration_2_weight) *
                                          iteration_3_upper_bound);


    // rescale numerator and denominator s.t., to reduce MPC iterations without decrease fail probability
    T upscale_factor_lower_bound = 1;
    T upscale_factor_upper_bound = 2;

    if (denominator == 1) {
        iteration_1_upper_bound = 1;
        iteration_1_lower_bound = 0;
        upscale_factor_upper_bound = 2;
    }

    if (denominator > 100) {
        upscale_factor_upper_bound = 2;
    }

    std::vector<long double> result_vector(8);

    for (std::size_t upscale_factor = upscale_factor_lower_bound; upscale_factor < upscale_factor_upper_bound; upscale_factor++) {
        for (std::size_t iteration_1 = iteration_1_lower_bound; iteration_1 < iteration_1_upper_bound; iteration_1++) {
            for (std::size_t iteration_2 = 1; iteration_2 < iteration_2_upper_bound; iteration_2++) {
                for (std::size_t iteration_3 = 1; iteration_3 < iteration_3_upper_bound; iteration_3++) {

                    long double discrete_laplace_fail_probability_estimation = discrete_laplace_distribution_EXP_fail_probability_estimation<std::uint64_t>(
                            numerator * upscale_factor, denominator * upscale_factor, iteration_1, iteration_2, iteration_3);

                    long double geometric_fail_probability_estimation = geometric_distribution_EXP_fail_probability_estimation<std::uint64_t>(
                            numerator * upscale_factor, denominator * upscale_factor, iteration_1, iteration_2);

                    if ((((iteration_1 + iteration_2) * iteration_3 + iteration_3) < minimum_total_iteration) &&
                        (discrete_laplace_fail_probability_estimation <= total_fail_probability) &&
                        (geometric_fail_probability_estimation <= total_fail_probability)) {


//                if ((((iteration_1 * iteration_1_weight + iteration_2 * iteration_2_weight) * iteration_3) <= minimum_total_MPC_time) &&
//                    (fail_probability_estimation <= total_fail_probability)) {

//                    if (fail_probability_estimation <= total_fail_probability) {

//                        std::cout << "geometric_fail_probability_estimation: " << geometric_fail_probability_estimation << std::endl;
//                        std::cout << "discrete_laplace_fail_probability_estimation: " << discrete_laplace_fail_probability_estimation << std::endl;

                        minimum_total_iteration = ((iteration_1 + iteration_2) * iteration_3 + iteration_3);
                        minimum_total_MPC_time = ((iteration_1 * iteration_1_weight + iteration_2 * iteration_2_weight) * iteration_3);

                        result_vector[0] = iteration_1;
                        result_vector[1] = iteration_2;
                        result_vector[2] = iteration_3;
                        result_vector[3] = minimum_total_iteration;
                        result_vector[4] = minimum_total_MPC_time;
                        result_vector[5] = geometric_fail_probability_estimation;
                        result_vector[6] = discrete_laplace_fail_probability_estimation;
                        result_vector[7] = upscale_factor;

                        std::cout << "discrete_laplace_best_iterations_1: " << result_vector[0] << std::endl;
                        std::cout << "discrete_laplace_best_iterations_2: " << result_vector[1] << std::endl;
                        std::cout << "discrete_laplace_best_iterations_3: " << result_vector[2] << std::endl;
                        std::cout << "minimum_total_iteration: " << result_vector[3] << std::endl;
                        std::cout << "minimum_total_MPC_time: " << result_vector[4] << std::endl;

                        std::cout << "geometric_fail_probability_estimation: " << result_vector[5] << std::endl;
                        std::cout << "log2(geometric_fail_probability_estimation): " << log2l(result_vector[5]) << std::endl;

                        std::cout << "discrete_laplace_fail_probability_estimation: " << result_vector[6] << std::endl;
                        std::cout << "log2(discrete_laplace_fail_probability_estimation): " << log2l(result_vector[6]) << std::endl;

                        std::cout << "upscale_factor: " << result_vector[7] << std::endl;
                        std::cout << std::endl;
                    }
                }
            }
        }

    }
    // std::cout << "discrete_laplace_best_iterations_1: " << result_vector[0] << std::endl;
    // std::cout << "discrete_laplace_best_iterations_2: " << result_vector[1] << std::endl;
    // std::cout << "discrete_laplace_best_iterations_3: " << result_vector[2] << std::endl;
    // std::cout << "minimum_total_iteration: " << result_vector[3] << std::endl;
    // std::cout << "minimum_total_MPC_time: " << result_vector[4] << std::endl;
    // std::cout << "geometric_fail_probability_estimation: " << result_vector[5] << std::endl;
    // std::cout << "discrete_laplace_fail_probability_estimation: " << result_vector[6] << std::endl;
    // std::cout << "upscale_factor: " << result_vector[7] << std::endl;
    // std::cout << std::endl;
    return result_vector;
}

template std::vector<long double>
optimize_discrete_laplace_distribution_EXP_iteration<std::uint64_t>(std::uint64_t numerator, std::uint64_t denominator,
                                                                    long double total_fail_probability);

template<typename T>
std::vector<long double>
optimize_discrete_laplace_distribution_EXP_iteration_with_tolerance(double scale, long double total_fail_probability, double error_threshold,
                                                                    double error_granularity) {
    std::cout << "optimize_discrete_laplace_distribution_EXP_iteration_with_tolerance" << std::endl;

    double scale_ = scale;
    std::uint64_t numerator_ = decimalToFraction(1 / scale)[0];
    std::uint64_t denominator_ = decimalToFraction(1 / scale)[1];

    if (error_threshold == 0) {
        return optimize_discrete_laplace_distribution_EXP_iteration<T>(numerator_, denominator_, total_fail_probability);
    } else {

        double error_granularity_ = error_granularity;
        double num_of_trials = error_threshold / error_granularity * 2;

        double scale_round = round(scale_ / error_granularity) * error_granularity;
        double scale_lower_bound = scale_round - error_threshold / 2;
        double scale_upper_bound = scale_round + error_threshold / 2;
        double scale_tmp = scale_lower_bound;

        std::vector<long double> result_vector = optimize_discrete_laplace_distribution_EXP_iteration<T>(numerator_, denominator_,
                                                                                                         total_fail_probability);
        long double minimum_total_iteration_ = result_vector[3];
        for (std::size_t i = 0; i < num_of_trials; i++) {

            scale_tmp = scale_tmp + error_granularity;

            std::cout << "scale with error tolerance: " << scale_tmp << std::endl;

            std::uint64_t numerator_tmp = decimalToFraction(1 / scale_tmp)[0];
            std::uint64_t denominator_tmp = decimalToFraction(1 / scale_tmp)[1];

            std::vector<long double> result_vector_tmp = optimize_discrete_laplace_distribution_EXP_iteration<T>(numerator_tmp, denominator_tmp,
                                                                                                                 total_fail_probability);
            if (result_vector_tmp[3] <= minimum_total_iteration_) {
                minimum_total_iteration_ = result_vector_tmp[3];
                std::cout << "*minimum_total_iteration with error tolerance: " << minimum_total_iteration_ << std::endl;
                result_vector = result_vector_tmp;
            }

        }

        return result_vector;
    }
}

template std::vector<long double>
optimize_discrete_laplace_distribution_EXP_iteration_with_tolerance<std::uint64_t>(double scale, long double total_fail_probability,
                                                                                   double error_threshold, double error_granularity);

long double discrete_laplace_distribution_PDF(long double t, std::int64_t x) {
    long double pdf_x = (expl(1 / t) - 1) / (expl(1 / t) + 1) * (expl(-std::abs(x) / t));
    return pdf_x;
}

template<typename T, typename T_int>
std::vector<long double>
discrete_gaussian_distribution_EXP_fail_probability_estimation(double sigma, T numerator, T denominator, long double iteration_1,
                                                               long double iteration_2, long double iteration_3, long double iteration_4) {
    T t = floor(sigma) + 1;
    T_int pdf_Y_upper_bound = 10000;
//        std::cout << "t: " << t << std::endl;


    T scale_factor = 6;

    if (denominator != 1 && denominator <= scale_factor) {
        numerator = numerator * scale_factor;
        denominator = denominator * scale_factor;

    }

//
    long double discrete_laplace_distribution_EXP_fail_probability_estimation_result = discrete_laplace_distribution_EXP_fail_probability_estimation(
            numerator, denominator, iteration_1, iteration_2, iteration_3);

    long double probability_dlap_fail = discrete_laplace_distribution_EXP_fail_probability_estimation_result;
//        std::cout << "probability_laplace_fail: " << probability_laplace_fail << std::endl;

    long double probability_dlap_success = 1 - discrete_laplace_distribution_EXP_fail_probability_estimation_result;
//    std::cout << "probability_laplace_success: " << probability_laplace_success << std::endl;

//    long double probability_C_equal_0_and_dlap_success = (1 - 0.29) * probability_laplace_success;
//    std::cout << "probability_C_equal_0_and_dlap_success: " << probability_C_equal_0_and_dlap_success << std::endl;
//    long double discrete_gaussian_fail_probability = probability_laplace_fail + probability_C_equal_0_and_dlap_success;
//    std::cout << "discrete_gaussian_fail_probability: " << discrete_gaussian_fail_probability << std::endl;

// this is only an approximation
    long double probability_C_equal_0_and_dlap_success = 0;
    for (T_int i = -pdf_Y_upper_bound; i < pdf_Y_upper_bound; i++) {
        long double probability_Y_equal_i = discrete_laplace_distribution_PDF(t, T_int(i));
        probability_C_equal_0_and_dlap_success = probability_C_equal_0_and_dlap_success + probability_Y_equal_i * (1 - (expl(-powl(
                std::abs((long double) (i)) - sigma * sigma / (long double) (t), 2) / (2 * sigma * sigma)))) * probability_dlap_success;
    }
//    std::cout<<"probability_C_equal_0_and_dlap_success: "<<probability_C_equal_0_and_dlap_success<<std::endl;

//    // only for debugging
//    long double expect_C = 0;
//    long double tau = 1.0 / t;
//    for (T_int i = -pdf_Y_upper_bound; i < pdf_Y_upper_bound; i++) {
//        expect_C = expect_C + (expl(-i*i / (2 * sigma * sigma)));
//    }
//    expect_C = (1 - expl(-tau)) / (1 + expl(-tau)) * expl(-sigma * sigma * tau * tau / 2) * expect_C;
//    std::cout << "expect_C: " << expect_C << std::endl;



//    std::cout << std::endl;
//    probability_C_equal_0_and_laplace_success = powl(probability_C_equal_0_and_laplace_success, iteration_4);

//    long double probability_C_equal_0 = probability_laplace_fail + probability_C_equal_0_and_laplace_success -
//                                        probability_laplace_fail * probability_C_equal_0_and_laplace_success;

    long double discrete_gaussian_fail_probability = probability_dlap_fail + probability_C_equal_0_and_dlap_success;

    std::vector<long double> result_output_vector(1);
    result_output_vector[0] = powl(discrete_gaussian_fail_probability, iteration_4);
//    result_output_vector[1] = probability_C_equal_0_and_laplace_success;
//    result_output_vector[2] = probability_C_equal_0;

    return result_output_vector;
}

template std::vector<long double>
discrete_gaussian_distribution_EXP_fail_probability_estimation<std::uint64_t, std::int64_t>(double sigma, std::uint64_t numerator,
                                                                                            std::uint64_t denominator, long double iteration_1,
                                                                                            long double iteration_2, long double iteration_3,
                                                                                            long double iteration_4);

template<typename T, typename T_int>
std::vector<long double>
discrete_gaussian_distribution_EXP_with_discrete_laplace_EKMPP_fail_probability_estimation(double sigma, long double iteration) {
    T t = floor(sigma) + 1;
    T_int pdf_Y_upper_bound = 100;

    long double probability_dlap_fail = 0;
    long double probability_dlap_success = 1;

    long double probability_C_equal_0_and_dlap_success = 0;
    for (T_int i = -pdf_Y_upper_bound; i < pdf_Y_upper_bound; i++) {
        long double probability_Y_equal_i = discrete_laplace_distribution_PDF(t, T_int(i));
        probability_C_equal_0_and_dlap_success = probability_C_equal_0_and_dlap_success + probability_Y_equal_i * (1 - (expl(-powl(
                std::abs((long double) (i)) - sigma * sigma / (long double) (t), 2) / (2 * sigma * sigma)))) * probability_dlap_success;
    }

    long double discrete_gaussian_fail_probability = probability_dlap_fail + probability_C_equal_0_and_dlap_success;

    std::vector<long double> result_output_vector(1);
    result_output_vector[0] = powl(discrete_gaussian_fail_probability, iteration);

    return result_output_vector;
}

template std::vector<long double>
discrete_gaussian_distribution_EXP_with_discrete_laplace_EKMPP_fail_probability_estimation<std::uint64_t, std::int64_t>(double sigma,
                                                                                                                        long double iteration);

template<typename T, typename T_int>
std::vector<long double> optimize_discrete_gaussian_distribution_EXP_iteration(double sigma, long double total_fail_probability) {
//    std::size_t iteration_1_lower_bound = 1;
//    std::size_t iteration_1_upper_bound = 50;
//    std::size_t iteration_2_upper_bound = 50;
//    std::size_t iteration_3_bound = 100;

    std::cout << "optimize_discrete_gaussian_distribution_EXP_iteration" << std::endl;
    std::cout << "sigma: " << sigma << std::endl;

    std::size_t iteration_4_upper_bound = 100;

    T t = floor(sigma) + 1;
    T numerator = 1;
    T denominator = t;
    std::cout << "numerator: " << numerator << std::endl;
    std::cout << "denominator: " << denominator << std::endl;

    std::vector<long double> optimize_discrete_laplace_distribution_EXP_iteration_result_vector = optimize_discrete_laplace_distribution_EXP_iteration<T>(
            numerator, denominator, total_fail_probability);

    std::size_t iteration_1 = optimize_discrete_laplace_distribution_EXP_iteration_result_vector[0];
    std::size_t iteration_2 = optimize_discrete_laplace_distribution_EXP_iteration_result_vector[1];
    std::size_t iteration_3 = optimize_discrete_laplace_distribution_EXP_iteration_result_vector[2];
    T upscale_factor = optimize_discrete_laplace_distribution_EXP_iteration_result_vector[7];

    long double minimum_total_iteration = ((iteration_1 + iteration_2) * iteration_3 + iteration_3) * iteration_4_upper_bound;

    long double minimum_total_MPC_time =
            ((iteration_1 * iteration_1_weight + iteration_2 * iteration_2_weight) * iteration_3 + iteration_4_weight) * iteration_4_upper_bound;

    std::vector<long double> result_vector(10);

    for (std::size_t iteration_4 = 1; iteration_4 < iteration_4_upper_bound; iteration_4++) {
        long double fail_probability_estimation = discrete_gaussian_distribution_EXP_fail_probability_estimation<T, T_int>(sigma,
                                                                                                                           numerator * upscale_factor,
                                                                                                                           denominator *
                                                                                                                           upscale_factor,
                                                                                                                           iteration_1, iteration_2,
                                                                                                                           iteration_3,
                                                                                                                           iteration_4)[0];
        if ((((iteration_1 + iteration_2) * iteration_3 + iteration_3) * iteration_4 < minimum_total_iteration) &&
            (fail_probability_estimation <= total_fail_probability)) {

//                    if ((((iteration_1 * iteration_1_weight + iteration_2 * iteration_2_weight) * iteration_3 + iteration_4_weight) * iteration_4 <=
//                         minimum_total_MPC_time) && (fail_probability_estimation <= total_fail_probability)) {

//        if (fail_probability_estimation <= total_fail_probability) {

            minimum_total_iteration = ((iteration_1 + iteration_2) * iteration_3 + iteration_3) * iteration_4;

            minimum_total_MPC_time = ((iteration_1 * iteration_1_weight + iteration_2 * iteration_2_weight) * iteration_3 + iteration_4_weight);

            result_vector[0] = iteration_1;
            result_vector[1] = iteration_2;
            result_vector[2] = iteration_3;
            result_vector[3] = iteration_4;
            result_vector[4] = minimum_total_iteration;
            result_vector[5] = minimum_total_MPC_time;
            result_vector[6] = optimize_discrete_laplace_distribution_EXP_iteration_result_vector[5];
            result_vector[7] = optimize_discrete_laplace_distribution_EXP_iteration_result_vector[6];
            result_vector[8] = fail_probability_estimation;
            result_vector[9] = upscale_factor;

            std::cout << "discrete_gaussian_best_iteration_1: " << iteration_1 << std::endl;
            std::cout << "discrete_gaussian_best_iteration_2: " << iteration_2 << std::endl;
            std::cout << "discrete_gaussian_best_iteration_3: " << iteration_3 << std::endl;
            std::cout << "discrete_gaussian_best_iteration_4: " << iteration_4 << std::endl;
            std::cout << "minimum_total_iteration: " << minimum_total_iteration << std::endl;
            std::cout << "minimum_total_MPC_time: " << result_vector[5] << std::endl;
            std::cout << "geometric_fail_probability_estimation: " << result_vector[6] << std::endl;
            std::cout << "discrete_laplace_fail_probability_estimation: " << result_vector[7] << std::endl;
            std::cout << "discrete_gaussian_fail_probability_estimation: " << result_vector[8] << std::endl;
            std::cout << "upscale_factor: " << result_vector[9] << std::endl;
            std::cout << std::endl;
            break;
        }
    }

    return result_vector;
}

template std::vector<long double>
optimize_discrete_gaussian_distribution_EXP_iteration<std::uint64_t, std::int64_t>(double sigma, long double total_fail_probability);

template<typename T, typename T_int>
std::vector<long double>
optimize_discrete_gaussian_distribution_EXP_with_discrete_laplace_EKMPP_iteration(double sigma, long double total_fail_probability) {

    std::cout << "optimize_discrete_gaussian_distribution_EXP_iteration" << std::endl;
    std::cout << "sigma: " << sigma << std::endl;

    std::size_t iteration_upper_bound = 100;

    long double minimum_total_iteration = iteration_upper_bound;
    long double minimum_total_MPC_time = (iteration_4_weight) * iteration_upper_bound;

    std::vector<long double> result_vector(4);

    for (std::size_t iteration = 1; iteration < iteration_upper_bound; iteration++) {
        long double fail_probability_estimation = discrete_gaussian_distribution_EXP_with_discrete_laplace_EKMPP_fail_probability_estimation<std::uint64_t, std::int64_t>(
                sigma, iteration)[0];

        if ((fail_probability_estimation <= total_fail_probability)) {

            minimum_total_iteration = iteration;

//            minimum_total_MPC_time = ((iteration_1 * iteration_1_weight + iteration_2 * iteration_2_weight) * iteration_3 + iteration_4_weight);

            result_vector[0] = iteration;
            result_vector[1] = minimum_total_iteration;
            result_vector[2] = minimum_total_MPC_time;
            result_vector[3] = fail_probability_estimation;

            std::cout << "discrete_gaussian_best_iteration: " << iteration << std::endl;
            std::cout << "minimum_total_iteration: " << minimum_total_iteration << std::endl;
            std::cout << "minimum_total_MPC_time: " << minimum_total_MPC_time << std::endl;
            std::cout << "discrete_gaussian_fail_probability_estimation: " << fail_probability_estimation << std::endl;
            std::cout << std::endl;
            break;
        }
    }

    return result_vector;

}

template std::vector<long double>
optimize_discrete_gaussian_distribution_EXP_with_discrete_laplace_EKMPP_iteration<std::uint64_t, std::int64_t>(double sigma,
                                                                                                               long double total_fail_probability);

template<typename T, typename T_int>
std::vector<T> geometric_noise_generation(T numerator, T denominator, long double fail_probability, std::size_t num_of_elements) {

    std::cout << "numerator: " << numerator << std::endl;
    std::cout << "denominator: " << denominator << std::endl;

    std::vector<long double> optimize_geometric_distribution_EXP_iteration_result_vector = optimize_geometric_distribution_EXP_iteration<T>(numerator,
                                                                                                                                            denominator,
                                                                                                                                            fail_probability);
    std::size_t iteration_1 = optimize_geometric_distribution_EXP_iteration_result_vector[0];
    std::size_t iteration_2 = optimize_geometric_distribution_EXP_iteration_result_vector[1];
    std::size_t total_iteration = optimize_geometric_distribution_EXP_iteration_result_vector[2];
    long double total_fail_probability = optimize_geometric_distribution_EXP_iteration_result_vector[3];

    std::cout << "iteration_1: " << iteration_1 << std::endl;
    std::cout << "iteration_2: " << iteration_2 << std::endl;
    std::cout << "total_iteration: " << total_iteration << std::endl;

    std::vector<T> result_vector(num_of_elements);

    if (denominator == 1) {
        iteration_1 = 0;
    }

    for (std::size_t j = 0; j < num_of_elements; j++) {
        std::vector<double> uniform_floating_point_0_1_vector = rand_range_double_vector(0, 1, (iteration_1 + iteration_2));

        std::vector<T> random_integer_vector = rand_range_integer_vector<T>(0, denominator, iteration_1);

        if (denominator != 1) {
            std::vector<T> geometric_distribution_EXP_result = geometric_distribution_EXP<T, std::allocator<T>>(numerator, denominator,
                                                                                                                uniform_floating_point_0_1_vector,
                                                                                                                random_integer_vector, iteration_1,
                                                                                                                iteration_2);
            std::cout << "geometric_distribution_EXP_result[0]: " << std::int64_t(geometric_distribution_EXP_result[0]) << std::endl;
//            std::cout << "discrete_laplace_distribution_EXP_result[1]: " << discrete_laplace_distribution_EXP_result[1] << std::endl;
            result_vector[j] = geometric_distribution_EXP_result[0];
        } else {
            std::vector<T> geometric_distribution_EXP_result = geometric_distribution_EXP<T, std::allocator<T>>(numerator,
                                                                                                                uniform_floating_point_0_1_vector,
                                                                                                                iteration_2);
            std::cout << "geometric_distribution_EXP_result[0]: " << std::int64_t(geometric_distribution_EXP_result[0]) << std::endl;
//            std::cout << "discrete_laplace_distribution_EXP_result[1]: " << discrete_laplace_distribution_EXP_result[1] << std::endl;

            result_vector[j] = geometric_distribution_EXP_result[0];
        }
    }

    return result_vector;

}

template std::vector<std::uint64_t>
geometric_noise_generation<std::uint64_t, std::int64_t>(std::uint64_t numerator, std::uint64_t denominator, long double fail_probability,
                                                        std::size_t num_of_elements);

template<typename T, typename T_int>
std::vector<T> discrete_laplace_noise_generation(double scale, long double fail_probability, std::size_t num_of_elements) {
    std::uint64_t numerator = decimalToFraction(1 / scale)[0];
    std::uint64_t denominator = decimalToFraction(1 / scale)[1];

    std::cout << "numerator: " << numerator << std::endl;
    std::cout << "denominator: " << denominator << std::endl;

    std::vector<long double> optimize_discrete_laplace_distribution_EXP_iteration_result_vector = optimize_discrete_laplace_distribution_EXP_iteration<T>(
            numerator, denominator, fail_probability);
    std::size_t iteration_1 = optimize_discrete_laplace_distribution_EXP_iteration_result_vector[0];
    std::size_t iteration_2 = optimize_discrete_laplace_distribution_EXP_iteration_result_vector[1];
    std::size_t iteration_3 = optimize_discrete_laplace_distribution_EXP_iteration_result_vector[2];
    std::size_t total_iteration = optimize_discrete_laplace_distribution_EXP_iteration_result_vector[3];
    long double total_fail_probability = optimize_discrete_laplace_distribution_EXP_iteration_result_vector[4];

    std::cout << "iteration_1: " << iteration_1 << std::endl;
    std::cout << "iteration_2: " << iteration_2 << std::endl;
    std::cout << "iteration_3: " << iteration_3 << std::endl;
    std::cout << "total_iteration: " << total_iteration << std::endl;

    std::vector<T> result_vector(num_of_elements);

    if (denominator == 1) {
        iteration_1 = 0;
    }
//

    for (std::size_t j = 0; j < num_of_elements; j++) {
        std::vector<double> uniform_floating_point_0_1_vector = rand_range_double_vector(0, 1, (iteration_1 + iteration_2) * iteration_3);

        std::vector<T> random_integer_vector = rand_range_integer_vector<T>(0, denominator, iteration_1 * iteration_3);

        std::vector<bool> bernoulli_sample_vector = rand_bool_vector(iteration_3);

        if (denominator != 1) {
            std::vector<T> discrete_laplace_distribution_EXP_result = discrete_laplace_distribution_EXP<T, std::allocator<T>>(numerator, denominator,
                                                                                                                              uniform_floating_point_0_1_vector,
                                                                                                                              random_integer_vector,
                                                                                                                              bernoulli_sample_vector,
                                                                                                                              iteration_1,
                                                                                                                              iteration_2,
                                                                                                                              iteration_3);
//            std::cout << "discrete_laplace_distribution_EXP_result[0]: " << std::int64_t(discrete_laplace_distribution_EXP_result[0]) << std::endl;
//            std::cout << "discrete_laplace_distribution_EXP_result[1]: " << discrete_laplace_distribution_EXP_result[1] << std::endl;
            result_vector[j] = discrete_laplace_distribution_EXP_result[0];
        } else {
            std::vector<T> discrete_laplace_distribution_EXP_result = discrete_laplace_distribution_EXP<T, std::allocator<T>>(numerator,
                                                                                                                              uniform_floating_point_0_1_vector,
                                                                                                                              bernoulli_sample_vector,
                                                                                                                              iteration_2,
                                                                                                                              iteration_3);
//            std::cout << "discrete_laplace_distribution_EXP_result[0]: " << std::int64_t(discrete_laplace_distribution_EXP_result[0]) << std::endl;
//            std::cout << "discrete_laplace_distribution_EXP_result[1]: " << discrete_laplace_distribution_EXP_result[1] << std::endl;

            result_vector[j] = discrete_laplace_distribution_EXP_result[0];
        }
    }

    return result_vector;
}

template std::vector<std::uint64_t>
discrete_laplace_noise_generation<std::uint64_t, std::int64_t>(double scale, long double fail_probability, std::size_t num_of_elements);

template<typename T, typename T_int>
std::vector<T> discrete_gaussian_noise_generation(double sigma, long double fail_probability, std::size_t num_of_elements) {
    std::uint64_t t = floor(sigma) + 1;

    std::vector<long double> optimize_discrete_gaussian_distribution_EXP_iteration_result_vector = optimize_discrete_gaussian_distribution_EXP_iteration<T, T_int>(
            sigma, fail_probability);
    std::size_t iteration_1 = optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[0];
    std::size_t iteration_2 = optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[1];
    std::size_t iteration_3 = optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[2];
    std::size_t iteration_4 = optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[3];
    std::size_t total_iteration = optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[4];
    long double total_fail_probability = optimize_discrete_gaussian_distribution_EXP_iteration_result_vector[5];

    std::cout << "iteration_1: " << iteration_1 << std::endl;
    std::cout << "iteration_2: " << iteration_2 << std::endl;
    std::cout << "iteration_3: " << iteration_3 << std::endl;
    std::cout << "iteration_4: " << iteration_4 << std::endl;
    std::cout << "total_iteration: " << total_iteration << std::endl;

    std::vector<T> result_vector(num_of_elements);

    if (t == 1) {
        iteration_1 = 0;
    }

    for (std::size_t j = 0; j < num_of_elements; j++) {
        std::vector<double> random_floating_point_0_1_dlap_vector = rand_range_double_vector(0, 1,
                                                                                             (iteration_1 + iteration_2) * iteration_3 * iteration_4);

        std::vector<T> random_integer_dlap_vector = rand_range_integer_vector<T>(0, t, iteration_1 * iteration_3 * iteration_4);

        std::vector<bool> bernoulli_sample_dlap_vector = rand_bool_vector(iteration_3 * iteration_4);

        std::vector<double> random_floating_point_0_1_dgau_vector = rand_range_double_vector(0, 1, iteration_4);

        if (t != 1) {
            std::vector<T> discrete_gaussian_distribution_EXP_result = discrete_gaussian_distribution_EXP<T, T_int, std::allocator<T>>(sigma,
                                                                                                                                       random_floating_point_0_1_dlap_vector,
                                                                                                                                       random_integer_dlap_vector,
                                                                                                                                       bernoulli_sample_dlap_vector,
                                                                                                                                       random_floating_point_0_1_dgau_vector,
                                                                                                                                       iteration_1,
                                                                                                                                       iteration_2,
                                                                                                                                       iteration_3,
                                                                                                                                       iteration_4);
            std::cout << "discrete_gaussian_distribution_EXP_result[0]: " << T_int(discrete_gaussian_distribution_EXP_result[0]) << std::endl;
//            std::cout << "discrete_gaussian_distribution_EXP_result[1]: " << discrete_gaussian_distribution_EXP_result[1] << std::endl;

            result_vector[j] = discrete_gaussian_distribution_EXP_result[0];
        } else {
            std::vector<T> discrete_gaussian_distribution_EXP_result = discrete_gaussian_distribution_EXP<T, T_int, std::allocator<T>>(sigma,
                                                                                                                                       random_floating_point_0_1_dlap_vector,
                                                                                                                                       bernoulli_sample_dlap_vector,
                                                                                                                                       random_floating_point_0_1_dgau_vector,
                                                                                                                                       iteration_2,
                                                                                                                                       iteration_3,
                                                                                                                                       iteration_4);
            std::cout << "discrete_gaussian_distribution_EXP_result[0]: " << T_int(discrete_gaussian_distribution_EXP_result[0]) << std::endl;
//            std::cout << "discrete_gaussian_distribution_EXP_result[1]: " << discrete_gaussian_distribution_EXP_result[1] << std::endl;
            result_vector[j] = discrete_gaussian_distribution_EXP_result[0];
        }
    }
    return result_vector;

}

template std::vector<std::uint64_t>
discrete_gaussian_noise_generation<std::uint64_t, std::int64_t>(double sigma, long double fail_probability, std::size_t num_of_elements);

void test_optimize_discrete_laplace_distribution_EXP_iteration() {

//    double scale = 0.788766;
//    double numerator = 1427419685638527;
//    double denominator = 1125899906842624;


//    double scale =26053.8;
//    double numerator = 177006027106111;
//    double denominator = 4611686018427387904;
    std::srand(time(nullptr));

    double total_fail_probability = std::exp2(-40);
    std::size_t num_of_elements = 100;
    double min = 0;

//    double max = 0.1; // high iterations
    double max = 2; // low iterations
//    double max = 10; // low iterations

    std::vector<double> scale_double_vector = rand_range_double_vector(min, max, num_of_elements);

    for (std::size_t i = 0; i < num_of_elements; i++) {
        std::cout << "i: " << i << std::endl;
        double scale_tmp = scale_double_vector[i];

//        // only for debug
        scale_tmp=0.5;

        std::uint64_t numerator_tmp = decimalToFraction(1 / scale_tmp)[0];
        std::uint64_t denominator_tmp = decimalToFraction(1 / scale_tmp)[1];

        std::cout << "scale_tmp: " << scale_tmp << std::endl;
        std::cout << "numerator_tmp: " << numerator_tmp << std::endl;
        std::cout << "denominator_tmp: " << denominator_tmp << std::endl;

        optimize_discrete_laplace_distribution_EXP_iteration(numerator_tmp, denominator_tmp, total_fail_probability);
        std::cout << "================================================================" << std::endl;
        std::cout << std::endl;

    }
}

void test_optimize_discrete_gaussian_distribution_EXP_iteration() {

    double total_fail_probability = std::exp2(-40);
    std::size_t num_of_elements = 100;
    double min = 1;

    double max = 2; // iterations_1=0
//    double max = 10;
//    double max = 100;

    std::vector<double> sigma_double_vector = rand_range_double_vector(min, max, num_of_elements);

    for (std::size_t i = 0; i < num_of_elements; i++) {
        std::cout << "i: " << i << std::endl;
        double sigma_tmp = sigma_double_vector[i];

        // only for debug
//        sigma_tmp=0.75;


        double t_tmp = floor(sigma_tmp) + 1;
        std::uint64_t numerator_tmp = 1;
        std::uint64_t denominator_tmp = t_tmp;

        std::cout << "sigma_tmp: " << sigma_tmp << std::endl;
        std::cout << "t_tmp: " << t_tmp << std::endl;
        std::cout << "numerator_tmp: " << numerator_tmp << std::endl;
        std::cout << "denominator_tmp: " << denominator_tmp << std::endl;

        optimize_discrete_gaussian_distribution_EXP_iteration<std::uint64_t, std::int64_t>(sigma_tmp, total_fail_probability);
        std::cout << "================================================================" << std::endl;

    }
}

void test_optimize_discrete_laplace_distribution_EXP_iteration_with_threshold() {

//    double scale = 0.788766;
//    double numerator = 1427419685638527;
//    double denominator = 1125899906842624;


//    double scale =26053.8;
//    double numerator = 177006027106111;
//    double denominator = 4611686018427387904;
    std::srand(time(nullptr));

    double total_fail_probability = std::exp2(-40);
    std::size_t num_of_elements = 1;
    double min = 0;

//    double max = 0.1; // high iterations
    double max = 1; // low iterations
//    double max = 10; // low iterations

    std::vector<double> scale_double_vector = rand_range_double_vector(min, max, num_of_elements);

    for (std::size_t i = 0; i < num_of_elements; i++) {
        std::cout << "i: " << i << std::endl;
//        double scale_tmp = scale_double_vector[i];

        // only for debug
        double scale_tmp = 1.2;

// only for debug
        double error_threshold = 0.01;
        double error_granularity = 0.0001;

        std::uint64_t numerator_tmp = decimalToFraction(1 / scale_tmp)[0];
        std::uint64_t denominator_tmp = decimalToFraction(1 / scale_tmp)[1];

        std::cout << "scale_tmp: " << scale_tmp << std::endl;
        std::cout << "numerator_tmp: " << numerator_tmp << std::endl;
        std::cout << "denominator_tmp: " << denominator_tmp << std::endl;

        optimize_discrete_laplace_distribution_EXP_iteration_with_tolerance<std::uint64_t>(scale_tmp, total_fail_probability, error_threshold,
                                                                                           error_granularity);
        std::cout << "================================================================" << std::endl;
        std::cout << std::endl;

    }
}