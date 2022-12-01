#include "discrete_gaussian_mechanism.h"
#include <cstdint>
#include <iostream>

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
        // skip the first for loop
        if (denominator == 1) {
            u = 0;
            u_success = true;
        }

            // the first for loop
        else {
            for (std::size_t i = 0; i < iteration_1; i++) {
                // bernoulli (p = exp^(-U/t))
                bool b1 = random_floating_point_0_1_vector[i] < std::exp(-(double) (random_integer_vector[i]) / (double) (denominator));

                // the first for loop succeeds and terminates
                if (b1 == 1) {
                    u = random_integer_vector[i];
                    u_success = true;
                    std::cout << "i: " << i << std::endl;
                    std::cout << "u_success" << std::endl;
                    break;
                }
            }
        }

        T v = 0;
        T v_success = false;

        // the second for loop
        for (std::size_t j = 0; j < iteration_2; j++) {
            bool b2 = random_floating_point_0_1_vector[iteration_1 + j] < std::exp(-1);

            if (b2 == 0) {
                v = j;
                v_success = true;
                std::cout << "j: " << j << std::endl;
                std::cout << "v_success" << std::endl;
                break;
            } else {
                v = j + 1;
            }
        }
        T t = denominator;
        T w = v * t + u;
        std::cout << "v: " << v << std::endl;
        std::cout << "u: " << u << std::endl;
        std::cout << "w: " << w << std::endl;

        std::vector<T> result_vector(2);
        // result_vector[0] = w / numerator;

        // output value of zeros if both for loops don't succeed
        result_vector[0] = floor(double(w) / double(numerator)) * (u_success & v_success);
        if (w / numerator != result_vector[0]) {
            std::cout << "unsigned integer division is not rounded towards zero! " << std::endl;
        }
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

    // degenerated case
    if (numerator == 0) {
        // std::cout << "numerator == 0" << std::endl;
        std::vector<T> result_vector(2);
        result_vector[0] = 0;
        result_vector[1] = 1;
        return result_vector;
    }

        // special case when denominator = 1, where bernoulli (p = exp^(-0/t)) always output 1, skip the
        // first for loop
    else {
        T u = 0;
        bool u_success = false;

        u = 0;
        u_success = true;

        T v = 0;
        T v_success = false;

        // begin the second for loop
        for (std::size_t j = 0; j < iteration_2; j++) {
            bool b2 = random_floating_point_0_1_vector[j] < std::exp(-1);

            // the second for loop succeeds and terminates
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
        // result_vector[0] = w / numerator;

        // if the second for loop fails, output value of zero instead
        result_vector[0] = floor(double(w) / double(numerator)) * (v_success);
        if (w / numerator != result_vector[0]) {
            std::cout << "unsigned integer division is not rounded towards zero! " << std::endl;
        }
        result_vector[1] = T(u_success & v_success);

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
std::vector<T> discrete_gaussian_distribution_EXP(double sigma, T numerator, T denominator, std::vector<double> random_floating_point_0_1_dlap_vector,
                                                  std::vector<T, A> random_integer_dlap_vector, std::vector<bool> bernoulli_sample_dlap_vector,
                                                  std::vector<double> random_floating_point_0_1_dgau_vector, std::size_t iteration_1,
                                                  std::size_t iteration_2, std::size_t iteration_3, std::size_t iteration_4) {
    std::cout << "discrete_gaussian_distribution_EXP" << std::endl;
    assert(sigma > 0);
    assert(random_floating_point_0_1_dlap_vector.size() == (iteration_1 + iteration_2) * iteration_3 * iteration_4);
    assert(random_integer_dlap_vector.size() == iteration_1 * iteration_3 * iteration_4);
    assert(bernoulli_sample_dlap_vector.size() == iteration_3 * iteration_4);
    assert(random_floating_point_0_1_dgau_vector.size() == iteration_4);

    std::vector<T> result_vector(2);
    std::size_t num_of_simd_dgau = iteration_4;

    bool iteration_4_finish = false;

    for (std::size_t i = 0; i < iteration_4; i++) {
        std::cout << "i: " << i << std::endl;
        std::vector<double> random_floating_point_0_1_dlap_subvector(

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
        // T numerator = 1;
        // T denominator = t;
        std::cout << "numerator: " << numerator << std::endl;
        std::cout << "denominator: " << denominator << std::endl;

        // // only for deubgging
        // T numerator_new = numerator;
        // T denominator_new = denominator;
        // std::cout << "numerator_new: " << numerator_new << std::endl;
        // std::cout << "denominator_new: " << denominator_new << std::endl;

        std::vector<T> discrete_laplace_distribution_EXP_result = discrete_laplace_distribution_EXP<T, A>(numerator, denominator,
                                                                                                          random_floating_point_0_1_dlap_subvector,
                                                                                                          random_integer_subvector,
                                                                                                          bernoulli_sample_dlap_subvector,
                                                                                                          iteration_1, iteration_2, iteration_3);

        T_int Y = discrete_laplace_distribution_EXP_result[0];
        bool dlap_success = discrete_laplace_distribution_EXP_result[1];
        std::cout << "dlap_success: " << dlap_success << std::endl;
        bool C = random_floating_point_0_1_dgau_vector[i] < exp(-(abs(Y) - sigma * sigma / t) * (abs(Y) - sigma * sigma / t) / (2 * sigma * sigma));

        std::cout << "C: " << C << std::endl;
        std::cout << "Y: " << Y << std::endl;
        std::cout << "random_floating_point_0_1_dgau_vector[i]: " << random_floating_point_0_1_dgau_vector[i] << std::endl;
        std::cout << "exp(-(abs(Y) - sigma * sigma / t) * (abs(Y) - sigma * sigma / t) / (2 * sigma "
                     "*sigma)): " << exp(-(abs(Y) - sigma * sigma / t) * (abs(Y) - sigma * sigma / t) / (2 * sigma * sigma)) << std::endl;

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
        //        std::cout << "dgau_success & dlap_success: " << (dgau_success & dlap_success) <<
        //        std::endl;
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

template std::vector<std::uint64_t>
discrete_gaussian_distribution_EXP<std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(double sigma, std::uint64_t numerator,
                                                                                               std::uint64_t denominator,
                                                                                               std::vector<double> random_floating_point_0_1_dlap_vector,
                                                                                               std::vector<std::uint64_t, std::allocator<std::uint64_t>> random_integer_dlap_vector,
                                                                                               std::vector<bool> bernoulli_sample_dlap_vector,
                                                                                               std::vector<double> random_floating_point_0_1_dgau_vector,
                                                                                               std::size_t iteration_1, std::size_t iteration_2,
                                                                                               std::size_t iteration_3, std::size_t iteration_4);

template<typename T, typename T_int, typename A>
std::vector<T> discrete_gaussian_distribution_EXP(double sigma, T numerator, T denominator, std::vector<double> random_floating_point_0_1_dlap_vector,
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
        // T numerator = 1;
        // T denominator = t;
        // T numerator = numerator;
        // std::cout<<"denominator: "<<denominator<<std::endl;
        // T denominator = denominator;
        // std::cout<<"denominator: "<<denominator<<std::endl;


        assert(denominator == 1);

        std::vector<T> discrete_laplace_distribution_EXP_result = discrete_laplace_distribution_EXP<T, A>(numerator,
                                                                                                          random_floating_point_0_1_dlap_subvector,
                                                                                                          bernoulli_sample_dlap_subvector,
                                                                                                          iteration_2, iteration_3);

        T_int Y = discrete_laplace_distribution_EXP_result[0];
        bool dlap_success = discrete_laplace_distribution_EXP_result[1];
        bool C = random_floating_point_0_1_dgau_vector[i] < exp(-(abs(Y) - sigma * sigma / t) * (abs(Y) - sigma * sigma / t) / (2 * sigma * sigma));

        //        std::cout << "exp(-(abs(Y) - sigma * sigma / t) * (abs(Y) - sigma * sigma / t) / (2 *
        //        sigma * "
        //                     "sigma)): " << exp(-(abs(Y) - sigma * sigma / t) * (abs(Y) - sigma *
        //                     sigma / t) / (2 * sigma * sigma)) << std::endl;

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
        //        std::cout << "dgau_success & dlap_success: " << (dgau_success & dlap_success) <<
        //        std::endl;
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

template std::vector<std::uint64_t>
discrete_gaussian_distribution_EXP<std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(double sigma, std::uint64_t numerator,
                                                                                               std::uint64_t denominator,
                                                                                               std::vector<double> random_floating_point_0_1_dlap_vector,
                                                                                               std::vector<bool> bernoulli_sample_dlap_vector,
                                                                                               std::vector<double> random_floating_point_0_1_dgau_vector,
                                                                                               std::size_t iteration_2, std::size_t iteration_3,
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

        //        std::cout << "exp(-(abs(Y) - sigma * sigma / t) * (abs(Y) - sigma * sigma / t) / (2 *
        //        sigma * "
        //                     "sigma)): " << exp(-(abs(Y) - sigma * sigma / t) * (abs(Y) - sigma *
        //                     sigma / t) / (2 * sigma * sigma)) << std::endl;

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
long double geometric_distribution_EXP_failure_probability_estimation(T numerator, T denominator, long double iteration_1, long double iteration_2) {
    long double failure_probability_geometric_slow = exp(-1);
    long double failure_probability_geometric_fast_uniform = 0;

    if (denominator != 1) {
        // use analytic solution to compute failure_probability_geometric_fast_uniform
        failure_probability_geometric_fast_uniform =
                1 - ((1 - expl(-1.0)) / (1 - expl(-1.0 / (long double) (denominator)))) / (long double) (denominator);
        //        std::cout << "failure_probability_geometric_fast_uniform: " <<
        //        failure_probability_geometric_fast_uniform << std::endl;

        long double result;

        // probability geometric_fast_uniform or geometric_slow fail
        result = powl(failure_probability_geometric_fast_uniform, iteration_1) + powl(failure_probability_geometric_slow, iteration_2) -
                 powl(failure_probability_geometric_fast_uniform, iteration_1) * powl(failure_probability_geometric_slow, iteration_2);
        return result;

    } else {
        failure_probability_geometric_fast_uniform = 0;
        long double result;
        result = powl(failure_probability_geometric_slow, iteration_2);
        return result;
    }
}

template long double
geometric_distribution_EXP_failure_probability_estimation<std::uint64_t>(std::uint64_t numerator, std::uint64_t denominator, long double iteration_1,
                                                                         long double iteration_2);

template<typename T>
GeometricDistributionEXPOptimizationStruct<T>
optimize_geometric_distribution_EXP_iteration(T numerator_init, T denominator_init, long double total_failure_probability) {
    // std::cout << "optimize_geometric_distribution_EXP_iteration" << std::endl;
    //    std::vector<long double> initial_estimation_result_vector =
    //    geometric_distribution_EXP_iteration_estimation<std::uint64_t>(numerator, denominator,
    //                                                                                                                               total_failure_probability);
    //    long double max_iterations = initial_estimation_result_vector[0] +
    //    initial_estimation_result_vector[1]; long double min_iterations =
    //    std::min(initial_estimation_result_vector[0], initial_estimation_result_vector[1]); long
    //    double min_iterations = 1;

    T numerator = numerator_init;
    T denominator = denominator_init;

    std::size_t iteration_1_lower_bound = 1;
    std::size_t iteration_1_upper_bound = 150;
    std::size_t iteration_2_upper_bound = 150;

    long double minimum_iteration_1 = iteration_1_upper_bound;
    long double minimum_iteration_2 = iteration_2_upper_bound;
    long double minimum_total_iteration = iteration_1_upper_bound + iteration_2_upper_bound;

    long double minimum_total_MPC_time = (iteration_1_upper_bound * iteration_1_weight + iteration_2_upper_bound * iteration_2_weight);

    // // rescale numerator and denominator s.t., to reduce MPC iterations without decrease fail
    // // probability
    // T upscale_factor_lower_bound = 1;
    // T upscale_factor_upper_bound = 50;
    std::size_t upscale_factor = 1;

    if (denominator == 1) {
        iteration_1_lower_bound = 0;
        iteration_1_upper_bound = 1;
        // upscale_factor_upper_bound = 2;
    }

    // if (denominator > 20) {
    //   upscale_factor_upper_bound = 2;
    // }

    // std::vector<long double> result_vector(6);
    GeometricDistributionEXPOptimizationStruct<T> result_struct{};
    //    result_vector[0] = initial_estimation_result_vector[0];
    //    result_vector[1] = initial_estimation_result_vector[1];

    // upscale_factor_upper_bound = 10;
    // upscale_factor_upper_bound = 2;

    // for (std::size_t upscale_factor = upscale_factor_lower_bound;
    //      upscale_factor < upscale_factor_upper_bound; upscale_factor++) {
    for (std::size_t iteration_1 = iteration_1_lower_bound; iteration_1 < iteration_1_upper_bound; iteration_1++) {
        // for (std::size_t iteration_2 = 1; iteration_2 < iteration_2_upper_bound; iteration_2++) {
        //   long double failure_probability_estimation =
        //       geometric_distribution_EXP_failure_probability_estimation<std::uint64_t>(
        //           numerator * upscale_factor, denominator * upscale_factor, iteration_1,
        //           iteration_2);
        for (std::size_t iteration_2 = 1; iteration_2 < iteration_2_upper_bound; iteration_2++) {
            long double failure_probability_estimation = geometric_distribution_EXP_failure_probability_estimation<std::uint64_t>(numerator,
                                                                                                                                  denominator,
                                                                                                                                  iteration_1,
                                                                                                                                  iteration_2);

//            if (((iteration_1 + iteration_2) <= minimum_total_iteration) && (failure_probability_estimation <= total_failure_probability)) {

            if (((iteration_1) <= minimum_iteration_1) && (failure_probability_estimation <= total_failure_probability)) {

                //            if (((iteration_1 * iteration_1_weight + iteration_2 * iteration_2_weight)
                //            <= minimum_total_MPC_time) &&
                //                (failure_probability_estimation <= total_failure_probability)) {



                minimum_iteration_1 = iteration_1;

                if (iteration_2 < minimum_iteration_2) { minimum_iteration_2 = iteration_2; }

                minimum_total_iteration = iteration_1 + minimum_iteration_2;
                minimum_total_MPC_time = iteration_1 * iteration_1_weight + minimum_iteration_2 * iteration_2_weight;
                result_struct.iteration_1 = iteration_1;
                result_struct.iteration_2 = minimum_iteration_2;
                result_struct.minimum_total_iteration = minimum_total_iteration;
                result_struct.minimum_total_MPC_time = minimum_total_MPC_time;
                result_struct.geometric_failure_probability_estimation = failure_probability_estimation;
                result_struct.upscale_factor = upscale_factor;

                // std::cout << "minimum_iteration_1: " << minimum_iteration_1 << std::endl;
                // std::cout << "minimum_iteration_2: " << minimum_iteration_2 << std::endl;
                // std::cout << "geometric_minimum_total_iteration: " << minimum_total_iteration <<
                // std::endl; std::cout << "minimum_total_MPC_time: " << minimum_total_MPC_time <<
                // std::endl;

                // std::cout << "geometric_best_iterations_1_result: " << result_vector[0] << std::endl;
                // std::cout << "geometric_best_iterations_2_result: " << result_vector[1] << std::endl;
                // std::cout << "geometric_best_failure_probability_result: " << result_vector[4] <<
                // std::endl; std::cout << "geometric_upscale_factor: " << result_vector[5] << std::endl;
                // std::cout << "================================================================"
                //           << std::endl;
                // std::cout << std::endl;
            }
        }
    }
    // }

    return result_struct;
}

template GeometricDistributionEXPOptimizationStruct<std::uint64_t>
optimize_geometric_distribution_EXP_iteration<std::uint64_t>(std::uint64_t numerator, std::uint64_t denominator,
                                                             long double total_failure_probability);

template<typename T>
GeometricDistributionEXPOptimizationStruct<T> optimize_geometric_distribution_EXP_iteration(long double x, long double total_failure_probability) {
    long double x_init = x;

    // std::vector<long double> result_vector_1(8);
    // std::vector<long double> result_vector_2(8);
    GeometricDistributionEXPOptimizationStruct<T> result_struct_1{};
    GeometricDistributionEXPOptimizationStruct<T> result_struct_2{};

    long double relative_error = 0.01;

    std::vector<long double> numerator_denominator_relative_error_vector(3);
    numerator_denominator_relative_error_vector[2] = 1;

    // check if we can change the denominator to 1, 2, 4, or 8
    // these values will decrease the failure_probabiility
    // std::cout << "denominator to 1, 2, 4, or 8" << std::endl;
    bool denominator_1_2_4_8 = false;
    for (std::size_t i = 0; i < 4; i++) {
        // std::cout<<"i: " << i << std::endl;
        T denominator_tmp = (powl(2, i));
        numerator_denominator_relative_error_vector = decimalToFractionWithDenominatorFixed(x, (long double) (denominator_tmp));
        T numerator_tmp = numerator_denominator_relative_error_vector[0];

        long double relative_error_tmp = numerator_denominator_relative_error_vector[2];
        // std::cout << "numerator_tmp: " << numerator_tmp << std::endl;
        // std::cout << "denominator_tmp: " << denominator_tmp << std::endl;
        // std::cout << "relative_error_tmp: " << relative_error_tmp << std::endl;
        if (relative_error_tmp < relative_error) {
            result_struct_1 = optimize_geometric_distribution_EXP_iteration(numerator_tmp, denominator_tmp, total_failure_probability);
            denominator_1_2_4_8 = true;
            result_struct_1.numerator = (numerator_tmp);
            result_struct_1.denominator = (denominator_tmp);
            result_struct_1.log2_denominator = i;
            break;
        }
    }

    // for 64-bit floating point
    // std::size_t log2_denominator = 48;

    // decrease log2_denominator for 32-bit floating-point and fixed-point
    std::size_t log2_denominator = 20;

    long double denominator_mod = powl(2, log2_denominator);
    numerator_denominator_relative_error_vector = decimalToFractionWithDenominatorFixed(x, denominator_mod);
    T numerator_tmp = numerator_denominator_relative_error_vector[0];
    T denominator_tmp = numerator_denominator_relative_error_vector[1];

    // std::cout << "numerator_tmp: " << numerator_tmp << std::endl;
    // std::cout << "denominator_tmp: " << denominator_tmp << std::endl;

    result_struct_2 = optimize_geometric_distribution_EXP_iteration(numerator_tmp, denominator_tmp, total_failure_probability);

    result_struct_2.numerator = (numerator_tmp);
    result_struct_2.denominator = (denominator_tmp);
    result_struct_2.log2_denominator = log2_denominator;

    if ((denominator_1_2_4_8) && (result_struct_1.iteration_1 < result_struct_2.iteration_1)) {
        return result_struct_1;
    } else {
        return result_struct_2;
    }
}

template GeometricDistributionEXPOptimizationStruct<std::uint64_t>
optimize_geometric_distribution_EXP_iteration<std::uint64_t>(long double x, long double total_failure_probability);

template<typename T>
long double
discrete_laplace_distribution_EXP_failure_probability_estimation(T numerator, T denominator, long double iteration_1, long double iteration_2,
                                                                 long double iteration_3) {
    long double geometric_distribution_EXP_failure_probability_estimation_result = geometric_distribution_EXP_failure_probability_estimation<std::uint64_t>(
            numerator, denominator, iteration_1, iteration_2);

    long double geometric_distribution_exp_failure_probability = geometric_distribution_EXP_failure_probability_estimation_result;
    long double geometric_distribution_exp_success_probability = 1 - geometric_distribution_exp_failure_probability;

    long double geometric_distribution_exp_Y_equal_0_and_success =
            (1.0 - exp(-(long double) (numerator) / (long double) (denominator))) * geometric_distribution_exp_success_probability;

    long double probability_sign_equal_1 = 0.5;
    long double probability_B_equal_1_and_Y_equal_0_and_geometric_distribution_exp_success =
            probability_sign_equal_1 * geometric_distribution_exp_Y_equal_0_and_success;
    long double discrete_laplace_failure_probability =
            probability_B_equal_1_and_Y_equal_0_and_geometric_distribution_exp_success + geometric_distribution_exp_failure_probability;

    return powl(discrete_laplace_failure_probability, iteration_3);
}

template long double
discrete_laplace_distribution_EXP_failure_probability_estimation<std::uint64_t>(std::uint64_t numerator, std::uint64_t denominator,
                                                                                long double iteration_1, long double iteration_2,
                                                                                long double iteration_3);

template<typename T>
DiscreteLaplaceDistributionOptimizationStruct<T>
optimize_discrete_laplace_distribution_EXP_iteration(long double x_lap, long double total_failure_probability) {
    // std::cout << "optimize_discrete_laplace_distribution_EXP_iteration" << std::endl;
    // std::cout << "numerator: " << numerator << std::endl;
    // std::cout << "denominator: " << denominator << std::endl;

    long double x_geo = 1 / x_lap;

    std::size_t iteration_1_lower_bound = 1;
    std::size_t iteration_1_upper_bound = 150;
    std::size_t iteration_2_upper_bound = 150;
    std::size_t iteration_3_upper_bound = 200;
//    long double minimum_total_iteration = (iteration_1_upper_bound + iteration_2_upper_bound) * iteration_3_upper_bound + iteration_3_upper_bound;
    long double minimum_total_iteration = (iteration_1_upper_bound) * iteration_3_upper_bound;

    long double minimum_total_MPC_time = ((iteration_1_upper_bound * iteration_1_weight + iteration_2_upper_bound * iteration_2_weight) *
                                          iteration_3_upper_bound);

    // if (denominator == 1) {
    //   iteration_1_lower_bound = 0;
    //   iteration_1_upper_bound = 1;
    // }

    std::size_t upscale_factor = 1;

    // std::vector<long double> result_vector(10);
    DiscreteLaplaceDistributionOptimizationStruct<T> result_struct{};

    for (std::size_t iteration_3 = 1; iteration_3 < iteration_3_upper_bound; iteration_3++) {
        GeometricDistributionEXPOptimizationStruct<T> geometric_distribution_exp_optimization_result_struct = optimize_geometric_distribution_EXP_iteration<T>(
                x_geo, total_failure_probability);

        long double iteration_1 = geometric_distribution_exp_optimization_result_struct.iteration_1;
        long double iteration_2 = geometric_distribution_exp_optimization_result_struct.iteration_2;
        long double geometric_failure_probability_estimation = geometric_distribution_exp_optimization_result_struct.geometric_failure_probability_estimation;

        T numerator = geometric_distribution_exp_optimization_result_struct.numerator;
        T denominator = geometric_distribution_exp_optimization_result_struct.denominator;
        std::size_t log2_denominator = geometric_distribution_exp_optimization_result_struct.log2_denominator;

        long double discrete_laplace_failure_probability_estimation = discrete_laplace_distribution_EXP_failure_probability_estimation<T>(numerator,
                                                                                                                                          denominator,
                                                                                                                                          iteration_1,
                                                                                                                                          iteration_2,
                                                                                                                                          iteration_3);

//        if ((((iteration_1 + iteration_2) * iteration_3 + iteration_3) < minimum_total_iteration) &&
//            (discrete_laplace_failure_probability_estimation <= total_failure_probability) &&
//            (geometric_failure_probability_estimation <= total_failure_probability)) {

        if ((((iteration_1) * iteration_3) < minimum_total_iteration) &&
            (discrete_laplace_failure_probability_estimation <= total_failure_probability) &&
            (geometric_failure_probability_estimation <= total_failure_probability)) {

//                            if ((((iteration_1 * iteration_1_weight + iteration_2 *
//                            iteration_2_weight) * iteration_3) <= minimum_total_MPC_time) &&
//                                (failure_probability_estimation <= total_failure_probability)) {

            //                    if (failure_probability_estimation <= total_failure_probability)
            //                    {

            //                        std::cout << "geometric_failure_probability_estimation: " <<
            //                        geometric_failure_probability_estimation << std::endl;
            //                        std::cout
            //                        << "discrete_laplace_failure_probability_estimation: " <<
            //                        discrete_laplace_failure_probability_estimation <<
            //                        std::endl;

//            minimum_total_iteration = ((iteration_1 + iteration_2) * iteration_3 + iteration_3);

            minimum_total_iteration = ((iteration_1) * iteration_3);

            minimum_total_MPC_time = ((iteration_1 * iteration_1_weight + iteration_2 * iteration_2_weight) * iteration_3);

            result_struct.iteration_geo_1 = iteration_1;
            result_struct.iteration_geo_2 = iteration_2;
            result_struct.iteration_dlap_3 = iteration_3;
            result_struct.minimum_total_iteration = minimum_total_iteration;
            result_struct.minimum_total_MPC_time = minimum_total_MPC_time;
            result_struct.geometric_failure_probability_estimation = geometric_failure_probability_estimation;
            result_struct.discrete_laplace_failure_probability_estimation = discrete_laplace_failure_probability_estimation;
            result_struct.upscale_factor = upscale_factor;
            result_struct.numerator = numerator;
            result_struct.denominator = denominator;
            result_struct.log2_denominator = log2_denominator;

            // std::cout << "discrete_laplace_best_iterations_1: " << result_vector[0] << std::endl;
            // std::cout << "discrete_laplace_best_iterations_2: " << result_vector[1] << std::endl;
            // std::cout << "discrete_laplace_best_iterations_3: " << result_vector[2] << std::endl;
            // std::cout << "minimum_total_iteration: " << result_vector[3] << std::endl;
            // std::cout << "minimum_total_MPC_time: " << result_vector[4] << std::endl;

            // std::cout << "geometric_failure_probability_estimation: " << result_vector[5] << std::endl;
            // std::cout << "log2(geometric_failure_probability_estimation): " << log2l(result_vector[5])
            //           << std::endl;

            // std::cout << "discrete_laplace_failure_probability_estimation: " << result_vector[6]
            //           << std::endl;
            // std::cout << "log2(discrete_laplace_failure_probability_estimation): "
            //           << log2l(result_vector[6]) << std::endl;

            // std::cout << "upscale_factor: " << result_vector[7] << std::endl;
            // std::cout << std::endl;
        }
    }
    return result_struct;
}

template DiscreteLaplaceDistributionOptimizationStruct<std::uint64_t>
optimize_discrete_laplace_distribution_EXP_iteration<std::uint64_t>(long double x_lap, long double total_failure_probability);

long double discrete_laplace_distribution_PDF(long double t, std::int64_t x) {
    long double pdf_x = (expl(1 / t) - 1) / (expl(1 / t) + 1) * (expl(-std::abs(x) / t));
    return pdf_x;
}

template<typename T, typename T_int>
std::vector<long double>
discrete_gaussian_distribution_EXP_failure_probability_estimation(long double sigma, T numerator, T denominator, long double iteration_1,
                                                                  long double iteration_2, long double iteration_3, long double iteration_4) {
    // T t = floor(sigma) + 1;
    T_int pdf_Y_upper_bound = 10000;
    //        std::cout << "t: " << t << std::endl;
    long double t = denominator / numerator;

    // std::cout << "numerator: " << numerator << std::endl;
    // std::cout << "denominator: " << denominator << std::endl;

    long double discrete_laplace_distribution_EXP_failure_probability_estimation_result = discrete_laplace_distribution_EXP_failure_probability_estimation(
            numerator, denominator, iteration_1, iteration_2, iteration_3);

    long double probability_dlap_fail = discrete_laplace_distribution_EXP_failure_probability_estimation_result;
    //        std::cout << "probability_laplace_fail: " << probability_laplace_fail << std::endl;

    long double probability_dlap_success = 1 - discrete_laplace_distribution_EXP_failure_probability_estimation_result;
    //    std::cout << "probability_laplace_success: " << probability_laplace_success << std::endl;

    // this is only an approximation
    long double probability_C_equal_0_and_dlap_success = 0;
    for (T_int i = -pdf_Y_upper_bound; i < pdf_Y_upper_bound; i++) {
        long double probability_Y_equal_i = discrete_laplace_distribution_PDF(t, T_int(i));
        probability_C_equal_0_and_dlap_success = probability_C_equal_0_and_dlap_success + probability_Y_equal_i * (1 - (expl(-powl(
                std::abs((long double) (i)) - sigma * sigma / (long double) (t), 2) / (2 * sigma * sigma)))) * probability_dlap_success;
    }
    //    std::cout<<"probability_C_equal_0_and_dlap_success:
    //    "<<probability_C_equal_0_and_dlap_success<<std::endl;

    //    // only for debugging
    //    long double expect_C = 0;
    //    long double tau = 1.0 / t;
    //    for (T_int i = -pdf_Y_upper_bound; i < pdf_Y_upper_bound; i++) {
    //        expect_C = expect_C + (expl(-i*i / (2 * sigma * sigma)));
    //    }
    //    expect_C = (1 - expl(-tau)) / (1 + expl(-tau)) * expl(-sigma * sigma * tau * tau / 2) *
    //    expect_C; std::cout << "expect_C: " << expect_C << std::endl;

    //    std::cout << std::endl;
    //    probability_C_equal_0_and_laplace_success =
    //    powl(probability_C_equal_0_and_laplace_success, iteration_4);

    //    long double probability_C_equal_0 = probability_laplace_fail +
    //    probability_C_equal_0_and_laplace_success -
    //                                        probability_laplace_fail *
    //                                        probability_C_equal_0_and_laplace_success;

    long double discrete_gaussian_failure_probability = probability_dlap_fail + probability_C_equal_0_and_dlap_success;

    std::vector<long double> result_output_vector(1);
    result_output_vector[0] = powl(discrete_gaussian_failure_probability, iteration_4);
    //    result_output_vector[1] = probability_C_equal_0_and_laplace_success;
    //    result_output_vector[2] = probability_C_equal_0;

    return result_output_vector;
}

template std::vector<long double>
discrete_gaussian_distribution_EXP_failure_probability_estimation<std::uint64_t, std::int64_t>(long double sigma, std::uint64_t numerator,
                                                                                               std::uint64_t denominator, long double iteration_1,
                                                                                               long double iteration_2, long double iteration_3,
                                                                                               long double iteration_4);

// template <typename T, typename T_int>
// std::vector<long double>
// discrete_gaussian_distribution_EXP_with_discrete_laplace_EKMPP_failure_probability_estimation(
//     double sigma, long double iteration) {
//   T t = floor(sigma) + 1;
//   T_int pdf_Y_upper_bound = 100;

//   long double probability_dlap_fail = 0;
//   long double probability_dlap_success = 1;

//   long double probability_C_equal_0_and_dlap_success = 0;
//   for (T_int i = -pdf_Y_upper_bound; i < pdf_Y_upper_bound; i++) {
//     long double probability_Y_equal_i = discrete_laplace_distribution_PDF(t, T_int(i));
//     probability_C_equal_0_and_dlap_success =
//         probability_C_equal_0_and_dlap_success +
//         probability_Y_equal_i *
//             (1 - (expl(-powl(std::abs((long double)(i)) - sigma * sigma / (long double)(t), 2) /
//                        (2 * sigma * sigma)))) *
//             probability_dlap_success;
//   }

//   long double discrete_gaussian_failure_probability =
//       probability_dlap_fail + probability_C_equal_0_and_dlap_success;

//   std::vector<long double> result_output_vector(1);
//   result_output_vector[0] = powl(discrete_gaussian_failure_probability, iteration);

//   return result_output_vector;
// }

// template std::vector<long double>
// discrete_gaussian_distribution_EXP_with_discrete_laplace_EKMPP_failure_probability_estimation<
//     std::uint64_t, std::int64_t>(double sigma, long double iteration);

template<typename T, typename T_int>
DiscreteGaussianDistributionOptimizationStruct<T>
optimize_discrete_gaussian_distribution_EXP_iteration(long double sigma, long double total_failure_probability) {
    // std::cout << "optimize_discrete_gaussian_distribution_EXP_iteration" << std::endl;
    // std::cout << "sigma: " << sigma << std::endl;

    std::size_t iteration_4_upper_bound = 100;

    T t = floor(sigma) + 1;
    // T numerator = 1;
    // T denominator = t;
    // std::cout << "numerator: " << numerator << std::endl;
    // std::cout << "denominator: " << denominator << std::endl;

    DiscreteLaplaceDistributionOptimizationStruct<T> optimize_discrete_laplace_distribution_EXP_iteration_result_struct = optimize_discrete_laplace_distribution_EXP_iteration<T>(
            (long double) (t), total_failure_probability);

    T numerator = optimize_discrete_laplace_distribution_EXP_iteration_result_struct.numerator;
    T denominator = optimize_discrete_laplace_distribution_EXP_iteration_result_struct.denominator;

    std::size_t log2_denominator = optimize_discrete_laplace_distribution_EXP_iteration_result_struct.log2_denominator;

    std::cout << "numerator: " << numerator << std::endl;
    std::cout << "denominator: " << denominator << std::endl;

    std::size_t iteration_1 = optimize_discrete_laplace_distribution_EXP_iteration_result_struct.iteration_geo_1;
    std::size_t iteration_2 = optimize_discrete_laplace_distribution_EXP_iteration_result_struct.iteration_geo_2;
    std::size_t iteration_3 = optimize_discrete_laplace_distribution_EXP_iteration_result_struct.iteration_dlap_3;
    T upscale_factor = optimize_discrete_laplace_distribution_EXP_iteration_result_struct.upscale_factor;

    long double minimum_total_iteration = ((iteration_1 + iteration_2) * iteration_3 + iteration_3) * iteration_4_upper_bound;
//    long double minimum_total_iteration = ((iteration_1) * iteration_3) * iteration_4_upper_bound;

    long double minimum_total_MPC_time =
            ((iteration_1 * iteration_1_weight + iteration_2 * iteration_2_weight) * iteration_3 + iteration_4_weight) * iteration_4_upper_bound;

    DiscreteGaussianDistributionOptimizationStruct<T> optimize_discrete_gaussian_distribution_EXP_iteration_result_struct{};

    for (std::size_t iteration_4 = 1; iteration_4 < iteration_4_upper_bound; iteration_4++) {
        long double failure_probability_estimation = discrete_gaussian_distribution_EXP_failure_probability_estimation<T, T_int>(sigma, numerator,
                                                                                                                                 denominator,
                                                                                                                                 iteration_1,
                                                                                                                                 iteration_2,
                                                                                                                                 iteration_3,
                                                                                                                                 iteration_4)[0];
//        if ((((iteration_1 + iteration_2) * iteration_3 + iteration_3) * iteration_4 < minimum_total_iteration) &&
//            (failure_probability_estimation <= total_failure_probability)) {

        if ((((iteration_1) * iteration_3) * iteration_4 < minimum_total_iteration) &&
            (failure_probability_estimation <= total_failure_probability)) {

            //                    if ((((iteration_1 * iteration_1_weight + iteration_2 *
            //                    iteration_2_weight) * iteration_3 + iteration_4_weight) * iteration_4
            //                    <=
            //                         minimum_total_MPC_time) && (failure_probability_estimation <=
            //                         total_failure_probability)) {

            //        if (failure_probability_estimation <= total_failure_probability) {

            //            minimum_total_iteration = ((iteration_1 + iteration_2) * iteration_3 + iteration_3) * iteration_4;
            minimum_total_iteration = ((iteration_1) * iteration_3) * iteration_4;

            minimum_total_MPC_time = ((iteration_1 * iteration_1_weight + iteration_2 * iteration_2_weight) * iteration_3 + iteration_4_weight);

            optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.iteration_geo_1 = iteration_1;
            optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.iteration_geo_2 = iteration_2;
            optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.iteration_dlap_3 = iteration_3;
            optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.iteration_dgauss_4 = iteration_4;
            optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.minimum_total_iteration = minimum_total_iteration;
            optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.minimum_total_MPC_time = minimum_total_MPC_time;
            optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.geometric_failure_probability_estimation = optimize_discrete_laplace_distribution_EXP_iteration_result_struct.geometric_failure_probability_estimation;
            optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.discrete_laplace_failure_probability_estimation = optimize_discrete_laplace_distribution_EXP_iteration_result_struct.discrete_laplace_failure_probability_estimation;
            optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.discrete_gaussian_failure_probability_estimation = failure_probability_estimation;
            optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.upscale_factor = upscale_factor;
            optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.numerator = numerator;
            optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.denominator = denominator;
            optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.log2_denominator = log2_denominator;
            optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.sigma = sigma;
            optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.t = denominator / numerator;

            // std::cout << "discrete_gaussian_best_iteration_1: " << iteration_1 << std::endl;
            // std::cout << "discrete_gaussian_best_iteration_2: " << iteration_2 << std::endl;
            // std::cout << "discrete_gaussian_best_iteration_3: " << iteration_3 << std::endl;
            // std::cout << "discrete_gaussian_best_iteration_4: " << iteration_4 << std::endl;
            // std::cout << "minimum_total_iteration: " << minimum_total_iteration << std::endl;
            // std::cout << "minimum_total_MPC_time: "
            //           << optimize_discrete_gaussian_distribution_EXP_iteration_result_struct
            //                  .minimum_total_MPC_time
            //           << std::endl;
            // std::cout << "geometric_failure_probability_estimation: "
            //           << optimize_discrete_gaussian_distribution_EXP_iteration_result_struct
            //                  .geometric_failure_probability_estimation
            //           << std::endl;
            // std::cout << "discrete_laplace_failure_probability_estimation: "
            //           << optimize_discrete_gaussian_distribution_EXP_iteration_result_struct
            //                  .discrete_laplace_failure_probability_estimation
            //           << std::endl;
            // std::cout << "discrete_gaussian_failure_probability_estimation: "
            //           << optimize_discrete_gaussian_distribution_EXP_iteration_result_struct
            //                  .discrete_gaussian_failure_probability_estimation
            //           << std::endl;
            // std::cout
            //     << "upscale_factor: "
            //     << optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.upscale_factor
            //     << std::endl;
            break;
        }
    }

    return optimize_discrete_gaussian_distribution_EXP_iteration_result_struct;
}

template DiscreteGaussianDistributionOptimizationStruct<std::uint64_t>
optimize_discrete_gaussian_distribution_EXP_iteration<std::uint64_t, std::int64_t>(long double sigma, long double total_failure_probability);

// template <typename T, typename T_int>
// std::vector<long double>
// optimize_discrete_gaussian_distribution_EXP_with_discrete_laplace_EKMPP_iteration(
//     double sigma, long double total_failure_probability) {
//   std::cout << "optimize_discrete_gaussian_distribution_EXP_iteration" << std::endl;
//   std::cout << "sigma: " << sigma << std::endl;

//   std::size_t iteration_upper_bound = 100;

//   long double minimum_total_iteration = iteration_upper_bound;
//   long double minimum_total_MPC_time = (iteration_4_weight)*iteration_upper_bound;

//   std::vector<long double> result_vector(4);

//   for (std::size_t iteration = 1; iteration < iteration_upper_bound; iteration++) {
//     long double failure_probability_estimation =
//         discrete_gaussian_distribution_EXP_with_discrete_laplace_EKMPP_failure_probability_estimation<
//             std::uint64_t, std::int64_t>(sigma, iteration)[0];

//     if ((failure_probability_estimation <= total_failure_probability)) {
//       minimum_total_iteration = iteration;

//       //            minimum_total_MPC_time = ((iteration_1 * iteration_1_weight + iteration_2 *
//       //            iteration_2_weight) * iteration_3 + iteration_4_weight);

//       result_vector[0] = iteration;
//       result_vector[1] = minimum_total_iteration;
//       result_vector[2] = minimum_total_MPC_time;
//       result_vector[3] = failure_probability_estimation;

//       std::cout << "discrete_gaussian_best_iteration: " << iteration << std::endl;
//       std::cout << "minimum_total_iteration: " << minimum_total_iteration << std::endl;
//       std::cout << "minimum_total_MPC_time: " << minimum_total_MPC_time << std::endl;
//       std::cout << "discrete_gaussian_failure_probability_estimation: "
//                 << failure_probability_estimation << std::endl;
//       std::cout << std::endl;
//       break;
//     }
//   }

//   return result_vector;
// }

// template std::vector<long double>
// optimize_discrete_gaussian_distribution_EXP_with_discrete_laplace_EKMPP_iteration<
//     std::uint64_t, std::int64_t>(double sigma, long double total_failure_probability);

// template <typename T, typename T_int>
// std::vector<T> geometric_noise_generation(T numerator, T denominator,
//                                           long double failure_probability,
//                                           std::size_t num_of_elements) {
//   std::cout << "numerator: " << numerator << std::endl;
//   std::cout << "denominator: " << denominator << std::endl;

//   GeometricDistributionEXPOptimizationStruct<T>
//       optimize_geometric_distribution_EXP_iteration_result_struct =
//           optimize_geometric_distribution_EXP_iteration<T>(numerator, denominator,
//                                                            failure_probability);
//   std::size_t iteration_1 =
//   optimize_geometric_distribution_EXP_iteration_result_struct.iteration_1; std::size_t
//   iteration_2 = optimize_geometric_distribution_EXP_iteration_result_struct.iteration_2;
//   std::size_t total_iteration =
//       optimize_geometric_distribution_EXP_iteration_result_struct.minimum_total_iteration;
//   long double total_failure_probability =
//       optimize_geometric_distribution_EXP_iteration_result_struct
//           .geometric_failure_probability_estimation;

//   std::cout << "iteration_1: " << iteration_1 << std::endl;
//   std::cout << "iteration_2: " << iteration_2 << std::endl;
//   std::cout << "total_iteration: " << total_iteration << std::endl;

//   std::vector<T> result_vector(num_of_elements);

//   if (denominator == 1) {
//     iteration_1 = 0;
//   }

//   for (std::size_t j = 0; j < num_of_elements; j++) {
//     std::vector<double> uniform_floating_point_0_1_vector =
//         rand_range_double_vector(0, 1, (iteration_1 + iteration_2));

//     std::vector<T> random_integer_vector =
//         rand_range_integer_vector<T>(0, denominator, iteration_1);

//     if (denominator != 1) {
//       std::vector<T> geometric_distribution_EXP_result =
//           geometric_distribution_EXP<T, std::allocator<T>>(
//               numerator, denominator, uniform_floating_point_0_1_vector, random_integer_vector,
//               iteration_1, iteration_2);
//       std::cout << "geometric_distribution_EXP_result[0]: "
//                 << std::int64_t(geometric_distribution_EXP_result[0]) << std::endl;
//       //            std::cout << "discrete_laplace_distribution_EXP_result[1]: " <<
//       //            discrete_laplace_distribution_EXP_result[1] << std::endl;
//       result_vector[j] = geometric_distribution_EXP_result[0];
//     } else {
//       std::vector<T> geometric_distribution_EXP_result =
//           geometric_distribution_EXP<T, std::allocator<T>>(
//               numerator, uniform_floating_point_0_1_vector, iteration_2);
//       std::cout << "geometric_distribution_EXP_result[0]: "
//                 << std::int64_t(geometric_distribution_EXP_result[0]) << std::endl;
//       //            std::cout << "discrete_laplace_distribution_EXP_result[1]: " <<
//       //            discrete_laplace_distribution_EXP_result[1] << std::endl;

//       result_vector[j] = geometric_distribution_EXP_result[0];
//     }
//   }

//   return result_vector;
// }

// template std::vector<std::uint64_t> geometric_noise_generation<std::uint64_t, std::int64_t>(
//     std::uint64_t numerator, std::uint64_t denominator, long double failure_probability,
//     std::size_t num_of_elements);

template<typename T, typename T_int>
std::vector<T> discrete_laplace_noise_generation(double scale, long double failure_probability, std::size_t num_of_elements) {
    // std::uint64_t numerator = decimalToFraction(1 / scale)[0];
    // std::uint64_t denominator = decimalToFraction(1 / scale)[1];

    // std::cout << "numerator: " << numerator << std::endl;
    // std::cout << "denominator: " << denominator << std::endl;

    DiscreteLaplaceDistributionOptimizationStruct<T> optimize_discrete_laplace_distribution_EXP_iteration_result_struct = optimize_discrete_laplace_distribution_EXP_iteration<T>(
            scale, failure_probability);
    std::size_t iteration_1 = optimize_discrete_laplace_distribution_EXP_iteration_result_struct.iteration_geo_1;
    std::size_t iteration_2 = optimize_discrete_laplace_distribution_EXP_iteration_result_struct.iteration_geo_2;
    std::size_t iteration_3 = optimize_discrete_laplace_distribution_EXP_iteration_result_struct.iteration_dlap_3;
    std::size_t total_iteration = optimize_discrete_laplace_distribution_EXP_iteration_result_struct.minimum_total_iteration;
    long double total_failure_probability = optimize_discrete_laplace_distribution_EXP_iteration_result_struct.discrete_laplace_failure_probability_estimation;
    T numerator = optimize_discrete_laplace_distribution_EXP_iteration_result_struct.numerator;
    T denominator = optimize_discrete_laplace_distribution_EXP_iteration_result_struct.denominator;

    std::cout << "iteration_1: " << iteration_1 << std::endl;
    std::cout << "iteration_2: " << iteration_2 << std::endl;
    std::cout << "iteration_3: " << iteration_3 << std::endl;
    std::cout << "total_iteration: " << total_iteration << std::endl;

    std::vector<T> result_vector(num_of_elements);

    if (denominator == 1) {
        iteration_1 = 0;
    }

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
            //            std::cout << "discrete_laplace_distribution_EXP_result[0]: " <<
            //            std::int64_t(discrete_laplace_distribution_EXP_result[0]) << std::endl;
            //            std::cout << "discrete_laplace_distribution_EXP_result[1]: " <<
            //            discrete_laplace_distribution_EXP_result[1] << std::endl;
            result_vector[j] = discrete_laplace_distribution_EXP_result[0];
        } else {
            std::vector<T> discrete_laplace_distribution_EXP_result = discrete_laplace_distribution_EXP<T, std::allocator<T>>(numerator,
                                                                                                                              uniform_floating_point_0_1_vector,
                                                                                                                              bernoulli_sample_vector,
                                                                                                                              iteration_2,
                                                                                                                              iteration_3);
            //            std::cout << "discrete_laplace_distribution_EXP_result[0]: " <<
            //            std::int64_t(discrete_laplace_distribution_EXP_result[0]) << std::endl;
            //            std::cout << "discrete_laplace_distribution_EXP_result[1]: " <<
            //            discrete_laplace_distribution_EXP_result[1] << std::endl;

            result_vector[j] = discrete_laplace_distribution_EXP_result[0];
        }
    }

    return result_vector;
}

template std::vector<std::uint64_t>
discrete_laplace_noise_generation<std::uint64_t, std::int64_t>(double scale, long double failure_probability, std::size_t num_of_elements);

template<typename T, typename T_int>
std::vector<T> discrete_gaussian_noise_generation(double sigma, long double failure_probability, std::size_t num_of_elements) {
    std::uint64_t t = floor(sigma) + 1;

    DiscreteGaussianDistributionOptimizationStruct<T> optimize_discrete_gaussian_distribution_EXP_iteration_result_struct = optimize_discrete_gaussian_distribution_EXP_iteration<T, T_int>(
            sigma, failure_probability);
    std::size_t iteration_1 = optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.iteration_geo_1;
    std::size_t iteration_2 = optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.iteration_geo_2;
    std::size_t iteration_3 = optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.iteration_dlap_3;
    std::size_t iteration_4 = optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.iteration_dgauss_4;
    std::size_t total_iteration = optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.minimum_total_iteration;
    long double total_failure_probability = optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.discrete_gaussian_failure_probability_estimation;

    T numerator = optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.numerator;
    T denominator = optimize_discrete_gaussian_distribution_EXP_iteration_result_struct.denominator;

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
                                                                                                                                       numerator,
                                                                                                                                       denominator,
                                                                                                                                       random_floating_point_0_1_dlap_vector,
                                                                                                                                       random_integer_dlap_vector,
                                                                                                                                       bernoulli_sample_dlap_vector,
                                                                                                                                       random_floating_point_0_1_dgau_vector,
                                                                                                                                       iteration_1,
                                                                                                                                       iteration_2,
                                                                                                                                       iteration_3,
                                                                                                                                       iteration_4);
            std::cout << "discrete_gaussian_distribution_EXP_result[0]: " << T_int(discrete_gaussian_distribution_EXP_result[0]) << std::endl;
            //            std::cout << "discrete_gaussian_distribution_EXP_result[1]: " <<
            //            discrete_gaussian_distribution_EXP_result[1] << std::endl;

            result_vector[j] = discrete_gaussian_distribution_EXP_result[0];
        } else {
            std::vector<T> discrete_gaussian_distribution_EXP_result = discrete_gaussian_distribution_EXP<T, T_int, std::allocator<T>>(sigma,
                                                                                                                                       numerator,
                                                                                                                                       denominator,
                                                                                                                                       random_floating_point_0_1_dlap_vector,
                                                                                                                                       bernoulli_sample_dlap_vector,
                                                                                                                                       random_floating_point_0_1_dgau_vector,
                                                                                                                                       iteration_2,
                                                                                                                                       iteration_3,
                                                                                                                                       iteration_4);
            std::cout << "discrete_gaussian_distribution_EXP_result[0]: " << T_int(discrete_gaussian_distribution_EXP_result[0]) << std::endl;
            //            std::cout << "discrete_gaussian_distribution_EXP_result[1]: " <<
            //            discrete_gaussian_distribution_EXP_result[1] << std::endl;
            result_vector[j] = discrete_gaussian_distribution_EXP_result[0];
        }
    }
    return result_vector;
}

template std::vector<std::uint64_t>
discrete_gaussian_noise_generation<std::uint64_t, std::int64_t>(double sigma, long double failure_probability, std::size_t num_of_elements);

void test_optimize_geometric_distribution_EXP_iteration() {
    std::srand(time(nullptr));

    long double total_failure_probability = std::exp2(-40);
//    std::size_t num_of_elements = 1;
    std::size_t num_of_elements = 100;

    double min = 0;
    double max = 0.5;

//    double min = 0.5;
//    double max = 1;

//    double min = 1;
//    double max = 5;
//
//    double min = 5;
//    double max = 10;
//
//    double min = 10;
//    double max = 100;

    std::vector<double> scale_double_vector = rand_range_double_vector(min, max, num_of_elements);

    for (std::size_t i = 0; i < num_of_elements; i++) {
        std::cout << "i: " << i << std::endl;
        long double scale_tmp = scale_double_vector[i];

        // only for debug
//        scale_tmp=0.00000125;
//        scale_tmp=0.00125;
//        scale_tmp=0.125;
//            scale_tmp = 0.25; // iteration_1=1
//            scale_tmp = 0.5; // iteration_1=1
//            scale_tmp = 0.75; // iteration_1=1
//            scale_tmp = 1; // iteration_1=1
//        scale_tmp = 1.5; // iteration_1=1
//            scale_tmp = 2; // iteration_1=1
//        scale_tmp = 2.5; // iteration_1=1
//            scale_tmp = 3; // iteration_1=1
//            scale_tmp = 3.25; // iteration_1=1
//            scale_tmp = 4; // iteration_1=1
//            scale_tmp = 5; // iteration_1=1
//            scale_tmp = 10; // iteration_1=1
//            scale_tmp = 50; // iteration_1=1
//            scale_tmp = 100; // iteration_1=1

        std::cout << "scale_tmp: " << scale_tmp << std::endl;

        // std::vector<long double> result_vector(8);
        GeometricDistributionEXPOptimizationStruct<std::uint64_t> result_struct{};

        result_struct = optimize_geometric_distribution_EXP_iteration<std::uint64_t>(scale_tmp, total_failure_probability);

        std::cout << "iteration_1: " << result_struct.iteration_1 << std::endl;
        std::cout << "iteration_2: " << result_struct.iteration_2 << std::endl;
        std::cout << "minimum_total_iteration: " << result_struct.minimum_total_iteration << std::endl;
        std::cout << "minimum_total_MPC_time: " << result_struct.minimum_total_MPC_time << std::endl;
        std::cout << "failure_probability_estimation: " << result_struct.geometric_failure_probability_estimation << std::endl;
        std::cout << "upscale_factor: " << result_struct.upscale_factor << std::endl;
        std::cout << "numerator: " << result_struct.numerator << std::endl;
        std::cout << "denominator: " << result_struct.denominator << std::endl;

        std::cout << "================================================================" << std::endl;
        std::cout << std::endl;
    }
}

void test_optimize_discrete_laplace_distribution_EXP_iteration() {
    std::srand(time(nullptr));

    long double total_failure_probability = std::exp2(-40);
    std::size_t num_of_elements = 200;
//    std::size_t num_of_elements = 1;
//    double min = 0;
//    double max = 0.5;

//    double min = 0.5;
//    double max = 1;

//    double min = 1;
//    double max = 5;
//
//    double min = 5;
//    double max = 10;
//
//    double min = 10;
//    double max = 100;

//    double min = 100;
//    double max = 1000;

    double min = 1000;
    double max = 10000;
//
    std::vector<double> scale_double_vector = rand_range_double_vector(min, max, num_of_elements);

    for (std::size_t i = 0; i < num_of_elements; i++) {
        std::cout << "i: " << i << std::endl;
        long double scale_tmp = 1 / scale_double_vector[i];

        //  only for debug
//        long double scale_tmp_inv;
//        scale_tmp_inv=0.00000125;
//        scale_tmp_inv=0.00125;
//        scale_tmp_inv = 0.125;
//        scale_tmp_inv = 0.25; // iteration_1=1
//        scale_tmp_inv = 0.5; // iteration_1=1
//        scale_tmp_inv = 0.75; // iteration_1=1
//        scale_tmp_inv = 1; // iteration_1=1
//        scale_tmp_inv = 1.5; // iteration_1=1
//        scale_tmp_inv = 2; // iteration_1=1
//        scale_tmp_inv = 2.5; // iteration_1=1
//        scale_tmp_inv = 3; // iteration_1=1
//        scale_tmp_inv = 3.25; // iteration_1=1
//        scale_tmp_inv = 4; // iteration_1=1
//        scale_tmp_inv = 5; // iteration_1=1
//        scale_tmp_inv = 10; // iteration_1=1
//        scale_tmp_inv = 50; // iteration_1=1
//        scale_tmp_inv = 100; // iteration_1=1
//        scale_tmp_inv = 1000; // iteration_1=1
//        scale_tmp_inv = 5000; // iteration_1=1
//        scale_tmp_inv = 10000; // iteration_1=1
//        scale_tmp_inv = 100000; // iteration_1=1

//        scale_tmp = 1 / scale_tmp_inv;

        std::cout << "scale_tmp: " << scale_tmp << std::endl;
        // std::vector<long double> result_vector(10);
        DiscreteLaplaceDistributionOptimizationStruct<std::uint64_t> result_struct{};
        result_struct = optimize_discrete_laplace_distribution_EXP_iteration<std::uint64_t>(scale_tmp, total_failure_probability);

        std::cout << "geo_best_iterations_1: " << result_struct.iteration_geo_1 << std::endl;
        std::cout << "geo_best_iterations_2: " << result_struct.iteration_geo_2 << std::endl;
        std::cout << "discrete_laplace_best_iterations_3: " << result_struct.iteration_dlap_3 << std::endl;
        std::cout << "minimum_total_iteration: " << result_struct.minimum_total_iteration << std::endl;
        std::cout << "minimum_total_MPC_time: " << result_struct.minimum_total_MPC_time << std::endl;

        std::cout << "geometric_failure_probability_estimation: " << result_struct.geometric_failure_probability_estimation << std::endl;
        std::cout << "log2(geometric_failure_probability_estimation): " << log2l(result_struct.geometric_failure_probability_estimation) << std::endl;

        std::cout << "numerator: " << result_struct.numerator << std::endl;
        std::cout << "denominator: " << result_struct.denominator << std::endl;

        std::cout << "discrete_laplace_failure_probability_estimation: " << result_struct.discrete_laplace_failure_probability_estimation
                  << std::endl;
        std::cout << "log2(discrete_laplace_failure_probability_estimation): " << log2l(result_struct.discrete_laplace_failure_probability_estimation)
                  << std::endl;

        std::cout << "upscale_factor: " << result_struct.upscale_factor << std::endl;
        std::cout << std::endl;
        std::cout << "================================================================" << std::endl;
    }
}

void test_discrete_gaussian_distribution_EXP_failure_estimation() {
    std::srand(time(nullptr));
    long double total_failure_probability = std::exp2(-40);
    std::size_t num_of_elements = 1;
    double min = 0;

    // double max = 1;  // iterations_1=0
    //    double max = 10;
    double max = 100;

    std::vector<double> sigma_double_vector = rand_range_double_vector(min, max, num_of_elements);

    for (std::size_t i = 0; i < num_of_elements; i++) {
        std::cout << "i: " << i << std::endl;
        long double sigma_tmp = sigma_double_vector[i];

        // only for debug
        //        sigma_tmp=0.75;

        double t_tmp = floor(sigma_tmp) + 1;
        std::uint64_t numerator_tmp = 1;
        std::uint64_t denominator_tmp = t_tmp;

        std::cout << "sigma_tmp: " << sigma_tmp << std::endl;
        std::cout << "t_tmp: " << t_tmp << std::endl;
        std::cout << "numerator_tmp: " << numerator_tmp << std::endl;
        std::cout << "denominator_tmp: " << denominator_tmp << std::endl;

        long double iteration_1 = 30;
        long double iteration_2 = 30;
        long double iteration_3 = 10;
        long double iteration_4 = 10;

        for (std::size_t i = 1; i < 10; i++) {
            long double upscale_factor = i;
            std::cout << "upscale_factor: " << upscale_factor << std::endl;
            std::vector<long double> result_vector(1);
            result_vector = discrete_gaussian_distribution_EXP_failure_probability_estimation<std::uint64_t, std::int64_t>(sigma_tmp, std::uint64_t(
                                                                                                                                   (long double) (numerator_tmp) * upscale_factor), std::uint64_t((long double) (denominator_tmp) * upscale_factor), iteration_1,
                                                                                                                           iteration_2, iteration_3,
                                                                                                                           iteration_4);

            std::cout << "discrete_laplace_failure_probability_estimation: " << result_vector[0] << std::endl;
            std::cout << "================================================================" << std::endl;
        }
    }
}

void test_optimize_discrete_gaussian_distribution_EXP_iteration() {
    std::srand(time(nullptr));
    long double total_failure_probability = std::exp2(-40);
//    std::size_t num_of_elements = 10;
    std::size_t num_of_elements = 1;
    double min = 1;

    // double max = 2;  // iterations_1=0
    double max = 10;
    // double max = 1;

    std::vector<double> sigma_double_vector = rand_range_double_vector(min, max, num_of_elements);

    for (std::size_t i = 0; i < num_of_elements; i++) {
        std::cout << "i: " << i << std::endl;
        long double sigma_tmp = sigma_double_vector[i];

        // only for debug
//        sigma_tmp = 0.1;
//         sigma_tmp = 1.1;
//         sigma_tmp = 2.1;
//         sigma_tmp = 3.1;
//         sigma_tmp = 4.1;
//         sigma_tmp = 5.1;
//         sigma_tmp = 6.1;
//         sigma_tmp = 7.1;
//         sigma_tmp = 8.1;
         sigma_tmp = 9.1;
//         sigma_tmp = 10.1;

        long double t_tmp = floor(sigma_tmp) + 1;
        // std::uint64_t numerator_tmp = 1;
        // std::uint64_t denominator_tmp = t_tmp;

        std::cout << "sigma_tmp: " << sigma_tmp << std::endl;
        std::cout << "t_tmp: " << t_tmp << std::endl;
        // std::cout << "numerator_tmp: " << numerator_tmp << std::endl;
        // std::cout << "denominator_tmp: " << denominator_tmp << std::endl;

        DiscreteGaussianDistributionOptimizationStruct<std::uint64_t> result_struct{};
        result_struct = optimize_discrete_gaussian_distribution_EXP_iteration<std::uint64_t, std::int64_t>(sigma_tmp, total_failure_probability);
        std::cout << "geo_best_iterations_1: " << result_struct.iteration_geo_1 << std::endl;
        std::cout << "geo_best_iterations_2: " << result_struct.iteration_geo_2 << std::endl;
        std::cout << "discrete_laplace_best_iterations_3: " << result_struct.iteration_dlap_3 << std::endl;
        std::cout << "discrete_gaussian_best_iterations_4: " << result_struct.iteration_dgauss_4 << std::endl;
        std::cout << "minimum_total_iteration: " << result_struct.minimum_total_iteration << std::endl;
        std::cout << "minimum_total_MPC_time: " << result_struct.minimum_total_MPC_time << std::endl;

        std::cout << "geometric_failure_probability_estimation: " << result_struct.geometric_failure_probability_estimation << std::endl;
        std::cout << "log2(geometric_failure_probability_estimation): " << log2l(result_struct.geometric_failure_probability_estimation) << std::endl;

        std::cout << "numerator: " << result_struct.numerator << std::endl;
        std::cout << "denominator: " << result_struct.denominator << std::endl;

        std::cout << "discrete_laplace_failure_probability_estimation: " << result_struct.discrete_laplace_failure_probability_estimation
                  << std::endl;
        std::cout << "log2(discrete_laplace_failure_probability_estimation): " << log2l(result_struct.discrete_laplace_failure_probability_estimation)
                  << std::endl;

        std::cout << "discrete_gaussian_failure_probability_estimation: " << result_struct.discrete_gaussian_failure_probability_estimation
                  << std::endl;
        std::cout << "log2(discrete_gaussian_failure_probability_estimation): "
                  << log2l(result_struct.discrete_gaussian_failure_probability_estimation) << std::endl;

        std::cout << "upscale_factor: " << result_struct.upscale_factor << std::endl;
        std::cout << std::endl;
        std::cout << "================================================================" << std::endl;
    }
}

// void test_optimize_discrete_laplace_distribution_EXP_iteration_with_threshold() {
//   //    double scale = 0.788766;
//   //    double numerator = 1427419685638527;
//   //    double denominator = 1125899906842624;

//   //    double scale =26053.8;
//   //    double numerator = 177006027106111;
//   //    double denominator = 4611686018427387904;
//   std::srand(time(nullptr));

//   double total_failure_probability = std::exp2(-40);
//   std::size_t num_of_elements = 1;
//   double min = 0;

//   //    double max = 0.1; // high iterations
//   double max = 1;  // low iterations
//   //    double max = 10; // low iterations

//   std::vector<double> scale_double_vector = rand_range_double_vector(min, max, num_of_elements);

//   for (std::size_t i = 0; i < num_of_elements; i++) {
//     std::cout << "i: " << i << std::endl;
//     double scale_tmp = scale_double_vector[i];

//     // // only for debug
//     // double scale_tmp = 1.2;

//     // only for debug
//     double error_threshold = 0.01;
//     double error_granularity = 0.0001;

//     std::uint64_t numerator_tmp = decimalToFraction(1 / scale_tmp)[0];
//     std::uint64_t denominator_tmp = decimalToFraction(1 / scale_tmp)[1];

//     std::cout << "scale_tmp: " << scale_tmp << std::endl;
//     std::cout << "numerator_tmp: " << numerator_tmp << std::endl;
//     std::cout << "denominator_tmp: " << denominator_tmp << std::endl;

//     optimize_discrete_laplace_distribution_EXP_iteration_with_tolerance<std::uint64_t>(
//         scale_tmp, total_failure_probability, error_threshold, error_granularity);
//     std::cout << "================================================================" << std::endl;
//     std::cout << std::endl;
//   }
// }
