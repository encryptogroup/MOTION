//
// Created by liangzhao on 02.06.22.
//

#include <ctime>
#include <iomanip>
#include "integer_scaling_mechanism.h"

FLType
geometric_sampling_binary_search(FLType L0, FLType R0, double lambda, std::size_t iterations, std::vector<double> uniform_floating_point_0_1_vector) {
    FLType M0 = L0 - (log(0.5) + log(1 + exp(-lambda * (R0 - L0)))) / lambda;

    std::cout << "M0: " << M0 << std::endl;

    if (!(M0 > L0)) {
        M0 = L0 + 1;
    } else if (!(M0 < R0)) {
        M0 = R0 - 1;
    }
    std::cout << "M0: " << M0 << std::endl;

    double Q0 = (exp(-lambda * (M0 - L0)) - 1) / (exp(-lambda * (R0 - L0)) - 1);
    std::cout << "Q0: " << Q0 << std::endl;
    bool cond_U0_gt_Q0 = uniform_floating_point_0_1_vector[0] > Q0;
    bool cond_U0_leq_Q0 = !cond_U0_gt_Q0;

    R0 = cond_U0_leq_Q0 * M0 + cond_U0_gt_Q0 * R0;
    L0 = cond_U0_gt_Q0 * M0 + cond_U0_leq_Q0 * L0;

    bool fg0 = !((L0 + 1) < R0);
    std::cout << "Q0: " << Q0 << std::endl;
    std::cout << "R0: " << R0 << std::endl;
    std::cout << "L0: " << L0 << std::endl;

    std::vector<FLType> M_vector(iterations);
    std::vector<double> Q_vector(iterations);
    std::vector<FLType> L_vector(iterations);
    std::vector<FLType> R_vector(iterations);
    std::vector<bool> fg_vector(iterations);
    M_vector[0] = M0;
    Q_vector[0] = Q0;
    L_vector[0] = L0;
    R_vector[0] = R0;
    fg_vector[0] = fg0;

    for (std::size_t j = 1; j < iterations; j++) {
        M_vector[j] = L_vector[j - 1] - (log(0.5) + log(1 + exp(-lambda * (R_vector[j - 1] - L_vector[j - 1])))) / lambda;

        bool cond_Mj_leq_L_j_minus_1 = !(M_vector[j] > L_vector[j - 1]);

        bool cond_Mj_geq_R_j_minus_1 = !(M_vector[j] < R_vector[j - 1]);

        bool cond_Mj_gt_L_j_minus_1_lt_R_j_minus_1 = !(cond_Mj_leq_L_j_minus_1 | cond_Mj_geq_R_j_minus_1);

        M_vector[j] = cond_Mj_leq_L_j_minus_1 * (L_vector[j - 1] + 1) + cond_Mj_geq_R_j_minus_1 * (R_vector[j - 1] - 1) +
                      cond_Mj_gt_L_j_minus_1_lt_R_j_minus_1 * M_vector[j];

        Q_vector[j] = (exp(-lambda * (M_vector[j] - L_vector[j - 1])) - 1) / (exp(-lambda * (R_vector[j - 1] - L_vector[j - 1])) - 1);

        bool cond_Uj_gt_Qj = uniform_floating_point_0_1_vector[j] > Q_vector[j];
        bool cond_Uj_leq_Qj = !cond_Uj_gt_Qj;

        R_vector[j] = cond_Uj_leq_Qj * M_vector[j] + cond_Uj_gt_Qj * R_vector[j - 1];
        L_vector[j] = cond_Uj_gt_Qj * M_vector[j] + cond_Uj_leq_Qj * L_vector[j - 1];

        fg_vector[j] = !((L_vector[j] + 1) < R_vector[j]);
    }

    std::vector<bool> one_hot_choose_vector(iterations);
    one_hot_choose_vector[0] = 0;
    for (std::size_t j = 1; j < iterations; j++) {
        one_hot_choose_vector[j] = fg_vector[j - 1] ^ fg_vector[j];
    }

    FLType result = 0;
    for (std::size_t j = 0; j < iterations; j++) {
        //            result = R_vector[j - 1];
        result = result + R_vector[j] * one_hot_choose_vector[j];
    }

    std::cout << "fg_vector[j]: ";
    for (std::size_t j = 0; j < iterations; j++) {
        std::cout << fg_vector[j];
    }
    std::cout << std::endl;
    std::cout << "one_hot_choose_vector[j]: ";
    for (std::size_t j = 0; j < iterations; j++) {
        std::cout << one_hot_choose_vector[j];
    }
    std::cout << std::endl;

    return result;
}

template<typename IntType, typename IntType_int, typename A>
std::vector<IntType> symmetrical_binomial_distribution(double constant_sqrt_n, std::vector<std::uint64_t> signed_integer_geometric_sample_vector,
                                                       std::vector<bool> random_bits_vector,
                                                       std::vector<std::uint64_t> random_unsigned_integer_vector,
                                                       std::vector<double> random_floating_point_0_1_vector, std::size_t iterations) {
    assert(signed_integer_geometric_sample_vector.size() == iterations);
    assert(random_bits_vector.size() == iterations);
    assert(random_unsigned_integer_vector.size() == iterations);
    assert(random_floating_point_0_1_vector.size() == iterations);

    double m = floorl(M_SQRT2 * constant_sqrt_n + 1);
    std::vector<IntType> result_vector(2);
    bool iterations_finish = false;

    for (std::size_t iter = 0; iter < iterations; iter++) {
        std::cout << "iter: " << iter << std::endl;
        IntType_int s = signed_integer_geometric_sample_vector[iter];
        IntType_int k = random_bits_vector[iter] * (s) + (!random_bits_vector[iter]) * (-s - 1);

        IntType_int i = k * m + IntType_int(random_unsigned_integer_vector[iter]);

        std::cout << "std::int64_t(s): " << std::int64_t(s) << std::endl;
        std::cout << "std::int64_t(k): " << std::int64_t(k) << std::endl;
        if (i < 0) {
            print_u128_u("-i: ", -i);
        } else {
            print_u128_u("i: ", i);
        }

        //    std::cout << "i: " << i << std::endl;
        if (k < 0) {
            print_u128_u("-k: ", -k);
        } else {
            print_u128_u("k: ", k);
        }
        print_u128_u("s: ", s);
        print_u128_u("k: ", k);
        print_u128_u("i: ", i);

        double p_i = sqrtl(2 / M_PI) / constant_sqrt_n * (1.0 - 0.4 * powl(logl(constant_sqrt_n) * 2, 1.5) / constant_sqrt_n) *
                     expl(-powl(((double) (i) * M_SQRT2 / constant_sqrt_n), 2));

        std::cout << " std::exp(-pow((double(i) * 2 / constant_sqrt_n), 2)): " << std::exp(-pow((double(i) * 2 / constant_sqrt_n), 2)) << std::endl;

        std::cout << "p_i: " << p_i << std::endl;

        bool i_in_range =
                ((double) (i) >= -constant_sqrt_n * logl(constant_sqrt_n) / 2.0) && ((double) (i) <= constant_sqrt_n * logl(constant_sqrt_n) / 2.0);

        std::cout << "i_in_range: " << i_in_range << std::endl;

        bool c = random_floating_point_0_1_vector[iter] < (p_i * m * powl(2, (double) (s)) / 4);
        std::cout << "(p_i * m * powl(2, (double)(s)) / 4): " << (p_i * m * powl(2, (double) (s)) / 4) << std::endl;
        std::cout << "choice: " << c << std::endl;
        std::cout << "random_floating_point_0_1_vector[iter]: " << random_floating_point_0_1_vector[iter] << std::endl;

        if (p_i > 0 && i_in_range && c) {
            if (!iterations_finish) {
                std::cout << "choose iter: " << iter << std::endl;
                iterations_finish = true;
                result_vector[0] = i;
                result_vector[1] = true;

                // only for debug
                break;
            }
        }
        std::cout << std::endl;
    }
    return result_vector;
}

template std::vector<std::uint64_t>
symmetrical_binomial_distribution<std::uint64_t, std::int64_t, std::allocator<std::uint64_t>>(double constant_sqrt_n,
                                                                                              std::vector<std::uint64_t> signed_integer_geometric_sample_vector,
                                                                                              std::vector<bool> random_bits_vector,
                                                                                              std::vector<std::uint64_t> random_unsigned_integer_vector,
                                                                                              std::vector<double> random_floating_point_0_1_vector,
                                                                                              std::size_t iteration);

template std::vector<__uint128_t> symmetrical_binomial_distribution<__uint128_t, __int128_t, std::allocator<__uint128_t>>(double constant_sqrt_n,
                                                                                                                          std::vector<std::uint64_t> signed_integer_geometric_sample_vector,
                                                                                                                          std::vector<bool> random_bits_vector,
                                                                                                                          std::vector<std::uint64_t> random_unsigned_integer_vector,
                                                                                                                          std::vector<double> random_floating_point_0_1_vector,
                                                                                                                          std::size_t iteration);

std::vector<long double> symmetrical_binomial_distribution_fail_probability_estimation(double sqrt_n, double iteration) {
    double s_upper_bound = 1022;
    //    long double s_upper_bound = 10;
    double m = floorl(M_SQRT2 * sqrt_n + 1);
    double i_lower_bound = -sqrt_n * logl(sqrt_n) / 2;
    double i_upper_bound = sqrt_n * logl(sqrt_n) / 2;
    double p_coefficient = sqrt(2 / M_PI) / sqrt_n * (1.0 - 0.4 * powl(logl(sqrt_n) * 2, 1.5) / sqrt_n);
    //    std::cout << "p_coefficient: " << p_coefficient << std::endl;

    //    long double probability_pi_greater_than_0 = 0;
    //    long double probability_pi_less_than_equal_0 = 0;
    //    long double probability_c_equal_1_under_pi_greater_than_0 = 1.0 / 16;
    //    long double probability_c_equal_0_under_pi_greater_than_0 = 1 -
    //    probability_c_equal_1_under_pi_greater_than_0; for (std::size_t s = 0; s < s_upper_bound;
    //    s++) {
    ////        std::cout << "s: " << s << std::endl;
    //
    //        // k = s,  with p = 0.5
    //        // k = -s -1, with p = 0.5
    //        // i = k * m + l
    //        long double i1_lower_bound = s * m;
    //        long double i1_upper_bound = s * m + m - 1;
    //
    //        long double i2_lower_bound = (-s - 1) * m;
    //        long double i2_upper_bound = (-s - 1) * m + m - 1;
    //
    //        long double i1_i_overlapping_area = overlapping_area_percent(i1_lower_bound,
    //        i1_upper_bound, i_lower_bound, i_upper_bound); long double i2_i_overlapping_area =
    //        overlapping_area_percent(i2_lower_bound, i2_upper_bound, i_lower_bound, i_upper_bound);
    //        long double geometric_distribution_pdf_s = geometric_distribution_PDF(0.5, s);
    //        probability_pi_greater_than_0 =
    //                probability_pi_greater_than_0 + geometric_distribution_pdf_s * 0.5 *
    //                (i1_i_overlapping_area + i2_i_overlapping_area);
    //        probability_pi_less_than_equal_0 = 1 - probability_pi_greater_than_0;
    //    }
    //    long double probability_c_equal_0_and_pi_greater_than_0 =
    //    probability_c_equal_0_under_pi_greater_than_0 * probability_pi_greater_than_0;
    //
    //    long double fail_probability_symmetric_binomial = probability_pi_less_than_equal_0 +
    //    probability_c_equal_0_and_pi_greater_than_0;

    long double fail_probability_symmetric_binomial = 15.0 / 16;
    std::vector<long double> result_vector(1);
    result_vector[0] = powl(fail_probability_symmetric_binomial, iteration);

    return result_vector;
}

std::vector<long double> optimize_symmetrical_binomial_distribution_iteration(double sqrt_n, double total_fail_probability) {
    std::size_t iteration_lower_bound = 1;
    std::size_t iteration_upper_bound = 2000;

    double minimum_total_iteration = iteration_upper_bound;
    std::vector<long double> result_vector(2);

    for (std::size_t iteration = iteration_lower_bound; iteration < iteration_upper_bound; iteration++) {
        // std::cout << "iteration: " << iteration << std::endl;
        std::vector<long double> symmetrical_binomial_distribution_fail_probability_estimation_result_vector = symmetrical_binomial_distribution_fail_probability_estimation(
                sqrt_n, iteration);

        if ((iteration < minimum_total_iteration) &&
            (symmetrical_binomial_distribution_fail_probability_estimation_result_vector[0] <= total_fail_probability)) {
            minimum_total_iteration = iteration;
            result_vector[0] = iteration;
            result_vector[1] = symmetrical_binomial_distribution_fail_probability_estimation_result_vector[0];
        }
    }
    return result_vector;
}

std::vector<double>
integer_scaling_laplace_noise_generation(double sensitivity_l1, double epsilon, std::size_t num_of_simd_lap, long double fail_probability,
                                         std::size_t num_of_elements) {
    double pow2_k = std::exp2l(40);

    double resolution_r = ceil_power_of_two(sensitivity_l1 / epsilon / pow2_k);
    double delta_r = sensitivity_l1 + resolution_r;

    double lambda = resolution_r * epsilon / delta_r;

    double scale = 1 / lambda;

    std::cout << "scale: " << scale << std::endl;

    std::vector<std::uint64_t> discrete_laplace_noise_vector = discrete_laplace_noise_generation<std::uint64_t, std::int64_t>(scale, fail_probability,
                                                                                                                              num_of_elements);

    std::vector<double> laplace_noise_vector(num_of_elements);
    for (std::size_t i = 0; i < num_of_elements; i++) {
        laplace_noise_vector[i] = discrete_laplace_noise_vector[i] * resolution_r;
    }

    return laplace_noise_vector;
}

std::vector<double>
integer_scaling_gaussian_noise_generation(double sensitivity_l1, double sigma, std::size_t num_of_simd_gau, long double fail_probability,
                                          std::size_t num_of_elements) {
    double binomial_bound = std::exp2l(57);

    double resolution_r = ceil_power_of_two(2.0 * sigma / binomial_bound);

    double sqrtN = 2.0 * sigma / resolution_r;

    std::uint64_t m = std::uint64_t(floor(M_SQRT2 * sqrtN + 1));
}

void test_symmetrical_binomial_distribution() {
    std::size_t iterations = 500;
    std::srand(std::time(nullptr));
    double sqrt_n = std::exp2(56);
    double m = floor(M_SQRT2 * sqrt_n + 1);

    using IntType = __uint128_t;
    using IntType_int = __int128_t;

    std::cout << "sqrt_n: " << sqrt_n << std::endl;
    std::cout << "m: " << m << std::endl;

    std::vector<std::uint64_t> signed_integer_geometric_sample_vector(iterations);
    for (std::size_t i = 0; i < iterations; i++) {
        signed_integer_geometric_sample_vector[i] = rand_range_double(0, 10);
    }

    std::vector<bool> random_bits_vector(iterations);
    for (std::size_t i = 0; i < iterations; i++) {
        random_bits_vector[i] = rand_range_double(0, 1) < 0.5;
//        std::cout<<"bernoulli_sample_vector[i]: "<<bernoulli_sample_vector[i]<<std::endl;
    }

    std::vector<std::uint64_t> random_unsigned_integer_vector(iterations);
    for (std::size_t i = 0; i < iterations; i++) {
        random_unsigned_integer_vector[i] = rand_range_double(0, m);

//        // only for debug
//        random_unsigned_integer_vector[i] =0;
    }

    std::vector<double> random_floating_point_0_1_vector(iterations);
    for (std::size_t i = 0; i < iterations; i++) {
        random_floating_point_0_1_vector[i] = rand_range_double(0, 1);
    }

    std::vector<IntType> symmetrical_binomial_distribution_result = symmetrical_binomial_distribution<IntType, IntType_int, std::allocator<IntType>>(
            sqrt_n, signed_integer_geometric_sample_vector, random_bits_vector, random_unsigned_integer_vector, random_floating_point_0_1_vector,
            iterations);
    print_u128_u_neg("symmetrical_binomial_distribution[0]: ", (symmetrical_binomial_distribution_result[0]));
    print_u128_u_neg("symmetrical_binomial_distribution[1]: ", (symmetrical_binomial_distribution_result[1]));

}

double SigmaForGaussian(std::int64_t l0Sensitivity, double lInfSensitivity, double epsilon, double delta) {
    if (delta >= 1) {
        return 0;
    }
    double l2Sensitivity = lInfSensitivity * sqrt(double(l0Sensitivity));
    double upper_bound = l2Sensitivity;

    double lower_bound;

    while (deltaForGaussian(upper_bound, l0Sensitivity, lInfSensitivity, epsilon) > delta) {
        lower_bound = upper_bound;
        upper_bound = upper_bound * 2.0;
    }

    double gaussianSigmaAccuracy = 1e-3;

    while (upper_bound - lower_bound > gaussianSigmaAccuracy * lower_bound) {
        double middle = lower_bound * 0.5 + upper_bound * 0.5;
        if (deltaForGaussian(middle, l0Sensitivity, lInfSensitivity, epsilon) > delta) {
            lower_bound = middle;
        } else {
            upper_bound = middle;
        }
    }

    return upper_bound;
}

double UnitNormalCDF(double value) {
    return 0.5 * erfc(-value * M_SQRT1_2);
}

double deltaForGaussian(double sigma, double l0Sensitivity, double lInfSensitivity, double epsilon) {
    double l2Sensitivity = lInfSensitivity * sqrt(double(l0Sensitivity));

    double a = l2Sensitivity / (2 * sigma);
    double b = epsilon * sigma / l2Sensitivity;
    double c = std::exp(epsilon);

    if (c > std::numeric_limits<double>::max()) {
        // δ(σ,s,ε) –> 0 as ε –> ∞, so return 0.
        return 0;
    }
    if (b > std::numeric_limits<double>::max()) {
        // δ(σ,s,ε) –> 0 as the L2 sensitivity –> 0, so return 0.
        return 0;
    }

    return UnitNormalCDF(a - b) - c * UnitNormalCDF(-a - b);
}

void test_SigmaForGaussian() {

//    double l0Sensitivity = 5;
//    double lInfSensitivity = 36;
//    double epsilon = 0.8;
//    double delta = 0.8;

    double l0Sensitivity = 1;
    double lInfSensitivity = 1;
    double epsilon = 0.1;
    double delta = 0.1;

    double sigma = SigmaForGaussian(l0Sensitivity, lInfSensitivity, epsilon, delta);
    std::cout << "sigma for Gaussian: " << std::setprecision(20) << sigma << std::endl;

    double granularity = ceil_power_of_two(2.0 * sigma / binomial_bound);
    double sqrtN = 2.0 * sigma / granularity;
    std::cout << "granularity: " << std::setprecision(20) << granularity << std::endl;
    std::cout << "sqrtN: " << std::setprecision(20) << sqrtN << std::endl;
    std::cout << "log2(sqrtN): " << std::setprecision(20) << log2(sqrtN) << std::endl;

}

void symmetrical_binomial_distribution_represent_as_int64_fail_probability_estimation() {

    long double sqrt_N = std::exp2(57);
    long double m = floor(M_SQRT2 * sqrt_N + 1);
    long double INT64_MAX_double = INT64_MAX;
    long double INT64_MIN_double = INT64_MIN;

    std::cout << "sqrtN: " << std::setprecision(20) << sqrt_N << std::endl;
    std::cout << "m: " << std::setprecision(20) << m << std::endl;
    std::cout << "INT64_MAX_double: " << std::setprecision(20) << INT64_MAX_double << std::endl;
    std::cout << "INT64_MIN_double: " << std::setprecision(20) << INT64_MIN_double << std::endl;

    // when l = 0,
    long double s_lower_bound = (INT64_MAX_double - m + 1) / m;
    std::cout << "s_lower_bound: " << std::setprecision(20) << s_lower_bound << std::endl;

    long double fail_probability = 0.0;

    long double s_greater_or_equal_zero = 0.5;

    // k >= 0
    for (std::size_t s = s_lower_bound; s < 10000; s++) {
        std::cout << "s: " << s << std::endl;
        bool INT64_MAX_double_minus_km_less_than_m = (INT64_MAX_double - (long double) (s) * m) < m;
        long double probability_l_overflow = INT64_MAX_double_minus_km_less_than_m * (INT64_MAX_double - (long double) (s) * m) / m;
        if (!INT64_MAX_double_minus_km_less_than_m) {
            probability_l_overflow = 1;
        }

        std::cout << "probability_l_overflow: " << probability_l_overflow << std::endl;
        long double probability_geometric_output_s = powl(0.5, s + 1);
        std::cout << "probability_geometric_output_s: " << probability_geometric_output_s << std::endl;

        fail_probability = fail_probability + s_greater_or_equal_zero * probability_l_overflow * probability_geometric_output_s;
        std::cout << std::endl;
    }

    std::cout << "fail_probability: " << fail_probability << std::endl;
    std::cout << "std::log2l(fail_probability): " << std::log2l(fail_probability) << std::endl;

//     k<0
    for (std::size_t s = 0; s < 10000; s++) {

        long double l_range = INT64_MIN_double + m * s + m;
        long double probability_l_overflow = 0;

        long double probability_geometric_output_s = powl(0.5, s + 1);
        std::cout << "probability_geometric_output_s: " << probability_geometric_output_s << std::endl;

        if (l_range > 0 && l_range < (m - 1)) {
            probability_l_overflow = l_range / m;
        }

        fail_probability = fail_probability + (1 - s_greater_or_equal_zero) * probability_l_overflow * probability_geometric_output_s;

    }
    std::cout << "fail_probability: " << fail_probability << std::endl;
    std::cout << "std::log2l(fail_probability): " << std::log2l(fail_probability) << std::endl;

};