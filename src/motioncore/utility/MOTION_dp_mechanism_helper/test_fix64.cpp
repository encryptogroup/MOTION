//
// Created by liangzhao on 23.06.22.
//

#include "test_fix64.h"

double floating_poly_eval(double x, const double coeff[], unsigned coeff_size) {
    double x_premult = x;
    double local_aggregation = coeff[0];

    unsigned i;
    for (i = 1; i < coeff_size - 1; i++) {
        double coefficient_mul_x = coeff[i] * x_premult;
        local_aggregation = local_aggregation + coefficient_mul_x;
        x_premult = x * x_premult;
    }

    double coefficient_mul_x = coeff[i] * x_premult;
    local_aggregation = local_aggregation + coefficient_mul_x;

    return local_aggregation;
}

double floating_exp2_P1045(double a){
//    bool s = a < 0;
//    double a_prime = abs(a);
//    double b = a_prime >> FIXEDPOINT_FRACTION_BITS;
//    double c = a_prime & fraction_mask;
//
//    double d = pow2(b);
//
//    double e = floating_poly_eval(c, p_1045_fixedptd, sizeof(p_1045_fixedptd) / sizeof(p_1045_fixedptd[0]));
//
//    double g = d * e;
//
//    // TODO: more efficient for division
//    double g_inverse = ((double) 1 << (2 * FIXEDPOINT_FRACTION_BITS)) / g;
//    double pow2_a = (1 - s) * g + s * g_inverse;
//
//    return pow2_a;


}