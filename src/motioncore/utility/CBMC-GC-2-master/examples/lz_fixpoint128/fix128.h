#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define FIXEDPOINT_BITS 128
#define FIXEDPOINT_INTEGER_BITS 64
#define FIXEDPOINT_FRACTION_BITS (FIXEDPOINT_BITS - FIXEDPOINT_INTEGER_BITS)

// typedef int32_t fixedpt;

typedef __uint128_t ufixedptd;
typedef __int128_t fixedptd;

#define fraction_part_mask ((fixedptd)1 << FIXEDPOINT_FRACTION_BITS) - 1;
#define constant_fixed_point_one (fixedptd)((fixedptd)1 << FIXEDPOINT_FRACTION_BITS);

// only for test
// typedef int32_t fixedptd;
// typedef unsigned long int fixedptd;

static const double p_1045[] = {0.99999999999998151058451, 0.69314718056364205693851,
                                0.24022650683729748257646, 0.0555041102193305250618,
                                0.0096181190501642860210497, 0.0013333931011014250476911,
                                0.00015395144945146697380844, 0.000015368748541192116946474,
                                0.0000012256971722926501833228, 0.00000014433329807023165258784};

static const double p_2524[] = {-2.05466671951, -8.8626599391,
                                +6.10585199015, +4.81147460989};
static const double q_2524[] = {+0.353553425277, +4.54517087629,
                                +6.42784209029, +1};

// recalculate if FIXEDPOINT_FRACTION_BITS changes
static const fixedptd p_1045_fixedptd[] = {18446744073709209600, 12786308645270849536, 4431396891348864512, 1023870116254957184, 177422980588850976,
                                           24596761285667912, 2839902987807844, 283503371072568, 22610122049152, 2662479410816};
static const fixedptd p_2524_fixedptd[] = {340282366920938463425472696300198871040, 340282366920938463299887387722872225792, 112633089014247178240,
                                           88756040745792339968};
static const fixedptd q_2524_fixedptd[] = {6521909552468212736, 83843603926199812096, 118572757985797881856, 18446744073709551616};

double fixeddptd_to_double(fixedptd fixed_point)
{
  double result;
  result = (double)((fixedptd)(fixed_point)) / (double)(pow(2, FIXEDPOINT_FRACTION_BITS));

  //    print_u128_u("T_int(fixed_point_struct.v): ", T_int(fixed_point));
  return result;
}

// convert double coefficient to fixed-point numbers (as integer)
void double_to_fixedptd(const double coeff[], unsigned coeff_size)
{
  ufixedptd fixed_point_array[coeff_size];
  unsigned i;
  for (i = 0; i < coeff_size; i++)
  {
    if (coeff[i] < 0)
    {

      fixed_point_array[i] = -(fixedptd)(-coeff[i] * (pow(2, FIXEDPOINT_FRACTION_BITS)));
    }
    else
    {
      fixed_point_array[i] = (fixedptd)(coeff[i] * (pow(2, FIXEDPOINT_FRACTION_BITS)));
    }
  }
  for (i = 0; i < coeff_size; i++)
  {
    printf("%ld ", fixed_point_array[i]);
    printf(", ");
  }
  printf("\n");
}

fixedptd fixedptd_add(fixedptd a, fixedptd b)
{
  return (a + b);
}

fixedptd fixedptd_sub(fixedptd a, fixedptd b)
{
  return (a - b);
}

fixedptd fixedptd_mul(fixedptd a, fixedptd b)
{
  fixedptd c = (a * b) >> FIXEDPOINT_FRACTION_BITS;
  return c;
}

// TODO: overflow?
// TODO: depth not optimized, find other algorithms
fixedptd fixedptd_div(fixedptd a, fixedptd b)
{
  return (fixedptd)(a << FIXEDPOINT_FRACTION_BITS) / b;
}

// fixedptd fixedptd_div(fixedptd a, fixedptd b)
// {
//   return (ufixedptd(a) << FIXEDPOINT_FRACTION_BITS) / b;
// }

fixedptd fixedptd_gt(fixedptd a, fixedptd b)
{
  return (a > b);
}

fixedptd fixedptd_poly_eval(fixedptd x, const fixedptd coeff[], unsigned coeff_size)
{
  fixedptd x_premult = x;
  fixedptd local_aggregation = coeff[0];

  unsigned i;
  for (i = 1; i < coeff_size - 1; i++)
  {
    fixedptd coefficient_mul_x = fixedptd_mul(coeff[i], x_premult);
    local_aggregation = local_aggregation + coefficient_mul_x;
    x_premult = fixedptd_mul(x, x_premult);
  }

  fixedptd coefficient_mul_x = fixedptd_mul(coeff[i], x_premult);
  local_aggregation = local_aggregation + coefficient_mul_x;

  return local_aggregation;
}

fixedptd exp2(fixedptd x)
{
  unsigned i;
  fixedptd pow2_x = 0;
  fixedptd x_temp = x;
  for (i = 0; i < FIXEDPOINT_INTEGER_BITS; i++)
  {
    bool x_lsb = x_temp & 1;
    pow2_x = pow2_x + x_lsb * ((fixedptd)1 << ((fixedptd)1 << i));
    x_temp = x_temp >> 1;
  }
  return pow2_x;
}

fixedptd msb(fixedptd x)
{
  unsigned i;
  fixedptd x_temp = x;
  bool a[FIXEDPOINT_BITS];
  for (i = 0; i < FIXEDPOINT_BITS; i++)
  {
    a[i] = x_temp & 1;
    x_temp = x_temp >> 1;
  }

  bool b[FIXEDPOINT_BITS];
  b[0] = a[FIXEDPOINT_BITS - 1];
  for (i = 1; i < FIXEDPOINT_BITS; i++)
  {
    b[i] = b[i - 1] | a[FIXEDPOINT_BITS - 1 - i];
  }

  fixedptd sum_1_minus_bi = 0;
  for (i = 0; i < FIXEDPOINT_BITS; i++)
  {
    sum_1_minus_bi = sum_1_minus_bi + (fixedptd)(1 - b[i]);
  }

  return sum_1_minus_bi;
}
