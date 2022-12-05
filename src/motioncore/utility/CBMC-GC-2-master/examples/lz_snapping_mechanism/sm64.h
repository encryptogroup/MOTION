#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#define FLOATINGPOINT64_BITS 64
#define FLOATINGPOINT64_MANTISSA_BITS 52
#define FLOATINGPOINT64_EXPONENT_BITS 11
#define FLOATINGPOINT_SIGN_BITS 1
#define FLOATINGPOINT64_EXPONENT_BIAS 1023

#define FLOATINGPOINT_MANTISSA_MASK ((FLType(1) << FLOATINGPOINT64_MANTISSA_BITS) - 1)
#define FLOATINGPOINT_EXPONENT_MASK (((FLType(1) << FLOATINGPOINT64_EXPONENT_BITS) - 1) << FLOATINGPOINT64_MANTISSA_BITS)
#define FLOATINGPOINT_SIGN_MASK ((FLType(1) << (FLOATINGPOINT64_BITS - FLOATINGPOINT_SIGN_BITS)))

#define ceil_log2_52 6
#define ceil_log2_64 6
#define max_pow2_log52 64
#define max_pow2_log64 64

typedef uint64_t FLType;
typedef int64_t FLType_int;

FLType bool_array_to_int(bool bool_array[], unsigned count);

void int_to_bool_array(FLType int_input, bool bool_array[]);

// void PreOrL(bool bool_array_list[], bool pre_or_list[], unsigned count = 52, unsigned log_k = ceil_log2_52, unsigned kmax = max_pow2_log52);

bool KAndL(bool bool_array_list[], const unsigned head, const unsigned tail);

FLType KOrL_int(FLType int_array_list[], const unsigned head, const unsigned tail);

bool KOrL(bool bool_array_list[], const unsigned head, const unsigned tail);

FLType bool_array_to_int(bool bool_array[], unsigned count)
{
    //    FLType ret = 0;
    FLType tmp;

    FLType tmp_int_array[count];
    for (unsigned i = 0; i < count; i++)
    {
        tmp_int_array[i] = ((FLType)bool_array[i] << (count - i - 1));
    }
    unsigned head = 0;
    unsigned tail = count - 1;

    FLType int_output = KOrL_int(tmp_int_array, head, tail);

    //    for (unsigned i = 0; i < count; i++) {
    //        tmp = bool_array[i];
    //        ret |= tmp << (count - i - 1);
    //    }

    return int_output;
}

void int_to_bool_array(FLType int_input, bool bool_array[])
{
    unsigned count = sizeof(FLType) * 8;
    unsigned i;
    for (i = 0; i < count; i++)
    {
        bool_array[count - i - 1] = ((int_input >> i) & 1);
    }
}

void PreOrL(bool bool_array_list[], bool pre_or_list[], unsigned count, unsigned log_k, unsigned kmax)
{
    //    unsigned log_k = ceil_log2_52;
    //    unsigned kmax = max_pow2_log52;

    memcpy(pre_or_list, bool_array_list, count);

    unsigned i;
    unsigned j;
    unsigned z;
    unsigned k = count;

    //    pre_or_list[0]=bool_array_list[0];
    for (i = 0; i < log_k; i++)
    {
        for (j = 0; j < kmax / ((unsigned)(1 << (i + 1))); j++)
        {
            unsigned y = ((unsigned)(1) << i) + j * ((unsigned)(1) << (i + 1)) - 1;
            for (z = 1; z < ((unsigned)(1) << i) + 1; z++)
            {
                if (y + z < k)
                {
                    pre_or_list[y + z] = pre_or_list[y] | pre_or_list[y + z];
                }
            }
        }
    }
    //    return preOr_list;
}

bool KAndL(bool bool_array_list[], const unsigned head, const unsigned tail)
{
    if (tail - head == 0)
    {
        return bool_array_list[head];
    }
    else
    {
        bool t1 = KAndL(bool_array_list, head, head + (tail - head) / 2);
        bool t2 = KAndL(bool_array_list, head + (tail - head) / 2 + 1, tail);
        return t1 & t2;
    }
}

bool KOrL(bool bool_array_list[], const unsigned head, const unsigned tail)
{
    if (tail - head == 0)
    {
        return bool_array_list[head];
    }
    else
    {
        bool t1 = KOrL(bool_array_list, head, head + (tail - head) / 2);
        bool t2 = KOrL(bool_array_list, head + (tail - head) / 2 + 1, tail);
        return t1 | t2;
    }
}

FLType KOrL_int(FLType int_array_list[], const unsigned head, const unsigned tail)
{
    if (tail - head == 0)
    {
        return int_array_list[head];
    }
    else
    {
        FLType t1 = KOrL_int(int_array_list, head, head + (tail - head) / 2);
        FLType t2 = KOrL_int(int_array_list, head + (tail - head) / 2 + 1, tail);
        return t1 | t2;
    }
}

FLType round_to_nearest_integer_CBMC(FLType x, FLType not_used)
{

    // TODO: compare bit mask and shift circuit cost
    //    FLType x_sign = x & FLOATINGPOINT_SIGN_MASK;
    //    FLType x_exponent = x & FLOATINGPOINT_EXPONENT_MASK;
    //    FLType x_mantissa = x & FLOATINGPOINT_MANTISSA_MASK;

    FLType x_sign = (x >> (FLOATINGPOINT64_EXPONENT_BITS + FLOATINGPOINT64_MANTISSA_BITS)) << (FLOATINGPOINT64_EXPONENT_BITS + FLOATINGPOINT64_MANTISSA_BITS);
    FLType x_exponent = ((x << FLOATINGPOINT_SIGN_BITS) >> (FLOATINGPOINT_SIGN_BITS + FLOATINGPOINT64_MANTISSA_BITS)) << FLOATINGPOINT64_MANTISSA_BITS;
    FLType x_mantissa = (x << (FLOATINGPOINT_SIGN_BITS + FLOATINGPOINT64_EXPONENT_BITS)) >> (FLOATINGPOINT_SIGN_BITS + FLOATINGPOINT64_EXPONENT_BITS);

    // FLType result = x;


    FLType mantissa_x_round_to_nearest_int = x_mantissa;
    FLType exponent_x_round_to_nearest_int = x_exponent;
    FLType sign_x_round_to_nearest_int = x_sign;

    // TODO: change to unsigned integer operation to save computation
    int16_t unbiased_exponent_num_y =
        (int16_t)(x_exponent >> FLOATINGPOINT64_MANTISSA_BITS) - (int16_t)(FLOATINGPOINT64_EXPONENT_BIAS);

    // std::cout << "exponent_x_num: " << (x_exponent >> FLOATINGPOINT64_MANTISSA_BITS) << std::endl;
    // std::cout << "unbiased_exponent_num_y: " << unbiased_exponent_num_y << std::endl;

    // case 1
    // y >= 52
    if (unbiased_exponent_num_y > (int16_t)(FLOATINGPOINT64_MANTISSA_BITS - 1))
    {
        // std::cout << "case 1" << std::endl;
        // std::cout << "y >= 52" << std::endl;
        // result = x;
    }

    // case 2, 3
    // y in [0, 51]
    else if (unbiased_exponent_num_y >= 0)
    {

        // std::cout << "case 2, 3" << std::endl;
        // std::cout << "y in [0, 51]" << std::endl;
        FLType mantissa_x_tmp = x_mantissa;
        // std::cout << "mantissa_x_tmp: " << mantissa_x_tmp << std::endl;

        unsigned i;
        bool mantissa_array[FLOATINGPOINT64_MANTISSA_BITS];
        mantissa_array[FLOATINGPOINT64_MANTISSA_BITS - 1] = (mantissa_x_tmp)&1;
        for (i = 1; i < FLOATINGPOINT64_MANTISSA_BITS; i++)
        {
            mantissa_array[FLOATINGPOINT64_MANTISSA_BITS - 1 - i] = ((mantissa_x_tmp >> i) & 1);
        }

        // std::cout << "mantissa_array: ";
        // for (i = 0; i < FLOATINGPOINT64_MANTISSA_BITS; i++)
        // {
        //     std::cout << mantissa_array[i];
        // }
        // std::cout << std::endl;

        bool mantissa_fraction_msb_mask[FLOATINGPOINT64_MANTISSA_BITS];
        mantissa_fraction_msb_mask[FLOATINGPOINT64_MANTISSA_BITS - 1] =
            (unbiased_exponent_num_y == (int16_t)(FLOATINGPOINT64_MANTISSA_BITS));

        bool mantissa_fraction_msb =
            mantissa_fraction_msb_mask[FLOATINGPOINT64_MANTISSA_BITS - 1] & mantissa_array[FLOATINGPOINT64_MANTISSA_BITS - 1];
        for (i = 1; i < FLOATINGPOINT64_MANTISSA_BITS; i++)
        {
            mantissa_fraction_msb_mask[FLOATINGPOINT64_MANTISSA_BITS - 1 - i] =
                (unbiased_exponent_num_y == (int16_t)(FLOATINGPOINT64_MANTISSA_BITS - i - 1));
            mantissa_fraction_msb = mantissa_fraction_msb ^
                                    (mantissa_fraction_msb_mask[FLOATINGPOINT64_MANTISSA_BITS - 1 - i] &
                                     mantissa_array[FLOATINGPOINT64_MANTISSA_BITS - 1 - i]);
        }

        // std::cout << "mantissa_fraction_msb_mask: ";
        // for (i = 0; i < FLOATINGPOINT64_MANTISSA_BITS; i++)
        // {
        //     std::cout << mantissa_fraction_msb_mask[i];
        // }
        // std::cout << std::endl;

        // std::cout << "mantissa_fraction_msb: " << mantissa_fraction_msb << std::endl;

        bool mantissa_fraction_mask[FLOATINGPOINT64_MANTISSA_BITS];
        PreOrL(mantissa_fraction_msb_mask, mantissa_fraction_mask,52,ceil_log2_52,max_pow2_log52);

        // std::cout << "mantissa_fraction_mask: ";
        // for (i = 0; i < FLOATINGPOINT64_MANTISSA_BITS; i++)
        // {
        //     std::cout << mantissa_fraction_mask[i];
        // }
        // std::cout << std::endl;

        bool mantissa_integer_mask[FLOATINGPOINT64_MANTISSA_BITS];
        for (i = 0; i < FLOATINGPOINT64_MANTISSA_BITS; i++)
        {
            mantissa_integer_mask[i] = !mantissa_fraction_mask[i];
        }

        // std::cout << "mantissa_integer_mask: ";
        // for (i = 0; i < FLOATINGPOINT64_MANTISSA_BITS; i++)
        // {
        //     std::cout << mantissa_integer_mask[i];
        // }
        // std::cout << std::endl;

        bool mantissa_integer_array[FLOATINGPOINT64_MANTISSA_BITS];
        for (i = 0; i < FLOATINGPOINT64_MANTISSA_BITS; i++)
        {
            mantissa_integer_array[i] = mantissa_integer_mask[i] & mantissa_array[i];
        }

        // std::cout << "mantissa_integer_array: ";
        // for (i = 0; i < FLOATINGPOINT64_MANTISSA_BITS; i++)
        // {
        //     std::cout << mantissa_integer_array[i];
        // }
        // std::cout << std::endl;

        const unsigned head = 0;
        const unsigned tail = FLOATINGPOINT64_MANTISSA_BITS - 1;

        bool mantissa_integer_with_fraction_all_ones[FLOATINGPOINT64_MANTISSA_BITS];
        for (i = 0; i < FLOATINGPOINT64_MANTISSA_BITS; i++)
        {
            mantissa_integer_with_fraction_all_ones[i] = mantissa_integer_array[i] ^ mantissa_fraction_mask[i];
        }

        // std::cout << "mantissa_integer_with_fraction_all_ones: ";
        // for (i = 0; i < FLOATINGPOINT64_MANTISSA_BITS; i++)
        // {
        //     std::cout << mantissa_integer_with_fraction_all_ones[i];
        // }
        // std::cout << std::endl;

        bool mantissa_integer_all_ones = KAndL(mantissa_integer_with_fraction_all_ones, head, tail);
        bool mantissa_integer_contain_zero = !mantissa_integer_all_ones;

        // std::cout << "mantissa_integer_all_ones: " << mantissa_integer_all_ones << std::endl;
        // std::cout << "mantissa_integer_contain_zero: " << mantissa_integer_contain_zero << std::endl;

        FLType mantissa_integer_bit[FLOATINGPOINT64_MANTISSA_BITS];
        // convert integer integer bool array to integer
        //        for (i = 0; i < FLOATINGPOINT64_MANTISSA_BITS; i++) {
        //            mantissa_integer_bit[i] = ((FLType) (mantissa_integer_array[i]) << (FLOATINGPOINT64_MANTISSA_BITS - 1 - i));
        //        }
        //        FLType mantissa_integer = KOrL(mantissa_integer_bit, head, tail);
        FLType mantissa_integer = bool_array_to_int(mantissa_integer_array, FLOATINGPOINT64_MANTISSA_BITS);

        // std::cout << "mantissa_integer: " << mantissa_integer << std::endl;

        bool mantissa_integer_one_array[FLOATINGPOINT64_MANTISSA_BITS];
        mantissa_integer_one_array[FLOATINGPOINT64_MANTISSA_BITS - 1] = 0;
        for (i = 0; i < FLOATINGPOINT64_MANTISSA_BITS - 1; i++)
        {
            mantissa_integer_one_array[i] = mantissa_fraction_msb_mask[i + 1];
        }

        FLType mantissa_integer_one = bool_array_to_int(mantissa_integer_one_array, FLOATINGPOINT64_MANTISSA_BITS);
        // std::cout << "mantissa_integer_one: " << mantissa_integer_one << std::endl;

        // case 3a
        if (mantissa_fraction_msb & mantissa_integer_contain_zero)
        {
            // std::cout << "case 3a" << std::endl;
            mantissa_x_round_to_nearest_int = mantissa_integer + mantissa_integer_one;
            // std::cout << "mantissa_x_round_to_nearest_int: " << mantissa_x_round_to_nearest_int << std::endl;

            // result = sign_x_round_to_nearest_int ^ exponent_x_round_to_nearest_int ^ mantissa_x_round_to_nearest_int;
        }

        // case 3c
        else if (!mantissa_fraction_msb)
        {
            // std::cout << "case 3c" << std::endl;
            mantissa_x_round_to_nearest_int = mantissa_integer;

            // result = sign_x_round_to_nearest_int ^ exponent_x_round_to_nearest_int ^ mantissa_x_round_to_nearest_int;
        }

        // case 3b
        else
        {
            // std::cout << "case 3b" << std::endl;
            mantissa_x_round_to_nearest_int = 0;
            exponent_x_round_to_nearest_int = (((exponent_x_round_to_nearest_int >> FLOATINGPOINT64_MANTISSA_BITS) + 1) << FLOATINGPOINT64_MANTISSA_BITS);

            // result = sign_x_round_to_nearest_int ^ exponent_x_round_to_nearest_int ^ mantissa_x_round_to_nearest_int;
        }
    }

    // case 4
    // y = -1
    else if (unbiased_exponent_num_y == -1)
    {

        // std::cout << "case 4" << std::endl;
        mantissa_x_round_to_nearest_int = 0;
        exponent_x_round_to_nearest_int = ((FLType)(FLOATINGPOINT64_EXPONENT_BIAS) << FLOATINGPOINT64_MANTISSA_BITS);

        // result = sign_x_round_to_nearest_int ^ exponent_x_round_to_nearest_int ^ mantissa_x_round_to_nearest_int;
    }

    // case 5
    else
    {
        // std::cout << "case 5" << std::endl;
        mantissa_x_round_to_nearest_int = 0;
        exponent_x_round_to_nearest_int = 0;

        // result = sign_x_round_to_nearest_int ^ exponent_x_round_to_nearest_int ^ mantissa_x_round_to_nearest_int;
    }


    // x_round_to_nearest_int[0] = sign_x_round_to_nearest_int;
    // x_round_to_nearest_int[1] = exponent_x_round_to_nearest_int;
    // x_round_to_nearest_int[2] = mantissa_x_round_to_nearest_int;

FLType result = sign_x_round_to_nearest_int^exponent_x_round_to_nearest_int^mantissa_x_round_to_nearest_int;

    return result^not_used;
}