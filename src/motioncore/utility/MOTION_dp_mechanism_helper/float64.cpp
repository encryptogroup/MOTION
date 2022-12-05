#include "float64.h"
#include "dp_mechanism_helper.h"
#include <vector>
#include <iomanip>
#include <iostream>
#include "print_uint128_t.h"

fixedptd KMulL_float64(fixedptd *x_array, unsigned head, unsigned tail) {
    if (tail - head == 0) {
        return x_array[head];
    } else {
        fixedptd premult_left = KMulL_float64(x_array, head, head + (tail - head) / 2);
        fixedptd premult_right = KMulL_float64(x_array, head + (tail - head) / 2 + 1, tail);
        return premult_left * premult_right;
    }
}

// 2^x
// x: integer
// m = ceil(log2(x_max)), m is the maximum number of bits to represent 2^x
fixedptd pow2_float64(fixedptd x, unsigned m) {
    unsigned i;

    fixedptd x_temp = x;
    bool x_array[m];

    for (i = 0; i < m - 1; i++) {
        x_array[i] = x_temp & 1;
        x_temp = x_temp >> 1;
    }
    x_array[m - 1] = x_temp & 1;

    // unsigned m = FLOATINGPOINT32_EXPONENT_BITS;

    fixedptd v[m];
    for (i = 0; i < m; i++) {
        v[i] = ((fixedptd) (1) << ((fixedptd) (1) << i)) * x_array[i] + 1 - x_array[i];
    }

    //    fixedptd pow2_x = v[0];
    //    for (std::size_t i = 1; i < m; i++) {
    //        pow2_x = pow2_x * v[i];
    //    }

    // more efficient methodf
    fixedptd pow2_x = KMulL_float64(v, 0, m - 1);

    return pow2_x;
}

INLINE bits64 extractFloat64Frac(float64 a) { return a & LIT64(0x000FFFFFFFFFFFFF); }

INLINE int16 extractFloat64Exp(float64 a) { return (a >> 52) & 0x7FF; }

INLINE flag extractFloat64Sign(float64 a) { return a >> 63; }

INLINE void shift64ExtraRightJamming(bits64 a0, bits64 a1, int16 count, bits64 *z0Ptr, bits64 *z1Ptr) {
    bits64 z0, z1;
    int8 negCount = (-count) & 63;

    if (count == 0) {
        z1 = a1;
        z0 = a0;
    } else if (count < 64) {
        z1 = (a0 << negCount) | (a1 != 0);
        z0 = a0 >> count;
    } else {
        if (count == 64) {
            z1 = a0 | (a1 != 0);
        } else {
            z1 = ((a0 | a1) != 0);
        }
        z0 = 0;
    }
    *z1Ptr = z1;
    *z0Ptr = z0;
}

INLINE float64 packFloat64(flag zSign, int16 zExp, bits64 zSig) {
    return (((bits64) zSign) << 63) + (((bits64) zExp) << 52) + zSig;
}

// =================================================================

static int8 countLeadingZeros32(bits32 a) {
    static const int8 countLeadingZerosHigh[] = {8, 7, 6, 6, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2,
                                                 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1,
                                                 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                                 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0,
                                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    int8 shiftCount;

    shiftCount = 0;
    if (a < 0x10000) {
        shiftCount += 16;
        a <<= 16;
    }
    if (a < 0x1000000) {
        shiftCount += 8;
        a <<= 8;
    }
    shiftCount += countLeadingZerosHigh[a >> 24];
    return shiftCount;
}

static int8 countLeadingZeros64(bits64 a) {
    int8 shiftCount;

    shiftCount = 0;
    if (a < ((bits64) 1) << 32) {
        shiftCount += 32;
    } else {
        a >>= 32;
    }
    shiftCount += countLeadingZeros32(a);
    return shiftCount;
}

static int64 roundAndPackInt64(flag zSign, bits64 absZ0, bits64 absZ1) {
    int8 roundingMode;
    flag roundNearestEven, increment;
    int64 z;

    // TODO: test different mode
    roundingMode = 0;

    roundNearestEven = (roundingMode == float_round_nearest_even);
    increment = ((sbits64) absZ1 < 0);
    if (!roundNearestEven) {
        if (roundingMode == float_round_to_zero) {
            increment = 0;
        } else {
            if (zSign) {
                increment = (roundingMode == float_round_down) && absZ1;
            } else {
                increment = (roundingMode == float_round_up) && absZ1;
            }
        }
    }
    if (increment) {
        ++absZ0;
        // if ( absZ0 == 0 ) goto overflow;
        absZ0 &= ~(((bits64) (absZ1 << 1) == 0) & roundNearestEven);
    }
    z = absZ0;
    if (zSign) {
        z = -z;
    }
    z = (sbits64) z;
    //     if ( z && ( ( z < 0 ) ^ zSign ) ) {
    //  overflow:
    //         float_raise( float_flag_invalid );
    //         return
    //               zSign ? (sbits64) LIT64( 0x8000000000000000 )
    //             : LIT64( 0x7FFFFFFFFFFFFFFF );
    //     }
    // if ( absZ1 ) float_exception_flags |= float_flag_inexact;
    return z;
}

INLINE void shift64RightJamming(bits64 a, int16 count, bits64 *zPtr) {
    bits64 z;

    if (count == 0) {
        z = a;
    } else if (count < 64) {
        z = (a >> count) | ((a << ((-count) & 63)) != 0);
    } else {
        z = (a != 0);
    }
    *zPtr = z;
}

static int32 roundAndPackInt32(flag zSign, bits64 absZ) {
    int8 roundingMode;
    flag roundNearestEven;
    int8 roundIncrement, roundBits;
    int32 z;

    roundingMode = 0;
    roundNearestEven = (roundingMode == float_round_nearest_even);
    roundIncrement = 0x40;
    if (!roundNearestEven) {
        if (roundingMode == float_round_to_zero) {
            roundIncrement = 0;
        } else {
            roundIncrement = 0x7F;
            if (zSign) {
                if (roundingMode == float_round_up) roundIncrement = 0;
            } else {
                if (roundingMode == float_round_down) roundIncrement = 0;
            }
        }
    }
    roundBits = absZ & 0x7F;
    absZ = (absZ + roundIncrement) >> 7;
    absZ &= ~(((roundBits ^ 0x40) == 0) & roundNearestEven);
    z = absZ;
    if (zSign) z = -z;
    z = (sbits32) z;
    if ((absZ >> 32) || (z && ((z < 0) ^ zSign))) {
        // float_raise(float_flag_invalid);
        z = zSign ? (sbits32) 0x80000000 : 0x7FFFFFFF;
        return z;
    }
    // if (roundBits) float_exception_flags |= float_flag_inexact;
    return z;
}

static float64 roundAndPackFloat64(flag zSign, int16 zExp, bits64 zSig) {
    int8 roundingMode;
    flag roundNearestEven;
    int16 roundIncrement, roundBits;
    flag isTiny;

    roundingMode = 0;
    roundNearestEven = (roundingMode == float_round_nearest_even);
    roundIncrement = 0x200;
    if (!roundNearestEven) {
        if (roundingMode == float_round_to_zero) {
            roundIncrement = 0;
        } else {
            roundIncrement = 0x3FF;
            if (zSign) {
                if (roundingMode == float_round_up) roundIncrement = 0;
            } else {
                if (roundingMode == float_round_down) roundIncrement = 0;
            }
        }
    }
    roundBits = zSig & 0x3FF;
    if (0x7FD <= (bits16) zExp) {
        if ((0x7FD < zExp) || ((zExp == 0x7FD) && ((sbits64) (zSig + roundIncrement) < 0))) {
            // float_raise(float_flag_overflow | float_flag_inexact);
            return packFloat64(zSign, 0x7FF, 0) - (roundIncrement == 0);
        }
        if (zExp < 0) {
            // isTiny = (float_detect_tininess == float_tininess_before_rounding) || (zExp < -1) ||
            //          (zSig + roundIncrement < LIT64(0x8000000000000000));
            shift64RightJamming(zSig, -zExp, &zSig);
            zExp = 0;
            roundBits = zSig & 0x3FF;
            // if (isTiny && roundBits) float_raise(float_flag_underflow);
        }
    }
    // if (roundBits) float_exception_flags |= float_flag_inexact;
    zSig = (zSig + roundIncrement) >> 10;
    zSig &= ~(((roundBits ^ 0x200) == 0) & roundNearestEven);
    if (zSig == 0) zExp = 0;
    return packFloat64(zSign, zExp, zSig);
}

static float64 normalizeRoundAndPackFloat64(flag zSign, int16 zExp, bits64 zSig) {
    int8 shiftCount;

    shiftCount = countLeadingZeros64(zSig) - 1;
    return roundAndPackFloat64(zSign, zExp - shiftCount, zSig << shiftCount);
}

int64 float64_to_int64(float64 a, float64 not_used) {
    flag aSign;
    int16 aExp, shiftCount;
    bits64 aSig, aSigExtra;

    aSig = extractFloat64Frac(a);
    aExp = extractFloat64Exp(a);
    aSign = extractFloat64Sign(a);
    if (aExp) aSig |= LIT64(0x0010000000000000);
    shiftCount = 0x433 - aExp;
    if (shiftCount <= 0) {
        if (0x43E < aExp) {
            // float_raise(float_flag_invalid);
            if (!aSign || ((aExp == 0x7FF) && (aSig != LIT64(0x0010000000000000)))) {
                return LIT64(0x7FFFFFFFFFFFFFFF);
            }
            return (sbits64) LIT64(0x8000000000000000);
        }
        aSigExtra = 0;
        aSig <<= -shiftCount;
    } else {
        shift64ExtraRightJamming(aSig, 0, shiftCount, &aSig, &aSigExtra);
    }
    return roundAndPackInt64(aSign, aSig, aSigExtra);
}

// ! we mask the correct result z with zero_bits_mask, otherwise, it cannot be converted to bristol
// format in MOTION, input wire zero_bits_mask must be zero bits
float64 int64_to_float64(int64 a, int64 zero_bits_mask) {
    flag zSign;
    float64 z = 0;

    if (a == 0) {
        z = 0;
        return z ^ zero_bits_mask;
    } else if (a == (sbits64) LIT64(0x8000000000000000)) {
        z = packFloat64(1, 0x43E, 0);
        return z;
    } else {
        zSign = (a < 0);
        z = normalizeRoundAndPackFloat64(zSign, 0x43C, zSign ? -a : a);
        return z;
    }
}

int64 float64_to_int64_round_to_zero(float64 a, float64 not_used) {
    flag aSign;
    int16 aExp, shiftCount;
    bits64 aSig;
    int64 z;

    aSig = extractFloat64Frac(a);
    aExp = extractFloat64Exp(a);
    aSign = extractFloat64Sign(a);
    if (aExp) aSig |= LIT64(0x0010000000000000);
    shiftCount = aExp - 0x433;
    if (0 <= shiftCount) {
        if (0x43E <= aExp) {
            if (a != LIT64(0xC3E0000000000000)) {
                // float_raise( float_flag_invalid );
                if (!aSign || ((aExp == 0x7FF) && (aSig != LIT64(0x0010000000000000)))) {
                    return LIT64(0x7FFFFFFFFFFFFFFF);
                }
            }
            return (sbits64) LIT64(0x8000000000000000);
        }
        z = aSig << shiftCount;
    } else {
        if (aExp < 0x3FE) {
            // if ( aExp | aSig ) float_exception_flags |= float_flag_inexact;
            return 0;
        }
        z = aSig >> (-shiftCount);
        // if ( (bits64) ( aSig<<( shiftCount & 63 ) ) ) {
        // float_exception_flags |= float_flag_inexact;
        // }
    }
    if (aSign) {
        z = -z;
    }
    return z;
}

float64 float64_floor(float64 a, float64 not_used) {
    flag aSign;
    int16 aExp;
    bits64 lastBitMask, roundBitsMask;
    int8 roundingMode;
    float64 z;
    int8 float_rounding_mode = 1;

    aExp = extractFloat64Exp(a);
    if (0x433 <= aExp) {
        z = a;
        return z;
    } else if (aExp < 0x3FF) {
        if ((bits64) (a << 1) == 0) {
            z = a;
            return z;
        } else {  // float_exception_flags |= float_flag_inexact;
            aSign = extractFloat64Sign(a);
            z = aSign ? LIT64(0xBFF0000000000000) : 0;
            return z;
        }
    } else {
        lastBitMask = 1;
        // lastBitMask <<= 0x433 - aExp;
        lastBitMask = pow2_float64(0x433 - aExp, 8);
        roundBitsMask = lastBitMask - 1;
        z = a;
        roundingMode = float_rounding_mode;
        if (extractFloat64Sign(z) ^ (roundingMode == float_round_up)) {
            z += roundBitsMask;
        }
        z &= ~roundBitsMask;
        return z;
    }
}

// backup
float64 float64_ceil(float64 a, float64 not_used) {
    flag aSign;
    int16 aExp;
    bits64 lastBitMask, roundBitsMask;
    int8 roundingMode;
    float64 z;
    int8 float_rounding_mode = 2;

    aExp = extractFloat64Exp(a);
    if (0x433 <= aExp) {
        z = a;
        return z;
    } else if (aExp < 0x3FF) {
        if ((bits64) (a << 1) == 0) {
            z = a;
            return z;
        } else {
            aSign = extractFloat64Sign(a);
            z = aSign ? LIT64(0x8000000000000000) : LIT64(0x3FF0000000000000);
            return z;
        }
    } else {
        lastBitMask = 1;
//        lastBitMask <<= 0x433 - aExp;
        lastBitMask = pow2_float64(0x433 - aExp, 8);
        roundBitsMask = lastBitMask - 1;
        z = a;
        roundingMode = float_rounding_mode;
        if (extractFloat64Sign(z) ^ (roundingMode == float_round_up)) {
            z += roundBitsMask;
        }
        z &= ~roundBitsMask;
        return z;
    }
}

//float64 float64_ceil_2(float64 a, float64 b) {
//    flag aSign;
//    int16 aExp;
//    bits64 lastBitMask, roundBitsMask;
//    int8 roundingMode;
//    float64 z;
//    int8 float_rounding_mode = 2;
//
//    aExp = extractFloat64Exp(a);
//    if (0x433 <= aExp) {
////        if ( ( aExp == 0x7FF ) && extractFloat64Frac( a ) ) {
////            return propagateFloat64NaN( a, a );
////        }
//        return a;
//    }
//    if (aExp < 0x3FF) {
//        if ((bits64) (a << 1) == 0) return a;
////        float_exception_flags |= float_flag_inexact;
//        aSign = extractFloat64Sign(a);
//        switch (float_rounding_mode) {
//            case float_round_nearest_even:
//                if ((aExp == 0x3FE) && extractFloat64Frac(a)) {
//                    return packFloat64(aSign, 0x3FF, 0);
//                }
//                break;
//            case float_round_down:
//                return aSign ? LIT64(0xBFF0000000000000) : 0;
//            case float_round_up:
//                return aSign ? LIT64(0x8000000000000000) : LIT64(0x3FF0000000000000);
//        }
//        return packFloat64(aSign, 0, 0);
//    }
//    lastBitMask = 1;
//    lastBitMask <<= 0x433 - aExp;
//    roundBitsMask = lastBitMask - 1;
//    z = a;
//    roundingMode = float_rounding_mode;
//    if (roundingMode == float_round_nearest_even) {
//        z += lastBitMask >> 1;
//        if ((z & roundBitsMask) == 0) z &= ~lastBitMask;
//    } else if (roundingMode != float_round_to_zero) {
//        if (extractFloat64Sign(z) ^ (roundingMode == float_round_up)) {
//            z += roundBitsMask;
//        }
//    }
//    z &= ~roundBitsMask;
////    if ( z != a ) float_exception_flags |= float_flag_inexact;
//    return z;
//
//}

int32 float64_to_int32(float64 a, float64 b) {
    flag aSign;
    int16 aExp, shiftCount;
    bits64 aSig;

    int32 z;

    aSig = extractFloat64Frac(a);
    aExp = extractFloat64Exp(a);
    aSign = extractFloat64Sign(a);
    if ((aExp == 0x7FF) && aSig) {
        aSign = 0;
    }
    if (aExp) {
        aSig |= LIT64(0x0010000000000000);
    }
    shiftCount = 0x42C - aExp;
    if (0 < shiftCount) {
        shift64RightJamming(aSig, shiftCount, &aSig);
    }
    z = roundAndPackInt32(aSign, aSig);
    return z;
}

float64 int32_to_float64(int32 a, int32 b) {
    flag zSign;
    uint32 absA;
    int8 shiftCount;
    bits64 zSig;
    float64 z;

    if (a == 0) {
        z = 0;
        return z;
    }
    zSign = (a < 0);
    absA = zSign ? -a : a;
    shiftCount = countLeadingZeros32(absA) + 21;
    zSig = absA;
    z = packFloat64(zSign, 0x432 - shiftCount, zSig << shiftCount);
    return z;
}

uint16_t msb_index_reverse_float64(__uint128_t x, unsigned num_of_bits) {
    unsigned i;
    __uint128_t x_temp = x;
    bool a[num_of_bits];
    for (i = 0; i < num_of_bits; i++) {
        a[i] = x_temp & 1;
        x_temp = x_temp >> 1;
    }

    bool b[num_of_bits];
    b[0] = a[num_of_bits - 1];
    for (i = 1; i < num_of_bits; i++) {
        b[i] = b[i - 1] | a[num_of_bits - 1 - i];
    }

    uint16_t sum_bi = (uint16_t) (b[0]);
    for (i = 1; i < num_of_bits; i++) {
        sum_bi = sum_bi + (uint16_t) (b[i]);
    }

    return sum_bi;
}

float64 int128_to_float64(__uint128_t a, __uint128_t not_used) {
    bool float64_sign_bit = (__int128_t)(a) < 0;

    __uint128_t a_abs = a;
    __uint128_t a_abs_round = a;

    if (float64_sign_bit) {
        a_abs = -a;
    } else {
        a_abs = a;
    }

    float64 float64_a;

    print_u128_u("a_abs: ", a_abs);

    uint16_t a_abs_msb_index = msb_index_reverse_float64(a_abs, 128);
    std::cout << "a_msb_index: " << std::int64_t(a_abs_msb_index) << std::endl;

    bool right_shift = false;
    float64 float64_mantissa_bits;
    float64 float64_exponent_bits;
    bool second_mantissa_bit;

    if (a_abs_msb_index > (FLOATINGPOINT64_MANTISSA_BITS + 1)) {
        std::cout << "if" << std::endl;
        right_shift = true;
        uint16_t right_shift_bits = a_abs_msb_index - (FLOATINGPOINT64_MANTISSA_BITS + 1);
        second_mantissa_bit = a_abs & (((float64) (1) << (right_shift_bits - 1)) - 1);

        // =============================================================================
        // round to nearest integer
        if (float64_sign_bit) { a_abs_round = a_abs + 1; }
        else { a_abs_round = a_abs - 1; }

        uint16_t a_abs_round_msb_index = msb_index_reverse_float64(a_abs_round, 128);
        std::cout << "a_abs_round_msb_index: " << std::int64_t(a_abs_round_msb_index) << std::endl;
        right_shift_bits = a_abs_round_msb_index - (FLOATINGPOINT64_MANTISSA_BITS + 1);

        // =============================================================================
        float64_mantissa_bits = (a_abs_round >> (right_shift_bits)) & (((float64) (1) << (FLOATINGPOINT64_MANTISSA_BITS)) - 1);
        float64_exponent_bits = right_shift_bits + (uint16_t) (FLOATINGPOINT64_EXPONENT_BIAS + FLOATINGPOINT64_MANTISSA_BITS);
    } else {
        std::cout << "else" << std::endl;
        right_shift = false;
        uint16_t left_shift_bits = (FLOATINGPOINT64_MANTISSA_BITS + 1) - a_abs_msb_index;
        std::cout << "left_shift_bits: " << std::int64_t(left_shift_bits) << std::endl;
        float64_mantissa_bits = (a_abs << (left_shift_bits)) & (((float64) (1) << (FLOATINGPOINT64_MANTISSA_BITS)) - 1);
        std::cout << "float64_mantissa_bits: " << float64_mantissa_bits << std::endl;
        float64_exponent_bits = (uint16_t) (FLOATINGPOINT64_EXPONENT_BIAS + FLOATINGPOINT64_MANTISSA_BITS) - left_shift_bits;
        std::cout << "float64_exponent_bits: " << float64_exponent_bits << std::endl;
    }

    float64_a = ((float64) (float64_sign_bit) << (FLOATINGPOINT64_BITS - 1)) ^ (float64_exponent_bits << (FLOATINGPOINT64_MANTISSA_BITS)) ^
                (float64_mantissa_bits);

//    if(a == 0){
//        float64_a=0;
//    }

    return float64_a;

}
float64 int128_to_float64_towards_zero(__uint128_t a, __uint128_t not_used) {
    bool float64_sign_bit = (__int128_t)(a) < 0;

    __uint128_t a_abs = a;
//    __uint128_t a_abs_round = a;

    if (float64_sign_bit) {
        a_abs = -a;
    } else {
        a_abs = a;
    }

    float64 float64_a;

    print_u128_u("a_abs: ", a_abs);

    uint16_t a_abs_msb_index = msb_index_reverse_float64(a_abs, 128);
    std::cout << "a_msb_index: " << std::int64_t(a_abs_msb_index) << std::endl;

    bool right_shift = false;
    float64 float64_mantissa_bits;
    float64 float64_exponent_bits;
    bool second_mantissa_bit;

    if (a_abs_msb_index > (FLOATINGPOINT64_MANTISSA_BITS + 1)) {
        std::cout << "if" << std::endl;
        right_shift = true;
        uint16_t right_shift_bits = a_abs_msb_index - (FLOATINGPOINT64_MANTISSA_BITS + 1);
        second_mantissa_bit = a_abs & (((float64) (1) << (right_shift_bits - 1)) - 1);

        // =============================================================================
//        // round to nearest integer
//        if (float64_sign_bit) { a_abs_round = a_abs + 1; }
//        else { a_abs_round = a_abs - 1; }
//
//        uint16_t a_abs_round_msb_index = msb_index_reverse_float64(a_abs_round, 128);
//        std::cout << "a_abs_round_msb_index: " << std::int64_t(a_abs_round_msb_index) << std::endl;
//        right_shift_bits = a_abs_round_msb_index - (FLOATINGPOINT64_MANTISSA_BITS + 1);

        // =============================================================================
        float64_mantissa_bits = (a_abs >> (right_shift_bits)) & (((float64) (1) << (FLOATINGPOINT64_MANTISSA_BITS)) - 1);
        float64_exponent_bits = right_shift_bits + (uint16_t) (FLOATINGPOINT64_EXPONENT_BIAS + FLOATINGPOINT64_MANTISSA_BITS);
    } else {
        std::cout << "else" << std::endl;
        right_shift = false;
        uint16_t left_shift_bits = (FLOATINGPOINT64_MANTISSA_BITS + 1) - a_abs_msb_index;
        std::cout << "left_shift_bits: " << std::int64_t(left_shift_bits) << std::endl;
        float64_mantissa_bits = (a_abs << (left_shift_bits)) & (((float64) (1) << (FLOATINGPOINT64_MANTISSA_BITS)) - 1);
        std::cout << "float64_mantissa_bits: " << float64_mantissa_bits << std::endl;
        float64_exponent_bits = (uint16_t) (FLOATINGPOINT64_EXPONENT_BIAS + FLOATINGPOINT64_MANTISSA_BITS) - left_shift_bits;
        std::cout << "float64_exponent_bits: " << float64_exponent_bits << std::endl;
    }

    float64_a = ((float64) (float64_sign_bit) << (FLOATINGPOINT64_BITS - 1)) ^ (float64_exponent_bits << (FLOATINGPOINT64_MANTISSA_BITS)) ^
                (float64_mantissa_bits);

    return float64_a;

}

void test_float64_to_int64() {
    std::size_t num_of_test = 500;
    double max = std::exp2(10);
    double min = -max;

    std::vector<double> random_float_vector = rand_range_double_vector(min, max, num_of_test);
    std::vector<float64> zero_vectors(num_of_test, 0);

//   std::cout<< std::numeric_limits<double>::is_iec559<<std::endl;
//   std::cout<< std::numeric_limits<double>::is_iec559<<std::endl;

// backup
    for (std::size_t i = 0; i < num_of_test; i++) {
        std::cout << "random_float: " << std::setprecision(15) << random_float_vector[i] << std::endl;
        auto *random_float64_pointer = reinterpret_cast<float64 *>(&random_float_vector[i]);
        float64 random_float64 = *random_float64_pointer;
        std::cout << "random_float64: " << (random_float64) << std::endl;

        int64 float64_to_integer_64 = float64_to_int64(random_float64, zero_vectors[i]);
        std::cout << "float64_to_integer_64: " << float64_to_integer_64 << std::endl;
//        std::cout << "integer_64: " << integer_64 << std::endl;

        double diff = abs(random_float_vector[i] - double(float64_to_integer_64));
        std::cout << "diff: " << diff << std::endl;
        if (diff > 1) {
            std::cout << "test_float64_to_int64 fails" << std::endl;
            break;
        }
        std::cout << std::endl;
    }
}

void test_int64_to_float64() {
    std::size_t num_of_test = 500;
    double max = std::exp2(25);
    double min = -max;

    std::vector<std::int64_t> random_integer_vector = rand_range_integer_vector<std::int64_t>(min, max, num_of_test);
    std::vector<float64> zero_vectors(num_of_test, 0);
//
// backup
    for (std::size_t i = 0; i < num_of_test; i++) {
        std::cout << "random_integer: " << random_integer_vector[i] << std::endl;
//

        int64 int64_to_float_64 = int64_to_float64(random_integer_vector[i], zero_vectors[i]);
//        std::cout << "int64_to_float_64: " << int64_to_float_64 << std::endl;
        auto *random_float_pointer = reinterpret_cast<double *>(&int64_to_float_64);
        double random_float = *random_float_pointer;
        std::cout << "random_float: " << random_float << std::endl;
//
        double diff = abs(random_integer_vector[i] - random_float);
        std::cout << "diff: " << diff << std::endl;
        if (diff > 1) {
            std::cout << "test_int64_to_float64 fails" << std::endl;
            break;
        }
        std::cout << std::endl;
    }
}

void test_float64_ceil() {
    std::size_t num_of_test = 500;
    double max = std::exp2(10);
    double min = -max;

    std::vector<double> random_float_vector = rand_range_double_vector(min, max, num_of_test);
    std::vector<float64> zero_vectors(num_of_test, 0);

// backup
    for (std::size_t i = 0; i < num_of_test; i++) {
        std::cout << "random_float: " << std::setprecision(15) << random_float_vector[i] << std::endl;
        auto *random_float64_pointer = reinterpret_cast<float64 *>(&random_float_vector[i]);
        float64 random_float64 = *random_float64_pointer;
        std::cout << "random_float64: " << (random_float64) << std::endl;

        int64 float64_ceil_ = float64_ceil(random_float64, zero_vectors[i]);
        std::cout << "float64_ceil: " << float64_ceil_ << std::endl;
        double float_ceil = *reinterpret_cast<double *>(&float64_ceil_);
        std::cout << "float_ceil: " << float_ceil << std::endl;

        double diff = abs(ceil(random_float_vector[i]) - float_ceil);
        std::cout << "diff: " << diff << std::endl;
        if (diff != 0) {
            std::cout << "test_float_ceil fails" << std::endl;
            break;
        }
        std::cout << std::endl;
    }
}

void test_float64_floor() {
    std::size_t num_of_test = 500;
    double max = std::exp2(15);
    double min = -max;

    std::vector<double> random_float_vector = rand_range_double_vector(min, max, num_of_test);
    std::vector<float64> zero_vectors(num_of_test, 0);

// backup
    for (std::size_t i = 0; i < num_of_test; i++) {
        std::cout << "random_float: " << std::setprecision(15) << random_float_vector[i] << std::endl;
        auto *random_float64_pointer = reinterpret_cast<float64 *>(&random_float_vector[i]);
        float64 random_float64 = *random_float64_pointer;
        std::cout << "random_float64: " << (random_float64) << std::endl;

        float64 float64_floor_ = float64_floor(random_float64, zero_vectors[i]);
        std::cout << "float64_floor: " << float64_floor_ << std::endl;
        double float_floor = *reinterpret_cast<double *>(&float64_floor_);
        std::cout << "float_floor: " << float_floor << std::endl;

        double diff = abs(floor(random_float_vector[i]) - float_floor);
        std::cout << "diff: " << diff << std::endl;
        if (diff != 0) {
            std::cout << "test_float64_floor fails" << std::endl;
            break;
        }
        std::cout << std::endl;
    }
}

void test_float64_to_int32() {
    std::srand(time(nullptr));
    std::size_t num_of_test = 500;
    double max = std::exp2(20);
    double min = -max;

    std::vector<double> random_float_vector = rand_range_double_vector(min, max, num_of_test);
    std::vector<float64> zero_vectors(num_of_test, 0);

//   std::cout<< std::numeric_limits<double>::is_iec559<<std::endl;
//   std::cout<< std::numeric_limits<double>::is_iec559<<std::endl;

// backup
    for (std::size_t i = 0; i < num_of_test; i++) {
        std::cout << "random_float: " << std::setprecision(15) << random_float_vector[i] << std::endl;
        auto *random_float64_pointer = reinterpret_cast<float64 *>(&random_float_vector[i]);
        float64 random_float64 = *random_float64_pointer;
        std::cout << "random_float64: " << (random_float64) << std::endl;

        int32 float64_to_integer_32 = float64_to_int32(random_float64, zero_vectors[i]);
        std::cout << "float64_to_integer_64: " << float64_to_integer_32 << std::endl;
//        std::cout << "integer_64: " << integer_64 << std::endl;

        double diff = abs(random_float_vector[i] - double(float64_to_integer_32));
        std::cout << "diff: " << diff << std::endl;
        if (diff > 1) {
            std::cout << "test_float64_to_int64 fails" << std::endl;
            break;
        }
        std::cout << std::endl;
    }
}

void test_int32_to_float64() {
    std::size_t num_of_test = 500;
    double max = std::exp2(25);
    double min = -max;

    std::vector<std::int32_t> random_integer_vector = rand_range_integer_vector<std::int32_t>(min, max, num_of_test);
    std::vector<std::int32_t> zero_vectors(num_of_test, 0);
//
// backup
    for (std::size_t i = 0; i < num_of_test; i++) {
        std::cout << "random_integer: " << random_integer_vector[i] << std::endl;
//

        float64 int32_to_float_64 = int32_to_float64(random_integer_vector[i], zero_vectors[i]);
//        std::cout << "int64_to_float_64: " << int64_to_float_64 << std::endl;
        auto *random_float_pointer = reinterpret_cast<double *>(&int32_to_float_64);
        double random_float = *random_float_pointer;
        std::cout << "random_float: " << random_float << std::endl;
//
        double diff = abs(random_integer_vector[i] - random_float);
        std::cout << "diff: " << diff << std::endl;
        if (diff > 1) {
            std::cout << "test_int64_to_float64 fails" << std::endl;
            break;
        }
        std::cout << std::endl;
    }
}


void test_int128_to_float64() {
    std::srand(time(nullptr));
    std::size_t num_of_test = 1;
    double max = std::exp2(120);
    double min = -max;

    std::vector<__int128_t> random_integer_vector = rand_range_integer_vector<__int128_t>(min, max, num_of_test);
    std::vector<__int128_t> zero_vectors(num_of_test, 0);
    __int128_t random_integer_tmp;
//
// backup
    for (std::size_t i = 0; i < num_of_test; i++) {

        random_integer_tmp = random_integer_vector[i];

//         only for debug
        random_integer_tmp=__uint128_t(0);

        print_u128_u("random_integer_tmp: ", random_integer_tmp);
        print_u128_u("-random_integer_tmp: ", -random_integer_tmp);
        std::cout << "std::int64_t(random_integer): " << std::int64_t(random_integer_tmp) << std::endl;
//

        float64 int128_to_float64_ = int128_to_float64(random_integer_tmp, zero_vectors[i]);
        std::cout << "int128_to_float64_: " << int128_to_float64_ << std::endl;
        auto *random_float_pointer = reinterpret_cast<double *>(&int128_to_float64_);
        double random_float = *random_float_pointer;

        double random_integer_plus_one = double(random_integer_tmp + 1);
        double random_integer_minus_one = double(random_integer_tmp - 1);

        std::cout << "random_float_double: " << std::setprecision(30) << random_integer_minus_one << std::endl;
        std::cout << "random_float_double: " << std::setprecision(30) << double(random_integer_tmp) << std::endl;
        std::cout << "random_float_double: " << std::setprecision(30) << random_integer_plus_one << std::endl;
        std::cout << "random_float_next: " << std::setprecision(30) << std::nextafter(random_float - 1, +INFINITY) << std::endl;
        std::cout << "random_float: " << std::setprecision(30) << random_float << std::endl;
        std::cout << "random_float_last: " << std::setprecision(30) << std::nextafter(random_float - 1, -INFINITY) << std::endl;
//
//        double diff = abs(random_integer_vector[i] - random_float);
//        std::cout << "diff: " << diff << std::endl;
        if ((double(random_integer_tmp) != random_float) && (double(random_integer_tmp) != std::nextafter(random_float - 1, +INFINITY)) &&
            (double(random_integer_tmp) != std::nextafter(random_float - 1, -INFINITY))) {
            std::cout << "int128_to_float64 fails" << std::endl;
            break;
        }
        std::cout << std::endl;
    }
}

void test_int128_to_float64_towards_zero() {
    std::srand(time(nullptr));
    std::size_t num_of_test = 500;
    double max = std::exp2(120);
    double min = -max;

    std::vector<__int128_t> random_integer_vector = rand_range_integer_vector<__int128_t>(min, max, num_of_test);
    std::vector<__int128_t> zero_vectors(num_of_test, 0);
    __int128_t random_integer_tmp;
//
// backup
    for (std::size_t i = 0; i < num_of_test; i++) {

        random_integer_tmp = random_integer_vector[i];

        // only for debug
//        random_integer_tmp=12;

        print_u128_u("random_integer_tmp: ", random_integer_tmp);
        print_u128_u("-random_integer_tmp: ", -random_integer_tmp);
        std::cout << "std::int64_t(random_integer): " << std::int64_t(random_integer_tmp) << std::endl;
//

        float64 int128_to_float64_ = int128_to_float64_towards_zero(random_integer_tmp, zero_vectors[i]);
        std::cout << "int128_to_float64_: " << int128_to_float64_ << std::endl;
        auto *random_float_pointer = reinterpret_cast<double *>(&int128_to_float64_);
        double random_float = *random_float_pointer;

        double random_integer_plus_one = double(random_integer_tmp + 1);
        double random_integer_minus_one = double(random_integer_tmp - 1);

        std::cout << "random_float_double: " << std::setprecision(30) << random_integer_minus_one << std::endl;
        std::cout << "random_float_double: " << std::setprecision(30) << double(random_integer_tmp) << std::endl;
        std::cout << "random_float_double: " << std::setprecision(30) << random_integer_plus_one << std::endl;
        std::cout << "random_float_next: " << std::setprecision(30) << std::nextafter(random_float - 1, +INFINITY) << std::endl;
        std::cout << "random_float: " << std::setprecision(30) << random_float << std::endl;
        std::cout << "random_float_last: " << std::setprecision(30) << std::nextafter(random_float - 1, -INFINITY) << std::endl;
//
//        double diff = abs(random_integer_vector[i] - random_float);
//        std::cout << "diff: " << diff << std::endl;
        if ((double(random_integer_tmp) != random_float) && (double(random_integer_tmp) != std::nextafter(random_float - 1, +INFINITY)) &&
            (double(random_integer_tmp) != std::nextafter(random_float - 1, -INFINITY))) {
            std::cout << "int128_to_float64_towards_zero fails" << std::endl;
            break;
        }
        std::cout << std::endl;
    }
}