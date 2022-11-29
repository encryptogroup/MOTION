#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "SPARC-GCC.h"

#define FLOATINGPOINT_BITS 64
#define FLOATINGPOINT_MANTISSA_BITS 52
#define FLOATINGPOINT_EXPONENT_BITS 11
#define FLOATINGPOINT_SIGN_BITS 1
#define FLOATINGPOINT_EXPONENT_BIAS 1023

typedef unsigned long long float64;

extern signed char float_rounding_mode;
enum {
  float_round_nearest_even = 0,
  float_round_down = 1,
  float_round_up = 2,
  float_round_to_zero = 3
};

typedef uint64_t fixedptd;

fixedptd KMulL_float64(fixedptd* x_array, unsigned head, unsigned tail) {
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
    v[i] = ((fixedptd)(1) << ((fixedptd)(1) << i)) * x_array[i] + 1 - x_array[i];
  }

  //    fixedptd pow2_float64_x = v[0];
  //    for (std::size_t i = 1; i < m; i++) {
  //        pow2_float64_x = pow2_float64_x * v[i];
  //    }

  // more efficient methodf
  fixedptd pow2_float64_x = KMulL_float64(v, 0, m - 1);

  return pow2_float64_x & 0xFFFFFFFFFFFFFFFF;
}

INLINE bits64 extractFloat64Frac(float64 a) { return a & LIT64(0x000FFFFFFFFFFFFF); }

INLINE int16 extractFloat64Exp(float64 a) { return (a >> 52) & 0x7FF; }

INLINE flag extractFloat64Sign(float64 a) { return a >> 63; }

INLINE void shift64ExtraRightJamming(bits64 a0, bits64 a1, int16 count, bits64* z0Ptr,
                                     bits64* z1Ptr) {
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
  return (((bits64)zSign) << 63) + (((bits64)zExp) << 52) + zSig;
}

// =================================================================

static int8 countLeadingZeros32(bits32 a) {
  static const int8 countLeadingZerosHigh[] = {
      8, 7, 6, 6, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
      3, 3, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
      2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
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
  if (a < ((bits64)1) << 32) {
    shiftCount += 32;
  } else {
    a >>= 32;
  }
  shiftCount += countLeadingZeros32(a);
  return shiftCount;
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
  z = (sbits32)z;
  if ((absZ >> 32) || (z && ((z < 0) ^ zSign))) {
    // float_raise(float_flag_invalid);
    z = zSign ? (sbits32)0x80000000 : 0x7FFFFFFF;
    return z;
  }
  // if (roundBits) float_exception_flags |= float_flag_inexact;
  return z;
}

static int64 roundAndPackInt64(flag zSign, bits64 absZ0, bits64 absZ1) {
  int8 roundingMode;
  flag roundNearestEven, increment;
  int64 z;

  // TODO: test different mode
  roundingMode = 0;

  roundNearestEven = (roundingMode == float_round_nearest_even);
  increment = ((sbits64)absZ1 < 0);
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
    absZ0 &= ~(((bits64)(absZ1 << 1) == 0) & roundNearestEven);
  }
  z = absZ0;
  if (zSign) {
    z = -z;
  }
  z = (sbits64)z;
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

INLINE void shift64RightJamming(bits64 a, int16 count, bits64* zPtr) {
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
  if (0x7FD <= (bits16)zExp) {
    if ((0x7FD < zExp) || ((zExp == 0x7FD) && ((sbits64)(zSig + roundIncrement) < 0))) {
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
      return (sbits64)LIT64(0x8000000000000000);
    }
    aSigExtra = 0;
    aSig <<= -shiftCount;
  } else {
    shift64ExtraRightJamming(aSig, 0, shiftCount, &aSig, &aSigExtra);
  }
  return roundAndPackInt64(aSign, aSig, aSigExtra);
}

// ! we mask the correct result z with zero_bits_mask, otherwise, it cannot be converted to bristol
// format in CBMC-GC, input wire zero_bits_mask must be zero bits
float64 int64_to_float64(int64 a, int64 zero_bits_mask) {
  flag zSign;
  float64 z = 0;

  if (a == 0) {
    z = 0;
    return z ^ zero_bits_mask;
  }

  else if (a == (sbits64)LIT64(0x8000000000000000)) {
    z = packFloat64(1, 0x43E, 0);
    return z;
  }

  else {
    zSign = (a < 0);
    z = normalizeRoundAndPackFloat64(zSign, 0x43C, zSign ? -a : a);
    return z;
  }
}

// int64 float64_to_int64_round_to_zero(float64 a, float64 not_used) {
//   flag aSign;
//   int16 aExp, shiftCount;
//   bits64 aSig;
//   int64 z;

//   aSig = extractFloat64Frac(a);
//   aExp = extractFloat64Exp(a);
//   aSign = extractFloat64Sign(a);
//   if (aExp) aSig |= LIT64(0x0010000000000000);
//   shiftCount = aExp - 0x433;
//   if (0 <= shiftCount) {
//     if (0x43E <= aExp) {
//       if (a != LIT64(0xC3E0000000000000)) {
//         // float_raise( float_flag_invalid );
//         if (!aSign || ((aExp == 0x7FF) && (aSig != LIT64(0x0010000000000000)))) {
//           return LIT64(0x7FFFFFFFFFFFFFFF);
//         }
//       }
//       return (sbits64)LIT64(0x8000000000000000);
//     }
//     z = aSig << shiftCount;
//   } else {
//     if (aExp < 0x3FE) {
//       // if ( aExp | aSig ) float_exception_flags |= float_flag_inexact;
//       return 0;
//     }
//     z = aSig >> (-shiftCount);
//     // if ( (bits64) ( aSig<<( shiftCount & 63 ) ) ) {
//     // float_exception_flags |= float_flag_inexact;
//     // }
//   }
//   if (aSign) {
//     z = -z;
//   }
//   return z;
// }

// ! we mask the correct result z with zero_bits_mask, otherwise, it cannot be converted to bristol
// ! the depth-optimized circuit is not correct, but the size-optimized circuit is correct
// format in CBMC-GC, input wire zero_bits_mask must be zero bits
float64 float64_floor(float64 a, float64 zero_bits_mask) {
  flag aSign;
  int16 aExp;
  bits64 lastBitMask, roundBitsMask;
  int8 roundingMode;
  float64 z;
  int8 float_rounding_mode = 1;

  aExp = extractFloat64Exp(a);
  if (0x433 <= aExp) {
    z = a;
    return z ^ zero_bits_mask;
  }

  else if (aExp < 0x3FF) {
    if ((bits64)(a << 1) == 0) {
      z = a;
      return z;
    } else {  // float_exception_flags |= float_flag_inexact;
      aSign = extractFloat64Sign(a);
      z = aSign ? LIT64(0xBFF0000000000000) : 0;
      return z;
    }
  }

  else {
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

// ! we mask the correct result z with zero_bits_mask, otherwise, it cannot be converted to bristol
// ! the depth-optimized circuit is not correct, but the size-optimized circuit is correct
// format in CBMC-GC, input wire zero_bits_mask must be zero bits
float64 float64_ceil(float64 a, float64 zero_bits_mask) {
  flag aSign;
  int16 aExp;
  bits64 lastBitMask, roundBitsMask;
  int8 roundingMode;
  float64 z;
  int8 float_rounding_mode = 2;

  aExp = extractFloat64Exp(a);
  if (0x433 <= aExp) {
    z = a;
    return z ^ zero_bits_mask;
    // return z;
  }

  else if (aExp < 0x3FF) {
    if ((bits64)(a << 1) == 0) {
      z = a;
      return z;
    } else {
      aSign = extractFloat64Sign(a);
      z = aSign ? LIT64(0x8000000000000000) : LIT64(0x3FF0000000000000);
      return z;
    }
  }

  else {
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

// ! we mask the correct result z with zero_bits_mask, otherwise, it cannot be converted to bristol
// ! the depth-optimized circuit is not correct, but the size-optimized circuit is correct
// format in CBMC-GC, input wire zero_bits_mask must be zero bits
float64 int32_to_float64(int32 a, int32 zero_bits_mask) {
  flag zSign;
  uint32 absA;
  int8 shiftCount;
  bits64 zSig;
  float64 z;

  if (a == 0) {
    z = 0;
    return z ^ zero_bits_mask;
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

  uint16_t sum_bi = (uint16_t)(b[0]);
  for (i = 1; i < num_of_bits; i++) {
    sum_bi = sum_bi + (uint16_t)(b[i]);
  }

  return sum_bi;
}

// ! we mask the correct result z with zero_bits_mask, otherwise, it cannot be converted to bristol
// format in CBMC-GC, input wire zero_bits_mask must be zero bits
float64 int128_to_float64(__uint128_t a, __uint128_t zero_mask) {
  bool float64_sign_bit = (__int128_t)(a) < 0;

  __uint128_t a_abs = a;
  __uint128_t a_abs_round = a;

  if (float64_sign_bit) {
    a_abs = -a;
  } else {
    a_abs = a;
  }

  float64 float64_a;

  // print_u128_u("a_abs: ", a_abs);

  uint16_t a_abs_msb_index = msb_index_reverse_float64(a_abs, 128);
  // std::cout << "a_msb_index: " << std::int64_t(a_abs_msb_index) << std::endl;

  bool right_shift = false;
  float64 float64_mantissa_bits;
  float64 float64_exponent_bits;
  bool second_mantissa_bit;

  if (a_abs_msb_index > (FLOATINGPOINT_MANTISSA_BITS + 1)) {
    // std::cout << "if" << std::endl;
    right_shift = true;
    uint16_t right_shift_bits = a_abs_msb_index - (FLOATINGPOINT_MANTISSA_BITS + 1);
    second_mantissa_bit = a_abs & (((float64)(1) << (right_shift_bits - 1)) - 1);

    // =============================================================================
    // round to nearest integer
    if (float64_sign_bit) {
      a_abs_round = a_abs + 1;
    } else {
      a_abs_round = a_abs - 1;
    }

    uint16_t a_abs_round_msb_index = msb_index_reverse_float64(a_abs_round, 128);
    // std::cout << "a_abs_round_msb_index: " << std::int64_t(a_abs_round_msb_index) << std::endl;
    right_shift_bits = a_abs_round_msb_index - (FLOATINGPOINT_MANTISSA_BITS + 1);

    // =============================================================================
    float64_mantissa_bits =
        (a_abs_round >> (right_shift_bits)) & (((float64)(1) << (FLOATINGPOINT_MANTISSA_BITS)) - 1);
    float64_exponent_bits =
        right_shift_bits + (uint16_t)(FLOATINGPOINT_EXPONENT_BIAS + FLOATINGPOINT_MANTISSA_BITS);
  } else {
    // std::cout << "else" << std::endl;
    right_shift = false;
    uint16_t left_shift_bits = (FLOATINGPOINT_MANTISSA_BITS + 1) - a_abs_msb_index;
    // std::cout << "left_shift_bits: " << std::int64_t(left_shift_bits) << std::endl;
    float64_mantissa_bits =
        (a_abs << (left_shift_bits)) & (((float64)(1) << (FLOATINGPOINT_MANTISSA_BITS)) - 1);
    // std::cout << "float64_mantissa_bits: " << float64_mantissa_bits << std::endl;
    float64_exponent_bits =
        (uint16_t)(FLOATINGPOINT_EXPONENT_BIAS + FLOATINGPOINT_MANTISSA_BITS) - left_shift_bits;
    // std::cout << "float64_exponent_bits: " << float64_exponent_bits << std::endl;
  }

  float64_a = ((float64)(float64_sign_bit) << (FLOATINGPOINT_BITS - 1)) ^
              (float64_exponent_bits << (FLOATINGPOINT_MANTISSA_BITS)) ^ (float64_mantissa_bits);

  if (a == 0) {
    float64_a = 0;
  }

  return float64_a ^ (float64)(zero_mask);
}

// ! we mask the correct result z with zero_bits_mask, otherwise, it cannot be converted to bristol
// format in CBMC-GC, input wire zero_bits_mask must be zero bits
float64 int128_to_float64_towards_zero(__uint128_t a, __uint128_t zero_mask) {
  bool float64_sign_bit = (__int128_t)(a) < 0;

  __uint128_t a_abs = a;
  //    __uint128_t a_abs_round = a;

  if (float64_sign_bit) {
    a_abs = -a;
  } else {
    a_abs = a;
  }

  float64 float64_a;

  // print_u128_u("a_abs: ", a_abs);

  uint16_t a_abs_msb_index = msb_index_reverse_float64(a_abs, 128);
  // std::cout << "a_msb_index: " << std::int64_t(a_abs_msb_index) << std::endl;

  bool right_shift = false;
  float64 float64_mantissa_bits;
  float64 float64_exponent_bits;
  bool second_mantissa_bit;

  if (a_abs_msb_index > (FLOATINGPOINT_MANTISSA_BITS + 1)) {
    // std::cout << "if" << std::endl;
    right_shift = true;
    uint16_t right_shift_bits = a_abs_msb_index - (FLOATINGPOINT_MANTISSA_BITS + 1);
    second_mantissa_bit = a_abs & (((float64)(1) << (right_shift_bits - 1)) - 1);

    // =============================================================================
    //        // round to nearest integer
    //        if (float64_sign_bit) { a_abs_round = a_abs + 1; }
    //        else { a_abs_round = a_abs - 1; }
    //
    //        uint16_t a_abs_round_msb_index = msb_index_reverse_float64(a_abs_round, 128);
    //        std::cout << "a_abs_round_msb_index: " << std::int64_t(a_abs_round_msb_index) <<
    //        std::endl; right_shift_bits = a_abs_round_msb_index - (FLOATINGPOINT_MANTISSA_BITS +
    //        1);

    // =============================================================================
    float64_mantissa_bits =
        (a_abs >> (right_shift_bits)) & (((float64)(1) << (FLOATINGPOINT_MANTISSA_BITS)) - 1);
    float64_exponent_bits =
        right_shift_bits + (uint16_t)(FLOATINGPOINT_EXPONENT_BIAS + FLOATINGPOINT_MANTISSA_BITS);
  } else {
    // std::cout << "else" << std::endl;
    right_shift = false;
    uint16_t left_shift_bits = (FLOATINGPOINT_MANTISSA_BITS + 1) - a_abs_msb_index;
    // std::cout << "left_shift_bits: " << std::int64_t(left_shift_bits) << std::endl;
    float64_mantissa_bits =
        (a_abs << (left_shift_bits)) & (((float64)(1) << (FLOATINGPOINT_MANTISSA_BITS)) - 1);
    // std::cout << "float64_mantissa_bits: " << float64_mantissa_bits << std::endl;
    float64_exponent_bits =
        (uint16_t)(FLOATINGPOINT_EXPONENT_BIAS + FLOATINGPOINT_MANTISSA_BITS) - left_shift_bits;
    // std::cout << "float64_exponent_bits: " << float64_exponent_bits << std::endl;
  }

  float64_a = ((float64)(float64_sign_bit) << (FLOATINGPOINT_BITS - 1)) ^
              (float64_exponent_bits << (FLOATINGPOINT_MANTISSA_BITS)) ^ (float64_mantissa_bits);

  if (a == 0) {
    float64_a = 0;
  }

  return float64_a ^ (float64)(zero_mask);
}
