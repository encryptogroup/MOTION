#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "SPARC-GCC.h"

typedef unsigned int float32;

#define FLOATINGPOINT32_BITS 32
#define FLOATINGPOINT32_MANTISSA_BITS 23
#define FLOATINGPOINT32_EXPONENT_BITS 8
#define FLOATINGPOINT32_EXPONENT_BIAS 127

#define float32_exponent_mask ((((int16)1) << 5) - 1)

enum {
  float_round_nearest_even = 0,
  float_round_down = 1,
  float_round_up = 2,
  float_round_to_zero = 3
};

enum { float_tininess_after_rounding = 0, float_tininess_before_rounding = 1 };

typedef float32 fixedptd;

INLINE bits32 extractFloat32Frac(float32 a) { return a & 0x007FFFFF; }

INLINE int16 extractFloat32Exp(float32 a) { return (a >> 23) & 0xFF; }

INLINE flag extractFloat32Sign(float32 a) { return a >> 31; }

INLINE float32 packFloat32(flag zSign, int16 zExp, bits32 zSig) {
  return (((bits32)zSign) << 31) + (((bits32)zExp) << 23) + zSig;
}

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

static int64 roundAndPackInt64(flag zSign, bits64 absZ0, bits64 absZ1) {
  int8 roundingMode;
  flag roundNearestEven, increment;
  int64 z;

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
    // if (absZ0 == 0) goto overflow;
    absZ0 &= ~(((bits64)(absZ1 << 1) == 0) & roundNearestEven);
  }
  z = absZ0;
  if (zSign) z = -z;
  z = (sbits64)z;
  // if (z && ((z < 0) ^ zSign)) {
  // overflow:
  //   float_raise(float_flag_invalid);
  //   return zSign ? (sbits64)LIT64(0x8000000000000000) : LIT64(0x7FFFFFFFFFFFFFFF);
  // }
  // if (absZ1) float_exception_flags |= float_flag_inexact;
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

fixedptd KMulL_float32(fixedptd* x_array, unsigned head, unsigned tail) {
  if (tail - head == 0) {
    return x_array[head];
  } else {
    fixedptd premult_left = KMulL_float32(x_array, head, head + (tail - head) / 2);
    fixedptd premult_right = KMulL_float32(x_array, head + (tail - head) / 2 + 1, tail);
    return premult_left * premult_right;
  }
}

// backup
// 2^x
// x: integer
// m = ceil(log2(x_max)), m is the maximum number of bits to represent 2^x
fixedptd pow2_float32(fixedptd x, unsigned m) {
  unsigned i;

  fixedptd x_temp = x;
  bool x_array[m];

  for (i = 0; i < m - 1; i++) {
    x_array[i] = x_temp & 0x1;
    x_temp = x_temp >> 1;
  }
  x_array[m - 1] = x_temp & 0x1;

  // unsigned m = FLOATINGPOINT32_EXPONENT_BITS;

  fixedptd v[m];
  for (i = 0; i < m; i++) {
    v[i] = (((fixedptd)(1) << ((fixedptd)(1) << i)) * x_array[i] + !x_array[i]);
  }

  // fixedptd pow2_float32_x = v[0];
  // for (i = 1; i < m; i++) {
  //   pow2_float32_x = pow2_float32_x * v[i];
  // }

  // low depth method
  fixedptd pow2_float32_x = KMulL_float32(v, 0, m - 1);

  return pow2_float32_x & 0xFFFFFFFF;
}

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

INLINE void shift32RightJamming(bits32 a, int16 count, bits32* zPtr) {
  bits32 z;

  if (count == 0) {
    z = a;
  } else if (count < 32) {
    z = (a >> count) | ((a << ((-count) & 31)) != 0);
  } else {
    z = (a != 0);
  }
  *zPtr = z;
}

static float32 roundAndPackFloat32(flag zSign, int16 zExp, bits32 zSig) {
  int8 roundingMode;
  flag roundNearestEven;
  int8 roundIncrement, roundBits;
  flag isTiny;

  roundingMode = 0;
  roundNearestEven = roundingMode == float_round_nearest_even;
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
  roundBits = zSig & 0x7F;
  if (0xFD <= (bits16)zExp) {
    if ((0xFD < zExp) || ((zExp == 0xFD) && ((sbits32)(zSig + roundIncrement) < 0))) {
      // float_raise( float_flag_overflow | float_flag_inexact );
      return packFloat32(zSign, 0xFF, 0) - (roundIncrement == 0);
    }
    if (zExp < 0) {
      // isTiny = (float_detect_tininess == float_tininess_before_rounding) || (zExp < -1) ||
      //          (zSig + roundIncrement < 0x80000000);
      shift32RightJamming(zSig, -zExp, &zSig);
      zExp = 0;
      roundBits = zSig & 0x7F;
      // if ( isTiny && roundBits ) float_raise( float_flag_underflow );
    }
  }
  // if (roundBits) float_exception_flags |= float_flag_inexact;
  zSig = (zSig + roundIncrement) >> 7;
  zSig &= ~(((roundBits ^ 0x40) == 0) & roundNearestEven);
  if (zSig == 0) {
    zExp = 0;
  }
  return packFloat32(zSign, zExp, zSig);
}

static float32 normalizeRoundAndPackFloat32(flag zSign, int16 zExp, bits32 zSig) {
  int8 shiftCount;

  shiftCount = countLeadingZeros32(zSig) - 1;
  return roundAndPackFloat32(zSign, zExp - shiftCount, zSig << shiftCount);
}

// static float32 propagateFloat32NaN( float32 a, float32 b )
// {
//     flag aIsNaN, aIsSignalingNaN, bIsNaN, bIsSignalingNaN;

//     aIsNaN = float32_is_nan( a );
//     aIsSignalingNaN = float32_is_signaling_nan( a );
//     bIsNaN = float32_is_nan( b );
//     bIsSignalingNaN = float32_is_signaling_nan( b );
//     a |= 0x00400000;
//     b |= 0x00400000;
//     // if ( aIsSignalingNaN | bIsSignalingNaN ) float_raise( float_flag_invalid );
//     if ( aIsSignalingNaN ) {
//         if ( bIsSignalingNaN ) goto returnLargerSignificand;
//         return bIsNaN ? b : a;
//     }
//     else if ( aIsNaN ) {
//         if ( bIsSignalingNaN | ! bIsNaN ) return a;
//  returnLargerSignificand:
//         if ( (bits32) ( a<<1 ) < (bits32) ( b<<1 ) ) return b;
//         if ( (bits32) ( b<<1 ) < (bits32) ( a<<1 ) ) return a;
//         return ( a < b ) ? a : b;
//     }
//     else {
//         return b;
//     }

// }
// =================================================================

int32 float32_to_int32(float32 a, float32 not_used) {
  flag aSign;
  int16 aExp, shiftCount;
  bits32 aSig, aSigExtra;
  int32 z = 0;
  int8 roundingMode = 0;

  aSig = extractFloat32Frac(a);
  aExp = extractFloat32Exp(a);
  aSign = extractFloat32Sign(a);
  shiftCount = aExp - 0x96;
  if (0 <= shiftCount) {
    if (0x9E <= aExp) {
      if (a != 0xCF000000) {
        //       // float_raise(float_flag_invalid);
        if (!aSign || ((aExp == 0xFF) && aSig)) {
          // return 0x7FFFFFFF;
          z = 0x7FFFFFFF;
          return z;
        }
      }
      // return (sbits32)0x80000000;
      z = (sbits32)0x80000000;
      return z;
    }
    z = (aSig | 0x00800000) << shiftCount;
    if (aSign) {
      z = -z;
    }
  } else {
    if (aExp < 0x7E) {
      aSigExtra = aExp | aSig;
      z = 0;
    } else {
      aSig |= 0x00800000;
      aSigExtra = aSig << (shiftCount & 31);
      z = aSig >> (-shiftCount);
    }
    // if (aSigExtra) {
    //   float_exception_flags |= float_flag_inexact;
    // }
    // roundingMode = float_rounding_mode;
    // if (roundingMode == float_round_nearest_even) {
    if ((sbits32)aSigExtra < 0) {
      ++z;
      if ((bits32)(aSigExtra << 1) == 0) {
        z &= ~1;
      }
    }
    if (aSign) {
      z = -z;
    }
    // }
    // else {
    // aSigExtra = (aSigExtra != 0);
    // if (aSign) {
    //   z += (roundingMode == float_round_down) & aSigExtra;
    //   z = -z;
    //   return z;
    // } else {
    //   z += (roundingMode == float_round_up) & aSigExtra;
    //   return z;
    // }
    // }
    // return z;
  }
  return z;
}

// ! we mask the correct result z with zero_bits_mask, otherwise, it cannot be converted to bristol
// format in MOTION, input wire zero_bits_mask must be zero bits
float32 int32_to_float32(int32 a, int32 zero_bits_mask) {
  flag zSign;
  float32 z = 0;
  bool cond_1 = a == 0;
  bool cond_2 = a == (sbits32)0x80000000;

  if (a == 0) {
    z = 0;
    return z ^ zero_bits_mask;
  }

  else if (a == (sbits32)0x80000000) {
    z = packFloat32(1, 0x9E, 0);
    return z;
  }

  else {
    zSign = (a < 0);
    z = normalizeRoundAndPackFloat32(zSign, 0x9C, zSign ? -a : a);
    return z;
  }
}

// backup
// ! we mask the correct result z with zero_bits_mask, otherwise, it cannot be converted to bristol
// format in MOTION, input wire zero_bits_mask must be zero bits
float32 float32_floor(float32 a, float32 zero_bits_mask) {
  flag aSign;
  int16 aExp;
  bits32 lastBitMask, roundBitsMask;
  int8 roundingMode;
  float32 z;
  int8 float_rounding_mode = 1;

  aExp = extractFloat32Exp(a);

  if (0x96 <= aExp) {
    z = a;
    return z ^ zero_bits_mask;
  }

  else if (aExp <= 0x7E) {
    if ((bits32)(a << 1) == 0) {
      z = a;
      return z;
    } else {
      aSign = extractFloat32Sign(a);
      z = aSign ? 0xBF800000 : 0;
      return z;
    }
  }

  else {
    lastBitMask = 1;
    // lastBitMask <<= 0x96 - aExp;
    lastBitMask = pow2_float32(0x96 - aExp, 16);
    roundBitsMask = lastBitMask - 1;
    z = a;
    roundingMode = float_rounding_mode;
    if (extractFloat32Sign(z) ^ (roundingMode == float_round_up)) {
      z += roundBitsMask;
    }
    z &= ~roundBitsMask;
    return z;
  }
}

// backup
// ! we mask the correct result z with zero_bits_mask, otherwise, it cannot be converted to
// bristol
// format in MOTION, input wire zero_bits_mask must be zero bits
float32 float32_ceil(float32 a, float32 zero_bits_mask) {
  flag aSign;
  int16 aExp;
  bits32 lastBitMask, roundBitsMask;
  int8 roundingMode;
  float32 z = a;

  int8 float_rounding_mode = 2;

  aExp = extractFloat32Exp(a);

  if (0x96 <= aExp) {
    z = a ^ zero_bits_mask;
    return z;
  } else if (aExp <= 0x7E) {
    if ((bits32)(a << 1) == 0) {
      z = a;
      return z;
    }
    aSign = extractFloat32Sign(a);
    z = aSign ? 0x80000000 : 0x3F800000;
    return z;
  } else {
    lastBitMask = 1;
    // lastBitMask <<= 0x96 - aExp;
    lastBitMask = pow2_float32(0x96 - aExp, 16);
    roundBitsMask = lastBitMask - 1;
    z = a;
    roundingMode = float_rounding_mode;
    if (extractFloat32Sign(z) ^ (roundingMode == float_round_up)) {
      z += roundBitsMask;
    }
    z &= ~roundBitsMask;
    return z;
  }
}

// // only for debug purposes
// // ! we mask the correct result z with zero_bits_mask, otherwise, it cannot be converted to
// bristol
// // format in MOTION, input wire zero_bits_mask must be zero bits
// float32 float32_ceil(float32 a, float32 zero_bits_mask) {
//   flag aSign;
//   int16 aExp;
//   bits32 lastBitMask, roundBitsMask;
//   int8 roundingMode;
//   float32 z = a;

//   int8 float_rounding_mode = 2;

//   aExp = extractFloat32Exp(a);
//   lastBitMask = 1;
//   // lastBitMask <<= 0x96 - aExp;
//   lastBitMask = pow2_float32(0x96 - aExp, 16);
//   roundBitsMask = lastBitMask - (float32)(1);

//   // if (0x96 <= aExp) {
//   //   return z ^ zero_bits_mask;
//   // } else if (aExp <= 0x7E) {
//   //   if ((bits32)(a << 1) == 0) {
//   //     return z ^ zero_bits_mask;
//   //   }
//   //   aSign = extractFloat32Sign(a);
//   //   z = aSign ? 0x80000000 : 0x3F800000;
//   //   return z ^ zero_bits_mask;
//   // } else if (!extractFloat32Sign(z)) {
//   // z = z + roundBitsMask;
//   // z = z & (~roundBitsMask);
//   // return z ^ zero_bits_mask;
//   // float32 b = (uint32_t)(roundBitsMask)&0xFFFFFFFF;
//   float32 b = (roundBitsMask);
//   float32 d = (float32)(8191);
//   float32 c1 = a + b;
//   float32 c2 = a + d;
//   return  c1;
//   // } else {
//   //   z = z & (~roundBitsMask);
//   //   return z ^ zero_bits_mask;
//   // }
// }

int64 float32_to_int64(float32 a, float32 not_used) {
  flag aSign;
  int16 aExp, shiftCount;
  bits32 aSig;
  bits64 aSig64, aSigExtra;
  int64 z;

  aSig = extractFloat32Frac(a);
  aExp = extractFloat32Exp(a);
  aSign = extractFloat32Sign(a);
  shiftCount = 0xBE - aExp;
  if (shiftCount < 0) {
    // float_raise( float_flag_invalid );
    if (!aSign || ((aExp == 0xFF) && aSig)) {
      z = LIT64(0x7FFFFFFFFFFFFFFF);
      return z;
    }
    z = (sbits64)LIT64(0x8000000000000000);
    return z;
  }
  if (aExp) {
    aSig |= 0x00800000;
  }
  aSig64 = aSig;
  aSig64 <<= 40;
  shift64ExtraRightJamming(aSig64, 0, shiftCount, &aSig64, &aSigExtra);
  z = roundAndPackInt64(aSign, aSig64, aSigExtra);
  return z;
}

// ! we mask the correct result z with zero_bits_mask, otherwise, it cannot be converted to bristol
// format in MOTION, input wire zero_bits_mask must be zero bits
float32 int64_to_float32(int64 a, int64 zero_bits_mask) {
  flag zSign;
  uint64 absA;
  int8 shiftCount;
  bits32 zSig;
  float32 z;

  if (a == 0) {
    z = 0;
    return z ^ zero_bits_mask;
  }
  zSign = (a < 0);
  absA = zSign ? -a : a;
  shiftCount = countLeadingZeros64(absA) - 40;
  if (0 <= shiftCount) {
    z = packFloat32(zSign, 0x95 - shiftCount, absA << shiftCount);
    return z;
  } else {
    shiftCount += 7;
    if (shiftCount < 0) {
      shift64RightJamming(absA, -shiftCount, &absA);
    } else {
      absA <<= shiftCount;
    }
    z = roundAndPackFloat32(zSign, 0x9C - shiftCount, absA);
    return z;
  }
}

unsigned char msb_index_reverse_float32(__uint128_t x, unsigned num_of_bits) {
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

  unsigned char sum_bi = (unsigned char)(b[0]);
  for (i = 1; i < num_of_bits; i++) {
    sum_bi = sum_bi + (unsigned char)(b[i]);
  }

  return sum_bi;
}

// round to nearest integer
// ! we mask the correct result z with zero_bits_mask, otherwise, it cannot be converted to bristol
// format in MOTION, input wire zero_bits_mask must be zero bits
float32 int128_to_float32(__uint128_t a, __uint128_t zero_mask) {
  bool float32_sign_bit = (__int128_t)(a) < 0;

  __uint128_t a_abs = a;
  __uint128_t a_abs_round = a;

  if (float32_sign_bit) {
    a_abs = -a;
  } else {
    a_abs = a;
  }

  float32 float32_a;
  unsigned char a_abs_msb_index = msb_index_reverse_float32(a_abs, 128);

  bool right_shift = false;
  float32 float32_mantissa_bits;
  float32 float32_exponent_bits;
  bool second_mantissa_bit;

  if (a_abs_msb_index > (FLOATINGPOINT32_MANTISSA_BITS + 1)) {
    right_shift = true;
    unsigned char right_shift_bits = a_abs_msb_index - (FLOATINGPOINT32_MANTISSA_BITS + 1);
    second_mantissa_bit = a_abs & (((float32)(1) << (right_shift_bits - 1)) - 1);

    // =============================================================================
    // round to nearest integer
    if (float32_sign_bit) {
      a_abs_round = a_abs + 1;
    } else {
      a_abs_round = a_abs - 1;
    }

    unsigned char a_abs_round_msb_index = msb_index_reverse_float32(a_abs_round, 128);
    right_shift_bits = a_abs_round_msb_index - (FLOATINGPOINT32_MANTISSA_BITS + 1);

    // =============================================================================
    float32_mantissa_bits = (a_abs_round >> (right_shift_bits)) &
                            (((float32)(1) << (FLOATINGPOINT32_MANTISSA_BITS)) - 1);
    float32_exponent_bits = right_shift_bits + (unsigned char)(FLOATINGPOINT32_EXPONENT_BIAS +
                                                               FLOATINGPOINT32_MANTISSA_BITS);
  } else {
    right_shift = false;
    unsigned char left_shift_bits = (FLOATINGPOINT32_MANTISSA_BITS + 1) - a_abs_msb_index;
    float32_mantissa_bits =
        (a_abs << (left_shift_bits)) & (((float32)(1) << (FLOATINGPOINT32_MANTISSA_BITS)) - 1);
    float32_exponent_bits =
        (unsigned char)(FLOATINGPOINT32_EXPONENT_BIAS + FLOATINGPOINT32_MANTISSA_BITS) -
        left_shift_bits;
  }

  float32_a = ((float32)(float32_sign_bit) << (FLOATINGPOINT32_BITS - 1)) ^
              (float32_exponent_bits << (FLOATINGPOINT32_MANTISSA_BITS)) ^ (float32_mantissa_bits);

  if (a == 0) {
    float32_a = 0;
  }

  return float32_a ^ (float32)(zero_mask);
}

// ! we mask the correct result z with zero_bits_mask, otherwise, it cannot be converted to bristol
// format in MOTION, input wire zero_bits_mask must be zero bits
float32 int128_to_float32_towards_zero(__uint128_t a, __uint128_t zero_mask) {
  bool float32_sign_bit = (__int128_t)(a) < 0;

  __uint128_t a_abs = a;
  //    __uint128_t a_abs_round = a;

  if (float32_sign_bit) {
    a_abs = -a;
  } else {
    a_abs = a;
  }

  float32 float32_a;

  unsigned char a_abs_msb_index = msb_index_reverse_float32(a_abs, 128);

  bool right_shift = false;
  float32 float32_mantissa_bits;
  float32 float32_exponent_bits;
  bool second_mantissa_bit;

  if (a_abs_msb_index > (FLOATINGPOINT32_MANTISSA_BITS + 1)) {
    right_shift = true;
    unsigned char right_shift_bits = a_abs_msb_index - (FLOATINGPOINT32_MANTISSA_BITS + 1);
    second_mantissa_bit = a_abs & (((float32)(1) << (right_shift_bits - 1)) - 1);

    // =============================================================================
    //        // round to nearest integer
    //        if (float32_sign_bit) { a_abs_round = a_abs + 1; }
    //        else { a_abs_round = a_abs - 1; }
    //
    //        unsigned char a_abs_round_msb_index = msb_index_reverse_float32(a_abs_round, 128);
    //        std::cout << "a_abs_round_msb_index: " << std::int64_t(a_abs_round_msb_index) <<
    //        std::endl; right_shift_bits = a_abs_round_msb_index - (FLOATINGPOINT32_MANTISSA_BITS +
    //        1);

    // =============================================================================
    float32_mantissa_bits =
        (a_abs >> (right_shift_bits)) & (((float32)(1) << (FLOATINGPOINT32_MANTISSA_BITS)) - 1);
    float32_exponent_bits = right_shift_bits + (unsigned char)(FLOATINGPOINT32_EXPONENT_BIAS +
                                                               FLOATINGPOINT32_MANTISSA_BITS);
  } else {
    right_shift = false;
    unsigned char left_shift_bits = (FLOATINGPOINT32_MANTISSA_BITS + 1) - a_abs_msb_index;
    float32_mantissa_bits =
        (a_abs << (left_shift_bits)) & (((float32)(1) << (FLOATINGPOINT32_MANTISSA_BITS)) - 1);
    float32_exponent_bits =
        (unsigned char)(FLOATINGPOINT32_EXPONENT_BIAS + FLOATINGPOINT32_MANTISSA_BITS) -
        left_shift_bits;
  }

  float32_a = ((float32)(float32_sign_bit) << (FLOATINGPOINT32_BITS - 1)) ^
              (float32_exponent_bits << (FLOATINGPOINT32_MANTISSA_BITS)) ^ (float32_mantissa_bits);
  if (a == 0) {
    float32_a = 0;
  }

  return float32_a ^ (float32)(zero_mask);
}
