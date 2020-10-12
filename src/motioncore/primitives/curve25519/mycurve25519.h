// This file was taken from the BoringSSL project (commit
// 982279b366eccd9e4146036c7fcda7f72d2cbdff) -- they used Fiat-Crypto to
// generate it -- and adapted for use in this project.
//
// The MIT License (MIT)
//
// Copyright (c) 2018 Lennart Braun
// Copyright (c) 2015-2016 the fiat-crypto authors (see the AUTHORS file).
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <cstdint>

#ifdef __cplusplus
namespace encrypto::motion::curve25519 {
#endif

#if defined(BORINGSSL_HAS_UINT128)
typedef __uint128_t uint128_t;
#define BORINGSSL_CURVE25519_64BIT
#endif

#if defined(BORINGSSL_CURVE25519_64BIT)
// fe means field element. Here the field is \Z/(2^255-19). An element t,
// entries t[0]...t[4], represents the integer t[0]+2^51 t[1]+2^102 t[2]+2^153
// t[3]+2^204 t[4].
// fe limbs are bounded by 1.125*2^51.
// Multiplication and carrying produce fe from fe_loose.
typedef struct fe {
  uint64_t v[5];
} fe;

// fe_loose limbs are bounded by 3.375*2^51.
// Addition and subtraction produce fe_loose from (fe, fe).
typedef struct fe_loose {
  uint64_t v[5];
} fe_loose;
#else
// fe means field element. Here the field is \Z/(2^255-19). An element t,
// entries t[0]...t[9], represents the integer t[0]+2^26 t[1]+2^51 t[2]+2^77
// t[3]+2^102 t[4]+...+2^230 t[9].
// fe limbs are bounded by 1.125*2^26,1.125*2^25,1.125*2^26,1.125*2^25,etc.
// Multiplication and carrying produce fe from fe_loose.
typedef struct fe {
  uint32_t v[10];
} fe;

// fe_loose limbs are bounded by 3.375*2^26,3.375*2^25,3.375*2^26,3.375*2^25,etc.
// Addition and subtraction produce fe_loose from (fe, fe).
typedef struct fe_loose {
  uint32_t v[10];
} fe_loose;
#endif

// ge means group element.
//
// Here the group is the set of pairs (x,y) of field elements (see fe.h)
// satisfying -x^2 + y^2 = 1 + d x^2y^2
// where d = -121665/121666.
//
// Representations:
//   ge_p2 (projective): (X:Y:Z) satisfying x=X/Z, y=Y/Z
//   ge_p3 (extended): (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
//   ge_p1p1 (completed): ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
//   ge_precomp (Duif): (y+x,y-x,2dxy)

typedef struct {
  fe X;
  fe Y;
  fe Z;
} ge_p2;

typedef struct {
  fe X;
  fe Y;
  fe Z;
  fe T;
} ge_p3;

typedef struct {
  fe_loose X;
  fe_loose Y;
  fe_loose Z;
  fe_loose T;
} ge_p1p1;

typedef struct {
  fe_loose yplusx;
  fe_loose yminusx;
  fe_loose xy2d;
} ge_precomp;

typedef struct {
  fe_loose YplusX;
  fe_loose YminusX;
  fe_loose Z;
  fe_loose T2d;
} ge_cached;

void x25519_ge_tobytes(uint8_t s[32], const ge_p2* h);
int x25519_ge_frombytes_vartime(ge_p3* h, const uint8_t* s);
void x25519_ge_p3_to_cached(ge_cached* r, const ge_p3* p);
void x25519_ge_p1p1_to_p2(ge_p2* r, const ge_p1p1* p);
void x25519_ge_p1p1_to_p3(ge_p3* r, const ge_p1p1* p);
void x25519_ge_add(ge_p1p1* r, const ge_p3* p, const ge_cached* q);
void x25519_ge_sub(ge_p1p1* r, const ge_p3* p, const ge_cached* q);
void x25519_ge_scalarmult_small_precomp(ge_p3* h, const uint8_t a[32],
                                        const uint8_t precomp_table[15 * 2 * 32]);
void x25519_ge_scalarmult_base(ge_p3* h, const uint8_t a[32]);
void x25519_ge_scalarmult(ge_p2* r, const uint8_t* scalar, const ge_p3* A);
void x25519_sc_reduce(uint8_t s[64]);

typedef struct {
  uint8_t s[32];
} sc;
void sc_random(uint8_t s[32]);
void x25519_ge_p2_to_p3(ge_p3* r, const ge_p2* p);
void ge_p3_tobytes(uint8_t s[32], const ge_p3* h);
void ge_double_scalarmult_vartime(ge_p2* r, const uint8_t* a, const ge_p3* A, const uint8_t* b);

void ge_p2_0(ge_p2* h);
void ge_p3_0(ge_p3* h);
void ge_cached_0(ge_cached* h);
void ge_precomp_0(ge_precomp* h);

#ifdef __cplusplus

}  // namespace encrypto::motion::curve25519
}  // extern "C"

#endif
